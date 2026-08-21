use crate::event::Event;
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use std::sync::Mutex;

pub struct Buffer {
    conn: Mutex<Connection>,
    /// Both caps are atomics rather than plain fields because they are read
    /// from the live config on every envelope: a `Buffer` handed a limit at
    /// startup keeps enforcing it for the lifetime of the daemon, so an
    /// operator raising the cap because the buffer is overflowing has to
    /// restart the thing that is currently losing their events.
    max_events: std::sync::atomic::AtomicU64,
    max_bytes: std::sync::atomic::AtomicU64,
    /// Running total of stored body bytes.
    ///
    /// Kept in memory so the byte cap costs an addition per write instead of a
    /// `SUM(LENGTH(body))` scan. It is allowed to drift, but only upward:
    /// `ack` and the row trim delete bytes without decrementing it, and a
    /// transaction that fails to commit leaves its addition behind. An
    /// overestimate triggers a byte trim early, and a byte trim recounts
    /// exactly — so the drift costs an occasional scan and can never lose an
    /// event. Drifting the other way could silently blow past the cap.
    bytes: std::sync::atomic::AtomicU64,
    /// Events the cap has destroyed since the last time anyone asked.
    ///
    /// Deliberately a counter rather than a row written at trim time. Writing
    /// the marker into the buffer would spend the one thing the buffer has
    /// just run out of, and a burst that trims on every push would fill the
    /// cap with markers describing the events they displaced. Coalescing into
    /// one record per flush costs a marker if the process dies in between,
    /// which is the cheaper of the two failures.
    dropped: std::sync::atomic::AtomicU64,
    /// Rows that were on disk, could not be parsed, and were deleted by the
    /// `ack` that settled the batch around them.
    ///
    /// Counted apart from `dropped` because it is a different failure with a
    /// different fix: the cap destroying old events is capacity, an unreadable
    /// row is corruption, and reporting the second as the first sends an
    /// operator to raise a limit that was never the problem.
    unreadable: std::sync::atomic::AtomicU64,
    /// The same two losses, counted for the heartbeat instead of for a record.
    ///
    /// Separate counters rather than a second reader of the two above, because
    /// those are *drained*: whoever takes them owes a loss record, and a
    /// heartbeat reading them would quietly swallow the gap it was supposed to
    /// describe. These only ever go up, for the lifetime of the process, so a
    /// heartbeat states a total rather than a delta nobody can reassemble.
    dropped_total: std::sync::atomic::AtomicU64,
    unreadable_total: std::sync::atomic::AtomicU64,
}

/// Keys in the `meta` table. Spelled once so a typo cannot mint a second
/// identity under a slightly different name.
const K_INSTALL_ID: &str = "install_id";
const K_BATCH_SEQ: &str = "batch_seq";
const K_BATCH_ROW: &str = "batch_row";

/// Counts trim queries. The trim is the expensive part of a write, and a
/// batch that trims once looks identical from the outside to one that trims
/// per event — so the cost has to be counted to be asserted on.
#[cfg(test)]
static TRIMS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Buffer {
    pub fn open(cfg: &crate::config::BufferCfg) -> Result<Self> {
        let max_events = cfg.max_events;
        // A cap of 0 would make the trim-to-cap DELETE below (OFFSET 0) wipe
        // every row on each push; clamp to a minimum of 1 to keep at least
        // the most recent event.
        let max_events = max_events.max(1);
        let data_dir = crate::paths::data_dir();
        crate::paths::create_private_dir(&data_dir)?;
        let conn = Connection::open(crate::paths::db_path())?;
        // Best-effort: on-disk events may hold pre-redaction data, so keep
        // the DB file readable only by its owner. A perm error here must not
        // break daemon startup.
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(
                crate::paths::db_path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
        }
        // Non-Unix platforms (e.g. Windows) don't use POSIX permission bits;
        // ACL-based hardening is out of scope here.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT NOT NULL
            );
             CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        let bytes = total_bytes(&conn)?;
        Ok(Buffer {
            conn: Mutex::new(conn),
            max_events: std::sync::atomic::AtomicU64::new(max_events),
            max_bytes: std::sync::atomic::AtomicU64::new(cfg.max_bytes.max(1)),
            bytes: std::sync::atomic::AtomicU64::new(bytes),
            dropped: std::sync::atomic::AtomicU64::new(0),
            unreadable: std::sync::atomic::AtomicU64::new(0),
            dropped_total: std::sync::atomic::AtomicU64::new(0),
            unreadable_total: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Adopt the caps from a reloaded config.
    ///
    /// Same clamps as `open`. `max_events` is the one that needs it: at zero the
    /// row trim's `OFFSET 0` takes every row on every write, which is a config
    /// typo away from turning the audit trail off. `max_bytes` is clamped for
    /// symmetry rather than out of need — `trim_to_bytes` exempts the newest row,
    /// so zero there already keeps the event that was just written.
    pub fn set_limits(&self, cfg: &crate::config::BufferCfg) {
        use std::sync::atomic::Ordering::Relaxed;
        self.max_events.store(cfg.max_events.max(1), Relaxed);
        self.max_bytes.store(cfg.max_bytes.max(1), Relaxed);
    }

    pub fn push(&self, e: &Event) -> Result<()> {
        self.push_batch(std::slice::from_ref(e))
    }

    /// Append a whole batch under one transaction, then trim once.
    ///
    /// One host payload routinely fans out into several events, and `push`
    /// charged each of them its own implicit transaction *and* its own
    /// trim-to-cap query — an `ORDER BY seq DESC ... OFFSET max_events` scan
    /// repeated per event, to enforce a cap that only the last of them could
    /// possibly cross. Batching keeps the cap exactly where it was (a single
    /// `push` is a batch of one, so nothing about the per-event path changes)
    /// while a burst pays for one commit and one trim.
    pub fn push_batch(&self, events: &[Event]) -> Result<()> {
        let trimmed = self.append(events)?;
        self.dropped
            .fetch_add(trimmed as u64, std::sync::atomic::Ordering::Relaxed);
        self.dropped_total
            .fetch_add(trimmed as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// The write itself, returning how many events the cap destroyed to make
    /// room. Separate from `push_batch` so one caller — and only one — can
    /// append without its own displacement being charged to the loss count.
    fn append(&self, events: &[Event]) -> Result<usize> {
        use std::sync::atomic::Ordering::Relaxed;
        if events.is_empty() {
            return Ok(0);
        }
        let bodies = events
            .iter()
            .map(serde_json::to_string)
            .collect::<serde_json::Result<Vec<_>>>()?;
        let added: u64 = bodies.iter().map(|b| b.len() as u64).sum();
        // A poisoned lock only means a panic elsewhere mid-operation; the SQLite connection itself is still usable.
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let mut trimmed = {
            let mut stmt = tx.prepare_cached("INSERT INTO events (body) VALUES (?1)")?;
            for body in &bodies {
                stmt.execute([body])?;
            }
            #[cfg(test)]
            TRIMS.fetch_add(1, Relaxed);
            tx.prepare_cached(
                "DELETE FROM events WHERE seq <= (
                    SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1
                )",
            )?
            .execute([self.max_events.load(Relaxed) as i64])?
        };
        let max_bytes = self.max_bytes.load(Relaxed);
        let trimmed_bytes = if self.bytes.fetch_add(added, Relaxed) + added > max_bytes {
            trimmed += trim_to_bytes(&tx, max_bytes)?;
            true
        } else {
            false
        };
        tx.commit()?;
        // Recounted only once the trim is durable. Read inside the transaction
        // it would describe a database that does not exist yet, and a commit
        // that then fails rolls the trim back while leaving the smaller total
        // behind — the one direction this counter may not drift, since an
        // underestimate stops the byte cap from binding at all.
        if trimmed_bytes {
            match total_bytes(&conn) {
                Ok(n) => self.bytes.store(n, Relaxed),
                // The overestimate already in place is the safe answer: it
                // costs an early trim, which recounts exactly.
                Err(e) => tracing::warn!(
                    "byte recount after a trim failed, keeping the running total: {e}"
                ),
            }
        }
        Ok(trimmed)
    }

    /// Queue a record of everything lost since the last call, and return
    /// whether there was anything to say.
    ///
    /// The marker is written through `append`, not `push_batch`, and that is
    /// the whole subtlety here: a buffer that just trimmed is by definition
    /// full, so inserting the marker evicts one further event. Charging that
    /// eviction to the loss count would leave a residue of one, which the next
    /// flush would report with another marker, which would evict another
    /// event — the report becomes the thing being reported, forever, on an
    /// idle machine. The marker's own displacement is instead folded into the
    /// gap it already describes. Losses from a concurrent writer are untouched
    /// and roll into the next flush.
    pub fn flush_loss_record(&self) -> Result<bool> {
        use std::sync::atomic::Ordering::Relaxed;
        let dropped = self.dropped.swap(0, Relaxed);
        let unreadable = self.unreadable.swap(0, Relaxed);
        let mut records = Vec::new();
        if dropped > 0 {
            records.push(self.loss_record(
                "buffer_full",
                dropped,
                format!(
                    "local buffer at capacity ({} events / {} bytes); oldest dropped \
                     before export",
                    self.max_events.load(Relaxed),
                    self.max_bytes.load(Relaxed)
                ),
            ));
        }
        if unreadable > 0 {
            records.push(
                self.loss_record(
                    "buffer_unreadable",
                    unreadable,
                    "buffered rows could not be parsed and were discarded with the batch \
                 around them"
                        .into(),
                ),
            );
        }
        if records.is_empty() {
            return Ok(false);
        }
        if let Err(e) = self.append(&records) {
            // The counter *is* the report, and taking it is what makes the
            // report owed. Letting it go here turns a gap that was about to be
            // stated into one nobody can see — and this write fails precisely
            // when the buffer is already in trouble, which is when the marker
            // is worth the most. Handed back for the next flush to carry.
            self.dropped.fetch_add(dropped, Relaxed);
            self.unreadable.fetch_add(unreadable, Relaxed);
            return Err(e);
        }
        Ok(true)
    }

    /// Take the losses accumulated since the last call, and forget them.
    ///
    /// Draining rather than reading keeps the count exact across repeated
    /// flushes: whoever takes it owns the obligation to report it.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// Turn outstanding losses into an event, so a gap in the stream arrives at
    /// the collector as a statement rather than as an absence.
    fn loss_record(&self, reason: &str, count: u64, detail: String) -> Event {
        Event::new(
            "argus",
            None,
            None,
            crate::event::EventKind::Loss {
                reason: reason.into(),
                count,
                detail,
            },
        )
    }

    /// The oldest events, bounded by both a row count and a byte budget.
    ///
    /// The budget is computed in SQL rather than by parsing rows and adding
    /// them up, so an oversized backlog costs one query instead of a
    /// deserialize-then-discard pass over rows the batch cannot carry anyway.
    ///
    /// The first row is always returned, even when it alone exceeds the budget.
    /// A batch that would otherwise be empty is a queue that never moves: the
    /// oversized event would be re-peeked forever and everything behind it
    /// would age out. Sent alone, a collector that cannot take it refuses it,
    /// and a refusal is settled (see `export_once`) rather than retried.
    pub fn peek_batch(&self, n: usize, max_bytes: u64) -> Result<Vec<(i64, Event)>> {
        // Read out the rows, then drop the connection before parsing them.
        // Deserializing a full batch is the expensive half of this call, and
        // it needs no database at all — holding the lock across it stalls
        // every arriving event behind the export loop's JSON work.
        // 0 is the "no budget" spelling used by the size caps elsewhere in the
        // config, and SQLite's integers are signed, so both meet at i64::MAX.
        let budget = match max_bytes {
            0 => i64::MAX,
            n => n.min(i64::MAX as u64) as i64,
        };
        let rows: Vec<(i64, String)> = {
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            // `running` is monotonic over `seq`, so the rows that pass the
            // budget test are always a prefix — no gap can open in the middle
            // and hand the exporter a non-contiguous batch that `ack` would
            // then delete rows out of.
            let mut stmt = conn.prepare_cached(
                "SELECT seq, body FROM (
                     SELECT seq, body,
                            SUM(LENGTH(CAST(body AS BLOB))) OVER (ORDER BY seq ASC) AS running,
                            ROW_NUMBER() OVER (ORDER BY seq ASC) AS rn
                     FROM (SELECT seq, body FROM events ORDER BY seq ASC LIMIT ?1)
                 )
                 WHERE running <= ?2 OR rn = 1
                 ORDER BY seq ASC",
            )?;
            let mapped = stmt.query_map(rusqlite::params![n as i64, budget], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        // Structural guarantees are easy to undo by accident, so make this one
        // falsifiable: moving the parse back inside the block above trips here.
        #[cfg(test)]
        assert!(
            self.conn.try_lock().is_ok(),
            "peek_batch must not hold the connection while deserializing"
        );
        let mut out = Vec::with_capacity(rows.len());
        for (seq, body) in rows {
            match serde_json::from_str(&body) {
                Ok(e) => out.push((seq, e)),
                Err(err) => tracing::warn!("skipping corrupt buffered event seq={seq}: {err}"),
            }
        }
        Ok(out)
    }

    /// Settle everything up to `up_to_seq`, of which `delivered` rows actually
    /// reached the exporter.
    ///
    /// The two numbers differ when `peek_batch` could not parse a row: the
    /// delete is a range and takes the unparsed rows out with the batch that
    /// straddled them. Deleting them is right — a row that cannot be read will
    /// not become readable, and leaving it wedges the queue behind it — but it
    /// is the one loss nothing else counts, so it is counted here. `seq` only
    /// increases, so a row written after the peek can never fall inside the
    /// range and be miscounted as one of them.
    pub fn ack(&self, up_to_seq: i64, delivered: usize) -> Result<()> {
        let deleted = self
            .conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .execute("DELETE FROM events WHERE seq <= ?1", [up_to_seq])?;
        let unread = deleted.saturating_sub(delivered) as u64;
        if unread > 0 {
            self.unreadable
                .fetch_add(unread, std::sync::atomic::Ordering::Relaxed);
            self.unreadable_total
                .fetch_add(unread, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Losses since this daemon started, for the heartbeat to state.
    ///
    /// Read-only, unlike [`Buffer::take_dropped`] and
    /// [`Buffer::flush_loss_record`]: a heartbeat must be able to say how much
    /// has been lost without becoming the thing that owes the loss record.
    pub fn loss_totals(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.dropped_total.load(Relaxed),
            self.unreadable_total.load(Relaxed),
        )
    }

    /// Stored body bytes, as the byte cap sees them.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// This install's identity, minted on first use and kept in the `meta`
    /// table of the event database.
    ///
    /// In the database rather than a sidecar file on purpose: the identity has
    /// to reset *exactly* when the evidence does. A user who deletes the data
    /// directory to shed their history then reports a new `install_id` under an
    /// unchanged `host.name`, which is a fact a collector can alert on; an
    /// identity that outlived the buffer would make the wipe invisible, and one
    /// that reset more eagerly would cry wolf on every upgrade.
    pub fn install_id(&self) -> Result<String> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // Mint-then-read rather than read-then-mint: `OR IGNORE` makes the
        // insert lose harmlessly against another process that got there first,
        // so the following read returns the winner's id either way. Two daemons
        // on one data dir are already excluded by the socket, but a `check`
        // running alongside one is not.
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![K_INSTALL_ID, uuid::Uuid::new_v4().to_string()],
        )?;
        Ok(conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [K_INSTALL_ID],
            |r| r.get(0),
        )?)
    }

    /// The sequence number for the batch ending at row `last_row`, allocating a
    /// new one only when this is not the batch already outstanding.
    ///
    /// Numbering *batches* rather than attempts is what makes the sequence
    /// readable at the far end. A retry of an unacked batch repeats its number,
    /// so at-least-once delivery does not look like a gap; and because a number
    /// is allocated before the send and `seq` never rewinds, a batch that left
    /// this daemon and never arrived leaves a hole nothing else would show —
    /// the collector's own view cannot distinguish a dropped batch from a quiet
    /// hour. A reset to 1 under an unchanged host is the wiped-database signal,
    /// since this counter lives in the database it counts.
    pub fn batch_seq_for(&self, last_row: i64) -> Result<u64> {
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let get = |key: &str| -> Result<Option<i64>> {
            Ok(tx
                .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .and_then(|v| v.parse().ok()))
        };
        let seq = match get(K_BATCH_ROW)? {
            Some(row) if row == last_row => get(K_BATCH_SEQ)?.unwrap_or(1) as u64,
            _ => {
                let next = get(K_BATCH_SEQ)?.unwrap_or(0).saturating_add(1);
                let mut set = tx.prepare_cached(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )?;
                set.execute(rusqlite::params![K_BATCH_SEQ, next.to_string()])?;
                set.execute(rusqlite::params![K_BATCH_ROW, last_row.to_string()])?;
                drop(set);
                next as u64
            }
        };
        tx.commit()?;
        Ok(seq)
    }

    pub fn len(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(count as u64)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// `LENGTH` on a TEXT value counts *characters*, and every size in this file is
/// quoted in bytes — to the user in `buffer.max_bytes`, and to a collector that
/// rejects on request size. A buffer of CJK or emoji-bearing prompts was
/// therefore holding several times the bytes it was told to — three per
/// character for CJK, four for an emoji, each of which `LENGTH` counts as one.
/// The `CAST` to BLOB is what makes it count octets.
fn total_bytes(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(CAST(body AS BLOB))), 0) FROM events",
        [],
        |r| r.get(0),
    )?;
    Ok(n as u64)
}

/// Drop the oldest rows until the retained ones fit inside `max_bytes`.
///
/// The running sum is taken newest-first, so every row whose sum has already
/// passed the cap is older than the cap allows; the newest such row is the
/// cut line. `MAX(seq)` is NULL when nothing exceeds the cap, and `seq <= NULL`
/// matches nothing, so the ordinary under-cap case deletes zero rows.
///
/// The newest row is exempt. A single event larger than the whole cap would
/// otherwise delete itself and leave an empty buffer, which is the one outcome
/// worse than storing it — same reasoning as the `max_events.max(1)` clamp.
fn trim_to_bytes(conn: &Connection, max_bytes: u64) -> Result<usize> {
    Ok(conn
        .prepare_cached(
            "DELETE FROM events
             WHERE seq < (SELECT MAX(seq) FROM events)
               AND seq <= (
                   SELECT MAX(seq) FROM (
                       SELECT seq, SUM(LENGTH(CAST(body AS BLOB))) OVER (ORDER BY seq DESC) AS running
                       FROM events
                   ) WHERE running > ?1
               )",
        )?
        .execute([max_bytes as i64])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BufferCfg;
    use crate::event::{Event, EventKind};

    /// A row cap with the byte cap parked out of the way, so a test that means
    /// to exercise one is never quietly failed by the other.
    fn rows(max_events: u64) -> BufferCfg {
        BufferCfg {
            max_events,
            max_bytes: u64::MAX,
        }
    }

    fn tmp() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        dir
    }

    fn ev(n: u32) -> Event {
        Event::new(
            "claude-code",
            None,
            None,
            EventKind::Prompt {
                text: format!("p{n}"),
            },
        )
    }

    #[test]
    fn push_peek_ack_cycle() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(1000)).unwrap();
        for i in 0..5 {
            b.push(&ev(i)).unwrap();
        }
        let batch = b.peek_batch(3, 0).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(b.len().unwrap(), 5, "peek must not delete");
        b.ack(batch.last().unwrap().0, batch.len()).unwrap();
        assert_eq!(b.len().unwrap(), 2);
    }

    #[test]
    fn cap_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(3)).unwrap();
        for i in 0..5 {
            b.push(&ev(i)).unwrap();
        }
        assert_eq!(b.len().unwrap(), 3);
        let batch = b.peek_batch(10, 0).unwrap();
        let first = serde_json::to_string(&batch[0].1).unwrap();
        assert!(first.contains("p2"), "oldest two dropped, got {first}");
    }

    #[test]
    fn max_events_zero_is_clamped_not_wiped() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(0)).unwrap();
        for i in 0..3 {
            b.push(&ev(i)).unwrap();
        }
        assert!(
            b.len().unwrap() >= 1,
            "max_events=0 must not delete every row on push"
        );
    }

    #[test]
    fn a_batch_costs_one_trim_and_still_honours_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(3)).unwrap();
        let batch: Vec<Event> = (0..5).map(ev).collect();
        TRIMS.store(0, std::sync::atomic::Ordering::Relaxed);
        b.push_batch(&batch).unwrap();
        assert_eq!(
            TRIMS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one trim per batch, not one per event"
        );
        assert_eq!(b.len().unwrap(), 3, "the cap still holds across a batch");
        let kept = b.peek_batch(10, 0).unwrap();
        let first = serde_json::to_string(&kept[0].1).unwrap();
        assert!(first.contains("p2"), "oldest two dropped, got {first}");
    }

    /// The cap is not a bug, but a cap that hides its own effect is. Whatever
    /// the buffer destroys has to be countable afterwards.
    #[test]
    fn overflow_is_counted_exactly() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(3)).unwrap();
        for i in 0..5 {
            b.push(&ev(i)).unwrap();
        }
        assert!(
            b.flush_loss_record().unwrap(),
            "two events were destroyed and nothing said so"
        );
        let loss = b
            .peek_batch(10, 0)
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .find(|e| matches!(e.kind, EventKind::Loss { .. }))
            .expect("the record must be queued, not merely returned");
        match loss.kind {
            EventKind::Loss {
                reason,
                count,
                detail,
            } => {
                assert_eq!(count, 2, "one record per lost event, not per trim");
                assert_eq!(reason, "buffer_full");
                assert!(detail.contains('3'), "the cap belongs in the record");
            }
            other => panic!("expected a loss record, got {other:?}"),
        }
    }

    /// Taken, not read: the same gap reported on every flush would turn one
    /// incident into a permanent alarm.
    #[test]
    fn a_loss_is_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(1)).unwrap();
        b.push(&ev(0)).unwrap();
        b.push(&ev(1)).unwrap();
        assert!(b.flush_loss_record().unwrap());
        assert!(
            !b.flush_loss_record().unwrap(),
            "the marker's own displacement must not re-report as a new gap"
        );
    }

    #[test]
    fn a_buffer_within_its_cap_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(1000)).unwrap();
        for i in 0..5 {
            b.push(&ev(i)).unwrap();
        }
        assert!(
            !b.flush_loss_record().unwrap(),
            "nothing was lost to report"
        );
    }

    /// The count *is* the report. Taking it and then failing to write the
    /// marker turns a reported gap into a silent one — and the write fails
    /// exactly when the buffer is already in trouble, which is when the marker
    /// is worth the most.
    #[test]
    fn a_loss_count_survives_a_failed_marker_write() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1)).unwrap();
        b.push(&ev(0)).unwrap();
        b.push(&ev(1)).unwrap();

        {
            let conn = b.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute_batch("PRAGMA query_only = ON").unwrap();
        }
        assert!(
            b.flush_loss_record().is_err(),
            "a read-only database accepted a write"
        );
        {
            let conn = b.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute_batch("PRAGMA query_only = OFF").unwrap();
        }

        assert!(
            b.flush_loss_record().unwrap(),
            "the gap went unreported once its marker failed to be written"
        );
        let loss = b
            .peek_batch(10, 0)
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .find(|e| matches!(e.kind, EventKind::Loss { .. }))
            .expect("no loss record was queued");
        let EventKind::Loss { count, .. } = loss.kind else {
            unreachable!()
        };
        assert_eq!(count, 1, "the count came back wrong");
    }

    /// A row `peek_batch` could not parse is deleted by the `ack` that settles
    /// the batch around it. It was never exported and nothing else counts it,
    /// so without this the gap is the one kind the buffer cannot see: a
    /// disappearance with no record and no number.
    #[test]
    fn a_row_that_could_not_be_read_is_still_reported_as_lost() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        b.push(&ev(1)).unwrap();
        {
            let conn = b.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute("INSERT INTO events (body) VALUES ('not json')", [])
                .unwrap();
        }
        b.push(&ev(2)).unwrap();

        let batch = b.peek_batch(10, 0).unwrap();
        assert_eq!(batch.len(), 2, "corrupt row skipped, valid rows returned");
        let last = batch.last().unwrap().0;
        b.ack(last, batch.len()).unwrap();
        assert_eq!(b.len().unwrap(), 0, "the range delete left rows behind");

        assert!(
            b.flush_loss_record().unwrap(),
            "the corrupt row went unsaid"
        );
        let loss = b
            .peek_batch(10, 0)
            .unwrap()
            .into_iter()
            .map(|(_, e)| e)
            .find(|e| matches!(e.kind, EventKind::Loss { .. }))
            .expect("no loss record was queued");
        let EventKind::Loss { count, reason, .. } = loss.kind else {
            unreachable!()
        };
        assert_eq!(count, 1);
        assert_eq!(
            reason, "buffer_unreadable",
            "an unreadable row is not the capacity cap and must not read as it"
        );
    }

    /// An ack that deletes exactly what was delivered has lost nothing, and
    /// saying otherwise would put a permanent false alarm on every healthy
    /// export cycle.
    #[test]
    fn an_ordinary_ack_reports_no_loss() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        for i in 0..5 {
            b.push(&ev(i)).unwrap();
        }
        let batch = b.peek_batch(10, 0).unwrap();
        b.ack(batch.last().unwrap().0, batch.len()).unwrap();
        assert!(!b.flush_loss_record().unwrap(), "nothing was lost");
    }

    /// The running byte total may drift, but only upward — an overestimate
    /// costs a recount, an underestimate silently overshoots the cap and the
    /// buffer stops being bounded by the thing it is configured by.
    ///
    /// A transaction that fails to commit rolls its trim back with everything
    /// else, so a total read from *inside* it describes a database state that
    /// never existed — and it is always the smaller one, because the read
    /// happens after the trim.
    ///
    /// Forcing a commit to fail takes a deferred foreign key: SQLite checks
    /// those at `COMMIT` and nowhere earlier, so every statement in the
    /// transaction succeeds and the commit is what refuses.
    #[test]
    fn a_failed_commit_does_not_drift_the_byte_total_downward() {
        use std::sync::atomic::Ordering::Relaxed;
        let _dir = tmp();
        std::fs::create_dir_all(crate::paths::data_dir()).unwrap();
        // The only failure SQLite lets a test inject at COMMIT rather than at
        // the statement: a deferred foreign key. Every row `append` writes
        // points at `parents(999)`, so the commit refuses the moment that
        // parent stops existing.
        {
            let conn = Connection::open(crate::paths::db_path()).unwrap();
            conn.execute_batch(
                "CREATE TABLE parents (id INTEGER PRIMARY KEY);
                 INSERT INTO parents (id) VALUES (1), (999);
                 CREATE TABLE events (
                     seq INTEGER PRIMARY KEY AUTOINCREMENT,
                     body TEXT NOT NULL,
                     parent INTEGER NOT NULL DEFAULT 999
                         REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED
                 );",
            )
            .unwrap();
        }
        let b = Buffer::open(&BufferCfg {
            max_events: 1_000_000,
            max_bytes: u64::MAX,
        })
        .unwrap();
        // The setup runs with the parent present and foreign keys on, which
        // matters twice: `append` caches its INSERT, and SQLite compiles the
        // key check into that cached statement. Filling the buffer with the
        // checks off would cache a statement that has none, and the push below
        // would quietly succeed.
        for i in 0..40 {
            b.push(&ev(i)).unwrap();
        }
        let on_disk = total_bytes(&b.conn.lock().unwrap()).unwrap();
        assert!(on_disk > 0, "the setup stored nothing to trim");
        // Dropped only now, so the doomed push below trims nearly everything.
        // Filling against the final cap would leave the stored bytes and the
        // post-trim count within a row of each other, and a drift that small
        // proves nothing.
        b.set_limits(&BufferCfg {
            max_events: 1_000_000,
            max_bytes: 100,
        });

        // Re-point the stored rows at a parent that stays, then retire 999.
        // Leaving them orphaned instead would defuse the whole test: the trim
        // below deletes them inside the same transaction, and SQLite credits
        // each deleted orphan back against the deferred counter, so the one
        // violation this test needs would net out to zero and commit.
        b.conn
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE events SET parent = 1;
                 DELETE FROM parents WHERE id = 999;",
            )
            .unwrap();
        assert!(
            b.push(&ev(99)).is_err(),
            "the deferred constraint did not refuse the commit"
        );

        assert_eq!(
            total_bytes(&b.conn.lock().unwrap()).unwrap(),
            on_disk,
            "the failed transaction was not rolled back"
        );
        let running = b.bytes.load(Relaxed);
        assert!(
            running >= on_disk,
            "the running total drifted down to {running} against {on_disk} bytes on disk, \
             so the byte cap now trims late"
        );
    }

    #[test]
    fn corrupt_row_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(&rows(1000)).unwrap();
        b.push(&ev(1)).unwrap();
        {
            let conn = b.conn.lock().unwrap_or_else(|e| e.into_inner());
            conn.execute("INSERT INTO events (body) VALUES ('not json')", [])
                .unwrap();
        }
        b.push(&ev(2)).unwrap();
        let batch = b.peek_batch(10, 0).unwrap();
        assert_eq!(batch.len(), 2, "corrupt row skipped, valid rows returned");
    }

    /// The byte cap exists because the row cap is not a disk bound: 100k rows
    /// of pasted file contents is a different quantity of disk from 100k rows
    /// of prompts, and only one of them fits.
    #[test]
    fn the_byte_cap_binds_when_the_row_cap_does_not() {
        let _dir = tmp();
        let b = Buffer::open(&BufferCfg {
            max_events: 1_000_000,
            max_bytes: 600,
        })
        .unwrap();
        for i in 0..40 {
            b.push(&ev(i)).unwrap();
        }
        let stored = total_bytes(&b.conn.lock().unwrap()).unwrap();
        assert!(
            stored <= 600,
            "the row cap was nowhere near binding and {stored} bytes were kept"
        );
        assert!(b.len().unwrap() > 0, "the trim emptied the buffer outright");
        assert!(
            b.take_dropped() > 0,
            "rows destroyed by the byte cap are still rows destroyed"
        );
    }

    /// One event larger than the entire cap would otherwise delete itself and
    /// leave nothing behind — the one outcome worse than storing it.
    #[test]
    fn an_event_too_large_for_the_cap_is_kept_rather_than_lost() {
        let _dir = tmp();
        let b = Buffer::open(&BufferCfg {
            max_events: 1000,
            max_bytes: 1,
        })
        .unwrap();
        b.push(&ev(1)).unwrap();
        b.push(&ev(2)).unwrap();
        assert_eq!(b.len().unwrap(), 1, "the newest event must survive");
    }

    /// The stored size of a peeked row.
    fn body_len(row: &(i64, Event)) -> u64 {
        serde_json::to_string(&row.1).unwrap().len() as u64
    }

    /// An event whose serialized body is one prompt of `n` euro signs: three
    /// bytes per character, so byte and character counts diverge by design.
    fn multibyte(n: usize) -> Event {
        Event::new(
            "claude-code",
            None,
            None,
            EventKind::Prompt {
                text: "€".repeat(n),
            },
        )
    }

    /// A batch is bounded by bytes as well as by rows, because a collector
    /// rejects on request size and 256 events say nothing about it.
    #[test]
    fn a_batch_stops_at_the_byte_budget() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        for i in 0..10 {
            b.push(&ev(i)).unwrap();
        }
        // Summed from the stored bodies rather than assumed uniform: a
        // timestamp serializes to a different width from one event to the next.
        let three: u64 = b.peek_batch(3, 0).unwrap().iter().map(body_len).sum();

        let batch = b.peek_batch(10, three).unwrap();
        assert_eq!(batch.len(), 3, "the budget, not the row cap, must bind");
        assert_eq!(batch[0].0, 1, "and it must be the oldest events");
        assert_eq!(
            b.peek_batch(2, three).unwrap().len(),
            2,
            "the row cap still binds when it is the tighter of the two"
        );
        assert_eq!(b.peek_batch(10, 0).unwrap().len(), 10, "0 = no budget");
    }

    /// A single event over the whole budget must still leave, or the queue
    /// stops: it would be re-peeked forever and everything behind it would age
    /// out. Alone, a collector that cannot take it refuses it, and a refusal is
    /// settled rather than retried.
    #[test]
    fn an_event_larger_than_the_budget_is_sent_alone_rather_than_stuck() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        b.push(&multibyte(4096)).unwrap();
        b.push(&ev(2)).unwrap();
        let batch = b.peek_batch(10, 1).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].0, 1, "the head of the queue, not a smaller row");
    }

    /// Every size here is quoted in bytes — to the operator in
    /// `buffer.max_bytes`, and to a collector that rejects on request size.
    /// SQLite's `LENGTH` counts characters, so a buffer of CJK or emoji-bearing
    /// prompts held several times what it was told to — three bytes per
    /// character for CJK, four for an emoji.
    #[test]
    fn sizes_are_counted_in_bytes_not_characters() {
        let _dir = tmp();
        let e = multibyte(1000);
        let body = serde_json::to_string(&e).unwrap();
        let (bytes, chars) = (body.len() as u64, body.chars().count() as u64);
        assert!(bytes > chars, "the fixture must actually be multi-byte");

        let b = Buffer::open(&rows(1000)).unwrap();
        b.push(&e).unwrap();
        b.push(&e).unwrap();
        assert_eq!(
            b.peek_batch(10, chars * 2).unwrap().len(),
            1,
            "a budget of two bodies' worth of characters holds one body"
        );

        // …and the same for the cap that decides what is kept at all.
        let capped = Buffer::open(&BufferCfg {
            max_events: 1_000_000,
            max_bytes: chars * 2,
        })
        .unwrap();
        capped.push(&e).unwrap();
        capped.push(&e).unwrap();
        assert_eq!(
            capped.len().unwrap(),
            1,
            "the byte cap kept two bodies it was told were too big"
        );
    }

    /// The in-memory running total is seeded and re-seeded from this query,
    /// and it is allowed to drift only *upward*: an overestimate costs an early
    /// trim, an underestimate silently holds more than the cap allows.
    #[test]
    fn the_running_byte_total_is_measured_in_bytes() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        let mut expected = 0u64;
        for n in [400, 800, 1200] {
            let e = multibyte(n);
            expected += serde_json::to_string(&e).unwrap().len() as u64;
            b.push(&e).unwrap();
        }
        assert_eq!(
            total_bytes(&b.conn.lock().unwrap()).unwrap(),
            expected,
            "the total the cap is compared against must be the total on disk"
        );
    }

    /// A cap that only applies at startup is no use to the operator raising it
    /// *because* the buffer is overflowing.
    #[test]
    fn a_reloaded_cap_takes_effect_without_a_restart() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        for i in 0..10 {
            b.push(&ev(i)).unwrap();
        }
        assert_eq!(b.len().unwrap(), 10);
        b.set_limits(&rows(3));
        b.push(&ev(99)).unwrap();
        assert_eq!(b.len().unwrap(), 3, "the reloaded row cap was ignored");

        b.set_limits(&BufferCfg {
            max_events: 0,
            max_bytes: 0,
        });
        b.push(&ev(100)).unwrap();
        assert_eq!(
            b.len().unwrap(),
            1,
            "a zero cap must clamp, not switch the audit trail off"
        );
    }

    /// The running byte total is deliberately allowed to drift upward, so the
    /// cap has to hold across a buffer reopened on an existing database too.
    #[test]
    fn a_reopened_buffer_counts_what_is_already_there() {
        let _dir = tmp();
        let cfg = BufferCfg {
            max_events: 1_000_000,
            max_bytes: 600,
        };
        {
            let b = Buffer::open(&rows(1_000_000)).unwrap();
            for i in 0..40 {
                b.push(&ev(i)).unwrap();
            }
            assert!(total_bytes(&b.conn.lock().unwrap()).unwrap() > 600);
        }
        let b = Buffer::open(&cfg).unwrap();
        b.push(&ev(99)).unwrap();
        let stored = total_bytes(&b.conn.lock().unwrap()).unwrap();
        assert!(
            stored <= 600,
            "a restart started the byte count from zero and kept {stored} bytes"
        );
    }

    /// The identity has to be worth reporting: constant for one install so a
    /// collector can key on it, and reissued the moment the evidence it names
    /// is destroyed. Deleting the data directory is the cheapest way to shed a
    /// history, and this is what makes it visible.
    #[test]
    fn a_wiped_database_mints_a_new_install_id() {
        let dir = tmp();
        let first = {
            let b = Buffer::open(&rows(1000)).unwrap();
            let id = b.install_id().unwrap();
            assert_eq!(
                b.install_id().unwrap(),
                id,
                "the identity changed between two reads of one install"
            );
            id
        };
        {
            let b = Buffer::open(&rows(1000)).unwrap();
            assert_eq!(
                b.install_id().unwrap(),
                first,
                "a restart looks like a fresh install"
            );
        }
        // `rm -rf ~/.local/share/argus`, which is the whole of the attack.
        std::fs::remove_dir_all(dir.path()).unwrap();
        let b = Buffer::open(&rows(1000)).unwrap();
        assert_ne!(
            b.install_id().unwrap(),
            first,
            "a wiped database kept its identity, so the wipe is invisible"
        );
    }

    /// Numbers batches, not attempts. A retry has to repeat its number or
    /// at-least-once delivery would look like tampering, and a number must be
    /// spent before the send or a destroyed batch would leave no hole.
    #[test]
    fn a_retry_repeats_its_batch_number_and_a_new_batch_takes_the_next() {
        let _dir = tmp();
        let b = Buffer::open(&rows(1000)).unwrap();
        for i in 0..6 {
            b.push(&ev(i)).unwrap();
        }
        let first = b.peek_batch(3, 0).unwrap();
        let last = first.last().unwrap().0;
        let seq = b.batch_seq_for(last).unwrap();
        assert_eq!(seq, 1, "the first batch of a fresh install is not 1");
        assert_eq!(
            b.batch_seq_for(last).unwrap(),
            seq,
            "a retry of an unacked batch was given a new number"
        );
        b.ack(last, first.len()).unwrap();
        let next = b.peek_batch(3, 0).unwrap();
        assert_eq!(
            b.batch_seq_for(next.last().unwrap().0).unwrap(),
            seq + 1,
            "a genuinely new batch reused the previous number"
        );
    }

    /// A batch this daemon numbered and then lost has to leave a hole the
    /// collector can see — that is the only server-side evidence of a batch
    /// destroyed between the send and the ack.
    #[test]
    fn a_batch_that_never_ships_leaves_a_gap_and_a_wipe_resets_the_run() {
        let dir = tmp();
        let (a, c) = {
            let b = Buffer::open(&rows(1000)).unwrap();
            for i in 0..9 {
                b.push(&ev(i)).unwrap();
            }
            let one = b.peek_batch(3, 0).unwrap();
            let a = b.batch_seq_for(one.last().unwrap().0).unwrap();
            b.ack(one.last().unwrap().0, one.len()).unwrap();
            // Batch two is numbered and then simply never acknowledged nor
            // delivered — the shape of a batch dropped in flight.
            let two = b.peek_batch(3, 0).unwrap();
            let _lost = b.batch_seq_for(two.last().unwrap().0).unwrap();
            b.ack(two.last().unwrap().0, two.len()).unwrap();
            let three = b.peek_batch(3, 0).unwrap();
            let c = b.batch_seq_for(three.last().unwrap().0).unwrap();
            (a, c)
        };
        assert_eq!(
            c - a,
            2,
            "the numbers the collector sees are contiguous, so a lost batch cannot be spotted"
        );
        // `rm -rf ~/.local/share/argus`, which is the whole of the attack.
        std::fs::remove_dir_all(dir.path()).unwrap();
        let b = Buffer::open(&rows(1000)).unwrap();
        b.push(&ev(0)).unwrap();
        let batch = b.peek_batch(1, 0).unwrap();
        assert_eq!(
            b.batch_seq_for(batch.last().unwrap().0).unwrap(),
            1,
            "the sequence outlived the database it counts"
        );
    }

    /// The `loss` table is the one query that tells an operator whether the rest
    /// of the database is the whole story, and the docs enumerate its `reason`
    /// values as if the list were closed. A reason the code emits and the page
    /// omits is a loss that reads as no loss at all.
    #[test]
    fn every_loss_reason_the_code_emits_is_documented() {
        const EMITTED: &[&str] = &[
            "buffer_full",
            "buffer_unreadable",
            "spool_full",
            "stdin_truncated",
            "export_rejected",
        ];
        let doc = include_str!("../docs/querying-local-database.md");
        for reason in EMITTED {
            assert!(
                doc.contains(reason),
                "docs/querying-local-database.md never mentions the `{reason}` \
                 loss reason, so a reader's query will not branch on it"
            );
        }
    }
}
