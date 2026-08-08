use crate::event::Event;
use anyhow::Result;
use rusqlite::Connection;
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
}

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
        std::fs::create_dir_all(&data_dir)?;
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(
                &data_dir,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
        }
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
            );",
        )?;
        let bytes = total_bytes(&conn)?;
        Ok(Buffer {
            conn: Mutex::new(conn),
            max_events: std::sync::atomic::AtomicU64::new(max_events),
            max_bytes: std::sync::atomic::AtomicU64::new(cfg.max_bytes.max(1)),
            bytes: std::sync::atomic::AtomicU64::new(bytes),
            dropped: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Adopt the caps from a reloaded config.
    ///
    /// Same clamps as `open`: a cap of zero would empty the buffer on every
    /// write, which is a config typo away from turning the audit trail off.
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
        if self.bytes.fetch_add(added, Relaxed) + added > max_bytes {
            trimmed += trim_to_bytes(&tx, max_bytes)?;
            self.bytes.store(total_bytes(&tx)?, Relaxed);
        }
        tx.commit()?;
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
        let Some(loss) = self.loss_record() else {
            return Ok(false);
        };
        self.append(std::slice::from_ref(&loss))?;
        Ok(true)
    }

    /// Take the losses accumulated since the last call, and forget them.
    ///
    /// Draining rather than reading keeps the count exact across repeated
    /// flushes: whoever takes it owns the obligation to report it.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// Turn any outstanding losses into an event, so a gap in the stream
    /// arrives at the collector as a statement rather than as an absence.
    fn loss_record(&self) -> Option<Event> {
        let count = self.take_dropped();
        (count > 0).then(|| {
            Event::new(
                "argus",
                None,
                None,
                crate::event::EventKind::Loss {
                    reason: "buffer_full".into(),
                    count,
                    detail: format!(
                        "local buffer at capacity ({} events / {} bytes); oldest dropped \
                         before export",
                        self.max_events.load(std::sync::atomic::Ordering::Relaxed),
                        self.max_bytes.load(std::sync::atomic::Ordering::Relaxed)
                    ),
                },
            )
        })
    }

    pub fn peek_batch(&self, n: usize) -> Result<Vec<(i64, Event)>> {
        // Read out the rows, then drop the connection before parsing them.
        // Deserializing a full batch is the expensive half of this call, and
        // it needs no database at all — holding the lock across it stalls
        // every arriving event behind the export loop's JSON work.
        let rows: Vec<(i64, String)> = {
            let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
            let mut stmt =
                conn.prepare_cached("SELECT seq, body FROM events ORDER BY seq ASC LIMIT ?1")?;
            let mapped = stmt.query_map([n as i64], |row| {
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

    pub fn ack(&self, up_to_seq: i64) -> Result<()> {
        self.conn
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .execute("DELETE FROM events WHERE seq <= ?1", [up_to_seq])?;
        Ok(())
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

fn total_bytes(conn: &Connection) -> Result<u64> {
    let n: i64 = conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(body)), 0) FROM events",
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
                       SELECT seq, SUM(LENGTH(body)) OVER (ORDER BY seq DESC) AS running
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
        let batch = b.peek_batch(3).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(b.len().unwrap(), 5, "peek must not delete");
        b.ack(batch.last().unwrap().0).unwrap();
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
        let batch = b.peek_batch(10).unwrap();
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
        let kept = b.peek_batch(10).unwrap();
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
            .peek_batch(10)
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
        let batch = b.peek_batch(10).unwrap();
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
}
