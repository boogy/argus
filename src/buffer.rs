use crate::event::Event;
use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;

pub struct Buffer {
    conn: Mutex<Connection>,
    max_events: u64,
}

/// Counts trim queries. The trim is the expensive part of a write, and a
/// batch that trims once looks identical from the outside to one that trims
/// per event — so the cost has to be counted to be asserted on.
#[cfg(test)]
static TRIMS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Buffer {
    pub fn open(max_events: u64) -> Result<Self> {
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
        Ok(Buffer {
            conn: Mutex::new(conn),
            max_events,
        })
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
        if events.is_empty() {
            return Ok(());
        }
        // A poisoned lock only means a panic elsewhere mid-operation; the SQLite connection itself is still usable.
        let mut conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("INSERT INTO events (body) VALUES (?1)")?;
            for e in events {
                stmt.execute([serde_json::to_string(e)?])?;
            }
            #[cfg(test)]
            TRIMS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tx.prepare_cached(
                "DELETE FROM events WHERE seq <= (
                    SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1
                )",
            )?
            .execute([self.max_events as i64])?;
        }
        tx.commit()?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind};

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
        let b = Buffer::open(1000).unwrap();
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
        let b = Buffer::open(3).unwrap();
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
        let b = Buffer::open(0).unwrap();
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
        let b = Buffer::open(3).unwrap();
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

    #[test]
    fn corrupt_row_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let b = Buffer::open(1000).unwrap();
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
}
