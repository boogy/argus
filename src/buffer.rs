use crate::event::Event;
use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;

pub struct Buffer {
    conn: Mutex<Connection>,
    max_events: u64,
}

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
        // A poisoned lock only means a panic elsewhere mid-operation; the SQLite connection itself is still usable.
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO events (body) VALUES (?1)",
            [serde_json::to_string(e)?],
        )?;
        conn.execute(
            "DELETE FROM events WHERE seq <= (
                SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1
            )",
            [self.max_events as i64],
        )?;
        Ok(())
    }

    pub fn peek_batch(&self, n: usize) -> Result<Vec<(i64, Event)>> {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT seq, body FROM events ORDER BY seq ASC LIMIT ?1")?;
        let rows = stmt.query_map([n as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, body) = row?;
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
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
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
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
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
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
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
    fn corrupt_row_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
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
