use crate::event::Envelope;
use crate::paths;
use anyhow::Result;

pub fn append(envelope: &Envelope) -> Result<()> {
    let dir = paths::spool_dir();
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        // Spooled envelopes hold raw, un-redacted payloads (prompts, tool
        // inputs) until the daemon can process them; keep the directory and
        // each file owner-only.
        let _ = std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    }
    let file = dir.join(format!("{}.jsonl", uuid::Uuid::new_v4()));
    std::fs::write(&file, serde_json::to_vec(envelope)?)?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    }
    Ok(())
}

/// How many spool files one pass takes.
///
/// The daemon replays these on its own event loop, synchronously, so an
/// unbounded pass would stall every live envelope behind a backlog that — on a
/// machine where the daemon has been down for a day — is tens of thousands of
/// files. Bounded, a backlog drains over several passes and live traffic keeps
/// flowing alongside it.
pub const DRAIN_BATCH: usize = 256;

/// Take up to `limit` spooled envelopes, oldest first, **leaving the files in
/// place**.
///
/// The caller deletes them with [`discard`], and only once they are durably in
/// the buffer. The previous code deleted first and returned the envelope
/// afterwards, which made the spool — the thing that exists so a daemon outage
/// costs nothing — the one place where a crash cost everything in flight: the
/// file was gone and the event had not yet reached SQLite. Delete-after-commit
/// can duplicate an event if the process dies in the window between, and the
/// pipeline is at-least-once delivery already; delete-before-commit can only
/// lose one.
///
/// A file that cannot be parsed is deleted here, since no amount of retrying
/// will commit it. It is the one case where this function destroys anything.
pub fn take(limit: usize) -> Vec<(std::path::PathBuf, Envelope)> {
    let dir = paths::spool_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    // Oldest first: the spool is a timeline, and a backlog drained newest-first
    // would keep re-reading the same tail while the oldest files starve behind
    // the batch bound. Names are UUIDs and carry no order, so mtime it is.
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .map(|p| {
            let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
            (mtime, p)
        })
        .collect();
    files.sort_by_key(|f| f.0);

    let mut out = Vec::new();
    for (_, path) in files {
        if out.len() >= limit {
            break;
        }
        match std::fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|s| serde_json::from_str::<Envelope>(&s).map_err(Into::into))
        {
            Ok(env) => out.push((path, env)),
            Err(e) => {
                tracing::warn!("dropping bad spool file {path:?}: {e}");
                if let Err(del_err) = std::fs::remove_file(&path) {
                    tracing::warn!("failed to delete corrupt spool file {path:?}: {del_err}");
                }
            }
        }
    }
    out
}

/// Delete a spool file whose envelope is now committed to the buffer.
///
/// A failure here is logged and otherwise ignored: the file stays, and the
/// envelope is replayed on the next pass. A duplicate is the acceptable half
/// of at-least-once.
pub fn discard(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!("failed to delete spool file {path:?}: {e}");
    }
}

/// Take *and* delete everything, in one call.
///
/// Only safe where the caller cannot lose what it is handed — tests, and the
/// `status` view. The daemon uses [`take`]/[`discard`] so a crash mid-replay
/// costs a duplicate rather than an event.
pub fn drain() -> Result<Vec<Envelope>> {
    Ok(take(usize::MAX)
        .into_iter()
        .map(|(path, env)| {
            discard(&path);
            env
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Envelope;

    fn setup() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        dir
    }

    #[test]
    fn append_then_drain_returns_envelope_and_empties_spool() {
        let _dir = setup();
        let env = Envelope {
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            event: None,
            payload: serde_json::json!({"k": "v"}),
        };
        append(&env).unwrap();
        append(&env).unwrap();
        let drained = drain().unwrap();
        assert_eq!(drained.len(), 2);
        assert!(drain().unwrap().is_empty());
    }

    /// The shim that notices the truncation and the daemon that reports it are
    /// different processes, so the flag is only worth anything if it survives
    /// the wire. It is skipped when false to keep the common envelope small,
    /// and that is exactly the kind of attribute that silently swallows the
    /// true case if it is written a shade too broadly.
    #[test]
    fn a_truncation_survives_the_spool() {
        let _dir = setup();
        let env = Envelope {
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: true,
            event: None,
            payload: serde_json::json!({"k": "v"}),
        };
        append(&env).unwrap();
        assert!(
            drain().unwrap()[0].truncated,
            "the daemon has no other way to know the payload was cut"
        );
    }

    /// An unbounded pass would stall every live envelope behind the backlog,
    /// and the backlog is largest exactly when the daemon has just come back.
    #[test]
    fn a_pass_is_bounded_and_takes_the_oldest_first() {
        let _dir = setup();
        for i in 0..5u32 {
            let env = Envelope {
                source: "codex".into(),
                received_at: chrono::Utc::now(),
                truncated: false,
                event: None,
                payload: serde_json::json!({ "n": i }),
            };
            append(&env).unwrap();
            // Coarse filesystem timestamps would make the sort meaningless.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let batch = take(2);
        assert_eq!(batch.len(), 2, "the batch bound was ignored");
        assert_eq!(batch[0].1.payload["n"], 0);
        assert_eq!(batch[1].1.payload["n"], 1);
        assert_eq!(
            take(usize::MAX).len(),
            5,
            "take must not delete what it hands out"
        );
    }

    #[cfg(unix)]
    #[test]
    fn spooled_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _dir = setup();
        let env = Envelope {
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            event: None,
            payload: serde_json::json!({"secret": "sk-raw"}),
        };
        append(&env).unwrap();
        let dir = crate::paths::spool_dir();
        let entry = std::fs::read_dir(&dir)
            .unwrap()
            .find_map(|e| e.ok())
            .expect("spool file was written");
        let mode = std::fs::metadata(entry.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "spool file must be owner-only");
    }

    #[test]
    fn unparseable_spool_file_is_deleted_and_skipped() {
        let _dir = setup();
        let dir = crate::paths::spool_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("garbage.jsonl"), "not json").unwrap();
        let drained = drain().unwrap();
        assert!(drained.is_empty());
        assert!(
            !dir.join("garbage.jsonl").exists(),
            "corrupt file must be deleted"
        );
    }
}
