use crate::event::Envelope;
use crate::paths;
use anyhow::Result;

/// Delete the oldest spool files until the directory has room for `incoming`
/// more bytes, and say how many were deleted.
///
/// Oldest-first for the same reason the buffer trims oldest-first: during the
/// incident this exists to record, the last minute matters more than the first.
/// The scan is one `read_dir` plus a `stat` per file, on every spooled write —
/// affordable precisely because the cap is what keeps the file count small.
/// Uncapped, the directory grows without bound and *every* later pass over it,
/// including the daemon's own replay, degrades with it.
///
/// An envelope larger than the whole cap is still written, after everything
/// else has been cleared out for it: refusing it would trade a bounded overrun
/// for a guaranteed hole, the same call the buffer's newest-row exemption makes.
fn enforce_cap(dir: &std::path::Path, incoming: u64, max_bytes: u64) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut files: Vec<_> = entries
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|e| {
            // A failed `metadata` means the file is gone — the daemon's
            // `discard` racing this read — so leaving it out is right.
            let m = e.metadata().ok()?;
            // A missing *mtime* is not the same: those bytes are still on the
            // disk. Dropping the file here would take it out of the total and
            // out of the eviction list at once, so it would push the spool
            // past its cap and stay there. Undated sorts oldest, which makes
            // it the first thing evicted instead of the one thing immortal.
            let mtime = m.modified().unwrap_or(std::time::UNIX_EPOCH);
            Some((mtime, e.file_name(), m.len(), e.path()))
        })
        .collect();
    let mut total: u64 = files.iter().map(|f| f.2).sum();
    if total + incoming <= max_bytes {
        return 0;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut dropped = 0;
    for (_, _, len, path) in files {
        if total + incoming <= max_bytes {
            break;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                total -= len;
                dropped += 1;
            }
            // Someone else's write is not this write's problem to solve, but
            // it does mean the cap is not being enforced — say so out loud
            // rather than spin.
            Err(e) => tracing::warn!("could not trim spool file {path:?}: {e}"),
        }
    }
    dropped
}

/// Write an envelope to the spool, first making room for it under
/// `spool.max_bytes`.
///
/// The cap comes from the config on every call rather than from anything
/// cached: the shim is a fresh process per hook, so it reads the operator's
/// current answer by construction — including one they changed *because* the
/// spool was filling their disk.
pub fn append(envelope: &Envelope) -> Result<()> {
    let dir = paths::spool_dir();
    // Spooled envelopes hold raw, un-redacted payloads (prompts, tool inputs)
    // until the daemon can process them; keep the directory and each file
    // owner-only, from the moment each exists.
    paths::create_private_dir(&dir)?;
    let mut body = serde_json::to_vec(envelope)?;
    // No `.max(1)` clamp here, unlike the buffer's: the newest envelope is
    // written whatever the cap says, so `max_bytes = 0` already means "hold
    // exactly one file" rather than "capture nothing". A clamp that changes no
    // observable behavior is a guarantee nothing can test.
    let dropped = enforce_cap(
        &dir,
        body.len() as u64,
        crate::config::load().spool.max_bytes,
    );
    if dropped > 0 {
        // Re-serialize rather than patch: the count is only knowable after the
        // trim, and this envelope is the only messenger the shim has. Nothing
        // else will ever mention those files again.
        let mut envelope = envelope.clone();
        envelope.dropped += dropped;
        body = serde_json::to_vec(&envelope)?;
    }
    let file = dir.join(spool_name());
    paths::write_private(&file, &body)?;
    Ok(())
}

/// A spool file name that carries its own place in the timeline.
///
/// The sort that replays these leads on mtime, which is not enough on its own:
/// Windows takes last-write-time from the ~15 ms system clock tick, so a burst
/// of spooled envelopes — precisely what a daemon outage produces — lands with
/// identical timestamps and would otherwise replay in whatever order `read_dir`
/// happened to yield. The name breaks that tie, so it is built to sort:
/// nanoseconds since the epoch first, then a per-process counter that separates
/// two writes a coarse clock reported at the same instant, then a UUID so two
/// processes spooling together still get distinct files.
///
/// Zero-padded because the sort is lexicographic; the nanosecond field stays
/// nineteen digits until the year 2262.
fn spool_name() -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{nanos:019}-{seq:012}-{}.jsonl", uuid::Uuid::new_v4())
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
    // the batch bound. mtime leads and the name breaks its ties — see
    // [`spool_name`], which exists to make that tiebreak mean something.
    let mut files: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .map(|p| {
            let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
            let name = p.file_name().map(std::ffi::OsStr::to_os_string);
            (mtime, name, p)
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let mut out = Vec::new();
    for (_, _, path) in files {
        if out.len() >= limit {
            break;
        }
        // A read that fails and a parse that fails are not the same news. The
        // second is a verdict on the file's contents and no retry will change
        // it; the first is a verdict on the moment — a descriptor limit, a
        // lock some scanner holds, a permission being repaired — and the
        // envelope behind it may be perfectly good. Deleting on either would
        // destroy real events because the machine was briefly busy.
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                tracing::warn!(
                    "could not read spool file {path:?}, leaving it for the next pass: {e}"
                );
                continue;
            }
        };
        match serde_json::from_str::<Envelope>(&text) {
            Ok(env) => out.push((path, env)),
            Err(e) => {
                tracing::warn!("dropping unparseable spool file {path:?}: {e}");
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
            cloud_identity: Default::default(),
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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
            cloud_identity: Default::default(),
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: true,
            dropped: 0,
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
                cloud_identity: Default::default(),
                source: "codex".into(),
                received_at: chrono::Utc::now(),
                truncated: false,
                dropped: 0,
                event: None,
                payload: serde_json::json!({ "n": i }),
            };
            // Deliberately no sleep between writes. This used to pause 10 ms so
            // that coarse filesystem timestamps could still order the files,
            // which meant the ordering the daemon actually depends on was never
            // the thing under test.
            append(&env).unwrap();
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

    /// The property the sort's tiebreak rests on, asserted where every platform
    /// can see it: on a filesystem whose timestamps are fine enough, mtime alone
    /// gets the order right and the tiebreak is never reached, so a test of
    /// `take` cannot tell whether the names sort at all. Windows is where that
    /// stops being true — and where nobody is watching.
    #[test]
    fn spool_names_sort_into_the_order_they_were_written() {
        let _dir = setup();
        for i in 0..5u32 {
            let env = Envelope {
                cloud_identity: Default::default(),
                source: "codex".into(),
                received_at: chrono::Utc::now(),
                truncated: false,
                dropped: 0,
                event: None,
                payload: serde_json::json!({ "n": i }),
            };
            append(&env).unwrap();
        }
        let mut paths: Vec<_> = std::fs::read_dir(crate::paths::spool_dir())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        paths.sort();
        let order: Vec<u64> = paths
            .iter()
            .map(|p| {
                let text = std::fs::read_to_string(p).unwrap();
                let env: Envelope = serde_json::from_str(&text).unwrap();
                env.payload["n"].as_u64().unwrap()
            })
            .collect();
        assert_eq!(order, [0, 1, 2, 3, 4], "names sorted out of write order");
    }

    fn env(n: u32) -> Envelope {
        Envelope {
            cloud_identity: Default::default(),
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            // Big enough that a handful of these clears a small cap.
            payload: serde_json::json!({ "n": n, "pad": "x".repeat(400) }),
        }
    }

    fn cap(dir: &std::path::Path, max_bytes: u64) {
        std::fs::write(
            dir.join("config.toml"),
            format!("[spool]\nmax_bytes = {max_bytes}\n"),
        )
        .unwrap();
    }

    fn spool_bytes() -> u64 {
        std::fs::read_dir(crate::paths::spool_dir())
            .unwrap()
            .flatten()
            .map(|e| e.metadata().unwrap().len())
            .sum()
    }

    /// The spool fills exactly while nothing is draining it — a daemon that
    /// died and agents that kept working. Uncapped, the component that must
    /// never harm the host tool eventually fills its disk.
    #[test]
    fn a_spool_over_its_cap_stops_growing() {
        let dir = setup();
        cap(dir.path(), 4096);
        for i in 0..64 {
            append(&env(i)).unwrap();
        }
        assert!(
            spool_bytes() <= 4096,
            "spool grew to {} bytes past a 4096-byte cap",
            spool_bytes()
        );
        // And what survived is the *end* of the timeline, not the start: during
        // the incident this exists to record, the last minute is the one worth
        // keeping.
        let kept: Vec<u64> = take(usize::MAX)
            .iter()
            .map(|(_, e)| e.payload["n"].as_u64().unwrap())
            .collect();
        assert!(
            kept.contains(&63),
            "the newest envelope was trimmed away: {kept:?}"
        );
        assert!(!kept.contains(&0), "the oldest envelope survived: {kept:?}");
    }

    /// A deletion nobody hears about is exactly the silent gap the `Loss` kind
    /// exists to close, and the shim has no exporter to report it with — so it
    /// rides out on the envelope whose arrival caused it.
    #[test]
    fn a_trim_is_charged_to_the_envelope_that_caused_it() {
        let dir = setup();
        cap(dir.path(), 4096);
        for i in 0..64 {
            append(&env(i)).unwrap();
        }
        let total: u64 = take(usize::MAX).iter().map(|(_, e)| e.dropped).sum();
        assert!(
            total > 0,
            "files were deleted and no surviving envelope admits to it"
        );
    }

    /// An envelope bigger than the whole cap must still be written. Refusing it
    /// would trade a bounded overrun for a guaranteed hole — the same call the
    /// buffer's newest-row exemption makes.
    #[test]
    fn an_envelope_larger_than_the_cap_is_still_written() {
        let dir = setup();
        cap(dir.path(), 64);
        append(&env(1)).unwrap();
        append(&env(2)).unwrap();
        let kept = take(usize::MAX);
        assert_eq!(kept.len(), 1, "the only copy of the event was refused");
        assert_eq!(
            kept[0].1.payload["n"], 2,
            "an unwritable cap must still keep the newest, not the first"
        );
        // Which is the whole point of not clamping the cap away: `max_bytes`
        // below one envelope degrades to holding one, never to holding none.
        assert_eq!(kept[0].1.dropped, 1);
    }

    /// The operator most likely to change this cap is the one whose disk is
    /// filling right now; a value read once at startup would reach a shim that
    /// is a fresh process anyway, so the only way to get this wrong is to cache
    /// it somewhere.
    #[test]
    fn the_cap_is_the_one_in_the_config_file_now() {
        let dir = setup();
        cap(dir.path(), 1024);
        for i in 0..16 {
            append(&env(i)).unwrap();
        }
        assert!(spool_bytes() <= 1024);

        cap(dir.path(), 32 * 1024);
        for i in 16..48 {
            append(&env(i)).unwrap();
        }
        assert!(
            spool_bytes() > 1024,
            "the raised cap never took effect; still holding {} bytes",
            spool_bytes()
        );
    }

    #[cfg(unix)]
    #[test]
    fn spooled_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let _dir = setup();
        let env = Envelope {
            cloud_identity: Default::default(),
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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

    /// The spool exists so a daemon outage costs nothing, which makes `take`
    /// the last place that should be destroying events on a guess. A file it
    /// could not open has said nothing about its contents.
    #[cfg(unix)]
    #[test]
    fn a_spool_file_that_cannot_be_read_is_kept_for_the_next_pass() {
        use std::os::unix::fs::PermissionsExt;
        let _dir = setup();
        let dir = crate::paths::spool_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("unreadable.jsonl");
        append(&env(7)).unwrap();
        std::fs::rename(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .next()
                .unwrap(),
            &path,
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&path).is_ok() {
            // root ignores the mode, so there is no failed read to observe.
            return;
        }
        assert!(take(usize::MAX).is_empty(), "an unreadable file was parsed");
        assert!(
            path.exists(),
            "a readable-tomorrow event was destroyed because today's open failed"
        );
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
