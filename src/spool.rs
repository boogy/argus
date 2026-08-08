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

pub fn drain() -> Result<Vec<Envelope>> {
    let dir = paths::spool_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(out);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "jsonl") {
            continue;
        }
        match std::fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|s| serde_json::from_str::<Envelope>(&s).map_err(Into::into))
        {
            Ok(env) => {
                // Try to delete FIRST, only push if successful
                match std::fs::remove_file(&path) {
                    Ok(()) => out.push(env),
                    Err(e) => tracing::warn!("failed to delete spool file {path:?}: {e}"),
                }
            }
            Err(e) => {
                tracing::warn!("dropping bad spool file {path:?}: {e}");
                // Try to delete, log if it fails
                if let Err(del_err) = std::fs::remove_file(&path) {
                    tracing::warn!("failed to delete corrupt spool file {path:?}: {del_err}");
                }
            }
        }
    }
    Ok(out)
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
