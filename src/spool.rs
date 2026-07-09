use crate::event::Envelope;
use crate::paths;
use anyhow::Result;

pub fn append(envelope: &Envelope) -> Result<()> {
    let dir = paths::spool_dir();
    std::fs::create_dir_all(&dir)?;
    let file = dir.join(format!("{}.jsonl", uuid::Uuid::new_v4()));
    std::fs::write(file, serde_json::to_vec(envelope)?)?;
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
            Ok(env) => out.push(env),
            Err(e) => tracing::warn!("dropping bad spool file {path:?}: {e}"),
        }
        let _ = std::fs::remove_file(&path);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Envelope;

    fn setup() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        dir
    }

    #[test]
    fn append_then_drain_returns_envelope_and_empties_spool() {
        let _dir = setup();
        let env = Envelope {
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({"k": "v"}),
        };
        append(&env).unwrap();
        append(&env).unwrap();
        let drained = drain().unwrap();
        assert_eq!(drained.len(), 2);
        assert!(drain().unwrap().is_empty());
    }
}
