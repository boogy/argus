use crate::event::Envelope;

/// Entry point for `llm-monitor hook --source X`. Must never fail the host tool.
pub fn run(source: &str) {
    let mut input = String::new();
    use std::io::Read;
    let _ = std::io::stdin().read_to_string(&mut input);
    deliver(source, &input);
}

/// Testable core: wrap raw hook text and hand it off. Malformed JSON is
/// preserved as a string payload so nothing is ever lost.
pub fn deliver(source: &str, raw: &str) {
    let payload =
        serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()));
    let envelope = Envelope {
        source: source.to_string(),
        received_at: chrono::Utc::now(),
        payload,
    };
    if crate::ipc::send(&envelope).is_ok() {
        return;
    }
    let _ = crate::spool::append(&envelope);
    autospawn_daemon();
}

fn autospawn_daemon() {
    if std::env::var("LLM_MONITOR_NO_AUTOSPAWN").is_ok() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe)
            .arg("daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_to_spool_when_no_daemon() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::env::set_var("LLM_MONITOR_SOCKET", dir.path().join("nope.sock"));
        std::env::set_var("LLM_MONITOR_NO_AUTOSPAWN", "1");

        deliver(
            "claude-code",
            r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#,
        );

        let drained = crate::spool::drain().unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].source, "claude-code");
    }

    #[test]
    fn malformed_stdin_is_swallowed_not_panicked() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::env::set_var("LLM_MONITOR_NO_AUTOSPAWN", "1");
        deliver("claude-code", "not json at all"); // must not panic
    }
}
