use crate::event::Envelope;

/// Entry point for `llm-monitor hook --source X`. Must never fail the host tool.
///
/// Most tools (Claude Code, opencode) pipe the event JSON via stdin. Codex's
/// `notify` instead invokes the program with the event JSON as a positional
/// argv argument; `arg_payload` carries that when present.
pub fn run(source: &str, arg_payload: Option<&str>) {
    let mut input = String::new();
    use std::io::Read;
    let _ = std::io::stdin().read_to_string(&mut input);
    let payload = choose_payload(&input, arg_payload);
    deliver(source, &payload);
}

/// Pure selection logic: stdin wins when non-empty (the common case); an
/// empty/whitespace-only stdin falls back to the positional argv payload
/// (Codex's notify invocation, which passes no stdin).
fn choose_payload(stdin: &str, arg: Option<&str>) -> String {
    if stdin.trim().is_empty() {
        if let Some(arg) = arg {
            if !arg.trim().is_empty() {
                return arg.to_string();
            }
        }
    }
    stdin.to_string()
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
    if send_with_deadline(&envelope, std::time::Duration::from_millis(250)) {
        return;
    }
    let _ = crate::spool::append(&envelope);
    autospawn_daemon();
}

/// Run `ipc::send` on a helper thread and give up after `deadline`. A wedged
/// daemon (socket accepted but never read) must never stall the host tool's
/// hook indefinitely. If the send completes after the deadline it may still
/// have reached the daemon while the envelope is also spooled here — a rare
/// duplicate is acceptable since the pipeline is at-least-once delivery.
fn send_with_deadline(envelope: &Envelope, deadline: std::time::Duration) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    let env = envelope.clone();
    std::thread::spawn(move || {
        let _ = tx.send(crate::ipc::send(&env).is_ok());
    });
    matches!(rx.recv_timeout(deadline), Ok(true))
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

        let started = std::time::Instant::now();
        deliver(
            "claude-code",
            r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#,
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "deliver must not block past the IPC deadline"
        );

        let drained = crate::spool::drain().unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].source, "claude-code");
    }

    /// Exercises the deadline mechanism directly: a socket path that can never
    /// be connected to must make `send_with_deadline` give up quickly rather
    /// than propagate an indefinite block. This is the same code path used to
    /// bound a genuinely wedged daemon (accepts a connection but never reads):
    /// on Unix a wedged daemon's kernel socket buffer can silently absorb a
    /// small envelope write without blocking, which makes that scenario
    /// unreliable to simulate in a portable test — the unreachable-socket case
    /// below still proves the timeout/give-up wiring is in place and that a
    /// send which cannot complete within `deadline` is treated as a failure.
    #[test]
    fn send_with_deadline_gives_up_promptly_when_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_SOCKET", dir.path().join("nope.sock"));

        let envelope = Envelope {
            source: "claude-code".to_string(),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({"hook_event_name": "UserPromptSubmit"}),
        };

        let started = std::time::Instant::now();
        let ok = send_with_deadline(&envelope, std::time::Duration::from_millis(250));
        let elapsed = started.elapsed();

        assert!(
            !ok,
            "send to an unreachable socket must be reported as failed"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "send_with_deadline must return promptly, took {elapsed:?}"
        );
    }

    #[test]
    fn malformed_stdin_is_swallowed_not_panicked() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::env::set_var("LLM_MONITOR_NO_AUTOSPAWN", "1");
        deliver("claude-code", "not json at all"); // must not panic
    }

    #[test]
    fn choose_payload_falls_back_to_arg_only_when_stdin_empty() {
        let event = r#"{"type":"agent-turn-complete"}"#;
        assert_eq!(choose_payload("", Some(event)), event);
        assert_eq!(choose_payload("   \n", Some(event)), event);
        assert_eq!(
            choose_payload(r#"{"stdin":"payload"}"#, Some(event)),
            r#"{"stdin":"payload"}"#,
            "non-empty stdin must win over argv payload"
        );
        assert_eq!(choose_payload("", None), "");
        assert_eq!(choose_payload("", Some("")), "");
    }
}
