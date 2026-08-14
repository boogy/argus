use crate::event::Envelope;

/// Hard cap on hook stdin: a runaway host payload (multi-hundred-MB tool
/// result) must not balloon shim memory/latency. 8 MiB keeps worst-case
/// read+parse well under the IPC deadline budget.
pub const MAX_STDIN_BYTES: usize = 8 * 1024 * 1024;

/// Read at most `MAX_STDIN_BYTES`, and say whether there was more.
///
/// Reads one byte *past* the cap on purpose: a `take` that stops exactly at
/// the cap cannot distinguish a payload that happened to end there from one
/// that was cut off, and a truncation nobody reports is precisely the silent
/// gap this is meant to close.
///
/// Byte-oriented rather than `read_to_string` for a second reason. Cutting at
/// a fixed byte offset lands mid-codepoint for most non-ASCII text, and
/// `read_to_string` answers that with `InvalidData` *and an untouched buffer*
/// — the whole 8 MiB discarded to avoid half a character. Backing up to the
/// last boundary keeps everything up to the break.
pub fn read_capped(r: &mut impl std::io::Read) -> (String, bool) {
    use std::io::Read;
    let mut bytes = Vec::new();
    let _ = r.take(MAX_STDIN_BYTES as u64 + 1).read_to_end(&mut bytes);
    let truncated = bytes.len() > MAX_STDIN_BYTES;
    if truncated {
        let mut cut = MAX_STDIN_BYTES;
        // A continuation byte is 0b10xxxxxx; anything else starts a character.
        while cut > 0 && bytes[cut] & 0xC0 == 0x80 {
            cut -= 1;
        }
        bytes.truncate(cut);
    }
    (String::from_utf8_lossy(&bytes).into_owned(), truncated)
}

/// Entry point for `argus hook --source X [--event NAME]`. Must never
/// fail the host tool.
///
/// Most tools (Claude Code, opencode) pipe the event JSON via stdin. Codex's
/// `notify` instead invokes the program with the event JSON as a positional
/// argv argument; `arg_payload` carries that when present. `event` is the
/// event-name hint for tools whose payloads carry no event-name field.
pub fn run(source: &str, event: Option<&str>, arg_payload: Option<&str>) {
    let (input, truncated) = read_capped(&mut std::io::stdin().lock());
    let payload = choose_payload(&input, arg_payload);
    // Falling back to argv means stdin was empty, so nothing of it was cut.
    let truncated = truncated && payload == input;
    deliver(source, event, &payload, truncated);
}

/// Pure selection logic: stdin wins when non-empty (the common case); an
/// empty/whitespace-only stdin falls back to the positional argv payload
/// (Codex's notify invocation, which passes no stdin).
fn choose_payload(stdin: &str, arg: Option<&str>) -> String {
    if stdin.trim().is_empty()
        && let Some(arg) = arg
        && !arg.trim().is_empty()
    {
        return arg.to_string();
    }
    stdin.to_string()
}

/// Testable core: wrap raw hook text and hand it off. Malformed JSON is
/// preserved as a string payload so nothing is ever lost.
pub fn deliver(source: &str, event: Option<&str>, raw: &str, truncated: bool) {
    let payload =
        serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_string()));
    let envelope = Envelope {
        // Read here because here is the only place it exists: this process was
        // spawned by the host agent and holds the agent's environment, where
        // the daemon holds whoever started the daemon. Collected
        // unconditionally — the *capture* policy is applied in the daemon,
        // alongside every other one, so a fleet turns this off centrally
        // instead of reinstalling on every host to change what a shim reads.
        cloud_identity: crate::cloudid::current(),
        source: source.to_string(),
        received_at: chrono::Utc::now(),
        event: event.map(String::from),
        truncated,
        // Filled in by `spool::append`, which is the only code that can know:
        // nothing is dropped on the path where the daemon answers.
        dropped: 0,
        payload,
    };
    // Before anything can parse, redact or reshape it — a fixture is only
    // worth having if it is what the tool really sent. Off by default and
    // best-effort when on; see `record`.
    crate::record::record(&envelope);
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

/// `CREATE_NO_WINDOW` from the Win32 process-creation flags. A hook runs
/// inside the host agent's own process tree, which for a GUI-launched editor
/// has no console — so every child it spawns gets a *new* console window
/// flashed on screen. Observability that blinks at the user is not passive.
#[cfg(windows)]
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn autospawn_daemon() {
    if std::env::var("ARGUS_NO_AUTOSPAWN").is_ok() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let _ = cmd.spawn();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_to_spool_when_no_daemon() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        unsafe {
            std::env::set_var("ARGUS_SOCKET", dir.path().join("nope.sock"));
        }
        unsafe {
            std::env::set_var("ARGUS_NO_AUTOSPAWN", "1");
        }

        let started = std::time::Instant::now();
        deliver(
            "claude-code",
            None,
            r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#,
            false,
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
        unsafe {
            std::env::set_var("ARGUS_SOCKET", dir.path().join("nope.sock"));
        }

        let envelope = Envelope {
            cloud_identity: Default::default(),
            source: "claude-code".to_string(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
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

    /// The shim is the only process that ever sees the agent's environment:
    /// the daemon it hands off to was started from somewhere else entirely.
    /// If the identity is not read here it cannot be recovered anywhere later,
    /// so the read has to be on the envelope, not on a config read in the
    /// daemon.
    #[test]
    fn the_agent_environment_is_read_where_it_exists_and_nowhere_else() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
            std::env::set_var("ARGUS_SOCKET", dir.path().join("nope.sock"));
            std::env::set_var("ARGUS_NO_AUTOSPAWN", "1");
            std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/prod-admin");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI");
        }
        deliver(
            "claude-code",
            None,
            r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#,
            false,
        );
        unsafe {
            std::env::remove_var("AWS_ROLE_ARN");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }

        let drained = crate::spool::drain().unwrap();
        let id = &drained[0].cloud_identity;
        assert_eq!(
            id.attributes.get("aws.role_arn").map(String::as_str),
            Some("arn:aws:iam::123456789012:role/prod-admin"),
            "the role the agent was holding never left the shim: {id:?}"
        );
        // Containment, not equality: this reads the *test runner's* real
        // environment, which is a developer's or a CI machine's shell and may
        // legitimately hold credentials of its own.
        assert!(
            id.credentials.iter().any(|c| c == "AWS_SECRET_ACCESS_KEY"),
            "{id:?}"
        );
        // Down the same path the daemon would take it, and still name-only.
        let spooled = serde_json::to_string(&drained[0]).unwrap();
        assert!(!spooled.contains("wJalrXUtnFEMI"), "{spooled}");
    }

    #[test]
    fn event_hint_lands_in_envelope() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        unsafe {
            std::env::set_var("ARGUS_SOCKET", dir.path().join("nope.sock"));
        }
        unsafe {
            std::env::set_var("ARGUS_NO_AUTOSPAWN", "1");
        }
        deliver(
            "copilot",
            Some("preToolUse"),
            r#"{"toolName":"bash"}"#,
            false,
        );
        let drained = crate::spool::drain().unwrap();
        assert_eq!(drained[0].event.as_deref(), Some("preToolUse"));
    }

    #[test]
    fn oversized_stdin_is_truncated_not_unbounded() {
        // read_capped is pure over any Read; 8MiB cap.
        let big = vec![b'a'; 9 * 1024 * 1024];
        let (s, truncated) = read_capped(&mut std::io::Cursor::new(big));
        assert_eq!(s.len(), MAX_STDIN_BYTES);
        assert!(
            truncated,
            "8 MiB of a 9 MiB payload was discarded in silence"
        );
    }

    /// The cap is a byte count, so it lands wherever it lands — including in
    /// the middle of a character. `read_to_string` treats that as `InvalidData`
    /// and leaves the buffer empty, which would throw away the whole payload
    /// to avoid half a glyph.
    #[test]
    fn a_cut_through_a_character_costs_the_character_not_the_payload() {
        let mut big = vec![b'a'; MAX_STDIN_BYTES - 1];
        big.extend_from_slice("é".as_bytes()); // two bytes, straddling the cap
        big.extend_from_slice(&[b'z'; 1024]);
        let (s, truncated) = read_capped(&mut std::io::Cursor::new(big));
        assert!(truncated);
        assert_eq!(
            s.len(),
            MAX_STDIN_BYTES - 1,
            "the read backed up to the character boundary and kept the rest"
        );
        assert!(s.ends_with('a'));
    }

    /// Exactly at the cap is a complete payload, not a truncated one: reading
    /// one byte past the cap is what makes the two distinguishable.
    #[test]
    fn a_payload_that_ends_exactly_at_the_cap_is_not_truncated() {
        let exact = vec![b'a'; MAX_STDIN_BYTES];
        let (s, truncated) = read_capped(&mut std::io::Cursor::new(exact));
        assert_eq!(s.len(), MAX_STDIN_BYTES);
        assert!(!truncated);
    }

    #[test]
    fn malformed_stdin_is_swallowed_not_panicked() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        unsafe {
            std::env::set_var("ARGUS_NO_AUTOSPAWN", "1");
        }
        deliver("claude-code", None, "not json at all", false); // must not panic
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
