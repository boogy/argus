//! Stage B of the daemon pipeline: everything done to a parsed batch between
//! the socket and the buffer.
//!
//! It lives on its own because it is the only stage that is both expensive and
//! parallelisable. Parsing is cheap, and the SQLite write has to be serialised
//! whatever else happens; redaction — a dozen compiled regexes over every
//! string in every event — is neither. Running it inline on the single
//! consumer made the slowest step the one step that could not be scaled, which
//! is the wrong way round.
//!
//! Stage B runs on the blocking pool, several batches at a time, and is
//! deliberately synchronous: it is CPU work and file reads, not I/O
//! the async runtime can interleave.

use crate::config::CaptureCfg;
use crate::event::Event;
use crate::filecap::PathFilter;
use crate::redact::Redactor;

/// Redact one parsed batch, then cut it down to the configured field cap.
///
/// The order is the point. Adapters cap while parsing, but only to
/// `max_field_bytes + `[`REDACTION_HEADROOM`](crate::adapters::REDACTION_HEADROOM),
/// so a secret sitting across the boundary reaches the redactor whole instead
/// of arriving as an unmatchable — and therefore unredacted — prefix. The
/// final cut happens here, once nothing recognisable as a credential is left.
///
/// Takes the whole batch rather than one event so that later additions with
/// per-*event* budgets — file-content capture — have somewhere to enforce them
/// that isn't a global.
pub fn enrich(
    events: Vec<Event>,
    redactor: &Redactor,
    capture: &CaptureCfg,
    paths: &PathFilter,
) -> Vec<Event> {
    #[cfg(test)]
    slow_down();
    events
        .into_iter()
        .map(|mut e| {
            // Before the scrub, not after: the copy has to be walked by the
            // same redactor pass as the input it was copied out of, or it is
            // the one field in the event nobody looked at.
            crate::filecap::capture(&mut e, capture, paths);
            resolve_mcp_endpoint(&mut e, redactor, capture);
            crate::adapters::cap_event(redactor.scrub_event(e), capture)
        })
        .collect()
}

/// Say where the MCP server named on this event is, if it is configured
/// anywhere this machine can see.
///
/// Runs here rather than in the adapters for the reason file capture does: it
/// touches the disk, so it belongs on the blocking pool, off the parse path,
/// and behind the same opt-in.
///
/// The redactor is applied by hand, and that is not belt-and-braces:
/// [`Redactor::scrub_event`] walks the event's `kind` and nothing else, so a
/// string put into `Meta` is a string no redaction pass will ever see.
/// [`crate::mcpcfg`] already drops a URL's userinfo and query and blanks an
/// argument whose name says credential; this catches what is left — a token
/// with a recognisable shape sitting in an argument that is named nothing in
/// particular.
fn resolve_mcp_endpoint(e: &mut Event, redactor: &Redactor, capture: &CaptureCfg) {
    if !capture.mcp_endpoints {
        return;
    }
    let Some(server) = e.meta.mcp_server.clone() else {
        return;
    };
    let Some(endpoint) = crate::mcpcfg::resolver().endpoint(&server, e.cwd.as_deref()) else {
        return;
    };
    e.meta.mcp_endpoint = Some(redactor.scrub_str(&endpoint).into_owned());
}

/// Test-only throttle. Backpressure is only observable when Stage B is slower
/// than its producer, and a redactor fast enough to be worth shipping cannot
/// be made slow by feeding it more data — a test that tried would be timing a
/// regex engine rather than the pipeline around it.
///
/// The delay *decays*: the first batch waits `SLOW_MICROS`, and each one after
/// it waits `SLOW_STEP_MICROS` less. That is what makes ordering falsifiable.
/// Under a flat delay, batches finish in the order they started whatever Stage
/// C does, so a pipeline that emitted them as they completed would look
/// perfectly ordered; make the earlier batches the slower ones and the two
/// behaviours produce opposite output.
#[cfg(test)]
static SLOW_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static SLOW_STEP_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static SLOW_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn set_delay(base_micros: u64, step_micros: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    SLOW_MICROS.store(base_micros, Relaxed);
    SLOW_STEP_MICROS.store(step_micros, Relaxed);
    SLOW_CALLS.store(0, Relaxed);
}

#[cfg(test)]
fn slow_down() {
    use std::sync::atomic::Ordering::Relaxed;
    let base = SLOW_MICROS.load(Relaxed);
    if base == 0 {
        return;
    }
    let nth = SLOW_CALLS.fetch_add(1, Relaxed);
    let micros = base.saturating_sub(SLOW_STEP_MICROS.load(Relaxed).saturating_mul(nth));
    if micros > 0 {
        std::thread::sleep(std::time::Duration::from_micros(micros));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RedactionCfg, TruncateMode};
    use crate::event::{Envelope, EventKind};

    fn capture(max: usize, mode: TruncateMode) -> CaptureCfg {
        CaptureCfg {
            max_field_bytes: max,
            truncate_mode: mode,
            ..CaptureCfg::default()
        }
    }

    fn prompt_through_pipeline(text: &str, capture: &CaptureCfg) -> String {
        let envelope = Envelope {
            cloud_identity: Default::default(),
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "UserPromptSubmit",
                "prompt": text,
            }),
        };
        let events = crate::adapters::parse(envelope, capture);
        let redactor = Redactor::new(&RedactionCfg::default());
        let paths = PathFilter::new(&capture.file_contents);
        let out = enrich(events, &redactor, capture, &paths);
        match &out[0].kind {
            EventKind::Prompt { text } => text.clone(),
            other => panic!("not a prompt: {other:?}"),
        }
    }

    /// The ordering hazard this stage exists to close. Capping during parsing
    /// and redacting afterwards cuts a token that straddles the boundary in
    /// half, and half a token matches nothing — so the prefix of a live
    /// credential is stored, looking like ordinary text.
    #[test]
    fn a_secret_across_the_cap_boundary_is_redacted_not_left_as_a_prefix() {
        let max = 200;
        let secret = format!("ghp_{}", "A".repeat(36));
        // Starts eight bytes before the cap and runs well past it.
        let text = format!("{}{secret} trailing", "x".repeat(max - 8));

        let out = prompt_through_pipeline(&text, &capture(max, TruncateMode::Head));
        assert!(
            !out.contains("ghp_"),
            "a fragment of the token survived the cap: {out}"
        );
        assert!(
            !out.contains("AAAAAAAAAA"),
            "the token's body survived without its prefix: {out}"
        );
        // A secret that straddles the cap necessarily starts within a few bytes
        // of it, so the marker that replaces it straddles the cap too and loses
        // its own tail. That is cosmetic — a cut marker is not a credential —
        // and it is still the proof that the redactor ran first: capping first
        // would leave `ghp_AAAA…` here and no marker at all.
        assert!(
            out.contains("[REDACT"),
            "the token was cut away rather than redacted, so a token that fitted \
             entirely inside the headroom would have leaked: {out}"
        );
    }

    /// The cap still has to be a cap. Headroom is slack for the redactor, not
    /// a bigger limit.
    #[test]
    fn the_final_cap_is_the_configured_one() {
        let out = prompt_through_pipeline(&"x".repeat(50_000), &capture(200, TruncateMode::Head));
        assert!(
            out.starts_with("xxx") && out.ends_with("…[truncated]"),
            "not capped in head mode: {}",
            &out[..40.min(out.len())]
        );
        assert!(
            out.len() < 200 + 32,
            "the parse-time headroom reached the buffer: {} bytes",
            out.len()
        );
    }

    /// `head` alone truncates away the outcome of a diff and the cause of a
    /// stack trace, which is why the mode exists — and why it has to survive
    /// the parse-time cap that runs before it.
    #[test]
    fn head_tail_keeps_the_end_of_a_long_field() {
        let text = format!("BEGIN{}END", "-".repeat(50_000));
        let out = prompt_through_pipeline(&text, &capture(200, TruncateMode::HeadTail));
        assert!(out.starts_with("BEGIN"), "lost the head: {out}");
        assert!(
            out.ends_with("END"),
            "lost the tail the mode is named for: {out}"
        );
        assert!(out.len() < 200 + 32, "{} bytes", out.len());

        let dropped = prompt_through_pipeline(&text, &capture(200, TruncateMode::Drop));
        assert_eq!(dropped, "[truncated]");
    }

    /// Capture copies a secret out of the input into a second field. Doing it
    /// after the scrub would leave that copy as the one string in the event
    /// nobody had looked at — the input redacted, the file body not.
    #[test]
    fn a_secret_in_a_captured_file_is_redacted_before_the_buffer() {
        let secret = format!("ghp_{}", "B".repeat(36));
        let mut capture = capture(65536, TruncateMode::HeadTail);
        capture.file_contents.enabled = true;
        let envelope = Envelope {
            cloud_identity: Default::default(),
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {
                    "file_path": "/repo/src/deploy.rs",
                    "content": format!("let token = \"{secret}\";"),
                },
            }),
        };
        let events = crate::adapters::parse(envelope, &capture);
        let redactor = Redactor::new(&RedactionCfg::default());
        let paths = PathFilter::new(&capture.file_contents);
        let out = enrich(events, &redactor, &capture, &paths);
        let EventKind::ToolUse { file_contents, .. } = &out[0].kind else {
            panic!("not a tool use: {:?}", out[0].kind)
        };
        let snap = &file_contents[0];
        let body = snap.content.as_deref().expect("nothing captured");
        assert!(!body.contains("ghp_"), "the captured body leaked: {body}");
        assert!(body.contains("[REDACT"), "not scrubbed at all: {body}");
        assert_eq!(
            snap.path, "/repo/src/deploy.rs",
            "the path was scrubbed along with the body"
        );
        // The digest is of the bytes the tool wrote, not of the scrubbed copy:
        // it exists to match a file on disk, and a hash of the redaction marker
        // matches nothing.
        assert_eq!(
            snap.sha256.as_deref(),
            Some(&crate::filecap::sha256_hex(format!("let token = \"{secret}\";").as_bytes())[..])
        );
    }

    /// Redaction and truncation walk the same fields, so a mode that keeps
    /// nothing must not be a way to skip the scrubber either.
    #[test]
    fn a_short_field_is_left_exactly_alone() {
        let out = prompt_through_pipeline("hello world", &capture(200, TruncateMode::HeadTail));
        assert_eq!(out, "hello world");
    }

    /// A `.mcp.json` in a temp project, and a server name nothing on a real
    /// machine is called — so the user-wide config files this also consults
    /// cannot answer, and the test does not have to move `ARGUS_HOME` out from
    /// under whatever else is running.
    fn project_with_server(entry: serde_json::Value) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            serde_json::json!({"mcpServers": {"argus-fixture-srv": entry}}).to_string(),
        )
        .unwrap();
        crate::mcpcfg::resolver().clear();
        dir
    }

    /// Through the adapter rather than hand-built, so the `mcp_server` this
    /// resolves from is the one `harness::parse` really stamps.
    fn mcp_call_through_pipeline(dir: &tempfile::TempDir, capture: &CaptureCfg) -> Event {
        let envelope = Envelope {
            cloud_identity: Default::default(),
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "PreToolUse",
                "session_id": "s1",
                "cwd": dir.path().to_string_lossy(),
                "tool_name": "mcp__argus-fixture-srv__create_issue",
                "tool_input": {},
            }),
        };
        let events = crate::adapters::parse(envelope, capture);
        let redactor = Redactor::new(&RedactionCfg::default());
        let paths = PathFilter::new(&capture.file_contents);
        let mut out = enrich(events, &redactor, capture, &paths);
        assert_eq!(
            out[0].meta.mcp_server.as_deref(),
            Some("argus-fixture-srv"),
            "the fixture stopped naming a server, so it proves nothing"
        );
        out.remove(0)
    }

    /// Which server the call went to is in the tool's name; where that server
    /// is only exists on disk.
    #[test]
    fn an_mcp_call_says_where_the_server_it_reached_is() {
        let dir = project_with_server(serde_json::json!({"url": "https://mcp.vendor.example/sse"}));
        let capture = CaptureCfg {
            mcp_endpoints: true,
            ..CaptureCfg::default()
        };
        assert_eq!(
            mcp_call_through_pipeline(&dir, &capture).meta.mcp_endpoint,
            Some("https://mcp.vendor.example/sse".into())
        );
    }

    /// Reading the host tools' config files is collection the operator has to
    /// ask for, like file contents — the default must leave the disk alone.
    #[test]
    fn no_config_file_is_read_until_the_operator_asks() {
        let dir = project_with_server(serde_json::json!({"url": "https://mcp.vendor.example/sse"}));
        assert_eq!(
            mcp_call_through_pipeline(&dir, &CaptureCfg::default())
                .meta
                .mcp_endpoint,
            None,
            "an endpoint was resolved with capture.mcp_endpoints off"
        );
    }

    /// The one field in the event the ordinary scrub cannot reach.
    /// `scrub_event` walks `kind`, so anything put into `Meta` is redacted
    /// here or nowhere — and a command line out of a config file is exactly
    /// where a token that no key name announces sits.
    #[test]
    fn a_secret_in_a_server_command_is_redacted_even_though_it_lands_in_meta() {
        let secret = format!("ghp_{}", "A".repeat(36));
        let dir = project_with_server(serde_json::json!({
            "command": "srv",
            "args": ["--opaque", secret],
        }));
        let capture = CaptureCfg {
            mcp_endpoints: true,
            ..CaptureCfg::default()
        };
        let got = mcp_call_through_pipeline(&dir, &capture)
            .meta
            .mcp_endpoint
            .expect("no endpoint");
        assert!(
            !got.contains("ghp_"),
            "a token reached Meta unredacted: {got}"
        );
        assert!(got.starts_with("stdio:srv --opaque"), "{got}");
    }

    /// An event with no MCP server on it has nothing to resolve, and a call to
    /// a server nobody configured is a gap rather than a guess.
    #[test]
    fn an_unconfigured_server_leaves_the_field_empty() {
        let dir = project_with_server(serde_json::json!({"url": "https://mcp.vendor.example/sse"}));
        let capture = CaptureCfg {
            mcp_endpoints: true,
            ..CaptureCfg::default()
        };
        let redactor = Redactor::new(&RedactionCfg::default());
        let paths = PathFilter::new(&capture.file_contents);

        let mut ordinary = Event::new(
            "claude-code",
            Some("s1".into()),
            Some(dir.path().to_string_lossy().into_owned()),
            EventKind::Prompt {
                text: "hello".into(),
            },
        );
        assert!(
            enrich(vec![ordinary.clone()], &redactor, &capture, &paths)[0]
                .meta
                .mcp_endpoint
                .is_none()
        );

        ordinary.meta.mcp_server = Some("a-server-nobody-configured".into());
        assert!(
            enrich(vec![ordinary], &redactor, &capture, &paths)[0]
                .meta
                .mcp_endpoint
                .is_none()
        );
    }
}
