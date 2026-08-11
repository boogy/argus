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
//! deliberately synchronous: it is CPU work and (from T18) file reads, not I/O
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
            crate::adapters::cap_event(redactor.scrub_event(e), capture)
        })
        .collect()
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
}
