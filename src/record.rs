//! Payload recorder — how a real session becomes a test fixture.
//!
//! Every adapter in this crate was written against documentation, and
//! documentation is where the field names in a payload go to drift. The only
//! way to know what a tool actually sends is to capture it while it sends it,
//! so setting [`RECORD_DIR_ENV`] makes the hook shim dump every envelope it
//! handles, verbatim, before anything parses or redacts it.
//!
//! Recording happens in the host tool's critical path, so it obeys the same
//! rule as the rest of the shim: it may fail, but it may never fail *loudly*.
//! An unwritable directory, a full disk, a hostile event name — all of them
//! end as a silently skipped file, never as a broken hook.
//!
//! [`promote`] is the other half: it turns a directory of raw recordings into
//! `tests/fixtures/<harness>/<event>.json`, one file per distinct event.
//! Those files get committed, which is why promotion — unlike recording —
//! redacts. A recording lives on the machine that made it; a fixture lives in
//! everyone's clone.

use crate::event::Envelope;
use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Set this to a directory to record every envelope the shim handles.
pub const RECORD_DIR_ENV: &str = "ARGUS_RECORD_DIR";

/// Timestamp stamped onto every promoted fixture. Real `received_at` values
/// differ on every recording, which would make promotion produce a fresh diff
/// each time it ran; nothing downstream of a fixture reads this field for
/// anything but its shape.
const FIXTURE_TS: &str = "2026-01-01T00:00:00Z";

/// Longest event label accepted as a path component.
const MAX_LABEL: usize = 64;

/// Dump `envelope` if recording is on. Best-effort by design: see the module
/// docs. Off, this costs one environment lookup.
pub fn record(envelope: &Envelope) {
    let Some(dir) = crate::paths::env_override(RECORD_DIR_ENV) else {
        return;
    };
    let _ = write_recording(Path::new(&dir), envelope);
}

fn write_recording(dir: &Path, envelope: &Envelope) -> std::io::Result<()> {
    // Recordings are raw: prompts, tool inputs, whatever the session
    // contained. Same posture as the spool — owner-only, both levels.
    crate::paths::create_private_dir(dir)?;
    // One file per invocation, so a recording never overwrites another; the
    // source and label are in the name purely so the directory is readable.
    let name = format!(
        "{}__{}__{}.json",
        slug(&envelope.source),
        label(envelope),
        uuid::Uuid::new_v4()
    );
    let path = dir.join(name);
    let body = serde_json::to_vec(envelope)?;
    // A recording is the one thing this crate writes that is never redacted,
    // so it is the last file that should spend a write world-readable.
    crate::paths::write_private(&path, &body)
}

/// The event name a payload carries, in the tool's own vocabulary.
///
/// Order is the same precedence the adapters use: an explicit `--event` hint
/// is authoritative (Copilot's payloads carry no name at all), then each
/// tool's own name field. A payload nobody claims records as `unknown` rather
/// than being dropped — an unrecognized event is exactly the kind of thing
/// recording exists to surface.
pub fn label(envelope: &Envelope) -> String {
    let raw = envelope
        .event
        .clone()
        .or_else(|| str_field(&envelope.payload, "hook_event_name"))
        .or_else(|| str_field(&envelope.payload, "event"))
        .or_else(|| str_field(&envelope.payload, "event_name"))
        .or_else(|| str_field(&envelope.payload, "type"))
        .unwrap_or_default();
    slug(&raw)
}

fn str_field(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(Value::as_str).map(String::from)
}

/// Make an arbitrary string safe as a single path component.
///
/// Both inputs to this are attacker-influenced in the sense that matters: a
/// payload field decides part of a filename. Anything outside the allowed set
/// becomes `-`, so a separator cannot survive, and a name that is only dots
/// (`..`) cannot either — it would otherwise name the parent directory.
fn slug(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .take(MAX_LABEL)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.trim_matches(['.', '-', '_']).is_empty() {
        return "unknown".into();
    }
    cleaned
}

/// Turn a directory of recordings into `<into>/<harness>/<event>.json`.
///
/// Repeated recordings of the same event collapse into one fixture — the last
/// one wins, since the point is a representative payload, not a transcript.
/// Output is deterministic: same recordings in, byte-identical files out, so
/// re-running this on an unchanged directory leaves the working tree clean.
///
/// Returns the fixtures written, sorted.
pub fn promote(from: &Path, into: &Path) -> Result<Vec<PathBuf>> {
    let redactor = crate::redact::Redactor::new(&crate::config::RedactionCfg::default());
    let fixed_ts: chrono::DateTime<chrono::Utc> = FIXTURE_TS.parse()?;

    let mut recordings: Vec<PathBuf> = std::fs::read_dir(from)
        .map_err(|e| anyhow::anyhow!("cannot read recordings in {}: {e}", from.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    // Deterministic "last one wins": without a defined order, which of two
    // recordings of the same event survives would depend on the filesystem.
    recordings.sort();

    let mut written = Vec::new();
    for recording in &recordings {
        let Ok(text) = std::fs::read_to_string(recording) else {
            continue;
        };
        let mut envelope: Envelope = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("skipping {}: not an envelope ({e})", recording.display());
                continue;
            }
        };
        let dir = into.join(slug(&envelope.source));
        let path = dir.join(format!("{}.json", label(&envelope)));

        envelope.received_at = fixed_ts;
        envelope.payload = scrub_value(&redactor, std::mem::take(&mut envelope.payload));

        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&envelope)?),
        )?;
        if !written.contains(&path) {
            written.push(path);
        }
    }
    written.sort();
    Ok(written)
}

/// Redact every string in a payload while leaving its shape untouched — an
/// adapter reads structure, so a fixture has to keep it.
fn scrub_value(redactor: &crate::redact::Redactor, value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(redactor.scrub_str(&s).into_owned()),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|v| scrub_value(redactor, v))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, scrub_value(redactor, v)))
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(source: &str, event: Option<&str>, payload: Value) -> Envelope {
        Envelope {
            env_overrides: Vec::new(),
            cloud_identity: Default::default(),
            source: source.into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: event.map(String::from),
            payload,
        }
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// Recording is per-invocation: two events must never collapse into one
    /// file, or a session's second PreToolUse would erase its first.
    #[test]
    fn recorder_writes_one_file_per_event() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var(RECORD_DIR_ENV, dir.path()) };

        record(&env(
            "claude-code",
            None,
            serde_json::json!({"hook_event_name": "PreToolUse", "tool_name": "Bash"}),
        ));
        record(&env(
            "claude-code",
            None,
            serde_json::json!({"hook_event_name": "PreToolUse", "tool_name": "Read"}),
        ));
        record(&env(
            "copilot",
            Some("preToolUse"),
            serde_json::json!({"toolName": "shell"}),
        ));

        unsafe { std::env::remove_var(RECORD_DIR_ENV) };

        let names = files(dir.path());
        assert_eq!(names.len(), 3, "one file per recorded event: {names:?}");
        assert_eq!(
            names
                .iter()
                .filter(|n| n.starts_with("claude-code__PreToolUse__"))
                .count(),
            2
        );
        assert!(names.iter().any(|n| n.starts_with("copilot__preToolUse__")));
    }

    /// Recording is opt-in *per invocation*: the variable is read every time,
    /// never remembered. Anything else would keep writing raw prompts to disk
    /// after the developer thought they had turned it off.
    #[test]
    fn recording_stops_the_moment_the_env_var_goes_away() {
        let dir = tempfile::tempdir().unwrap();
        let prompt = || {
            env(
                "claude-code",
                None,
                serde_json::json!({"hook_event_name": "UserPromptSubmit"}),
            )
        };

        unsafe { std::env::set_var(RECORD_DIR_ENV, dir.path()) };
        record(&prompt());
        assert_eq!(files(dir.path()).len(), 1);

        unsafe { std::env::remove_var(RECORD_DIR_ENV) };
        record(&prompt());
        assert_eq!(files(dir.path()).len(), 1, "recording outlived its switch");
    }

    #[test]
    fn label_follows_each_tool_s_own_name_field() {
        let cases = [
            (
                env("copilot", Some("postToolUse"), serde_json::json!({})),
                "postToolUse",
            ),
            (
                env(
                    "claude-code",
                    None,
                    serde_json::json!({"hook_event_name": "Stop", "type": "ignored"}),
                ),
                "Stop",
            ),
            (
                env(
                    "opencode",
                    None,
                    serde_json::json!({"event": "tool.execute.before"}),
                ),
                "tool.execute.before",
            ),
            (
                env(
                    "codex",
                    None,
                    serde_json::json!({"event_name": "codex.user_prompt"}),
                ),
                "codex.user_prompt",
            ),
            (
                env(
                    "codex",
                    None,
                    serde_json::json!({"type": "agent-turn-complete"}),
                ),
                "agent-turn-complete",
            ),
            (
                env("codex", None, serde_json::json!({"nope": 1})),
                "unknown",
            ),
            (
                env("codex", None, serde_json::json!("not an object")),
                "unknown",
            ),
        ];
        for (envelope, expected) in cases {
            assert_eq!(label(&envelope), expected, "payload {:?}", envelope.payload);
        }
    }

    /// A payload field decides part of a path, so it gets the same treatment
    /// as any other untrusted input.
    #[test]
    fn a_hostile_event_name_cannot_escape_the_fixture_directory() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("rec");
        let into = root.path().join("fixtures");

        unsafe { std::env::set_var(RECORD_DIR_ENV, &from) };
        record(&env(
            "../../etc",
            None,
            serde_json::json!({"hook_event_name": "../../../../etc/passwd"}),
        ));
        record(&env("codex", None, serde_json::json!({"type": ".."})));
        // The source names the *directory*, so `..` there is the one that
        // would genuinely walk out of the fixture tree.
        record(&env("..", None, serde_json::json!({"type": ".."})));
        unsafe { std::env::remove_var(RECORD_DIR_ENV) };

        for name in files(&from) {
            assert!(!name.contains('/') && !name.contains('\\'), "{name}");
        }
        let written = promote(&from, &into).unwrap();
        assert_eq!(written.len(), 3);
        for path in written {
            assert!(
                !path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
                "{} walks out of the fixture tree",
                path.display()
            );
            assert!(
                path.parent()
                    .unwrap()
                    .canonicalize()
                    .unwrap()
                    .starts_with(into.canonicalize().unwrap()),
                "{} escaped {}",
                path.display(),
                into.display()
            );
            assert_eq!(
                path.components().count(),
                into.components().count() + 2,
                "fixtures are exactly <into>/<source>/<event>.json"
            );
        }
    }

    /// Promotion is the step whose output is committed, so running it twice
    /// on the same recordings must leave the tree clean.
    #[test]
    fn promote_collapses_repeats_by_source_and_event_and_is_deterministic() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("rec");
        let into = root.path().join("fixtures");
        unsafe { std::env::set_var(RECORD_DIR_ENV, &from) };
        for tool in ["Bash", "Read", "Write"] {
            record(&env(
                "claude-code",
                None,
                serde_json::json!({"hook_event_name": "PreToolUse", "tool_name": tool}),
            ));
        }
        record(&env(
            "opencode",
            None,
            serde_json::json!({"event": "tool.execute.after", "tool": "bash"}),
        ));
        unsafe { std::env::remove_var(RECORD_DIR_ENV) };

        let written = promote(&from, &into).unwrap();
        assert_eq!(
            written,
            vec![
                into.join("claude-code").join("PreToolUse.json"),
                into.join("opencode").join("tool.execute.after.json"),
            ]
        );

        let first = std::fs::read_to_string(&written[0]).unwrap();
        assert_eq!(promote(&from, &into).unwrap(), written);
        assert_eq!(
            std::fs::read_to_string(&written[0]).unwrap(),
            first,
            "re-promoting unchanged recordings must not churn the fixture"
        );
        assert!(
            first.contains("\"received_at\": \"2026-01-01T00:00:00Z\""),
            "timestamps are normalised, else every promotion is a diff: {first}"
        );
        // Last recording wins, and "last" is defined by sorted filename, not
        // by whatever order the filesystem hands back.
        let last = std::fs::read_to_string(
            files(&from)
                .iter()
                .filter(|n| n.starts_with("claude-code__"))
                .map(|n| from.join(n))
                .max()
                .unwrap(),
        )
        .unwrap();
        let expected: Envelope = serde_json::from_str(&last).unwrap();
        let got: Envelope = serde_json::from_str(&first).unwrap();
        assert_eq!(got.payload, expected.payload);
    }

    /// A recording stays on the machine that made it; a fixture is committed.
    #[test]
    fn promote_scrubs_secrets_before_they_reach_the_repo() {
        let root = tempfile::tempdir().unwrap();
        let from = root.path().join("rec");
        let into = root.path().join("fixtures");
        let secret = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLL";
        unsafe { std::env::set_var(RECORD_DIR_ENV, &from) };
        record(&env(
            "claude-code",
            None,
            serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": format!("curl -H 'x-api-key: {secret}' https://api.example.com")},
                "nested": [{"deep": secret}],
            }),
        ));
        unsafe { std::env::remove_var(RECORD_DIR_ENV) };

        let raw = std::fs::read_to_string(from.join(&files(&from)[0])).unwrap();
        assert!(raw.contains(secret), "recordings are deliberately raw");

        let written = promote(&from, &into).unwrap();
        let fixture = std::fs::read_to_string(&written[0]).unwrap();
        assert!(
            !fixture.contains(secret),
            "secret reached a fixture:\n{fixture}"
        );
        // Shape survives redaction — an adapter reads structure, not values.
        let envelope: Envelope = serde_json::from_str(&fixture).unwrap();
        assert_eq!(
            envelope
                .payload
                .pointer("/tool_name")
                .and_then(Value::as_str),
            Some("Bash")
        );
        assert!(
            envelope
                .payload
                .pointer("/tool_input/command")
                .and_then(Value::as_str)
                .is_some_and(|c| c.starts_with("curl -H")),
            "redaction replaced the secret, not the field"
        );
    }
}
