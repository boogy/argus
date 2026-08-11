pub mod claude_code;
pub mod codex;
pub mod copilot;
pub mod opencode;
pub mod pi;

use crate::config::CaptureCfg;
use crate::event::{Envelope, Event};
use serde_json::Value;

/// Adding a new tool = one adapter module here exposing
/// `parse(&Envelope, &CaptureCfg) -> Vec<Event>` + one `impl Harness` in
/// `harness/` wiring it to its install/detect data. See docs/adding-a-tool.md.
///
/// Dispatch lives on [`crate::harness::HARNESSES`] so a tool cannot be
/// installable but unparseable (or vice versa) — the old separate `ADAPTERS`
/// table made that a silent, per-tool omission.
pub fn parse(envelope: Envelope, capture: &CaptureCfg) -> Vec<Event> {
    crate::harness::parse(envelope, capture)
}

pub(crate) const FILE_KEYS: &[&str] = &["file_path", "filePath", "notebook_path", "path"];
const NET_KEYS: &[&str] = &["url", "command", "query"];

/// File paths from a tool input: known path keys plus apply_patch-style
/// patch headers embedded in any string value for patch-shaped tools.
pub fn extract_files_for_tool(tool: &str, input: &Value) -> Vec<String> {
    let mut out: Vec<String> = FILE_KEYS
        .iter()
        .filter_map(|k| input.get(k).and_then(Value::as_str))
        .map(String::from)
        .collect();
    if tool.eq_ignore_ascii_case("apply_patch") || tool.eq_ignore_ascii_case("applypatch") {
        for v in input.as_object().into_iter().flat_map(|o| o.values()) {
            if let Some(s) = v.as_str() {
                out.extend(extract_patch_files(s));
            }
        }
        if let Some(s) = input.as_str() {
            out.extend(extract_patch_files(s));
        }
    }
    // Sort before dedup: `dedup` only drops *adjacent* duplicates, and the two
    // sources here interleave — an `apply_patch` naming `a.rs` in `file_path`
    // and again in a patch header that also touches `b.rs` yields
    // `[a.rs, b.rs, a.rs]`, which a bare `dedup` leaves alone. A file counted
    // twice inflates every "how often was this touched" query.
    out.sort();
    out.dedup();
    out
}

pub fn extract_net_for_tool(_tool: &str, input: &Value) -> Vec<String> {
    let mut out = vec![];
    for key in NET_KEYS {
        if let Some(s) = input.get(key).and_then(Value::as_str) {
            out.extend(extract_fqdns(s));
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn extract_patch_files(patch: &str) -> Vec<String> {
    patch
        .lines()
        .filter_map(|l| {
            l.strip_prefix("*** Add File: ")
                .or_else(|| l.strip_prefix("*** Update File: "))
                .or_else(|| l.strip_prefix("*** Delete File: "))
        })
        .map(|s| s.trim().to_string())
        .collect()
}

/// Slack the parse-time cap leaves the redactor.
///
/// Adapters cap while parsing and the redactor runs afterwards, so a secret
/// lying across the cap boundary used to be cut in half — and half a token no
/// longer matches the pattern that would have removed it, so what survived was
/// a fragment of a live credential nobody could see was one. Parsing therefore
/// caps to `max + this`, the redactor sees whole tokens, and [`cap_mode`]
/// trims the rest away afterwards. Bounded work either way — the slack is a
/// constant, not a share of the input.
///
/// 512 bytes covers the shapes that fit in a field: an API key, a bearer
/// token, an access-key id. It does not cover a PEM block, which runs to
/// thousands of bytes and so can still be cut in two; that is why
/// [`crate::redact`] carries a second rule matching the
/// `-----BEGIN … PRIVATE KEY-----` header on its own. A severed key is at
/// least named as one — its remaining base64 still ships, which is the honest
/// limit of capping before scrubbing.
pub const REDACTION_HEADROOM: usize = 512;

fn working(max: usize) -> usize {
    if max == 0 {
        0
    } else {
        max.saturating_add(REDACTION_HEADROOM)
    }
}

/// The parse-time cap: a working ceiling, not the final one.
///
/// It keeps both ends regardless of the configured mode, because the final cap
/// cannot invent bytes that this one has already thrown away — a `head_tail`
/// deployment whose parse-time cap kept only the head would show a "tail" taken
/// from the middle of the field.
pub fn cap_text(s: &str, max: usize) -> String {
    cap_mode(s, working(max), crate::config::TruncateMode::HeadTail)
}

/// The final cap, applied after redaction.
pub fn cap_mode(s: &str, max: usize, mode: crate::config::TruncateMode) -> String {
    use crate::config::TruncateMode as M;
    if max == 0 || s.len() <= max {
        return s.to_string();
    }
    match mode {
        M::Drop => "[truncated]".to_string(),
        M::Head => format!("{}…[truncated]", head(s, max)),
        M::HeadTail => {
            let h = max * 3 / 4;
            format!("{}…[truncated]…{}", head(s, h), tail(s, max - h))
        }
    }
}

/// The first `n` bytes, rounded down to a character boundary.
fn head(s: &str, n: usize) -> &str {
    let mut end = n.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// The last `n` bytes, rounded up to a character boundary.
fn tail(s: &str, n: usize) -> &str {
    let mut start = s.len().saturating_sub(n);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// Apply the final cap to every user-authored string in an event.
///
/// Runs after redaction, on the enrichment stage — see [`REDACTION_HEADROOM`]
/// for why the order matters. It visits exactly the fields the redactor does,
/// through the same walk, so a field that is capped is one that was scrubbed
/// first and a new field cannot pick up one without the other.
pub fn cap_event(mut e: Event, capture: &CaptureCfg) -> Event {
    let (max, mode) = (capture.max_field_bytes, capture.truncate_mode);
    if max == 0 {
        return e;
    }
    crate::event::visit_strings(&mut e.kind, &mut |s| {
        if s.len() > max {
            *s = cap_mode(s, max, mode);
        }
    });
    e
}

/// How much larger than one field's cap a whole structure may be before it is
/// dropped outright.
///
/// Capping each string separately bounds the *strings*, not their number: a
/// payload of ten thousand short ones is still ten thousand. This is the
/// backstop for that shape, and it is deliberately loose — at the default cap
/// it is a megabyte — because reaching it destroys the event, and an ordinary
/// tool call with a dozen populated fields must never come close.
const STRUCTURE_CEILING: usize = 16;

/// Deepest nesting that is walked rather than dropped.
///
/// `cap_leaves` recurses, and a stack overflow is not an error the daemon can
/// report — hence a bound. `serde_json` stops parsing at 128 levels, so that
/// is the deepest thing the socket can deliver, but 32 is the limit that
/// actually bites: a payload nested forty deep parses fine and then loses
/// everything below level 32 to a `depth` marker. Set far below any nesting a
/// real tool input reaches, because the cost of hitting it is bounded and the
/// cost of not having it is not.
const MAX_DEPTH: usize = 32;

/// Cap every string inside `v`, keeping the structure around them.
///
/// This used to replace the whole value with `{"_truncated": …}` the moment its
/// serialized form went one byte over, which meant a `Write` of a large file
/// cost the `file_path` too — the record said something big was written and not
/// what, which is the one detail an investigation needs. Capping the leaves
/// keeps every key and every short field, and truncates only what is actually
/// oversized.
pub fn cap_value(v: Value, max: usize) -> Value {
    if max == 0 {
        return v;
    }
    let capped = cap_leaves(v, max, 0);
    let n = serde_json::to_string(&capped).map(|s| s.len()).unwrap_or(0);
    if n > max.saturating_mul(STRUCTURE_CEILING) {
        return serde_json::json!({"_truncated": true, "_bytes": n});
    }
    capped
}

fn cap_leaves(v: Value, max: usize, depth: usize) -> Value {
    match v {
        Value::String(s) => Value::String(cap_text(&s, max)),
        Value::Array(_) | Value::Object(_) if depth >= MAX_DEPTH => {
            serde_json::json!({"_truncated": true, "_reason": "depth"})
        }
        Value::Array(a) => Value::Array(
            a.into_iter()
                .map(|x| cap_leaves(x, max, depth + 1))
                .collect(),
        ),
        Value::Object(o) => Value::Object(
            o.into_iter()
                .map(|(k, x)| (k, cap_leaves(x, max, depth + 1)))
                .collect(),
        ),
        other => other,
    }
}

/// Extract deduped hostnames from any http(s) URLs inside a string.
///
/// Skips an optional `user:pass@` userinfo section and captures only
/// hostname characters, so the match can't end with `.` or `-` (and
/// therefore doesn't swallow trailing punctuation like a sentence-final
/// dot or a closing paren). IPv6-literal hosts (`https://[::1]/`) are
/// out of scope for FQDN extraction.
pub fn extract_fqdns(text: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r#"(?i)https?://(?:[^/@?#\s"'<>]*@)?([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)"#)
            .unwrap()
    });
    let mut out: Vec<String> = re
        .captures_iter(text)
        .map(|c| c[1].to_lowercase())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_dispatches_and_unknown_source_is_raw() {
        let env = Envelope {
            source: "some-future-tool".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({"x": 1}),
        };
        let events = parse(env, &CaptureCfg::default());
        assert!(matches!(
            &events[0].kind,
            crate::event::EventKind::Raw { .. }
        ));
        assert_eq!(events[0].source, "some-future-tool");
        assert!(
            crate::harness::HARNESSES
                .iter()
                .any(|h| h.id() == "claude-code")
        );
    }

    #[test]
    fn extract_patch_files_reads_apply_patch_headers() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n@@\n*** Add File: docs/b.md\n*** Delete File: old.txt\n*** End Patch";
        assert_eq!(
            extract_patch_files(patch),
            vec!["src/a.rs".to_string(), "docs/b.md".into(), "old.txt".into()]
        );
    }

    #[test]
    fn generic_file_and_net_extraction() {
        let input = serde_json::json!({"filePath": "/r/x.ts", "url": "https://api.example.com/v1"});
        assert_eq!(
            extract_files_for_tool("someTool", &input),
            vec!["/r/x.ts".to_string()]
        );
        assert_eq!(
            extract_net_for_tool("someTool", &input),
            vec!["api.example.com".to_string()]
        );
        let patch_input = serde_json::json!({"input": "*** Update File: lib/z.py\n@@"});
        assert_eq!(
            extract_files_for_tool("apply_patch", &patch_input),
            vec!["lib/z.py".to_string()]
        );
    }

    /// A command is not a file, and `files` is what a reviewer reads to answer
    /// "what did this session touch". A shell command mentions paths in a
    /// dozen shapes, none of them a claim that the tool opened one, so a key
    /// carrying a command must never join `FILE_KEYS` — the list would fill
    /// with strings that only look like paths, and file capture keys off the
    /// same list.
    #[test]
    fn a_shell_command_is_not_a_file_path() {
        let input = serde_json::json!({"command": "cat /etc/passwd > /tmp/out.txt"});
        assert!(extract_files_for_tool("Bash", &input).is_empty());
        assert!(extract_files_for_tool("shell", &input).is_empty());
    }

    /// The same path reached through both sources — a path key and a patch
    /// header — must be counted once. It arrives non-adjacent whenever the
    /// patch touches anything else first, which is the ordinary case.
    #[test]
    fn a_file_named_twice_is_listed_once() {
        let input = serde_json::json!({
            "file_path": "src/a.rs",
            "patch": "*** Update File: src/b.rs\n@@\n*** Update File: src/a.rs\n@@",
        });
        assert_eq!(
            extract_files_for_tool("apply_patch", &input),
            vec!["src/a.rs".to_string(), "src/b.rs".to_string()]
        );
    }

    #[test]
    fn cap_helpers_truncate() {
        assert_eq!(cap_text("short", 100), "short");
        let long = "x".repeat(10_000);
        let capped = cap_text(&long, 50);
        assert!(
            capped.len() < 700 && capped.contains("…[truncated]…"),
            "the parse-time cap did not bound the field: {} bytes",
            capped.len()
        );
        assert_eq!(cap_text(&long, 0), long, "0 disables the cap");
        let big = serde_json::json!({"blob": "y".repeat(10_000)});
        let v = cap_value(big.clone(), 50);
        assert!(
            v["blob"].as_str().unwrap().len() < 700,
            "the oversized leaf was not capped: {v}"
        );
        assert_eq!(cap_value(big.clone(), 0), big);
    }

    /// The parse-time cap is a working ceiling: it leaves the redactor room to
    /// match a token lying across the final boundary. Without the slack, the
    /// redactor sees a fragment, nothing matches, and the fragment ships.
    #[test]
    fn the_parse_time_cap_leaves_the_redactor_headroom() {
        let capped = cap_text(&"x".repeat(10_000), 64);
        assert!(
            capped.len() > 64 + 400,
            "no headroom left for the redactor: {} bytes",
            capped.len()
        );
        assert!(
            capped.len() < 64 + REDACTION_HEADROOM + 32,
            "the headroom is unbounded work, not slack: {} bytes",
            capped.len()
        );
    }

    /// A `head_tail` deployment cannot show a tail the parse-time cap already
    /// threw away, so that cap keeps both ends whatever the configured mode is.
    #[test]
    fn the_parse_time_cap_keeps_both_ends() {
        let s = format!("{}{}", "a".repeat(10_000), "OMEGA");
        let capped = cap_text(&s, 64);
        assert!(capped.starts_with("aaa"));
        assert!(
            capped.ends_with("OMEGA"),
            "the true tail was discarded before the final cap could keep it"
        );
    }

    #[test]
    fn each_mode_keeps_what_it_says_it_keeps() {
        use crate::config::TruncateMode as M;
        let s = format!("HEAD{}TAIL", "-".repeat(1_000));
        let head = cap_mode(&s, 64, M::Head);
        assert!(head.starts_with("HEAD") && head.ends_with("…[truncated]"));
        assert!(head.len() < 96, "{} bytes", head.len());

        let both = cap_mode(&s, 64, M::HeadTail);
        assert!(
            both.starts_with("HEAD") && both.ends_with("TAIL"),
            "head_tail lost an end: {both}"
        );
        assert!(both.len() < 96, "{} bytes", both.len());

        assert_eq!(cap_mode(&s, 64, M::Drop), "[truncated]");
        assert_eq!(
            cap_mode("short", 64, M::Drop),
            "short",
            "a field under the cap is untouched"
        );
    }

    /// Cutting a string at a byte offset inside a character panics; a payload
    /// full of emoji or CJK is ordinary, not adversarial.
    #[test]
    fn capping_lands_on_character_boundaries() {
        let s = "é".repeat(500);
        for mode in [
            crate::config::TruncateMode::Head,
            crate::config::TruncateMode::HeadTail,
        ] {
            let out = cap_mode(&s, 65, mode);
            assert!(out.len() < 128, "{mode:?}: {} bytes", out.len());
            assert!(out.contains('é'), "{mode:?} kept nothing readable");
        }
    }

    /// The record of a large write has to say *what* was written. Dropping the
    /// whole input left "something big happened here" and nothing else — the
    /// file path, the tool, the surrounding keys, all gone for the sake of one
    /// oversized field.
    #[test]
    fn only_the_oversized_leaf_of_a_structure_is_truncated() {
        let v = cap_value(
            serde_json::json!({
                "file_path": "/repo/src/main.rs",
                "content": "z".repeat(1_000_000),
                "line": 12,
                "flags": ["a", "b"],
            }),
            64,
        );
        assert_eq!(v["file_path"], "/repo/src/main.rs");
        assert_eq!(v["line"], 12);
        assert_eq!(v["flags"], serde_json::json!(["a", "b"]));
        let content = v["content"].as_str().unwrap();
        assert!(content.starts_with("zzz") && content.contains("…[truncated]…"));
        assert!(
            content.len() < 64 + REDACTION_HEADROOM + 32,
            "leaf cap not applied: {}",
            content.len()
        );
    }

    /// Per-leaf capping bounds the strings, not how many there are. Without a
    /// ceiling on the whole structure, a payload of a hundred thousand short
    /// strings passes every individual check and lands in the buffer entire.
    #[test]
    fn a_structure_of_many_small_strings_still_hits_a_ceiling() {
        let many: Vec<Value> = (0..5_000).map(|i| Value::String(format!("s{i}"))).collect();
        let v = cap_value(Value::Array(many), 64);
        assert_eq!(
            v["_truncated"], true,
            "a structure far past the ceiling was kept whole"
        );

        // And the ceiling is loose enough that an ordinary multi-field input
        // is not caught by it.
        let ordinary = serde_json::json!({
            "file_path": "/repo/src/main.rs",
            "old_string": "a".repeat(60),
            "new_string": "b".repeat(60),
        });
        assert_eq!(cap_value(ordinary.clone(), 64), ordinary);
    }

    /// `cap_leaves` recurses, so depth is a stack bound, not a size bound.
    #[test]
    fn nesting_deeper_than_the_walk_is_dropped_not_followed() {
        let mut v = Value::String("leaf".into());
        for _ in 0..64 {
            v = Value::Array(vec![v]);
        }
        let capped = cap_value(v, 64);
        let mut cur = &capped;
        for _ in 0..MAX_DEPTH {
            cur = &cur[0];
        }
        assert_eq!(cur["_truncated"], true);
        assert_eq!(cur["_reason"], "depth");
    }

    #[test]
    fn extract_fqdns_handles_credentials_punctuation_and_ports() {
        assert_eq!(
            extract_fqdns("clone https://user:token@github.com/org/repo.git"),
            vec!["github.com"]
        );
        assert_eq!(
            extract_fqdns("see (https://evil.example.com) for details"),
            vec!["evil.example.com"]
        );
        assert_eq!(
            extract_fqdns("trailing dot https://example.com. end"),
            vec!["example.com"]
        );
        assert_eq!(
            extract_fqdns("port https://example.com:8080/path"),
            vec!["example.com"]
        );
        assert_eq!(
            extract_fqdns("upper HTTPS://MiXeD.Example.COM/x"),
            vec!["mixed.example.com"]
        );
        assert_eq!(
            extract_fqdns("query at https://exfil.evil.com?to=admin@corp.com"),
            vec!["exfil.evil.com"]
        );
        assert_eq!(
            extract_fqdns("fragment https://evil.com#a@b.com"),
            vec!["evil.com"]
        );
    }
}
