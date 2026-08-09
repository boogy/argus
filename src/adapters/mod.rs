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

const FILE_KEYS: &[&str] = &["file_path", "filePath", "notebook_path", "path"];
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

pub fn cap_text(s: &str, max: usize) -> String {
    if max == 0 || s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated]", &s[..end])
}

pub fn cap_value(v: Value, max: usize) -> Value {
    if max == 0 {
        return v;
    }
    let n = serde_json::to_string(&v).map(|s| s.len()).unwrap_or(0);
    if n <= max {
        v
    } else {
        serde_json::json!({"_truncated": true, "_bytes": n})
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
        let long = "x".repeat(200);
        let capped = cap_text(&long, 50);
        assert!(capped.len() < 200 && capped.ends_with("…[truncated]"));
        assert_eq!(cap_text(&long, 0), long, "0 disables the cap");
        let big = serde_json::json!({"blob": "y".repeat(200)});
        let v = cap_value(big.clone(), 50);
        assert_eq!(v["_truncated"], true);
        assert_eq!(cap_value(big.clone(), 0), big);
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
