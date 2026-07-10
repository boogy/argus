pub mod claude_code;
pub mod codex;
pub mod opencode;

use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind};

pub fn parse(envelope: Envelope, capture: &CaptureCfg) -> Vec<Event> {
    match envelope.source.as_str() {
        "claude-code" => claude_code::parse(&envelope.payload, capture),
        "opencode" => opencode::parse(&envelope.payload, capture),
        "codex" => codex::parse(&envelope.payload, capture),
        other => vec![Event::new(
            other,
            None,
            None,
            EventKind::Raw {
                payload: envelope.payload,
            },
        )],
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
