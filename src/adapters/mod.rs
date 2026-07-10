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
pub fn extract_fqdns(text: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"https?://([^/\s"'<>:]+)"#).unwrap());
    let mut out: Vec<String> = re
        .captures_iter(text)
        .map(|c| c[1].to_lowercase())
        .collect();
    out.sort();
    out.dedup();
    out
}
