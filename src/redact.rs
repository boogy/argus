use crate::config::RedactionCfg;
use crate::event::{Event, EventKind};
use regex::Regex;

pub struct Redactor {
    rules: Vec<(String, Regex)>,
    enabled: bool,
}

const BUILTIN: &[(&str, &str)] = &[
    ("anthropic-key", r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    ("openai-key", r"sk-[A-Za-z0-9_\-]{20,}"),
    ("bearer-token", r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{16,}"),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("aws-access-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    (
        "private-key-block",
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    (
        "generic-assignment",
        r#"(?i)(api[_-]?key|secret|password|token)["']?\s*[:=]\s*["'][^"']{8,}["']"#,
    ),
    (
        "generic-assignment-unquoted",
        r#"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*[^\s"']{8,}"#,
    ),
];

impl Redactor {
    pub fn new(cfg: &RedactionCfg) -> Self {
        let mut rules: Vec<(String, Regex)> = BUILTIN
            .iter()
            .filter_map(|(name, p)| Regex::new(p).ok().map(|r| (name.to_string(), r)))
            .collect();
        for (i, p) in cfg.extra_patterns.iter().enumerate() {
            match Regex::new(p) {
                Ok(r) => rules.push((format!("custom-{i}"), r)),
                Err(e) => tracing::warn!("skipping invalid redaction pattern {p:?}: {e}"),
            }
        }
        Redactor {
            rules,
            enabled: cfg.enabled,
        }
    }

    pub fn scrub_str(&self, s: &str) -> String {
        if !self.enabled {
            return s.to_string();
        }
        let mut out = s.to_string();
        for (name, re) in &self.rules {
            out = re
                .replace_all(&out, format!("[REDACTED:{name}]"))
                .into_owned();
        }
        out
    }

    fn scrub_json(&self, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => *s = self.scrub_str(s),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| self.scrub_json(x)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|x| self.scrub_json(x)),
            _ => {}
        }
    }

    pub fn scrub_event(&self, mut e: Event) -> Event {
        if !self.enabled {
            return e;
        }
        match &mut e.kind {
            EventKind::Prompt { text } => *text = self.scrub_str(text),
            EventKind::ToolUse { input, .. } => self.scrub_json(input),
            EventKind::Skill { args: Some(a), .. } => *a = self.scrub_str(a),
            EventKind::Raw { payload } => self.scrub_json(payload),
            _ => {}
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionCfg;

    fn r() -> Redactor {
        Redactor::new(&RedactionCfg::default())
    }

    #[test]
    fn scrubs_common_secrets() {
        let cases = [
            ("key sk-ant-api03-AbCd1234567890abcdef1234 done", "sk-ant"),
            (
                "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x.y",
                "Bearer",
            ),
            ("token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 ok", "ghp_"),
            ("AKIAIOSFODNN7EXAMPLE is an aws key id", "AKIA"),
            ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE KEY"),
        ];
        for (input, must_not_survive) in cases {
            let out = r().scrub_str(input);
            assert!(!out.contains(must_not_survive), "leaked in: {out}");
            assert!(out.contains("[REDACTED:"), "no redaction marker in: {out}");
        }
    }

    #[test]
    fn scrubs_nested_tool_input_json() {
        let e = crate::event::Event::new(
            "claude-code",
            None,
            None,
            crate::event::EventKind::ToolUse {
                tool: "Bash".into(),
                phase: "pre".into(),
                input: serde_json::json!({"command": "curl -H 'Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'"}),
                files: vec![],
                fqdns: vec![],
            },
        );
        let out = r().scrub_event(e);
        let s = serde_json::to_string(&out).unwrap();
        assert!(!s.contains("ghp_AbCdEf"));
    }

    #[test]
    fn extra_patterns_from_config_apply() {
        let cfg = RedactionCfg {
            enabled: true,
            extra_patterns: vec!["ACME-[0-9]{6}".into()],
        };
        let out = Redactor::new(&cfg).scrub_str("badge ACME-123456 end");
        assert!(!out.contains("ACME-123456"));
    }

    #[test]
    fn disabled_is_identity() {
        let cfg = RedactionCfg {
            enabled: false,
            extra_patterns: vec![],
        };
        assert_eq!(
            Redactor::new(&cfg).scrub_str("sk-ant-api03-AbCd1234567890abcdef1234"),
            "sk-ant-api03-AbCd1234567890abcdef1234"
        );
    }

    #[test]
    fn pem_block_body_does_not_leak() {
        let input =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEoSECRETBODYDATA\n-----END RSA PRIVATE KEY-----\n";
        let out = r().scrub_str(input);
        assert!(!out.contains("SECRETBODYDATA"), "PEM body leaked: {out}");
        assert!(out.contains("[REDACTED:private-key-block]"));
    }

    #[test]
    fn truncated_pem_header_still_redacted() {
        let out = r().scrub_str("-----BEGIN EC PRIVATE KEY-----\nMIIEoPARTIAL");
        assert!(!out.contains("BEGIN EC PRIVATE KEY"));
    }

    #[test]
    fn unquoted_assignment_is_redacted() {
        let out = r().scrub_str("export PASSWORD=hunter2secret and API_KEY=abcd1234efgh");
        assert!(
            !out.contains("hunter2secret"),
            "unquoted password leaked: {out}"
        );
        assert!(
            !out.contains("abcd1234efgh"),
            "unquoted api key leaked: {out}"
        );
    }

    #[test]
    fn custom_rules_get_indexed_names() {
        let cfg = crate::config::RedactionCfg {
            enabled: true,
            extra_patterns: vec!["AAA[0-9]{4}".into(), "BBB[0-9]{4}".into()],
        };
        let red = Redactor::new(&cfg);
        assert!(red.scrub_str("x AAA1234 y").contains("[REDACTED:custom-0]"));
        assert!(red.scrub_str("x BBB1234 y").contains("[REDACTED:custom-1]"));
    }
}
