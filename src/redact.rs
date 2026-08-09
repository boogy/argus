use crate::config::RedactionCfg;
use crate::event::{Event, EventKind};
use regex::{Regex, RegexSet};
use std::borrow::Cow;

pub struct Redactor {
    rules: Vec<(String, Regex)>,
    /// The same patterns as `rules`, in the same order, compiled into one
    /// automaton. Almost no string a session produces contains a secret, and
    /// this answers "which rules could possibly match" in a single pass over
    /// the input — so the common case allocates nothing at all, and a string
    /// that does match is rewritten once per *matching* rule instead of once
    /// per rule. Indices are only meaningful because both are built from the
    /// same filtered list; see `new`.
    set: RegexSet,
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
        r#"(?i)(?:\b|_)(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*[^\s"']{8,}"#,
    ),
];

/// Counts regex-set compilations. Building a `Redactor` recompiles every
/// pattern, so the daemon caches one and rebuilds only on a config change —
/// a guarantee that is invisible in the output and therefore counted here.
#[cfg(test)]
pub(crate) static REDACTOR_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

impl Redactor {
    pub fn new(cfg: &RedactionCfg) -> Self {
        #[cfg(test)]
        REDACTOR_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // A pattern that fails to compile is dropped from *both* the rule list
        // and the set, in one pass, so rule `i` and set index `i` always name
        // the same pattern. Building the set from `BUILTIN` directly would
        // silently misalign every rule after the first bad pattern.
        let named: Vec<(String, &str)> = BUILTIN
            .iter()
            .map(|(name, p)| ((*name).to_string(), *p))
            .chain(
                cfg.extra_patterns
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (format!("custom-{i}"), p.as_str())),
            )
            .collect();
        let mut rules: Vec<(String, Regex)> = Vec::with_capacity(named.len());
        let mut patterns: Vec<&str> = Vec::with_capacity(named.len());
        for (name, p) in &named {
            match Regex::new(p) {
                Ok(r) => {
                    rules.push((name.clone(), r));
                    patterns.push(p);
                }
                Err(e) => tracing::warn!("skipping invalid redaction pattern {p:?}: {e}"),
            }
        }
        // Every pattern here already compiled individually, so the set can only
        // fail on a size limit; an empty set matches nothing, which fails safe
        // in the wrong direction — so fall back to "everything might match".
        let set = RegexSet::new(&patterns).unwrap_or_else(|e| {
            tracing::warn!("redaction prefilter unavailable, scanning every rule: {e}");
            RegexSet::new(std::iter::repeat_n("", patterns.len())).expect("empty patterns compile")
        });
        Redactor {
            rules,
            set,
            enabled: cfg.enabled,
        }
    }

    /// Borrows when nothing matched — which is the overwhelmingly common case
    /// on a text-heavy event stream.
    pub fn scrub_str<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(s);
        }
        let mut out = Cow::Borrowed(s);
        // Candidates come from the *original* string. A replacement inserts
        // only `[REDACTED:<rule-name>]`, which none of these patterns match, so
        // this cannot miss a match that the sequential scan would have found.
        for i in self.set.matches(s) {
            let (name, re) = &self.rules[i];
            out = Cow::Owned(
                re.replace_all(&out, format!("[REDACTED:{name}]"))
                    .into_owned(),
            );
        }
        out
    }

    /// Rewrites in place, leaving the original allocation untouched when there
    /// was nothing to redact.
    fn scrub_in_place(&self, s: &mut String) {
        if let Cow::Owned(scrubbed) = self.scrub_str(s) {
            *s = scrubbed;
        }
    }

    fn scrub_json(&self, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => self.scrub_in_place(s),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| self.scrub_json(x)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|x| self.scrub_json(x)),
            _ => {}
        }
    }

    pub fn scrub_event(&self, mut e: Event) -> Event {
        if !self.enabled {
            return e;
        }
        // Every variant and every field is named — no `..`, no `_ =>`. This is
        // the point of the match: a new secret-bearing field added to
        // `EventKind` must not quietly ship unscrubbed to the SIEM, so it has
        // to become a compile error here instead. Fields deliberately left
        // alone are still listed, prefixed `_`, so skipping one is a decision
        // on the record rather than an oversight.
        match &mut e.kind {
            EventKind::Prompt { text } | EventKind::AssistantMessage { text } => {
                self.scrub_in_place(text)
            }
            // Both halves are prompt text and both can carry a secret — the
            // rewritten one especially, since whatever a policy hook splices in
            // is not something the user chose to type.
            EventKind::PromptTransformed {
                original,
                transformed,
            } => {
                self.scrub_in_place(original);
                self.scrub_in_place(transformed);
            }
            EventKind::ToolUse {
                tool: _,
                phase: _,
                input,
                output,
                error,
                // A duration and a cancelled-by-a-human flag: neither can
                // carry a secret, so neither is scrubbed.
                duration_ms: _,
                interrupted: _,
                files: _,
                fqdns: _,
            } => {
                self.scrub_json(input);
                self.scrub_json(output);
                if let Some(err) = error {
                    self.scrub_in_place(err);
                }
            }
            // `name`/`agent_type` are tool identifiers, not user content.
            EventKind::Skill { name: _, args } => {
                if let Some(a) = args {
                    self.scrub_in_place(a);
                }
            }
            EventKind::Agent {
                agent_type: _,
                description,
            } => {
                if let Some(d) = description {
                    self.scrub_in_place(d);
                }
            }
            EventKind::Permission {
                tool: _,
                action: _,
                input,
            } => self.scrub_json(input),
            EventKind::Notification {
                message,
                category: _,
                title,
            } => {
                self.scrub_in_place(message);
                if let Some(t) = title {
                    self.scrub_in_place(t);
                }
            }
            EventKind::Error {
                message,
                context: _,
                // Scrubbed, unlike `context`, whose vocabulary the host tool
                // enumerates. This one is whatever the throwing code called
                // its error class, and code that builds a class name by
                // interpolation puts the interpolated value here.
                name,
                // A boolean.
                recoverable: _,
            } => {
                self.scrub_in_place(message);
                if let Some(n) = name {
                    self.scrub_in_place(n);
                }
            }
            EventKind::Session { action: _, detail } => self.scrub_json(detail),
            EventKind::Raw { payload } => self.scrub_json(payload),
            // Everything but `instructions` is enumerated or a count. That
            // one is free text the user typed, and it is typed at the moment
            // they are deciding what the transcript should stop holding.
            EventKind::Compact {
                phase: _,
                trigger: _,
                tokens_before: _,
                tokens_after: _,
                instructions,
            } => {
                if let Some(i) = instructions {
                    self.scrub_in_place(i);
                }
            }
            // Enumerated, fixed-vocabulary fields: nothing user-authored.
            EventKind::FileChange { path: _, action: _ }
            | EventKind::Integrity {
                status: _,
                tool: _,
                detail: _,
            } => {}
            // Argus writes all three of these itself; nothing here came from
            // the host tool. `detail` is scrubbed anyway, since it is the one
            // field a future reason could reasonably widen to carry a path.
            EventKind::Loss {
                reason: _,
                count: _,
                detail,
            } => self.scrub_in_place(detail),
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
                output: serde_json::Value::Null,
                error: None,
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns: vec![],
            },
        );
        let out = r().scrub_event(e);
        let s = serde_json::to_string(&out).unwrap();
        assert!(!s.contains("ghp_AbCdEf"));
    }

    #[test]
    fn new_kinds_are_scrubbed() {
        let secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let cases = vec![
            crate::event::EventKind::AssistantMessage {
                text: format!("token {secret}"),
            },
            crate::event::EventKind::Notification {
                message: format!("use {secret}"),
                category: "x".into(),
                title: None,
            },
            // The title is what a human reads, and a tool that puts the
            // interesting part in the title is not doing anything unusual.
            crate::event::EventKind::Notification {
                message: "use it".into(),
                category: "x".into(),
                title: Some(format!("copy {secret}")),
            },
            crate::event::EventKind::Error {
                message: format!("auth {secret}"),
                context: "x".into(),
                name: None,
                recoverable: None,
            },
            crate::event::EventKind::Error {
                message: "auth failed".into(),
                context: "x".into(),
                name: Some(format!("BadTokenError({secret})")),
                recoverable: Some(false),
            },
            // The one place a user is explicitly writing about what should
            // not be kept — and quoting it while they do is the obvious way
            // to get it wrong.
            crate::event::EventKind::Compact {
                phase: "pre".into(),
                trigger: "manual".into(),
                tokens_before: None,
                tokens_after: None,
                instructions: Some(format!("drop the part where I pasted {secret}")),
            },
            crate::event::EventKind::Permission {
                tool: "Bash".into(),
                action: "requested".into(),
                input: serde_json::json!({"command": format!("curl -H 'X: {secret}'")}),
            },
            crate::event::EventKind::Session {
                action: "SessionEnd".into(),
                detail: serde_json::json!({"reason": format!("had {secret}")}),
            },
            // Listed twice on purpose: an arm that scrubs one half and forgets
            // the other still passes with a single case, and the rewritten
            // half is the one a policy hook — not the user — authored.
            crate::event::EventKind::PromptTransformed {
                original: format!("deploy with {secret}"),
                transformed: "deploy".into(),
            },
            crate::event::EventKind::PromptTransformed {
                original: "deploy".into(),
                transformed: format!("deploy using {secret}"),
            },
            crate::event::EventKind::ToolUse {
                tool: "Bash".into(),
                phase: "post".into(),
                input: serde_json::Value::Null,
                output: serde_json::json!({"stdout": format!("printed {secret}")}),
                error: Some(format!("failed with {secret}")),
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns: vec![],
            },
        ];
        for kind in cases {
            let e = crate::event::Event::new("t", None, None, kind);
            let s = serde_json::to_string(&r().scrub_event(e)).unwrap();
            assert!(!s.contains("ghp_AbCdEf"), "leaked: {s}");
        }
    }

    #[test]
    fn clean_text_is_not_reallocated() {
        // Nearly everything flowing through here is ordinary prose and code.
        // Paying ten full-string rewrites for each of those was the cost this
        // prefilter exists to remove, so the borrow is the assertion.
        let clean = "read src/main.rs and summarise the daemon loop for me";
        assert!(
            matches!(r().scrub_str(clean), Cow::Borrowed(_)),
            "a string with no secret in it must not be copied"
        );
        assert!(
            matches!(
                r().scrub_str("token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
                Cow::Owned(_)
            ),
            "a string that does match still has to be rewritten"
        );
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

    #[test]
    fn underscore_prefixed_env_var_assignments_are_redacted() {
        let out = r().scrub_str(
            "ANTHROPIC_API_KEY=abcd1234efgh DB_PASSWORD=hunter2secret GITHUB_TOKEN=ghx12345678",
        );
        assert!(!out.contains("abcd1234efgh"), "leaked: {out}");
        assert!(!out.contains("hunter2secret"), "leaked: {out}");
        assert!(!out.contains("ghx12345678"), "leaked: {out}");
    }
}
