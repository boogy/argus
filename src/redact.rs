use crate::config::RedactionCfg;
use crate::event::Event;
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

/// The name half of an assignment that holds a secret.
///
/// The marker word is not reliably the *last* segment of the key:
/// `AWS_SECRET_ACCESS_KEY` ends in `KEY`, `STRIPE_SECRET_KEY` carries `SECRET`
/// in the middle, and a rule anchored on a trailing marker ships both — which
/// between them is most of what a `.env` holds. So the marker is matched as a
/// whole `_`/`-`/`.`-delimited *segment*, with any segments before and after
/// it. Requiring a segment and not a substring is what still refuses
/// `TOKENIZER=`, where `token` names nothing.
///
/// A macro rather than a const because `concat!` takes literals only, and the
/// two rules below must share one definition or drift apart.
macro_rules! secret_marker {
    () => {
        r"api[_-]?key|secret|password|passwd|token|credential"
    };
}

/// The same markers, but only their first letter may be capitalized.
///
/// `SecretKey` is how .NET and Java config spell it, and the lower-case-first
/// [`secret_key_name`] camel branch cannot see it. Matching the rest of the
/// word case-insensitively instead would put `TOKENIZER` back in range, where
/// `IZER` reads as a following camel segment — so the tail stays lower-case
/// and only the lead is allowed to shout.
macro_rules! secret_marker_lead {
    () => {
        r"[Aa]pi[_-]?[Kk]ey|[Ss]ecret|[Pp]assword|[Pp]asswd|[Tt]oken|[Cc]redential"
    };
}

macro_rules! secret_key_name {
    () => {
        concat!(
            r"(?:\b|_)(?:",
            // `AWS_SECRET_ACCESS_KEY`, `stripe-secret-key`,
            // `my.service.password.value`: the marker is one whole segment,
            // wherever in the name it falls.
            //
            // The two optional pieces after the marker are what a name with no
            // separator left to give still needs: `SECRETKEY` runs two words
            // together, and `API_KEY2` numbers a rotation. Both end the name
            // where `\b` cannot see a boundary. Only a second *marker-ish*
            // word is allowed to run on, which is what keeps `TOKENIZER` out —
            // `IZER` is not one of them, so the name still ends mid-word and
            // nothing matches.
            r"(?:[A-Za-z0-9]+[_\-.])*(?i:",
            secret_marker!(),
            // The trailing `s` is the same problem in its smallest form:
            // `credential` is in the marker list and `credentials` is how the
            // key is actually spelled, and `SECRETS`/`PASSWORDS` end a word
            // where `\b` cannot see it. It cannot widen the rule onto a
            // neighbouring word — only `s` follows.
            r")(?i:key|token|secret|pass|value)?[Ss]?[0-9]*",
            r"(?:[_\-.][A-Za-z0-9]+)*",
            r"|",
            // `stripeSecretKey`, `accessToken`: in camelCase the case change is
            // the separator, so the lower-case character before the marker is
            // what a segment boundary looks like here.
            r"[A-Za-z0-9]*[a-z0-9](?i:",
            secret_marker!(),
            r")(?:[A-Z][A-Za-z0-9]*)*",
            r"|",
            // `secretKey`, `tokenValue`, `SecretKey`: the same shape with the
            // marker first, which is why the marker's tail is lower-case here
            // and only here. Matched case-insensitively it would swallow
            // `TOKENIZER`, where the `IZER` reads as a following camel segment
            // and `token` names nothing.
            r"(?:",
            secret_marker_lead!(),
            r")(?:[A-Z][A-Za-z0-9]*)+",
            r")",
        )
    };
}

const BUILTIN: &[(&str, &str)] = &[
    ("anthropic-key", r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    ("openai-key", r"sk-[A-Za-z0-9_\-]{20,}"),
    ("bearer-token", r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{16,}"),
    // `gh[pousr]_` is the classic spelling; `github_pat_` is the fine-grained
    // one GitHub has issued since 2022, and it is not a `gh?_` prefix.
    (
        "github-token",
        r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    ),
    ("aws-access-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    (
        "private-key-block",
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    // Case-insensitivity is scoped to the marker rather than set on the whole
    // pattern: the camelCase branches distinguish `Token` from `TOKEN`, and a
    // global `(?i)` would erase exactly that distinction.
    (
        "generic-assignment",
        concat!(secret_key_name!(), r#"["']?\s*[:=]\s*["'][^"']{8,}["']"#),
    ),
    (
        "generic-assignment-unquoted",
        concat!(secret_key_name!(), r#"\b\s*[:=]\s*[^\s"']{8,}"#),
    ),
    // A connection string announces nothing in its key name — `DATABASE_URL`
    // is not a secret and its value is. Only the credentials are matched: the
    // host and path that follow are what the record exists to report.
    ("url-credentials", r"://[^\s/:@]{1,128}:[^\s/@]{1,256}@"),
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

    pub fn scrub_event(&self, mut e: Event) -> Event {
        if !self.enabled {
            return e;
        }
        // The walk itself — which fields are user content and which are
        // argus's own vocabulary — lives on `EventKind`, because truncation
        // has to visit exactly the same set and two copies of that decision
        // would drift apart in opposite directions.
        crate::event::visit_strings(&mut e.kind, &mut |s| self.scrub_in_place(s));
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
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![],
            },
        );
        let out = r().scrub_event(e);
        let s = serde_json::to_string(&out).unwrap();
        assert!(!s.contains("ghp_AbCdEf"));
    }

    /// Captured file content is the largest concentration of credentials
    /// argus handles — a `.env` written through a `Write` is every secret in
    /// the project in one field.
    ///
    /// The exhaustive destructure in `scrub_event` is what forces a *decision*
    /// about a new field; it cannot force the right one, and "matched and left
    /// alone" compiles exactly as well as "scrubbed". That is what this test
    /// is for. The `path` beside the content deliberately survives untouched:
    /// it is an identifier every query joins on, not free text.
    #[test]
    fn captured_file_content_is_scrubbed() {
        let secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let e = crate::event::Event::new(
            "claude-code",
            None,
            None,
            crate::event::EventKind::ToolUse {
                tool: "Write".into(),
                phase: "post".into(),
                input: serde_json::Value::Null,
                output: serde_json::Value::Null,
                error: None,
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns: vec![],
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![crate::event::FileSnapshot {
                    path: "/repo/deploy.sh".into(),
                    action: crate::event::FileAction::Written,
                    bytes: 40,
                    sha256: None,
                    mtime: None,
                    source: crate::event::SnapshotSource::Payload,
                    content: Some(format!("export TOKEN={secret}")),
                    truncated: false,
                    skipped: None,
                }],
            },
        );
        let out = r().scrub_event(e);
        let crate::event::EventKind::ToolUse { file_contents, .. } = &out.kind else {
            panic!()
        };
        let content = file_contents[0].content.as_deref().unwrap();
        assert!(!content.contains("ghp_AbCdEf"), "leaked: {content}");
        assert!(content.contains("[REDACTED:"), "no marker: {content}");
        assert_eq!(file_contents[0].path, "/repo/deploy.sh");
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
            // `category` and `context` read like enumerations and are not:
            // Copilot fills them from `notificationType` and `errorContext`,
            // free-form strings a plugin author writes, and they are the one
            // field their adapters do not cap either.
            crate::event::EventKind::Notification {
                message: "heads up".into(),
                category: format!("auth-failure({secret})"),
                title: None,
            },
            crate::event::EventKind::Error {
                message: "call failed".into(),
                context: format!("while sending {secret}"),
                name: None,
                recoverable: None,
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
            // A receipt is almost all numbers, but the stop reason is a string
            // the provider chose, and a provider is free to put an error there.
            crate::event::EventKind::Usage {
                input_tokens: 1,
                output_tokens: 2,
                reasoning_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                cost: 0.5,
                finish: Some(format!("error: rejected {secret}")),
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
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![],
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

    /// The marker word is not always the last thing in the key name.
    /// `AWS_SECRET_ACCESS_KEY` ends in `KEY`, `STRIPE_SECRET_KEY` carries
    /// `SECRET` in the middle, and a rule that only recognises a *trailing*
    /// marker ships all three — which is most of what a `.env` contains.
    #[test]
    fn a_marker_anywhere_in_the_key_name_is_still_a_secret() {
        let cases = [
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "STRIPE_SECRET_KEY=sk_live_abcdefgh12345678",
            "SECRET_KEY=django-insecure-abcdefgh",
            "TOKEN_VALUE=abcdefgh12345678",
            "API_KEY_PROD=abcdefgh12345678",
            "my.service.password.value = hunter2secret",
            r#"{"aws_secret_access_key": "wJalrXUtnFEMIK7MDENGbPx"}"#,
            r#"{"stripeSecretKey": "sk_live_abcdefgh1234"}"#,
            r#"{"accessToken": "abcdefgh12345678"}"#,
            r#"{"secretKey": "django-insecure-abcdefgh"}"#,
            // A name with no separator left to give: `SecretKey` is how .NET
            // and Java config spell it, `SECRETKEY` runs the two words
            // together, and a trailing digit is what rotating a key looks
            // like. All three end where `\b` sees no boundary, so all three
            // used to ship.
            "SecretKey=abcdefgh12345678",
            "SECRETKEY=abcdefgh12345678",
            "API_KEY2=abcdefgh12345678",
            "TOKEN1=abcdefgh12345678",
            r#"{"SecretKey": "abcdefgh12345678"}"#,
            r#"{"SECRETKEY": "abcdefgh12345678"}"#,
            r#"{"API_KEY2": "abcdefgh12345678"}"#,
            r#"{"PasswordHash": "abcdefgh12345678"}"#,
            // Plurals: `credential` is in the marker list, and `credentials`
            // is how the key is spelled in practice.
            "SECRETS=abcdefgh12345678",
            "REFRESH_TOKENS=abcdefgh12345678",
            "PASSWORDS=abcdefgh12345678",
            r#"{"credentials": "abcdefgh12345678"}"#,
        ];
        for input in cases {
            let out = r().scrub_str(input);
            assert!(out.contains("[REDACTED:"), "no redaction marker in: {out}");
            for leak in [
                "wJalrXUtnFEMIK7MDENGbPx",
                "sk_live_abcdefgh",
                "django-insecure",
                "abcdefgh12345678",
                "hunter2secret",
            ] {
                assert!(!out.contains(leak), "leaked {leak} in: {out}");
            }
        }
    }

    /// The other half of that rule: a marker that is only a *substring* of a
    /// word names nothing secret, and redacting it would teach a deployment
    /// that the markers mean nothing.
    #[test]
    fn a_marker_inside_a_longer_word_is_not_a_secret() {
        for input in [
            "TOKENIZER=gpt2-large-model",
            "PASSWORDLESS=true-for-everyone",
            "SUBTOKEN_COUNT=12345678",
            // Widening the key-name rule to reach `SECRETKEY` and `TOKEN1`
            // means letting a name run past the marker without a separator.
            // These are the words that must not be let through with it: a
            // following word that names nothing (`ARY`, `IZER`) still ends the
            // name mid-word, and lower-case camel tails are not marker leads.
            "SECRETARY=abcdefgh12345678",
            "Tokenizer=gpt2-large-model",
            "TOKENIZER2=gpt2-large-model",
        ] {
            let out = r().scrub_str(input);
            assert_eq!(out, input, "redacted something that names no secret");
        }
    }

    /// Fine-grained PATs are the spelling GitHub has issued since 2022 and the
    /// one `gh[pousr]_` does not cover.
    #[test]
    fn fine_grained_github_pats_are_redacted() {
        for input in [
            "github_pat_11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ0123456789abcdefghijklmn",
            "Authorization: token github_pat_11ABCDEFG0abcdefghij_KLMNOPQRSTUVWXYZ01",
        ] {
            let out = r().scrub_str(input);
            assert!(!out.contains("github_pat_11"), "leaked in: {out}");
            assert!(out.contains("[REDACTED:"), "no redaction marker in: {out}");
        }
    }

    /// A connection string carries its password in a place no key name
    /// announces: `DATABASE_URL` names nothing secret, and the credential is
    /// inside the value. The host is left alone — it is what the record is for.
    #[test]
    fn credentials_inside_a_url_are_redacted() {
        let out = r().scrub_str("DATABASE_URL=postgres://admin:Sup3rS3cretPw@db.internal:5432/app");
        assert!(!out.contains("Sup3rS3cretPw"), "leaked in: {out}");
        assert!(!out.contains("admin"), "the user name leaked in: {out}");
        assert!(out.contains("db.internal:5432/app"), "host lost in: {out}");

        let clean = "https://docs.example.com/a:b/c";
        assert_eq!(r().scrub_str(clean), clean, "a plain url was rewritten");
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
