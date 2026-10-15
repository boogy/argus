//! The AI-provider account of the agent.
//!
//! [`crate::cloudid`] records the cloud identity of the agent. This module
//! records the account at the model provider. For Claude Code, this is the
//! account and the organization. For Copilot, this is the GitHub login. Use
//! this data to find an agent that uses a personal account in a company
//! repository. The hook payloads do not contain this data.
//!
//! # Data that argus reads
//!
//! * **Claude Code**: the `oauthAccount` object in `.claude.json`. This file
//!   contains settings and project data. The OAuth tokens are in the OS
//!   keychain, not in this file. argus keeps four fields only.
//! * **Copilot CLI**: `last_logged_in_user` in `config.json`. Copilot keeps
//!   its token in the keychain. If there is no keychain, Copilot writes the
//!   token to `copilotTokens` in the same file. argus reads the file, but it
//!   does not keep the token.
//! * **Codex**: no file. The Codex OTLP stream sends the account on each
//!   event. The Codex adapter copies it.
//!
//! argus does not read opencode and pi. Each tool keeps its identity in the
//! same file as its tokens. That identity is an OpenAI account ID at most.
//!
//! # Location of the read
//!
//! The daemon reads the files in [`crate::enrich`], one time at each session
//! start. The shim does not read them: `.claude.json` can be large, and the
//! shim has a 250 ms limit. The daemon cannot see the environment of the
//! agent. Thus the shim sends a small set of variables ([`env_hints`]):
//!
//! * The two config-directory variables, with their values.
//! * The provider switches, with their values.
//! * The credential variables, as `"set"` only. The shim does not send their
//!   values.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The shim sends these values. They are directories and switches, not
/// secrets.
const BY_VALUE: &[&str] = &[
    "CLAUDE_CONFIG_DIR",
    "COPILOT_HOME",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
];

/// Credentials. The shim sends `"set"` only. It does not send the value.
const PRESENCE: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
];

/// The maximum file size. argus does not parse a larger file.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The account of the agent. All fields are optional. If a tool does not
/// supply a field, the field is empty. argus does not guess a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    /// The GitHub login name for Copilot. It is not an email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    /// The GitHub host of the login: `github.com` or an Enterprise host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The authentication method. For Claude Code, the values are `oauth`,
    /// `api_key`, `bedrock`, `vertex` and `foundry`. For Codex, argus copies
    /// the Codex value without change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    /// The file that [`resolve`] must read. `harness::parse` sets it.
    /// `enrich` removes it. argus does not serialize it.
    #[serde(skip)]
    pub pending: Option<Pending>,
}

impl AiIdentity {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    Claude(PathBuf),
    Copilot(PathBuf),
}

/// The shim calls this function. The shim has the environment of the agent.
pub fn env_hints() -> BTreeMap<String, String> {
    hints_from(|k| std::env::var(k).ok())
}

fn hints_from(get: impl Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    let mut hints = BTreeMap::new();
    for &k in BY_VALUE {
        if let Some(v) = get(k).filter(|v| !v.is_empty()) {
            hints.insert(k.to_string(), v);
        }
    }
    for &k in PRESENCE {
        if get(k).is_some_and(|v| !v.is_empty()) {
            hints.insert(k.to_string(), "set".to_string());
        }
    }
    hints
}

/// Returns the identity data that is known before argus reads a file.
/// Returns `None` if the event does not get an identity. `home` is the home
/// directory of the daemon. argus uses it if the agent sets no config
/// directory.
pub fn at_session_start(
    source: &str,
    action: &str,
    hints: &BTreeMap<String, String>,
    home: &Path,
) -> Option<AiIdentity> {
    let dir = |var: &str, default: PathBuf| hints.get(var).map(PathBuf::from).unwrap_or(default);
    match (source, action) {
        ("claude-code", "SessionStart") => {
            Some(claude(hints, dir("CLAUDE_CONFIG_DIR", home.into())))
        }
        ("copilot", "sessionStart") => Some(AiIdentity {
            pending: Some(Pending::Copilot(
                dir("COPILOT_HOME", home.join(".copilot")).join("config.json"),
            )),
            ..Default::default()
        }),
        _ => None,
    }
}

/// This function uses the precedence of Claude Code. A provider switch has
/// priority over an API key. An API key has priority over the login.
fn claude(hints: &BTreeMap<String, String>, config_dir: PathBuf) -> AiIdentity {
    let on = |k: &str| {
        hints
            .get(k)
            .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true"))
    };
    let set = |k: &str| hints.contains_key(k);
    let provider = [
        ("CLAUDE_CODE_USE_BEDROCK", "bedrock"),
        ("CLAUDE_CODE_USE_VERTEX", "vertex"),
        ("CLAUDE_CODE_USE_FOUNDRY", "foundry"),
    ]
    .into_iter()
    .find(|(k, _)| on(k))
    .map(|(_, mode)| mode);
    if let Some(mode) =
        provider.or((set("ANTHROPIC_API_KEY") || set("ANTHROPIC_AUTH_TOKEN")).then_some("api_key"))
    {
        // The agent does not use the login on disk. Thus argus does not
        // record it.
        return AiIdentity {
            auth_mode: Some(mode.into()),
            ..Default::default()
        };
    }
    AiIdentity {
        // A `claude setup-token` token is a login. The machine can have no
        // `oauthAccount` for this token.
        auth_mode: set("CLAUDE_CODE_OAUTH_TOKEN").then(|| "oauth".into()),
        pending: Some(Pending::Claude(config_dir.join(".claude.json"))),
        ..Default::default()
    }
}

/// Reads the file that the session start set. If the file is missing or not
/// correct, the identity stays empty. This is not an error.
pub fn resolve(id: &mut AiIdentity) {
    let Some(pending) = id.pending.take() else {
        return;
    };
    let (Pending::Claude(path) | Pending::Copilot(path)) = &pending;
    let Some(doc) = read_json(path) else {
        return;
    };
    let s = |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    match pending {
        Pending::Claude(_) => {
            let Some(a) = doc.get("oauthAccount") else {
                return;
            };
            id.email = s(a, "emailAddress");
            id.account_id = s(a, "accountUuid");
            id.org_id = s(a, "organizationUuid");
            id.org_name = s(a, "organizationName");
            if id.email.is_some() || id.account_id.is_some() {
                id.auth_mode = Some("oauth".into());
            }
        }
        Pending::Copilot(_) => {
            // Different Copilot CLI releases use different key names.
            let Some(u) = doc
                .get("last_logged_in_user")
                .or_else(|| doc.get("lastLoggedInUser"))
            else {
                return;
            };
            id.login = s(u, "login");
            id.host = s(u, "host");
        }
    }
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    if std::fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        let m: BTreeMap<_, _> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        hints_from(|k| m.get(k).cloned())
    }

    #[test]
    fn the_shim_sends_a_credential_as_set_and_not_its_value() {
        let h = hints(&[
            ("ANTHROPIC_API_KEY", "sk-ant-secret"),
            ("CLAUDE_CONFIG_DIR", "/c"),
            ("HOME", "/h"),
        ]);
        assert_eq!(h.get("ANTHROPIC_API_KEY").map(String::as_str), Some("set"));
        assert_eq!(h.get("CLAUDE_CONFIG_DIR").map(String::as_str), Some("/c"));
        assert!(
            !h.contains_key("HOME"),
            "the shim sent a variable that is not on the list"
        );
    }

    #[test]
    fn argus_reads_the_claude_account_from_the_config_dir_of_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".claude.json"),
            r#"{"projects":{},"oauthAccount":{"emailAddress":"john.doe@example.com",
                "accountUuid":"acc","organizationUuid":"org","organizationName":"Example Corp",
                "fullName":"John Doe"}}"#,
        )
        .unwrap();
        let h = hints(&[("CLAUDE_CONFIG_DIR", dir.path().to_str().unwrap())]);
        let mut id =
            at_session_start("claude-code", "SessionStart", &h, Path::new("/nowhere")).unwrap();
        resolve(&mut id);
        assert_eq!(
            id,
            AiIdentity {
                email: Some("john.doe@example.com".into()),
                account_id: Some("acc".into()),
                org_id: Some("org".into()),
                org_name: Some("Example Corp".into()),
                auth_mode: Some("oauth".into()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn a_provider_switch_or_an_api_key_has_priority_over_the_login_on_disk() {
        let home = Path::new("/nowhere");
        for (pairs, mode) in [
            (
                &[("CLAUDE_CODE_USE_BEDROCK", "1"), ("ANTHROPIC_API_KEY", "k")][..],
                "bedrock",
            ),
            (&[("CLAUDE_CODE_USE_VERTEX", "true")][..], "vertex"),
            (&[("ANTHROPIC_AUTH_TOKEN", "t")][..], "api_key"),
        ] {
            let id = at_session_start("claude-code", "SessionStart", &hints(pairs), home).unwrap();
            assert_eq!(id.auth_mode.as_deref(), Some(mode));
            assert!(
                id.pending.is_none(),
                "argus must not read the file if the agent does not use the login"
            );
        }
    }

    #[test]
    fn argus_keeps_the_copilot_login_and_not_the_fallback_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"last_logged_in_user":{"host":"https://github.com","login":"johndoe"},
                "copilotTokens":{"https://github.com:johndoe":"gho_secret"}}"#,
        )
        .unwrap();
        let h = hints(&[("COPILOT_HOME", dir.path().to_str().unwrap())]);
        let mut id =
            at_session_start("copilot", "sessionStart", &h, Path::new("/nowhere")).unwrap();
        resolve(&mut id);
        assert_eq!(id.login.as_deref(), Some("johndoe"));
        assert_eq!(id.host.as_deref(), Some("https://github.com"));
        assert!(!format!("{id:?}").contains("gho_secret"));
    }

    #[test]
    fn only_a_session_start_gets_an_identity_and_a_missing_file_is_not_an_error() {
        let h = BTreeMap::new();
        let home = Path::new("/nowhere");
        assert!(at_session_start("claude-code", "Stop", &h, home).is_none());
        assert!(at_session_start("codex", "SessionStart", &h, home).is_none());
        let mut id = at_session_start("claude-code", "SessionStart", &h, home).unwrap();
        resolve(&mut id);
        assert!(id.is_empty());
    }
}
