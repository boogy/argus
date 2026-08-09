use super::{
    Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, KillSwitch, Probes, Required,
    Scope, TomlEditOp, install_path,
};
use crate::config::CaptureCfg;
use crate::detect::BinaryProbe;
use crate::event::{Envelope, Event};

/// Codex `hooks.json` events (verified against the Codex hooks docs:
/// Claude-compatible `hooks.{Event}[]` schema, JSON payload on stdin with
/// `hook_event_name`; non-managed hooks need one-time trust via `/hooks` in
/// the Codex CLI).
pub const EVENTS: &[HookEvent] = &[
    HookEvent::new("SessionStart", false),
    // Codex runs this while it is shutting down, so its timeout is time the
    // user spends watching the CLI refuse to exit. Three seconds is already
    // more than ten times what the shim needs before it falls back to the
    // spool, and an event lost at shutdown is the cheapest one to lose.
    HookEvent::with_timeout("SessionEnd", false, 3),
    HookEvent::new("UserPromptSubmit", false),
    HookEvent::new("PreToolUse", true),
    HookEvent::new("PostToolUse", true),
    HookEvent::new("PermissionRequest", true),
    HookEvent::new("SubagentStart", false),
    HookEvent::new("SubagentStop", false),
    HookEvent::new("Stop", false),
    HookEvent::new("PreCompact", false),
    HookEvent::new("PostCompact", false),
];

const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env: Some(("CODEX_HOME", "")),
    rel: ".codex",
    platform: None,
}];

/// `codex` is an ordinary English word: LaTeX tooling, document managers and
/// at least one package manager ship a binary by that name. Seeing it decides
/// nothing on its own.
const BINARIES: &[BinaryProbe] = &[BinaryProbe::generic("codex")];
const NPM: &[&str] = &["@openai/codex"];
const BREW: &[&str] = &["codex"];

/// The endpoint baked into `config.toml` before it was configurable. Still
/// recognised on uninstall so hosts wired by an older argus clean up.
const LEGACY_ENDPOINT: &str = "http://127.0.0.1:4327";

/// Everything after the program path in the `notify` argv array. `check`
/// compares these element-wise, so a `notify` repointed at another program
/// is caught rather than passing a loose substring test.
const NOTIFY_TAIL: &[&str] = &["hook", "--source", "codex"];

pub struct Codex;

impl Harness for Codex {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn display_name(&self) -> &'static str {
        "Codex"
    }

    fn probes(&self) -> Probes {
        Probes {
            config_dirs: CONFIG_DIRS,
            binaries: BINARIES,
            npm_packages: NPM,
            brew_formulae: BREW,
        }
    }

    fn artifacts(&self, d: &Detection, scope: Scope) -> Vec<Artifact> {
        // A repository gets the hooks and nothing else. `config.toml` carries
        // the `[otel]` block, and that block carries this install's receiver
        // token — committing it would publish the one secret standing between
        // the audit trail and anything else on the machine that can reach
        // loopback. Project hooks are additive in Codex (a repository can add
        // hooks, never replace the user's), so wiring only these leaves a
        // user-level install intact rather than competing with it.
        if scope == Scope::Project {
            return vec![Artifact::JsonHooks {
                path: d.config_home.join("hooks.json"),
                events: EVENTS,
                shape: HookShape::CommandArray,
                source: "codex",
            }];
        }
        // Sourced from config so Codex's OTLP target and the daemon's actual
        // listen address can't drift apart.
        let endpoint = format!("http://{}", crate::config::load().codex.otlp_listen);
        // `notify` is an argv array executed without a shell, so the program
        // path is a distinct element and must NOT be shell-quoted.
        let mut notify = toml_edit::Array::new();
        notify.push(install_path());
        for arg in NOTIFY_TAIL {
            notify.push(*arg);
        }

        let mut otel = toml_edit::Table::new();
        otel["environment"] = toml_edit::value("prod");
        let mut otlp_http = toml_edit::InlineTable::new();
        otlp_http.insert("endpoint", endpoint.clone().into());
        otlp_http.insert("protocol", "json".into());
        // Loopback authenticates nobody, so the receiver requires this and
        // Codex is the only thing told it. Read, never created: a dry run and
        // `check` come through here too. A missing token is not fatal to the
        // install — the rest of the wiring is worth having, and the receiver
        // refuses everything in that state anyway, so the gap cannot be a way
        // in, only a capture outage that `check` reports.
        let token = crate::adapters::codex::existing_token();
        if let Some(token) = &token {
            let mut headers = toml_edit::InlineTable::new();
            headers.insert("authorization", format!("Bearer {token}").into());
            otlp_http.insert("headers", toml_edit::Value::InlineTable(headers));
        }
        let mut exporter = toml_edit::InlineTable::new();
        exporter.insert("otlp-http", toml_edit::Value::InlineTable(otlp_http));
        otel["exporter"] = toml_edit::value(toml_edit::Value::InlineTable(exporter));

        // TOML holds user-authored config, so there is no structured marker to
        // stamp the way shared JSON gets `_argus`; ownership is inferred from
        // the value pointing at us.
        let markers = vec![
            "argus".to_string(),
            endpoint.clone(),
            LEGACY_ENDPOINT.to_string(),
        ];

        let mut must_carry = vec![Required {
            what: format!("the endpoint {endpoint}"),
            needle: endpoint,
            present: true,
        }];
        // With no token on disk the current one is unknowable, but a header is
        // still wrong: the next daemon start mints a replacement and refuses
        // whatever this config presents. That is the restored-profile case —
        // the Codex config came back, the `0700` data directory did not.
        must_carry.push(match &token {
            Some(t) => Required {
                what: "the receiver token from this install".into(),
                needle: format!("Bearer {t}"),
                present: true,
            },
            None => Required {
                what: "a receiver token this install does not know".into(),
                needle: "Bearer ".into(),
                present: false,
            },
        });

        vec![
            Artifact::TomlEdit {
                path: d.config_home.join("config.toml"),
                edits: vec![
                    TomlEditOp {
                        key: "notify",
                        value: toml_edit::value(notify),
                        only_if_absent: true,
                        ours_markers: markers.clone(),
                        must_carry: vec![],
                        argv_tail: Some(NOTIFY_TAIL),
                    },
                    TomlEditOp {
                        key: "otel",
                        value: toml_edit::Item::Table(otel),
                        only_if_absent: true,
                        ours_markers: markers,
                        must_carry,
                        argv_tail: None,
                    },
                ],
            },
            Artifact::JsonHooks {
                path: d.config_home.join("hooks.json"),
                events: EVENTS,
                shape: HookShape::CommandArray,
                source: "codex",
            },
        ]
    }

    /// Settings that leave every hook entry in place and still stop it from
    /// running. Without these, `check` reads a perfectly wired `hooks.json`
    /// and reports "wired" about a tool that is capturing nothing — which is
    /// worse than reporting nothing at all, because someone believes it.
    ///
    /// Verified against <https://learn.chatgpt.com/docs/hooks> (Codex is not
    /// installed on the machine this was written on).
    fn kill_switches(&self, d: &Detection) -> Vec<KillSwitch> {
        let mut out = Vec::new();
        for file in ["config.toml", "requirements.toml"] {
            let path = d.config_home.join(file);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let doc = match text.parse::<toml::Table>() {
                Ok(t) => t,
                Err(e) => {
                    // Codex cannot read its own config either, so whatever
                    // this file was meant to say — including our `notify` and
                    // `[otel]` wiring — is not in force.
                    out.push(KillSwitch {
                        name: "unreadable config",
                        detail: format!("{} is not valid TOML: {e}", path.display()),
                    });
                    continue;
                }
            };
            // `hooks` is canonical; `codex_hooks` is the deprecated alias and
            // still works, so checking only the new name would miss a host
            // that was disabled before the rename.
            for key in ["hooks", "codex_hooks"] {
                if doc
                    .get("features")
                    .and_then(|f| f.get(key))
                    .and_then(toml::Value::as_bool)
                    == Some(false)
                {
                    out.push(KillSwitch {
                        name: "hooks disabled",
                        detail: format!(
                            "[features] {key} = false in {} — no hook runs, wired or not",
                            path.display()
                        ),
                    });
                }
            }
            // argus installs a *user* hook. This setting keeps only
            // administrator-managed hooks, so ours is discovered, listed, and
            // never executed.
            if doc
                .get("allow_managed_hooks_only")
                .and_then(toml::Value::as_bool)
                == Some(true)
            {
                out.push(KillSwitch {
                    name: "user hooks ignored",
                    detail: format!(
                        "allow_managed_hooks_only = true in {} — only administrator-managed hooks run",
                        path.display()
                    ),
                });
            }
        }
        out
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::codex::parse(env, cfg)
    }
}
