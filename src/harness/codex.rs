use super::{
    Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, KillSwitch, ManagedDir, Probes,
    Required, Scope, TomlEditOp, install_path,
};
use crate::config::CaptureCfg;
use crate::detect::{BinaryProbe, Platform};
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

/// The administrator-owned layer, read out of the shipped binaries: the unix
/// builds carry `/etc/codex/config.toml` and `/etc/codex/requirements.toml`
/// adjacent — the same path on macOS, which has no
/// `Library/Application Support` location — and the Windows build resolves
/// `SHGetKnownFolderPath(FOLDERID_ProgramData)` with `OpenAI`/`Codex` beneath.
///
/// `managed_config.toml` sits beside these as the legacy name (the binary says
/// "Overridden by legacy managed_config.toml"). argus writes the current
/// files; a host still carrying the legacy one is not argus's to migrate.
const MANAGED_DIRS: &[ManagedDir] = &[
    ManagedDir {
        rel: "etc/codex",
        platform: Platform::MacOS,
    },
    ManagedDir {
        rel: "etc/codex",
        platform: Platform::Linux,
    },
    ManagedDir {
        rel: "ProgramData/OpenAI/Codex",
        platform: Platform::Windows,
    },
];

/// The endpoint baked into `config.toml` before it was configurable. Still
/// recognised on uninstall so hosts wired by an older argus clean up.
const LEGACY_ENDPOINT: &str = "http://127.0.0.1:4327";

/// Everything after the program path in the `notify` argv array. `check`
/// compares these element-wise, so a `notify` repointed at another program
/// is caught rather than passing a loose substring test.
const NOTIFY_TAIL: &[&str] = &["hook", "--source", "codex"];

/// The machine-wide layer, which is a different shape from the user one and
/// deliberately smaller.
///
/// Codex's layer precedence — the binary's own wording — is managed policy
/// (MDM), then managed config (system), then enterprise-managed config, then
/// *user* config, then project config. The system `config.toml` is therefore
/// the weakest layer, not the strongest: anything an administrator needs to be
/// unarguable goes in `requirements.toml`, which is the enforcement file.
///
/// So the three artifacts are:
///
/// 1. `hooks/hooks.json` — argus's own entries, inside the managed hooks
///    directory. This has to exist *before* the setting in (3), or the
///    machine is left running no hooks at all.
/// 2. `config.toml` — `[hooks] managed_dir` pointing at that directory.
///    Windows spells the same setting `windows_managed_dir`, and the binary
///    reports the two as conflicting, so exactly one is written per platform.
/// 3. `requirements.toml` — `allow_managed_hooks_only = true`.
///
/// What is deliberately *not* written is the user layer's `notify` and
/// `[otel]`. Both carry this install's receiver token, and the daemon, socket
/// and OTLP port are per-user (see the multi-user note in the README): a token
/// in a world-readable machine-wide file is a credential handed to every
/// account on the host, in exchange for wiring that could only ever be right
/// for one of them.
///
/// Also not written is a `feature_requirements` pin for the hooks feature.
/// The field exists, but its inner schema could not be read out of the binary,
/// and a `requirements.toml` Codex rejects as having an unknown field is a
/// config-load failure for every user on the machine — a worse outcome than
/// the gap. The gap is covered from the other side: [`Codex::kill_switches`]
/// reports `[features] hooks = false` wherever someone sets it.
fn managed_artifacts(d: &Detection, platform: Platform) -> Vec<Artifact> {
    let hooks_dir = d.config_home.join("hooks");
    let key = match platform {
        Platform::Windows => "windows_managed_dir",
        Platform::Linux | Platform::MacOS => "managed_dir",
    };
    let mut hooks = toml_edit::Table::new();
    hooks[key] = toml_edit::value(hooks_dir.to_string_lossy().into_owned());

    vec![
        Artifact::JsonHooks {
            path: hooks_dir.join("hooks.json"),
            events: EVENTS,
            shape: HookShape::CommandArray,
            source: "codex",
            pinned: Vec::new(),
        },
        Artifact::TomlEdit {
            path: d.config_home.join("config.toml"),
            edits: vec![TomlEditOp {
                key: "hooks",
                value: toml_edit::Item::Table(hooks),
                only_if_absent: true,
                ours_markers: vec![hooks_dir.to_string_lossy().into_owned()],
                must_carry: vec![Required {
                    what: format!("{key} pointing at {}", hooks_dir.display()),
                    needle: hooks_dir.to_string_lossy().into_owned(),
                    present: true,
                }],
                argv_tail: None,
            }],
        },
        Artifact::TomlEdit {
            path: d.config_home.join("requirements.toml"),
            edits: vec![TomlEditOp {
                key: "allow_managed_hooks_only",
                value: toml_edit::value(true),
                // The one edit here that overwrites. (2) is an administrator's
                // own content — a `managed_dir` already pointing somewhere is
                // *their* hooks directory, and clobbering it would break hooks
                // argus knows nothing about, so it is left alone and reported.
                // This is argus's enforcement pin, and re-running the install
                // is the documented repair for finding it flipped, exactly as
                // it is for Claude Code's pinned settings.
                only_if_absent: false,
                ours_markers: vec!["true".to_string()],
                must_carry: vec![Required {
                    what: "allow_managed_hooks_only = true".into(),
                    needle: "true".into(),
                    present: true,
                }],
                argv_tail: None,
            }],
        },
    ]
}

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

    fn managed_dirs(&self) -> &'static [ManagedDir] {
        MANAGED_DIRS
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
                pinned: Vec::new(),
            }];
        }
        if let Scope::Managed(platform) = scope {
            return managed_artifacts(d, platform);
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
                pinned: Vec::new(),
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
