use super::{
    Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, Probes, Scope, TomlEditOp,
    install_path,
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

    fn artifacts(&self, d: &Detection, _scope: Scope) -> Vec<Artifact> {
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
        if let Some(token) = crate::adapters::codex::existing_token() {
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
        vec![
            Artifact::TomlEdit {
                path: d.config_home.join("config.toml"),
                edits: vec![
                    TomlEditOp {
                        key: "notify",
                        value: toml_edit::value(notify),
                        only_if_absent: true,
                        ours_markers: markers.clone(),
                        must_point_at: None,
                        argv_tail: Some(NOTIFY_TAIL),
                    },
                    TomlEditOp {
                        key: "otel",
                        value: toml_edit::Item::Table(otel),
                        only_if_absent: true,
                        ours_markers: markers,
                        must_point_at: Some(endpoint),
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

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::codex::parse(env, cfg)
    }
}
