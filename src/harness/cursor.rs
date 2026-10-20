use super::{
    Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, KillSwitch, ManagedDir, Probes,
    Scope,
};
use crate::config::CaptureCfg;
use crate::detect::{BinaryProbe, Platform};
use crate::event::{Envelope, Event};
use serde_json::Value;

/// Cursor `hooks.json` events, from <https://cursor.com/docs/agent/hooks>.
/// Each payload has `hook_event_name`, so the command has no `--event`.
///
/// Not wired:
/// - `beforeShellExecution`, `beforeMCPExecution` and their `after` events:
///   `preToolUse` and `postToolUse` also match `Shell` and `MCP:<tool>`, so
///   the IDE would record each call two times.
/// - `beforeReadFile`: the payload has all of the file. `preToolUse` records
///   the read.
/// - `afterAgentThought`: reasoning text, and many events.
/// - `workspaceOpen`: it is not part of an agent session.
/// - The Tab events.
///
/// A command that exits 0 and writes nothing to stdout lets the action
/// continue. No entry sets `failClosed`, so a broken argus never blocks Cursor.
pub const EVENTS: &[HookEvent] = &[
    HookEvent::new("sessionStart", false),
    HookEvent::new("sessionEnd", false),
    HookEvent::new("beforeSubmitPrompt", false),
    HookEvent::new("preToolUse", false),
    HookEvent::new("postToolUse", false),
    HookEvent::new("postToolUseFailure", false),
    HookEvent::new("subagentStart", false),
    HookEvent::new("subagentStop", false),
    HookEvent::new("preCompact", false),
    HookEvent::new("stop", false),
    HookEvent::new("afterAgentResponse", false),
    HookEvent::new("afterFileEdit", false),
];

const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env: None,
    rel: ".cursor",
    platform: None,
}];

/// `cursor` is the launcher of Cursor.app (and of the Windows and Linux
/// installs). `cursor-agent` is the old name of the CLI. `agent` is its
/// current name, but other programs use that word too.
const BINARIES: &[BinaryProbe] = &[
    BinaryProbe::new("cursor"),
    BinaryProbe::new("cursor-agent"),
    BinaryProbe::generic("agent"),
];

/// The enterprise layer. Cursor runs the hooks of all layers, so this does
/// not stop a user's own hooks.
const MANAGED_DIRS: &[ManagedDir] = &[
    ManagedDir {
        rel: "Library/Application Support/Cursor",
        platform: Platform::MacOS,
    },
    ManagedDir {
        rel: "etc/cursor",
        platform: Platform::Linux,
    },
    ManagedDir {
        rel: "ProgramData/Cursor",
        platform: Platform::Windows,
    },
];

fn hooks_path(d: &Detection) -> std::path::PathBuf {
    d.config_home.join("hooks.json")
}

pub struct Cursor;

impl Harness for Cursor {
    fn id(&self) -> &'static str {
        "cursor"
    }

    fn display_name(&self) -> &'static str {
        "Cursor"
    }

    fn probes(&self) -> Probes {
        Probes {
            config_dirs: CONFIG_DIRS,
            binaries: BINARIES,
            npm_packages: &[],
            brew_formulae: &[],
        }
    }

    fn managed_dirs(&self) -> &'static [ManagedDir] {
        MANAGED_DIRS
    }

    /// The same file name in each scope. The user can have hooks of their own
    /// in it, so argus merges its entries and does not own the file.
    fn artifacts(&self, d: &Detection, _scope: Scope) -> Vec<Artifact> {
        vec![Artifact::JsonHooks {
            path: hooks_path(d),
            events: EVENTS,
            shape: HookShape::Flat,
            source: "cursor",
            pinned: Vec::new(),
        }]
    }

    /// States where the argus entries are correct and Cursor still runs none
    /// of them.
    fn kill_switches(&self, d: &Detection) -> Vec<KillSwitch> {
        let path = hooks_path(d);
        // Artifact verification reports a missing file.
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let doc = match serde_json::from_str::<Value>(&text) {
            Ok(v) => v,
            Err(e) => {
                return vec![KillSwitch {
                    name: "unreadable hooks file",
                    detail: format!(
                        "{} is not valid JSON ({e}) — Cursor cannot load it either, \
                         so none of the hooks it lists run",
                        path.display()
                    ),
                }];
            }
        };
        if doc.get("version").and_then(Value::as_u64) != Some(1) {
            let version = doc.get("version").unwrap_or(&Value::Null);
            return vec![KillSwitch {
                name: "unsupported hooks version",
                detail: format!(
                    "version is {version} in {} — Cursor runs the hooks only when it is 1",
                    path.display()
                ),
            }];
        }
        Vec::new()
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::cursor::parse(env, cfg)
    }
}
