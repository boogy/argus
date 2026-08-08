use super::{Artifact, CmdStyle, ConfigDir, Detection, Harness, Probes, Scope, hook_command};
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event};
use serde_json::json;
use std::borrow::Cow;

/// Copilot CLI hook events (verified against the Copilot hooks reference:
/// camelCase events, `bash`/`powershell` command entries, `timeoutSec`;
/// `permissionRequest` with empty stdout + exit 0 falls through to the normal
/// permission flow, so observe-only wiring is safe).
pub const EVENTS: &[&str] = &[
    "sessionStart",
    "sessionEnd",
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "errorOccurred",
    "agentStop",
    "subagentStart",
    "subagentStop",
    "preCompact",
    "notification",
    "permissionRequest",
];

const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env_override: Some("COPILOT_HOME"),
    rel: ".copilot",
}];

pub struct Copilot;

impl Harness for Copilot {
    fn id(&self) -> &'static str {
        "copilot"
    }

    fn display_name(&self) -> &'static str {
        "Copilot CLI hooks"
    }

    fn probes(&self) -> Probes {
        Probes {
            config_dirs: CONFIG_DIRS,
        }
    }

    /// The hooks file has our own filename, so argus owns it outright:
    /// install overwrites, uninstall deletes — same policy as the opencode
    /// plugin shim, and no marker is needed inside it.
    fn artifacts(&self, d: &Detection, _scope: Scope) -> Vec<Artifact> {
        let mut hooks = serde_json::Map::new();
        for event in EVENTS {
            // Distinct per shell: PowerShell needs the `&` call operator, and
            // each quotes the program path its own way.
            hooks.insert(
                (*event).into(),
                json!([{
                    "type": "command",
                    "bash": hook_command("copilot", Some(event), CmdStyle::Shell),
                    "powershell": hook_command("copilot", Some(event), CmdStyle::PowerShell),
                    "timeoutSec": 10,
                }]),
            );
        }
        let doc = json!({ "version": 1, "hooks": hooks });
        vec![Artifact::OwnedFile {
            path: d.config_home.join("hooks/argus.json"),
            contents: Cow::Owned(
                serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
            ),
        }]
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::copilot::parse(env, cfg)
    }
}
