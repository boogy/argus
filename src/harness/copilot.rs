use super::{
    Artifact, CmdStyle, ConfigDir, Detection, Harness, KillSwitch, Probes, Scope, hook_command,
};
use crate::config::CaptureCfg;
use crate::detect::BinaryProbe;
use crate::event::{Envelope, Event};
use serde_json::{Value, json};
use std::borrow::Cow;

/// Copilot CLI hook events (verified against the Copilot hooks reference:
/// camelCase events, `bash`/`powershell` command entries, `timeoutSec`;
/// `permissionRequest` with empty stdout + exit 0 falls through to the normal
/// permission flow, so observe-only wiring is safe).
pub const EVENTS: &[&str] = &[
    "sessionStart",
    "sessionEnd",
    "userPromptSubmitted",
    // What was actually sent, after every hook and policy in the chain had a
    // turn at it. Without this the record shows only what the user typed, and
    // an instruction spliced in on their behalf leaves no trace anywhere.
    "userPromptTransformed",
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
    env: Some(("COPILOT_HOME", "")),
    rel: ".copilot",
    platform: None,
}];

const BINARIES: &[BinaryProbe] = &[BinaryProbe::new("copilot")];
const NPM: &[&str] = &["@github/copilot"];

/// `s` as it appears *inside* a JSON string literal — the body of
/// `serde_json`'s own output, minus the surrounding quotes. Needed because the
/// artifact's markers are matched against the raw file text, where a Windows
/// path's backslashes are doubled.
fn json_escaped(s: &str) -> String {
    let q = serde_json::to_string(s).unwrap_or_default();
    q.get(1..q.len().saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

/// The one file argus writes for Copilot. Named once so the artifact and the
/// kill-switch read can never drift onto different paths — a kill switch
/// looked for in a file nobody writes reports healthy forever.
fn hooks_path(d: &Detection) -> std::path::PathBuf {
    d.config_home.join("hooks/argus.json")
}

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
            binaries: BINARIES,
            npm_packages: NPM,
            brew_formulae: &[],
        }
    }

    /// The hooks file has our own filename, so argus owns it outright:
    /// install overwrites, uninstall deletes — same policy as the opencode
    /// plugin shim, and no marker is needed inside it.
    fn artifacts(&self, d: &Detection, scope: Scope) -> Vec<Artifact> {
        // Nothing to put in a repository. Copilot's hook file is a machine-level path with no repository
        // equivalent to write into.
        if scope == Scope::Project {
            return Vec::new();
        }
        let mut hooks = serde_json::Map::new();
        // One marker per event, each the exact command that must still be on
        // disk. Checking the whole set is what makes "one event quietly
        // deleted" and "the binary moved" both visible; checking that the file
        // merely exists makes neither.
        let mut markers = Vec::with_capacity(EVENTS.len());
        let mut commands = Vec::new();
        for event in EVENTS {
            // Distinct per shell: PowerShell needs the `&` call operator, and
            // each quotes the program path its own way.
            let bash = hook_command("copilot", Some(event), CmdStyle::Shell);
            hooks.insert(
                (*event).into(),
                json!([{
                    "type": "command",
                    "bash": bash,
                    "powershell": hook_command("copilot", Some(event), CmdStyle::PowerShell),
                    "timeoutSec": 10,
                }]),
            );
            // The file is JSON, so the command is stored escaped; compare
            // against the same escaping rather than the raw string.
            markers.push(json_escaped(&bash));
            // Every event shares one program, so resolving it once is enough.
            if commands.is_empty() {
                commands.push(bash);
            }
        }
        let doc = json!({ "version": 1, "hooks": hooks });
        vec![Artifact::OwnedFile {
            path: hooks_path(d),
            contents: Cow::Owned(
                serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
            ),
            markers,
            commands,
        }]
    }

    /// States that leave every hook entry in place and still stop it running.
    /// Artifact verification reads this file for markers and a resolvable
    /// program, and both survive either of these — so without this read,
    /// `check` says "present" about a tool capturing nothing.
    ///
    /// Only argus's own file is consulted, and that is the documented scope:
    /// "Inside a single `.github/hooks/*.json` file — only the hooks declared
    /// in that file are skipped." A `disableAllHooks` in some other hooks file
    /// disables that file's hooks, not ours, and reporting it would be a false
    /// alarm. The flag's session-wide form lives at the top level of a
    /// *repository* `settings.json`, where it skips "every hook from every
    /// source" for sessions in that repository — out of reach of a
    /// machine-level check, and noted as such in the README.
    ///
    /// Doc-derived from <https://docs.github.com/en/copilot/reference/hooks-configuration>;
    /// Copilot CLI is not installed on the machine this was written on.
    fn kill_switches(&self, d: &Detection) -> Vec<KillSwitch> {
        let path = hooks_path(d);
        // A file that is not there is already reported as missing by artifact
        // verification. Saying it twice is noise, not a second finding.
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let doc = match serde_json::from_str::<Value>(&text) {
            Ok(v) => v,
            Err(e) => {
                // Copilot parses this file too. Marker text can survive
                // trailing garbage that makes the document unloadable, so the
                // hooks read as present and none of them run.
                return vec![KillSwitch {
                    name: "unreadable hooks file",
                    detail: format!(
                        "{} is not valid JSON ({e}) — Copilot cannot load it either, \
                         so none of the hooks it lists run",
                        path.display()
                    ),
                }];
            }
        };
        if doc.get("disableAllHooks").and_then(Value::as_bool) == Some(true) {
            return vec![KillSwitch {
                name: "hooks disabled",
                detail: format!(
                    "disableAllHooks = true in {} — every hook in the file is skipped \
                     without being deleted; re-run `argus install` to rewrite it",
                    path.display()
                ),
            }];
        }
        Vec::new()
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::copilot::parse(env, cfg)
    }
}
