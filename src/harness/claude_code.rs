use super::{
    Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, KillSwitch, ManagedDir, Probes,
    Scope,
};
use crate::config::CaptureCfg;
use crate::detect::{BinaryProbe, Platform};
use crate::event::{Envelope, Event};

/// Events we subscribe to, and whether the entry carries a `"matcher": "*"`.
/// Matchers are set only for tool-name-matched events; matcher-less entries
/// run for every matcher value anyway. Deliberately not wired (see README):
/// MessageDisplay, FileChanged, Worktree*, Setup, TeammateIdle, Elicitation*.
pub const EVENTS: &[HookEvent] = &[
    HookEvent::new("UserPromptSubmit", false),
    HookEvent::new("UserPromptExpansion", false),
    HookEvent::new("PreToolUse", true),
    HookEvent::new("PostToolUse", true),
    HookEvent::new("PostToolUseFailure", true),
    // A batch spans several tools, so no single tool name can match it.
    HookEvent::new("PostToolBatch", false),
    HookEvent::new("PermissionRequest", true),
    HookEvent::new("PermissionDenied", true),
    HookEvent::new("Notification", false),
    HookEvent::new("SessionStart", false),
    HookEvent::new("SessionEnd", false),
    HookEvent::new("Stop", false),
    HookEvent::new("SubagentStart", false),
    HookEvent::new("SubagentStop", false),
    HookEvent::new("PreCompact", false),
    HookEvent::new("PostCompact", false),
    HookEvent::new("StopFailure", false),
    HookEvent::new("ConfigChange", false),
    HookEvent::new("CwdChanged", false),
    HookEvent::new("InstructionsLoaded", false),
    HookEvent::new("TaskCreated", false),
    HookEvent::new("TaskCompleted", false),
    HookEvent::new("DirectoryAdded", false),
];

const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env: None,
    rel: ".claude",
    platform: None,
}];

/// The administrator-owned layer, read straight out of the shipped binary,
/// where all three sit adjacent in one table. Claude Code also reads
/// `managed-settings.d/*.json` beside each of these, and on WSL inherits the
/// Windows location through `/mnt/c/Program Files/ClaudeCode`; argus writes
/// the file itself, which is the location that is honoured everywhere.
///
/// Windows additionally supports `HKLM\SOFTWARE\Policies\ClaudeCode` and macOS
/// the MDM domain `com.anthropic.claudecode`. Neither is written here: an MDM
/// that can set a policy key does not need argus to do it, and a registry
/// value argus wrote would be invisible to the file-based `check`.
const MANAGED_DIRS: &[ManagedDir] = &[
    ManagedDir {
        rel: "Library/Application Support/ClaudeCode",
        platform: Platform::MacOS,
    },
    ManagedDir {
        rel: "etc/claude-code",
        platform: Platform::Linux,
    },
    ManagedDir {
        rel: "Program Files/ClaudeCode",
        platform: Platform::Windows,
    },
];

/// `claude` is distinctive enough to stand on its own as evidence.
const BINARIES: &[BinaryProbe] = &[BinaryProbe::new("claude")];

/// The npm package, which is how the CLI ships; the binary on `PATH` is a
/// shim into `node_modules/@anthropic-ai/claude-code/`.
const NPM: &[&str] = &["@anthropic-ai/claude-code"];

/// The two settings that decide whether the hooks in this file run at all.
/// Settings precedence is `user -> project -> local -> flag -> policy`, policy
/// last and highest, so a value pinned here cannot be weakened by anything a
/// user writes — which is the entire reason the machine-wide layer exists.
///
/// * `disableAllHooks` is the switch that would otherwise turn every hook off
///   from a file the user owns. Pinning it `false` is what actually protects
///   capture, and it is the Claude Code analogue of Codex's pinned feature.
/// * `allowManagedHooksOnly` restricts execution to hooks from *this* file.
///   argus's entries are in it, so its capture is unaffected either way — what
///   it changes is that the user's own hooks stop running. That is a real cost
///   and a deliberate one: it is the setting an administrator deploying a
///   machine-wide layer is asking for, and `check --managed` reports it
///   flipped rather than letting the posture drift back.
///
/// Both descriptions are the shipped binary's own: "When true (and set in
/// managed settings), only hooks from managed settings run. User, project, and
/// local hooks are ignored."
fn pinned_settings() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("disableAllHooks", serde_json::Value::Bool(false)),
        ("allowManagedHooksOnly", serde_json::Value::Bool(true)),
    ]
}

pub struct ClaudeCode;

impl Harness for ClaudeCode {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn display_name(&self) -> &'static str {
        "Claude Code"
    }

    fn probes(&self) -> Probes {
        Probes {
            config_dirs: CONFIG_DIRS,
            binaries: BINARIES,
            npm_packages: NPM,
            brew_formulae: &[],
        }
    }

    fn managed_dirs(&self) -> &'static [ManagedDir] {
        MANAGED_DIRS
    }

    fn artifacts(&self, d: &Detection, scope: Scope) -> Vec<Artifact> {
        match scope {
            // Nothing to put in a repository. Claude Code does have a project
            // layer (`<repo>/.claude/settings.json`) and it works the same way;
            // it is simply not wired yet.
            Scope::Project => Vec::new(),
            Scope::User => vec![Artifact::JsonHooks {
                path: d.config_home.join("settings.json"),
                events: EVENTS,
                shape: HookShape::CommandArray,
                source: "claude-code",
                pinned: Vec::new(),
            }],
            // `d.config_home` is the machine-wide directory here, never a home
            // directory — see `harness::managed_detection`, which is the only
            // caller that passes this scope.
            Scope::Managed => vec![Artifact::JsonHooks {
                path: d.config_home.join("managed-settings.json"),
                events: EVENTS,
                shape: HookShape::CommandArray,
                source: "claude-code",
                pinned: pinned_settings(),
            }],
        }
    }

    /// Settings that leave every hook entry intact and still stop argus's from
    /// running — the case where `check` would otherwise report "wired" about a
    /// host capturing nothing, which is worse than reporting nothing at all.
    ///
    /// Read out of the shipped `cli.js`, whose hook resolution is, in full:
    ///
    /// ```text
    /// policy.disableAllHooks             -> {}                 // nothing runs
    /// policy.allowManagedHooksOnly       -> policy.hooks       // only managed
    /// policy.strictPluginOnlyCustomization("hooks")
    ///                                    -> policy.hooks       // only managed
    /// merged.disableAllHooks             -> policy.hooks       // only managed
    /// otherwise                          -> merged.hooks
    /// ```
    ///
    /// So three of the four restrict execution to the managed layer, and only
    /// the first stops that layer too. Where argus is *in* the managed layer
    /// its capture is untouched, and saying otherwise would be a false alarm
    /// on every machine `install --managed` has been run on — hence the
    /// `managed_wired` test rather than an unconditional report.
    fn kill_switches(&self, d: &Detection) -> Vec<KillSwitch> {
        let mut out = Vec::new();
        let read = |p: &std::path::Path| -> Option<serde_json::Value> {
            serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()
        };

        // The user layer. `disableAllHooks` here does not disable the managed
        // layer, but argus's own entry lives in the user file, so for a
        // user-scope install it is fatal all the same.
        if let Some(doc) = read(&d.config_home.join("settings.json"))
            && doc.get("disableAllHooks") == Some(&serde_json::Value::Bool(true))
        {
            out.push(KillSwitch {
                name: "hooks disabled",
                detail: format!(
                    "disableAllHooks = true in {} — no hook outside the machine-wide layer runs",
                    d.config_home.join("settings.json").display()
                ),
            });
        }

        // The managed layer, which outranks everything the user can write.
        // `managed-settings.d/*.json` is read beside the file and carries the
        // same keys, so a switch hidden in a drop-in counts too.
        let platform = crate::detect::Platform::host();
        let root = super::system_root(platform);
        let Some(dir) = MANAGED_DIRS
            .iter()
            .find(|m| m.platform == platform)
            .map(|m| root.path.join(m.rel))
        else {
            return out;
        };
        let mut files = vec![dir.join("managed-settings.json")];
        if let Ok(entries) = std::fs::read_dir(dir.join("managed-settings.d")) {
            files.extend(
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json")),
            );
        }
        for path in files {
            let Some(doc) = read(&path) else { continue };
            let yes = |k: &str| doc.get(k) == Some(&serde_json::Value::Bool(true));
            // Whether *our* hooks survive the restriction. `hooks` here is the
            // managed file's own, which is what the three restricting branches
            // fall back to.
            let managed_wired = doc
                .get("hooks")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|h| {
                    h.values()
                        .filter_map(serde_json::Value::as_array)
                        .flatten()
                        .any(|e| super::is_ours(e, "claude-code"))
                });
            if yes("disableAllHooks") {
                out.push(KillSwitch {
                    name: "hooks disabled",
                    detail: format!(
                        "disableAllHooks = true in {} — no hook runs at all, managed or not",
                        path.display()
                    ),
                });
            }
            if managed_wired {
                continue;
            }
            // `strictPluginOnlyCustomization` is either `true` or a list of
            // the customizations it covers; only the list containing "hooks"
            // reaches ours.
            let strict = doc.get("strictPluginOnlyCustomization");
            let strict_hooks = strict == Some(&serde_json::Value::Bool(true))
                || strict
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("hooks")));
            for (on, key) in [
                (yes("allowManagedHooksOnly"), "allowManagedHooksOnly = true"),
                (strict_hooks, "strictPluginOnlyCustomization covers hooks"),
            ] {
                if on {
                    out.push(KillSwitch {
                        name: "user hooks ignored",
                        detail: format!(
                            "{key} in {} — only hooks in the machine-wide layer run,                              and argus is not one of them",
                            path.display()
                        ),
                    });
                }
            }
        }
        out
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::claude_code::parse(env, cfg)
    }
}
