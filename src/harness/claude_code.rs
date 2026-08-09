use super::{Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, Probes, Scope};
use crate::config::CaptureCfg;
use crate::detect::BinaryProbe;
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

/// `claude` is distinctive enough to stand on its own as evidence.
const BINARIES: &[BinaryProbe] = &[BinaryProbe::new("claude")];

/// The npm package, which is how the CLI ships; the binary on `PATH` is a
/// shim into `node_modules/@anthropic-ai/claude-code/`.
const NPM: &[&str] = &["@anthropic-ai/claude-code"];

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

    fn artifacts(&self, d: &Detection, _scope: Scope) -> Vec<Artifact> {
        vec![Artifact::JsonHooks {
            path: d.config_home.join("settings.json"),
            events: EVENTS,
            shape: HookShape::CommandArray,
            source: "claude-code",
        }]
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::claude_code::parse(env, cfg)
    }
}
