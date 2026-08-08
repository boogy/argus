use super::{Artifact, ConfigDir, Detection, Harness, HookEvent, HookShape, Probes, Scope};
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event};

/// Events we subscribe to, and whether the entry carries a `"matcher": "*"`.
/// Matchers are set only for tool-name-matched events; matcher-less entries
/// run for every matcher value anyway. Deliberately not wired (see README):
/// MessageDisplay, UserPromptExpansion, FileChanged, Worktree*, Setup,
/// TeammateIdle, Elicitation*.
pub const EVENTS: &[HookEvent] = &[
    HookEvent::new("UserPromptSubmit", false),
    HookEvent::new("PreToolUse", true),
    HookEvent::new("PostToolUse", true),
    HookEvent::new("PostToolUseFailure", true),
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
];

const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env_override: None,
    rel: ".claude",
}];

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
