use super::{Artifact, ConfigDir, Detection, Harness, Probes, Scope};
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event};
use std::borrow::Cow;

const SHIM: &str = include_str!("../../plugins/opencode/argus.ts");

/// Substrings the installed shim must still contain for events to reach us:
/// one per transport it uses. The plugin talks to the daemon directly rather
/// than invoking the binary through a shell, so there is no hook command to
/// resolve — these are what "still wired" means here.
fn markers() -> Vec<String> {
    vec![
        // Fast path: the daemon's local socket.
        "argus.sock".into(),
        // Fallback: spawn the shim binary.
        r#""hook", "--source", "opencode""#.into(),
    ]
}

const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env_override: None,
    rel: ".config/opencode",
}];

pub struct OpenCode;

impl Harness for OpenCode {
    fn id(&self) -> &'static str {
        "opencode"
    }

    fn display_name(&self) -> &'static str {
        "opencode plugin"
    }

    fn probes(&self) -> Probes {
        Probes {
            config_dirs: CONFIG_DIRS,
        }
    }

    fn artifacts(&self, d: &Detection, _scope: Scope) -> Vec<Artifact> {
        vec![Artifact::OwnedFile {
            path: d.config_home.join("plugin/argus.ts"),
            contents: Cow::Borrowed(SHIM),
            markers: markers(),
            // The plugin reaches the daemon over the socket and resolves the
            // fallback binary itself at runtime, so there is no baked-in path
            // for `check` to resolve.
            commands: Vec::new(),
        }]
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::opencode::parse(env, cfg)
    }
}
