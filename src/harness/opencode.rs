use super::{Artifact, ConfigDir, Detection, Harness, Probes, Scope};
use crate::config::CaptureCfg;
use crate::detect::{BinaryProbe, Platform};
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

/// XDG on Unix, `%APPDATA%` on Windows. Declaration order is install order:
/// the first entry that matches the platform is where a first-time install
/// writes, so the env-rooted location has to come first.
const CONFIG_DIRS: &[ConfigDir] = &[
    ConfigDir {
        env: Some(("XDG_CONFIG_HOME", "opencode")),
        rel: ".config/opencode",
        platform: None,
    },
    ConfigDir {
        env: Some(("APPDATA", "opencode")),
        rel: "AppData/Roaming/opencode",
        platform: Some(Platform::Windows),
    },
];

const BINARIES: &[BinaryProbe] = &[BinaryProbe::new("opencode")];
const NPM: &[&str] = &["opencode-ai"];
const BREW: &[&str] = &["opencode"];

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
            binaries: BINARIES,
            npm_packages: NPM,
            brew_formulae: BREW,
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
