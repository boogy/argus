use super::{Artifact, ConfigDir, Detection, Harness, Probes, Scope};
use crate::config::CaptureCfg;
use crate::detect::{BinaryProbe, Platform};
use crate::event::{Envelope, Event};
use std::borrow::Cow;

/// The socket/spawn transport, shared with every other TypeScript plugin host.
/// Kept in one file because the pieces that must agree with the Rust side —
/// the FNV discriminator, the socket path, the envelope frame — are pieces a
/// second copy would drift away from silently: the plugin would still work, it
/// would just stop finding the daemon and spawn a process per event forever.
const TRANSPORT: &str = include_str!("../../plugins/shared/transport.ts");
/// opencode's own half: its event vocabulary and nothing else.
const ADAPTER: &str = include_str!("../../plugins/opencode/argus.ts");

/// The bytes `install` writes. A plugin host loads exactly one file, so the
/// two halves are joined here rather than shipped as two files with a relative
/// import between them — an import that resolves on this machine and not
/// necessarily in someone else's editor.
pub fn shim_source() -> String {
    format!("{TRANSPORT}\n{ADAPTER}")
}

/// Substrings the installed shim must still contain for events to reach us:
/// one per transport it uses, plus the line that ties the file to this
/// harness. The plugin talks to the daemon directly rather than invoking the
/// binary through a shell, so there is no hook command to resolve — these are
/// what "still wired" means here.
fn markers() -> Vec<String> {
    vec![
        // Fast path: the daemon's local socket.
        "argus.sock".into(),
        // Fallback: spawn the shim binary.
        r#""hook", "--source", source"#.into(),
        // Both halves are present, and the adapter half is opencode's. A file
        // holding only the transport parses, installs, and forwards nothing.
        r#"send("opencode""#.into(),
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

    fn artifacts(&self, d: &Detection, scope: Scope) -> Vec<Artifact> {
        // Nothing to put in a repository. The opencode plugin is a file the runtime loads from the user's
        // config directory, not something a repository contributes.
        if scope == Scope::Project {
            return Vec::new();
        }
        vec![Artifact::OwnedFile {
            path: d.config_home.join("plugin/argus.ts"),
            contents: Cow::Owned(shim_source()),
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
