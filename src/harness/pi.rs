use super::{Artifact, ConfigDir, Detection, Harness, Probes, Scope};
use crate::config::CaptureCfg;
use crate::detect::BinaryProbe;
use crate::event::{Envelope, Event};
use std::borrow::Cow;

/// The socket/spawn transport, shared with every other TypeScript plugin host.
const TRANSPORT: &str = include_str!("../../plugins/shared/transport.ts");
/// pi's own half: its event vocabulary and nothing else.
const ADAPTER: &str = include_str!("../../plugins/pi/argus.ts");

/// The bytes `install` writes. pi loads an extension as one module, so the two
/// halves are joined here rather than shipped as two files with a relative
/// import between them — an import that resolves on this machine and not
/// necessarily in someone else's `~/.pi`.
pub fn shim_source() -> String {
    format!("{TRANSPORT}\n{ADAPTER}")
}

/// Substrings the installed extension must still contain for events to reach
/// us: one per transport it uses, plus the line that ties the file to this
/// harness. pi's extensions talk to the daemon directly rather than invoking
/// the binary through a shell, so there is no hook command to resolve — these
/// are what "still wired" means here.
fn markers() -> Vec<String> {
    vec![
        // Fast path: the daemon's local socket.
        "argus.sock".into(),
        // Fallback: spawn the shim binary.
        r#""hook", "--source", source"#.into(),
        // Both halves are present, and the adapter half is pi's. A file
        // holding only the transport parses, installs, and forwards nothing.
        r#"send("pi""#.into(),
    ]
}

/// `~/.pi/agent`, on every platform. pi derives it as
/// `join(homedir(), CONFIG_DIR_NAME, "agent")` with no environment override and
/// no per-platform branch, so there is nothing else to probe.
const CONFIG_DIRS: &[ConfigDir] = &[ConfigDir {
    env: None,
    rel: ".pi/agent",
    platform: None,
}];

/// `pi` is two letters and a word people name their own scripts. On its own it
/// is not evidence that pi.dev is installed — a `~/.pi`, or a realpath landing
/// in the npm package or the brew cellar, is what makes it one.
const BINARIES: &[BinaryProbe] = &[BinaryProbe::generic("pi")];

/// Both scopes the CLI has shipped under. The package moved from its author's
/// scope to the project's, and an install that predates the move is still a pi
/// install — dropping the old name would make those machines undetectable by
/// provenance, which for a generic binary name is the only corroboration there
/// is.
const NPM: &[&str] = &[
    "@earendil-works/pi-coding-agent",
    "@mariozechner/pi-coding-agent",
];
const BREW: &[&str] = &["pi-coding-agent"];

pub struct Pi;

impl Harness for Pi {
    fn id(&self) -> &'static str {
        "pi"
    }

    fn display_name(&self) -> &'static str {
        "pi extension"
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
        // pi does discover `<repo>/.pi/extensions/*.ts`, so a project install
        // is technically possible here — and is deliberately not done. An
        // extension loads in pi's own process with no sandbox around it; one
        // committed to a repository is one that starts running against every
        // person who clones it and opens a session, without their having
        // installed anything. Monitoring is something a machine's owner turns
        // on for themselves.
        if scope == Scope::Project {
            return Vec::new();
        }
        vec![Artifact::OwnedFile {
            // `config_home` is `~/.pi/agent`; global extensions are the
            // `extensions/` directory under it. Note that pi's *project*
            // location is `.pi/extensions` — one level shallower — which is
            // another reason not to treat the two as the same install with a
            // different root.
            path: d.config_home.join("extensions").join("argus.ts"),
            contents: Cow::Owned(shim_source()),
            markers: markers(),
            // The extension reaches the daemon over the socket and resolves
            // the fallback binary itself at runtime, so there is no baked-in
            // path for `check` to resolve.
            commands: Vec::new(),
            // Code the runtime loads into its own process: anything on disk
            // that this binary did not write is a finding.
            exact: true,
        }]
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::pi::parse(env, cfg)
    }
}
