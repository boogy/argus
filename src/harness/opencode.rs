use super::{Artifact, ConfigDir, Detection, Harness, Probes, Scope};
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event};
use std::borrow::Cow;

const SHIM: &str = include_str!("../../plugins/opencode/argus.ts");

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
        }]
    }

    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event> {
        crate::adapters::opencode::parse(env, cfg)
    }
}
