//! Where a harness is installed on this machine, and how we know.
//!
//! Detection used to be a single question — "does `~/.<tool>` exist" — which
//! is wrong in both directions. A tool that is installed but has not been run
//! yet has no config directory, so argus stayed blind on exactly the machines
//! that had just onboarded; and a bare `codex` on `PATH` may be any of several
//! unrelated programs, so treating a name as proof wires (and later reports on)
//! a tool that was never there.
//!
//! So four independent signals are read instead — [`Signal::ConfigDir`],
//! [`Signal::Binary`], [`Signal::NpmGlobal`], [`Signal::Brew`] — and a
//! *generic* binary name only counts once something else corroborates it.
//!
//! Everything the algorithm reads from the outside world arrives in [`Env`],
//! **including the platform**. Nothing here branches on `cfg!`, so the Windows
//! layout is exercised by the suite on Linux and macOS too. The alternative —
//! `cfg!(windows)` inline — produces code that only Windows CI ever executes,
//! which is how the untested-path bugs got here in the first place.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::harness::{Detection, HARNESSES, Harness, Signal};

/// Host operating-system family, as far as file layout is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
}

impl Platform {
    /// Every platform argus supports — the axis the detection tests sweep.
    pub const ALL: &'static [Platform] = &[Platform::Linux, Platform::MacOS, Platform::Windows];

    pub fn host() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOS
        } else {
            Platform::Linux
        }
    }
}

/// Environment variables detection consults. Listed explicitly so [`Env`]
/// captures a fixed, inspectable set rather than carrying the whole process
/// environment into every fixture.
const PROBE_VARS: &[&str] = &[
    "COPILOT_HOME",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "APPDATA",
    "LOCALAPPDATA",
];

/// `PATHEXT` when Windows does not set it. Only the extensions a CLI is
/// plausibly shipped as; `.VBS`/`.JS` entries would match a script that
/// happens to share the tool's name.
const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

/// Search these directories for tool binaries instead of `PATH` and the
/// standard per-user prefixes.
///
/// Detection otherwise reads the real machine, which would make the install
/// tests depend on whichever agents the developer happens to have installed.
/// It is also the supported way to point a locked-down deployment at a known
/// set of prefixes.
pub const BIN_DIRS_ENV: &str = "ARGUS_BIN_DIRS";

/// Everything detection reads from outside the process.
pub struct Env {
    pub platform: Platform,
    pub home: PathBuf,
    /// Where to look for a tool's binary, in order: `PATH` first, then the
    /// per-user install prefixes. The prefixes matter because a hook fires
    /// under whatever `PATH` the agent inherited, which for a GUI-launched
    /// app is often the bare system one.
    pub bin_dirs: Vec<PathBuf>,
    /// Executable extensions, lowercase and dot-less. Empty off Windows,
    /// where the executable bit decides instead.
    pub exe_exts: Vec<String>,
    vars: BTreeMap<&'static str, String>,
}

impl Env {
    /// This machine, with `home` injected (tests and `ARGUS_HOME` both need to
    /// redirect it).
    pub fn host(home: &Path) -> Self {
        let vars: BTreeMap<&'static str, String> = PROBE_VARS
            .iter()
            .filter_map(|k| {
                std::env::var(k)
                    .ok()
                    .filter(|v| !v.is_empty())
                    .map(|v| (*k, v))
            })
            .collect();
        let platform = Platform::host();
        let bin_dirs = match std::env::var_os(BIN_DIRS_ENV) {
            Some(v) => std::env::split_paths(&v).collect(),
            None => {
                let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
                    .map(|p| std::env::split_paths(&p).collect())
                    .unwrap_or_default();
                dirs.extend(user_prefixes(platform, home, &vars));
                dirs
            }
        };
        Self::new(
            platform,
            home,
            bin_dirs,
            std::env::var("PATHEXT").ok().as_deref(),
            vars,
        )
    }

    /// A fully specified environment — the constructor fixtures use.
    pub fn new(
        platform: Platform,
        home: &Path,
        bin_dirs: Vec<PathBuf>,
        pathext: Option<&str>,
        vars: BTreeMap<&'static str, String>,
    ) -> Self {
        let mut seen = Vec::new();
        for d in bin_dirs {
            if !d.as_os_str().is_empty() && !seen.contains(&d) {
                seen.push(d);
            }
        }
        let exe_exts = if platform == Platform::Windows {
            pathext
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(DEFAULT_PATHEXT)
                .split(';')
                .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|e| !e.is_empty())
                .collect()
        } else {
            Vec::new()
        };
        Self {
            platform,
            home: home.to_path_buf(),
            bin_dirs: seen,
            exe_exts,
            vars,
        }
    }

    pub fn var(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    /// Filenames a program called `name` could be stored under.
    fn exe_names(&self, name: &str) -> Vec<String> {
        if self.platform == Platform::Windows {
            // A bare extension-less file is not executable on Windows, so the
            // `PATHEXT` variants are the only candidates.
            self.exe_exts
                .iter()
                .map(|e| format!("{name}.{e}"))
                .collect()
        } else {
            vec![name.to_string()]
        }
    }

    /// Can the shell that runs the hook actually execute this file?
    ///
    /// Windows carries executability in the extension, and [`Env::exe_names`]
    /// has already restricted the candidates to `PATHEXT` ones, so existing as
    /// a file is the whole test — deliberately *not* the host's mode bits,
    /// which a Windows layout under test on a Unix host would fail. Unix does
    /// use the executable bit, falling back to "is a file" only where the host
    /// cannot report one (a Unix layout under test on Windows).
    fn is_executable(&self, p: &Path) -> bool {
        let Ok(md) = std::fs::metadata(p) else {
            return false;
        };
        if !md.is_file() {
            return false;
        }
        if self.platform == Platform::Windows {
            return true;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            md.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

/// Per-user install prefixes that are frequently *not* on the `PATH` a hook
/// inherits.
fn user_prefixes(
    platform: Platform,
    home: &Path,
    vars: &BTreeMap<&'static str, String>,
) -> Vec<PathBuf> {
    let based = |key: &str, fallback: &str| -> PathBuf {
        vars.get(key)
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(fallback))
    };
    match platform {
        Platform::Windows => vec![
            based("APPDATA", "AppData/Roaming").join("npm"),
            based("LOCALAPPDATA", "AppData/Local").join("Programs"),
            home.join("scoop/shims"),
            home.join(".bun/bin"),
            home.join(".cargo/bin"),
        ],
        _ => vec![
            home.join(".local/bin"),
            home.join("bin"),
            home.join(".npm-global/bin"),
            home.join(".bun/bin"),
            home.join(".deno/bin"),
            home.join(".cargo/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/home/linuxbrew/.linuxbrew/bin"),
        ],
    }
}

/// A binary name a harness ships.
#[derive(Debug, Clone, Copy)]
pub struct BinaryProbe {
    pub name: &'static str,
    /// A name common enough to belong to something else — `codex`, `pi`.
    /// Finding it on `PATH` is a hint, never proof: it is ignored unless
    /// another signal (a config directory, or npm/brew provenance naming the
    /// package) corroborates it. Without this rule argus wires and then
    /// permanently reports on a tool the user does not have.
    pub generic: bool,
}

impl BinaryProbe {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            generic: false,
        }
    }
    pub const fn generic(name: &'static str) -> Self {
        Self {
            name,
            generic: true,
        }
    }
}

/// Every harness detected under `home` on this machine.
pub fn detect(home: &Path) -> Vec<Detection> {
    detect_in(&Env::host(home))
}

/// Detection against an explicit environment.
pub fn detect_in(env: &Env) -> Vec<Detection> {
    HARNESSES
        .iter()
        .filter_map(|h| detect_one(*h, env))
        .collect()
}

fn detect_one(h: &dyn Harness, env: &Env) -> Option<Detection> {
    let probes = h.probes();
    let mut signals = Vec::new();

    // Candidates in declaration order: the first is where an install writes
    // when nothing exists yet, so it must survive an unsuccessful search.
    let candidates: Vec<PathBuf> = probes
        .config_dirs
        .iter()
        .filter(|cd| cd.matches(env.platform))
        .map(|cd| cd.resolve(env))
        .collect();
    let existing = candidates.iter().find(|c| c.is_dir()).cloned();
    if existing.is_some() {
        signals.push(Signal::ConfigDir);
    }
    // No config directory is even *possible* on this platform: not installable.
    let config_home = existing.or_else(|| candidates.first().cloned())?;

    let mut binary = None;
    if let Some((path, generic)) = find_binary(env, probes.binaries) {
        let real = real_path(&path);
        // Provenance is derived from the binary we just found, so it is only
        // ever reported together with `Binary`.
        let mut provenance = Vec::new();
        if probes.npm_packages.iter().any(|p| under_npm(&real, p)) {
            provenance.push(Signal::NpmGlobal);
        }
        if probes.brew_formulae.iter().any(|f| under_brew(&real, f)) {
            provenance.push(Signal::Brew);
        }
        if !generic || !signals.is_empty() || !provenance.is_empty() {
            signals.push(Signal::Binary);
            signals.extend(provenance);
            binary = Some(path);
        }
    }

    if signals.is_empty() {
        return None;
    }
    Some(Detection {
        id: h.id(),
        signals,
        config_home,
        binary,
    })
}

fn find_binary(env: &Env, probes: &[BinaryProbe]) -> Option<(PathBuf, bool)> {
    for probe in probes {
        for dir in &env.bin_dirs {
            for name in env.exe_names(probe.name) {
                let cand = dir.join(name);
                if env.is_executable(&cand) {
                    return Some((cand, probe.generic));
                }
            }
        }
    }
    None
}

/// Where a binary really lives, as a lowercase `/`-separated string.
///
/// The shim on `PATH` is almost always a symlink or shim pointing into the
/// package manager's own tree, and that tree is what identifies the installer.
/// Windows canonicalisation returns the extended-length form (`\\?\C:\…`,
/// `\\?\UNC\server\share`), which has to be stripped or every match below
/// misses.
fn real_path(p: &Path) -> String {
    let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = real.to_string_lossy().replace('\\', "/").to_lowercase();
    if let Some(rest) = s.strip_prefix("//?/unc/") {
        return format!("//{rest}");
    }
    s.strip_prefix("//?/").unwrap_or(&s).to_string()
}

/// Installed by npm (or a compatible client) as global package `pkg`.
fn under_npm(real: &str, pkg: &str) -> bool {
    real.contains(&format!("/node_modules/{}/", pkg.to_lowercase()))
}

/// Installed by Homebrew (or Linuxbrew) as formula `formula`.
fn under_brew(real: &str, formula: &str) -> bool {
    real.contains(&format!("/cellar/{}/", formula.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::ConfigDir;

    fn touch_exe(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn env_for(platform: Platform, home: &Path, bin: &Path) -> Env {
        Env::new(
            platform,
            home,
            vec![bin.to_path_buf()],
            None,
            BTreeMap::new(),
        )
    }

    /// The file name a binary is stored under for `platform`.
    fn exe(platform: Platform, name: &str) -> String {
        if platform == Platform::Windows {
            format!("{name}.exe")
        } else {
            name.to_string()
        }
    }

    fn config_dir_for(h: &dyn Harness, platform: Platform, home: &Path) -> Option<PathBuf> {
        h.probes()
            .config_dirs
            .iter()
            .find(|cd| cd.matches(platform))
            .map(|cd| cd.resolve(&Env::new(platform, home, Vec::new(), None, BTreeMap::new())))
    }

    fn detected<'a>(ds: &'a [Detection], id: &str) -> Option<&'a Detection> {
        ds.iter().find(|d| d.id == id)
    }

    /// Every harness, on every platform, found through every signal it
    /// declares — the sweep that catches a harness registered with no way to
    /// be seen on some platform.
    #[test]
    fn every_harness_is_detectable_by_every_signal_it_declares_on_every_platform() {
        for &platform in Platform::ALL {
            for h in HARNESSES {
                let probes = h.probes();
                let dir = tempfile::tempdir().unwrap();
                let home = dir.path();
                let bin = home.join("fakebin");
                std::fs::create_dir_all(&bin).unwrap();
                let ctx = format!("{} on {platform:?}", h.id());

                // Every harness must be installable somewhere on every
                // platform, or install silently skips that platform forever.
                let cfg = config_dir_for(*h, platform, home)
                    .unwrap_or_else(|| panic!("{ctx}: no config dir declared"));

                // 1. config dir alone
                std::fs::create_dir_all(&cfg).unwrap();
                let env = env_for(platform, home, &bin);
                let found = detect_in(&env);
                let d = detected(&found, h.id())
                    .unwrap_or_else(|| panic!("{ctx}: config dir missed"))
                    .signals
                    .clone();
                assert!(d.contains(&Signal::ConfigDir), "{ctx}: {d:?}");
                std::fs::remove_dir_all(&cfg).unwrap();

                // 2. binary alone — proof only for a non-generic name.
                let probe = probes
                    .binaries
                    .first()
                    .unwrap_or_else(|| panic!("{ctx}: no binary declared"));
                let exe_path = bin.join(exe(platform, probe.name));
                touch_exe(&exe_path);
                let found = detect_in(&env_for(platform, home, &bin));
                match detected(&found, h.id()) {
                    Some(d) => assert!(
                        !probe.generic && d.signals.contains(&Signal::Binary),
                        "{ctx}: {:?}",
                        d.signals
                    ),
                    None => assert!(probe.generic, "{ctx}: non-generic binary must detect"),
                }
                std::fs::remove_file(&exe_path).unwrap();

                // 3./4. npm and brew provenance, via a binary living inside
                // the package manager's tree. A generic name is corroborated
                // by provenance, so both must detect regardless.
                for (label, tree, names) in [
                    (
                        "npm",
                        home.join("node_modules"),
                        probes.npm_packages.to_vec(),
                    ),
                    ("brew", home.join("Cellar"), probes.brew_formulae.to_vec()),
                ] {
                    let Some(pkg) = names.first() else {
                        continue; // harness ships no package for this manager
                    };
                    let owned = tree.join(pkg).join("1.0.0/bin");
                    let exe_path = owned.join(exe(platform, probe.name));
                    touch_exe(&exe_path);
                    let env = env_for(platform, home, &owned);
                    let found = detect_in(&env);
                    let d =
                        detected(&found, h.id()).unwrap_or_else(|| panic!("{ctx}: {label} missed"));
                    let want = if label == "npm" {
                        Signal::NpmGlobal
                    } else {
                        Signal::Brew
                    };
                    assert!(d.signals.contains(&want), "{ctx}: {label}: {:?}", d.signals);
                    assert!(d.signals.contains(&Signal::Binary), "{ctx}: {label}");
                    std::fs::remove_dir_all(&tree).unwrap();
                }
            }
        }
    }

    /// The false-positive rule. `codex` and `pi` are ordinary words; a binary
    /// by that name is regularly something else entirely, and wiring on the
    /// strength of it means `check` reports a tool the user never had as
    /// broken, forever.
    #[test]
    fn a_bare_generic_binary_on_path_is_not_enough() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let mut any_generic = false;
        for h in HARNESSES {
            for probe in h.probes().binaries.iter().filter(|b| b.generic) {
                any_generic = true;
                touch_exe(&bin.join(probe.name));
                touch_exe(&bin.join(format!("{}.exe", probe.name)));
            }
        }
        assert!(any_generic, "no harness declares a generic binary name");
        for &platform in Platform::ALL {
            let found = detect_in(&env_for(platform, dir.path(), &bin));
            for d in &found {
                let generic = harness(d.id).probes().binaries.iter().any(|b| b.generic);
                assert!(
                    !generic,
                    "{platform:?}: generic name alone detected {}: {:?}",
                    d.id, d.signals
                );
            }
        }
    }

    /// …but the same name inside the package manager's tree *is* proof.
    #[test]
    fn a_generic_binary_is_accepted_once_provenance_corroborates_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut checked = 0;
        for h in HARNESSES {
            let probes = h.probes();
            let Some(probe) = probes.binaries.iter().find(|b| b.generic) else {
                continue;
            };
            let Some(pkg) = probes.npm_packages.first() else {
                continue;
            };
            checked += 1;
            let home = dir.path().join(h.id());
            let bin = home.join("node_modules").join(pkg).join("bin");
            touch_exe(&bin.join(probe.name));
            let found = detect_in(&env_for(Platform::Linux, &home, &bin));
            let d = detected(&found, h.id()).expect("npm provenance detects");
            assert!(d.signals.contains(&Signal::NpmGlobal), "{:?}", d.signals);
            assert!(!d.signals.contains(&Signal::ConfigDir), "{:?}", d.signals);
        }
        assert!(checked > 0, "no generic-named harness ships an npm package");
    }

    /// The two sweeps above skip a harness that declares no generic binary, or
    /// no npm package to corroborate one — so both stay green if `pi` quietly
    /// stops being either. That matters more for `pi` than for anything else
    /// in the registry: it is the shortest name argus probes for, it is a word
    /// people give their own scripts, and treating a bare one as proof would
    /// have argus write an extension into a `~/.pi` that pi.dev never made.
    /// This pins pi's own two halves of the rule directly.
    #[test]
    fn a_bare_pi_on_path_is_not_pi_dev_but_one_from_npm_is() {
        let dir = tempfile::tempdir().unwrap();

        let home = dir.path().join("bare");
        let bin = home.join("bin");
        for platform in Platform::ALL {
            touch_exe(&bin.join(exe(*platform, "pi")));
        }
        for &platform in Platform::ALL {
            assert!(
                detected(&detect_in(&env_for(platform, &home, &bin)), "pi").is_none(),
                "{platform:?}: a bare `pi` on PATH was taken as evidence"
            );
        }

        // The same name, resolved into the package that ships it.
        let home = dir.path().join("npm");
        let bin = home
            .join("node_modules")
            .join("@earendil-works/pi-coding-agent")
            .join("bin");
        touch_exe(&bin.join("pi"));
        let found = detect_in(&env_for(Platform::Linux, &home, &bin));
        let d = detected(&found, "pi").expect("npm provenance must corroborate the name");
        assert!(d.signals.contains(&Signal::NpmGlobal), "{:?}", d.signals);
    }

    fn harness(id: &str) -> &'static dyn Harness {
        HARNESSES.iter().copied().find(|h| h.id() == id).unwrap()
    }

    /// A symlinked shim is the normal npm and brew layout; provenance has to
    /// follow it, because the link itself lives in a neutral `bin` directory
    /// that identifies nothing.
    #[cfg(unix)]
    #[test]
    fn provenance_follows_the_symlink_the_package_manager_installed() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let real = home.join("Cellar/opencode/1.18.10/bin/opencode");
        touch_exe(&real);
        let bin = home.join("brewbin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(&real, bin.join("opencode")).unwrap();

        let found = detect_in(&env_for(Platform::MacOS, home, &bin));
        let d = detected(&found, "opencode").expect("symlinked brew shim detects");
        assert!(d.signals.contains(&Signal::Brew), "{:?}", d.signals);
    }

    /// Windows stores executability in the extension, so a file without one is
    /// not a binary however permissive its mode bits are — and `PATHEXT` is
    /// what says which extensions count.
    #[test]
    fn windows_executability_comes_from_pathext() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        touch_exe(&bin.join("claude")); // no extension
        touch_exe(&bin.join("claude.ps1")); // not in the default PATHEXT

        let vars = BTreeMap::new();
        let plain = Env::new(
            Platform::Windows,
            dir.path(),
            vec![bin.clone()],
            None,
            vars.clone(),
        );
        assert!(
            detected(&detect_in(&plain), "claude-code").is_none(),
            "extension-less file is not executable on Windows"
        );

        let extended = Env::new(
            Platform::Windows,
            dir.path(),
            vec![bin],
            Some(".EXE;.PS1"),
            vars,
        );
        let found = detect_in(&extended);
        let d = detected(&found, "claude-code").expect("PATHEXT honoured");
        assert!(d.signals.contains(&Signal::Binary), "{:?}", d.signals);
    }

    /// `\\?\` is how Windows reports a canonical path; leaving it in place
    /// does not break the match, but the `\` separators do.
    #[test]
    fn windows_verbatim_paths_normalise_for_provenance() {
        assert!(under_npm(
            &real_path(Path::new(
                r"\\?\C:\Users\A\AppData\Roaming\npm\node_modules\opencode-ai\bin\x"
            )),
            "opencode-ai"
        ));
        assert!(under_brew(
            &real_path(Path::new(
                "/opt/homebrew/Cellar/opencode/1.18.10/bin/opencode"
            )),
            "opencode"
        ));
        assert!(!under_brew(
            &real_path(Path::new("/opt/homebrew/Cellar/opencode-ui/1.0/bin/x")),
            "opencode"
        ));
    }

    /// Per-user prefixes are searched even when the agent's `PATH` omits them
    /// — a GUI-launched agent commonly inherits only the system `PATH`.
    #[test]
    fn user_prefixes_are_searched_when_path_omits_them() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        for (platform, rel) in [
            (Platform::Linux, ".local/bin"),
            (Platform::MacOS, ".local/bin"),
            (Platform::Windows, "AppData/Roaming/npm"),
        ] {
            let exe_path = home.join(rel).join(exe(platform, "claude"));
            touch_exe(&exe_path);
            let env = Env::new(
                platform,
                home,
                user_prefixes(platform, home, &BTreeMap::new()),
                None,
                BTreeMap::new(),
            );
            let found = detect_in(&env);
            let d = detected(&found, "claude-code")
                .unwrap_or_else(|| panic!("{platform:?}: {rel} not searched"));
            assert!(d.signals.contains(&Signal::Binary), "{platform:?}");
            std::fs::remove_file(&exe_path).unwrap();
        }
    }

    /// A config directory declared for one platform must not resolve on
    /// another, or the Windows layout would be installed on Linux.
    #[test]
    fn platform_scoped_config_dirs_only_match_their_platform() {
        let cd = ConfigDir {
            env: None,
            rel: "AppData/Roaming/opencode",
            platform: Some(Platform::Windows),
        };
        assert!(cd.matches(Platform::Windows));
        assert!(!cd.matches(Platform::Linux));
        assert!(!cd.matches(Platform::MacOS));
    }

    /// An env-var-rooted config dir (`COPILOT_HOME`, `XDG_CONFIG_HOME`) wins
    /// over the home-relative default.
    #[test]
    fn env_rooted_config_dirs_win_over_the_home_relative_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut vars = BTreeMap::new();
        vars.insert(
            "XDG_CONFIG_HOME",
            dir.path().join("xdg").display().to_string(),
        );
        let env = Env::new(Platform::Linux, dir.path(), Vec::new(), None, vars);
        let cd = ConfigDir {
            env: Some(("XDG_CONFIG_HOME", "opencode")),
            rel: ".config/opencode",
            platform: None,
        };
        assert_eq!(cd.resolve(&env), dir.path().join("xdg/opencode"));

        let bare = Env::new(
            Platform::Linux,
            dir.path(),
            Vec::new(),
            None,
            BTreeMap::new(),
        );
        assert_eq!(cd.resolve(&bare), dir.path().join(".config/opencode"));
    }
}
