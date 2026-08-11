//! One registry for every supported agent harness.
//!
//! Before this module, adding a tool meant hand-syncing 6-7 edit sites with no
//! compiler enforcement: detection was duplicated verbatim in `install::run`
//! and `integrity::check`, and the per-tool installers were near-identical
//! 45-line copies. Here each harness instead *describes* itself — where its
//! config lives ([`Probes`]) and what files argus owns or edits
//! ([`Artifact`]) — and install/uninstall/check are single generic
//! implementations driven by that data.
//!
//! Two correctness properties come from centralising it:
//!
//! * **Entries are marked structurally.** Everything argus writes into a
//!   shared JSON file carries `"_argus": true`, so uninstall and check match a
//!   *field* rather than the substring "argus" in a serialized blob. The old
//!   substring test would happily delete a user's own hook that merely lived
//!   under a path containing "argus".
//! * **Command strings are quoted once, correctly, per platform.** The old
//!   `format!("{} hook …", exe)` broke on any path with a space — the common
//!   case on Windows (`C:\Program Files\…`, `C:\Users\John Smith\…`) — and
//!   wrote the same unquoted string to both the `bash` and `powershell` keys,
//!   where PowerShell additionally needs the `&` call operator.

pub mod claude_code;
pub mod codex;
pub mod copilot;
pub mod opencode;
pub mod pi;

use crate::config::CaptureCfg;
use crate::detect::{BinaryProbe, Env, Platform, detect};
use crate::event::{Envelope, Event};
use crate::integrity::Finding;
use anyhow::Result;
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Field stamped on every hook entry argus writes into a *shared* JSON file.
/// Structured ownership: uninstall/check test this key, not a substring.
pub const MARKER_KEY: &str = "_argus";

/// Pre-`_argus` installs tagged entries only by having "argus" somewhere in
/// the serialized entry. That is kept as a *fallback* so upgrading then
/// uninstalling still removes old entries — but narrowed to the command
/// actually invoking our shim (`… hook --source <id>`) rather than the string
/// "argus" appearing anywhere, which also matched a user's unrelated hook
/// living under an "argus" path (a repo checked out at `~/src/argus/`).
fn is_legacy_ours(entry: &Value, source: &str) -> bool {
    let needle = format!(" hook --source {source}");
    entry["hooks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|h| h.get("command").and_then(Value::as_str))
        .any(|c| c.contains(&needle))
}

/// Every harness argus knows how to wire itself into.
pub const HARNESSES: &[&dyn Harness] = &[
    &claude_code::ClaudeCode,
    &opencode::OpenCode,
    &codex::Codex,
    &copilot::Copilot,
    &pi::Pi,
];

/// Which layer an install targets: the invoking user's own config, the
/// admin-owned machine-wide layer users cannot disable, or a single
/// repository's own config directory.
///
/// `Project` is a strictly smaller install than `User`, not a variant of it —
/// only hook wiring goes into a repository. Machine-level settings must not:
/// Codex's `[otel]` block carries this install's receiver token, and a token
/// committed to a repository is a token published to everyone who can clone
/// it. Harnesses with nothing to put in a repository return no artifacts.
///
/// `Managed` carries the platform it is being resolved for, because a
/// machine-wide install is the one case where argus writes artifacts for a
/// platform it may not be running on: the round-trip tests sweep all three
/// against a fake system root, and the layers genuinely differ per OS (Codex
/// spells the same setting `managed_dir` on unix and `windows_managed_dir` on
/// Windows, and setting both is an error). Nothing else can be told apart from
/// the path alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Managed(Platform),
    Project,
}

/// One hook event to subscribe to.
///
/// `matcher` marks the tool-name-matched events that take `"matcher": "*"`;
/// matcher-less entries run for every matcher value anyway.
#[derive(Debug, Clone, Copy)]
pub struct HookEvent {
    pub name: &'static str,
    pub matcher: bool,
    /// Seconds. Bounded so a wedged shim can never stall the agent.
    pub timeout: u64,
}

impl HookEvent {
    pub const fn new(name: &'static str, matcher: bool) -> Self {
        Self {
            name,
            matcher,
            timeout: 10,
        }
    }

    /// For events where the default is too patient. The shim gives up on the
    /// daemon after 250 ms and spools instead, so no event needs seconds —
    /// the default is slack, not a requirement, and on a shutdown hook that
    /// slack is a delay the user watches.
    pub const fn with_timeout(name: &'static str, matcher: bool, timeout: u64) -> Self {
        Self {
            name,
            matcher,
            timeout,
        }
    }
}

/// Layout of a hooks JSON file. Claude Code and Codex share one schema
/// (`hooks.{Event}[] = [{ hooks: [{type, command, timeout}], matcher? }]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookShape {
    CommandArray,
}

/// A key-level edit into a shared TOML file, applied with `toml_edit` so
/// comments and formatting survive.
pub struct TomlEditOp {
    pub key: &'static str,
    pub value: toml_edit::Item,
    /// Never clobber a value the user set themselves.
    pub only_if_absent: bool,
    /// Substrings identifying an existing value as ours, for uninstall.
    pub ours_markers: Vec<String>,
    /// Set when being *ours* is not enough and the value has to match this
    /// install exactly (Codex's OTLP endpoint and receiver token).
    /// `ours_markers` deliberately includes what older argus versions wrote, so
    /// uninstall still recognises what it left behind — but a config pointing
    /// at an endpoint nothing listens on, or presenting a token the receiver
    /// refuses, captures nothing, and matching a legacy marker would report
    /// that as wired. `check` uses these instead when the list is non-empty.
    pub must_carry: Vec<Required>,
    /// Set when the value is an argv array whose first element is the argus
    /// binary (Codex's `notify`). `check` then confirms the trailing arguments
    /// still match *and* that element 0 still names a runnable program — the
    /// substring markers alone would pass on a value pointing at a binary that
    /// no longer exists.
    pub argv_tail: Option<&'static [&'static str]>,
}

/// One thing `check` demands of an existing value.
///
/// `what` rather than the needle is what the error prints. One of these needles
/// is a bearer token, and a `check` designed for MDM compliance scripts and
/// monitoring agents writes its output somewhere it will be collected, indexed,
/// and read by more people than the account that owns the secret.
pub struct Required {
    /// The requirement in words, e.g. "the endpoint http://127.0.0.1:41234".
    pub what: String,
    /// Substring searched for in the rendered value.
    pub needle: String,
    /// `false` inverts it: the needle must *not* appear. Used where a stale
    /// credential is the failure and the current one is not known — a data
    /// directory restored without its token file leaves Codex presenting
    /// something the receiver will mint a replacement for and then refuse.
    pub present: bool,
}

/// Something argus writes on install and reverses on uninstall.
pub enum Artifact {
    /// Merge argus entries into a shared JSON file, preserving key order.
    JsonHooks {
        path: PathBuf,
        events: &'static [HookEvent],
        shape: HookShape,
        /// `--source` value for the hook command.
        source: &'static str,
        /// Top-level settings argus pins in this file, beside the hooks.
        ///
        /// Only the machine-wide layer uses them, and only for settings that
        /// decide whether hooks run at all: an entry wired perfectly into a
        /// file that also says `disableAllHooks` is wiring that captures
        /// nothing. `check` requires each to still hold exactly, so flipping
        /// one is a finding rather than a silent capture outage.
        ///
        /// A `Vec` rather than a `&'static [..]` because `serde_json::Value`
        /// cannot be constructed in a `const`.
        pinned: Vec<(&'static str, Value)>,
    },
    /// Whole file argus owns outright; overwrite on install, delete on uninstall.
    OwnedFile {
        path: PathBuf,
        contents: Cow<'static, str>,
        /// Literal substrings whose absence means capture through this file is
        /// blind — for a hooks file, the exact stored command per event.
        /// `check` requires every one to still be on disk. Existence alone
        /// proves nothing: a zero-byte or hand-edited file passes an
        /// `exists()` test while capturing nothing.
        ///
        /// These are matched against the raw file text, so they must be
        /// written the way the file stores them (JSON-escaped inside a JSON
        /// file), which is why they cannot double as `commands`.
        markers: Vec<String>,
        /// Hook commands, unescaped, whose program must still resolve to an
        /// executable. Empty for a file that reaches the daemon without
        /// invoking the binary (the opencode plugin speaks the socket).
        commands: Vec<String>,
    },
    /// Key-level edits into a shared TOML file via toml_edit, never clobbering.
    TomlEdit {
        path: PathBuf,
        edits: Vec<TomlEditOp>,
    },
}

/// A config directory that signals a harness is installed.
#[derive(Debug, Clone, Copy)]
pub struct ConfigDir {
    /// `(variable, path relative to its value)` — an environment-rooted
    /// location that wins over `rel` when the variable is set and non-empty
    /// (`COPILOT_HOME`, `XDG_CONFIG_HOME`).
    pub env: Option<(&'static str, &'static str)>,
    /// Path relative to the user's home directory.
    pub rel: &'static str,
    /// Restrict this location to one platform; `None` matches all of them.
    pub platform: Option<Platform>,
}

impl ConfigDir {
    pub fn matches(&self, platform: Platform) -> bool {
        self.platform.is_none_or(|p| p == platform)
    }

    pub fn resolve(&self, env: &Env) -> PathBuf {
        if let Some((key, rel)) = self.env
            && let Some(v) = env.var(key)
        {
            return PathBuf::from(v).join(rel);
        }
        env.home.join(self.rel)
    }
}

/// A machine-wide config directory: administrator-owned, resolved against the
/// *system* root rather than against anybody's home directory.
///
/// Being a separate type from [`ConfigDir`] is the whole point. `argus install
/// --managed` runs under `sudo`, so `dirs::home_dir()` is `/root` — a managed
/// location that went through [`Env::home`] would quietly wire the
/// administrator's own account and monitor nobody.
#[derive(Debug, Clone, Copy)]
pub struct ManagedDir {
    /// Path relative to the system root, forward-slashed
    /// (`etc/claude-code`, `Program Files/ClaudeCode`).
    pub rel: &'static str,
    /// Unlike [`ConfigDir::platform`] there is no all-platforms option: every
    /// documented managed layer sits somewhere different on each OS, so a
    /// missing entry means "this tool has no managed layer here" rather than
    /// "the same path works everywhere".
    pub platform: Platform,
}

/// Environment override for the machine-wide root, so the round-trip tests
/// exercise the real relative paths against a temp directory.
///
/// It redirects a write; it never grants the right to perform one.
/// [`crate::install::run_managed`] demands administrator rights only when the
/// root is the real one, which is the only place they mean anything — and a
/// user who can set this variable could equally well write the directory it
/// points at.
pub const SYSTEM_ROOT_ENV: &str = "ARGUS_SYSTEM_ROOT";

/// Where the managed layer is rooted, and whether that is the real machine.
pub struct SystemRoot {
    pub path: PathBuf,
    /// `false` when [`SYSTEM_ROOT_ENV`] redirected it at a test directory.
    pub real: bool,
}

/// Resolve [`SystemRoot`] for a platform. Takes the platform rather than
/// reading `cfg!`, so the Windows layout is exercised by the suite on Linux
/// and macOS too — the same rule [`crate::detect`] follows.
pub fn system_root(platform: Platform) -> SystemRoot {
    match std::env::var_os(SYSTEM_ROOT_ENV) {
        Some(v) if !v.is_empty() => SystemRoot {
            path: PathBuf::from(v),
            real: false,
        },
        _ => SystemRoot {
            path: PathBuf::from(match platform {
                Platform::Windows => "C:\\",
                Platform::Linux | Platform::MacOS => "/",
            }),
            real: true,
        },
    }
}

/// Declarative detection inputs. Each is one independent way to conclude the
/// tool is present; see [`crate::detect`] for how they combine.
pub struct Probes {
    pub config_dirs: &'static [ConfigDir],
    /// Binary names the tool installs. A [`BinaryProbe::generic`] name needs
    /// corroboration before it counts.
    pub binaries: &'static [BinaryProbe],
    /// Global npm package names, matched against `node_modules/<name>/` in the
    /// binary's real path.
    pub npm_packages: &'static [&'static str],
    /// Homebrew formula names, matched against `Cellar/<name>/`.
    pub brew_formulae: &'static [&'static str],
}

/// Which detection signal(s) fired for a harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    ConfigDir,
    Binary,
    NpmGlobal,
    Brew,
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Signal::ConfigDir => "config dir",
            Signal::Binary => "binary",
            Signal::NpmGlobal => "npm",
            Signal::Brew => "brew",
        })
    }
}

/// A harness found on this machine.
pub struct Detection {
    pub id: &'static str,
    pub signals: Vec<Signal>,
    /// Where argus installs. The first declared location for this platform
    /// when none exists yet — a tool installed but never run has no config
    /// directory, and install creates it.
    pub config_home: PathBuf,
    /// The tool's binary, when a binary signal fired. Reported by `status` and
    /// `install --dry-run` so a surprising detection can be traced to a file.
    pub binary: Option<PathBuf>,
}

impl Detection {
    /// The signals that fired, for human output.
    pub fn why(&self) -> String {
        let mut s = self
            .signals
            .iter()
            .map(Signal::to_string)
            .collect::<Vec<_>>()
            .join("+");
        if let Some(b) = &self.binary {
            s.push_str(&format!(" ({})", b.display()));
        }
        s
    }
}

/// A harness-specific setting that silently disables capture (e.g. Codex's
/// `[features] hooks = false`). Check-only: reported, never written.
///
/// Claude Code, Codex and Copilot report these. opencode has no equivalent
/// setting; pi.dev's extensions are loaded by presence, so removing one is the
/// only way to disable it and there is nothing silent to detect.
pub struct KillSwitch {
    pub name: &'static str,
    pub detail: String,
}

pub trait Harness: Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn probes(&self) -> Probes;
    /// Machine-wide locations this tool reads, one per platform it has one on.
    /// Empty — the default — means the tool documents no managed layer, and
    /// [`install_managed`] then never asks it for `Scope::Managed` artifacts.
    fn managed_dirs(&self) -> &'static [ManagedDir] {
        &[]
    }
    fn artifacts(&self, d: &Detection, scope: Scope) -> Vec<Artifact>;
    fn kill_switches(&self, _d: &Detection) -> Vec<KillSwitch> {
        Vec::new()
    }
    fn parse(&self, env: &Envelope, cfg: &CaptureCfg) -> Vec<Event>;
}

// ---------------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------------

/// How the shell that runs a hook command parses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdStyle {
    /// POSIX shell, or the `bash` key of a Copilot hook entry.
    Shell,
    /// PowerShell, which needs `&` to invoke a quoted path.
    PowerShell,
}

/// Environment override for the binary path baked into hook commands. The
/// opencode plugin shim reads the same variable to find the binary.
pub const BIN_ENV: &str = "ARGUS_BIN";

/// Path to argus as baked into every hook command — deliberately *not* raw
/// `current_exe()`.
///
/// On Linux and macOS `current_exe()` resolves symlinks, so a Homebrew install
/// reports `…/Cellar/argus/0.2.0/bin/argus`. That path stops existing the next
/// time the formula is upgraded, and every hook baked from it silently stops
/// firing — capture goes blind with no error anywhere. The stable entry point
/// is the alias on `PATH` (`/opt/homebrew/bin/argus`, `~/.npm-global/bin/argus`,
/// `~/.cargo/bin/argus`), which keeps pointing at whatever version is current,
/// so it wins whenever it resolves to this very binary.
pub fn install_path() -> String {
    if let Ok(v) = std::env::var(BIN_ENV)
        && !v.is_empty()
    {
        return v;
    }
    let Ok(exe) = std::env::current_exe() else {
        return "argus".into();
    };
    std::env::var_os("PATH")
        .and_then(|p| stable_alias(&exe, &p))
        .unwrap_or(exe)
        .to_string_lossy()
        .into_owned()
}

/// An entry on `PATH` that names this same binary under a stable alias.
///
/// "Same binary" is decided by canonicalisation, not by name, so an unrelated
/// `argus` earlier on `PATH` is never adopted — a dev build in `target/debug`
/// keeps pointing at itself rather than silently retargeting the packaged
/// install.
fn stable_alias(exe: &Path, path_var: &OsStr) -> Option<PathBuf> {
    let target = exe.canonicalize().ok()?;
    let name = exe.file_name()?;
    std::env::split_paths(path_var)
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(name))
        .find(|cand| cand != exe && cand.canonicalize().is_ok_and(|c| c == target))
}

/// Quote a program path for `style`, so a path containing spaces survives.
pub fn quote_program(exe: &str, style: CmdStyle) -> String {
    match style {
        CmdStyle::PowerShell => {
            // PowerShell parses a bare quoted string as a *string literal*;
            // `&` is what makes it an invocation. Backticks escape inside "".
            let escaped = exe.replace('`', "``").replace('"', "`\"");
            format!("& \"{escaped}\"")
        }
        CmdStyle::Shell => {
            // POSIX quoting whatever host wrote the file. The only consumer is
            // the `bash` key of a Copilot hook entry, which bash runs; the
            // machine argus installed from does not get a say in that, and
            // quoting for the local shell instead would put cmd.exe syntax in a
            // field bash is going to read. A Windows path survives it: the
            // backslashes are literal inside single quotes.
            if exe
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
            {
                exe.to_string()
            } else {
                // POSIX single quotes are literal; close/escape/reopen for `'`.
                format!("'{}'", exe.replace('\'', r"'\''"))
            }
        }
    }
}

/// The full hook command for `source`, quoted for `style`.
pub fn hook_command(source: &str, event: Option<&str>, style: CmdStyle) -> String {
    hook_command_for(&install_path(), source, event, style)
}

/// Testable core of [`hook_command`] with the exe path injected.
pub fn hook_command_for(exe: &str, source: &str, event: Option<&str>, style: CmdStyle) -> String {
    let mut cmd = format!("{} hook --source {source}", quote_program(exe, style));
    if let Some(e) = event {
        cmd.push_str(&format!(" --event {e}"));
    }
    cmd
}

// ---------------------------------------------------------------------------
// Command verification
// ---------------------------------------------------------------------------

/// Recover the program path from a stored hook command — the inverse of
/// [`quote_program`], plus the bare unquoted form older installs wrote.
///
/// `check` has to read the command *as recorded on disk*, not re-derive it:
/// the whole point is to catch a command baked at an install path that no
/// longer holds a binary.
pub fn program_of(cmd: &str) -> Option<String> {
    // A leading `&` is PowerShell's call operator, and also tells us backticks
    // in the quoted path are escapes rather than literal characters.
    let (s, powershell) = match cmd.trim_start().strip_prefix('&') {
        Some(rest) => (rest.trim_start(), true),
        None => (cmd.trim_start(), false),
    };

    if let Some(mut rest) = s.strip_prefix('\'') {
        // POSIX single quotes are literal end to end; `'\''` is the only
        // escape, encoding one quote by closing, escaping, and reopening.
        let mut out = String::new();
        loop {
            let i = rest.find('\'')?;
            out.push_str(&rest[..i]);
            rest = &rest[i + 1..];
            match rest.strip_prefix(r"\''") {
                Some(r) => {
                    out.push('\'');
                    rest = r;
                }
                None => return Some(out),
            }
        }
    }

    if let Some(mut rest) = s.strip_prefix('"') {
        let mut out = String::new();
        loop {
            let stop: &[char] = if powershell { &['"', '`'] } else { &['"'] };
            let i = rest.find(stop)?;
            out.push_str(&rest[..i]);
            let c = rest[i..].chars().next()?;
            rest = &rest[i + c.len_utf8()..];
            if c == '"' {
                return Some(out);
            }
            // Backtick escape: the next character stands for itself.
            let mut it = rest.chars();
            out.push(it.next()?);
            rest = it.as_str();
        }
    }

    s.split_whitespace().next().map(str::to_string)
}

/// Is this a file that can actually be executed?
fn runnable(p: &Path) -> bool {
    let Ok(md) = std::fs::metadata(p) else {
        return false;
    };
    if !md.is_file() {
        return false;
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

/// Resolve a recorded program to a runnable file, searching `PATH` for a bare
/// name the way the shell that runs the hook would.
fn resolve_program(p: &str) -> Option<PathBuf> {
    let path = Path::new(p);
    if path.components().count() > 1 {
        return runnable(path).then(|| path.to_path_buf());
    }
    let candidates = |dir: PathBuf| -> Vec<PathBuf> {
        let mut v = vec![dir.join(p)];
        if cfg!(windows) {
            v.push(dir.join(format!("{p}.exe")));
        }
        v
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .filter(|d| !d.as_os_str().is_empty())
        .flat_map(candidates)
        .find(|c| runnable(c))
}

/// `Ok(())` when the command's program still exists and is executable.
fn check_command(cmd: &str) -> std::result::Result<(), String> {
    let Some(prog) = program_of(cmd) else {
        return Err(format!("unparsable hook command: {cmd}"));
    };
    if resolve_program(&prog).is_some() {
        Ok(())
    } else {
        Err(format!(
            "hook points at a missing or non-executable binary: {prog}"
        ))
    }
}

fn harness_by_id(id: &str) -> Option<&'static dyn Harness> {
    HARNESSES.iter().copied().find(|h| h.id() == id)
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

/// Is this hook entry one argus wrote?
///
/// The structured marker is authoritative when present — including when it
/// says `false` — so a user can opt an entry out explicitly. Only an entry
/// with no marker at all falls through to the legacy shape test.
fn is_ours(entry: &Value, source: &str) -> bool {
    match entry.get(MARKER_KEY) {
        Some(Value::Bool(b)) => *b,
        _ => is_legacy_ours(entry, source),
    }
}

// ---------------------------------------------------------------------------
// Generic install / uninstall / check
// ---------------------------------------------------------------------------

pub fn install(home: &Path, dry_run: bool) -> Result<()> {
    // Minted here rather than lazily inside `artifacts`, which a dry run also
    // calls: creating the token file is a write, and "would update" must not
    // leave anything behind. Not gated on a Codex being detected — the file is
    // one line in our own data directory, and threading detection into it
    // would trade that for a rule about ordering.
    if !dry_run && let Err(e) = crate::adapters::codex::shared_token() {
        eprintln!("warning: could not create the Codex receiver token: {e}");
    }
    for d in detect(home) {
        let Some(h) = harness_by_id(d.id) else {
            continue;
        };
        println!(
            "{}detected {} via {}",
            if dry_run { "[dry-run] " } else { "" },
            h.display_name(),
            d.why()
        );
        // A tool found only by its binary has never been run, so its config
        // directory does not exist yet. Nothing extra is needed to create it:
        // every artifact writer creates its own parent chain, and each writes
        // under `config_home`. What matters is that the writers are the *only*
        // thing that creates it, so a dry run — which returns before all of
        // them — still leaves the disk exactly as it found it.
        for artifact in h.artifacts(&d, Scope::User) {
            apply(&artifact, h.display_name(), dry_run)?;
        }
    }
    Ok(())
}

/// Where a harness keeps its config *inside a repository*. Detection has no
/// part in it: the operator named the directory, and a repository that has
/// never been opened in the tool has no `.codex/` yet — which is exactly the
/// case wiring it ahead of time is for.
fn project_detection(h: &dyn Harness, root: &Path) -> Option<Detection> {
    let rel = h.probes().config_dirs.first()?.rel;
    Some(Detection {
        id: h.id(),
        signals: Vec::new(),
        config_home: root.join(rel),
        binary: None,
    })
}

/// Wire a single repository, so anyone who runs a supported agent inside it is
/// captured without a per-machine install of the *hooks* — the argus binary
/// itself still has to be on that machine's `PATH`, and a clone on a machine
/// without it runs a hook command that resolves to nothing.
///
/// Codex additionally loads a repository's hooks only once that `.codex/`
/// layer is trusted there, per user. This is a convenience for teams that
/// already ship argus in their image, not an enforcement mechanism: anyone who
/// can push to the repository can also remove what this writes.
pub fn install_project(root: &Path, dry_run: bool) -> Result<()> {
    let mut wired = 0;
    for h in HARNESSES {
        let Some(d) = project_detection(*h, root) else {
            continue;
        };
        for artifact in h.artifacts(&d, Scope::Project) {
            apply(&artifact, h.display_name(), dry_run)?;
            wired += 1;
        }
    }
    if wired == 0 {
        println!("no tool supports repository-level wiring yet");
    }
    Ok(())
}

/// Exact inverse of [`install_project`].
pub fn uninstall_project(root: &Path) -> Result<()> {
    for h in HARNESSES {
        let Some(d) = project_detection(*h, root) else {
            continue;
        };
        for artifact in h.artifacts(&d, Scope::Project) {
            revert(&artifact)?;
        }
    }
    Ok(())
}

/// [`check`] for a repository. A repository nothing wired is silent rather
/// than broken, the same rule detection follows for an absent tool: reporting
/// every unwired checkout as a failure would make the exit code meaningless.
pub fn check_project(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for h in HARNESSES {
        let Some(d) = project_detection(*h, root) else {
            continue;
        };
        let artifacts = h.artifacts(&d, Scope::Project);
        if artifacts.is_empty() || artifacts.iter().all(|a| !artifact_path(a).exists()) {
            continue;
        }
        let problems: Vec<String> = artifacts.iter().filter_map(|a| verify(a).err()).collect();
        out.push(Finding {
            tool: format!("{} ({})", h.id(), root.display()),
            ok: problems.is_empty(),
            detail: if problems.is_empty() {
                "wired".into()
            } else {
                problems.join("; ")
            },
        });
    }
    out
}

// ---------------------------------------------------------------------------
// The machine-wide layer
// ---------------------------------------------------------------------------

/// Where a harness keeps its administrator-owned config on this platform, or
/// `None` when it has none there.
///
/// Detection has no part in it, for the same reason it has none in
/// [`project_detection`]: an admin wires a fleet image before anybody has run
/// the tool on it. What replaces detection is the declaration — a harness that
/// names no [`ManagedDir`] for this platform is never asked for
/// `Scope::Managed` artifacts at all, so it cannot answer with the user-scope
/// paths it would otherwise return.
fn managed_detection(h: &dyn Harness, root: &Path, platform: Platform) -> Option<Detection> {
    let rel = h
        .managed_dirs()
        .iter()
        .find(|m| m.platform == platform)?
        .rel;
    Some(Detection {
        id: h.id(),
        signals: Vec::new(),
        config_home: root.join(rel),
        binary: None,
    })
}

/// The backstop behind [`managed_detection`]: `Some(why)` when an artifact
/// would land outside the machine-wide layer.
///
/// A harness that grows a managed location but forgets to branch on
/// `Scope::Managed` falls through to its *user* artifacts, and under `sudo`
/// those are paths in `/root` — wiring the administrator's own account and
/// monitoring nobody. Enforced centrally rather than trusted to each harness,
/// so getting it wrong is a refusal instead of a silent misinstall.
fn escapes_managed_root(root: &Path, a: &Artifact) -> Option<String> {
    let p = artifact_path(a);
    (!p.starts_with(root)).then(|| {
        format!(
            "{} is outside the machine-wide layer under {}",
            p.display(),
            root.display()
        )
    })
}

/// Wire the whole machine: settings in a root ordinary users cannot write, so
/// capture survives a user editing their own config.
///
/// This is one half of a managed deployment. The other half is not a file:
/// the argus binary has to be readable and executable by every account the
/// hooks fire under, and — because the socket, the OTLP port and the buffer
/// are all per-user (T8) — each of those accounts needs its own running
/// daemon. A managed layer alone wires every user to a binary they can run and
/// a daemon that is not there.
pub fn install_managed(root: &Path, platform: Platform, dry_run: bool) -> Result<()> {
    install_managed_in(HARNESSES, root, platform, dry_run)
}

fn install_managed_in(
    harnesses: &[&dyn Harness],
    root: &Path,
    platform: Platform,
    dry_run: bool,
) -> Result<()> {
    let mut wired = 0;
    for h in harnesses {
        let Some(d) = managed_detection(*h, root, platform) else {
            continue;
        };
        let artifacts = h.artifacts(&d, Scope::Managed(platform));
        // Checked for the whole harness before a single one is applied: a
        // refusal half-way through would leave the machine in a state neither
        // install nor uninstall describes.
        for a in &artifacts {
            if let Some(why) = escapes_managed_root(root, a) {
                anyhow::bail!("{}: refusing to write it — {why}", h.id());
            }
        }
        for a in &artifacts {
            apply(a, h.display_name(), dry_run)?;
            wired += 1;
        }
    }
    if wired == 0 {
        println!("no tool supports machine-wide wiring on {platform:?} yet");
    }
    Ok(())
}

/// Exact inverse of [`install_managed`].
pub fn uninstall_managed(root: &Path, platform: Platform) -> Result<()> {
    uninstall_managed_in(HARNESSES, root, platform)
}

fn uninstall_managed_in(harnesses: &[&dyn Harness], root: &Path, platform: Platform) -> Result<()> {
    for h in harnesses {
        let Some(d) = managed_detection(*h, root, platform) else {
            continue;
        };
        let artifacts = h.artifacts(&d, Scope::Managed(platform));
        // The containment rule binds uninstall harder than install: reverting
        // an `OwnedFile` deletes it, so a harness answering with a user-scope
        // path here would have argus remove a file it never wrote.
        for a in &artifacts {
            if let Some(why) = escapes_managed_root(root, a) {
                anyhow::bail!("{}: refusing to touch it — {why}", h.id());
            }
        }
        for a in &artifacts {
            revert(a)?;
        }
    }
    Ok(())
}

/// [`check`] for the machine-wide layer.
///
/// Where [`check_project`] stays silent about a repository nothing wired, an
/// absent managed artifact is BROKEN: passing `--managed` is the operator
/// asserting the layer should be there, and a removed file is exactly the
/// tampering this check exists to catch. Harnesses with no managed layer on
/// this platform are still silent — they are not missing anything.
pub fn check_managed(root: &Path, platform: Platform) -> Vec<Finding> {
    check_managed_in(HARNESSES, root, platform)
}

fn check_managed_in(harnesses: &[&dyn Harness], root: &Path, platform: Platform) -> Vec<Finding> {
    let mut out = Vec::new();
    for h in harnesses {
        let Some(d) = managed_detection(*h, root, platform) else {
            continue;
        };
        let artifacts = h.artifacts(&d, Scope::Managed(platform));
        if artifacts.is_empty() {
            continue;
        }
        let mut problems: Vec<String> = artifacts
            .iter()
            .filter_map(|a| escapes_managed_root(root, a))
            .collect();
        problems.extend(artifacts.iter().filter_map(|a| verify(a).err()));
        out.push(Finding {
            tool: format!("{} (managed)", h.id()),
            ok: problems.is_empty(),
            detail: if problems.is_empty() {
                "wired".into()
            } else {
                problems.join("; ")
            },
        });
    }
    out
}

/// Can this process write the machine-wide root?
pub fn is_admin() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no
        // memory this process owns.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        use std::ptr;
        use windows_sys::Win32::Security::{
            AllocateAndInitializeSid, CheckTokenMembership, FreeSid, PSID, SECURITY_NT_AUTHORITY,
            SID_IDENTIFIER_AUTHORITY,
        };

        // `SECURITY_BUILTIN_DOMAIN_RID` and `DOMAIN_ALIAS_RID_ADMINS`. Spelled
        // out rather than imported: windows-sys keeps them behind
        // `Win32_System_SystemServices`, a feature that would pull thousands of
        // unrelated definitions in for two stable documented integers.
        const BUILTIN_DOMAIN_RID: u32 = 32;
        const ADMINS_ALIAS_RID: u32 = 544;

        let authority: SID_IDENTIFIER_AUTHORITY = SECURITY_NT_AUTHORITY;
        let mut sid: PSID = ptr::null_mut();
        // SAFETY: `authority` outlives the call and `sid` is a valid
        // out-pointer, read only after a success return.
        let built = unsafe {
            AllocateAndInitializeSid(
                &authority,
                2,
                BUILTIN_DOMAIN_RID,
                ADMINS_ALIAS_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            )
        };
        if built == 0 {
            return false;
        }
        let mut member = 0;
        // SAFETY: a null token handle asks about the calling thread's own
        // effective token, which is what "am I elevated" means here; `sid` is
        // the SID just allocated.
        let ok = unsafe { CheckTokenMembership(ptr::null_mut(), sid, &mut member) } != 0;
        // SAFETY: `FreeSid` is the documented release for what
        // `AllocateAndInitializeSid` returned, and nothing borrows it now.
        unsafe { FreeSid(sid) };
        ok && member != 0
    }
}

/// Fail before the first write rather than part-way through with an `EACCES`
/// from whichever file happened to come first — a partial managed install is
/// worse than none, because `check` would then report some of it wired.
pub fn require_admin() -> Result<()> {
    if is_admin() {
        return Ok(());
    }
    anyhow::bail!(
        "the machine-wide layer is administrator-owned: re-run as `sudo argus …`, \
         or on Windows from an elevated prompt"
    )
}

fn artifact_path(a: &Artifact) -> &Path {
    match a {
        Artifact::JsonHooks { path, .. }
        | Artifact::OwnedFile { path, .. }
        | Artifact::TomlEdit { path, .. } => path,
    }
}

fn apply(artifact: &Artifact, display: &str, dry_run: bool) -> Result<()> {
    match artifact {
        Artifact::JsonHooks {
            path,
            events,
            shape,
            source,
            pinned,
        } => {
            let mut doc = read_json_object(path);
            let hooks = object_entry(&mut doc, "hooks");
            let cmd = hook_command(source, None, CmdStyle::Shell);
            for ev in *events {
                let arr = object_entry(hooks, ev.name);
                if !arr.is_array() {
                    *arr = json!([]);
                }
                let arr = arr.as_array_mut().unwrap();
                // Refreshed rather than skipped. The entry is versioned with
                // the binary — the baked command and the per-event timeout
                // both change between releases — so skipping an event that
                // already has an argus entry left every upgraded host running
                // whatever the *first* install wrote, forever, with no way
                // short of uninstalling to correct it. Same rule as
                // `OwnedFile` below, and idempotent for the same reason:
                // exactly one argus entry per event, and an unchanged release
                // rewrites identical bytes. Only entries carrying our own
                // marker are touched; a hand-written hook beside ours is not
                // ours to replace.
                let want = hook_entry(*shape, &cmd, ev);
                match arr.iter_mut().find(|h| is_ours(h, source)) {
                    Some(ours) => *ours = want,
                    None => arr.push(want),
                }
            }
            // Set, not merged: these exist to hold one value, and an
            // administrator who wants a different one wants argus not to
            // write this file.
            for (key, value) in pinned {
                doc[*key] = value.clone();
            }
            if dry_run {
                println!("[dry-run] would update {}", path.display());
                return Ok(());
            }
            write_json(path, &doc)?;
            println!("wired {display} hooks in {}", path.display());
        }
        Artifact::OwnedFile { path, contents, .. } => {
            if dry_run {
                println!("[dry-run] would write {}", path.display());
                return Ok(());
            }
            // Overwrite unconditionally: the file is versioned with the
            // binary, so a stale copy from an older install must be replaced.
            write_atomic(path, contents.as_ref().as_bytes())?;
            println!("installed {display} at {}", path.display());
        }
        Artifact::TomlEdit { path, edits } => {
            let mut doc = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
                .unwrap_or_default();
            for e in edits {
                if e.only_if_absent && doc.contains_key(e.key) {
                    eprintln!("{display}: existing {} preserved; not overwriting", e.key);
                    continue;
                }
                doc[e.key] = e.value.clone();
            }
            if dry_run {
                println!("[dry-run] would update {}", path.display());
                return Ok(());
            }
            write_atomic(path, doc.to_string().as_bytes())?;
            let keys: Vec<&str> = edits.iter().map(|e| e.key).collect();
            println!("wired {display} {} in {}", keys.join("+"), path.display());
        }
    }
    Ok(())
}

fn hook_entry(shape: HookShape, cmd: &str, ev: &HookEvent) -> Value {
    match shape {
        HookShape::CommandArray => {
            let mut entry = json!({
                "hooks": [{ "type": "command", "command": cmd, "timeout": ev.timeout }],
                MARKER_KEY: true,
            });
            if ev.matcher {
                entry["matcher"] = json!("*");
            }
            entry
        }
    }
}

/// Exact inverse of [`install`]: remove what argus added and nothing else.
pub fn uninstall(home: &Path) -> Result<()> {
    for d in detect(home) {
        let Some(h) = harness_by_id(d.id) else {
            continue;
        };
        for artifact in h.artifacts(&d, Scope::User) {
            revert(&artifact)?;
        }
    }
    Ok(())
}

fn revert(artifact: &Artifact) -> Result<()> {
    match artifact {
        Artifact::JsonHooks {
            path,
            events,
            source,
            pinned,
            ..
        } => {
            let Ok(text) = std::fs::read_to_string(path) else {
                return Ok(());
            };
            let Ok(mut doc) = serde_json::from_str::<Value>(&text) else {
                return Ok(());
            };
            if let Some(hooks) = doc.get_mut("hooks").and_then(Value::as_object_mut) {
                for v in hooks.values_mut() {
                    if let Some(arr) = v.as_array_mut() {
                        arr.retain(|h| !is_ours(h, source));
                    }
                }
                // Drop event keys left empty. Two cases, both handled by
                // keying off the *known event list* rather than off what we
                // just removed: the array we just emptied, and — on machines
                // wired by an older argus — a key already sitting empty, where
                // no argus entry survives to trigger the retain above.
                for ev in *events {
                    if hooks
                        .get(ev.name)
                        .and_then(Value::as_array)
                        .is_some_and(|a| a.is_empty())
                    {
                        hooks.remove(ev.name);
                    }
                }
                let empty = hooks.is_empty();
                if empty {
                    doc.as_object_mut().map(|o| o.remove("hooks"));
                }
            }
            // Only while the value is still the one argus wrote. An
            // administrator who has since set it themselves has taken it over,
            // and uninstalling argus is not a reason to change their policy.
            if let Some(obj) = doc.as_object_mut() {
                for (key, value) in pinned {
                    if obj.get(*key) == Some(value) {
                        obj.remove(*key);
                    }
                }
            }
            write_json(path, &doc)?;
        }
        Artifact::OwnedFile { path, .. } => {
            let _ = std::fs::remove_file(path);
        }
        Artifact::TomlEdit { path, edits } => {
            let Ok(text) = std::fs::read_to_string(path) else {
                return Ok(());
            };
            let Ok(mut doc) = text.parse::<toml_edit::DocumentMut>() else {
                return Ok(());
            };
            for e in edits {
                let ours = doc.get(e.key).is_some_and(|item| {
                    let s = item.to_string();
                    e.ours_markers.iter().any(|m| s.contains(m.as_str()))
                });
                if ours {
                    doc.remove(e.key);
                }
            }
            write_atomic(path, doc.to_string().as_bytes())?;
        }
    }
    Ok(())
}

/// Wiring status for every harness argus could have wired.
///
/// Detection is deliberately wider than this: `install` acts on a binary alone
/// so a freshly-installed agent is covered before its first run. `check` must
/// not, or a machine that merely has `claude` on `PATH` and was never wired
/// reports broken forever. The config directory is the dividing line — argus
/// only ever writes inside one, and install creates it — so its presence means
/// "this host could have been wired", which is exactly the population a
/// monitor wants to alert on.
pub fn check(home: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in detect(home) {
        if !d.signals.contains(&Signal::ConfigDir) {
            continue;
        }
        let Some(h) = harness_by_id(d.id) else {
            continue;
        };
        let mut problems = Vec::new();
        for artifact in h.artifacts(&d, Scope::User) {
            if let Err(detail) = verify(&artifact) {
                problems.push(detail);
            }
        }
        for ks in h.kill_switches(&d) {
            problems.push(format!("{}: {}", ks.name, ks.detail));
        }
        out.push(Finding {
            tool: h.id().into(),
            ok: problems.is_empty(),
            detail: if problems.is_empty() {
                wired_detail(h, &d)
            } else {
                problems.join("; ")
            },
        });
    }
    out
}

fn wired_detail(h: &dyn Harness, d: &Detection) -> String {
    // Preserve the historical per-artifact wording so existing operator
    // tooling parsing these strings keeps working.
    match h.artifacts(d, Scope::User).first() {
        Some(Artifact::OwnedFile { .. }) => "present".into(),
        _ => "wired".into(),
    }
}

/// `Ok(())` when intact, `Err(detail)` describing the breakage otherwise.
///
/// Presence is not proof. A hook entry naming a binary that no longer exists,
/// a zero-byte plugin file, and a `notify` array left pointing at an old
/// install prefix all pass an existence test while capturing nothing — so
/// each artifact is checked down to something that has to be true for events
/// to actually arrive.
fn verify(artifact: &Artifact) -> std::result::Result<(), String> {
    match artifact {
        Artifact::JsonHooks {
            path,
            events,
            source,
            shape,
            pinned,
        } => {
            let Ok(text) = std::fs::read_to_string(path) else {
                return Err(format!("{} unreadable", path.display()));
            };
            let doc: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            // Ahead of the hooks, because it decides whether they mean
            // anything: a file whose every entry is intact and which also says
            // `disableAllHooks` is a host reporting "wired" while capturing
            // nothing.
            for (key, value) in pinned {
                let found = doc.get(*key).unwrap_or(&Value::Null);
                if found != value {
                    return Err(format!(
                        "{}: {key} is {found}, must be {value} — \
                         hooks do not run as written otherwise",
                        path.display()
                    ));
                }
            }
            let hooks = &doc["hooks"];
            // Every expected event must still carry an argus entry, so
            // stripping one event's wiring is caught, not just wiping the file.
            let mut missing: Vec<&str> = Vec::new();
            let mut altered: Vec<&str> = Vec::new();
            let mut commands: BTreeSet<&str> = BTreeSet::new();
            let cmd = hook_command(source, None, CmdStyle::Shell);
            for ev in *events {
                let ours: Vec<&Value> = hooks[ev.name]
                    .as_array()
                    .map(|a| a.iter().filter(|h| is_ours(h, source)).collect())
                    .unwrap_or_default();
                if ours.is_empty() {
                    missing.push(ev.name);
                    continue;
                }
                // Present is not the same as intact. Everything about the
                // entry past its existence decides whether the event is
                // captured the way this argus means it to be — the arguments
                // after the program name choose which adapter parses it, and
                // `timeout: 0` is a hook that is wired and never completes.
                // Neither shows up as a missing entry or an unresolvable
                // program, so without this both read as "wired".
                let want = hook_entry(*shape, &cmd, ev);
                if ours.len() != 1 || *ours[0] != want {
                    altered.push(ev.name);
                }
                for entry in ours {
                    for h in entry["hooks"].as_array().into_iter().flatten() {
                        if let Some(c) = h.get("command").and_then(Value::as_str) {
                            commands.insert(c);
                        }
                    }
                }
            }
            if !missing.is_empty() {
                return Err(format!("missing hooks: {}", missing.join(",")));
            }
            // Deduplicated: every event shares one command, so a moved binary
            // reports once rather than twenty times.
            for c in commands {
                check_command(c)?;
            }
            // Reported after the command check, which is the more actionable
            // of the two when both fire: a program that cannot run says which
            // path is wrong, where this only says the entry is not ours.
            if !altered.is_empty() {
                return Err(format!(
                    "hooks altered: {} — not what this argus writes; re-run `argus install` \
                     (Codex records trust against a hook's current hash, so a changed hook \
                     is skipped until re-trusted via `/hooks`)",
                    altered.join(",")
                ));
            }
            Ok(())
        }
        Artifact::OwnedFile {
            path,
            markers,
            commands,
            ..
        } => {
            if !path.exists() {
                return Err(format!("{} missing", path.display()));
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                return Err(format!("{} unreadable", path.display()));
            };
            if text.trim().is_empty() {
                return Err(format!("{} is empty", path.display()));
            }
            for m in markers {
                if !text.contains(m.as_str()) {
                    return Err(format!("{} no longer contains {m:?}", path.display()));
                }
            }
            for c in commands {
                check_command(c)?;
            }
            Ok(())
        }
        Artifact::TomlEdit { path, edits } => {
            if !path.exists() {
                return Err(format!("{} missing", path.display()));
            }
            let Ok(text) = std::fs::read_to_string(path) else {
                return Err(format!("{} unreadable", path.display()));
            };
            let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
                return Err(format!("{} is not valid TOML", path.display()));
            };
            for e in edits {
                let Some(item) = doc.get(e.key) else {
                    return Err(format!("{} missing from {}", e.key, path.display()));
                };
                match e.argv_tail {
                    // An argv array is checked element-wise: the trailing
                    // arguments must be exactly ours, and element 0 must still
                    // name a binary that can run.
                    Some(tail) => {
                        let Some(arr) = item.as_array() else {
                            return Err(format!("{} is no longer an argv array", e.key));
                        };
                        let got: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                        if got.len() != tail.len() + 1 || got[1..] != *tail {
                            return Err(format!("{} no longer invokes argus", e.key));
                        }
                        if resolve_program(got[0]).is_none() {
                            return Err(format!(
                                "{} points at a missing or non-executable binary: {}",
                                e.key, got[0]
                            ));
                        }
                    }
                    None => {
                        let s = item.to_string();
                        if e.must_carry.is_empty() {
                            if !e.ours_markers.iter().any(|m| s.contains(m.as_str())) {
                                return Err(format!("{} no longer points at argus", e.key));
                            }
                        } else if let Some(r) = e
                            .must_carry
                            .iter()
                            .find(|r| s.contains(r.needle.as_str()) != r.present)
                        {
                            let verb = if r.present {
                                "does not carry"
                            } else {
                                "still carries"
                            };
                            return Err(format!(
                                "{} {verb} {} — this tool is wired to a receiver that will not \
                                 accept it, so nothing it exports is being recorded. Re-run \
                                 `argus install`.",
                                e.key, r.what
                            ));
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

fn read_json_object(path: &Path) -> Value {
    let mut v: Value = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    if !v.is_object() {
        v = json!({});
    }
    v
}

/// `doc[key]`, coerced to an object, created if absent.
fn object_entry<'a>(doc: &'a mut Value, key: &str) -> &'a mut Value {
    let e = doc
        .as_object_mut()
        .unwrap()
        .entry(key.to_string())
        .or_insert_with(|| json!({}));
    if key == "hooks" && !e.is_object() {
        *e = json!({});
    }
    e
}

fn write_json(path: &Path, doc: &Value) -> Result<()> {
    write_atomic(path, serde_json::to_string_pretty(doc)?.as_bytes())
}

/// Replace a file's contents in one step, via a sibling temporary and a rename.
///
/// Every caller here is editing a file argus does not own — `settings.json`,
/// `config.toml`, the user's *agent's* configuration. `fs::write` truncates
/// first and writes second, so a full disk or a killed install between the two
/// leaves that file empty, and what breaks is the coding agent, not argus's
/// wiring to it. The rename gives the file no intermediate state: a reader
/// sees the old contents or the new ones.
///
/// The temporary is a sibling so the rename stays within one filesystem, and
/// the existing file's mode is carried over — several of these are `0600` and
/// silently widening them would be a worse bug than the one being fixed.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("argus-tmp");
    std::fs::write(&tmp, contents)?;
    #[cfg(unix)]
    if let Ok(md) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, md.permissions());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Dispatch a raw envelope to its harness adapter.
///
/// Every event coming out of here is stamped with the envelope's capture time
/// rather than the parse time. `Event::new` uses `Utc::now()`, which is when
/// the *daemon* got around to the payload — for anything that sat in the spool
/// while the daemon was down, or arrived during a burst, that is minutes or
/// hours after the tool actually did the thing. On a SIEM timeline the whole
/// backlog then lands in a single spike at drain time, and ordering within a
/// session is lost. Stamping here rather than in each adapter means no adapter
/// can forget to (telemetry-gaps #8).
pub fn parse(envelope: Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let received_at = envelope.received_at;
    let (truncated, dropped) = (envelope.truncated, envelope.dropped);
    let source = envelope.source.clone();
    let mut events = dispatch(envelope, capture);
    // Ahead of the events they qualify, not after them: a reader who sees a
    // tool call with no result should learn that the payload was cut, or that
    // the minutes before it are missing, before drawing the obvious wrong
    // conclusion from the absence. Both are attributed to the host tool rather
    // than to argus, since which agent produced an 8 MiB payload — or filled
    // the spool while the daemon was down — is the actionable half.
    if dropped > 0 {
        events.insert(
            0,
            Event::new(
                &source,
                None,
                None,
                crate::event::EventKind::Loss {
                    reason: "spool_full".into(),
                    count: dropped,
                    detail: "the hand-off spool hit spool.max_bytes while the daemon was \
                             unreachable; these are the oldest undelivered events, deleted \
                             to make room for this one"
                        .into(),
                },
            ),
        );
    }
    if truncated {
        events.insert(
            0,
            Event::new(
                &source,
                None,
                None,
                crate::event::EventKind::Loss {
                    reason: "stdin_truncated".into(),
                    count: 1,
                    detail: format!(
                        "hook payload exceeded the {} MiB stdin cap; the tail was discarded \
                         before parsing, so the event that follows is incomplete",
                        crate::hook::MAX_STDIN_BYTES / (1024 * 1024)
                    ),
                },
            ),
        );
    }
    for e in &mut events {
        e.ts = received_at;
    }
    events
}

fn dispatch(envelope: Envelope, capture: &CaptureCfg) -> Vec<Event> {
    for h in HARNESSES {
        if h.id() == envelope.source {
            return h.parse(&envelope, capture);
        }
    }
    vec![Event::new(
        &envelope.source,
        None,
        None,
        crate::event::EventKind::Raw {
            payload: envelope.payload,
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These files belong to the user's coding agent, not to argus. A
    /// truncate-then-write leaves a window where `settings.json` is empty, and
    /// a crash or a full disk inside it breaks the agent rather than argus.
    ///
    /// Asserted through a hard link, which is the only way to observe the
    /// difference from outside: after an in-place write the link sees the new
    /// bytes, because it is the same inode being rewritten. After a rename it
    /// still sees the old ones, which is exactly the property that says the
    /// original was never opened for truncation.
    #[cfg(unix)]
    #[test]
    fn a_config_file_is_replaced_whole_never_truncated_in_place() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{\"theirs\": true}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let witness = dir.path().join("witness");
        std::fs::hard_link(&path, &witness).unwrap();

        write_atomic(&path, b"{\"ours\": true}").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ours\": true}");
        assert_eq!(
            std::fs::read(&witness).unwrap(),
            b"{\"theirs\": true}",
            "the original file was written through, so there was a moment when it \
             held neither the old contents nor the new"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "replacing the file widened its mode"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary left behind: {leftovers:?}");
    }

    /// A harness that exists only to be driven through the managed layer.
    ///
    /// `escape` reproduces the exact bug the layer is built to survive: a
    /// harness that grows a [`ManagedDir`] but never learns to branch on
    /// `Scope::Managed`, so it answers with the *user* path it always returned
    /// — which under `sudo` is a path in root's home.
    struct ManagedStub {
        dir: &'static [ManagedDir],
        escape: Option<PathBuf>,
    }

    impl Harness for ManagedStub {
        fn id(&self) -> &'static str {
            "stub"
        }
        fn display_name(&self) -> &'static str {
            "Stub"
        }
        fn probes(&self) -> Probes {
            Probes {
                config_dirs: &[],
                binaries: &[],
                npm_packages: &[],
                brew_formulae: &[],
            }
        }
        fn managed_dirs(&self) -> &'static [ManagedDir] {
            self.dir
        }
        fn artifacts(&self, d: &Detection, _scope: Scope) -> Vec<Artifact> {
            let path = self
                .escape
                .clone()
                .unwrap_or_else(|| d.config_home.join("settings.json"));
            vec![Artifact::JsonHooks {
                path,
                events: STUB_EVENTS,
                shape: HookShape::CommandArray,
                source: "stub",
                pinned: Vec::new(),
            }]
        }
        fn parse(&self, _env: &Envelope, _cfg: &CaptureCfg) -> Vec<Event> {
            Vec::new()
        }
    }

    const STUB_EVENTS: &[HookEvent] = &[HookEvent::new("SessionStart", false)];

    /// Only on Linux, so the platform filter has something to get wrong.
    const LINUX_ONLY: &[ManagedDir] = &[ManagedDir {
        rel: "etc/stub",
        platform: Platform::Linux,
    }];

    /// The full operator cycle against a fake system root, on the one platform
    /// the stub claims — and the silence owed to the two it does not.
    ///
    /// The last leg is the property `check --managed` is bought for: unlike a
    /// repository, where nothing wired is nothing to say, a *removed* managed
    /// file is a finding. Someone who deletes it is who this is looking for.
    #[test]
    fn a_managed_layer_installs_checks_and_uninstalls_under_the_system_root() {
        let root = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let exe = fake_binary(bin.path(), "argus");
        unsafe { std::env::set_var(BIN_ENV, &exe) };
        let stub = ManagedStub {
            dir: LINUX_ONLY,
            escape: None,
        };
        let hs: &[&dyn Harness] = &[&stub];
        let settings = root.path().join("etc/stub/settings.json");

        install_managed_in(hs, root.path(), Platform::Linux, false).unwrap();
        assert!(settings.exists(), "managed settings not written");
        let checked = check_managed_in(hs, root.path(), Platform::Linux);
        assert_eq!(checked.len(), 1);
        assert!(checked[0].ok, "freshly installed: {:?}", checked[0]);

        // A platform the harness declares nothing for is not "broken", it is
        // absent — and must not have been written either.
        for p in [Platform::MacOS, Platform::Windows] {
            assert!(
                check_managed_in(hs, root.path(), p).is_empty(),
                "{p:?} reported a layer the stub never declared"
            );
            install_managed_in(hs, root.path(), p, false).unwrap();
        }
        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            1,
            "a platform with no managed dir still wrote something"
        );

        std::fs::remove_file(&settings).unwrap();
        let after = check_managed_in(hs, root.path(), Platform::Linux);
        assert_eq!(after.len(), 1);
        assert!(!after[0].ok, "a removed managed file must be BROKEN");

        install_managed_in(hs, root.path(), Platform::Linux, false).unwrap();
        uninstall_managed_in(hs, root.path(), Platform::Linux).unwrap();
        let text = std::fs::read_to_string(&settings).unwrap();
        assert!(
            !text.contains("argus"),
            "uninstall left our wiring behind: {text}"
        );
        unsafe { std::env::remove_var(BIN_ENV) };
    }

    /// The one that matters under `sudo`: a harness answering with a path in
    /// the invoking user's home is refused, not written. Without this, `sudo
    /// argus install --managed` wires `/root` and monitors nobody.
    #[test]
    fn a_managed_install_refuses_to_write_outside_the_system_root() {
        let root = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let escape = home.path().join(".claude/settings.json");
        let stub = ManagedStub {
            dir: LINUX_ONLY,
            escape: Some(escape.clone()),
        };
        let hs: &[&dyn Harness] = &[&stub];

        let err = install_managed_in(hs, root.path(), Platform::Linux, false)
            .expect_err("wrote a user-scope path under --managed");
        assert!(err.to_string().contains("outside the machine-wide layer"));
        assert!(!escape.exists(), "refused, yet the file was written anyway");

        // Uninstall is refused on the same grounds, and for a sharper reason:
        // reverting deletes, so obeying would remove a file argus never wrote.
        std::fs::create_dir_all(escape.parent().unwrap()).unwrap();
        std::fs::write(&escape, "{\"hooks\":{}}").unwrap();
        uninstall_managed_in(hs, root.path(), Platform::Linux)
            .expect_err("reverted a user-scope path under --managed");
        assert!(escape.exists());

        let reported = check_managed_in(hs, root.path(), Platform::Linux);
        assert_eq!(reported.len(), 1);
        assert!(!reported[0].ok);
        assert!(
            reported[0]
                .detail
                .contains("outside the machine-wide layer")
        );
    }

    /// Every harness argus actually ships, swept across every platform: nothing
    /// it declares for the managed layer may resolve outside the system root.
    /// Vacuous until a harness declares its first [`ManagedDir`], which is
    /// precisely when it starts earning its place.
    #[test]
    fn no_shipped_harness_can_place_a_managed_artifact_outside_the_root() {
        let root = tempfile::tempdir().unwrap();
        for p in Platform::ALL {
            for h in HARNESSES {
                let Some(d) = managed_detection(*h, root.path(), *p) else {
                    continue;
                };
                for a in h.artifacts(&d, Scope::Managed(*p)) {
                    assert!(
                        escapes_managed_root(root.path(), &a).is_none(),
                        "{} on {p:?} escapes: {}",
                        h.id(),
                        artifact_path(&a).display()
                    );
                }
            }
        }
    }

    /// The override redirects a write and says so. `real` is what gates the
    /// privilege demand, so a test root must never look like the real machine
    /// — and the real machine must never look like a test root.
    #[test]
    fn the_system_root_override_is_marked_as_not_the_real_machine() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var(SYSTEM_ROOT_ENV, dir.path()) };
        let r = system_root(Platform::Linux);
        assert_eq!(r.path, dir.path());
        assert!(!r.real);

        unsafe { std::env::remove_var(SYSTEM_ROOT_ENV) };
        assert!(system_root(Platform::Linux).real);
        assert_eq!(system_root(Platform::Linux).path, PathBuf::from("/"));
        assert_eq!(system_root(Platform::Windows).path, PathBuf::from("C:\\"));
    }

    /// Claude Code's real managed layer, driven end to end against a fake
    /// system root on each of the three platforms it documents one for.
    ///
    /// The paths are the shipped binary's own, so this is also the test that
    /// notices if one is ever mistyped: a `managed-settings.json` written a
    /// directory off is a file Claude Code never reads.
    #[test]
    fn claude_codes_managed_layer_round_trips_on_every_platform() {
        let bin = tempfile::tempdir().unwrap();
        let exe = fake_binary(bin.path(), "argus");
        unsafe { std::env::set_var(BIN_ENV, &exe) };
        let hs: &[&dyn Harness] = &[&crate::harness::claude_code::ClaudeCode];

        for (p, rel) in [
            (Platform::MacOS, "Library/Application Support/ClaudeCode"),
            (Platform::Linux, "etc/claude-code"),
            (Platform::Windows, "Program Files/ClaudeCode"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let file = root.path().join(rel).join("managed-settings.json");

            install_managed_in(hs, root.path(), p, false).unwrap();
            assert!(file.exists(), "{p:?}: nothing at {}", file.display());
            let doc: Value =
                serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(doc["disableAllHooks"], json!(false), "{p:?}");
            assert_eq!(doc["allowManagedHooksOnly"], json!(true), "{p:?}");
            assert!(doc["hooks"]["SessionStart"].is_array(), "{p:?}");

            let checked = check_managed_in(hs, root.path(), p);
            assert_eq!(checked.len(), 1);
            assert!(checked[0].ok, "{p:?}: {:?}", checked[0]);
            assert_eq!(checked[0].tool, "claude-code (managed)");

            // The user layer must stay where it always was: a managed install
            // writes `managed-settings.json` and nothing beside it.
            assert!(
                !root.path().join(rel).join("settings.json").exists(),
                "{p:?}: a managed install wrote the user file too"
            );

            uninstall_managed_in(hs, root.path(), p).unwrap();
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(!text.contains("argus"), "{p:?}: wiring left behind: {text}");
            assert!(
                !text.contains("allowManagedHooksOnly"),
                "{p:?}: enforcement left behind: {text}"
            );
        }
        unsafe { std::env::remove_var(BIN_ENV) };
    }

    /// The plan's own bar for `check --managed`: a flipped enforcement key is a
    /// finding, not a shrug. Every entry can be byte-perfect and the file still
    /// capture nothing, so this is checked ahead of the hooks and reported with
    /// the value that is wrong.
    #[test]
    fn a_flipped_enforcement_key_makes_a_wired_managed_file_broken() {
        let bin = tempfile::tempdir().unwrap();
        let exe = fake_binary(bin.path(), "argus");
        unsafe { std::env::set_var(BIN_ENV, &exe) };
        let hs: &[&dyn Harness] = &[&crate::harness::claude_code::ClaudeCode];
        let root = tempfile::tempdir().unwrap();
        let file = root
            .path()
            .join("etc/claude-code")
            .join("managed-settings.json");
        install_managed_in(hs, root.path(), Platform::Linux, false).unwrap();

        // Each of the three ways the pin stops holding: turned off, turned on,
        // and quietly deleted — the last being what a hand-edit looks like.
        for (key, bad) in [
            ("disableAllHooks", Some(json!(true))),
            ("allowManagedHooksOnly", Some(json!(false))),
            ("disableAllHooks", None),
        ] {
            let mut doc: Value =
                serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
            let obj = doc.as_object_mut().unwrap();
            match &bad {
                Some(v) => {
                    obj.insert(key.into(), v.clone());
                }
                None => {
                    obj.remove(key);
                }
            }
            std::fs::write(&file, doc.to_string()).unwrap();

            let f = check_managed_in(hs, root.path(), Platform::Linux);
            assert_eq!(f.len(), 1);
            assert!(!f[0].ok, "{key}={bad:?} was accepted as healthy");
            assert!(
                f[0].detail.contains(key) && f[0].detail.contains("must be"),
                "{key}={bad:?}: unhelpful detail {:?}",
                f[0].detail
            );
            // Re-running the install is the documented repair.
            install_managed_in(hs, root.path(), Platform::Linux, false).unwrap();
            assert!(check_managed_in(hs, root.path(), Platform::Linux)[0].ok);
        }
        unsafe { std::env::remove_var(BIN_ENV) };
    }

    /// Codex's machine-wide layer, whose shape differs from Claude Code's in
    /// every way that matters: three files rather than one, the enforcement in
    /// a *different* file from the hooks it enforces, and one setting spelled
    /// differently on Windows.
    ///
    /// The ordering assertion is the substantive one. `allow_managed_hooks_only`
    /// tells Codex to run managed hooks and nothing else, so a run that set it
    /// before writing `hooks.json` would leave the machine executing no hooks
    /// at all — the window being a whole install, not an instant.
    #[test]
    fn codexs_managed_layer_round_trips_on_every_platform() {
        let bin = tempfile::tempdir().unwrap();
        let exe = fake_binary(bin.path(), "argus");
        unsafe { std::env::set_var(BIN_ENV, &exe) };
        let hs: &[&dyn Harness] = &[&crate::harness::codex::Codex];

        for (p, rel, key) in [
            (Platform::MacOS, "etc/codex", "managed_dir"),
            (Platform::Linux, "etc/codex", "managed_dir"),
            (
                Platform::Windows,
                "ProgramData/OpenAI/Codex",
                "windows_managed_dir",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let base = root.path().join(rel);
            let hooks = base.join("hooks/hooks.json");
            let config = base.join("config.toml");
            let requirements = base.join("requirements.toml");

            // The hooks must exist before anything says "managed hooks only".
            let order: Vec<PathBuf> = {
                let d = managed_detection(hs[0], root.path(), p).unwrap();
                hs[0]
                    .artifacts(&d, Scope::Managed(p))
                    .iter()
                    .map(|a| artifact_path(a).to_path_buf())
                    .collect()
            };
            assert_eq!(order[0], hooks, "{p:?}: hooks are not written first");
            assert_eq!(order.last().unwrap(), &requirements, "{p:?}");

            install_managed_in(hs, root.path(), p, false).unwrap();
            let cfg = std::fs::read_to_string(&config).unwrap();
            assert!(cfg.contains(key), "{p:?}: {key} missing from {cfg}");
            assert!(
                !cfg.contains(if key == "managed_dir" {
                    "windows_managed_dir"
                } else {
                    "\nmanaged_dir"
                }),
                "{p:?}: both spellings written, which Codex reports as a conflict: {cfg}"
            );
            let req = std::fs::read_to_string(&requirements).unwrap();
            assert!(req.contains("allow_managed_hooks_only"), "{p:?}: {req}");
            // The per-user receiver token has no business in a machine-wide
            // file, and neither does wiring that can only be right for one
            // account.
            assert!(!cfg.contains("otel") && !cfg.contains("notify"), "{p:?}");
            assert!(hooks.exists(), "{p:?}: no hooks at {}", hooks.display());

            let checked = check_managed_in(hs, root.path(), p);
            assert_eq!(checked.len(), 1);
            assert!(checked[0].ok, "{p:?}: {:?}", checked[0]);

            // Each file on its own is enough to break the layer, and each has
            // to say so — the hooks are useless unpointed-at, and the pointer
            // is useless with nothing to point at.
            for victim in [&hooks, &config, &requirements] {
                let saved = std::fs::read_to_string(victim).unwrap();
                std::fs::remove_file(victim).unwrap();
                let f = check_managed_in(hs, root.path(), p);
                assert!(
                    !f[0].ok,
                    "{p:?}: removing {} was accepted",
                    victim.display()
                );
                std::fs::write(victim, saved).unwrap();
            }
            assert!(check_managed_in(hs, root.path(), p)[0].ok, "{p:?}");

            // Flipping the enforcement flag leaves every file in place and
            // every hook entry intact, and still has to read as broken.
            std::fs::write(&requirements, "allow_managed_hooks_only = false\n").unwrap();
            assert!(!check_managed_in(hs, root.path(), p)[0].ok, "{p:?}");
            // Re-running the install is the repair, as it is for Claude Code's
            // pinned settings.
            install_managed_in(hs, root.path(), p, false).unwrap();
            assert!(check_managed_in(hs, root.path(), p)[0].ok, "{p:?}");

            // An administrator's own managed hooks directory is their content,
            // not argus's to overwrite: it survives, and is reported instead.
            std::fs::write(&config, format!("[hooks]\n{key} = \"/opt/theirs\"\n")).unwrap();
            install_managed_in(hs, root.path(), p, false).unwrap();
            let cfg = std::fs::read_to_string(&config).unwrap();
            assert!(
                cfg.contains("/opt/theirs"),
                "{p:?}: clobbered their hooks: {cfg}"
            );
            assert!(!check_managed_in(hs, root.path(), p)[0].ok, "{p:?}: {cfg}");
            std::fs::remove_file(&config).unwrap();
            install_managed_in(hs, root.path(), p, false).unwrap();

            uninstall_managed_in(hs, root.path(), p).unwrap();
            assert!(
                !std::fs::read_to_string(&config).unwrap().contains(key),
                "{p:?}: the managed pointer outlived the hooks it pointed at"
            );
            assert!(
                !std::fs::read_to_string(&requirements)
                    .unwrap()
                    .contains("allow_managed_hooks_only"),
                "{p:?}: left Codex running managed hooks only, with none left"
            );
        }
        unsafe { std::env::remove_var(BIN_ENV) };
    }

    /// Pinned settings are a machine-wide instrument and nothing else. The
    /// same two keys written into a file the *user* owns would turn off the
    /// user's own hooks in their own config — argus quietly seizing a policy
    /// decision that was never its to make. Swept over every shipped harness
    /// so a new one cannot introduce it either.
    #[test]
    fn only_the_machine_wide_scope_pins_settings() {
        let dir = tempfile::tempdir().unwrap();
        let d = Detection {
            id: "x",
            signals: Vec::new(),
            config_home: dir.path().into(),
            binary: None,
        };
        for h in HARNESSES {
            for scope in [Scope::User, Scope::Project] {
                for a in h.artifacts(&d, scope) {
                    if let Artifact::JsonHooks { path, pinned, .. } = a {
                        assert!(
                            pinned.is_empty(),
                            "{} pins {:?} at {scope:?} in {}",
                            h.id(),
                            pinned,
                            path.display()
                        );
                    }
                }
            }
        }
    }

    /// Uninstalling argus is not a licence to rewrite an administrator's
    /// policy. A pinned key they have since changed is theirs, and survives.
    #[test]
    fn uninstall_leaves_a_pinned_value_an_administrator_has_taken_over() {
        let bin = tempfile::tempdir().unwrap();
        let exe = fake_binary(bin.path(), "argus");
        unsafe { std::env::set_var(BIN_ENV, &exe) };
        let hs: &[&dyn Harness] = &[&crate::harness::claude_code::ClaudeCode];
        let root = tempfile::tempdir().unwrap();
        let file = root
            .path()
            .join("etc/claude-code")
            .join("managed-settings.json");
        install_managed_in(hs, root.path(), Platform::Linux, false).unwrap();

        let mut doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        doc["disableAllHooks"] = json!(true);
        std::fs::write(&file, doc.to_string()).unwrap();

        uninstall_managed_in(hs, root.path(), Platform::Linux).unwrap();
        let after: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(
            after["disableAllHooks"],
            json!(true),
            "took back a setting argus no longer owned"
        );
        assert!(
            after.get("allowManagedHooksOnly").is_none(),
            "left behind a pin that was still ours: {after}"
        );
        unsafe { std::env::remove_var(BIN_ENV) };
    }

    /// A truncated payload still parses — it is the *tail* that is missing, so
    /// the leading fields an adapter reads are usually intact and the event
    /// looks perfectly ordinary. That is exactly why the caveat has to be
    /// emitted alongside it rather than inferred from a parse failure.
    #[test]
    fn a_truncated_payload_announces_itself_ahead_of_the_event_it_spoils() {
        let mut env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: true,
            dropped: 0,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "UserPromptSubmit",
                "session_id": "s1",
                "prompt": "hi",
            }),
        };
        let events = parse(env.clone(), &CaptureCfg::default());
        let crate::event::EventKind::Loss {
            reason,
            count,
            detail,
        } = &events[0].kind
        else {
            panic!("a cut-off payload reached the collector with nothing said about it");
        };
        assert_eq!(reason, "stdin_truncated");
        assert_eq!(*count, 1);
        assert!(detail.contains('8'), "the cap belongs in the message");
        assert_eq!(
            events[0].source, "claude-code",
            "attributed to the tool that produced the oversized payload"
        );
        assert!(
            events.len() > 1,
            "the event itself must still be delivered, incomplete or not"
        );

        env.truncated = false;
        assert!(
            !parse(env, &CaptureCfg::default())
                .iter()
                .any(|e| matches!(e.kind, crate::event::EventKind::Loss { .. })),
            "an intact payload must not claim a gap"
        );
    }

    /// The shim deletes the files; only the daemon can say so. The count is
    /// carried on the envelope precisely because it is the one thing crossing
    /// between them, and it is worth nothing until it becomes an event.
    #[test]
    fn a_spool_trim_becomes_a_gap_the_collector_can_see() {
        let mut env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 7,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "UserPromptSubmit",
                "session_id": "s1",
                "prompt": "hi",
            }),
        };
        let events = parse(env.clone(), &CaptureCfg::default());
        let crate::event::EventKind::Loss { reason, count, .. } = &events[0].kind else {
            panic!("seven events were deleted and nothing downstream was told");
        };
        assert_eq!(reason, "spool_full");
        assert_eq!(*count, 7);
        assert_eq!(events[0].source, "claude-code");
        assert!(events.len() > 1, "the envelope's own event still counts");

        env.dropped = 0;
        assert!(
            !parse(env, &CaptureCfg::default())
                .iter()
                .any(|e| matches!(e.kind, crate::event::EventKind::Loss { .. })),
            "a spool with room must not claim a gap"
        );
    }

    /// Two independent gaps on one envelope are two independent findings; the
    /// truncation qualifies the event that follows it, so it leads.
    #[test]
    fn a_cut_payload_that_also_trimmed_the_spool_reports_both() {
        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: true,
            dropped: 3,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "UserPromptSubmit",
                "session_id": "s1",
                "prompt": "hi",
            }),
        };
        let events = parse(env, &CaptureCfg::default());
        let reasons: Vec<&str> = events
            .iter()
            .filter_map(|e| match &e.kind {
                crate::event::EventKind::Loss { reason, .. } => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(reasons, ["stdin_truncated", "spool_full"]);
    }

    #[test]
    fn powershell_uses_call_operator_and_quotes() {
        let cmd = hook_command_for(
            r"C:\Program Files\argus\argus.exe",
            "copilot",
            Some("preToolUse"),
            CmdStyle::PowerShell,
        );
        assert_eq!(
            cmd,
            r#"& "C:\Program Files\argus\argus.exe" hook --source copilot --event preToolUse"#
        );
    }

    #[test]
    fn unix_shell_quotes_only_when_needed() {
        assert_eq!(
            quote_program("/usr/local/bin/argus", CmdStyle::Shell),
            "/usr/local/bin/argus",
            "a plain path stays readable"
        );
        assert_eq!(
            quote_program("/opt/my apps/argus", CmdStyle::Shell),
            "'/opt/my apps/argus'"
        );
        assert_eq!(
            quote_program("/opt/it's/argus", CmdStyle::Shell),
            r"'/opt/it'\''s/argus'"
        );
        // Asserted on every host, not just Unix ones: the quoting belongs to
        // the shell that will run the command, and installing from Windows does
        // not change which shell that is.
        assert_eq!(
            quote_program(r"C:\Program Files\argus\argus.exe", CmdStyle::Shell),
            r"'C:\Program Files\argus\argus.exe'"
        );
    }

    /// The bug: `format!("{} hook …", exe)` on a path with a space produced a
    /// command the shell split into two words, so the hook silently no-op'd.
    #[cfg(unix)]
    #[test]
    fn quoted_command_round_trips_through_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let spaced = dir.path().join("my apps");
        std::fs::create_dir_all(&spaced).unwrap();
        let exe = spaced.join("argus");
        std::fs::write(&exe, "#!/bin/sh\necho ARGUS_RAN \"$@\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cmd = hook_command_for(&exe.to_string_lossy(), "claude-code", None, CmdStyle::Shell);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("ARGUS_RAN hook --source claude-code"),
            "command {cmd:?} did not execute; stdout={stdout:?} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn ownership_is_structural_not_a_path_substring() {
        let ours = json!({ "hooks": [{ "command": "/opt/tool hook" }], MARKER_KEY: true });
        assert!(
            is_ours(&ours, "claude-code"),
            "structured marker identifies our entry regardless of path"
        );

        let legacy =
            json!({ "hooks": [{ "command": "/usr/bin/argus hook --source claude-code" }] });
        assert!(
            is_ours(&legacy, "claude-code"),
            "unmarked entry from an older install is still cleaned up"
        );
        assert!(
            !is_ours(&legacy, "codex"),
            "another harness must not claim it"
        );

        // The bug the marker exists to fix: a user's own hook script that
        // merely lives under a path containing "argus".
        let users_own = json!({ "hooks": [{ "command": "/home/u/src/argus/scripts/mine.sh" }] });
        assert!(!is_ours(&users_own, "claude-code"));
    }

    // -----------------------------------------------------------------
    // T3 — `check` proves capture can actually happen
    // -----------------------------------------------------------------

    fn fake_binary(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    /// `check` reads the command as recorded on disk, so it must be able to
    /// recover the program from every form we ever wrote.
    #[test]
    fn program_of_inverts_quoting() {
        for exe in [
            "/usr/local/bin/argus",
            "/opt/my apps/argus",
            "/opt/it's/argus",
            r"C:\Program Files\argus\argus.exe",
        ] {
            for style in [CmdStyle::Shell, CmdStyle::PowerShell] {
                let cmd = hook_command_for(exe, "codex", Some("Stop"), style);
                assert_eq!(
                    program_of(&cmd).as_deref(),
                    Some(exe),
                    "{style:?} did not round-trip: {cmd}"
                );
            }
        }
        assert_eq!(
            program_of("/usr/bin/argus hook --source codex").as_deref(),
            Some("/usr/bin/argus"),
            "the unquoted form older installs wrote"
        );
    }

    /// The upgrade failure this exists to prevent: `current_exe()` reports the
    /// symlink *target* (`…/Cellar/argus/0.2.0/bin/argus`), a path the next
    /// `brew upgrade` deletes. The alias on PATH keeps working.
    #[cfg(unix)]
    #[test]
    fn stable_alias_prefers_the_path_entry_over_the_resolved_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let cellar = dir.path().join("Cellar/argus/0.2.0/bin");
        std::fs::create_dir_all(&cellar).unwrap();
        let real = fake_binary(&cellar, "argus");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let link = bin.join("argus");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let path_var = std::env::join_paths([&bin]).unwrap();
        assert_eq!(stable_alias(&real, &path_var), Some(link));

        // An unrelated binary of the same name must never be adopted — that
        // would silently retarget a dev build at the packaged install.
        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        fake_binary(&other, "argus");
        let path_var = std::env::join_paths([&other]).unwrap();
        assert_eq!(stable_alias(&real, &path_var), None);
    }

    /// A hook entry can be perfectly formed and still capture nothing.
    #[test]
    fn verify_flags_a_hook_whose_binary_cannot_run() {
        const EVENTS: &[HookEvent] = &[HookEvent::new("Stop", false)];
        let dir = tempfile::tempdir().unwrap();
        let exe = fake_binary(dir.path(), "argus");
        // `verify` now compares the entry against the one install would write,
        // so the command has to come from the same place install gets it —
        // a hand-typed equivalent would read as altered and mask the failure
        // this test is about.
        unsafe {
            std::env::set_var(BIN_ENV, &exe);
        }
        let settings = dir.path().join("settings.json");
        let cmd = hook_command("claude-code", None, CmdStyle::Shell);
        std::fs::write(
            &settings,
            json!({
                "hooks": { "Stop": [hook_entry(HookShape::CommandArray, &cmd, &EVENTS[0])] }
            })
            .to_string(),
        )
        .unwrap();
        let artifact = Artifact::JsonHooks {
            path: settings,
            events: EVENTS,
            shape: HookShape::CommandArray,
            source: "claude-code",
            pinned: Vec::new(),
        };
        assert_eq!(verify(&artifact), Ok(()), "healthy wiring must verify");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = verify(&artifact).unwrap_err();
            assert!(err.contains("missing or non-executable"), "{err}");
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(verify(&artifact), Ok(()));
        }

        std::fs::remove_file(&exe).unwrap();
        let err = verify(&artifact).unwrap_err();
        assert!(err.contains("missing or non-executable"), "{err}");
    }

    #[test]
    fn verify_flags_an_owned_file_that_is_empty_or_edited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("argus.json");
        let artifact = Artifact::OwnedFile {
            path: path.clone(),
            contents: Cow::Borrowed(""),
            markers: vec!["--event preToolUse".into()],
            commands: Vec::new(),
        };

        std::fs::write(&path, "argus hook --source copilot --event preToolUse\n").unwrap();
        assert_eq!(verify(&artifact), Ok(()));

        // The bug: `path.exists()` passes on all three of these.
        std::fs::write(&path, "").unwrap();
        assert!(verify(&artifact).unwrap_err().contains("is empty"));
        std::fs::write(&path, "   \n\n").unwrap();
        assert!(verify(&artifact).unwrap_err().contains("is empty"));
        std::fs::write(&path, "{}\n").unwrap();
        assert!(
            verify(&artifact)
                .unwrap_err()
                .contains("no longer contains")
        );

        std::fs::remove_file(&path).unwrap();
        assert!(verify(&artifact).unwrap_err().contains("missing"));
    }

    #[test]
    fn verify_flags_codex_toml_edits_that_stopped_pointing_at_argus() {
        const TAIL: &[&str] = &["hook", "--source", "codex"];
        let dir = tempfile::tempdir().unwrap();
        let exe = fake_binary(dir.path(), "argus");
        let path = dir.path().join("config.toml");
        let artifact = Artifact::TomlEdit {
            path: path.clone(),
            edits: vec![
                TomlEditOp {
                    key: "notify",
                    // `value` is install-only; verification reads what is on disk.
                    value: toml_edit::Item::None,
                    only_if_absent: true,
                    ours_markers: vec!["argus".into()],
                    must_carry: vec![],
                    argv_tail: Some(TAIL),
                },
                TomlEditOp {
                    key: "otel",
                    value: toml_edit::Item::None,
                    only_if_absent: true,
                    ours_markers: vec!["127.0.0.1".into()],
                    must_carry: vec![],
                    argv_tail: None,
                },
            ],
        };
        // TOML literal strings, so a Windows path's backslashes stay literal.
        let healthy = format!(
            "notify = ['{}', 'hook', '--source', 'codex']\n\
             [otel]\nexporter = {{ otlp-http = {{ endpoint = 'http://127.0.0.1:4327' }} }}\n",
            exe.display()
        );
        std::fs::write(&path, &healthy).unwrap();
        assert_eq!(verify(&artifact), Ok(()), "healthy config must verify");

        // Previously a TomlEdit was never checked, so every one of these
        // passed and a half-installed Codex looked healthy forever.
        let mut doc: toml_edit::DocumentMut = healthy.parse().unwrap();
        doc.remove("otel");
        std::fs::write(&path, doc.to_string()).unwrap();
        assert!(verify(&artifact).unwrap_err().contains("otel missing from"));

        std::fs::write(
            &path,
            healthy.replace("'hook', '--source', 'codex'", "'--version'"),
        )
        .unwrap();
        assert!(
            verify(&artifact)
                .unwrap_err()
                .contains("notify no longer invokes argus")
        );

        std::fs::write(&path, &healthy).unwrap();
        std::fs::remove_file(&exe).unwrap();
        let err = verify(&artifact).unwrap_err();
        assert!(err.contains("notify points at a missing"), "{err}");
    }

    /// A Codex wired by an older argus points at the fixed port that the
    /// per-install one replaced. It is still recognisably ours — `uninstall`
    /// must keep removing it — but nothing listens there any more, so `check`
    /// reporting it as wired would be the same silent capture stop the whole
    /// integrity check exists to catch.
    #[test]
    fn verify_rejects_a_codex_wired_to_an_endpoint_nothing_listens_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let artifact = Artifact::TomlEdit {
            path: path.clone(),
            edits: vec![TomlEditOp {
                key: "otel",
                value: toml_edit::Item::None,
                only_if_absent: true,
                // Deliberately still a marker, as it is in the real harness.
                ours_markers: vec!["http://127.0.0.1:4327".into()],
                must_carry: vec![Required {
                    what: "the endpoint http://127.0.0.1:41234".into(),
                    needle: "http://127.0.0.1:41234".into(),
                    present: true,
                }],
                argv_tail: None,
            }],
        };

        let stale = "[otel]\nexporter = { otlp-http = { endpoint = 'http://127.0.0.1:4327' } }\n";
        std::fs::write(&path, stale).unwrap();
        let err = verify(&artifact).unwrap_err();
        assert!(
            err.contains("http://127.0.0.1:41234") && err.contains("argus install"),
            "the error must name the endpoint we listen on and how to fix it: {err}"
        );

        let current = stale.replace("4327", "41234");
        std::fs::write(&path, &current).unwrap();
        assert_eq!(verify(&artifact), Ok(()), "current endpoint must verify");
    }

    /// The receiver refuses a token it did not mint, so a Codex still carrying
    /// an older install's is exporting into `401`s — the same silent capture
    /// stop as a stale endpoint, and one a restored home directory produces
    /// without anybody doing anything wrong.
    ///
    /// The error must not print the token. `check` exists to be run by MDM
    /// compliance scripts and monitoring agents, whose output is collected,
    /// indexed and readable by far more people than the account that owns it.
    #[test]
    fn verify_rejects_a_codex_carrying_a_token_the_receiver_will_not_accept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let ours = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let artifact = |required| Artifact::TomlEdit {
            path: path.clone(),
            edits: vec![TomlEditOp {
                key: "otel",
                value: toml_edit::Item::None,
                only_if_absent: true,
                ours_markers: vec!["http://127.0.0.1:41234".into()],
                must_carry: required,
                argv_tail: None,
            }],
        };
        let config = |token: &str| {
            format!(
                "[otel]\nexporter = {{ otlp-http = {{ endpoint = \
                 'http://127.0.0.1:41234', headers = {{ authorization = 'Bearer {token}' }} }} }}\n"
            )
        };
        let current = vec![Required {
            what: "the receiver token from this install".into(),
            needle: format!("Bearer {ours}"),
            present: true,
        }];

        std::fs::write(&path, config("f".repeat(64).as_str())).unwrap();
        let err = verify(&artifact(current)).unwrap_err();
        assert!(
            err.contains("does not carry") && err.contains("argus install"),
            "the error must say what is wrong and how to fix it: {err}"
        );
        assert!(
            !err.contains(ours) && !err.contains(&"f".repeat(64)),
            "check output is collected and indexed; it must not print a bearer \
             token, ours or theirs: {err}"
        );

        let current = vec![Required {
            what: "the receiver token from this install".into(),
            needle: format!("Bearer {ours}"),
            present: true,
        }];
        std::fs::write(&path, config(ours)).unwrap();
        assert_eq!(verify(&artifact(current)), Ok(()));

        // No token on disk: the current one is unknowable, but the next daemon
        // start will mint a replacement, so any credential here is already dead.
        let none_known = vec![Required {
            what: "a receiver token this install does not know".into(),
            needle: "Bearer ".into(),
            present: false,
        }];
        let err = verify(&artifact(none_known)).unwrap_err();
        assert!(err.contains("still carries"), "{err}");
        assert!(!err.contains(ours), "{err}");
    }

    /// The stale-endpoint check above only proves the *mechanism* works; it
    /// says nothing about any harness switching it on. An edit that points a
    /// tool at this install's receiver and settles for `ours_markers` verifies
    /// happily against an endpoint from an older argus that nothing listens on
    /// any more — the exact failure `must_carry` exists to catch, and one that
    /// is silent, because `check` reports the wiring as intact.
    #[test]
    fn an_edit_naming_our_receiver_demands_that_exact_receiver() {
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", home.path().join("data"));
        }
        let endpoint = format!("http://{}", crate::config::load().codex.otlp_listen);
        let mut checked = 0usize;
        for h in HARNESSES {
            let d = Detection {
                id: h.id(),
                signals: vec![Signal::ConfigDir],
                config_home: home.path().join(h.id()),
                binary: None,
            };
            for a in h.artifacts(&d, Scope::User) {
                let Artifact::TomlEdit { path, edits } = a else {
                    continue;
                };
                for e in edits {
                    if !e.value.to_string().contains(&endpoint) {
                        continue;
                    }
                    checked += 1;
                    assert!(
                        e.must_carry
                            .iter()
                            .any(|r| r.present && r.needle == endpoint),
                        "{}: {} writes our endpoint but `check` would accept any \
                         marker match, so a config left pointing at a receiver \
                         from an older install passes as healthy",
                        path.display(),
                        e.key
                    );
                }
            }
        }
        assert!(
            checked > 0,
            "no harness writes {endpoint} any more — this test now guards nothing"
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// The receiver rejects an OTLP post that does not present the token, so a
    /// Codex not *told* the token is a Codex whose telemetry is 401'd on every
    /// turn. Both halves are quiet — the receiver logs once per process, Codex
    /// treats an export failure as its own business — so this would read as
    /// "Codex just isn't very chatty" for as long as nobody looked.
    #[test]
    fn install_hands_codex_the_token_the_receiver_will_ask_for() {
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", home.path().join("data"));
        }
        let token = crate::adapters::codex::shared_token().unwrap();
        let d = Detection {
            id: "codex",
            signals: vec![Signal::ConfigDir],
            config_home: home.path().join("codex"),
            binary: None,
        };
        let artifacts = harness_by_id("codex").unwrap().artifacts(&d, Scope::User);
        let edits = artifacts
            .iter()
            .filter_map(|a| match a {
                Artifact::TomlEdit { edits, .. } => Some(edits),
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>();
        assert!(
            edits
                .iter()
                .any(|e| e.value.to_string().contains(&format!("Bearer {token}"))),
            "install writes no credential Codex can present to our own receiver"
        );
        // And `check` has to ask for it back. Writing the header without
        // demanding it is the T8e lesson repeated one field along: a restored
        // home directory leaves Codex presenting a token the receiver refuses,
        // and a `check` that only looks at the endpoint calls that intact.
        assert!(
            edits.iter().any(|e| e
                .must_carry
                .iter()
                .any(|r| r.present && r.needle == format!("Bearer {token}"))),
            "install writes the token but `check` never verifies it is still there"
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// An `OwnedFile` verifies by looking for its markers, so a marker that is
    /// not actually in what `install` writes would make `check` fail
    /// immediately after a successful install.
    #[test]
    fn owned_file_markers_are_present_in_what_install_writes() {
        let home = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", home.path().join("data"));
        }
        for h in HARNESSES {
            let d = Detection {
                id: h.id(),
                signals: vec![Signal::ConfigDir],
                config_home: home.path().join(h.id()),
                binary: None,
            };
            for a in h.artifacts(&d, Scope::User) {
                let Artifact::OwnedFile {
                    path,
                    contents,
                    markers,
                    commands,
                } = a
                else {
                    continue;
                };
                assert!(
                    !markers.is_empty(),
                    "{}: an owned file with no markers verifies against any garbage",
                    path.display()
                );
                for m in &markers {
                    assert!(
                        contents.contains(m.as_str()),
                        "{}: marker {m:?} is not in the contents install writes",
                        path.display()
                    );
                }
                for c in &commands {
                    assert!(
                        program_of(c).is_some(),
                        "{}: no program recoverable from {c:?}",
                        path.display()
                    );
                }
            }
        }
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }
}
