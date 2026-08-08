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

use crate::config::CaptureCfg;
use crate::event::{Envelope, Event};
use crate::integrity::Finding;
use anyhow::Result;
use serde_json::{Value, json};
use std::borrow::Cow;
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
];

/// Which layer an install targets: the invoking user's own config, or the
/// admin-owned machine-wide layer users cannot disable.
///
/// T15 implements `Managed`. It is defined here now so the artifact-producing
/// signature is stable and later work is additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Managed,
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
    },
    /// Whole file argus owns outright; overwrite on install, delete on uninstall.
    OwnedFile {
        path: PathBuf,
        contents: Cow<'static, str>,
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
    /// Environment variable that overrides the location (e.g. `COPILOT_HOME`).
    pub env_override: Option<&'static str>,
    /// Path relative to the user's home directory.
    pub rel: &'static str,
}

impl ConfigDir {
    pub fn resolve(&self, home: &Path) -> PathBuf {
        if let Some(key) = self.env_override
            && let Ok(v) = std::env::var(key)
            && !v.is_empty()
        {
            return PathBuf::from(v);
        }
        home.join(self.rel)
    }
}

/// Declarative detection inputs.
///
/// T4 extends this with binaries, npm packages and brew formulae, and with
/// per-platform config dirs; today only `config_dirs` is populated and
/// consulted, which reproduces the previous "does the config dir exist"
/// behaviour exactly.
pub struct Probes {
    pub config_dirs: &'static [ConfigDir],
}

/// Which detection signal(s) fired for a harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    ConfigDir,
    // T4: Binary, NpmGlobal, Brew
}

/// A harness found on this machine.
pub struct Detection {
    pub id: &'static str,
    pub signals: Vec<Signal>,
    pub config_home: PathBuf,
}

/// A harness-specific setting that silently disables capture (e.g. Codex's
/// `[features] hooks = false`). Check-only: reported, never written.
///
/// T3/T11/T12 populate these; no harness reports one yet.
pub struct KillSwitch {
    pub name: &'static str,
    pub detail: String,
}

pub trait Harness: Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn probes(&self) -> Probes;
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

/// Absolute path to the running binary, used as the hook command.
///
/// T3 replaces this with a *stable* install path: a command baked from
/// `current_exe()` silently stops working the moment the binary moves
/// (brew upgrade, npm reinstall, `cargo install` to a new prefix).
pub fn self_exe() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "argus".into())
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
        CmdStyle::Shell if cfg!(windows) => {
            // cmd.exe has no escape for `"` inside a quoted string; paths
            // containing one are not representable, and Windows forbids `"`
            // in filenames anyway.
            format!("\"{}\"", exe.replace('"', ""))
        }
        CmdStyle::Shell => {
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
    hook_command_for(&self_exe(), source, event, style)
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
// Detection
// ---------------------------------------------------------------------------

/// Every harness detected under `home`.
///
/// T4 replaces the config-dir-only probe with multi-signal detection (binary
/// on PATH, npm global, brew) and per-platform layouts.
pub fn detect(home: &Path) -> Vec<Detection> {
    HARNESSES
        .iter()
        .filter_map(|h| detect_one(*h, home))
        .collect()
}

fn detect_one(h: &dyn Harness, home: &Path) -> Option<Detection> {
    for cd in h.probes().config_dirs {
        let path = cd.resolve(home);
        if path.exists() {
            return Some(Detection {
                id: h.id(),
                signals: vec![Signal::ConfigDir],
                config_home: path,
            });
        }
    }
    None
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
    for d in detect(home) {
        let Some(h) = harness_by_id(d.id) else {
            continue;
        };
        for artifact in h.artifacts(&d, Scope::User) {
            apply(&artifact, h.display_name(), dry_run)?;
        }
    }
    Ok(())
}

fn apply(artifact: &Artifact, display: &str, dry_run: bool) -> Result<()> {
    match artifact {
        Artifact::JsonHooks {
            path,
            events,
            shape,
            source,
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
                // Idempotent: never a second argus entry for one event.
                if arr.iter().any(|h| is_ours(h, source)) {
                    continue;
                }
                arr.push(hook_entry(*shape, &cmd, ev));
            }
            if dry_run {
                println!("[dry-run] would update {}", path.display());
                return Ok(());
            }
            write_json(path, &doc)?;
            println!("wired {display} hooks in {}", path.display());
        }
        Artifact::OwnedFile { path, contents } => {
            if dry_run {
                println!("[dry-run] would write {}", path.display());
                return Ok(());
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Overwrite unconditionally: the file is versioned with the
            // binary, so a stale copy from an older install must be replaced.
            std::fs::write(path, contents.as_ref())?;
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
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, doc.to_string())?;
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
            std::fs::write(path, doc.to_string())?;
        }
    }
    Ok(())
}

/// Wiring status for every *detected* harness. A harness the user never
/// installed can't be tampered with, so it is absent rather than broken.
pub fn check(home: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    for d in detect(home) {
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
/// T3 hardens this: resolve the hook command's program path and fail when the
/// binary is missing or non-executable, fail on a zero-byte owned file, and
/// verify the Codex `config.toml` edits (today a `TomlEdit` is not checked at
/// all, so a partial install there is silently permanent).
fn verify(artifact: &Artifact) -> std::result::Result<(), String> {
    match artifact {
        Artifact::JsonHooks {
            path,
            events,
            source,
            ..
        } => {
            let Ok(text) = std::fs::read_to_string(path) else {
                return Err(format!("{} unreadable", path.display()));
            };
            let doc: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let hooks = &doc["hooks"];
            // Every expected event must still carry an argus entry, so
            // stripping one event's wiring is caught, not just wiping the file.
            let missing: Vec<&str> = events
                .iter()
                .filter(|ev| {
                    !hooks[ev.name]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|h| is_ours(h, source)))
                })
                .map(|ev| ev.name)
                .collect();
            if missing.is_empty() {
                Ok(())
            } else {
                Err(format!("missing hooks: {}", missing.join(",")))
            }
        }
        Artifact::OwnedFile { path, .. } => {
            if path.exists() {
                Ok(())
            } else {
                Err(format!("{} missing", path.display()))
            }
        }
        // T3: verify the Codex config.toml edits are still present.
        Artifact::TomlEdit { .. } => Ok(()),
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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(doc)?)?;
    Ok(())
}

/// Dispatch a raw envelope to its harness adapter.
pub fn parse(envelope: Envelope, capture: &CaptureCfg) -> Vec<Event> {
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
        if !cfg!(windows) {
            assert_eq!(
                quote_program("/opt/my apps/argus", CmdStyle::Shell),
                "'/opt/my apps/argus'"
            );
            assert_eq!(
                quote_program("/opt/it's/argus", CmdStyle::Shell),
                r"'/opt/it'\''s/argus'"
            );
        }
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
}
