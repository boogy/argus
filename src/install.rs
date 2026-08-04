//! Wires/unwires argus into installed tools (Claude Code hooks,
//! opencode plugin, codex config).
//!
//! Detection is home-dir presence based (`~/.claude`, `~/.config/opencode`,
//! `~/.codex`); all edits are additive and tagged with "argus" in the
//! command/binary path so `uninstall` can find and remove exactly what
//! `install::run` added, without touching unrelated user config.

use anyhow::Result;
use serde_json::{json, Value};

const OPENCODE_SHIM: &str = include_str!("../plugins/opencode/argus.ts");

/// (event name, whether the entry carries a `"matcher": "*"` field).
/// Matchers are set only for tool-name-matched events; matcher-less entries
/// run for every matcher value anyway. Deliberately not wired (see README):
/// MessageDisplay, UserPromptExpansion, FileChanged, Worktree*, Setup,
/// TeammateIdle, Elicitation*.
pub(crate) const CC_HOOKS: &[(&str, bool)] = &[
    ("UserPromptSubmit", false),
    ("PreToolUse", true),
    ("PostToolUse", true),
    ("PostToolUseFailure", true),
    ("PermissionRequest", true),
    ("PermissionDenied", true),
    ("Notification", false),
    ("SessionStart", false),
    ("SessionEnd", false),
    ("Stop", false),
    ("SubagentStart", false),
    ("SubagentStop", false),
    ("PreCompact", false),
    ("PostCompact", false),
    ("StopFailure", false),
    ("ConfigChange", false),
    ("CwdChanged", false),
    ("InstructionsLoaded", false),
    ("TaskCreated", false),
    ("TaskCompleted", false),
];

/// Home directory root. Overridable via `ARGUS_HOME` so tests never
/// touch a real home directory.
pub(crate) fn home() -> std::path::PathBuf {
    std::env::var("ARGUS_HOME")
        .map(Into::into)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| ".".into()))
}

/// Absolute path to the running binary, used as the hook/notify command.
/// Falls back to a bare name (resolved via PATH) if the exe path can't be
/// determined.
fn self_exe() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "argus".into())
}

/// Wire argus into every detected tool. Idempotent: running twice
/// never duplicates entries. `dry_run` prints planned changes without
/// writing anything.
pub fn run(dry_run: bool) -> Result<()> {
    let home = home();
    if home.join(".claude").exists() {
        install_claude_code(&home, dry_run)?;
    }
    if home.join(".config/opencode").exists() {
        install_opencode(&home, dry_run)?;
    }
    if home.join(".codex").exists() {
        install_codex(&home, dry_run)?;
        install_codex_hooks(&home, dry_run)?;
    }
    if copilot_dir(&home).exists() {
        install_copilot(&home, dry_run)?;
    }
    Ok(())
}

fn install_claude_code(home: &std::path::Path, dry_run: bool) -> Result<()> {
    let path = home.join(".claude/settings.json");
    let mut settings: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    if !settings.is_object() {
        settings = json!({});
    }
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let cmd = format!("{} hook --source claude-code", self_exe());
    for (event, has_matcher) in CC_HOOKS {
        let arr = hooks
            .as_object_mut()
            .unwrap()
            .entry(*event)
            .or_insert_with(|| json!([]));
        if !arr.is_array() {
            *arr = json!([]);
        }
        let arr = arr.as_array_mut().unwrap();
        if arr.iter().any(|h| h.to_string().contains("argus")) {
            continue;
        }
        let mut entry = json!({ "hooks": [{ "type": "command", "command": cmd, "timeout": 10 }] });
        if *has_matcher {
            entry["matcher"] = json!("*");
        }
        arr.push(entry);
    }
    if dry_run {
        println!("[dry-run] would update {}", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&settings)?)?;
    println!("wired Claude Code hooks in {}", path.display());
    Ok(())
}

fn install_opencode(home: &std::path::Path, dry_run: bool) -> Result<()> {
    let path = home.join(".config/opencode/plugin/argus.ts");
    if dry_run {
        println!("[dry-run] would write {}", path.display());
        return Ok(());
    }
    std::fs::create_dir_all(path.parent().unwrap())?;
    // Overwrite unconditionally: the shim is versioned with the binary, so a
    // stale copy from an older install must always be replaced.
    std::fs::write(&path, OPENCODE_SHIM)?;
    println!("installed opencode plugin at {}", path.display());
    Ok(())
}

/// Codex hooks.json events we subscribe to (verified against the Codex hooks
/// docs: Claude-compatible `hooks.{Event}[]` schema, JSON payload on stdin
/// with `hook_event_name`; non-managed hooks need one-time trust via
/// `/hooks` in the Codex CLI).
pub(crate) const CODEX_HOOK_EVENTS: &[(&str, bool)] = &[
    ("SessionStart", false),
    ("UserPromptSubmit", false),
    ("PreToolUse", true),
    ("PostToolUse", true),
    ("PermissionRequest", true),
    ("SubagentStart", false),
    ("SubagentStop", false),
    ("Stop", false),
    ("PreCompact", false),
    ("PostCompact", false),
];

fn install_codex_hooks(home: &std::path::Path, dry_run: bool) -> Result<()> {
    let path = home.join(".codex/hooks.json");
    let mut doc: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    if !doc.is_object() {
        doc = json!({});
    }
    let hooks = doc
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let cmd = format!("{} hook --source codex", self_exe());
    for (event, has_matcher) in CODEX_HOOK_EVENTS {
        let arr = hooks
            .as_object_mut()
            .unwrap()
            .entry(*event)
            .or_insert_with(|| json!([]));
        if !arr.is_array() {
            *arr = json!([]);
        }
        let arr = arr.as_array_mut().unwrap();
        if arr.iter().any(|h| h.to_string().contains("argus")) {
            continue;
        }
        let mut entry = json!({ "hooks": [{ "type": "command", "command": cmd, "timeout": 10 }] });
        if *has_matcher {
            entry["matcher"] = json!("*");
        }
        arr.push(entry);
    }
    if dry_run {
        println!("[dry-run] would update {}", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    println!("wired Codex hooks in {}", path.display());
    Ok(())
}

fn uninstall_codex_hooks(home: &std::path::Path) -> Result<()> {
    let path = home.join(".codex/hooks.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let Ok(mut doc) = serde_json::from_str::<Value>(&text) else {
        return Ok(());
    };
    if let Some(hooks) = doc.get_mut("hooks").and_then(Value::as_object_mut) {
        for (_, v) in hooks.iter_mut() {
            if let Some(arr) = v.as_array_mut() {
                arr.retain(|h| !h.to_string().contains("argus"));
            }
        }
    }
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

fn install_codex(home: &std::path::Path, dry_run: bool) -> Result<()> {
    let path = home.join(".codex/config.toml");
    let mut doc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.parse::<toml_edit::DocumentMut>().ok())
        .unwrap_or_default();
    if !doc.contains_key("notify") {
        let mut arr = toml_edit::Array::new();
        arr.push(self_exe());
        arr.push("hook");
        arr.push("--source");
        arr.push("codex");
        doc["notify"] = toml_edit::value(arr);
    } else {
        eprintln!("codex: existing notify preserved; codex turn events not wired");
    }
    if !doc.contains_key("otel") {
        // Source the endpoint from config so Codex's notify target and the
        // daemon's actual OTLP listen address can't drift apart.
        let listen = crate::config::load().codex.otlp_listen;
        let endpoint = format!("http://{listen}");
        let mut otel = toml_edit::Table::new();
        otel["environment"] = toml_edit::value("prod");
        let mut otlp_http = toml_edit::InlineTable::new();
        otlp_http.insert("endpoint", endpoint.into());
        otlp_http.insert("protocol", "json".into());
        let mut exporter = toml_edit::InlineTable::new();
        exporter.insert("otlp-http", toml_edit::Value::InlineTable(otlp_http));
        otel["exporter"] = toml_edit::value(toml_edit::Value::InlineTable(exporter));
        doc["otel"] = toml_edit::Item::Table(otel);
    } else {
        eprintln!("codex: existing [otel] preserved; not overwriting");
    }
    if dry_run {
        println!("[dry-run] would update {}", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, doc.to_string())?;
    println!("wired Codex otel+notify in {}", path.display());
    Ok(())
}

/// Copilot CLI hook events (verified against the Copilot hooks reference:
/// camelCase events, `bash`/`powershell` command entries, `timeoutSec`;
/// `permissionRequest` with empty stdout + exit 0 falls through to the
/// normal permission flow, so observe-only wiring is safe).
const COPILOT_EVENTS: &[&str] = &[
    "sessionStart",
    "sessionEnd",
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "errorOccurred",
    "agentStop",
    "subagentStart",
    "subagentStop",
    "preCompact",
    "notification",
    "permissionRequest",
];

pub(crate) fn copilot_dir(home: &std::path::Path) -> std::path::PathBuf {
    std::env::var("COPILOT_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| home.join(".copilot"))
}

/// The hooks file is wholly ours (own filename), so install overwrites it
/// unconditionally — same policy as the opencode plugin shim.
fn install_copilot(home: &std::path::Path, dry_run: bool) -> Result<()> {
    let path = copilot_dir(home).join("hooks/argus.json");
    let exe = self_exe();
    let mut hooks = serde_json::Map::new();
    for event in COPILOT_EVENTS {
        let cmd = format!("{exe} hook --source copilot --event {event}");
        hooks.insert(
            (*event).into(),
            json!([{ "type": "command", "bash": cmd, "powershell": cmd, "timeoutSec": 10 }]),
        );
    }
    let doc = json!({ "version": 1, "hooks": hooks });
    if dry_run {
        println!("[dry-run] would write {}", path.display());
        return Ok(());
    }
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    println!("wired Copilot CLI hooks in {}", path.display());
    Ok(())
}

/// Reverse `run`: remove exactly what `install` added, leaving unrelated
/// user config (including a pre-existing Codex `[otel]`/`notify` that
/// `install` refused to touch) untouched.
pub fn uninstall() -> Result<()> {
    let home = home();
    uninstall_claude_code(&home)?;
    let _ = std::fs::remove_file(home.join(".config/opencode/plugin/argus.ts"));
    uninstall_codex(&home)?;
    uninstall_codex_hooks(&home)?;
    let _ = std::fs::remove_file(copilot_dir(&home).join("hooks/argus.json"));
    println!("argus unwired from all tools");
    Ok(())
}

fn uninstall_claude_code(home: &std::path::Path) -> Result<()> {
    let path = home.join(".claude/settings.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let Ok(mut settings) = serde_json::from_str::<Value>(&text) else {
        return Ok(());
    };
    if let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) {
        for (_, v) in hooks.iter_mut() {
            if let Some(arr) = v.as_array_mut() {
                arr.retain(|h| !h.to_string().contains("argus"));
            }
        }
    }
    std::fs::write(&path, serde_json::to_string_pretty(&settings)?)?;
    Ok(())
}

fn uninstall_codex(home: &std::path::Path) -> Result<()> {
    let path = home.join(".codex/config.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let Ok(mut doc) = text.parse::<toml_edit::DocumentMut>() else {
        return Ok(());
    };
    // Load the current configured endpoint, using the same format install_codex uses
    let listen = crate::config::load().codex.otlp_listen;
    let endpoint = format!("http://{listen}");
    let default_endpoint = "http://127.0.0.1:4327";
    let ours = |v: &toml_edit::Item| {
        let s = v.to_string();
        s.contains("argus") || s.contains(&endpoint) || s.contains(default_endpoint)
    };
    if doc.get("notify").is_some_and(ours) {
        doc.remove("notify");
    }
    if doc.get("otel").is_some_and(ours) {
        doc.remove("otel");
    }
    std::fs::write(&path, doc.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("ARGUS_HOME", dir.path());
        // install_codex now reads config::load(), which in turn reads
        // ARGUS_DATA_DIR; isolate it so tests never pick up a real
        // on-disk config.
        std::env::set_var("ARGUS_DATA_DIR", dir.path().join("data"));
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::create_dir_all(dir.path().join(".config/opencode")).unwrap();
        std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
        dir
    }

    #[test]
    fn install_wires_all_three_tools_idempotently() {
        let home = fake_home();
        run(false).unwrap();
        run(false).unwrap(); // second run must not duplicate

        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            pre.iter()
                .filter(|h| h.to_string().contains("argus"))
                .count(),
            1
        );
        assert!(settings["hooks"]["UserPromptSubmit"]
            .to_string()
            .contains("argus"));

        assert!(home
            .path()
            .join(".config/opencode/plugin/argus.ts")
            .exists());

        let codex = std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap();
        assert!(codex.contains("otel"));
        assert!(codex.contains("127.0.0.1:4327"));
        assert!(codex.contains("notify"));
    }

    #[test]
    fn install_wires_full_claude_hook_set() {
        let home = fake_home();
        run(false).unwrap();
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        for event in [
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "PermissionRequest",
            "PermissionDenied",
            "Notification",
            "SessionStart",
            "SessionEnd",
            "Stop",
            "SubagentStart",
            "SubagentStop",
            "PreCompact",
            "PostCompact",
            "StopFailure",
            "ConfigChange",
            "CwdChanged",
            "InstructionsLoaded",
            "TaskCreated",
            "TaskCompleted",
        ] {
            assert!(
                settings["hooks"][event].to_string().contains("argus"),
                "missing hook wiring for {event}"
            );
        }
        // hooks must be bounded so a wedged shim can't stall Claude Code
        assert!(settings["hooks"]["PreToolUse"]
            .to_string()
            .contains("\"timeout\":10"));
    }

    #[test]
    fn install_skips_missing_tools_and_preserves_existing_codex_otel() {
        let home = fake_home();
        std::fs::remove_dir_all(home.path().join(".config/opencode")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[otel]\nenvironment = \"custom\"\n",
        )
        .unwrap();
        run(false).unwrap();
        assert!(!home
            .path()
            .join(".config/opencode/plugin/argus.ts")
            .exists());
        let codex = std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap();
        assert!(codex.contains("custom"), "existing otel config preserved");
    }

    #[test]
    fn install_wires_codex_hooks_json_idempotently() {
        let home = fake_home();
        run(false).unwrap();
        run(false).unwrap();
        let text = std::fs::read_to_string(home.path().join(".codex/hooks.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "PermissionRequest",
            "SubagentStart",
            "SubagentStop",
            "Stop",
            "PreCompact",
            "PostCompact",
        ] {
            let arr = doc["hooks"][event].as_array().unwrap();
            assert_eq!(
                arr.iter()
                    .filter(|h| h.to_string().contains("argus"))
                    .count(),
                1,
                "event {event}"
            );
        }
    }

    #[test]
    fn uninstall_removes_codex_hooks_entries_only() {
        let home = fake_home();
        std::fs::write(
            home.path().join(".codex/hooks.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"my-own-tool"}]}]}}"#,
        )
        .unwrap();
        run(false).unwrap();
        uninstall().unwrap();
        let text = std::fs::read_to_string(home.path().join(".codex/hooks.json")).unwrap();
        assert!(text.contains("my-own-tool"), "user hooks preserved");
        assert!(!text.contains("argus"));
    }

    #[test]
    fn uninstall_reverses_install() {
        let home = fake_home();
        run(false).unwrap();
        uninstall().unwrap();
        let settings = std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap();
        assert!(!settings.contains("argus"));
        assert!(!home
            .path()
            .join(".config/opencode/plugin/argus.ts")
            .exists());
    }

    #[test]
    fn install_writes_copilot_hooks_file_and_uninstall_removes_it() {
        let home = fake_home();
        std::fs::create_dir_all(home.path().join(".copilot")).unwrap();
        run(false).unwrap();
        let path = home.path().join(".copilot/hooks/argus.json");
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["version"], 1);
        for event in [
            "sessionStart",
            "sessionEnd",
            "userPromptSubmitted",
            "preToolUse",
            "postToolUse",
            "postToolUseFailure",
            "errorOccurred",
            "agentStop",
            "subagentStart",
            "subagentStop",
            "preCompact",
            "notification",
            "permissionRequest",
        ] {
            let entry = &doc["hooks"][event][0];
            assert_eq!(entry["type"], "command", "event {event}");
            let bash = entry["bash"].as_str().unwrap();
            assert!(bash.contains("--source copilot"), "event {event}");
            assert!(bash.contains(&format!("--event {event}")), "event {event}");
            assert!(
                entry["powershell"].as_str().unwrap().contains("--event"),
                "event {event}"
            );
            assert_eq!(entry["timeoutSec"], 10);
        }
        uninstall().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn copilot_skipped_when_not_installed() {
        let home = fake_home(); // fake_home creates .claude/.config/.codex only
        run(false).unwrap();
        assert!(!home.path().join(".copilot/hooks/argus.json").exists());
    }

    #[test]
    fn install_preserves_claude_settings_key_order() {
        let home = fake_home();
        std::fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"z_first": 1, "hooks": {}, "a_last": 2}"#,
        )
        .unwrap();
        run(false).unwrap();
        let text = std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap();
        let z_pos = text.find("z_first").unwrap();
        let a_pos = text.find("a_last").unwrap();
        assert!(z_pos < a_pos, "expected z_first before a_last, got: {text}");
    }

    #[test]
    fn install_preserves_codex_comments_and_formatting() {
        let home = fake_home();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "# my custom codex config\nmodel = \"o3\"\n",
        )
        .unwrap();
        run(false).unwrap();
        let text = std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap();
        assert!(text.contains("# my custom codex config"));
        assert!(text.contains("model = \"o3\""));
        assert!(text.contains("otel"));
        assert!(text.contains("127.0.0.1:4327"));
    }

    #[test]
    fn uninstall_removes_codex_otel_for_custom_endpoint() {
        let home = fake_home();
        let data = home.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(
            data.join("config.toml"),
            "[codex]\notlp_listen = \"127.0.0.1:9999\"\n",
        )
        .unwrap();
        run(false).unwrap();
        let cfg_path = home.path().join(".codex/config.toml");
        let installed = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(installed.contains("9999"), "install wrote custom endpoint");
        uninstall().unwrap();
        let after = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            !after.contains("otel"),
            "uninstall removed custom-endpoint otel block"
        );
    }
}
