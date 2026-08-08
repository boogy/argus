//! `argus install` / `argus uninstall`.
//!
//! Both are now thin drivers over the [`crate::harness`] registry: every
//! supported tool declares where its config lives and which files argus owns
//! or edits, and one generic implementation applies (or reverses) that.
//! Adding a tool is a new `impl Harness`, not another near-identical 45-line
//! installer here.

use anyhow::Result;

/// Home directory root. Overridable via `ARGUS_HOME` so tests never
/// touch a real home directory.
pub(crate) fn home() -> std::path::PathBuf {
    std::env::var("ARGUS_HOME")
        .map(Into::into)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| ".".into()))
}

/// Wire argus into every detected tool. Idempotent: running twice
/// never duplicates entries. `dry_run` prints planned changes without
/// writing anything.
pub fn run(dry_run: bool) -> Result<()> {
    crate::harness::install(&home(), dry_run)
}

/// Reverse `run`: remove exactly what `install` added, leaving unrelated
/// user config (including a pre-existing Codex `[otel]`/`notify` that
/// `install` refused to touch) untouched.
pub fn uninstall() -> Result<()> {
    crate::harness::uninstall(&home())?;
    println!("argus unwired from all tools");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_HOME", dir.path());
        }
        // The Codex artifact reads config::load(), which in turn reads
        // ARGUS_DATA_DIR; isolate it so tests never pick up a real
        // on-disk config.
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path().join("data"));
        }
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
        assert!(
            settings["hooks"]["UserPromptSubmit"]
                .to_string()
                .contains("argus")
        );

        assert!(
            home.path()
                .join(".config/opencode/plugin/argus.ts")
                .exists()
        );

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
        assert!(
            settings["hooks"]["PreToolUse"]
                .to_string()
                .contains("\"timeout\":10")
        );
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
        assert!(
            !home
                .path()
                .join(".config/opencode/plugin/argus.ts")
                .exists()
        );
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
        assert!(
            !home
                .path()
                .join(".config/opencode/plugin/argus.ts")
                .exists()
        );
    }

    /// Uninstall must leave the file as it found it, not as a shell of empty
    /// event keys. The stale `"PreToolUse": []` left by the old retain-only
    /// uninstall was not cosmetic: Claude Code treats an event key present
    /// with an empty array as "configured, nothing to run", and a later
    /// `install` had to re-populate it — while `check` saw a key it could not
    /// distinguish from deliberate user config.
    #[test]
    fn uninstall_leaves_no_orphaned_empty_hook_keys() {
        let home = fake_home();
        run(false).unwrap();
        uninstall().unwrap();
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        assert!(
            settings.get("hooks").is_none(),
            "no argus events left behind, so `hooks` itself must go: {settings}"
        );
    }

    /// Machines wired by a pre-`_argus` build already carry empty event keys
    /// with no argus entry left to trigger the retain filter, so sweeping only
    /// the arrays we just emptied would strand them forever. Sweep by the
    /// known event list instead.
    #[test]
    fn uninstall_sweeps_preexisting_orphaned_keys() {
        let home = fake_home();
        std::fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[],"Stop":[{"hooks":[{"command":"mine"}]}]},"other":1}"#,
        )
        .unwrap();
        uninstall().unwrap();
        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        assert!(
            settings["hooks"].get("PreToolUse").is_none(),
            "orphaned empty key must be swept: {settings}"
        );
        assert!(
            settings["hooks"]["Stop"].to_string().contains("mine"),
            "user's own hook untouched: {settings}"
        );
        assert_eq!(settings["other"], 1, "unrelated keys untouched");
    }

    /// The old ownership test was `entry.to_string().contains("argus")`, which
    /// deletes a user's own hook that merely lives under a path containing
    /// "argus" — e.g. a repo checked out at `~/src/argus/`.
    #[test]
    fn uninstall_keeps_user_hook_whose_path_merely_contains_argus() {
        let home = fake_home();
        std::fs::write(
            home.path().join(".claude/settings.json"),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/home/u/src/argus/scripts/mine.sh"}],"_argus":false}]}}"#,
        )
        .unwrap();
        uninstall().unwrap();
        let text = std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap();
        assert!(
            text.contains("mine.sh"),
            "structurally-unmarked user hook must survive: {text}"
        );
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
            let ps = entry["powershell"].as_str().unwrap();
            assert!(ps.contains("--event"), "event {event}");
            assert!(
                ps.starts_with("& \""),
                "powershell needs the call operator on a quoted path: {ps}"
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
