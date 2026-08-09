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
pub fn home() -> std::path::PathBuf {
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
        // Hook commands are baked from ARGUS_BIN when set; clear it so a test
        // that points it at a temp file can't leak into the next one.
        unsafe {
            std::env::remove_var(crate::harness::BIN_ENV);
        }
        // Detection reads the real machine's PATH and config-dir overrides.
        // Without pinning both, these tests assert on whichever agents the
        // developer happens to have installed — `opencode` on this machine's
        // PATH is enough to make "not installed" cases fail.
        unsafe {
            std::env::set_var(crate::detect::BIN_DIRS_ENV, dir.path().join("nobin"));
            for k in ["XDG_CONFIG_HOME", "CODEX_HOME", "COPILOT_HOME"] {
                std::env::remove_var(k);
            }
        }
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::create_dir_all(dir.path().join(".config/opencode")).unwrap();
        std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
        dir
    }

    /// A stand-in for the installed argus binary, so a test can move or delete
    /// it without touching the real one.
    fn fake_bin(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join(if cfg!(windows) { "argus.exe" } else { "argus" });
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        unsafe {
            std::env::set_var(crate::harness::BIN_ENV, &p);
        }
        p
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
        // The port is derived from the data directory, not fixed: assert what
        // install actually writes matches what the daemon will bind.
        assert!(
            codex.contains(&crate::config::load().codex.otlp_listen),
            "codex must be pointed at the endpoint this install listens on: {codex}"
        );
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
        // Spelled out rather than read from `EVENTS`, so this states what
        // should be wired instead of restating whatever is.
        for (event, timeout) in [
            ("SessionStart", 10),
            ("SessionEnd", 3),
            ("UserPromptSubmit", 10),
            ("PreToolUse", 10),
            ("PostToolUse", 10),
            ("PermissionRequest", 10),
            ("SubagentStart", 10),
            ("SubagentStop", 10),
            ("Stop", 10),
            ("PreCompact", 10),
            ("PostCompact", 10),
        ] {
            let arr = doc["hooks"][event].as_array().unwrap();
            let ours: Vec<_> = arr
                .iter()
                .filter(|h| h.to_string().contains("argus"))
                .collect();
            assert_eq!(ours.len(), 1, "event {event}");
            // `SessionEnd` runs while Codex is exiting, so its timeout is
            // time the user watches the CLI hang. It has to reach the file:
            // a per-event timeout nobody writes out is a comment.
            assert_eq!(
                ours[0]["hooks"][0]["timeout"], timeout,
                "event {event} timeout"
            );
        }
    }

    /// An upgrade has to reach hosts that are already wired. The entry argus
    /// writes is versioned with the binary — T11a changed `SessionEnd`'s
    /// timeout from 10 to 3 — and install used to skip any event that already
    /// had an argus entry, so every host wired before that release kept the
    /// old one with no way short of uninstalling to correct it.
    #[test]
    fn install_refreshes_a_stale_argus_hook_entry_and_leaves_foreign_ones() {
        let home = fake_home();
        run(false).unwrap();
        let path = home.path().join(".codex/hooks.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        // What a pre-T11a install left behind, plus somebody else's hook in
        // the same array — the case that makes "just overwrite the file" the
        // wrong fix.
        // Ahead of ours, not after it: "refresh the entry that is ours" and
        // "refresh the first entry" are the same edit when ours is first, and
        // only one of them is correct.
        let arr = doc["hooks"]["SessionEnd"].as_array_mut().unwrap();
        arr.insert(
            0,
            serde_json::json!({
                "hooks": [{ "type": "command", "command": "/usr/local/bin/audit-log" }]
            }),
        );
        arr[1]["hooks"][0]["timeout"] = serde_json::json!(10);
        arr[1]["hooks"][0]["command"] = serde_json::json!("/opt/old/argus hook");
        std::fs::write(&path, doc.to_string()).unwrap();

        run(false).unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let arr = doc["hooks"]["SessionEnd"].as_array().unwrap();
        let ours: Vec<_> = arr
            .iter()
            .filter(|h| h[crate::harness::MARKER_KEY] == serde_json::json!(true))
            .collect();
        assert_eq!(ours.len(), 1, "still exactly one argus entry: {arr:?}");
        assert_eq!(ours[0]["hooks"][0]["timeout"], 3, "{arr:?}");
        assert!(
            !ours[0]["hooks"][0]["command"]
                .as_str()
                .unwrap()
                .contains("/opt/old/"),
            "stale command survived: {arr:?}"
        );
        assert!(
            arr.iter().any(|h| h.to_string().contains("audit-log")),
            "somebody else's hook was taken with it: {arr:?}"
        );
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
        assert!(text.contains(&crate::config::load().codex.otlp_listen));
    }

    /// The check that used to be missing entirely. Every config file below is
    /// byte-for-byte intact after the binary disappears — an upgrade that
    /// relocates it (brew, npm, `cargo install --root`) leaves exactly this
    /// state, and `check` reported everything healthy while nothing was being
    /// captured.
    #[test]
    fn check_passes_when_healthy_and_fails_once_the_binary_is_gone() {
        let home = fake_home();
        std::fs::create_dir_all(home.path().join(".copilot")).unwrap();
        let bin = fake_bin(home.path());
        run(false).unwrap();

        let findings = crate::integrity::check(home.path());
        assert_eq!(
            findings.len(),
            4,
            "all four harnesses checked: {findings:?}"
        );
        assert!(
            findings.iter().all(|f| f.ok),
            "a fresh install must verify: {findings:?}"
        );

        std::fs::remove_file(&bin).unwrap();
        let after = crate::integrity::check(home.path());
        for tool in ["claude-code", "codex", "copilot"] {
            let f = after.iter().find(|f| f.tool == tool).unwrap();
            assert!(!f.ok, "{tool} must report broken: {f:?}");
            assert!(
                f.detail.contains("missing or non-executable"),
                "{tool}: {f:?}"
            );
        }
        // opencode is the deliberate exception: its plugin talks to the daemon
        // socket and resolves the fallback binary itself at runtime, so no
        // path is baked into the artifact for `check` to resolve.
        let oc = after.iter().find(|f| f.tool == "opencode").unwrap();
        assert!(oc.ok, "opencode has no baked-in binary path: {oc:?}");
    }

    #[test]
    fn check_detects_an_emptied_plugin_file() {
        let home = fake_home();
        fake_bin(home.path());
        run(false).unwrap();
        let plugin = home.path().join(".config/opencode/plugin/argus.ts");
        // Truncation, not deletion: `path.exists()` still says yes.
        std::fs::write(&plugin, "").unwrap();
        let f = crate::integrity::check(home.path())
            .into_iter()
            .find(|f| f.tool == "opencode")
            .unwrap();
        assert!(!f.ok && f.detail.contains("is empty"), "{f:?}");
    }

    #[test]
    fn check_detects_a_gutted_plugin_file_that_is_still_non_empty() {
        let home = fake_home();
        fake_bin(home.path());
        run(false).unwrap();
        let plugin = home.path().join(".config/opencode/plugin/argus.ts");
        std::fs::write(&plugin, "export const Plugin = () => ({});\n").unwrap();
        let f = crate::integrity::check(home.path())
            .into_iter()
            .find(|f| f.tool == "opencode")
            .unwrap();
        assert!(!f.ok && f.detail.contains("no longer contains"), "{f:?}");
    }

    /// Codex is wired in two files; only `hooks.json` was ever verified, so a
    /// `config.toml` stripped of `[otel]` — no OTLP export at all — looked
    /// perfectly healthy.
    #[test]
    fn check_detects_a_stripped_codex_config_toml() {
        let home = fake_home();
        fake_bin(home.path());
        run(false).unwrap();
        let cfg = home.path().join(".codex/config.toml");
        let mut doc: toml_edit::DocumentMut =
            std::fs::read_to_string(&cfg).unwrap().parse().unwrap();
        doc.remove("otel");
        std::fs::write(&cfg, doc.to_string()).unwrap();
        let f = crate::integrity::check(home.path())
            .into_iter()
            .find(|f| f.tool == "codex")
            .unwrap();
        assert!(!f.ok && f.detail.contains("otel missing from"), "{f:?}");
    }

    /// Edit the wired Codex config and return the codex finding. Every case
    /// here starts from a healthy install, so a finding that flips can only
    /// have flipped because of the edit. Edits go through `toml_edit` rather
    /// than appended text: a bare key appended after the `[otel]` table would
    /// land *inside* that table, and the test would pass for the wrong reason.
    fn codex_finding_after(
        home: &std::path::Path,
        file: &str,
        edit: impl FnOnce(&mut toml_edit::DocumentMut),
    ) -> crate::integrity::Finding {
        let cfg = home.join(".codex").join(file);
        // `requirements.toml` is administrator-supplied, so a healthy install
        // leaves it absent; starting from an empty document is that state.
        let mut doc: toml_edit::DocumentMut = std::fs::read_to_string(&cfg)
            .unwrap_or_default()
            .parse()
            .unwrap();
        edit(&mut doc);
        std::fs::write(&cfg, doc.to_string()).unwrap();
        crate::integrity::check(home)
            .into_iter()
            .find(|f| f.tool == "codex")
            .unwrap()
    }

    /// A hook entry that is present, correct, and never executed. Without
    /// this, `check` reads the wiring and reports "wired" about a tool
    /// capturing nothing — worse than reporting nothing, because someone
    /// believes it.
    #[test]
    fn check_detects_codex_kill_switches() {
        let home = fake_home();
        fake_bin(home.path());
        run(false).unwrap();
        // The baseline has to be healthy or the cases below prove nothing.
        let f = crate::integrity::check(home.path())
            .into_iter()
            .find(|f| f.tool == "codex")
            .unwrap();
        assert!(f.ok, "{f:?}");

        type Edit = fn(&mut toml_edit::DocumentMut);
        let cases: [(&str, &str, Edit); 4] = [
            ("config.toml", "[features] hooks = false", |d| {
                d["features"]["hooks"] = toml_edit::value(false)
            }),
            // The deprecated alias still works, so a host disabled before the
            // rename must not read as healthy.
            ("config.toml", "[features] codex_hooks = false", |d| {
                d["features"]["codex_hooks"] = toml_edit::value(false)
            }),
            ("config.toml", "allow_managed_hooks_only = true", |d| {
                d["allow_managed_hooks_only"] = toml_edit::value(true)
            }),
            // The file the docs actually name for this setting. It is not an
            // artifact argus writes, so nothing but the kill-switch read ever
            // opens it — check the file the user's administrator uses, not
            // only the one that happens to be convenient.
            (
                "requirements.toml",
                "allow_managed_hooks_only = true",
                |d| d["allow_managed_hooks_only"] = toml_edit::value(true),
            ),
        ];
        for (file, needle, edit) in cases {
            let home2 = fake_home();
            fake_bin(home2.path());
            run(false).unwrap();
            let f = codex_finding_after(home2.path(), file, edit);
            assert!(
                !f.ok && f.detail.contains(needle),
                "{file}/{needle} -> {f:?}"
            );
        }
    }

    /// Codex cannot read this file either, so whatever it was meant to say —
    /// including a `allow_managed_hooks_only` that would blind us — is not
    /// knowable, and "wired" is not an answer anyone should act on.
    ///
    /// Deliberately `requirements.toml` and not `config.toml`: artifact
    /// verification already parses `config.toml` and reports the same words,
    /// so a broken one there would pass this test with the kill switch
    /// deleted. This file is read by nothing else.
    #[test]
    fn check_detects_a_codex_requirements_toml_that_no_longer_parses() {
        let home = fake_home();
        fake_bin(home.path());
        run(false).unwrap();
        let cfg = home.path().join(".codex/requirements.toml");
        std::fs::write(&cfg, "this is not = = toml\n").unwrap();
        let f = crate::integrity::check(home.path())
            .into_iter()
            .find(|f| f.tool == "codex")
            .unwrap();
        assert!(!f.ok && f.detail.contains("not valid TOML"), "{f:?}");
    }

    /// A dry run's whole contract is that it is safe to run anywhere. Now that
    /// install *creates* config directories for a tool detected by its binary
    /// alone, "writes nothing" has to be asserted against the tree, not
    /// reviewed by eye.
    #[test]
    fn dry_run_creates_nothing() {
        let home = fake_home();
        std::fs::create_dir_all(home.path().join(".copilot")).unwrap();
        fake_bin(home.path());
        let before = tree(home.path());
        run(true).unwrap();
        assert_eq!(before, tree(home.path()), "dry run touched the filesystem");
        // Guard against the assertion passing because `tree` sees nothing: the
        // same call without --dry-run must change it.
        run(false).unwrap();
        assert_ne!(before, tree(home.path()));
    }

    /// A tool installed but never run has no config directory. Detection finds
    /// it by its binary, and install has to create the directory or every
    /// artifact below it lands nowhere.
    #[test]
    fn a_tool_found_only_by_its_binary_gets_its_config_dir_created() {
        let home = fake_home();
        std::fs::remove_dir_all(home.path().join(".claude")).unwrap();
        let bin = home.path().join("nobin");
        std::fs::create_dir_all(&bin).unwrap();
        let claude = bin.join(if cfg!(windows) {
            "claude.exe"
        } else {
            "claude"
        });
        std::fs::write(&claude, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        run(false).unwrap();
        let settings = home.path().join(".claude/settings.json");
        assert!(settings.exists(), "binary-only detection must still wire");
        assert!(
            std::fs::read_to_string(&settings)
                .unwrap()
                .contains("argus"),
            "hooks written into the freshly created config dir"
        );
    }

    /// `check` deliberately does not follow detection all the way: a machine
    /// with `claude` on PATH that was never wired is not broken, and reporting
    /// it as broken would make the MDM exit code useless.
    #[test]
    fn check_ignores_a_tool_that_was_never_wired() {
        let home = fake_home();
        std::fs::remove_dir_all(home.path().join(".claude")).unwrap();
        let bin = home.path().join("nobin");
        std::fs::create_dir_all(&bin).unwrap();
        let claude = bin.join(if cfg!(windows) {
            "claude.exe"
        } else {
            "claude"
        });
        std::fs::write(&claude, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert!(
            crate::detect::detect(home.path())
                .iter()
                .any(|d| d.id == "claude-code"),
            "precondition: the binary is detected"
        );
        assert!(
            !crate::integrity::check(home.path())
                .iter()
                .any(|f| f.tool == "claude-code"),
            "unwired tool must not be reported"
        );
    }

    /// Every file under `root`, with its contents — the shape a dry run must
    /// leave untouched.
    fn tree(root: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn walk(
            dir: &std::path::Path,
            out: &mut std::collections::BTreeMap<std::path::PathBuf, Vec<u8>>,
        ) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    // Record directories too: creating an empty one is still a
                    // write, and it is the exact thing install now does.
                    out.insert(p.clone(), Vec::new());
                    walk(&p, out);
                } else {
                    out.insert(p.clone(), std::fs::read(&p).unwrap_or_default());
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(root, &mut out);
        out
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
