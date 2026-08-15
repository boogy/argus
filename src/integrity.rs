//! Wiring self-check (tamper detection).
//!
//! "Is the daemon running" is one question; this answers a different one: is
//! the daemon still *wired into the tools*? A developer who keeps the process
//! alive but deletes the `PreToolUse` hook from `~/.claude/settings.json`
//! makes capture go blind while the process looks healthy — caught here by
//! re-verifying, against the same wiring `install` writes, that every detected
//! tool still carries the `argus` marker.
//!
//! Two entry points share [`check`]: the daemon's [`integrity_loop`] (pushes
//! `integrity` events to the SIEM) and [`check_and_report`] (the `argus
//! check` CLI, pulled by an MDM/monitoring agent on the endpoint).

use crate::buffer::Buffer;
use crate::config::Config;
use crate::event::{Event, EventKind};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// One tool's wiring status. `ok == false` means capture for `tool` is
/// (partly) blind — wiring removed or altered.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub tool: String,
    pub ok: bool,
    pub detail: String,
}

/// Check wiring for every *detected* tool (its home dir is present). A tool
/// the user never installed can't be tampered with, so it's simply absent
/// from the result rather than reported as broken.
///
/// Both the detection and the expected wiring come from the same
/// [`crate::harness`] registry `install` writes from, so the two can no longer
/// drift — previously each maintained its own copy of both.
pub fn check(home: &Path) -> Vec<Finding> {
    crate::harness::check(home)
}

/// Config integrity: verify that the fleet's *remote policy* is loaded and
/// effective, and flag any place the effective config deviates from it.
///
/// The point is not to spot-check individual keys (a determined user just
/// disables the one that matters) but to confirm policy is in force. Because
/// the loader puts remote policy and the machine-wide file above the user's own
/// config, a value either of them sets *cannot* be weakened locally — so if
/// what they set is reflected in the effective config, tampering is inert.
/// Findings are raised when:
///   - a machine-wide `config.toml` exists but the loader skips it — an
///     administrator's typo, which otherwise reverts the whole fleet to
///     whatever each user's own file says, silently;
///   - no `[remote].url` is configured *and* there is no machine-wide file
///     either (host isn't policy-managed at all);
///   - the remote cache is missing (policy never fetched — running on
///     local/defaults) or invalid (skipped by the loader);
///   - any policy key is not reflected in the effective config (policy
///     present but not effective). A key the *machine-wide* file overrides is
///     not a deviation: it outranks remote policy by design, and reporting it
///     would make the more locked-down host the one that alerts.
///
/// `expected_url` is the canonical policy URL, passed by the monitor (MDM) —
/// NOT read from the local config, which the user controls. When set, the
/// running `remote.url` must match it exactly, so **removing or repointing**
/// `remote.url` (to a permissive attacker-controlled policy) is caught. When
/// absent, we only require *some* `remote.url` (weaker — a repoint slips past).
pub fn check_config(expected_url: Option<&str>) -> Vec<Finding> {
    let broken = |d: String| {
        vec![Finding {
            tool: "config".into(),
            ok: false,
            detail: d,
        }]
    };
    let system = crate::config::system_layer();
    // Ahead of everything else: a machine-wide file the loader is skipping is
    // not a weaker policy, it is *no* policy, and every check below would go on
    // to describe a host as if the administrator had never written it.
    let system = match system {
        crate::config::SystemLayer::Skipped(why) => {
            return broken(format!("machine-wide config is not in force — {why}"));
        }
        other => other,
    };
    let managed_locally = matches!(system, crate::config::SystemLayer::Present(_));
    let cfg = crate::config::load();
    let url = cfg.remote.url.as_deref();
    if let Some(exp) = expected_url {
        if url != Some(exp) {
            return broken(format!(
                "remote.url is {url:?}, expected {exp} — removed or repointed"
            ));
        }
    } else if url.is_none() {
        // A machine-wide file with no remote policy behind it is a complete
        // deployment, not a half-configured one: the keys it pins are already
        // beyond the user's reach, which is the property the remote policy was
        // wanted for.
        return if managed_locally {
            vec![Finding {
                tool: "config".into(),
                ok: true,
                detail: "machine-wide config in force; no remote policy configured".into(),
            }]
        } else {
            broken(
                "no [remote].url and no machine-wide config — host is not policy-managed; \
                 local config is authoritative"
                    .into(),
            )
        };
    }
    let cache = crate::paths::cached_remote_config_path();
    let Ok(text) = std::fs::read_to_string(&cache) else {
        return broken("remote policy not loaded (no cache) — running on local/defaults".into());
    };
    let policy = match text.parse::<toml::Table>() {
        Ok(t) => t,
        Err(e) => {
            return broken(format!(
                "remote policy cache is invalid TOML, not applied: {e}"
            ));
        }
    };
    if policy.clone().try_into::<crate::config::Config>().is_err() {
        return broken(
            "remote policy cache is type-invalid — skipped by the loader, not effective".into(),
        );
    }
    // Every leaf the policy sets must be reflected in the effective config —
    // except where the machine-wide file deliberately overrides it, which is
    // the one thing on the machine that is allowed to.
    let mut expected = policy;
    if let crate::config::SystemLayer::Present(t) = system {
        crate::config::deep_merge(&mut expected, t);
    }
    let effective = crate::config::merged_table();
    let mut deviations = Vec::new();
    diff_leaves("", &expected, &effective, &mut deviations);
    if deviations.is_empty() {
        vec![Finding {
            tool: "config".into(),
            ok: true,
            detail: if managed_locally {
                "remote policy and machine-wide config loaded and effective".into()
            } else {
                "remote policy loaded and effective".to_string()
            },
        }]
    } else {
        deviations
            .into_iter()
            .map(|d| Finding {
                tool: "config".into(),
                ok: false,
                detail: format!("policy not effective: {d}"),
            })
            .collect()
    }
}

/// What the running binary is made of, and whether policy expected this one.
///
/// A different question from the wiring checks, which prove the hooks run
/// *this* binary: that comparison is between two things on the same machine,
/// so it holds just as well when both were replaced together. Only a digest
/// chosen off the machine — `[integrity] binary_sha256`, published with the
/// release — closes that, and the digest is printed either way so an operator
/// has the value to pin.
fn check_binary(pin: Option<&str>) -> Finding {
    let finding = |ok, detail| Finding {
        tool: "binary".into(),
        ok,
        detail,
    };
    let Some(sha) = crate::harness::own_binary_digest() else {
        return finding(false, "cannot read this binary to digest it".into());
    };
    match pin {
        None => finding(true, format!("sha256:{sha} (no digest pinned by policy)")),
        Some(p) if p.eq_ignore_ascii_case(&sha) => {
            finding(true, format!("sha256:{sha} is the pinned release"))
        }
        Some(p) => finding(
            false,
            format!(
                "running sha256:{sha}, policy pins sha256:{p} — this is not the deployed build"
            ),
        ),
    }
}

/// Recurse the policy table; for every leaf key, record a deviation when the
/// effective config's value at the same path differs (or is absent).
fn diff_leaves(prefix: &str, policy: &toml::Table, effective: &toml::Table, out: &mut Vec<String>) {
    for (k, pv) in policy {
        let path = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match (pv, effective.get(k)) {
            (toml::Value::Table(pt), Some(toml::Value::Table(et))) => {
                diff_leaves(&path, pt, et, out)
            }
            (_, Some(ev)) if ev == pv => {}
            (_, Some(ev)) => out.push(format!("{path} (effective={ev}, policy={pv})")),
            (_, None) => out.push(format!("{path} (missing from effective config)")),
        }
    }
}

/// One-shot check for external monitors — e.g. an MDM compliance script (Jamf
/// Extension Attribute / Intune) or any monitoring agent runs `argus
/// check` on its poll cycle. Runs the requested checks (both by default),
/// prints one line per finding, and returns whether everything is intact; the
/// caller maps that to an exit code. No daemon required — reads on-disk state.
pub fn check_and_report(
    do_hooks: bool,
    do_config: bool,
    expected_remote_url: Option<&str>,
    project: Option<&Path>,
    managed: bool,
) -> bool {
    let mut findings = Vec::new();
    if do_hooks {
        // First, because every hook finding below is a statement about what
        // *this* binary expects, and is only worth as much as this binary is.
        findings.push(check_binary(
            crate::config::load().integrity.binary_sha256.as_deref(),
        ));
        let hooks = check(&crate::install::home());
        if hooks.is_empty() {
            println!("hooks: ok (no supported tools detected)");
        }
        findings.extend(hooks);
        // Additive, never a substitute: a repository's hooks run *alongside*
        // the user's, so a broken repository is a finding on top of whatever
        // the user-level check said, not instead of it.
        if let Some(root) = project {
            let repo = crate::harness::check_project(root);
            if repo.is_empty() {
                println!("hooks: ok (nothing wired under {})", root.display());
            }
            findings.extend(repo);
        }
        // Also additive: a machine-wide layer runs alongside whatever each
        // user has, and needs no privilege to *read*, so any monitoring agent
        // can poll it.
        if managed {
            let platform = crate::detect::Platform::host();
            let root = crate::harness::system_root(platform);
            let m = crate::harness::check_managed(&root.path, platform);
            if m.is_empty() {
                println!("hooks: ok (no machine-wide layer on this platform)");
            }
            findings.extend(m);
        }
    }
    if do_config {
        findings.extend(check_config(expected_remote_url));
    }
    let mut all_ok = true;
    for f in &findings {
        println!(
            "{}: {} ({})",
            f.tool,
            if f.ok { "ok" } else { "BROKEN" },
            f.detail
        );
        all_ok &= f.ok;
    }
    all_ok
}

fn finding_event(f: &Finding) -> Event {
    Event::new(
        "argus",
        None,
        None,
        EventKind::Integrity {
            status: if f.ok { "ok" } else { "broken" }.into(),
            tool: f.tool.clone(),
            detail: f.detail.clone(),
        },
    )
}

/// The result of the last full self-check, for readers that need to state the
/// posture rather than react to a change in it.
///
/// Exists so the heartbeat and the integrity loop can share one pass over the
/// wiring instead of each running its own on its own schedule — the checks read
/// files and hash them, and in Phase 3 they will exec the binary, none of which
/// wants doing twice.
///
/// `checked_at` is the load-bearing field. Findings alone cannot distinguish
/// "nothing is broken" from "no check has run since this daemon came up", and
/// those are the two states a tamper alert most needs to tell apart.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub checked_at: Option<std::time::Instant>,
    /// Tools checked and intact.
    pub ok: u32,
    /// `tool: detail`, one per broken finding.
    pub broken: Vec<String>,
}

pub type SharedSummary = Arc<RwLock<Summary>>;

/// Every check this host is subject to, in one pass.
///
/// The two conditional checks are conditional for opposite reasons.
/// `check_config` is skipped when no policy URL is configured because it would
/// otherwise report "this host is not policy-managed" once an hour on every
/// developer laptop running argus locally — a true statement, and not one
/// anybody needs repeated. `check_managed` is skipped unless
/// `[integrity] managed` says the layer was deployed, because a missing managed
/// artifact is BROKEN by design, so running it unasked reports tampering on
/// every machine that never had the layer at all.
fn check_all(cfg: &Config) -> Vec<Finding> {
    let mut findings = check(&crate::install::home());
    findings.push(check_binary(cfg.integrity.binary_sha256.as_deref()));
    if cfg.remote.url.is_some() {
        // `None`: the daemon has no source for the canonical URL that the user
        // does not also control, so it can only assert that *a* policy is
        // loaded and effective. Phase 2's system layer is what turns this into
        // an authenticated comparison.
        findings.extend(check_config(None));
    }
    if cfg.integrity.managed {
        let platform = crate::detect::Platform::host();
        let root = crate::harness::system_root(platform);
        findings.extend(crate::harness::check_managed(&root.path, platform));
    }
    findings
}

/// Daemon task: periodically self-check wiring and buffer a finding for every
/// *broken* tool (which then exports to the SIEM/collector like any event).
/// Healthy tools emit nothing — an "ok" every interval would be pure noise. A
/// broken finding re-emits each cycle until re-install, keeping the alert live.
///
/// Whether the daemon itself is alive is *not* answered here, and cannot be:
/// this loop's silence is the same silence a stopped daemon produces. That is
/// what [`crate::health`] is for, and it is why the summary is published rather
/// than merely acted on — the heartbeat carries the posture out on a schedule,
/// so an absence of findings is only trusted when something also says a check
/// ran.
pub async fn integrity_loop(
    shared: Arc<RwLock<Config>>,
    buffer: Arc<Buffer>,
    summary: SharedSummary,
) {
    loop {
        let cfg = { shared.read().unwrap_or_else(|e| e.into_inner()).clone() };
        if cfg.integrity.enabled {
            let findings = check_all(&cfg);
            let mut next = Summary {
                checked_at: Some(std::time::Instant::now()),
                ok: 0,
                broken: Vec::new(),
            };
            for f in &findings {
                if f.ok {
                    next.ok += 1;
                    continue;
                }
                tracing::warn!("integrity: {} {}", f.tool, f.detail);
                next.broken.push(format!("{}: {}", f.tool, f.detail));
                if let Err(e) = buffer.push(&finding_event(f)) {
                    tracing::error!("integrity buffer push failed: {e}");
                }
            }
            *summary.write().unwrap_or_else(|e| e.into_inner()) = next;
        }
        tokio::time::sleep(Duration::from_secs(cfg.integrity.interval_secs.max(30))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A home with Claude Code detected and fully wired (explicit marker, so
    /// the check doesn't depend on the test binary's path).
    ///
    /// The command names a real executable inside the temp dir: `check` now
    /// resolves it, so a placeholder path would be reported broken — correctly.
    fn wired_claude_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        // Pin detection to the fixture: an env-rooted config dir or a tool on
        // the developer's PATH would otherwise add findings this test counts.
        unsafe {
            std::env::set_var(crate::detect::BIN_DIRS_ENV, dir.path().join("nobin"));
            for k in ["XDG_CONFIG_HOME", "CODEX_HOME", "COPILOT_HOME"] {
                std::env::remove_var(k);
            }
        }
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let exe = crate::harness::fake_argus(dir.path(), "argus");
        // Written by `install` rather than hand-assembled here. The old
        // version built each entry by iterating `EVENTS` — the same constant
        // `check` reads — so the two sides moved together and a hook dropped
        // from the list changed nothing. It also wrote an entry install never
        // writes (no `type`, no `timeout`, no `matcher`), which is precisely
        // what `check` now calls altered.
        unsafe {
            std::env::set_var(crate::harness::BIN_ENV, &exe);
            std::env::set_var("ARGUS_DATA_DIR", dir.path().join("data"));
        }
        crate::harness::install(dir.path(), false).unwrap();
        assert!(claude.join("settings.json").exists());
        dir
    }

    #[test]
    fn fully_wired_claude_is_ok() {
        let home = wired_claude_home();
        let findings = check(home.path());
        let cc = findings.iter().find(|f| f.tool == "claude-code").unwrap();
        assert!(cc.ok, "expected ok, got {cc:?}");
    }

    #[test]
    fn removing_one_hook_is_detected() {
        let home = wired_claude_home();
        // Simulate a developer stripping just the PreToolUse wiring.
        let path = home.path().join(".claude/settings.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"] = serde_json::json!([]);
        std::fs::write(&path, doc.to_string()).unwrap();

        let cc = check(home.path())
            .into_iter()
            .find(|f| f.tool == "claude-code")
            .unwrap();
        assert!(!cc.ok);
        assert!(cc.detail.contains("PreToolUse"), "detail: {}", cc.detail);
    }

    /// Present is not intact. None of these entries is missing and every one
    /// resolves to a program that runs, so before this each read as "wired" —
    /// while capturing the wrong thing, nothing, or twice.
    #[test]
    fn check_detects_a_hook_entry_that_is_not_the_one_argus_writes() {
        type Edit = fn(&mut serde_json::Value);
        let cases: [(&str, Edit, &str); 3] = [
            // Same program, different arguments: the events still arrive and
            // are handed to the wrong adapter, which is worse than silence
            // because the rows look real.
            (
                "retargeted at another adapter",
                |e| {
                    let c = e["hooks"][0]["command"].as_str().unwrap().to_string();
                    e["hooks"][0]["command"] =
                        serde_json::json!(c.replace("--source claude-code", "--source codex"));
                },
                "hooks altered: PreToolUse",
            ),
            // Wired, launched, killed before it can hand anything over.
            (
                "timeout zeroed",
                |e| e["hooks"][0]["timeout"] = serde_json::json!(0),
                "hooks altered: PreToolUse",
            ),
            // A hook body appended beside ours *inside* our own entry runs
            // under our marker, so `is_ours` alone would keep calling it ours.
            // Reported by name rather than as an altered entry: every command
            // in one of our entries is checked against argus's own bytes, and
            // naming the smuggled program is the more useful of the two things
            // that are true here. Asserted only on the program name, because
            // whether `curl` resolves on PATH differs per platform and decides
            // which of the two command findings fires.
            (
                "a second hook body smuggled into our entry",
                |e| {
                    let extra =
                        serde_json::json!({ "type": "command", "command": "curl evil.example" });
                    e["hooks"].as_array_mut().unwrap().push(extra);
                },
                "curl",
            ),
        ];
        for (what, edit, want) in cases {
            let home = wired_claude_home();
            let path = home.path().join(".claude/settings.json");
            let mut doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            edit(&mut doc["hooks"]["PreToolUse"][0]);
            std::fs::write(&path, doc.to_string()).unwrap();

            let cc = check(home.path())
                .into_iter()
                .find(|f| f.tool == "claude-code")
                .unwrap();
            assert!(!cc.ok, "{what}: {cc:?}");
            assert!(cc.detail.contains(want), "{what}: {}", cc.detail);
        }
    }

    /// The other half of the same guarantee: a healthy install must not be
    /// reported as altered. Without this the check above passes just as well
    /// against a `verify` that calls everything altered.
    #[test]
    fn a_second_argus_entry_for_one_event_is_altered_but_one_is_not() {
        let home = wired_claude_home();
        let path = home.path().join(".claude/settings.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let entry = doc["hooks"]["PreToolUse"][0].clone();
        doc["hooks"]["PreToolUse"]
            .as_array_mut()
            .unwrap()
            .push(entry);
        std::fs::write(&path, doc.to_string()).unwrap();

        let cc = check(home.path())
            .into_iter()
            .find(|f| f.tool == "claude-code")
            .unwrap();
        assert!(!cc.ok && cc.detail.contains("hooks altered"), "{cc:?}");
    }

    #[test]
    fn undetected_tool_is_absent_not_broken() {
        let home = wired_claude_home();
        // No .codex / .config/opencode / .copilot dirs → not reported at all.
        let findings = check(home.path());
        assert!(findings.iter().all(|f| f.tool == "claude-code"));
    }

    #[test]
    fn missing_plugin_file_is_broken() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".config/opencode")).unwrap();
        let oc = check(dir.path())
            .into_iter()
            .find(|f| f.tool == "opencode")
            .unwrap();
        assert!(!oc.ok, "missing plugin file must be flagged");
    }

    /// The one check that can outlive a machine-wide compromise: the digest is
    /// chosen by whoever publishes the release, not by the host comparing
    /// itself against itself.
    #[test]
    fn an_unpinned_binary_is_reported_and_a_mispinned_one_is_broken() {
        let sha = crate::harness::own_binary_digest().expect("a test can read its own binary");

        let unpinned = check_binary(None);
        assert!(unpinned.ok, "no pin is not a finding: {unpinned:?}");
        assert!(
            unpinned.detail.contains(&sha),
            "an operator has no value to pin: {}",
            unpinned.detail
        );

        // Hex case is a formatting choice of whoever wrote the policy file.
        assert!(check_binary(Some(&sha.to_uppercase())).ok);

        let wrong = check_binary(Some(&"ab".repeat(32)));
        assert!(!wrong.ok, "a build nobody published passed: {wrong:?}");
        assert!(wrong.detail.contains(&sha), "{}", wrong.detail);
    }

    #[test]
    fn check_and_report_reflects_wiring() {
        let home = wired_claude_home();
        unsafe {
            std::env::set_var("ARGUS_HOME", home.path());
        }
        assert!(
            check_and_report(true, false, None, None, false),
            "fully wired => true"
        );
        // strip one hook, as a tampering developer would
        let path = home.path().join(".claude/settings.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"] = serde_json::json!([]);
        std::fs::write(&path, doc.to_string()).unwrap();
        assert!(
            !check_and_report(true, false, None, None, false),
            "broken wiring => false"
        );
        unsafe {
            std::env::remove_var("ARGUS_HOME");
        }
    }

    /// A repository's hooks run *alongside* the user's, so a broken repository
    /// has to move the exit code on its own — a user-level install that is
    /// perfectly wired must not vote it back to healthy.
    #[test]
    fn a_broken_repository_fails_the_check_a_healthy_user_install_passed() {
        let home = wired_claude_home();
        unsafe {
            std::env::set_var("ARGUS_HOME", home.path());
        }
        let repo = tempfile::tempdir().unwrap();
        // Nothing wired here yet: silent, so every checkout on the machine
        // isn't a failure.
        assert!(check_and_report(
            true,
            false,
            None,
            Some(repo.path()),
            false
        ));

        crate::harness::install_project(repo.path(), false).unwrap();
        assert!(check_and_report(
            true,
            false,
            None,
            Some(repo.path()),
            false
        ));

        let path = repo.path().join(".codex/hooks.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"] = serde_json::json!([]);
        std::fs::write(&path, doc.to_string()).unwrap();
        assert!(!check_and_report(
            true,
            false,
            None,
            Some(repo.path()),
            false
        ));
        unsafe {
            std::env::remove_var("ARGUS_HOME");
        }
    }

    fn set_data_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        std::fs::create_dir_all(dir.path()).unwrap();
        dir
    }

    #[test]
    fn config_flags_when_no_remote_url() {
        let _d = set_data_dir();
        std::fs::write(crate::paths::config_path(), "[capture]\nprompts = true\n").unwrap();
        let f = &check_config(None)[0];
        assert!(!f.ok);
        assert!(
            f.detail.contains("not policy-managed"),
            "detail: {}",
            f.detail
        );
    }

    #[test]
    fn config_flags_when_remote_set_but_no_cache() {
        let _d = set_data_dir();
        std::fs::write(
            crate::paths::config_path(),
            "[remote]\nurl = \"https://p\"\n",
        )
        .unwrap();
        let f = &check_config(None)[0];
        assert!(!f.ok);
        assert!(f.detail.contains("no cache"), "detail: {}", f.detail);
    }

    #[test]
    fn config_ok_when_policy_loaded_and_effective() {
        let _d = set_data_dir();
        std::fs::write(
            crate::paths::config_path(),
            "[remote]\nurl = \"https://p\"\n",
        )
        .unwrap();
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[capture]\ntool_inputs = false\n[redaction]\nenabled = true\n",
        )
        .unwrap();
        let fs = check_config(None);
        assert!(fs.iter().all(|f| f.ok), "expected ok, got {fs:?}");
        assert!(fs[0].detail.contains("effective"));
    }

    #[test]
    fn config_flags_repointed_remote_url() {
        let _d = set_data_dir();
        // user repoints policy to their own permissive server
        std::fs::write(
            crate::paths::config_path(),
            "[remote]\nurl = \"https://evil.example/policy.toml\"\n",
        )
        .unwrap();
        let f = &check_config(Some("https://config.internal/llm.toml"))[0];
        assert!(!f.ok);
        assert!(f.detail.contains("expected"), "detail: {}", f.detail);
    }

    #[test]
    fn config_ok_when_remote_url_matches_expected() {
        let _d = set_data_dir();
        let url = "https://config.internal/llm.toml";
        std::fs::write(
            crate::paths::config_path(),
            format!("[remote]\nurl = \"{url}\"\n"),
        )
        .unwrap();
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[redaction]\nenabled = true\n",
        )
        .unwrap();
        let fs = check_config(Some(url));
        assert!(fs.iter().all(|f| f.ok), "expected ok, got {fs:?}");
    }

    #[test]
    fn local_tamper_is_inert_under_policy() {
        let _d = set_data_dir();
        // A user tries to disable capture locally...
        std::fs::write(
            crate::paths::config_path(),
            "[remote]\nurl = \"https://p\"\n[capture]\ntool_inputs = false\n",
        )
        .unwrap();
        // ...but policy sets it true; remote wins, so the tamper is inert.
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[capture]\ntool_inputs = true\n",
        )
        .unwrap();
        assert!(
            crate::config::load().capture.tool_inputs,
            "policy must override the local tamper"
        );
        let fs = check_config(None);
        assert!(fs.iter().all(|f| f.ok), "policy effective => ok: {fs:?}");
    }

    /// "Not policy-managed" is the right verdict for a laptop with nothing but
    /// its own config, and the wrong one for a host whose administrator chose
    /// to pin the settings locally instead of serving them. Both are fully
    /// deployed; only one of them is a host anybody can reconfigure.
    #[test]
    fn a_machine_wide_config_is_policy_management_even_with_no_remote_url() {
        let d = set_data_dir();
        std::fs::write(crate::paths::config_path(), "[capture]\nprompts = true\n").unwrap();
        assert!(!check_config(None)[0].ok, "no layer, no policy");

        let sys = d.path().join("system.toml");
        std::fs::write(&sys, "[capture]\nprompts = true\n").unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);
        let f = &check_config(None)[0];
        assert!(f.ok, "{f:?}");
        assert!(f.detail.contains("machine-wide config in force"), "{f:?}");
    }

    /// The file being there is not the control — the loader applying it is.
    /// A machine-wide file with a typo in it leaves the host running on the
    /// user's own config while looking, to anyone who goes and reads
    /// `/etc/argus`, entirely governed.
    #[test]
    fn a_machine_wide_config_the_loader_skips_is_broken_not_merely_absent() {
        let d = set_data_dir();
        std::fs::write(
            crate::paths::config_path(),
            "[remote]\nurl = \"https://p\"\n",
        )
        .unwrap();
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[redaction]\nenabled = true\n",
        )
        .unwrap();
        assert!(check_config(None).iter().all(|f| f.ok), "baseline");

        let sys = d.path().join("system.toml");
        std::fs::write(&sys, "[capture\nprompts = true\n").unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);
        let f = &check_config(None)[0];
        assert!(!f.ok, "{f:?}");
        assert!(f.detail.contains("not in force"), "{f:?}");
    }

    /// A host locked down *harder* than the served policy must not be the one
    /// that alerts. The machine-wide layer sits above the remote cache
    /// precisely so an administrator can pin a key beyond the fleet default,
    /// and reporting that as "policy not effective" would train operators to
    /// ignore the finding that catches real tampering.
    #[test]
    fn the_machine_wide_layer_overriding_remote_policy_is_not_a_deviation() {
        let d = set_data_dir();
        std::fs::write(
            crate::paths::config_path(),
            "[remote]\nurl = \"https://p\"\n",
        )
        .unwrap();
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[capture]\nprompts = false\ntool_inputs = true\n",
        )
        .unwrap();
        let sys = d.path().join("system.toml");
        std::fs::write(&sys, "[capture]\nprompts = true\n").unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);

        assert!(
            crate::config::load().capture.prompts,
            "the layer has to actually win for the finding to be about anything"
        );
        let fs = check_config(None);
        assert!(fs.iter().all(|f| f.ok), "{fs:?}");
        assert!(fs[0].detail.contains("machine-wide"), "{fs:?}");
    }

    #[test]
    fn broken_finding_maps_to_warn_severity() {
        let f = Finding {
            tool: "claude-code".into(),
            ok: false,
            detail: "missing hooks: PreToolUse".into(),
        };
        let body = crate::export::to_otlp_body(
            std::slice::from_ref(&finding_event(&f)),
            &crate::export::Resource::default(),
        );
        let rec = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        let attrs = rec["attributes"].as_array().unwrap();
        let has = |k: &str, v: &str| {
            attrs
                .iter()
                .any(|a| a["key"] == k && a["value"]["stringValue"] == v)
        };
        assert!(has("event.type", "integrity"));
        assert!(has("integrity.status", "broken"));
        assert!(has("integrity.tool", "claude-code"));
    }
}
