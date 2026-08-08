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
/// the loader is `defaults <- local <- remote` with remote winning, a value
/// the policy sets *cannot* be weakened locally — so if the policy is loaded
/// and every policy key is reflected in the effective config, tampering is
/// inert. Findings are raised when:
///   - no `[remote].url` is configured (host isn't policy-managed);
///   - the remote cache is missing (policy never fetched — running on
///     local/defaults) or invalid (skipped by the loader);
///   - any policy key is not reflected in the effective config (policy
///     present but not effective).
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
    let cfg = crate::config::load();
    let url = cfg.remote.url.as_deref();
    if let Some(exp) = expected_url {
        if url != Some(exp) {
            return broken(format!(
                "remote.url is {url:?}, expected {exp} — removed or repointed"
            ));
        }
    } else if url.is_none() {
        return broken(
            "no [remote].url — host is not policy-managed; local config is authoritative".into(),
        );
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
    // Every leaf the policy sets must be reflected in the effective config.
    let effective = crate::config::merged_table();
    let mut deviations = Vec::new();
    diff_leaves("", &policy, &effective, &mut deviations);
    if deviations.is_empty() {
        vec![Finding {
            tool: "config".into(),
            ok: true,
            detail: "remote policy loaded and effective".into(),
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
) -> bool {
    let mut findings = Vec::new();
    if do_hooks {
        let hooks = check(&crate::install::home());
        if hooks.is_empty() {
            println!("hooks: ok (no supported tools detected)");
        }
        findings.extend(hooks);
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

/// Daemon task: periodically self-check wiring and buffer a finding for every
/// *broken* tool (which then exports to the SIEM/collector like any event).
/// Healthy tools emit nothing — an "ok" every interval would be pure noise;
/// whether the daemon itself is alive is answered by `argus check` /
/// process monitoring, not here. A broken finding re-emits each cycle until
/// re-install, keeping the alert live.
pub async fn integrity_loop(shared: Arc<RwLock<Config>>, buffer: Arc<Buffer>) {
    loop {
        let (enabled, interval) = {
            let cfg = shared.read().unwrap();
            (cfg.integrity.enabled, cfg.integrity.interval_secs)
        };
        if enabled {
            for f in check(&crate::install::home()) {
                if !f.ok {
                    tracing::warn!("integrity: {} {}", f.tool, f.detail);
                    if let Err(e) = buffer.push(&finding_event(&f)) {
                        tracing::error!("integrity buffer push failed: {e}");
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(interval.max(30))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A home with Claude Code detected and fully wired (explicit marker, so
    /// the check doesn't depend on the test binary's path).
    fn wired_claude_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        let mut hooks = serde_json::Map::new();
        for ev in crate::harness::claude_code::EVENTS {
            hooks.insert(
                ev.name.into(),
                serde_json::json!([{
                    "hooks": [{ "command": "/opt/argus hook" }],
                    "_argus": true,
                }]),
            );
        }
        std::fs::write(
            claude.join("settings.json"),
            serde_json::to_string(&serde_json::json!({ "hooks": hooks })).unwrap(),
        )
        .unwrap();
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

    #[test]
    fn check_and_report_reflects_wiring() {
        let home = wired_claude_home();
        unsafe {
            std::env::set_var("ARGUS_HOME", home.path());
        }
        assert!(check_and_report(true, false, None), "fully wired => true");
        // strip one hook, as a tampering developer would
        let path = home.path().join(".claude/settings.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"] = serde_json::json!([]);
        std::fs::write(&path, doc.to_string()).unwrap();
        assert!(
            !check_and_report(true, false, None),
            "broken wiring => false"
        );
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

    #[test]
    fn broken_finding_maps_to_warn_severity() {
        let f = Finding {
            tool: "claude-code".into(),
            ok: false,
            detail: "missing hooks: PreToolUse".into(),
        };
        let body = crate::export::to_otlp_body(std::slice::from_ref(&finding_event(&f)));
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
