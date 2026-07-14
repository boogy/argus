//! Wiring self-check (tamper detection).
//!
//! "Is the daemon running" is one question; this answers a different one: is
//! the daemon still *wired into the tools*? A developer who keeps the process
//! alive but deletes the `PreToolUse` hook from `~/.claude/settings.json`
//! makes capture go blind while the process looks healthy — caught here by
//! re-verifying, against the same wiring `install` writes, that every detected
//! tool still carries the `llm-monitor` marker.
//!
//! Two entry points share [`check`]: the daemon's [`integrity_loop`] (pushes
//! `integrity` events to the SIEM) and [`check_and_report`] (the `llm-monitor
//! check` CLI, pulled by an MDM/monitoring agent on the endpoint).

use crate::buffer::Buffer;
use crate::config::Config;
use crate::event::{Event, EventKind};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

const MARKER: &str = "llm-monitor";

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
pub fn check(home: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    if home.join(".claude").exists() {
        out.push(check_json_hooks(
            "claude-code",
            &home.join(".claude/settings.json"),
            crate::install::CC_HOOKS.iter().map(|(e, _)| *e),
        ));
    }
    if home.join(".config/opencode").exists() {
        out.push(check_file(
            "opencode",
            &home.join(".config/opencode/plugin/llm-monitor.ts"),
        ));
    }
    if home.join(".codex").exists() {
        out.push(check_json_hooks(
            "codex",
            &home.join(".codex/hooks.json"),
            crate::install::CODEX_HOOK_EVENTS.iter().map(|(e, _)| *e),
        ));
    }
    let copilot = crate::install::copilot_dir(home);
    if copilot.exists() {
        out.push(check_file("copilot", &copilot.join("hooks/llm-monitor.json")));
    }
    out
}

/// A hooks JSON file (Claude Code `settings.json`, Codex `hooks.json`) is
/// intact only if *every* expected event still carries an llm-monitor entry —
/// so removing even one event's wiring is caught, not just wiping the file.
fn check_json_hooks<'a>(tool: &str, path: &Path, events: impl Iterator<Item = &'a str>) -> Finding {
    let broken = |detail: String| Finding {
        tool: tool.into(),
        ok: false,
        detail,
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return broken(format!("{} unreadable", path.display()));
    };
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    let hooks = &doc["hooks"];
    let missing: Vec<&str> = events
        .filter(|e| !hooks[*e].to_string().contains(MARKER))
        .collect();
    if missing.is_empty() {
        Finding {
            tool: tool.into(),
            ok: true,
            detail: "wired".into(),
        }
    } else {
        broken(format!("missing hooks: {}", missing.join(",")))
    }
}

fn check_file(tool: &str, path: &Path) -> Finding {
    Finding {
        tool: tool.into(),
        ok: path.exists(),
        detail: if path.exists() {
            "present".into()
        } else {
            format!("{} missing", path.display())
        },
    }
}

/// One-shot check for external monitors — e.g. an MDM compliance script (Jamf
/// Extension Attribute / Intune) or any monitoring agent runs `llm-monitor
/// check` on its poll cycle. Prints one line per detected tool and returns
/// whether every tool is intact; the caller maps that to an exit code. No
/// daemon required — this reads the on-disk wiring directly.
pub fn check_and_report() -> bool {
    let findings = check(&crate::install::home());
    if findings.is_empty() {
        println!("llm-monitor: no supported tools detected");
        return true;
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
        "llm-monitor",
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
/// whether the daemon itself is alive is answered by `llm-monitor check` /
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
        for (event, _) in crate::install::CC_HOOKS {
            hooks.insert(
                (*event).into(),
                serde_json::json!([{ "hooks": [{ "command": "/opt/llm-monitor hook" }] }]),
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
        std::env::set_var("LLM_MONITOR_HOME", home.path());
        assert!(check_and_report(), "fully wired => true");
        // strip one hook, as a tampering developer would
        let path = home.path().join(".claude/settings.json");
        let mut doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["hooks"]["PreToolUse"] = serde_json::json!([]);
        std::fs::write(&path, doc.to_string()).unwrap();
        assert!(!check_and_report(), "broken wiring => false");
        std::env::remove_var("LLM_MONITOR_HOME");
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
