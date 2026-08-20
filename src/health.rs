//! The daemon saying it is still here.
//!
//! Everything else argus emits is a consequence of the watched tool doing
//! something. That makes every failure of argus itself *silent*: a killed
//! daemon, a deleted data directory, a firewall rule in front of the collector
//! and a laptop nobody opened all arrive at the SIEM as the same thing, which
//! is nothing at all. Three of those four are things a developer who would
//! rather not be monitored can do without any privilege they don't already
//! have.
//!
//! A heartbeat converts them into an alertable absence — *host enrolled, no
//! `argus.health` in N minutes* — and carries with it the state a responder
//! would otherwise have to reach the endpoint to read: what is broken, when
//! that was last checked, which policy is in force, how much is stuck in the
//! queues, and where this daemon was pointed.
//!
//! It cannot defend against a collector that is simply unreachable — a
//! heartbeat that can't be sent is as silent as no heartbeat. That is the
//! point: the alert fires either way, and *why* it fired is answered by the
//! `check` an MDM runs on the endpoint.

use crate::buffer::Buffer;
use crate::config::Config;
use crate::event::{Event, EventKind};
use crate::integrity::SharedSummary;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How many broken findings a heartbeat spells out before summarising.
///
/// The list is a summary — every finding also ships as its own `Integrity`
/// event, in full — and an unbounded join of them would put an arbitrarily long
/// string into an indexed attribute on the one event that is guaranteed to be
/// emitted forever.
const MAX_BROKEN: usize = 20;

/// Everything a heartbeat has to read, held for the life of the daemon.
pub struct Monitor {
    started: Instant,
    buffer: Arc<Buffer>,
    cfg: Arc<RwLock<Config>>,
    summary: SharedSummary,
}

/// The `policy_age_secs` a heartbeat should carry.
///
/// Three states, and a responder needs all three apart: a host with no
/// `remote.url` has no policy to be stale about, so the attribute is absent;
/// a managed host that has never had an answer reports `-1`; one that has
/// reports the seconds since. `-1` rather than a large number because
/// "never" must not be a function of uptime — otherwise a daemon that
/// started a minute ago and a host whose policy URL has been blocked for a
/// month are told apart only by a field the attacker also influences.
fn policy_age_secs(url: Option<&str>, since_last_ok: Option<std::time::Duration>) -> Option<i64> {
    url?;
    Some(since_last_ok.map_or(-1, |d| d.as_secs() as i64))
}

impl Monitor {
    pub fn new(buffer: Arc<Buffer>, cfg: Arc<RwLock<Config>>, summary: SharedSummary) -> Self {
        Monitor {
            started: Instant::now(),
            buffer,
            cfg,
            summary,
        }
    }

    /// Build one heartbeat and put it in the buffer.
    ///
    /// Buffered like any other event rather than sent directly, so it takes the
    /// same path everything else takes: it survives a collector outage, it is
    /// subject to the same batching, and — the reason that matters — a
    /// heartbeat cannot be delivered by a pipeline that would have dropped a
    /// real event.
    pub fn record(&self, reason: &str) {
        if let Err(e) = self.buffer.push(&self.snapshot(reason)) {
            tracing::error!("could not buffer the {reason} heartbeat: {e}");
        }
    }

    fn snapshot(&self, reason: &str) -> Event {
        let (dropped_total, unreadable_total) = self.buffer.loss_totals();
        let (spool_files, spool_bytes) = crate::spool::depth();
        let summary = self
            .summary
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut broken = summary.broken;
        if broken.len() > MAX_BROKEN {
            let rest = broken.len() - MAX_BROKEN;
            broken.truncate(MAX_BROKEN);
            broken.push(format!("(+{rest} more)"));
        }
        let (policy_url, pin) = {
            let cfg = self.cfg.read().unwrap_or_else(|e| e.into_inner());
            (cfg.remote.url.clone(), cfg.integrity.binary_sha256.clone())
        };
        let policy_age_secs = policy_age_secs(
            policy_url.as_deref(),
            crate::config::since_last_policy_fetch(),
        );
        // Empty when this process cannot read its own file — which is itself
        // worth seeing, and better said as a blank than as a digest of nothing.
        let binary_sha256 = crate::harness::own_binary_digest().unwrap_or_default();
        Event::new(
            "argus",
            None,
            None,
            EventKind::Health {
                reason: reason.to_string(),
                // An unreadable `meta` table leaves this empty rather than
                // inventing an identity: a blank id is a fault a collector can
                // see, and a fresh one every heartbeat would look exactly like
                // the wipe this field exists to report.
                install_id: self.buffer.install_id().unwrap_or_default(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                uptime_secs: self.started.elapsed().as_secs(),
                checks_age_secs: summary.checked_at.map(|t| t.elapsed().as_secs()),
                checks_ok: summary.ok,
                broken,
                config_fingerprint: crate::daemon::config_fingerprint(&self.cfg),
                policy_url,
                policy_age_secs,
                // A depth that cannot be read is reported as zero, which is the
                // conservative direction: it understates a backlog rather than
                // inventing one, and a database this daemon cannot count is
                // already going to surface as `dropped`/`unreadable`.
                buffer_events: self.buffer.len().unwrap_or(0),
                buffer_bytes: self.buffer.bytes(),
                spool_files,
                spool_bytes,
                dropped_total,
                unreadable_total,
                data_dir: crate::paths::data_dir().display().to_string(),
                binary: std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                binary_pin_ok: pin.map(|p| p.eq_ignore_ascii_case(&binary_sha256)),
                binary_sha256,
                env_overrides: crate::paths::overrides_in_force(),
            },
        )
    }

    /// Emit one heartbeat every `health.interval_secs`, for as long as this
    /// daemon runs.
    ///
    /// Unconditional by design — no "only when something changed", no "only
    /// when there is other traffic". A quiet host is precisely the case this
    /// exists to distinguish, and a heartbeat that skips quiet periods says
    /// nothing about them.
    ///
    /// The interval is re-read every cycle, so a fleet can shorten it by policy
    /// without restarting anything.
    pub async fn run(self: Arc<Self>) {
        loop {
            let (enabled, interval) = {
                let cfg = self.cfg.read().unwrap_or_else(|e| e.into_inner());
                (cfg.health.enabled, cfg.health.interval_secs.max(30))
            };
            tokio::time::sleep(Duration::from_secs(interval)).await;
            if enabled {
                self.record("interval");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BufferCfg;

    fn tmp() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        dir
    }

    fn monitor(dir: &tempfile::TempDir) -> (Monitor, Arc<Buffer>) {
        monitor_with(dir, Config::default())
    }

    fn monitor_with(dir: &tempfile::TempDir, cfg: Config) -> (Monitor, Arc<Buffer>) {
        let _ = dir;
        let buffer = Arc::new(Buffer::open(&BufferCfg::default()).unwrap());
        let cfg = Arc::new(RwLock::new(cfg));
        let summary = SharedSummary::default();
        (Monitor::new(buffer.clone(), cfg, summary), buffer)
    }

    fn health_of(e: &Event) -> &EventKind {
        assert!(matches!(e.kind, EventKind::Health { .. }));
        &e.kind
    }

    /// The whole point of the thing: a heartbeat lands with no host-tool
    /// traffic whatsoever. Without this, an idle machine and a machine whose
    /// daemon was killed produce identical evidence.
    #[test]
    fn heartbeat_is_emitted_with_no_traffic_at_all() {
        let dir = tmp();
        let (mon, buffer) = monitor(&dir);
        assert_eq!(buffer.len().unwrap(), 0);
        mon.record("interval");
        let batch = buffer.peek_batch(10, 0).unwrap();
        assert_eq!(batch.len(), 1);
        health_of(&batch[0].1);
    }

    /// "Nothing is broken" and "no check has run" are the two states a tamper
    /// alert must separate, and the absence of an age is what separates them.
    #[test]
    fn an_unchecked_daemon_reports_no_check_age() {
        let dir = tmp();
        let (mon, _buffer) = monitor(&dir);
        let e = mon.snapshot("startup");
        let EventKind::Health {
            checks_age_secs,
            checks_ok,
            broken,
            ..
        } = &e.kind
        else {
            panic!("not a health event")
        };
        assert_eq!(*checks_age_secs, None, "no check has run yet");
        assert_eq!(*checks_ok, 0);
        assert!(broken.is_empty());
    }

    /// A check that ran gets an age, and its broken findings ride out on the
    /// schedule that is actually watched.
    #[test]
    fn a_completed_check_is_summarised() {
        let dir = tmp();
        let buffer = Arc::new(Buffer::open(&BufferCfg::default()).unwrap());
        let summary = SharedSummary::default();
        *summary.write().unwrap() = crate::integrity::Summary {
            checked_at: Some(Instant::now()),
            ok: 3,
            broken: vec!["claude-code: hook entry missing".into()],
        };
        let mon = Monitor::new(buffer, Arc::new(RwLock::new(Config::default())), summary);
        let e = mon.snapshot("interval");
        let EventKind::Health {
            checks_age_secs,
            checks_ok,
            broken,
            ..
        } = &e.kind
        else {
            panic!("not a health event")
        };
        assert!(checks_age_secs.is_some());
        assert_eq!(*checks_ok, 3);
        assert_eq!(broken, &["claude-code: hook entry missing"]);
        let _ = dir;
    }

    /// A long finding list is summarised rather than joined without bound: this
    /// attribute is on the one event that is emitted forever.
    #[test]
    fn the_broken_list_is_bounded() {
        let dir = tmp();
        let buffer = Arc::new(Buffer::open(&BufferCfg::default()).unwrap());
        let summary = SharedSummary::default();
        *summary.write().unwrap() = crate::integrity::Summary {
            checked_at: Some(Instant::now()),
            ok: 0,
            broken: (0..MAX_BROKEN + 5).map(|i| format!("t{i}: bad")).collect(),
        };
        let mon = Monitor::new(buffer, Arc::new(RwLock::new(Config::default())), summary);
        let EventKind::Health { broken, .. } = mon.snapshot("interval").kind else {
            panic!("not a health event")
        };
        assert_eq!(broken.len(), MAX_BROKEN + 1);
        assert_eq!(broken.last().unwrap(), "(+5 more)");
        let _ = dir;
    }

    /// An override in the *agent's* environment is how capture gets redirected
    /// at a directory with no daemon behind it. It has to be visible at the
    /// collector, and the value must not be — `ARGUS_RECORD_DIR` names a
    /// directory of pre-redaction envelopes.
    #[test]
    fn env_overrides_are_reported_by_name_only() {
        let dir = tmp();
        let (mon, _buffer) = monitor(&dir);
        let EventKind::Health { env_overrides, .. } = mon.snapshot("interval").kind else {
            panic!("not a health event")
        };
        assert!(
            env_overrides.contains(&"ARGUS_DATA_DIR".to_string()),
            "the override this test set is not reported: {env_overrides:?}"
        );
        let path = dir.path().display().to_string();
        assert!(
            !env_overrides.iter().any(|o| o.contains(&path)),
            "an override *value* leaked into the report: {env_overrides:?}"
        );
    }

    /// On-machine checks compare argus against argus, so a build nobody
    /// published is only visible where the comparison happens somewhere the
    /// machine's owner does not control. The heartbeat is what carries it
    /// there — with a pin, pre-judged; without one, as the raw digest, which
    /// still makes an odd build stand out across a fleet.
    #[test]
    fn the_heartbeat_states_which_binary_is_running() {
        // Held, not dropped: it is the data dir the buffer below opens in.
        let _dir = tmp();
        let buffer = Arc::new(Buffer::open(&BufferCfg::default()).unwrap());
        let cfg = Arc::new(RwLock::new(Config::default()));
        let mon = Monitor::new(buffer, cfg.clone(), SharedSummary::default());

        let EventKind::Health {
            binary_sha256,
            binary_pin_ok,
            ..
        } = mon.snapshot("interval").kind
        else {
            panic!("not a health event")
        };
        assert_eq!(binary_sha256.len(), 64, "not a sha256: {binary_sha256:?}");
        assert_eq!(
            binary_pin_ok, None,
            "nothing is pinned, so nothing to judge"
        );

        cfg.write().unwrap().integrity.binary_sha256 = Some(binary_sha256.to_uppercase());
        let EventKind::Health { binary_pin_ok, .. } = mon.snapshot("interval").kind else {
            panic!("not a health event")
        };
        assert_eq!(binary_pin_ok, Some(true), "hex case decided the answer");

        cfg.write().unwrap().integrity.binary_sha256 = Some("ab".repeat(32));
        let event = mon.snapshot("interval");
        let EventKind::Health { binary_pin_ok, .. } = event.kind else {
            panic!("not a health event")
        };
        assert_eq!(
            binary_pin_ok,
            Some(false),
            "a host running an unpublished build"
        );

        // A field that stops at the event body is invisible to every rule
        // anyone writes, which for this one is the same as not collecting it.
        let event = mon.snapshot("interval");
        let body = crate::export::to_otlp_body(
            std::slice::from_ref(&event),
            &crate::export::Resource::default(),
        );
        let attrs = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"].clone();
        let get = |k: &str| {
            attrs
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].as_str().unwrap().to_string())
        };
        assert_eq!(
            get("health.binary_sha256").as_deref(),
            Some(&*binary_sha256)
        );
        assert_eq!(get("health.binary_pin_ok").as_deref(), Some("false"));
    }

    /// A blocked policy URL is the one policy attack that costs nothing and, as
    /// shipped, signalled nothing: the daemon keeps applying the last cache, the
    /// heartbeat keeps reporting the configured URL, and the fingerprint keeps
    /// matching the fleet. The age of the last successful fetch is what makes a
    /// frozen host distinguishable from a current one.
    #[test]
    fn policy_age_separates_unmanaged_from_never_fetched_from_current() {
        use std::time::Duration;
        assert_eq!(
            policy_age_secs(None, None),
            None,
            "a host with no policy URL has no policy age, and an attribute that \
             is always present cannot be alerted on"
        );
        assert_eq!(
            policy_age_secs(Some("https://policy.example/argus.toml"), None),
            Some(-1),
            "a host that has never fetched is not a host that just fetched"
        );
        assert_eq!(
            policy_age_secs(
                Some("https://policy.example/argus.toml"),
                Some(Duration::from_secs(30))
            ),
            Some(30),
        );
    }

    /// And that the heartbeat actually carries it — both branches. A field
    /// wired to a constant `None` satisfies the unmanaged case while shipping
    /// no signal at all on the managed one, which is the only case the alert
    /// exists for.
    #[test]
    fn the_heartbeat_carries_the_policy_age() {
        let dir = tmp();
        let (mon, _buffer) = monitor(&dir);
        let EventKind::Health {
            policy_age_secs, ..
        } = mon.snapshot("interval").kind
        else {
            panic!("expected a health event");
        };
        assert_eq!(
            policy_age_secs, None,
            "the test monitor configures no remote.url"
        );

        // `LAST_POLICY_OK` is only ever written by `poll_loop`, which no unit
        // test drives, so a managed host reaches this point in the
        // never-fetched state. The third phase below sets it deliberately;
        // this test is the only one that asserts on the field, so the order
        // within it is the whole ordering that matters.
        let managed = || Config {
            remote: crate::config::RemoteCfg {
                url: Some("https://policy.example/argus.toml".into()),
                ..Default::default()
            },
            ..Config::default()
        };
        let (mon, _buffer) = monitor_with(&dir, managed());
        let EventKind::Health {
            policy_age_secs, ..
        } = mon.snapshot("interval").kind
        else {
            panic!("expected a health event");
        };
        assert_eq!(
            policy_age_secs,
            Some(-1),
            "a managed host that has never had an answer must say so; this is \
             the assertion a hardcoded `None` fails"
        );

        // The two assertions above are both satisfied by a field wired to a
        // constant: `None` for the unmanaged host, `-1` for a managed one that
        // has never fetched. Neither reads the clock. This third one is the
        // only assertion that fails if the `since_last_policy_fetch()`
        // argument is replaced by a literal — and a real elapsed age is the
        // entire signal the staleness alert was added for.
        crate::config::set_last_policy_fetch_for_test(std::time::Duration::from_secs(3600));
        let (mon, _buffer) = monitor_with(&dir, managed());
        let EventKind::Health {
            policy_age_secs, ..
        } = mon.snapshot("interval").kind
        else {
            panic!("expected a health event");
        };
        assert_eq!(
            policy_age_secs,
            Some(3600),
            "the seconds since the last successful fetch must reach the \
             heartbeat, not just the never-fetched sentinel"
        );
    }
}
