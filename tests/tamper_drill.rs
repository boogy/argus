//! The drill: every bypass in `docs/threat-model.md`, run for real, against
//! the evidence a SIEM would actually receive.
//!
//! The unit suite proves each control does what its code says. It cannot prove
//! the control *fires* — every one of these tests exercises the assembled
//! product: the installed binary, a real daemon process, a real collector, and
//! the OTLP body that leaves the host. Where a case below fails, an alert in
//! the threat model has stopped working, whatever the unit tests say.
//!
//! Each test is named for its case in the threat model and asserts the alert
//! that document promises (A1–A14). Case 9, "steal the endpoint", is not here:
//! the document itself collapses it into case 1, because a collector pointed
//! somewhere else is a collector that receives nothing.
//!
//! ## What the drill cannot reach
//!
//! Two controls are *enforcement* by the machine-wide layer —
//! `[policy] allow_env_overrides = false` refusing the `ARGUS_*` variables, and
//! `allow_user_uninstall = false` refusing a user-scope uninstall. Both read
//! `/etc/argus/config.toml`, which is deliberately not redirectable outside
//! `cfg(test)`: a layer the watched account can relocate is not a layer. So
//! they cannot be drilled from a test process without root, and are covered
//! instead by `paths::tests` (the override gate) and
//! `install::tests` (the refusal and its record). This is a limit of the drill,
//! not a gap in the control, and it is stated here rather than skipped
//! silently.
//!
//! Unix-only, like `tests/shutdown.rs` and for the same reason: half of these
//! cases are a signal — SIGTERM for a stop that records itself, SIGKILL for one
//! that does not — and Windows has no equivalent to send.
#![cfg(unix)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, atomic::AtomicBool, atomic::Ordering};
use std::time::{Duration, Instant};

/// How long any single wait-for-evidence may take. Generous: CI runners are
/// slow and a flaky drill is a drill nobody runs.
const LIMIT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// The collector
// ---------------------------------------------------------------------------

/// A mock OTLP endpoint that can also be taken away, which is case 3.
struct Collector {
    addr: String,
    rx: Receiver<String>,
    /// Bodies already pulled off the channel, so one test can ask several
    /// questions of the same traffic.
    seen: Vec<String>,
    refusing: Arc<AtomicBool>,
}

impl Collector {
    fn start() -> Collector {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let refusing = Arc::new(AtomicBool::new(false));
        let refuse = refusing.clone();
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                // A refused batch is *not* recorded: the point of case 3 is
                // that the events survive the outage, so a body counted here
                // would be a body the drill could not tell from a delivered
                // one.
                if refuse.load(Ordering::SeqCst) {
                    let _ = req.respond(tiny_http::Response::empty(503));
                    continue;
                }
                let _ = tx.send(body);
                let _ = req.respond(tiny_http::Response::empty(200));
            }
        });
        Collector {
            addr,
            rx,
            seen: Vec::new(),
            refusing,
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Stop taking batches — a firewall rule, from the daemon's side.
    fn refuse(&self, yes: bool) {
        self.refusing.store(yes, Ordering::SeqCst);
    }

    /// Pull everything that has arrived so far, without waiting.
    fn drain(&mut self) {
        while let Ok(body) = self.rx.try_recv() {
            self.seen.push(body);
        }
    }

    /// The first body matching `pred`, waiting up to [`LIMIT`] for one.
    ///
    /// Already-seen bodies are searched first, so the order a test asks its
    /// questions in does not have to match the order the batches arrived.
    fn wait(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        if let Some(body) = self.seen.iter().find(|b| pred(b)) {
            return body.clone();
        }
        let deadline = Instant::now() + LIMIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(body) => {
                    self.seen.push(body.clone());
                    if pred(&body) {
                        return body;
                    }
                }
                Err(RecvTimeoutError::Timeout) => panic!(
                    "no {what} within {LIMIT:?}; {} bodies arrived:\n{}",
                    self.seen.len(),
                    self.seen.join("\n")
                ),
                Err(RecvTimeoutError::Disconnected) => panic!("the collector thread died"),
            }
        }
    }

    /// Assert that nothing matching `pred` shows up in `window`. Used for the
    /// records a tamper is supposed to *prevent*.
    fn never(&mut self, what: &str, window: Duration, pred: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + window;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            match self.rx.recv_timeout(left) {
                Ok(body) => {
                    assert!(!pred(&body), "a {what} arrived after all: {body}");
                    self.seen.push(body);
                }
                Err(_) => return,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reading the evidence
// ---------------------------------------------------------------------------

/// Every attribute in an OTLP body, resource-level and record-level alike, as
/// one flat list. Flat because a SIEM rule is written against the attribute
/// name, not against where in the envelope it happened to be carried.
fn attrs(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut collect = |v: &serde_json::Value| {
        for a in v.as_array().into_iter().flatten() {
            let (Some(k), Some(v)) = (
                a.get("key").and_then(|k| k.as_str()),
                a.get("value")
                    .and_then(|v| v.get("stringValue"))
                    .and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            out.push((k.to_string(), v.to_string()));
        }
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return out;
    };
    for rl in json["resourceLogs"].as_array().into_iter().flatten() {
        collect(&rl["resource"]["attributes"]);
        for sl in rl["scopeLogs"].as_array().into_iter().flatten() {
            for rec in sl["logRecords"].as_array().into_iter().flatten() {
                collect(&rec["attributes"]);
            }
        }
    }
    out
}

/// The first value of `key` in `body`.
fn attr(body: &str, key: &str) -> Option<String> {
    attrs(body)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
}

/// Does `body` carry `key = value`?
fn has(body: &str, key: &str, value: &str) -> bool {
    attrs(body).iter().any(|(k, v)| k == key && v == value)
}

/// A heartbeat with this `health.reason`.
fn heartbeat(reason: &str) -> impl Fn(&str) -> bool + '_ {
    move |body: &str| has(body, "health.reason", reason)
}

// ---------------------------------------------------------------------------
// The sandbox
// ---------------------------------------------------------------------------

/// A throwaway machine: its own home, data directory, socket and copy of
/// argus, so a drill can wire, kill and unwire without touching the developer
/// running it.
struct Sandbox {
    home: tempfile::TempDir,
    data: tempfile::TempDir,
    /// Where the hooks point. A *copy*, so case 7 can overwrite it without
    /// breaking the test binary itself.
    bin: PathBuf,
    _bindir: tempfile::TempDir,
    socket: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let home = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let bindir = tempfile::tempdir().unwrap();

        // One tool for argus to detect. `install` wires what is installed, and
        // an empty home is a host it would correctly leave alone.
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(home.path().join(".claude/settings.json"), "{}\n").unwrap();

        let bin = bindir.path().join("argus");
        std::fs::copy(env!("CARGO_BIN_EXE_argus"), &bin).unwrap();

        // Short by construction: `sun_path` is 104 bytes on macOS, and a
        // socket under a nested temp directory overruns it.
        let socket =
            std::env::temp_dir().join(format!("argus-drill-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);

        Sandbox {
            home,
            data,
            bin,
            _bindir: bindir,
            socket,
        }
    }

    /// Point this sandbox's argus at `collector`, flushing fast enough to
    /// assert on.
    fn configure(&self, collector: &Collector, extra: &str) {
        std::fs::write(
            self.data.path().join("config.toml"),
            format!(
                "[export]\n\
                 otlp_endpoint = \"{}\"\n\
                 flush_interval_secs = 1\n\
                 {extra}",
                collector.endpoint()
            ),
        )
        .unwrap();
    }

    fn config(&self) -> PathBuf {
        self.data.path().join("config.toml")
    }

    /// `Command` for this sandbox's argus, with the host's own `ARGUS_*`
    /// removed so a developer's shell cannot change what the drill measures.
    fn cmd(&self) -> Command {
        self.cmd_with(&self.bin)
    }

    /// The same, for a `prog` other than the one the hooks point at — which is
    /// case 7, where the copy behind the hooks has been replaced and the
    /// question is what a *real* argus says about it.
    fn cmd_with(&self, prog: &Path) -> Command {
        let mut c = Command::new(prog);
        for k in [
            "ARGUS_RECORD_DIR",
            "ARGUS_NO_AUTOSPAWN",
            "ARGUS_SYSTEM_ROOT",
            "ARGUS_LOG",
        ] {
            c.env_remove(k);
        }
        c.env("ARGUS_HOME", self.home.path())
            .env("ARGUS_DATA_DIR", self.data.path())
            .env("ARGUS_SOCKET", &self.socket)
            .env("ARGUS_BIN", &self.bin);
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    /// Run and require success — for the steps that set a case up rather than
    /// the step it is testing.
    fn must(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "argus {args:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// `argus check --hooks`, as an MDM runs it: 0 intact, 2 broken.
    fn check(&self) -> (i32, String) {
        let out = self.run(&["check", "--hooks"]);
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.code().unwrap_or(-1), text)
    }

    fn start_daemon(&self) -> Daemon {
        let child = self
            .cmd()
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the daemon binary must be runnable");
        self.wait_live();
        Daemon { child }
    }

    /// Block until something is accepting on the socket.
    ///
    /// The heartbeat is not a substitute: it says a daemon *started*, and a
    /// `check` racing the bind would report the liveness finding from case 1
    /// and attribute it to whatever the test was actually about.
    fn wait_live(&self) {
        let deadline = Instant::now() + LIMIT;
        while Instant::now() < deadline {
            if std::os::unix::net::UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no daemon accepted on {}", self.socket.display());
    }

    /// Fire one hook, the way a watched agent would.
    fn hook(&self, source: &str, payload: &str) {
        let mut child = self
            .cmd()
            .args(["hook", "--source", source])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        let _ = child.wait();
    }

    /// The supervisor this install wrote.
    fn unit(&self) -> PathBuf {
        let env = argus::detect::Env::host(self.home.path());
        argus::service::user_unit(&env)
    }

    fn settings(&self) -> PathBuf {
        self.home.path().join(".claude/settings.json")
    }
}

/// A daemon process, stoppable the two ways that matter.
struct Daemon {
    child: Child,
}

impl Daemon {
    /// SIGTERM: the stop a service manager performs, and the one argus is
    /// supposed to record on its way out.
    fn terminate(mut self) {
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + LIMIT;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon ignored SIGTERM");
    }

    /// SIGKILL: what an unwilling developer types, and the one case argus
    /// cannot narrate — it can only fail to arrive.
    fn kill(mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Case 1 — kill the daemon
// ---------------------------------------------------------------------------

/// The baseline every other case rests on: a daemon that is running says so,
/// with an identity and a sequence attached (A1's raw material, plus A2/A3).
///
/// Then both stops, told apart. SIGTERM leaves a `health.reason=shutdown`
/// record, so an authorised stop is attributable. SIGKILL leaves nothing —
/// which is the point: the host goes quiet, and A1 is the only thing that
/// fires. A drill that could not show the difference would not be showing that
/// the shutdown record means anything.
#[test]
fn case_1_killing_the_daemon() {
    let sb = Sandbox::new("kill");
    let mut col = Collector::start();
    sb.configure(&col, "");
    sb.must(&["install"]);

    let d = sb.start_daemon();
    let startup = col.wait("startup heartbeat", heartbeat("startup"));
    assert!(
        !attr(&startup, "health.install_id")
            .unwrap_or_default()
            .is_empty(),
        "a heartbeat with no install identity cannot support A2: {startup}"
    );
    assert!(
        attr(&startup, "service.instance.id").is_some(),
        "A2 reads service.instance.id off the resource: {startup}"
    );
    assert!(
        attr(&startup, "argus.batch_seq").is_some(),
        "A3 reads argus.batch_seq off the resource: {startup}"
    );

    // A stop that announces itself.
    d.terminate();
    col.wait("shutdown heartbeat", heartbeat("shutdown"));

    // And one that cannot.
    let d = sb.start_daemon();
    col.wait("second startup heartbeat", |b| {
        has(b, "health.reason", "startup")
    });
    col.drain();
    d.kill();
    col.never(
        "shutdown record after SIGKILL",
        Duration::from_secs(3),
        |b| has(b, "health.reason", "shutdown"),
    );

    // What the endpoint says instead, which is what an MDM would collect: the
    // supervisor is there and the daemon is not.
    let (code, text) = sb.check();
    assert_eq!(
        code, 2,
        "a supervised host with no daemon is broken: {text}"
    );
    assert!(
        text.contains("not reachable"),
        "the finding must name the dead socket: {text}"
    );
}

// ---------------------------------------------------------------------------
// Case 2 — wipe the data directory
// ---------------------------------------------------------------------------

/// `rm -rf ~/.local/share/argus` destroys the buffer, the spool and the
/// install identity in one command. The identity is the point: it comes back
/// different, under the same `host.name`, which is A2 — and the export
/// sequence restarts, which is A3. The threat model's claim is that the two
/// fire *together*, and that is what is asserted here.
#[test]
fn case_2_wiping_the_data_directory() {
    let sb = Sandbox::new("wipe");
    let mut col = Collector::start();
    sb.configure(&col, "");

    let d = sb.start_daemon();
    let before = col.wait("first startup heartbeat", heartbeat("startup"));
    let id_before = attr(&before, "service.instance.id").unwrap();
    let seq_before: u64 = attr(&before, "argus.batch_seq").unwrap().parse().unwrap();
    // Traffic, so the sequence is somewhere a reset is visible from.
    for i in 0..3 {
        sb.hook(
            "claude-code",
            &format!(
                r#"{{"hook_event_name":"PreToolUse","session_id":"wipe-{i}",
                     "tool_name":"Bash","tool_input":{{"command":"echo {i}"}}}}"#
            ),
        );
    }
    let busy = col.wait("an exported tool call", |b| b.contains("wipe-2"));
    let seq_busy: u64 = attr(&busy, "argus.batch_seq").unwrap().parse().unwrap();
    assert!(
        seq_busy > seq_before,
        "the sequence must advance for a gap to mean anything: {seq_before} -> {seq_busy}"
    );
    d.terminate();

    // The bypass.
    for entry in std::fs::read_dir(sb.data.path()).unwrap() {
        let p = entry.unwrap().path();
        if p.file_name().is_some_and(|n| n == "config.toml") {
            continue;
        }
        let _ = std::fs::remove_file(&p);
    }

    let d = sb.start_daemon();
    let after = col.wait("startup heartbeat after the wipe", |b| {
        has(b, "health.reason", "startup")
            && attr(b, "service.instance.id").as_deref() != Some(id_before.as_str())
    });
    let seq_after: u64 = attr(&after, "argus.batch_seq").unwrap().parse().unwrap();
    assert!(
        seq_after < seq_busy,
        "A3 needs the sequence to restart, not continue: {seq_busy} -> {seq_after}"
    );
    d.terminate();
}

// ---------------------------------------------------------------------------
// Case 3 — block the collector
// ---------------------------------------------------------------------------

/// A firewall rule in front of the collector is the cheapest bypass there is,
/// and the only one that needs nothing installed. What it buys is a delay: the
/// events sit in the buffer and the spool, and arrive when the block lifts,
/// carrying their original capture times — which is A6.
///
/// A drill for this has to prove the events were *not* lost, so the collector
/// refuses without recording, and the assertion is on the same session id
/// arriving afterwards.
#[test]
fn case_3_blocking_the_collector() {
    let sb = Sandbox::new("block");
    let mut col = Collector::start();
    sb.configure(&col, "");

    col.refuse(true);
    let d = sb.start_daemon();
    sb.hook(
        "claude-code",
        r#"{"hook_event_name":"PreToolUse","session_id":"blocked-session",
            "tool_name":"Bash","tool_input":{"command":"echo during the outage"}}"#,
    );
    // Long enough for several flush intervals to have been refused.
    col.never("delivery through the block", Duration::from_secs(4), |b| {
        b.contains("blocked-session")
    });

    col.refuse(false);
    let late = col.wait("the delayed batch", |b| b.contains("blocked-session"));
    assert!(
        late.contains("echo during the outage"),
        "the event survived the outage but not intact: {late}"
    );
    d.terminate();
}

// ---------------------------------------------------------------------------
// Case 4 — unwire the tools
// ---------------------------------------------------------------------------

/// `argus uninstall` is the honest bypass, and the one argus answers by
/// reporting itself *before* it unwires: A7. Editing a hook out by hand
/// instead leaves the wiring visibly wrong, which is A8.
///
/// Both halves are here because they are the same bypass at two levels of
/// nerve, and a fleet that only alerted on the polite one would be teaching
/// the impolite one.
#[test]
fn case_4_unwiring_the_tools() {
    let sb = Sandbox::new("unwire");
    let mut col = Collector::start();
    sb.configure(&col, "");
    sb.must(&["install"]);
    // With a daemon, because `install` also writes a supervisor and a
    // supervised host with no daemon is a finding in its own right — that is
    // case 1, and it would otherwise mask everything this case asserts.
    let _d = sb.start_daemon();
    col.wait("startup heartbeat", heartbeat("startup"));
    assert_eq!(sb.check().0, 0, "a fresh install must be intact");

    // A8: the wiring edited rather than removed. Retargeting the command is
    // the version that leaves every file in place and captures nothing.
    let wired = std::fs::read_to_string(sb.settings()).unwrap();
    std::fs::write(
        sb.settings(),
        wired.replace(sb.bin.to_str().unwrap(), "/bin/true"),
    )
    .unwrap();
    let (code, text) = sb.check();
    assert_eq!(code, 2, "a retargeted hook command is broken: {text}");
    std::fs::write(sb.settings(), &wired).unwrap();
    assert_eq!(sb.check().0, 0, "restoring the wiring must clear it");

    // A7: the uninstall reports itself, and the record names the scope.
    let out = sb.must(&["uninstall"]);
    assert!(
        out.contains("reported this uninstall"),
        "uninstall did not claim to have reported itself: {out}"
    );
    let record = col.wait("the uninstall record", |b| {
        has(b, "integrity.status", "uninstalled")
    });
    assert!(
        attr(&record, "integrity.tool")
            .unwrap_or_default()
            .contains("user"),
        "the record must say which scope was unwired: {record}"
    );
    assert!(
        !std::fs::read_to_string(sb.settings())
            .unwrap()
            .contains(sb.bin.to_str().unwrap()),
        "the hooks are still wired after uninstall"
    );
}

// ---------------------------------------------------------------------------
// Case 5 — redirect capture with the environment
// ---------------------------------------------------------------------------

/// One line in `~/.zshrc` used to be enough: the `ARGUS_*` variables are read
/// out of the watched agent's environment. Where the machine-wide layer has
/// not forbidden them, argus honours them and *says so* — the variables in
/// force (A9) and the directory capture actually landed in (A10).
///
/// The drill is necessarily running under overrides itself, which is why the
/// assertion is on *which* variables are named and *where* they pointed, not
/// on the attribute merely being present.
#[test]
fn case_5_redirecting_with_the_environment() {
    let sb = Sandbox::new("envvar");
    let mut col = Collector::start();
    sb.configure(&col, "");

    let elsewhere = tempfile::tempdir().unwrap();
    let mut child = sb
        .cmd()
        .arg("daemon")
        .env("ARGUS_RECORD_DIR", elsewhere.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let hb = col.wait("startup heartbeat", heartbeat("startup"));
    let overrides = attr(&hb, "health.env_overrides").unwrap_or_default();
    assert!(
        overrides.contains("ARGUS_RECORD_DIR"),
        "A9 must name the pre-redaction recording directory: {overrides}"
    );
    assert!(
        overrides.contains("ARGUS_DATA_DIR"),
        "A9 must name the redirected data directory: {overrides}"
    );
    assert_eq!(
        attr(&hb, "health.data_dir").as_deref(),
        sb.data.path().to_str(),
        "A10 compares this against the expected location: {hb}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

// ---------------------------------------------------------------------------
// Case 6 — weaken the policy
// ---------------------------------------------------------------------------

/// Everything about what is captured lives in a file the watched user owns,
/// unless a machine-wide layer outranks it. The layer is out of a test
/// process's reach, but the *detection* is not: the config in force is
/// fingerprinted into every heartbeat, so a host running something other than
/// the fleet's configuration says so on its own. That is A11.
#[test]
fn case_6_weakening_the_policy() {
    let sb = Sandbox::new("policy");
    let mut col = Collector::start();
    sb.configure(&col, "");

    let d = sb.start_daemon();
    let before = col.wait("startup heartbeat", heartbeat("startup"));
    let fp_before = attr(&before, "health.config_fingerprint").unwrap();
    assert!(
        !fp_before.is_empty(),
        "A11 has nothing to compare: {before}"
    );
    d.terminate();

    // The weakening: stop capturing what the developer typed.
    sb.configure(&col, "[capture]\nprompts = false\n");
    let d = sb.start_daemon();
    let after = col.wait("startup heartbeat after the edit", |b| {
        has(b, "health.reason", "startup")
            && attr(b, "health.config_fingerprint").as_deref() != Some(fp_before.as_str())
    });
    assert_ne!(
        attr(&after, "health.config_fingerprint").unwrap(),
        fp_before,
        "an edited config that fingerprints the same is A11 defeated"
    );
    d.terminate();
}

// ---------------------------------------------------------------------------
// Case 7 — replace the binary
// ---------------------------------------------------------------------------

/// The bypass that leaves every check but this one green: keep the hooks, keep
/// the config, keep the unit, and put `#!/bin/sh\nexit 0` where argus was. The
/// hook still fires, the program still resolves, and nothing is captured.
///
/// Content is what gives it away, so both halves of A13 are drilled: the
/// endpoint check against the running binary, and the heartbeat's
/// `binary_pin_ok` against a digest the fleet published.
#[test]
fn case_7_replacing_the_binary() {
    let sb = Sandbox::new("binary");
    let mut col = Collector::start();
    sb.configure(&col, "");
    sb.must(&["install"]);
    // See case 4: the baseline needs a daemon, or the supervisor's own
    // liveness finding answers every `check` in this test.
    let baseline = sb.start_daemon();
    col.wait("startup heartbeat", heartbeat("startup"));
    assert_eq!(sb.check().0, 0, "a fresh install must be intact");
    baseline.terminate();

    // A pin nothing can satisfy: the fleet says one thing, this host runs
    // another.
    let real = env!("CARGO_BIN_EXE_argus");
    sb.configure(
        &col,
        &format!("[integrity]\nbinary_sha256 = \"{}\"\n", "0".repeat(64)),
    );
    let d = sb.start_daemon();
    let hb = col.wait("startup heartbeat under a pin", |b| {
        has(b, "health.reason", "startup") && attr(b, "health.binary_pin_ok").is_some()
    });
    assert_eq!(
        attr(&hb, "health.binary_pin_ok").as_deref(),
        Some("false"),
        "A13's fleet half did not fire: {hb}"
    );
    d.terminate();
    let (code, text) = sb.check();
    assert_eq!(
        code, 2,
        "a host that is not the pinned release is broken: {text}"
    );
    assert!(
        text.contains("pins"),
        "the finding must name the pin as the reason: {text}"
    );

    // And with no pin at all, the weaker statement still holds: whatever the
    // hooks run has to be byte-identical to the argus asking.
    sb.configure(&col, "");
    let unpinned = sb.start_daemon();
    col.wait("startup heartbeat with the pin gone", |b| {
        has(b, "health.reason", "startup") && attr(b, "health.binary_pin_ok").is_none()
    });
    assert_eq!(sb.check().0, 0, "unpinned and untampered must be intact");
    unpinned.terminate();

    // Removed rather than truncated: overwriting a running executable is
    // ETXTBSY, and the replacement an adversary performs is a new file anyway.
    std::fs::remove_file(&sb.bin).unwrap();
    std::fs::write(&sb.bin, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&sb.bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The daemon comes from the untampered binary too — otherwise the stub
    // would answer `daemon`, the liveness probe would fail, and this case's
    // exit code would be explained by case 1 instead of by the digest.
    let mut real_daemon = sb
        .cmd_with(Path::new(real))
        .arg("daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    sb.wait_live();

    let out = sb
        .cmd_with(Path::new(real))
        .args(["check", "--hooks"])
        .output()
        .unwrap();
    let _ = real_daemon.kill();
    let _ = real_daemon.wait();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(2),
        "a shell stub behind the hook passed the check: {text}"
    );
    assert!(
        text.contains("captures nothing"),
        "the finding must say what a wrapped binary costs: {text}"
    );
}

// ---------------------------------------------------------------------------
// Case 8 — remove the supervisor
// ---------------------------------------------------------------------------

/// Delete the unit and the next `pkill argus` is permanent again. The unit is
/// an owned artifact, so removing it, emptying it, or editing the directive
/// that brings the daemon back are all A8 — and the drill checks all three,
/// because the interesting one is the edit that leaves a plausible file
/// behind.
#[test]
fn case_8_removing_the_supervisor() {
    let sb = Sandbox::new("unit");
    let col = Collector::start();
    sb.configure(&col, "");
    sb.must(&["install"]);
    // See case 4: a daemon, so the findings this case makes are the only ones
    // in the answer.
    let _d = sb.start_daemon();
    let unit = sb.unit();
    let good = std::fs::read_to_string(&unit).expect("install wrote no supervisor");
    assert_eq!(sb.check().0, 0, "a fresh install must be intact");

    // Neutered but still loadable: the file is there, the daemon still starts
    // at login, and nothing restarts it.
    let (from, to) = if cfg!(target_os = "macos") {
        ("KeepAlive", "keepAlive")
    } else {
        ("Restart=always", "Restart=no")
    };
    let edited = good.replace(from, to);
    assert_ne!(edited, good, "the {from} mutation did not change the unit");
    std::fs::write(&unit, &edited).unwrap();
    let (code, text) = sb.check();
    assert_eq!(code, 2, "an edited supervisor was accepted: {text}");

    std::fs::write(&unit, "").unwrap();
    assert_eq!(sb.check().0, 2, "an emptied supervisor was accepted");

    std::fs::remove_file(&unit).unwrap();
    let (code, text) = sb.check();
    assert_eq!(code, 2, "a deleted supervisor was accepted: {text}");
    assert!(
        text.contains("daemon"),
        "the finding must name the supervisor: {text}"
    );

    std::fs::write(&unit, &good).unwrap();
    assert_eq!(sb.check().0, 0, "the restored supervisor is still broken");
}

/// Not a bypass — the control on the drill itself. Every case above asserts
/// that a tamper is *caught*; this asserts the untampered host is quiet, which
/// is what makes the other eight mean anything. A `check` that returned 2
/// unconditionally would pass all of them.
#[test]
fn an_untouched_install_is_clean() {
    let sb = Sandbox::new("clean");
    let mut col = Collector::start();
    sb.configure(&col, "");
    sb.must(&["install"]);

    let d = sb.start_daemon();
    let hb = col.wait("startup heartbeat", heartbeat("startup"));
    assert_eq!(
        attr(&hb, "health.checks_broken").as_deref(),
        Some("0"),
        "a fresh install reported findings: {hb}"
    );
    let (code, text) = sb.check();
    assert_eq!(code, 0, "a fresh install is not clean: {text}");
    d.terminate();
    assert!(sb.config().exists());
    assert!(Path::new(&sb.bin).exists());
}
