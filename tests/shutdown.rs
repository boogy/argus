//! How the daemon dies.
//!
//! Everything else in this suite runs `daemon::run` in-process, which cannot
//! observe a signal disposition or an exit status — the two things a service
//! manager judges the daemon by. This one spawns the real binary.
#![cfg(unix)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Wait for `child` to exit, up to `limit`, killing it if it will not.
fn wait_for_exit(
    child: &mut std::process::Child,
    limit: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Two daemons on one endpoint is not a tidiness problem: they drain the same
/// SQLite buffer against each other, and the loser's `bind` unlinks the
/// winner's socket, leaving a live process no hook can reach. The old
/// probe-then-bind guard lost this race often — three of eight rounds left two
/// or three survivors — because the check and the claim were separate
/// syscalls.
#[test]
fn only_one_daemon_survives_a_simultaneous_start() {
    for round in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let sock =
            std::env::temp_dir().join(format!("lm-race-{}-{round}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);

        let mut children: Vec<_> = (0..8)
            .map(|_| {
                Command::new(env!("CARGO_BIN_EXE_argus"))
                    .arg("daemon")
                    .env("ARGUS_DATA_DIR", dir.path())
                    .env("ARGUS_SOCKET", &sock)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("the daemon binary must be runnable")
            })
            .collect();

        // Long enough for every loser to have exited: a daemon that is going
        // to stand down does it during startup, before it ever accepts.
        std::thread::sleep(Duration::from_secs(2));
        let mut alive = 0;
        for c in children.iter_mut() {
            if matches!(c.try_wait(), Ok(None)) {
                alive += 1;
            }
        }
        for mut c in children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_file(&sock);
        assert_eq!(
            alive, 1,
            "round {round}: {alive} daemons are sharing one endpoint and one buffer"
        );
    }
}

/// SIGTERM is how the daemon is stopped everywhere except a developer's
/// terminal: `systemctl stop`, launchd, a container runtime, a package
/// upgrade. Handling only Ctrl-C left that path taking the default
/// disposition — no staged drain, no final flush — so the events lost were
/// the last ones before the machine went down, which is exactly the window
/// the buffer exists to survive.
#[test]
fn sigterm_shuts_the_daemon_down_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let sock = std::env::temp_dir().join(format!("lm-sigterm-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&sock);

    let mut child = Command::new(env!("CARGO_BIN_EXE_argus"))
        .arg("daemon")
        .env("ARGUS_DATA_DIR", dir.path())
        .env("ARGUS_SOCKET", &sock)
        .env("ARGUS_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the daemon binary must be runnable");

    // Up and listening: the socket file is the daemon's own signal that bind
    // succeeded, so nothing here races on a fixed sleep.
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(sock.exists(), "the daemon never bound its socket");

    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .unwrap()
            .success(),
        "could not signal the daemon"
    );

    let status = wait_for_exit(&mut child, Duration::from_secs(10))
        .expect("the daemon ignored SIGTERM and had to be killed");
    assert!(
        status.success(),
        "SIGTERM did not reach the shutdown path: {status:?}. A daemon killed \
         by the signal's default disposition never drains its pipeline or \
         flushes its buffer."
    );

    let mut err = String::new();
    use std::io::Read;
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut err);
    }
    // The same run proves the daemon has a voice at all. Without a subscriber
    // installed, every `tracing` call in the binary is a no-op, and an
    // operator asking why nothing is arriving has nothing to read.
    assert!(
        err.contains("shutdown signal received"),
        "the daemon logged nothing on the way out; stderr was: {err:?}"
    );

    let _ = std::fs::remove_file(&sock);
}
