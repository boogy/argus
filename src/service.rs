//! The daemon's supervisor: the OS unit that starts argus at login and
//! restarts it when it dies.
//!
//! Until this existed the daemon was autospawned by the first hook invocation
//! and by nothing else, so `pkill argus` was a permanent stop: events spooled
//! to the 64 MB cap and were then dropped, and the only thing the collector
//! saw was a host that had gone quiet — which is also what a laptop in a
//! drawer looks like.
//!
//! The unit is written as an ordinary [`Artifact::OwnedFile`] with
//! `exact: true`, which is the whole design. Everything `harness` already does
//! to the opencode plugin — write it, delete it on uninstall, report it
//! missing, empty, or edited by so much as a byte — applies to the supervisor
//! with no new code on the check side. A `KeepAlive` flipped to `false` is a
//! file that is not the file this argus writes.

use crate::detect::{Env, Platform};
use crate::harness::{Artifact, CmdStyle, ConfigDir, quote_program};
use crate::integrity::Finding;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// launchd's reverse-DNS label, also the plist's basename.
pub const LABEL: &str = "io.argus.daemon";

/// systemd's unit name, also the basename of the Windows startup script.
const UNIT: &str = "argus.service";

/// Where the per-user supervisor lives.
///
/// Resolved through [`ConfigDir`] rather than from `home` alone because two of
/// the three locations are environment-rooted for real: systemd reads
/// `$XDG_CONFIG_HOME/systemd/user`, and the Startup folder moves with
/// `%APPDATA%`. A unit written to the directory those variables are *not*
/// pointing at is a supervisor nothing loads — indistinguishable, from the
/// collector, from never having written one.
fn user_dir(platform: Platform) -> (ConfigDir, &'static str) {
    match platform {
        Platform::MacOS => (
            ConfigDir {
                env: None,
                rel: "Library/LaunchAgents",
                platform: None,
            },
            "io.argus.daemon.plist",
        ),
        Platform::Linux => (
            ConfigDir {
                env: Some(("XDG_CONFIG_HOME", "systemd/user")),
                rel: ".config/systemd/user",
                platform: None,
            },
            UNIT,
        ),
        Platform::Windows => (
            ConfigDir {
                env: Some(("APPDATA", STARTUP_REL)),
                rel: "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
                platform: None,
            },
            "argus.cmd",
        ),
    }
}

const STARTUP_REL: &str = "Microsoft/Windows/Start Menu/Programs/Startup";

/// The unit file this user's install owns.
pub fn user_unit(env: &Env) -> PathBuf {
    let (dir, name) = user_dir(env.platform);
    dir.resolve(env).join(name)
}

/// The unit file the machine-wide layer owns.
///
/// macOS gets `/Library/LaunchAgents`, which launchd loads for *every* account
/// at login — the correct managed form, and root-owned. Linux gets
/// `/etc/systemd/user`, the system-wide search path for user units, so one
/// file supervises every account's own daemon rather than a single system
/// service capturing for one uid. Windows gets the all-users Startup folder
/// under `C:\ProgramData`, which is Administrator-owned for the same reason.
pub fn managed_unit(platform: Platform, root: &Path) -> PathBuf {
    let (rel, name) = match platform {
        Platform::MacOS => ("Library/LaunchAgents", "io.argus.daemon.plist"),
        Platform::Linux => ("etc/systemd/user", UNIT),
        Platform::Windows => (
            "ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp",
            "argus.cmd",
        ),
    };
    root.join(rel).join(name)
}

// ---------------------------------------------------------------------------
// The unit text
// ---------------------------------------------------------------------------

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// systemd splits `ExecStart` on whitespace unless the word is quoted, and
/// treats `\` as an escape inside `"`.
fn systemd_quote(exe: &str) -> String {
    if exe
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
    {
        return exe.to_string();
    }
    format!("\"{}\"", exe.replace('\\', "\\\\").replace('"', "\\\""))
}

/// How the program appears *inside the file* — which is what a marker has to
/// match, since markers are tested against the raw text.
fn program_field(platform: Platform, exe: &str) -> String {
    match platform {
        Platform::MacOS => xml_escape(exe),
        Platform::Linux => systemd_quote(exe),
        Platform::Windows => format!("\"{exe}\""),
    }
}

/// The supervisor definition for `platform`, running `exe daemon`.
///
/// Windows gets a Startup-folder script rather than a Scheduled Task: a task
/// lives in a registry-backed store that only `schtasks` can read, so
/// verifying it would mean shelling out and parsing XML on every check, and
/// removing it would mean trusting a subprocess to have run. A `.cmd` file is
/// an artifact — written, deleted and byte-compared by exactly the code that
/// handles every other file argus owns. The cost is real and bounded: no
/// restart-on-crash there, only restart-at-logon. The shim's autospawn still
/// covers a daemon killed mid-session, on the next hook.
pub fn unit_text(platform: Platform, exe: &str) -> String {
    let prog = program_field(platform, exe);
    match platform {
        Platform::MacOS => format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{prog}</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
"#
        ),
        Platform::Linux => format!(
            "[Unit]\n\
             Description=argus AI coding agent observability daemon\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={prog} daemon\n\
             Restart=always\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n"
        ),
        // CRLF: a `.cmd` with bare LF endings is run by cmd.exe with the CR
        // absent rather than stripped, which is fine for these lines and not
        // fine for the next person who edits it. Written the way the platform
        // writes them.
        Platform::Windows => [
            "@echo off",
            "rem argus daemon supervisor — written by `argus install`, removed by `argus uninstall`",
            &format!("start \"argus\" /b {prog} daemon"),
            "",
        ]
        .join("\r\n"),
    }
}

/// The unit as an artifact, so install, uninstall and check all get it from
/// the machinery that already handles every other file argus owns.
///
/// `exact: true` for the same reason the opencode plugin has it: the markers
/// constrain only the substrings they name, and everything else in a
/// supervisor definition — `KeepAlive`, `Restart`, the argument after the
/// program — decides whether the daemon comes back.
fn unit_artifact(platform: Platform, path: PathBuf, exe: &str) -> Artifact {
    Artifact::OwnedFile {
        path,
        contents: Cow::Owned(unit_text(platform, exe)),
        markers: vec![program_field(platform, exe)],
        // Rebuilt POSIX-quoted rather than lifted out of the file: `commands`
        // is never compared against the text, only resolved and digested, and
        // three per-platform quotings of the same path would be three ways for
        // `program_of` to fail to recover it.
        commands: vec![format!("{} daemon", quote_program(exe, CmdStyle::Shell))],
        exact: true,
    }
}

/// The per-user supervisor.
pub fn artifact(env: &Env, exe: &str) -> Artifact {
    unit_artifact(env.platform, user_unit(env), exe)
}

/// The machine-wide supervisor.
pub fn managed_artifact(platform: Platform, root: &Path, exe: &str) -> Artifact {
    unit_artifact(platform, managed_unit(platform, root), exe)
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

/// The commands that make a freshly written unit take effect *now* rather than
/// at the next login, as `(program, args)`.
///
/// Pure, and separate from running them, so the suite can assert what argus
/// would do to a machine without doing it to the machine running the suite.
pub fn activation(platform: Platform, unit: &Path, uid: u32) -> Vec<(String, Vec<String>)> {
    match platform {
        Platform::MacOS => vec![
            // A `bootout` of a label that is not loaded fails, which is why
            // every one of these is best-effort: the pair is "replace whatever
            // is loaded", and the first half is a no-op on a first install.
            (
                "launchctl".into(),
                vec!["bootout".into(), format!("gui/{uid}/{LABEL}")],
            ),
            (
                "launchctl".into(),
                vec![
                    "bootstrap".into(),
                    format!("gui/{uid}"),
                    unit.to_string_lossy().into_owned(),
                ],
            ),
        ],
        Platform::Linux => vec![
            (
                "systemctl".into(),
                vec!["--user".into(), "daemon-reload".into()],
            ),
            (
                "systemctl".into(),
                vec![
                    "--user".into(),
                    "enable".into(),
                    "--now".into(),
                    UNIT.into(),
                ],
            ),
        ],
        // Nothing to activate: the Startup folder is read at logon and has no
        // registration step. It also means nothing starts until the next
        // logon — the shim's autospawn covers the gap.
        Platform::Windows => Vec::new(),
    }
}

/// The inverse, for uninstall. A unit file deleted while its job is still
/// loaded leaves launchd/systemd supervising a path that no longer exists.
pub fn deactivation(platform: Platform, uid: u32) -> Vec<(String, Vec<String>)> {
    match platform {
        Platform::MacOS => vec![(
            "launchctl".into(),
            vec!["bootout".into(), format!("gui/{uid}/{LABEL}")],
        )],
        Platform::Linux => vec![(
            "systemctl".into(),
            vec![
                "--user".into(),
                "disable".into(),
                "--now".into(),
                UNIT.into(),
            ],
        )],
        Platform::Windows => Vec::new(),
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, cannot fail, and touches no memory
    // this process owns.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Whether argus may touch this machine's service manager at all.
///
/// Two independent gates, because getting this wrong once means a test run
/// bootstraps a launchd job on a developer's laptop:
///
/// * `ARGUS_HOME` is set — the install is aimed at a directory that is not
///   this account's home, so the unit written there is a fixture and
///   registering it would supervise the wrong thing. Read raw rather than
///   through [`crate::paths::env_override`]: a machine-wide policy denying
///   overrides must not turn this gate *off*.
/// * `cfg!(test)` — a hard stop for the in-crate suite regardless.
fn may_activate() -> bool {
    !cfg!(test) && std::env::var_os("ARGUS_HOME").is_none()
}

fn run_all(steps: Vec<(String, Vec<String>)>) {
    for (prog, args) in steps {
        let _ = std::process::Command::new(prog)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Load the freshly written user unit. Best-effort: the unit is on disk either
/// way, so the worst case is that supervision begins at the next login rather
/// than now — and an install that failed because `launchctl` was unhappy would
/// be a worse outcome than that.
pub fn activate(env: &Env) {
    if !may_activate() {
        return;
    }
    run_all(activation(env.platform, &user_unit(env), current_uid()));
}

/// Unload it, before the file goes.
pub fn deactivate(env: &Env) {
    if !may_activate() {
        return;
    }
    run_all(deactivation(env.platform, current_uid()));
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

/// The socket probe, answered as "running" for the in-crate suite.
///
/// Every wiring test installs into a temp home, and no daemon is listening on
/// the socket that home derives — so probing for real would turn the liveness
/// finding into a second, unrelated failure in sixty tests about something
/// else. The judgement the probe feeds is what matters and is tested directly:
/// see [`liveness`].
#[cfg(test)]
fn daemon_running() -> bool {
    true
}

#[cfg(not(test))]
fn daemon_running() -> bool {
    crate::ipc::is_daemon_running()
}

/// Is the daemon there, and does it matter that it isn't?
///
/// Kept pure and separate from the probe because the interesting half is the
/// judgement, not the socket. A host with no supervisor is not broken for
/// being idle — the shim starts the daemon on the next hook, which is how
/// argus worked before this module existed, and alerting on it would fire on
/// every host between logins. A host that *has* a supervisor and still has no
/// daemon is the case worth waking somebody for: something stopped it and
/// stopped it from coming back.
pub fn liveness(supervised: bool, running: bool) -> Finding {
    let (ok, detail) = match (running, supervised) {
        (true, _) => (true, "socket reachable".to_string()),
        (false, true) => (
            false,
            format!(
                "supervised by {LABEL} but the socket is not reachable — the daemon was \
                 stopped and did not come back; events are spooling to disk"
            ),
        ),
        (false, false) => (
            true,
            "not running; the hook shim starts it on demand".to_string(),
        ),
    };
    Finding {
        tool: "daemon".into(),
        ok,
        detail,
    }
}

/// Supervisor findings for this user's install.
///
/// `wired` is whether anything else reported at all — the same "this host
/// could have been wired" population [`crate::harness::check`] uses. Without
/// it, a machine that has never run `argus install` would report a missing
/// supervisor as BROKEN forever, and `check` would exit `2` on every host in
/// the fleet that runs no agents. With it, a *removed* unit on a wired host is
/// BROKEN, which is the case this exists to catch.
pub fn check(home: &Path, wired: bool) -> Vec<Finding> {
    let env = Env::host(home);
    let unit = user_unit(&env);
    let mut out = Vec::new();
    if wired {
        let problem =
            crate::harness::verify(&artifact(&env, &crate::harness::install_path())).err();
        out.push(Finding {
            tool: "daemon (service)".into(),
            ok: problem.is_none(),
            detail: problem.unwrap_or_else(|| format!("supervised, {}", unit.display())),
        });
    }
    out.push(liveness(unit.exists(), daemon_running()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_for(platform: Platform, home: &Path) -> Env {
        Env::new(platform, home, Vec::new(), None, Default::default())
    }

    #[test]
    fn each_platform_puts_the_unit_where_its_service_manager_looks() {
        let home = Path::new("/home/dev");
        assert_eq!(
            user_unit(&env_for(Platform::MacOS, home)),
            home.join("Library/LaunchAgents/io.argus.daemon.plist")
        );
        assert_eq!(
            user_unit(&env_for(Platform::Linux, home)),
            home.join(".config/systemd/user/argus.service")
        );
        assert_eq!(
            user_unit(&env_for(Platform::Windows, home)),
            home.join("AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/argus.cmd")
        );
    }

    /// A systemd user unit is rooted at `XDG_CONFIG_HOME`, not at `~/.config`,
    /// and the Startup folder moves with `%APPDATA%`. Writing to the home
    /// directory regardless would leave a file no service manager reads on
    /// exactly the machines that set them.
    #[test]
    fn the_environment_rooted_locations_are_honoured() {
        let mut vars = std::collections::BTreeMap::new();
        vars.insert("XDG_CONFIG_HOME", "/xdg".to_string());
        let env = Env::new(
            Platform::Linux,
            Path::new("/home/dev"),
            Vec::new(),
            None,
            vars,
        );
        assert_eq!(
            user_unit(&env),
            Path::new("/xdg/systemd/user/argus.service")
        );

        let mut vars = std::collections::BTreeMap::new();
        vars.insert("APPDATA", "D:\\roam".to_string());
        let env = Env::new(
            Platform::Windows,
            Path::new("C:\\Users\\dev"),
            Vec::new(),
            None,
            vars,
        );
        // Compared as a path rather than a string: the separator `join`
        // inserts is the *host's*, so a literal expectation would only hold on
        // one of the two platforms that run this test.
        assert_eq!(
            user_unit(&env),
            Path::new("D:\\roam").join(STARTUP_REL).join("argus.cmd")
        );
    }

    #[test]
    fn the_managed_unit_is_the_all_users_location() {
        let root = Path::new("/");
        assert_eq!(
            managed_unit(Platform::MacOS, root),
            Path::new("/Library/LaunchAgents/io.argus.daemon.plist")
        );
        assert_eq!(
            managed_unit(Platform::Linux, root),
            Path::new("/etc/systemd/user/argus.service")
        );
        assert_eq!(
            managed_unit(Platform::Windows, Path::new("C:\\")),
            Path::new("C:\\")
                .join("ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/argus.cmd")
        );
    }

    /// The restart directive is the whole point of the file. A unit that
    /// starts the daemon at login and lets it stay dead afterwards is a
    /// supervisor in name only.
    #[test]
    fn every_unit_asks_for_the_daemon_and_asks_for_it_back() {
        let exe = "/opt/homebrew/bin/argus";
        let mac = unit_text(Platform::MacOS, exe);
        assert!(mac.contains("<key>KeepAlive</key>\n\t<true/>"), "{mac}");
        assert!(mac.contains("<key>RunAtLoad</key>\n\t<true/>"), "{mac}");
        assert!(mac.contains("<string>daemon</string>"), "{mac}");

        let linux = unit_text(Platform::Linux, exe);
        assert!(linux.contains("Restart=always"), "{linux}");
        assert!(
            linux.contains("ExecStart=/opt/homebrew/bin/argus daemon"),
            "{linux}"
        );

        let win = unit_text(Platform::Windows, "C:\\Program Files\\argus\\argus.exe");
        assert!(win.contains("\r\n"), "{win}");
        assert!(
            win.contains("start \"argus\" /b \"C:\\Program Files\\argus\\argus.exe\" daemon"),
            "{win}"
        );
    }

    /// A path with a space in it is the common case on Windows and reachable
    /// on the other two. Each format has its own escape, and getting one wrong
    /// produces a unit that parses and runs the wrong program — or nothing.
    #[test]
    fn a_path_with_a_space_survives_each_format() {
        let linux = unit_text(Platform::Linux, "/opt/my argus/argus");
        assert!(
            linux.contains("ExecStart=\"/opt/my argus/argus\" daemon"),
            "{linux}"
        );
        let mac = unit_text(Platform::MacOS, "/opt/a&b/argus");
        assert!(mac.contains("<string>/opt/a&amp;b/argus</string>"), "{mac}");
    }

    /// The marker is what `verify` reports when the file no longer names our
    /// binary, so it has to be written the way the file stores it — not the
    /// way the command line does.
    #[test]
    fn the_marker_matches_the_text_as_written() {
        for &platform in Platform::ALL {
            let exe = "/opt/my argus/argus";
            let a = unit_artifact(platform, PathBuf::from("/tmp/u"), exe);
            let Artifact::OwnedFile {
                contents, markers, ..
            } = &a
            else {
                panic!("not an OwnedFile")
            };
            for m in markers {
                assert!(
                    contents.contains(m.as_str()),
                    "{platform:?}: {m:?} not in {contents}"
                );
            }
        }
    }

    /// `verify` resolves and digests `commands` without ever looking at the
    /// file, so the stored command has to survive the round trip through
    /// `program_of` on every platform's quoting.
    #[test]
    fn the_stored_command_still_names_the_binary() {
        let exe = "/opt/my argus/argus";
        let a = unit_artifact(Platform::Windows, PathBuf::from("/tmp/u"), exe);
        let Artifact::OwnedFile { commands, .. } = &a else {
            panic!("not an OwnedFile")
        };
        assert_eq!(
            crate::harness::program_of(&commands[0]).as_deref(),
            Some(exe)
        );
    }

    #[test]
    fn a_stopped_daemon_is_only_a_finding_where_something_was_meant_to_restart_it() {
        assert!(liveness(true, true).ok);
        assert!(liveness(false, true).ok);
        // The one that matters: supervised and gone.
        let dead = liveness(true, false);
        assert!(!dead.ok);
        assert!(dead.detail.contains("not reachable"), "{}", dead.detail);
        // Unsupervised and idle is how argus worked before this module, and
        // is not a fleet alert.
        assert!(liveness(false, false).ok);
    }

    /// A wired host with a temp home, an argus stand-in on `ARGUS_BIN`, and a
    /// pinned data directory — the shape every install-side test in the crate
    /// uses.
    fn wired_home() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        tempfile::TempDir,
        crate::paths::DataDir,
    ) {
        let home = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let exe = crate::harness::fake_argus(bin.path(), "argus");
        unsafe {
            std::env::set_var(crate::harness::BIN_ENV, &exe);
            // A systemd unit is rooted at `XDG_CONFIG_HOME` and the Startup
            // folder at `%APPDATA%`; a developer's real values would send this
            // test's writes outside its temp home.
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("APPDATA");
        }
        let guard = crate::paths::DataDir::set(data.path());
        (home, bin, data, guard)
    }

    /// The whole of D1/D2 on the user scope: `install` leaves a supervisor,
    /// `check` reads it, and `uninstall` takes it back out.
    #[test]
    fn install_writes_the_supervisor_and_uninstall_removes_it() {
        let (home, _bin, _data, _guard) = wired_home();
        let env = Env::host(home.path());
        let unit = user_unit(&env);

        crate::harness::install(home.path(), false).unwrap();
        assert!(unit.exists(), "no supervisor at {}", unit.display());
        let f = check(home.path(), true);
        assert!(f.iter().all(|f| f.ok), "freshly installed: {f:?}");

        crate::harness::uninstall(home.path()).unwrap();
        assert!(!unit.exists(), "uninstall left {}", unit.display());
        unsafe { std::env::remove_var(crate::harness::BIN_ENV) };
    }

    /// The reason the unit is an `OwnedFile` rather than a side effect of a
    /// subprocess: every way of neutering it without deleting the file is a
    /// finding, for free, through the same `verify` the opencode plugin gets.
    ///
    /// The edit that matters is the one that survives a reload: neuter the
    /// directive that brings the daemon back and the file still loads, the
    /// daemon still starts at login, and the next `pkill argus` is permanent
    /// again. Each supervisor format spells that directive differently, so the
    /// mutation is picked for the host — a plist key on a systemd unit is a
    /// no-op, and a no-op edit would leave this test asserting nothing.
    #[test]
    fn editing_or_deleting_the_supervisor_is_broken() {
        let (home, _bin, _data, _guard) = wired_home();
        let env = Env::host(home.path());
        let unit = user_unit(&env);
        crate::harness::install(home.path(), false).unwrap();
        let good = std::fs::read_to_string(&unit).unwrap();

        let broken = |what: &str| {
            let f = check(home.path(), true);
            assert!(!f[0].ok, "{what} was accepted as healthy: {f:?}");
            f[0].detail.clone()
        };

        let (from, to) = match Platform::host() {
            Platform::MacOS => ("KeepAlive", "keepAlive"),
            Platform::Linux => ("Restart=always", "Restart=no"),
            // No restart-on-crash to disable there, so the equivalent is the
            // launch itself: commented out, the script still runs at logon and
            // starts nothing.
            Platform::Windows => ("start \"argus\"", "rem start \"argus\""),
        };
        let neutered = good.replace(from, to);
        assert_ne!(
            neutered, good,
            "the {from} mutation did not change the unit"
        );
        std::fs::write(&unit, &neutered).unwrap();
        assert!(broken("a disabled restart directive").contains("does not match"));

        std::fs::write(&unit, "").unwrap();
        assert!(broken("an emptied unit").contains("is empty"));

        std::fs::remove_file(&unit).unwrap();
        assert!(broken("a deleted unit").contains("missing"));

        // And the liveness half goes quiet with it: nothing is supervising the
        // daemon any more, so a stopped daemon is no longer an alert.
        assert_eq!(
            check(home.path(), true).len(),
            2,
            "the supervisor finding must survive the file"
        );

        std::fs::write(&unit, &good).unwrap();
        assert!(check(home.path(), true).iter().all(|f| f.ok));
        unsafe { std::env::remove_var(crate::harness::BIN_ENV) };
    }

    /// A host nobody wired says nothing, or `argus check` would exit `2` on
    /// every machine in the fleet that runs no coding agent.
    #[test]
    fn an_unwired_host_reports_no_supervisor_finding() {
        let (home, _bin, _data, _guard) = wired_home();
        let f = check(home.path(), false);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].tool, "daemon");
        unsafe { std::env::remove_var(crate::harness::BIN_ENV) };
    }

    #[test]
    fn activation_targets_this_session_not_the_next_login() {
        let steps = activation(Platform::MacOS, Path::new("/u.plist"), 501);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[1].0, "launchctl");
        assert_eq!(steps[1].1[1], "gui/501");
        let steps = activation(Platform::Linux, Path::new("/u.service"), 501);
        assert!(steps.iter().any(|(_, a)| a.contains(&"--now".to_string())));
        // The Startup folder has no registration step, so claiming one would
        // be a subprocess that always fails.
        assert!(activation(Platform::Windows, Path::new("/u.cmd"), 0).is_empty());
    }
}
