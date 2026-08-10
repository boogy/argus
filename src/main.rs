use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "argus", version, about = "LLM tool observability agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Hot-path hook shim: reads hook JSON on stdin, forwards to daemon.
    Hook {
        #[arg(long)]
        source: String,
        /// Event-name hint for tools whose payloads carry no event name
        /// (Copilot camelCase payloads).
        #[arg(long)]
        event: Option<String>,
        /// Codex notify passes the event JSON as a positional arg; other
        /// tools pipe it via stdin.
        payload: Option<String>,
    },
    /// Background daemon: parse, redact, buffer, export.
    Daemon,
    /// Wire argus into installed tools.
    Install {
        #[arg(long)]
        dry_run: bool,
        /// Wire this repository instead of the current user: writes
        /// `<dir>/.codex/hooks.json` and nothing else. Machine-level settings
        /// are deliberately excluded — Codex's `[otel]` block carries this
        /// install's receiver token, which must not be committed. The argus
        /// binary still has to be on `PATH` wherever the repository is cloned.
        #[arg(long, value_name = "DIR")]
        project: Option<std::path::PathBuf>,
        /// Wire the whole machine instead of the current user: settings in an
        /// administrator-owned root ordinary users cannot edit away. Needs
        /// root/Administrator. Note that this wires *tools*, not users — the
        /// argus binary must be executable by every account, and each account
        /// needs its own daemon (socket, OTLP port and buffer are per-user).
        #[arg(long, conflicts_with = "project")]
        managed: bool,
    },
    /// Remove argus wiring from tools.
    Uninstall {
        /// Unwire this repository instead of the current user.
        #[arg(long, value_name = "DIR")]
        project: Option<std::path::PathBuf>,
        /// Unwire the machine-wide layer. Needs root/Administrator.
        #[arg(long, conflicts_with = "project")]
        managed: bool,
    },
    /// Show daemon/config status.
    Status,
    /// Developer tool: promote recorded envelopes (ARGUS_RECORD_DIR) into
    /// `tests/fixtures/<harness>/<event>.json`. Hidden because it is only
    /// useful inside a checkout; driven by `make record-fixtures`.
    #[command(hide = true)]
    RecordFixtures {
        #[arg(long, default_value = "target/recordings")]
        from: std::path::PathBuf,
        #[arg(long, default_value = "tests/fixtures")]
        into: std::path::PathBuf,
    },
    /// One-shot integrity self-check for MDM/monitoring (e.g. Jamf, Intune).
    /// Verifies hook wiring AND that remote policy is loaded and effective.
    /// With no flag, checks both. Exits 0 if intact, 2 if anything is broken.
    /// No daemon required.
    Check {
        /// Check only the tool hook/plugin wiring.
        #[arg(long)]
        hooks: bool,
        /// Check only that remote config policy is loaded and effective.
        #[arg(long)]
        config: bool,
        /// Canonical policy URL the monitor (MDM) expects. When set, the config
        /// check fails unless the running remote.url matches it exactly —
        /// catching a removed or repointed remote.url. Pass this from your MDM.
        #[arg(long)]
        remote_url: Option<String>,
        /// Also verify repository-level wiring under this directory. A
        /// repository nothing wired is silent, not broken.
        #[arg(long, value_name = "DIR")]
        project: Option<std::path::PathBuf>,
        /// Also verify the machine-wide layer. Unlike `--project`, a missing
        /// managed artifact is BROKEN: passing this asserts the layer should
        /// be there. Reading it needs no privilege.
        #[arg(long)]
        managed: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        // Must never propagate errors: a failure here must not break the
        // host tool's hook invocation.
        Cmd::Hook {
            source,
            event,
            payload,
        } => argus::hook::run(&source, event.as_deref(), payload.as_deref()),
        Cmd::Daemon => {
            tokio::runtime::Runtime::new()?.block_on(argus::daemon::run())?;
        }
        Cmd::Install {
            dry_run,
            project,
            managed,
        } => match (project, managed) {
            (Some(root), _) => argus::install::run_project(&root, dry_run)?,
            (None, true) => argus::install::run_managed(dry_run)?,
            (None, false) => argus::install::run(dry_run)?,
        },
        Cmd::Uninstall { project, managed } => match (project, managed) {
            (Some(root), _) => argus::install::uninstall_project(&root)?,
            (None, true) => argus::install::uninstall_managed()?,
            (None, false) => argus::install::uninstall()?,
        },
        Cmd::Status => print_status()?,
        Cmd::RecordFixtures { from, into } => {
            let written = argus::record::promote(&from, &into)?;
            for path in &written {
                println!("{}", path.display());
            }
            println!("{} fixture(s) from {}", written.len(), from.display());
        }
        Cmd::Check {
            hooks,
            config,
            remote_url,
            project,
            managed,
        } => {
            // No flag = check everything.
            let (do_hooks, do_config) = if !hooks && !config {
                (true, true)
            } else {
                (hooks, config)
            };
            // Exit code is the contract for monitors: 0 = intact, 2 = broken.
            std::process::exit(
                if argus::integrity::check_and_report(
                    do_hooks,
                    do_config,
                    remote_url.as_deref(),
                    project.as_deref(),
                    managed,
                ) {
                    0
                } else {
                    2
                },
            );
        }
    }
    Ok(())
}

fn print_status() -> Result<()> {
    let data_dir = argus::paths::data_dir();
    println!("data dir: {}", data_dir.display());

    let cfg = argus::config::load();
    println!(
        "config: otlp_endpoint={} batch_size={} flush_interval_secs={} redaction_enabled={}",
        cfg.export.otlp_endpoint.as_deref().unwrap_or("(none)"),
        cfg.export.batch_size,
        cfg.export.flush_interval_secs,
        cfg.redaction.enabled,
    );

    match argus::buffer::Buffer::open(&cfg.buffer).and_then(|b| b.len()) {
        Ok(n) => println!("buffered events: {n}"),
        Err(e) => println!("buffered events: unavailable ({e})"),
    }

    // Which tools argus would wire, and on what evidence. Printing the signal
    // is what makes a surprising result diagnosable: "detected via binary"
    // with no config dir means the tool has never been run, and a lone generic
    // name is not shown here at all because it never counts.
    let detected = argus::detect::detect(&argus::install::home());
    if detected.is_empty() {
        println!("tools: none detected");
    } else {
        for d in &detected {
            println!("tool {}: {} -> {}", d.id, d.why(), d.config_home.display());
        }
    }

    let running = argus::ipc::is_daemon_running();
    println!(
        "daemon socket: {}",
        if running {
            "connected"
        } else {
            "not reachable"
        }
    );

    Ok(())
}
