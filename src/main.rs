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
    },
    /// Remove argus wiring from tools.
    Uninstall,
    /// Show daemon/config status.
    Status,
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
        Cmd::Install { dry_run } => argus::install::run(dry_run)?,
        Cmd::Uninstall => argus::install::uninstall()?,
        Cmd::Status => print_status()?,
        Cmd::Check {
            hooks,
            config,
            remote_url,
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

    match argus::buffer::Buffer::open(cfg.buffer.max_events).and_then(|b| b.len()) {
        Ok(n) => println!("buffered events: {n}"),
        Err(e) => println!("buffered events: unavailable ({e})"),
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
