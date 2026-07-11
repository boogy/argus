use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "llm-monitor", version, about = "LLM tool observability agent")]
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
        /// Codex notify passes the event JSON as a positional arg; other
        /// tools pipe it via stdin.
        payload: Option<String>,
    },
    /// Background daemon: parse, redact, buffer, export.
    Daemon,
    /// Wire llm-monitor into installed tools.
    Install {
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove llm-monitor wiring from tools.
    Uninstall,
    /// Show daemon/config status.
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        // Must never propagate errors: a failure here must not break the
        // host tool's hook invocation.
        Cmd::Hook { source, payload } => llm_monitor::hook::run(&source, payload.as_deref()),
        Cmd::Daemon => {
            tokio::runtime::Runtime::new()?.block_on(llm_monitor::daemon::run())?;
        }
        Cmd::Install { dry_run } => llm_monitor::install::run(dry_run)?,
        Cmd::Uninstall => llm_monitor::install::uninstall()?,
        Cmd::Status => print_status()?,
    }
    Ok(())
}

fn print_status() -> Result<()> {
    let data_dir = llm_monitor::paths::data_dir();
    println!("data dir: {}", data_dir.display());

    let cfg = llm_monitor::config::load();
    println!(
        "config: otlp_endpoint={} batch_size={} flush_interval_secs={} redaction_enabled={}",
        cfg.export.otlp_endpoint.as_deref().unwrap_or("(none)"),
        cfg.export.batch_size,
        cfg.export.flush_interval_secs,
        cfg.redaction.enabled,
    );

    match llm_monitor::buffer::Buffer::open(cfg.buffer.max_events).and_then(|b| b.len()) {
        Ok(n) => println!("buffered events: {n}"),
        Err(e) => println!("buffered events: unavailable ({e})"),
    }

    let running = llm_monitor::ipc::is_daemon_running();
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
