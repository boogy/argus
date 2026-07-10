#![allow(dead_code)]

mod config;
mod event;
mod hook;
mod ipc;
mod paths;
mod spool;

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

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Hook { source } => hook::run(&source),
        Cmd::Daemon => {}
        Cmd::Install { dry_run } => {
            let _ = dry_run;
        }
        Cmd::Uninstall => {}
        Cmd::Status => {}
    }
}
