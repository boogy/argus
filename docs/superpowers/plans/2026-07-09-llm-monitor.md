# llm-monitor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## Context

Security teams have zero visibility into how developers use AI coding tools (Claude Code, opencode, OpenAI Codex): which files agents write, which FQDNs they contact, which skills/agents run, and what prompts users send. Network proxying was rejected in favor of **in-tool hooks/plugins**: all of this data already flows through each tool's extension surface, so a local agent fed by hooks captures it with full fidelity and no TLS MITM.

**llm-monitor** is a single cross-platform Rust binary:

- `llm-monitor hook` — ultra-fast shim invoked by tool hooks; forwards raw JSON to the daemon and exits in ms. Never blocks or breaks the host tool.
- `llm-monitor daemon` — background process: parses events per-tool, extracts file paths/FQDNs/skills/agents/prompts, redacts secrets, buffers durably in SQLite (offline-first), exports OTLP/JSON logs to the security team's existing collector (Splunk/Datadog/Grafana/any OTLP endpoint).
- `llm-monitor install` — detects installed tools and wires each up (Claude Code hooks, opencode TS plugin, Codex OTLP+notify config).
- Config: built-in defaults < local `config.toml` (bootstrap) < remote HTTPS-polled config (cached to disk for offline; ETag-based polling). Remote wins so fleet policy can't be locally weakened.

**Goal:** One Rust binary that observes Claude Code, opencode, and Codex usage via their native hook/plugin surfaces and exports enriched, redacted events to any OTLP backend.

**Architecture:** Hook shim (hot path, IPC or spool fallback) → daemon (adapter parsing → redaction → SQLite buffer → OTLP/JSON export). Cross-platform IPC via `interprocess` (Unix socket / Windows named pipe). No custom server; no OpenTelemetry SDK — OTLP/JSON is hand-rolled for a small, fast binary.

**Tech Stack:** Rust stable, tokio, clap, serde/serde_json, interprocess, rusqlite (bundled), reqwest (rustls), regex, chrono, dirs, tiny_http (dev, mock servers), TypeScript (opencode shim only).

## Global Constraints

- Targets macOS, Linux, Windows. No Unix-only APIs outside `#[cfg(unix)]` blocks; IPC via `interprocess` crate; paths via `dirs` crate.
- Hook hot path budget: < 10 ms typical. `llm-monitor hook` ALWAYS exits 0 (never break the host tool), even on internal error.
- Never blocks/filters prompts or tools — observe only. All enrichment/redaction happens in the daemon, off the user's critical path.
- TLS via rustls only (`reqwest` with `default-features = false, features = ["rustls-tls", "json", "gzip"]`). No OpenSSL.
- Redaction runs before buffering — secrets never touch disk or the network exporter.
- Offline-first: no internet → events accumulate in SQLite (capped, oldest-dropped), config falls back to cached remote copy then local file then defaults.
- Config precedence: defaults < local file < cached-remote < fresh-remote (remote wins; it is fleet policy).
- Commit messages: conventional commits, no co-author or generated-with lines.
- Rust 2021 edition; `cargo fmt` + `cargo clippy -- -D warnings` clean at every commit.

## File Structure

```
llm-monitor/
├── Cargo.toml
├── src/
│   ├── main.rs            # clap CLI dispatch only
│   ├── paths.rs           # per-OS data dir, socket name, spool dir, db path
│   ├── event.rs           # canonical Event model + hook wire Envelope
│   ├── ipc.rs             # cross-platform local-socket client/server framing
│   ├── spool.rs           # JSONL spool fallback (append + drain)
│   ├── hook.rs            # hook subcommand (hot path)
│   ├── config.rs          # layered config, remote poller, disk cache
│   ├── redact.rs          # regex secret scrubbing
│   ├── buffer.rs          # SQLite durable event queue
│   ├── export.rs          # OTLP/JSON log exporter
│   ├── daemon.rs          # daemon assembly: listener, drain, pipeline, shutdown
│   ├── install.rs         # install/uninstall wiring for all three tools
│   └── adapters/
│       ├── mod.rs         # Envelope -> Vec<Event> dispatch + shared extractors
│       ├── claude_code.rs # Claude Code hook payload parsing
│       ├── opencode.rs    # opencode shim payload parsing
│       └── codex.rs       # Codex OTLP/JSON receiver + notify parsing
├── plugins/opencode/llm-monitor.ts   # embedded via include_str! by install
├── tests/
│   └── e2e.rs             # daemon end-to-end: hook -> daemon -> mock collector
└── README.md
```

---

### Task 1: Project scaffold, CLI skeleton, paths module

**Files:**

- Create: `Cargo.toml`, `src/main.rs`, `src/paths.rs`
- Test: unit tests inside `src/paths.rs`

**Interfaces:**

- Produces: `paths::data_dir() -> PathBuf`, `paths::spool_dir() -> PathBuf`, `paths::db_path() -> PathBuf`, `paths::socket_name() -> String`, `paths::config_path() -> PathBuf`, `paths::cached_remote_config_path() -> PathBuf`. All respect env override `LLM_MONITOR_DATA_DIR` (critical for tests). CLI enum `Cmd` with variants `Hook { source: String }`, `Daemon`, `Install { dry_run: bool }`, `Uninstall`, `Status`.

- [ ] **Step 1: Scaffold project and add dependencies**

```bash
cargo init --name llm-monitor
cargo add clap --features derive
cargo add serde --features derive
cargo add serde_json chrono --features chrono/serde
cargo add uuid --features v4
cargo add tokio --features full
cargo add interprocess --features tokio
cargo add rusqlite --features bundled
cargo add reqwest --no-default-features --features rustls-tls,json,gzip
cargo add regex dirs toml anyhow tracing tracing-subscriber
cargo add --dev tiny_http tempfile
```

- [ ] **Step 2: Write failing tests for paths**

In `src/paths.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_respects_env_override() {
        std::env::set_var("LLM_MONITOR_DATA_DIR", "/tmp/lmtest");
        assert_eq!(data_dir(), std::path::PathBuf::from("/tmp/lmtest"));
        std::env::remove_var("LLM_MONITOR_DATA_DIR");
    }

    #[test]
    fn derived_paths_live_under_data_dir() {
        std::env::set_var("LLM_MONITOR_DATA_DIR", "/tmp/lmtest");
        assert_eq!(spool_dir(), data_dir().join("spool"));
        assert_eq!(db_path(), data_dir().join("events.db"));
        assert_eq!(config_path(), data_dir().join("config.toml"));
        assert_eq!(cached_remote_config_path(), data_dir().join("remote-config.cache.toml"));
        assert!(!socket_name().is_empty());
        std::env::remove_var("LLM_MONITOR_DATA_DIR");
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test paths -- --test-threads=1`
Expected: FAIL — functions not defined.

- [ ] **Step 4: Implement `src/paths.rs`**

```rust
use std::path::PathBuf;

pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("LLM_MONITOR_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("llm-monitor")
}

pub fn spool_dir() -> PathBuf { data_dir().join("spool") }
pub fn db_path() -> PathBuf { data_dir().join("events.db") }
pub fn config_path() -> PathBuf { data_dir().join("config.toml") }
pub fn cached_remote_config_path() -> PathBuf { data_dir().join("remote-config.cache.toml") }

/// Name used by `interprocess` local sockets. Filesystem path on Unix,
/// named pipe on Windows. Env override keeps parallel tests isolated.
pub fn socket_name() -> String {
    if let Ok(name) = std::env::var("LLM_MONITOR_SOCKET") {
        return name;
    }
    #[cfg(unix)]
    { data_dir().join("llm-monitor.sock").to_string_lossy().into_owned() }
    #[cfg(windows)]
    { r"\\.\pipe\llm-monitor".to_string() }
}
```

- [ ] **Step 5: Implement `src/main.rs` CLI skeleton**

```rust
mod paths;

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
        Cmd::Hook { source } => { let _ = source; }
        Cmd::Daemon => {}
        Cmd::Install { dry_run } => { let _ = dry_run; }
        Cmd::Uninstall => {}
        Cmd::Status => {}
    }
}
```

- [ ] **Step 6: Verify tests pass and lints are clean**

Run: `cargo test paths -- --test-threads=1 && cargo clippy -- -D warnings && cargo fmt --check`
Expected: PASS (allow `dead_code` warnings by adding `#![allow(dead_code)]` temporarily at top of main.rs — removed in Task 11).

- [ ] **Step 7: Commit**

```bash
git init && git add -A && git commit -m "feat: scaffold llm-monitor CLI with cross-platform paths"
```

---

### Task 2: Canonical event model and hook wire envelope

**Files:**

- Create: `src/event.rs`
- Modify: `src/main.rs` (add `mod event;`)

**Interfaces:**

- Produces:
  - `Envelope { source: String, received_at: DateTime<Utc>, payload: serde_json::Value }` — the raw frame the shim sends over IPC/spool. Shim never parses payloads.
  - `Event { id: String, ts: DateTime<Utc>, host: String, username: String, source: String, session_id: Option<String>, cwd: Option<String>, kind: EventKind }`
  - `EventKind` (serde `tag = "type"`): `Prompt { text: String }`, `ToolUse { tool: String, phase: String, input: Value, files: Vec<String>, fqdns: Vec<String> }`, `Skill { name: String, args: Option<String> }`, `Agent { agent_type: String, description: Option<String> }`, `Session { action: String }`, `Raw { payload: Value }`
  - `Event::new(source: &str, session_id: Option<String>, cwd: Option<String>, kind: EventKind) -> Event` (fills id/ts/host/username)

- [ ] **Step 1: Write failing serde round-trip test**

In `src/event.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_json() {
        let e = Event::new(
            "claude-code",
            Some("sess-1".into()),
            Some("/repo".into()),
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "pre".into(),
                input: serde_json::json!({"file_path": "/repo/a.rs"}),
                files: vec!["/repo/a.rs".into()],
                fqdns: vec![],
            },
        );
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.source, "claude-code");
        assert!(matches!(back.kind, EventKind::ToolUse { .. }));
        assert!(!back.id.is_empty());
        assert!(!back.host.is_empty());
    }

    #[test]
    fn envelope_roundtrips() {
        let env = Envelope {
            source: "opencode".into(),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({"event": "tool.execute.before"}),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.source, "opencode");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test event`
Expected: FAIL — types not defined.

- [ ] **Step 3: Implement `src/event.rs`**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Raw frame sent by the hook shim. The shim never parses tool payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub source: String,
    pub received_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub username: String,
    pub source: String,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Prompt { text: String },
    ToolUse { tool: String, phase: String, input: serde_json::Value, files: Vec<String>, fqdns: Vec<String> },
    Skill { name: String, args: Option<String> },
    Agent { agent_type: String, description: Option<String> },
    Session { action: String },
    Raw { payload: serde_json::Value },
}

impl Event {
    pub fn new(source: &str, session_id: Option<String>, cwd: Option<String>, kind: EventKind) -> Self {
        Event {
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now(),
            host: hostname(),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".into()),
            source: source.to_string(),
            session_id,
            cwd,
            kind,
        }
    }
}

fn hostname() -> String {
    std::process::Command::new(if cfg!(windows) { "hostname" } else { "hostname" })
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test event`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add canonical event model and hook envelope"
```

---

### Task 3: Cross-platform IPC framing

**Files:**

- Create: `src/ipc.rs`
- Modify: `src/main.rs` (add `mod ipc;`)

**Interfaces:**

- Consumes: `paths::socket_name()`, `event::Envelope`
- Produces:
  - `ipc::send(envelope: &Envelope) -> anyhow::Result<()>` — blocking, used by the shim. Connects, writes one newline-delimited JSON frame, flushes, closes.
  - `ipc::Listener::bind() -> anyhow::Result<Listener>` and `Listener::accept_loop(tx: tokio::sync::mpsc::Sender<Envelope>)` — async, used by the daemon. Newline-delimited JSON frames; malformed frames are logged and dropped, never crash the loop.

- [ ] **Step 1: Write failing round-trip test**

In `src/ipc.rs` (tests use a per-test socket via `LLM_MONITOR_SOCKET`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Envelope;

    #[tokio::test]
    async fn shim_send_reaches_daemon_listener() {
        let sock = std::env::temp_dir().join(format!("lm-ipc-{}.sock", std::process::id()));
        std::env::set_var("LLM_MONITOR_SOCKET", &sock);

        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({"hook_event_name": "UserPromptSubmit"}),
        };
        let env2 = env.clone();
        tokio::task::spawn_blocking(move || send(&env2).unwrap()).await.unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.unwrap().unwrap();
        assert_eq!(got.source, "claude-code");
        std::env::remove_var("LLM_MONITOR_SOCKET");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test ipc`
Expected: FAIL — `Listener`/`send` not defined.

- [ ] **Step 3: Implement `src/ipc.rs`**

```rust
use crate::event::Envelope;
use crate::paths;
use anyhow::Result;
use interprocess::local_socket::{
    tokio::{prelude::*, Stream as AsyncStream},
    traits::Stream as _,
    GenericFilePath, ListenerOptions, Stream, ToFsName,
};
use tokio::io::{AsyncBufReadExt, BufReader};

fn name() -> Result<interprocess::local_socket::Name<'static>> {
    Ok(paths::socket_name().to_fs_name::<GenericFilePath>()?.into_owned())
}

/// Blocking one-shot send used by the hook shim hot path.
pub fn send(envelope: &Envelope) -> Result<()> {
    use std::io::Write;
    let mut conn = Stream::connect(name()?)?;
    let mut frame = serde_json::to_vec(envelope)?;
    frame.push(b'\n');
    conn.write_all(&frame)?;
    conn.flush()?;
    Ok(())
}

pub struct Listener {
    inner: interprocess::local_socket::tokio::Listener,
}

impl Listener {
    pub fn bind() -> Result<Self> {
        // Remove a stale socket file left by a crashed daemon (Unix only).
        #[cfg(unix)]
        let _ = std::fs::remove_file(paths::socket_name());
        let inner = ListenerOptions::new().name(name()?).create_tokio()?;
        Ok(Listener { inner })
    }

    pub async fn accept_loop(self, tx: tokio::sync::mpsc::Sender<Envelope>) {
        loop {
            let Ok(conn) = self.inner.accept().await else { continue };
            let tx = tx.clone();
            tokio::spawn(async move { handle(conn, tx).await });
        }
    }
}

async fn handle(conn: AsyncStream, tx: tokio::sync::mpsc::Sender<Envelope>) {
    let mut lines = BufReader::new(conn).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<Envelope>(&line) {
            Ok(env) => { let _ = tx.send(env).await; }
            Err(e) => tracing::warn!("dropping malformed frame: {e}"),
        }
    }
}
```

Note: `interprocess` 2.x API names may differ slightly (`GenericNamespaced` is preferred on Windows — use `ToNsName` under `#[cfg(windows)]` with name `"llm-monitor.sock"`). Adjust to the crate's current API; the test defines correctness.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test ipc`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add cross-platform IPC framing over local sockets"
```

---

### Task 4: Spool fallback (daemon down or busy)

**Files:**

- Create: `src/spool.rs`
- Modify: `src/main.rs` (add `mod spool;`)

**Interfaces:**

- Consumes: `paths::spool_dir()`, `event::Envelope`
- Produces:
  - `spool::append(envelope: &Envelope) -> anyhow::Result<()>` — writes one JSONL line to a unique file `spool/<uuid>.jsonl` (unique file per shim invocation: no cross-process file locking needed).
  - `spool::drain() -> anyhow::Result<Vec<Envelope>>` — reads and DELETES all spool files, returning parsed envelopes; unparseable files are deleted and logged.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Envelope;

    fn setup() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        dir
    }

    #[test]
    fn append_then_drain_returns_envelope_and_empties_spool() {
        let _dir = setup();
        let env = Envelope {
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({"k": "v"}),
        };
        append(&env).unwrap();
        append(&env).unwrap();
        let drained = drain().unwrap();
        assert_eq!(drained.len(), 2);
        assert!(drain().unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test spool -- --test-threads=1`
Expected: FAIL.

- [ ] **Step 3: Implement `src/spool.rs`**

```rust
use crate::event::Envelope;
use crate::paths;
use anyhow::Result;

pub fn append(envelope: &Envelope) -> Result<()> {
    let dir = paths::spool_dir();
    std::fs::create_dir_all(&dir)?;
    let file = dir.join(format!("{}.jsonl", uuid::Uuid::new_v4()));
    std::fs::write(file, serde_json::to_vec(envelope)?)?;
    Ok(())
}

pub fn drain() -> Result<Vec<Envelope>> {
    let dir = paths::spool_dir();
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else { return Ok(out) };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "jsonl") { continue; }
        match std::fs::read_to_string(&path).map_err(anyhow::Error::from)
            .and_then(|s| serde_json::from_str::<Envelope>(&s).map_err(Into::into))
        {
            Ok(env) => out.push(env),
            Err(e) => tracing::warn!("dropping bad spool file {path:?}: {e}"),
        }
        let _ = std::fs::remove_file(&path);
    }
    Ok(out)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test spool -- --test-threads=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add JSONL spool fallback for offline daemon"
```

---

### Task 5: Hook shim (hot path)

**Files:**

- Create: `src/hook.rs`
- Modify: `src/main.rs` (wire `Cmd::Hook` to `hook::run(&source)`)

**Interfaces:**

- Consumes: `ipc::send`, `spool::append`, `event::Envelope`
- Produces: `hook::run(source: &str)` — reads all of stdin (hook JSON), wraps in `Envelope`, tries `ipc::send` with a 250 ms budget; on any failure falls back to `spool::append` and best-effort spawns the daemon detached. NEVER panics, NEVER returns non-zero, prints nothing to stdout (Claude Code interprets hook stdout).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_to_spool_when_no_daemon() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::env::set_var("LLM_MONITOR_SOCKET", dir.path().join("nope.sock"));
        std::env::set_var("LLM_MONITOR_NO_AUTOSPAWN", "1");

        deliver("claude-code", r#"{"hook_event_name":"UserPromptSubmit","prompt":"hi"}"#);

        let drained = crate::spool::drain().unwrap();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].source, "claude-code");
    }

    #[test]
    fn malformed_stdin_is_swallowed_not_panicked() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::env::set_var("LLM_MONITOR_NO_AUTOSPAWN", "1");
        deliver("claude-code", "not json at all"); // must not panic
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test hook -- --test-threads=1`
Expected: FAIL — `deliver` not defined.

- [ ] **Step 3: Implement `src/hook.rs`**

```rust
use crate::event::Envelope;

/// Entry point for `llm-monitor hook --source X`. Must never fail the host tool.
pub fn run(source: &str) {
    let mut input = String::new();
    use std::io::Read;
    let _ = std::io::stdin().read_to_string(&mut input);
    deliver(source, &input);
}

/// Testable core: wrap raw hook text and hand it off. Malformed JSON is
/// preserved as a string payload so nothing is ever lost.
pub fn deliver(source: &str, raw: &str) {
    let payload = serde_json::from_str(raw)
        .unwrap_or_else(|_| serde_json::Value::String(raw.to_string()));
    let envelope = Envelope {
        source: source.to_string(),
        received_at: chrono::Utc::now(),
        payload,
    };
    if crate::ipc::send(&envelope).is_ok() {
        return;
    }
    let _ = crate::spool::append(&envelope);
    autospawn_daemon();
}

fn autospawn_daemon() {
    if std::env::var("LLM_MONITOR_NO_AUTOSPAWN").is_ok() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe)
            .arg("daemon")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}
```

In `src/main.rs`, wire it up: `Cmd::Hook { source } => hook::run(&source),` — and `main` must still end returning `()` so exit code is 0 regardless.

- [ ] **Step 4: Run tests, verify pass, and measure hot path**

Run: `cargo test hook -- --test-threads=1`
Expected: PASS.
Then verify latency: `cargo build --release && echo '{"hook_event_name":"x"}' | time ./target/release/llm-monitor hook --source claude-code`
Expected: well under 50 ms wall clock (release build, spool path).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add hook shim hot path with spool fallback and daemon autospawn"
```

---

### Task 6: Layered config with remote poll + offline cache

**Files:**

- Create: `src/config.rs`
- Modify: `src/main.rs` (add `mod config;`)

**Interfaces:**

- Consumes: `paths::config_path()`, `paths::cached_remote_config_path()`
- Produces:
  - `Config` struct (all fields have defaults):
    ```rust
    pub struct Config {
        pub remote: RemoteCfg,      // url: Option<String>, poll_interval_secs: u64 (300)
        pub export: ExportCfg,      // otlp_endpoint: Option<String>, headers: BTreeMap<String,String>, batch_size: usize (256), flush_interval_secs: u64 (10)
        pub capture: CaptureCfg,    // prompts: bool (true), tool_inputs: bool (true)
        pub redaction: RedactionCfg,// enabled: bool (true), extra_patterns: Vec<String>
        pub buffer: BufferCfg,      // max_events: u64 (100_000)
        pub codex: CodexCfg,        // otlp_listen: String ("127.0.0.1:4327")
    }
    ```
  - `config::load() -> Config` — merge: defaults ← local file ← cached remote (remote wins per policy).
  - `config::fetch_remote(url: &str, etag: Option<&str>) -> anyhow::Result<Option<(String, Option<String>)>>` — async; `None` on HTTP 304; on 200 returns (body, new_etag) and caller caches to disk.
  - `config::poll_loop(shared: Arc<ArcSwap<Config>>-like Arc<RwLock<Config>>)` — daemon task: fetch, validate (must parse as TOML `Config` overlay), write cache atomically, swap in.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_no_files() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        let cfg = load();
        assert!(cfg.redaction.enabled);
        assert!(cfg.capture.prompts);
        assert_eq!(cfg.remote.poll_interval_secs, 300);
        assert_eq!(cfg.codex.otlp_listen, "127.0.0.1:4327");
    }

    #[test]
    fn remote_cache_overrides_local_file() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(crate::paths::config_path(),
            "[capture]\nprompts = true\n[export]\notlp_endpoint = \"http://local:4318\"\n").unwrap();
        std::fs::write(crate::paths::cached_remote_config_path(),
            "[capture]\nprompts = false\n").unwrap();
        let cfg = load();
        assert!(!cfg.capture.prompts, "remote policy must win");
        assert_eq!(cfg.export.otlp_endpoint.as_deref(), Some("http://local:4318"),
            "local keys absent from remote survive");
    }

    #[tokio::test]
    async fn fetch_remote_honors_etag_304() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let has_etag = req.headers().iter()
                    .any(|h| h.field.equiv("If-None-Match"));
                let resp = if has_etag {
                    tiny_http::Response::empty(304)
                } else {
                    tiny_http::Response::from_string("[capture]\nprompts = false\n")
                        .with_status_code(200)
                        .with_header("ETag: \"v1\"".parse::<tiny_http::Header>().unwrap())
                };
                let _ = req.respond(resp);
            }
        });
        let url = format!("http://{addr}/cfg.toml");
        let (body, etag) = fetch_remote(&url, None).await.unwrap().unwrap();
        assert!(body.contains("prompts = false"));
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(fetch_remote(&url, etag.as_deref()).await.unwrap().is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test config -- --test-threads=1`
Expected: FAIL.

- [ ] **Step 3: Implement `src/config.rs`**

```rust
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub remote: RemoteCfg,
    pub export: ExportCfg,
    pub capture: CaptureCfg,
    pub redaction: RedactionCfg,
    pub buffer: BufferCfg,
    pub codex: CodexCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RemoteCfg { pub url: Option<String>, pub poll_interval_secs: u64 }
impl Default for RemoteCfg {
    fn default() -> Self { Self { url: None, poll_interval_secs: 300 } }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ExportCfg {
    pub otlp_endpoint: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CaptureCfg { pub prompts: bool, pub tool_inputs: bool }
impl Default for CaptureCfg { fn default() -> Self { Self { prompts: true, tool_inputs: true } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RedactionCfg { pub enabled: bool, pub extra_patterns: Vec<String> }
impl Default for RedactionCfg { fn default() -> Self { Self { enabled: true, extra_patterns: vec![] } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BufferCfg { pub max_events: u64 }
impl Default for BufferCfg { fn default() -> Self { Self { max_events: 100_000 } } }

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CodexCfg { pub otlp_listen: String }
impl Default for CodexCfg { fn default() -> Self { Self { otlp_listen: "127.0.0.1:4327".into() } } }

/// defaults <- local file <- cached remote (remote is fleet policy, wins).
pub fn load() -> Config {
    let mut merged = toml::Table::new();
    for path in [crate::paths::config_path(), crate::paths::cached_remote_config_path()] {
        if let Ok(text) = std::fs::read_to_string(&path) {
            match text.parse::<toml::Table>() {
                Ok(table) => deep_merge(&mut merged, table),
                Err(e) => tracing::warn!("ignoring invalid config {path:?}: {e}"),
            }
        }
    }
    // Fix batch/flush defaults that Default::default() can't express as non-zero.
    let mut cfg: Config = toml::Table::try_into(merged).unwrap_or_default();
    if cfg.export.batch_size == 0 { cfg.export.batch_size = 256; }
    if cfg.export.flush_interval_secs == 0 { cfg.export.flush_interval_secs = 10; }
    cfg
}

fn deep_merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(bt)), toml::Value::Table(ot)) => deep_merge(bt, ot),
            (_, v) => { base.insert(k, v); }
        }
    }
}

/// Returns Ok(None) on 304; Ok(Some((body, etag))) on 200.
pub async fn fetch_remote(url: &str, etag: Option<&str>) -> anyhow::Result<Option<(String, Option<String>)>> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build()?;
    let mut req = client.get(url);
    if let Some(tag) = etag { req = req.header("If-None-Match", tag); }
    let resp = req.send().await?;
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    let new_etag = resp.headers().get("etag").and_then(|v| v.to_str().ok()).map(String::from);
    let body = resp.text().await?;
    // Validate before caching: a bad remote config must not poison the agent.
    body.parse::<toml::Table>()?;
    Ok(Some((body, new_etag)))
}

/// Daemon task: poll remote config, atomically cache, hot-swap shared config.
pub async fn poll_loop(shared: std::sync::Arc<std::sync::RwLock<Config>>) {
    let mut etag: Option<String> = None;
    loop {
        let (url, interval) = {
            let cfg = shared.read().unwrap();
            (cfg.remote.url.clone(), cfg.remote.poll_interval_secs)
        };
        if let Some(url) = url {
            match fetch_remote(&url, etag.as_deref()).await {
                Ok(Some((body, new_etag))) => {
                    etag = new_etag;
                    let cache = crate::paths::cached_remote_config_path();
                    let tmp = cache.with_extension("tmp");
                    if std::fs::write(&tmp, &body).and_then(|_| std::fs::rename(&tmp, &cache)).is_ok() {
                        *shared.write().unwrap() = load();
                        tracing::info!("remote config applied");
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("remote config fetch failed (using cache): {e}"),
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval.max(30))).await;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test config -- --test-threads=1`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add layered config with remote polling and offline cache"
```

---

### Task 7: Secret redaction engine

**Files:**

- Create: `src/redact.rs`
- Modify: `src/main.rs` (add `mod redact;`)

**Interfaces:**

- Consumes: `config::RedactionCfg`, `event::{Event, EventKind}`
- Produces:
  - `Redactor::new(cfg: &RedactionCfg) -> Redactor` — compiles built-in + extra patterns once (invalid extra patterns logged and skipped).
  - `Redactor::scrub_str(&self, s: &str) -> String` — replaces matches with `[REDACTED:<rule>]`.
  - `Redactor::scrub_event(&self, e: Event) -> Event` — scrubs `Prompt.text`, `ToolUse.input` (recursively over JSON strings), `Skill.args`, `Raw.payload`. Disabled config = identity.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionCfg;

    fn r() -> Redactor { Redactor::new(&RedactionCfg::default()) }

    #[test]
    fn scrubs_common_secrets() {
        let cases = [
            ("key sk-ant-api03-AbCd1234567890abcdef1234 done", "sk-ant"),
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x.y", "Bearer"),
            ("token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 ok", "ghp_"),
            ("AKIAIOSFODNN7EXAMPLE is an aws key id", "AKIA"),
            ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE KEY"),
        ];
        for (input, must_not_survive) in cases {
            let out = r().scrub_str(input);
            assert!(!out.contains(must_not_survive), "leaked in: {out}");
            assert!(out.contains("[REDACTED:"), "no redaction marker in: {out}");
        }
    }

    #[test]
    fn scrubs_nested_tool_input_json() {
        let e = crate::event::Event::new("claude-code", None, None,
            crate::event::EventKind::ToolUse {
                tool: "Bash".into(), phase: "pre".into(),
                input: serde_json::json!({"command": "curl -H 'Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'"}),
                files: vec![], fqdns: vec![],
            });
        let out = r().scrub_event(e);
        let s = serde_json::to_string(&out).unwrap();
        assert!(!s.contains("ghp_AbCdEf"));
    }

    #[test]
    fn extra_patterns_from_config_apply() {
        let cfg = RedactionCfg { enabled: true, extra_patterns: vec!["ACME-[0-9]{6}".into()] };
        let out = Redactor::new(&cfg).scrub_str("badge ACME-123456 end");
        assert!(!out.contains("ACME-123456"));
    }

    #[test]
    fn disabled_is_identity() {
        let cfg = RedactionCfg { enabled: false, extra_patterns: vec![] };
        assert_eq!(Redactor::new(&cfg).scrub_str("sk-ant-api03-AbCd1234567890abcdef1234"),
                   "sk-ant-api03-AbCd1234567890abcdef1234");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test redact`
Expected: FAIL.

- [ ] **Step 3: Implement `src/redact.rs`**

```rust
use crate::config::RedactionCfg;
use crate::event::{Event, EventKind};
use regex::Regex;

pub struct Redactor {
    rules: Vec<(String, Regex)>,
    enabled: bool,
}

const BUILTIN: &[(&str, &str)] = &[
    ("anthropic-key", r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    ("openai-key", r"sk-[A-Za-z0-9_\-]{20,}"),
    ("bearer-token", r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{16,}"),
    ("github-token", r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("aws-access-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("generic-assignment", r#"(?i)(api[_-]?key|secret|password|token)["']?\s*[:=]\s*["'][^"']{8,}["']"#),
];

impl Redactor {
    pub fn new(cfg: &RedactionCfg) -> Self {
        let mut rules: Vec<(String, Regex)> = BUILTIN.iter()
            .filter_map(|(name, p)| Regex::new(p).ok().map(|r| (name.to_string(), r)))
            .collect();
        for p in &cfg.extra_patterns {
            match Regex::new(p) {
                Ok(r) => rules.push(("custom".into(), r)),
                Err(e) => tracing::warn!("skipping invalid redaction pattern {p:?}: {e}"),
            }
        }
        Redactor { rules, enabled: cfg.enabled }
    }

    pub fn scrub_str(&self, s: &str) -> String {
        if !self.enabled { return s.to_string(); }
        let mut out = s.to_string();
        for (name, re) in &self.rules {
            out = re.replace_all(&out, format!("[REDACTED:{name}]")).into_owned();
        }
        out
    }

    fn scrub_json(&self, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => *s = self.scrub_str(s),
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| self.scrub_json(x)),
            serde_json::Value::Object(o) => o.values_mut().for_each(|x| self.scrub_json(x)),
            _ => {}
        }
    }

    pub fn scrub_event(&self, mut e: Event) -> Event {
        if !self.enabled { return e; }
        match &mut e.kind {
            EventKind::Prompt { text } => *text = self.scrub_str(text),
            EventKind::ToolUse { input, .. } => self.scrub_json(input),
            EventKind::Skill { args: Some(a), .. } => *a = self.scrub_str(a),
            EventKind::Raw { payload } => self.scrub_json(payload),
            _ => {}
        }
        e
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test redact`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add regex secret redaction engine"
```

---

### Task 8: SQLite durable event buffer

**Files:**

- Create: `src/buffer.rs`
- Modify: `src/main.rs` (add `mod buffer;`)

**Interfaces:**

- Consumes: `paths::db_path()`, `event::Event`, `config::BufferCfg`
- Produces:
  - `Buffer::open(max_events: u64) -> anyhow::Result<Buffer>` — opens/creates SQLite db, WAL mode, schema `events(seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)`.
  - `Buffer::push(&self, e: &Event) -> anyhow::Result<()>` — inserts; if row count exceeds `max_events`, deletes oldest overflow (drop-oldest policy).
  - `Buffer::peek_batch(&self, n: usize) -> anyhow::Result<Vec<(i64, Event)>>` — oldest-first, does NOT delete.
  - `Buffer::ack(&self, up_to_seq: i64) -> anyhow::Result<()>` — deletes rows `seq <= up_to_seq` (called after successful export only — at-least-once delivery).
  - `Buffer::len(&self) -> anyhow::Result<u64>`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind};

    fn ev(n: u32) -> Event {
        Event::new("claude-code", None, None, EventKind::Prompt { text: format!("p{n}") })
    }

    #[test]
    fn push_peek_ack_cycle() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        let b = Buffer::open(1000).unwrap();
        for i in 0..5 { b.push(&ev(i)).unwrap(); }
        let batch = b.peek_batch(3).unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(b.len().unwrap(), 5, "peek must not delete");
        b.ack(batch.last().unwrap().0).unwrap();
        assert_eq!(b.len().unwrap(), 2);
    }

    #[test]
    fn cap_drops_oldest() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        let b = Buffer::open(3).unwrap();
        for i in 0..5 { b.push(&ev(i)).unwrap(); }
        assert_eq!(b.len().unwrap(), 3);
        let batch = b.peek_batch(10).unwrap();
        let first = serde_json::to_string(&batch[0].1).unwrap();
        assert!(first.contains("p2"), "oldest two dropped, got {first}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test buffer -- --test-threads=1`
Expected: FAIL.

- [ ] **Step 3: Implement `src/buffer.rs`**

```rust
use crate::event::Event;
use anyhow::Result;
use rusqlite::Connection;
use std::sync::Mutex;

pub struct Buffer {
    conn: Mutex<Connection>,
    max_events: u64,
}

impl Buffer {
    pub fn open(max_events: u64) -> Result<Self> {
        std::fs::create_dir_all(crate::paths::data_dir())?;
        let conn = Connection::open(crate::paths::db_path())?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                body TEXT NOT NULL
            );",
        )?;
        Ok(Buffer { conn: Mutex::new(conn), max_events })
    }

    pub fn push(&self, e: &Event) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT INTO events (body) VALUES (?1)", [serde_json::to_string(e)?])?;
        conn.execute(
            "DELETE FROM events WHERE seq <= (
                SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?1
            )",
            [self.max_events],
        )?;
        Ok(())
    }

    pub fn peek_batch(&self, n: usize) -> Result<Vec<(i64, Event)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT seq, body FROM events ORDER BY seq ASC LIMIT ?1")?;
        let rows = stmt.query_map([n as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, body) = row?;
            match serde_json::from_str(&body) {
                Ok(e) => out.push((seq, e)),
                Err(err) => tracing::warn!("skipping corrupt buffered event seq={seq}: {err}"),
            }
        }
        Ok(out)
    }

    pub fn ack(&self, up_to_seq: i64) -> Result<()> {
        self.conn.lock().unwrap()
            .execute("DELETE FROM events WHERE seq <= ?1", [up_to_seq])?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test buffer -- --test-threads=1`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add capped SQLite durable event buffer"
```

---

### Task 9: Claude Code adapter (full-fidelity parsing)

**Files:**

- Create: `src/adapters/mod.rs`, `src/adapters/claude_code.rs`
- Modify: `src/main.rs` (add `mod adapters;`)

**Interfaces:**

- Consumes: `event::{Envelope, Event, EventKind}`
- Produces:
  - `adapters::parse(envelope: Envelope, capture: &config::CaptureCfg) -> Vec<Event>` — dispatches on `envelope.source` (`claude-code` / `opencode` / `codex`); unknown sources → one `Raw` event.
  - `adapters::extract_fqdns(text: &str) -> Vec<String>` — hosts from any `http(s)://` URL in a string, deduped.
  - `adapters::claude_code::parse(payload: &Value, capture: &CaptureCfg) -> Vec<Event>` handling hook events: `UserPromptSubmit` → `Prompt`; `PreToolUse`/`PostToolUse` → `ToolUse` with extracted `files` (Write/Edit/NotebookEdit `file_path`) and `fqdns` (WebFetch `url`, URLs inside Bash `command`); `PreToolUse` with `tool_name == "Skill"` → additional `Skill` event; `tool_name == "Task"`/`"Agent"` → additional `Agent` event (from `tool_input.subagent_type`/`description`); `SessionStart`/`SessionEnd`/`Stop`/`SubagentStop` → `Session`. Unknown hook names → `Raw`. `capture.prompts == false` → prompt text replaced by `"[not captured]"`; `capture.tool_inputs == false` → `input` replaced by `json!(null)`.

- [ ] **Step 1: Write failing tests with real-shaped hook fixtures**

In `src/adapters/claude_code.rs`:

```rust
#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope { source: "claude-code".into(), received_at: chrono::Utc::now(), payload }
    }

    #[test]
    fn user_prompt_submit_becomes_prompt_event() {
        let events = adapters::parse(env(json!({
            "session_id": "abc", "cwd": "/repo",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "refactor the auth module"
        })), &CaptureCfg::default());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].session_id.as_deref(), Some("abc"));
        let EventKind::Prompt { text } = &events[0].kind else { panic!("wrong kind") };
        assert_eq!(text, "refactor the auth module");
    }

    #[test]
    fn write_tool_extracts_file_path() {
        let events = adapters::parse(env(json!({
            "session_id": "abc", "cwd": "/repo",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/repo/src/db.rs", "content": "fn x() {}"}
        })), &CaptureCfg::default());
        let EventKind::ToolUse { tool, files, .. } = &events[0].kind else { panic!() };
        assert_eq!(tool, "Write");
        assert_eq!(files, &vec!["/repo/src/db.rs".to_string()]);
    }

    #[test]
    fn bash_and_webfetch_extract_fqdns() {
        let events = adapters::parse(env(json!({
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": "curl https://evil.example.com/x && wget http://cdn.foo.io/pkg"}
        })), &CaptureCfg::default());
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else { panic!() };
        assert!(fqdns.contains(&"evil.example.com".to_string()));
        assert!(fqdns.contains(&"cdn.foo.io".to_string()));

        let events = adapters::parse(env(json!({
            "hook_event_name": "PreToolUse", "tool_name": "WebFetch",
            "tool_input": {"url": "https://docs.rs/tokio", "prompt": "read"}
        })), &CaptureCfg::default());
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else { panic!() };
        assert_eq!(fqdns, &vec!["docs.rs".to_string()]);
    }

    #[test]
    fn skill_and_agent_tools_emit_dedicated_events() {
        let events = adapters::parse(env(json!({
            "hook_event_name": "PreToolUse", "tool_name": "Skill",
            "tool_input": {"skill": "commit", "args": "-m fix"}
        })), &CaptureCfg::default());
        assert_eq!(events.len(), 2, "ToolUse + Skill");
        assert!(events.iter().any(|e| matches!(&e.kind,
            EventKind::Skill { name, .. } if name == "commit")));

        let events = adapters::parse(env(json!({
            "hook_event_name": "PreToolUse", "tool_name": "Task",
            "tool_input": {"subagent_type": "Explore", "description": "find auth code", "prompt": "..."}
        })), &CaptureCfg::default());
        assert!(events.iter().any(|e| matches!(&e.kind,
            EventKind::Agent { agent_type, .. } if agent_type == "Explore")));
    }

    #[test]
    fn capture_flags_suppress_content() {
        let cfg = CaptureCfg { prompts: false, tool_inputs: false };
        let events = adapters::parse(env(json!({
            "hook_event_name": "UserPromptSubmit", "prompt": "secret plans"
        })), &cfg);
        let EventKind::Prompt { text } = &events[0].kind else { panic!() };
        assert_eq!(text, "[not captured]");

        let events = adapters::parse(env(json!({
            "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": "/repo/a.rs", "content": "secret"}
        })), &cfg);
        let EventKind::ToolUse { input, files, .. } = &events[0].kind else { panic!() };
        assert!(input.is_null(), "content suppressed");
        assert_eq!(files.len(), 1, "metadata (paths) still captured");
    }

    #[test]
    fn session_and_unknown_events() {
        let events = adapters::parse(env(json!({
            "hook_event_name": "SessionStart", "session_id": "abc"
        })), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Session { action } if action == "SessionStart"));

        let events = adapters::parse(env(json!({"hook_event_name": "SomethingNew"})), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test claude_code`
Expected: FAIL.

- [ ] **Step 3: Implement `src/adapters/mod.rs`**

```rust
pub mod claude_code;
pub mod codex;
pub mod opencode;

use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind};

pub fn parse(envelope: Envelope, capture: &CaptureCfg) -> Vec<Event> {
    match envelope.source.as_str() {
        "claude-code" => claude_code::parse(&envelope.payload, capture),
        "opencode" => opencode::parse(&envelope.payload, capture),
        "codex" => codex::parse(&envelope.payload, capture),
        other => vec![Event::new(other, None, None, EventKind::Raw { payload: envelope.payload })],
    }
}

/// Extract deduped hostnames from any http(s) URLs inside a string.
pub fn extract_fqdns(text: &str) -> Vec<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"https?://([^/\s"'<>:]+)"#).unwrap());
    let mut out: Vec<String> = re.captures_iter(text).map(|c| c[1].to_lowercase()).collect();
    out.sort();
    out.dedup();
    out
}
```

(Temporary stubs so it compiles: `opencode::parse` and `codex::parse` return `vec![Event::new(source, None, None, EventKind::Raw { payload: payload.clone() })]` — replaced in Tasks 12–13.)

- [ ] **Step 4: Implement `src/adapters/claude_code.rs`**

```rust
use crate::adapters::extract_fqdns;
use crate::config::CaptureCfg;
use crate::event::{Event, EventKind};
use serde_json::Value;

pub fn parse(p: &Value, capture: &CaptureCfg) -> Vec<Event> {
    let session_id = p.get("session_id").and_then(Value::as_str).map(String::from);
    let cwd = p.get("cwd").and_then(Value::as_str).map(String::from);
    let hook = p.get("hook_event_name").and_then(Value::as_str).unwrap_or("");
    let mk = |kind| Event::new("claude-code", session_id.clone(), cwd.clone(), kind);

    match hook {
        "UserPromptSubmit" => {
            let text = if capture.prompts {
                p.get("prompt").and_then(Value::as_str).unwrap_or("").to_string()
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "PreToolUse" | "PostToolUse" => {
            let tool = p.get("tool_name").and_then(Value::as_str).unwrap_or("unknown").to_string();
            let input = p.get("tool_input").cloned().unwrap_or(Value::Null);
            let files = extract_files(&tool, &input);
            let fqdns = extract_net(&tool, &input);
            let phase = if hook == "PreToolUse" { "pre" } else { "post" }.to_string();
            let kept_input = if capture.tool_inputs { input.clone() } else { Value::Null };
            let mut events = vec![mk(EventKind::ToolUse {
                tool: tool.clone(), phase, input: kept_input, files, fqdns,
            })];
            if hook == "PreToolUse" {
                match tool.as_str() {
                    "Skill" => events.push(mk(EventKind::Skill {
                        name: input.get("skill").and_then(Value::as_str).unwrap_or("unknown").into(),
                        args: input.get("args").and_then(Value::as_str).map(String::from),
                    })),
                    "Task" | "Agent" => events.push(mk(EventKind::Agent {
                        agent_type: input.get("subagent_type").and_then(Value::as_str)
                            .unwrap_or("general-purpose").into(),
                        description: input.get("description").and_then(Value::as_str).map(String::from),
                    })),
                    _ => {}
                }
            }
            events
        }
        "SessionStart" | "SessionEnd" | "Stop" | "SubagentStop" | "PreCompact" | "Notification" => {
            vec![mk(EventKind::Session { action: hook.to_string() })]
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

fn extract_files(tool: &str, input: &Value) -> Vec<String> {
    match tool {
        "Write" | "Edit" | "NotebookEdit" | "Read" => input
            .get("file_path").or_else(|| input.get("notebook_path"))
            .and_then(Value::as_str).map(|s| vec![s.to_string()]).unwrap_or_default(),
        _ => vec![],
    }
}

fn extract_net(tool: &str, input: &Value) -> Vec<String> {
    match tool {
        "WebFetch" => input.get("url").and_then(Value::as_str)
            .map(extract_fqdns).unwrap_or_default(),
        "Bash" => input.get("command").and_then(Value::as_str)
            .map(extract_fqdns).unwrap_or_default(),
        _ => vec![],
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test claude_code && cargo test adapters`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: add Claude Code hook adapter with file/fqdn/skill/agent extraction"
```

---

### Task 10: OTLP/JSON log exporter

**Files:**

- Create: `src/export.rs`
- Modify: `src/main.rs` (add `mod export;`)

**Interfaces:**

- Consumes: `event::Event`, `config::ExportCfg`
- Produces:
  - `export::to_otlp_body(events: &[Event]) -> serde_json::Value` — OTLP/HTTP JSON `ExportLogsServiceRequest`: one `resourceLogs` entry with resource attrs (`service.name = "llm-monitor"`, `host.name`, `user.name`), one `logRecord` per event with `timeUnixNano`, `severityText: "INFO"`, `body.stringValue` = event JSON, and flat attributes (`event.type`, `source`, `session.id`, `tool.name`, `skill.name`, `agent.type`, `file.paths`, `net.fqdns` — present when applicable).
  - `Exporter::new(cfg: &ExportCfg) -> Exporter`
  - `Exporter::export(&self, events: &[Event]) -> anyhow::Result<()>` — POST `{otlp_endpoint}/v1/logs`, JSON, custom headers from config (e.g. auth), 15 s timeout; `Err` on non-2xx (caller keeps events buffered — at-least-once).

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind};

    #[test]
    fn otlp_body_shape_is_valid() {
        let e = Event::new("claude-code", Some("s1".into()), None,
            EventKind::ToolUse { tool: "Write".into(), phase: "pre".into(),
                input: serde_json::json!({}), files: vec!["/a.rs".into()], fqdns: vec![] });
        let body = to_otlp_body(std::slice::from_ref(&e));
        let records = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert_eq!(records.as_array().unwrap().len(), 1);
        let rec = &records[0];
        assert!(rec["timeUnixNano"].is_string());
        let attrs = rec["attributes"].as_array().unwrap();
        let get = |k: &str| attrs.iter().find(|a| a["key"] == k)
            .map(|a| a["value"]["stringValue"].as_str().unwrap().to_string());
        assert_eq!(get("event.type").as_deref(), Some("tool_use"));
        assert_eq!(get("tool.name").as_deref(), Some("Write"));
        assert_eq!(get("session.id").as_deref(), Some("s1"));
    }

    #[tokio::test]
    async fn export_posts_to_v1_logs_and_errors_on_500() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let mut body = String::new();
                use std::io::Read;
                let _ = req.as_reader().read_to_string(&mut body);
                let url = req.url().to_string();
                let status = if tx.send(url.clone()).is_ok() && url == "/v1/logs" { 200 } else { 500 };
                let _ = req.respond(tiny_http::Response::empty(status));
            }
        });
        let cfg = crate::config::ExportCfg {
            otlp_endpoint: Some(format!("http://{addr}")),
            ..Default::default()
        };
        let exporter = Exporter::new(&cfg);
        let e = Event::new("codex", None, None, EventKind::Session { action: "start".into() });
        exporter.export(std::slice::from_ref(&e)).await.unwrap();
        assert_eq!(rx.recv().unwrap(), "/v1/logs");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test export`
Expected: FAIL.

- [ ] **Step 3: Implement `src/export.rs`**

```rust
use crate::config::ExportCfg;
use crate::event::{Event, EventKind};
use anyhow::{Context, Result};
use serde_json::{json, Value};

pub fn to_otlp_body(events: &[Event]) -> Value {
    let (host, user) = events.first()
        .map(|e| (e.host.clone(), e.username.clone()))
        .unwrap_or_default();
    let records: Vec<Value> = events.iter().map(record).collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                attr("service.name", "llm-monitor"),
                attr("host.name", &host),
                attr("user.name", &user),
            ]},
            "scopeLogs": [{
                "scope": { "name": "llm-monitor", "version": env!("CARGO_PKG_VERSION") },
                "logRecords": records
            }]
        }]
    })
}

fn attr(k: &str, v: &str) -> Value {
    json!({ "key": k, "value": { "stringValue": v } })
}

fn record(e: &Event) -> Value {
    let mut attrs = vec![attr("source", &e.source)];
    if let Some(s) = &e.session_id { attrs.push(attr("session.id", s)); }
    if let Some(c) = &e.cwd { attrs.push(attr("cwd", c)); }
    let event_type = match &e.kind {
        EventKind::Prompt { .. } => "prompt",
        EventKind::ToolUse { tool, files, fqdns, .. } => {
            attrs.push(attr("tool.name", tool));
            if !files.is_empty() { attrs.push(attr("file.paths", &files.join(","))); }
            if !fqdns.is_empty() { attrs.push(attr("net.fqdns", &fqdns.join(","))); }
            "tool_use"
        }
        EventKind::Skill { name, .. } => { attrs.push(attr("skill.name", name)); "skill" }
        EventKind::Agent { agent_type, .. } => { attrs.push(attr("agent.type", agent_type)); "agent" }
        EventKind::Session { action } => { attrs.push(attr("session.action", action)); "session" }
        EventKind::Raw { .. } => "raw",
    };
    attrs.insert(0, attr("event.type", event_type));
    json!({
        "timeUnixNano": (e.ts.timestamp_nanos_opt().unwrap_or(0)).to_string(),
        "severityText": "INFO",
        "body": { "stringValue": serde_json::to_string(e).unwrap_or_default() },
        "attributes": attrs
    })
}

pub struct Exporter {
    client: reqwest::Client,
    endpoint: Option<String>,
    headers: std::collections::BTreeMap<String, String>,
}

impl Exporter {
    pub fn new(cfg: &ExportCfg) -> Self {
        Exporter {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build().expect("reqwest client"),
            endpoint: cfg.otlp_endpoint.clone(),
            headers: cfg.headers.clone(),
        }
    }

    pub async fn export(&self, events: &[Event]) -> Result<()> {
        let endpoint = self.endpoint.as_ref().context("no otlp_endpoint configured")?;
        let mut req = self.client
            .post(format!("{}/v1/logs", endpoint.trim_end_matches('/')))
            .json(&to_otlp_body(events));
        for (k, v) in &self.headers { req = req.header(k, v); }
        req.send().await?.error_for_status()?;
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test export`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add OTLP/JSON log exporter"
```

---

### Task 11: Daemon assembly + end-to-end integration test

**Files:**

- Create: `src/daemon.rs`, `tests/e2e.rs`
- Modify: `src/main.rs` (wire `Cmd::Daemon` and `Cmd::Status`; make modules `pub` and add `src/lib.rs` OR keep binary-only and put the e2e test behind `assert_cmd`-style process spawning — choose: add `src/lib.rs` re-exporting all modules, `main.rs` uses the lib; remove the temporary `#![allow(dead_code)]`)

**Interfaces:**

- Consumes: everything from Tasks 3–10.
- Produces: `daemon::run() -> anyhow::Result<()>`:
  1. Single-instance guard: try `ipc::Listener::bind()`; if the name is taken, another daemon is running → exit 0.
  2. Load `config::load()` into `Arc<RwLock<Config>>`; spawn `config::poll_loop`.
  3. Spawn IPC accept loop → mpsc channel of `Envelope`.
  4. Spawn spool drain tick (every 5 s: `spool::drain()` → same channel).
  5. Spawn Codex OTLP listener (Task 13 fills in; stub logs and drops until then).
  6. Pipeline task: for each `Envelope` → `adapters::parse` → `Redactor::scrub_event` (rebuild redactor when config generation changes) → `Buffer::push`.
  7. Export task: every `flush_interval_secs` or when buffer ≥ `batch_size`: `peek_batch` → `Exporter::export` → `ack` on success; exponential backoff (max 5 min) on failure.
  8. Graceful shutdown on ctrl-c: flush one final batch.

- [ ] **Step 1: Convert to lib+bin layout**

Create `src/lib.rs`:

```rust
pub mod adapters;
pub mod buffer;
pub mod config;
pub mod daemon;
pub mod event;
pub mod export;
pub mod hook;
pub mod install;
pub mod ipc;
pub mod paths;
pub mod redact;
pub mod spool;
```

(`install` gets a stub `pub fn run(_dry_run: bool) {}` / `pub fn uninstall() {}` until Task 14.) `src/main.rs` becomes a thin dispatcher over `llm_monitor::…`.

- [ ] **Step 2: Write failing e2e test**

`tests/e2e.rs`:

```rust
use llm_monitor::event::Envelope;

#[tokio::test]
async fn hook_event_flows_to_mock_collector() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
    std::env::set_var("LLM_MONITOR_SOCKET",
        std::env::temp_dir().join(format!("lm-e2e-{}.sock", std::process::id())));

    // Mock OTLP collector.
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_string();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for mut req in server.incoming_requests() {
            let mut body = String::new();
            use std::io::Read;
            let _ = req.as_reader().read_to_string(&mut body);
            let _ = tx.send(body);
            let _ = req.respond(tiny_http::Response::empty(200));
        }
    });

    // Local config pointing at the mock collector, fast flush.
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(dir.path().join("config.toml"), format!(
        "[export]\notlp_endpoint = \"http://{addr}\"\nflush_interval_secs = 1\n")).unwrap();

    tokio::spawn(async { llm_monitor::daemon::run().await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Simulate a Claude Code hook firing, including a secret to test redaction.
    llm_monitor::hook::deliver("claude-code",
        r#"{"hook_event_name":"PreToolUse","session_id":"e2e","tool_name":"Bash",
            "tool_input":{"command":"curl -H 'Authorization: Bearer ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789' https://api.internal.example.com/v1"}}"#);

    let body = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    assert!(body.contains("api.internal.example.com"), "fqdn extracted");
    assert!(body.contains("tool.name"), "otlp attributes present");
    assert!(!body.contains("ghp_AbCdEf"), "secret redacted before export");
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --test e2e`
Expected: FAIL — `daemon::run` unimplemented.

- [ ] **Step 4: Implement `src/daemon.rs`**

```rust
use crate::{adapters, buffer::Buffer, config, event::Envelope, export::Exporter,
            ipc, redact::Redactor, spool};
use anyhow::Result;
use std::sync::{Arc, RwLock};

pub async fn run() -> Result<()> {
    let Ok(listener) = ipc::Listener::bind() else {
        tracing::info!("daemon already running; exiting");
        return Ok(());
    };
    std::fs::create_dir_all(crate::paths::data_dir())?;

    let shared_cfg = Arc::new(RwLock::new(config::load()));
    tokio::spawn(config::poll_loop(shared_cfg.clone()));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(1024);
    tokio::spawn(listener.accept_loop(tx.clone()));

    // Spool drain: pick up events written while the daemon was down.
    let spool_tx = tx.clone();
    tokio::spawn(async move {
        loop {
            for env in spool::drain().unwrap_or_default() {
                let _ = spool_tx.send(env).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    // Codex OTLP receiver (Task 13 wires real events into tx).
    tokio::spawn(crate::adapters::codex::otlp_listener(shared_cfg.clone(), tx.clone()));

    let buffer = Arc::new(Buffer::open(shared_cfg.read().unwrap().buffer.max_events)?);

    // Export loop with backoff.
    let export_buf = buffer.clone();
    let export_cfg = shared_cfg.clone();
    tokio::spawn(async move {
        let mut backoff = 1u64;
        loop {
            let (flush, batch_size, exporter) = {
                let cfg = export_cfg.read().unwrap();
                (cfg.export.flush_interval_secs, cfg.export.batch_size, Exporter::new(&cfg.export))
            };
            tokio::time::sleep(std::time::Duration::from_secs(flush.min(backoff * flush))).await;
            let Ok(batch) = export_buf.peek_batch(batch_size) else { continue };
            if batch.is_empty() { backoff = 1; continue; }
            let events: Vec<_> = batch.iter().map(|(_, e)| e.clone()).collect();
            match exporter.export(&events).await {
                Ok(()) => {
                    let _ = export_buf.ack(batch.last().unwrap().0);
                    backoff = 1;
                }
                Err(e) => {
                    tracing::warn!("export failed, will retry: {e}");
                    backoff = (backoff * 2).min(30);
                }
            }
        }
    });

    // Pipeline: parse -> redact -> buffer. Redactor rebuilt when config changes.
    let mut redactor = Redactor::new(&shared_cfg.read().unwrap().redaction);
    let mut redactor_gen = config_fingerprint(&shared_cfg);
    while let Some(envelope) = rx.recv().await {
        let current = config_fingerprint(&shared_cfg);
        if current != redactor_gen {
            redactor = Redactor::new(&shared_cfg.read().unwrap().redaction);
            redactor_gen = current;
        }
        let capture = shared_cfg.read().unwrap().capture.clone();
        for event in adapters::parse(envelope, &capture) {
            let event = redactor.scrub_event(event);
            if let Err(e) = buffer.push(&event) {
                tracing::error!("buffer push failed: {e}");
            }
        }
    }
    Ok(())
}

fn config_fingerprint(cfg: &Arc<RwLock<config::Config>>) -> String {
    let c = cfg.read().unwrap();
    format!("{}:{:?}", c.redaction.enabled, c.redaction.extra_patterns)
}
```

Wire `main.rs`: `Cmd::Daemon => tokio::runtime::Runtime::new()?.block_on(llm_monitor::daemon::run())?,` (make `main` return `anyhow::Result<()>` — but `Cmd::Hook` must still never propagate errors). `Cmd::Status` prints data dir, buffer length, config summary, and whether the socket accepts a connection.

- [ ] **Step 5: Run all tests**

Run: `cargo test -- --test-threads=1 && cargo clippy -- -D warnings`
Expected: PASS (e2e + all prior tests). Remove any remaining `#![allow(dead_code)]`.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: assemble daemon pipeline with export loop and e2e test"
```

---

### Task 12: opencode adapter + TypeScript plugin shim

**Files:**

- Create: `plugins/opencode/llm-monitor.ts`, `src/adapters/opencode.rs` (replace stub)
- Test: tests inside `src/adapters/opencode.rs`

**Interfaces:**

- Consumes: `adapters::extract_fqdns`, `event::{Event, EventKind}`, `config::CaptureCfg`
- Produces: `adapters::opencode::parse(payload: &Value, capture: &CaptureCfg) -> Vec<Event>` for shim payloads shaped `{"event": "...", "sessionID": "...", ...}`:
  - `"chat.message"` (role user) → `Prompt`
  - `"tool.execute.before"` / `"tool.execute.after"` → `ToolUse` (files from `args.filePath`/`args.path`, fqdns from `args.url`/`args.command`)
  - `"session.created"` / `"session.idle"` → `Session`
  - anything else → `Raw`
- The TS shim forwards each opencode plugin event by spawning `llm-monitor hook --source opencode` with JSON on stdin (fire-and-forget, detached, ~ms cost, no daemon coupling).

- [ ] **Step 1: Write failing Rust adapter tests**

```rust
#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope { source: "opencode".into(), received_at: chrono::Utc::now(), payload }
    }

    #[test]
    fn user_message_becomes_prompt() {
        let events = adapters::parse(env(json!({
            "event": "chat.message", "sessionID": "oc1",
            "message": {"role": "user"}, "parts": [{"type": "text", "text": "add tests"}]
        })), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "add tests"));
        assert_eq!(events[0].session_id.as_deref(), Some("oc1"));
    }

    #[test]
    fn tool_execute_maps_files_and_fqdns() {
        let events = adapters::parse(env(json!({
            "event": "tool.execute.before", "sessionID": "oc1",
            "tool": "write", "args": {"filePath": "/repo/x.ts", "content": "..."}
        })), &CaptureCfg::default());
        let EventKind::ToolUse { tool, files, .. } = &events[0].kind else { panic!() };
        assert_eq!(tool, "write");
        assert_eq!(files, &vec!["/repo/x.ts".to_string()]);

        let events = adapters::parse(env(json!({
            "event": "tool.execute.before", "tool": "bash",
            "args": {"command": "curl https://registry.npmjs.org/x"}
        })), &CaptureCfg::default());
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else { panic!() };
        assert_eq!(fqdns, &vec!["registry.npmjs.org".to_string()]);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test opencode`
Expected: FAIL (stub returns `Raw`).

- [ ] **Step 3: Implement `src/adapters/opencode.rs`**

```rust
use crate::adapters::extract_fqdns;
use crate::config::CaptureCfg;
use crate::event::{Event, EventKind};
use serde_json::Value;

pub fn parse(p: &Value, capture: &CaptureCfg) -> Vec<Event> {
    let session_id = p.get("sessionID").and_then(Value::as_str).map(String::from);
    let mk = |kind| Event::new("opencode", session_id.clone(), None, kind);
    let event = p.get("event").and_then(Value::as_str).unwrap_or("");

    match event {
        "chat.message" => {
            let is_user = p.pointer("/message/role").and_then(Value::as_str) == Some("user");
            if !is_user { return vec![]; }
            let text = if capture.prompts {
                p.get("parts").and_then(Value::as_array).map(|parts| {
                    parts.iter()
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>().join("\n")
                }).unwrap_or_default()
            } else { "[not captured]".into() };
            vec![mk(EventKind::Prompt { text })]
        }
        "tool.execute.before" | "tool.execute.after" => {
            let tool = p.get("tool").and_then(Value::as_str).unwrap_or("unknown").to_string();
            let args = p.get("args").cloned().unwrap_or(Value::Null);
            let files = ["filePath", "path"].iter()
                .filter_map(|k| args.get(k).and_then(Value::as_str))
                .map(String::from).collect();
            let mut fqdns: Vec<String> = vec![];
            for key in ["url", "command"] {
                if let Some(s) = args.get(key).and_then(Value::as_str) {
                    fqdns.extend(extract_fqdns(s));
                }
            }
            let phase = if event.ends_with("before") { "pre" } else { "post" }.to_string();
            let input = if capture.tool_inputs { args } else { Value::Null };
            vec![mk(EventKind::ToolUse { tool, phase, input, files, fqdns })]
        }
        "session.created" | "session.idle" => vec![mk(EventKind::Session { action: event.into() })],
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test opencode`
Expected: PASS.

- [ ] **Step 5: Write the TS shim `plugins/opencode/llm-monitor.ts`**

```typescript
// llm-monitor opencode plugin shim: forwards events to the llm-monitor
// binary. Fire-and-forget; never blocks or fails the user's session.
import { spawn } from "node:child_process";
import type { Plugin } from "@opencode-ai/plugin";

function send(payload: Record<string, unknown>): void {
  try {
    const bin = process.env.LLM_MONITOR_BIN ?? "llm-monitor";
    const child = spawn(bin, ["hook", "--source", "opencode"], {
      stdio: ["pipe", "ignore", "ignore"],
      detached: true,
    });
    child.on("error", () => {});
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
    child.unref();
  } catch {
    // Observability must never break the tool.
  }
}

export const LlmMonitorPlugin: Plugin = async () => {
  return {
    "chat.message": async (_input, output) => {
      send({
        event: "chat.message",
        sessionID: output.message?.sessionID,
        message: { role: output.message?.role },
        parts: output.parts,
      });
    },
    "tool.execute.before": async (input, output) => {
      send({
        event: "tool.execute.before",
        sessionID: input.sessionID,
        tool: input.tool,
        args: output.args,
      });
    },
    "tool.execute.after": async (input, _output) => {
      send({
        event: "tool.execute.after",
        sessionID: input.sessionID,
        tool: input.tool,
      });
    },
  };
};
```

(Verify hook names/shapes against the installed opencode version's `@opencode-ai/plugin` types during implementation; the Rust adapter tests define the wire contract the shim must produce.)

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: add opencode adapter and TypeScript plugin shim"
```

---

### Task 13: Codex adapter (OTLP/JSON receiver + notify)

**Files:**

- Create: `src/adapters/codex.rs` (replace stub)
- Test: tests inside `src/adapters/codex.rs`

**Interfaces:**

- Consumes: `config::Config` (for `codex.otlp_listen`), `event::{Envelope, Event, EventKind}`, mpsc `Sender<Envelope>`
- Produces:
  - `codex::otlp_listener(cfg: Arc<RwLock<Config>>, tx: Sender<Envelope>)` — minimal HTTP server (tokio TcpListener + hand-rolled HTTP/1.1 or `tiny_http` in a blocking thread) bound to `codex.otlp_listen`, accepting `POST /v1/logs` with `content-type: application/json` (Codex configured with `protocol = "json"`). Each OTLP logRecord becomes an `Envelope { source: "codex", payload: <flattened record> }` sent into the same pipeline. Responds `{}` with 200. Any other path → 404.
  - `codex::parse(payload: &Value, capture: &CaptureCfg) -> Vec<Event>` — payload is a flattened OTLP logRecord `{"event_name": "...", "attributes": {...}}` or a notify payload `{"notify": {...}}`:
    - `event_name == "codex.user_prompt"` → `Prompt` (attr `prompt` if `capture.prompts`, else `"[not captured]"`; Codex may itself omit it unless configured)
    - `event_name == "codex.tool_decision"` / `"codex.tool_result"` → `ToolUse` (attrs `tool_name`, `command`/`arguments` — fqdns extracted from arguments text)
    - `event_name == "codex.conversation_starts"` → `Session { action: "start" }`
    - notify payload (raw JSON with top-level `"type": "agent-turn-complete"`, delivered via `hook --source codex`) → `Session { action: "turn-complete" }`
    - unknown → `Raw`

- [ ] **Step 1: Write failing parser tests**

```rust
#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope { source: "codex".into(), received_at: chrono::Utc::now(), payload }
    }

    #[test]
    fn codex_user_prompt_maps_to_prompt() {
        let events = adapters::parse(env(json!({
            "event_name": "codex.user_prompt",
            "attributes": {"conversation.id": "cx1", "prompt": "write a script"}
        })), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "write a script"));
        assert_eq!(events[0].session_id.as_deref(), Some("cx1"));
    }

    #[test]
    fn codex_tool_decision_maps_to_tool_use_with_fqdns() {
        let events = adapters::parse(env(json!({
            "event_name": "codex.tool_decision",
            "attributes": {"tool_name": "shell", "decision": "approved",
                           "command": "curl https://pypi.org/simple/requests"}
        })), &CaptureCfg::default());
        let EventKind::ToolUse { tool, fqdns, .. } = &events[0].kind else { panic!() };
        assert_eq!(tool, "shell");
        assert_eq!(fqdns, &vec!["pypi.org".to_string()]);
    }

    #[tokio::test]
    async fn otlp_listener_accepts_json_logs_and_forwards_envelopes() {
        let cfg = std::sync::Arc::new(std::sync::RwLock::new(crate::config::Config::default()));
        cfg.write().unwrap().codex.otlp_listen = "127.0.0.1:0".into();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx));

        let body = json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
            "eventName": "codex.user_prompt",
            "attributes": [{"key": "prompt", "value": {"stringValue": "hello"}}]
        }]}]}]});
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logs"))
            .json(&body).send().await.unwrap();
        assert!(resp.status().is_success());

        let envelope = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.unwrap().unwrap();
        assert_eq!(envelope.source, "codex");
        assert_eq!(envelope.payload["event_name"], "codex.user_prompt");
        assert_eq!(envelope.payload["attributes"]["prompt"], "hello");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test codex`
Expected: FAIL.

- [ ] **Step 3: Implement `src/adapters/codex.rs`**

```rust
use crate::adapters::extract_fqdns;
use crate::config::{CaptureCfg, Config};
use crate::event::{Envelope, Event, EventKind};
use serde_json::{json, Value};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

pub fn parse(p: &Value, capture: &CaptureCfg) -> Vec<Event> {
    let attrs = p.get("attributes").cloned().unwrap_or(json!({}));
    let session_id = attrs.get("conversation.id").and_then(Value::as_str).map(String::from);
    let mk = |kind| Event::new("codex", session_id.clone(), None, kind);
    let name = p.get("event_name").and_then(Value::as_str).unwrap_or("");

    match name {
        "codex.user_prompt" => {
            let text = if capture.prompts {
                attrs.get("prompt").and_then(Value::as_str).unwrap_or("[not exported by codex]").into()
            } else { "[not captured]".into() };
            vec![mk(EventKind::Prompt { text })]
        }
        "codex.tool_decision" | "codex.tool_result" => {
            let tool = attrs.get("tool_name").and_then(Value::as_str).unwrap_or("unknown").into();
            let text_blob = [attrs.get("command"), attrs.get("arguments")]
                .into_iter().flatten().filter_map(Value::as_str)
                .collect::<Vec<_>>().join(" ");
            let phase = if name.ends_with("decision") { "pre" } else { "post" }.into();
            let input = if capture.tool_inputs { attrs.clone() } else { Value::Null };
            vec![mk(EventKind::ToolUse {
                tool, phase, input, files: vec![], fqdns: extract_fqdns(&text_blob),
            })]
        }
        "codex.conversation_starts" => vec![mk(EventKind::Session { action: "start".into() })],
        // Codex `notify` delivers raw JSON like {"type": "agent-turn-complete", ...}
        _ if p.get("type").and_then(Value::as_str) == Some("agent-turn-complete") =>
            vec![mk(EventKind::Session { action: "turn-complete".into() })],
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

pub async fn bind_listener(cfg: Arc<RwLock<Config>>) -> anyhow::Result<TcpListener> {
    let addr = cfg.read().unwrap().codex.otlp_listen.clone();
    Ok(TcpListener::bind(addr).await?)
}

pub async fn otlp_listener(cfg: Arc<RwLock<Config>>, tx: Sender<Envelope>) {
    match bind_listener(cfg).await {
        Ok(listener) => serve(listener, tx).await,
        Err(e) => tracing::warn!("codex otlp listener disabled: {e}"),
    }
}

/// Minimal HTTP/1.1 server: enough for Codex's OTLP/JSON POSTs on localhost.
pub async fn serve(listener: TcpListener, tx: Sender<Envelope>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(8192);
            let mut tmp = [0u8; 4096];
            // Read until end of headers, then content-length worth of body.
            let (headers_end, content_length) = loop {
                let Ok(n) = stream.read(&mut tmp).await else { return };
                if n == 0 { return; }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_headers_end(&buf) {
                    let head = String::from_utf8_lossy(&buf[..pos]);
                    let len = head.lines()
                        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (pos, len);
                }
                if buf.len() > 10_000_000 { return; }
            };
            while buf.len() < headers_end + content_length {
                let Ok(n) = stream.read(&mut tmp).await else { return };
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..headers_end]);
            let ok = head.starts_with("POST /v1/logs");
            if ok {
                if let Ok(v) = serde_json::from_slice::<Value>(&buf[headers_end..headers_end + content_length]) {
                    for record in flatten_otlp_records(&v) {
                        let _ = tx.send(Envelope {
                            source: "codex".into(),
                            received_at: chrono::Utc::now(),
                            payload: record,
                        }).await;
                    }
                }
            }
            let status = if ok { "200 OK" } else { "404 Not Found" };
            let _ = stream.write_all(
                format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{{}}").as_bytes()
            ).await;
        });
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// OTLP JSON -> flat {"event_name", "attributes": {k: v}} records.
fn flatten_otlp_records(v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let records = v.pointer("/resourceLogs").and_then(Value::as_array).into_iter().flatten()
        .filter_map(|rl| rl.pointer("/scopeLogs").and_then(Value::as_array)).flatten()
        .filter_map(|sl| sl.pointer("/logRecords").and_then(Value::as_array)).flatten();
    for rec in records {
        let name = rec.get("eventName").and_then(Value::as_str)
            .or_else(|| rec.pointer("/body/stringValue").and_then(Value::as_str))
            .unwrap_or("");
        let mut attrs = serde_json::Map::new();
        for a in rec.get("attributes").and_then(Value::as_array).into_iter().flatten() {
            let (Some(k), Some(val)) = (a.get("key").and_then(Value::as_str), a.get("value")) else { continue };
            let flat = val.get("stringValue").cloned()
                .or_else(|| val.get("intValue").cloned())
                .or_else(|| val.get("boolValue").cloned())
                .unwrap_or(Value::Null);
            attrs.insert(k.to_string(), flat);
        }
        out.push(json!({"event_name": name, "attributes": attrs}));
    }
    out
}
```

(Verify Codex's actual OTLP event names — `codex.user_prompt`, `codex.tool_decision`, etc. — against the installed Codex version's docs during implementation; unknown names degrade safely to `Raw`, so mismatches lose fidelity, not data.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test codex && cargo test --test e2e -- --test-threads=1`
Expected: PASS (daemon e2e still green with the real codex listener wired).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add Codex OTLP/JSON receiver and event adapter"
```

---

### Task 14: Install/uninstall command + README + final verification

**Files:**

- Create: `src/install.rs` (replace stub), `README.md`
- Modify: `src/main.rs` (wire `Cmd::Install`/`Cmd::Uninstall`)

**Interfaces:**

- Consumes: `paths`, embedded `include_str!("../plugins/opencode/llm-monitor.ts")`
- Produces:
  - `install::run(dry_run: bool) -> anyhow::Result<()>` — for each detected tool, idempotently wire llm-monitor. All edits are additive and tagged so uninstall can find them. `dry_run` prints planned changes without writing. Home-dir roots overridable via `LLM_MONITOR_HOME` for tests.
    - **Claude Code** (`~/.claude/` exists): merge into `~/.claude/settings.json` `hooks` — for each of `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `SessionStart`, `SessionEnd`, `Stop`, `SubagentStop`: append `{ "matcher": "*", "hooks": [{ "type": "command", "command": "<abs-path-to-llm-monitor> hook --source claude-code" }] }` unless an entry containing `llm-monitor` already exists. (`UserPromptSubmit`/`SessionStart` take no matcher — omit the field.)
    - **opencode** (`~/.config/opencode/` exists): write embedded shim to `~/.config/opencode/plugin/llm-monitor.ts` (overwrite: shim is versioned with the binary).
    - **Codex** (`~/.codex/` exists): parse `~/.codex/config.toml` (create if absent); set `notify = ["<abs-path>", "hook", "--source", "codex"]` if unset, and add `[otel]` table: `environment = "prod"`, `exporter = { otlp-http = { endpoint = "http://127.0.0.1:4327", protocol = "json" } }` if no `[otel]` exists. Never clobber an existing user `[otel]` or `notify` — warn instead.
  - `install::uninstall() -> anyhow::Result<()>` — reverse: remove hook entries whose command contains `llm-monitor`, delete the opencode plugin file, remove `[otel]`/`notify` only if they reference llm-monitor's endpoint/binary.

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fake_home() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_HOME", dir.path());
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::create_dir_all(dir.path().join(".config/opencode")).unwrap();
        std::fs::create_dir_all(dir.path().join(".codex")).unwrap();
        dir
    }

    #[test]
    fn install_wires_all_three_tools_idempotently() {
        let home = fake_home();
        run(false).unwrap();
        run(false).unwrap(); // second run must not duplicate

        let settings: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap()).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.iter().filter(|h| h.to_string().contains("llm-monitor")).count(), 1);
        assert!(settings["hooks"]["UserPromptSubmit"].to_string().contains("llm-monitor"));

        assert!(home.path().join(".config/opencode/plugin/llm-monitor.ts").exists());

        let codex = std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap();
        assert!(codex.contains("otel"));
        assert!(codex.contains("127.0.0.1:4327"));
        assert!(codex.contains("notify"));
    }

    #[test]
    fn install_skips_missing_tools_and_preserves_existing_codex_otel() {
        let home = fake_home();
        std::fs::remove_dir_all(home.path().join(".config/opencode")).unwrap();
        std::fs::write(home.path().join(".codex/config.toml"),
            "[otel]\nenvironment = \"custom\"\n").unwrap();
        run(false).unwrap();
        assert!(!home.path().join(".config/opencode/plugin/llm-monitor.ts").exists());
        let codex = std::fs::read_to_string(home.path().join(".codex/config.toml")).unwrap();
        assert!(codex.contains("custom"), "existing otel config preserved");
    }

    #[test]
    fn uninstall_reverses_install() {
        let home = fake_home();
        run(false).unwrap();
        uninstall().unwrap();
        let settings = std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap();
        assert!(!settings.contains("llm-monitor"));
        assert!(!home.path().join(".config/opencode/plugin/llm-monitor.ts").exists());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test install -- --test-threads=1`
Expected: FAIL.

- [ ] **Step 3: Implement `src/install.rs`**

Implementation outline (full code follows the tested contract above):

```rust
use anyhow::Result;
use serde_json::{json, Value};

const OPENCODE_SHIM: &str = include_str!("../plugins/opencode/llm-monitor.ts");
const CC_HOOKS: &[(&str, bool)] = &[
    ("UserPromptSubmit", false), ("PreToolUse", true), ("PostToolUse", true),
    ("SessionStart", false), ("SessionEnd", false), ("Stop", false), ("SubagentStop", false),
];

fn home() -> std::path::PathBuf {
    std::env::var("LLM_MONITOR_HOME").map(Into::into)
        .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| ".".into()))
}

fn self_exe() -> String {
    std::env::current_exe().ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "llm-monitor".into())
}

pub fn run(dry_run: bool) -> Result<()> {
    if home().join(".claude").exists() { install_claude_code(dry_run)?; }
    if home().join(".config/opencode").exists() { install_opencode(dry_run)?; }
    if home().join(".codex").exists() { install_codex(dry_run)?; }
    Ok(())
}

fn install_claude_code(dry_run: bool) -> Result<()> {
    let path = home().join(".claude/settings.json");
    let mut settings: Value = std::fs::read_to_string(&path).ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    let hooks = settings.as_object_mut().unwrap()
        .entry("hooks").or_insert(json!({}));
    let cmd = format!("{} hook --source claude-code", self_exe());
    for (event, has_matcher) in CC_HOOKS {
        let arr = hooks.as_object_mut().unwrap()
            .entry(*event).or_insert(json!([]));
        let arr = arr.as_array_mut().unwrap();
        if arr.iter().any(|h| h.to_string().contains("llm-monitor")) { continue; }
        let mut entry = json!({ "hooks": [{ "type": "command", "command": cmd }] });
        if *has_matcher { entry["matcher"] = json!("*"); }
        arr.push(entry);
    }
    if dry_run { println!("[dry-run] would update {path:?}"); return Ok(()); }
    std::fs::write(&path, serde_json::to_string_pretty(&settings)?)?;
    println!("wired Claude Code hooks in {path:?}");
    Ok(())
}

fn install_opencode(dry_run: bool) -> Result<()> {
    let path = home().join(".config/opencode/plugin/llm-monitor.ts");
    if dry_run { println!("[dry-run] would write {path:?}"); return Ok(()); }
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, OPENCODE_SHIM)?;
    println!("installed opencode plugin at {path:?}");
    Ok(())
}

fn install_codex(dry_run: bool) -> Result<()> {
    let path = home().join(".codex/config.toml");
    let mut table = std::fs::read_to_string(&path).ok()
        .and_then(|s| s.parse::<toml::Table>().ok())
        .unwrap_or_default();
    if !table.contains_key("notify") {
        table.insert("notify".into(), toml::Value::Array(vec![
            self_exe().into(), "hook".into(), "--source".into(), "codex".into(),
        ]));
    } else { eprintln!("codex: existing notify preserved; codex turn events not wired"); }
    if !table.contains_key("otel") {
        let otel: toml::Table = toml::toml! {
            environment = "prod"
            exporter = { otlp-http = { endpoint = "http://127.0.0.1:4327", protocol = "json" } }
        };
        table.insert("otel".into(), toml::Value::Table(otel));
    } else { eprintln!("codex: existing [otel] preserved; not overwriting"); }
    if dry_run { println!("[dry-run] would update {path:?}"); return Ok(()); }
    std::fs::write(&path, toml::to_string_pretty(&table)?)?;
    println!("wired Codex otel+notify in {path:?}");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    // Claude Code: filter out entries containing "llm-monitor".
    let path = home().join(".claude/settings.json");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(mut settings) = serde_json::from_str::<Value>(&text) {
            if let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) {
                for (_, v) in hooks.iter_mut() {
                    if let Some(arr) = v.as_array_mut() {
                        arr.retain(|h| !h.to_string().contains("llm-monitor"));
                    }
                }
            }
            std::fs::write(&path, serde_json::to_string_pretty(&settings)?)?;
        }
    }
    let _ = std::fs::remove_file(home().join(".config/opencode/plugin/llm-monitor.ts"));
    let path = home().join(".codex/config.toml");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(mut table) = text.parse::<toml::Table>() {
            let ours = |v: &toml::Value| v.to_string().contains("llm-monitor")
                || v.to_string().contains("127.0.0.1:4327");
            if table.get("notify").is_some_and(|v| ours(v)) { table.remove("notify"); }
            if table.get("otel").is_some_and(|v| ours(v)) { table.remove("otel"); }
            std::fs::write(&path, toml::to_string_pretty(&table)?)?;
        }
    }
    println!("llm-monitor unwired from all tools");
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test install -- --test-threads=1 && cargo test -- --test-threads=1 && cargo clippy -- -D warnings && cargo fmt --check`
Expected: PASS — full suite green.

- [ ] **Step 5: Write `README.md`**

Contents: what llm-monitor is (observability agent for Claude Code / opencode / Codex feeding any OTLP backend); quick start (`cargo install` or release binary, `llm-monitor install`, set `otlp_endpoint` in `<data-dir>/config.toml` or point `remote.url` at fleet config); per-tool fidelity table (Claude Code: prompts+tools+files+fqdns+skills+agents; opencode: prompts+tools+files+fqdns; Codex: prompts+tool decisions+turn events, thinner by design); config reference (all keys from Task 6 with defaults and precedence `defaults < local < remote`); privacy/redaction section (built-in patterns, `extra_patterns`, `capture.prompts=false` for metadata-only); architecture diagram (shim → IPC/spool → daemon → redact → SQLite → OTLP); troubleshooting (`llm-monitor status`, spool dir, buffer growth when offline).

- [ ] **Step 6: Manual end-to-end verification (real Claude Code)**

```bash
cargo build --release
LLM_MONITOR_DATA_DIR=/tmp/lm-verify ./target/release/llm-monitor install --dry-run
# Start a throwaway OTLP sink:
python3 -m http.server 4318 &  # observe POSTs land (or use an otel-collector if available)
printf '[export]\notlp_endpoint = "http://127.0.0.1:4318"\nflush_interval_secs = 2\n' > /tmp/lm-verify/config.toml
LLM_MONITOR_DATA_DIR=/tmp/lm-verify ./target/release/llm-monitor daemon &
echo '{"hook_event_name":"UserPromptSubmit","session_id":"manual","prompt":"hello"}' \
  | LLM_MONITOR_DATA_DIR=/tmp/lm-verify ./target/release/llm-monitor hook --source claude-code
# Expect: POST /v1/logs hits the sink within ~2s containing "hello".
```

Then run `llm-monitor install` for real, open Claude Code, run one prompt, and confirm events arrive. Verify `llm-monitor uninstall` cleanly removes hook entries.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: add install/uninstall wiring and README"
```

---

## Verification (whole project)

1. `cargo test -- --test-threads=1` — full suite including `tests/e2e.rs` (hook → daemon → redaction → OTLP mock).
2. `cargo clippy -- -D warnings && cargo fmt --check` — clean.
3. Manual: Task 14 Step 6 flow against a real Claude Code session and a throwaway OTLP sink.
4. Hot-path budget: `time` the release `hook` invocation (Task 5 Step 4) — must be far under 50 ms.
5. Offline behavior: stop the OTLP sink, send events, confirm they accumulate in SQLite (`llm-monitor status`), restart sink, confirm drain.
6. Cross-platform: `cargo build --target x86_64-pc-windows-msvc` (or CI matrix: macOS + ubuntu + windows runners running `cargo test`).

## Known follow-ups (out of scope for v1)

- Service management (`launchd`/`systemd`/Windows service) — v1 relies on hook autospawn.
- Signed remote config (detached signature verification) — v1 trusts HTTPS.
- Deeper Bash parsing for file writes (`>` redirects, `tee`) — v1 extracts FQDNs only from Bash.
- Claude Code transcript-path mining for token counts/model usage stats.
