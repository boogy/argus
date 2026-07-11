# llm-monitor

A single cross-platform Rust binary that gives security/platform teams visibility
into how AI coding agents are used: which prompts are sent, which tools/files/FQDNs
they touch, which skills/subagents run — captured through each tool's native
hook/plugin surface (no TLS proxying, no MITM) and exported as OTLP/JSON logs to
any observability backend (Splunk, Datadog, Grafana, an OTel Collector, ...).

Supports **Claude Code**, **opencode**, and **OpenAI Codex**.

## Quick start

```bash
cargo install --path .          # or grab a release binary
llm-monitor install             # detects installed tools, wires hooks/plugins/config
```

Point the daemon at your collector — edit `<data-dir>/config.toml`:

```toml
[export]
otlp_endpoint = "https://otel-collector.internal:4318"
```

(`<data-dir>` is `~/Library/Application Support/llm-monitor` on macOS,
`~/.local/share/llm-monitor` on Linux, `%APPDATA%\llm-monitor` on Windows —
see [Architecture](#architecture).)

For fleet-wide rollout, skip local `config.toml` entirely and set:

```toml
[remote]
url = "https://config.internal/llm-monitor.toml"
```

The daemon polls that URL (ETag-conditional) and caches the result to disk, so
policy still applies offline after the first successful fetch. Remote config
always wins over the local file — see [Config reference](#config-reference).

Run `llm-monitor status` any time to see the resolved config, buffered event
count, and whether the daemon is reachable. Run `llm-monitor uninstall` to
cleanly remove all wiring.

## Per-tool fidelity

Each tool exposes a different amount of detail through its hook/plugin API;
llm-monitor captures everything each surface offers.

| Signal              | Claude Code | opencode | Codex |
|----------------------|:-----------:|:--------:|:-----:|
| Prompts              | Y | Y | Y |
| Tool use (pre/post)  | Y | Y | Y (tool decision/result) |
| File paths touched   | Y | Y | — (not exposed by the tool surface) |
| FQDNs contacted      | Y | Y | Y (from tool args/command text) |
| Skill invocations    | Y | — | — |
| Subagent/Task runs   | Y | — | — |
| Session lifecycle    | Y (Start/End/Stop/SubagentStop/Compact/Notification) | Y (created/idle) | Y (conversation start, turn-complete) |

Codex is thinner by design: it speaks OTLP logs (`[otel]` in `config.toml`) plus
a single `notify` hook for turn completion — it does not expose file-write or
skill/subagent hooks the way Claude Code does.

## Config reference

Resolved with precedence **defaults < local `config.toml` < cached/fresh remote
config** (remote is fleet policy and always wins, so a compromised or
uncooperative developer machine can't locally weaken it). All keys are optional;
unset keys keep their default.

| Key | Default | Meaning |
|---|---|---|
| `remote.url` | *(unset)* | HTTPS URL polled for fleet-wide config. |
| `remote.poll_interval_secs` | `300` | Poll interval (floor `30`). |
| `export.otlp_endpoint` | *(unset)* | OTLP/JSON logs endpoint (`POST {endpoint}/v1/logs`). No endpoint = events stay buffered locally. |
| `export.headers` | `{}` | Extra HTTP headers sent with each export (e.g. auth). |
| `export.batch_size` | `256` | Max events per export batch. |
| `export.flush_interval_secs` | `10` | Export loop interval; backs off exponentially (capped ~30x) on repeated failures. |
| `capture.prompts` | `true` | Capture prompt text. `false` → events still emitted, text replaced with `[not captured]` (metadata-only mode). |
| `capture.tool_inputs` | `true` | Capture tool-call input JSON. `false` → tool events still emitted (name, files, FQDNs) without the input payload. |
| `redaction.enabled` | `true` | Run the built-in secret scrubber before anything is buffered or exported. |
| `redaction.extra_patterns` | `[]` | Additional regexes scrubbed the same way as built-ins (invalid patterns are skipped with a warning, not fatal). |
| `buffer.max_events` | `100000` | SQLite buffer cap; oldest events are dropped once full (offline-first, not unbounded). |
| `codex.otlp_listen` | `"127.0.0.1:4327"` | Local address the daemon listens on for Codex's `[otel]` OTLP/JSON export. |

Example `config.toml`:

```toml
[export]
otlp_endpoint = "https://otel-collector.internal:4318"
flush_interval_secs = 5

[capture]
prompts = false        # metadata-only: never persist prompt text

[redaction]
extra_patterns = ["ACME-[0-9]{6}"]
```

## Privacy and redaction

- Redaction runs **before** anything touches disk or the network — secrets never
  reach SQLite or the exporter.
- Built-in patterns cover common credential shapes: Anthropic/OpenAI API keys,
  bearer tokens, GitHub tokens, AWS access keys, PEM private key blocks, Slack
  tokens, and generic `key=`/`token:`/`password=` assignments (quoted and
  unquoted, e.g. `API_KEY=abcd1234efgh`).
- Add organization-specific patterns via `redaction.extra_patterns` (plain
  regex strings); matches are replaced with `[REDACTED:<rule-name>]`.
- For environments that must never capture prompt/tool-input content at all,
  set `capture.prompts = false` and `capture.tool_inputs = false` — llm-monitor
  still emits metadata (which tool ran, which files, which hosts, session
  lifecycle) with content fields replaced by a `[not captured]` marker.

## Architecture

```
 Claude Code hook / opencode plugin / Codex notify+otel
                    |
                    v
        llm-monitor hook  (hot path: parse stdin JSON, forward, exit)
             |                     |
        IPC (< 250ms)        spool fallback (JSONL on disk)
             |                     |
             +----------+----------+
                        v
                 llm-monitor daemon
                        |
              adapter parse (per-tool)
                        |
                    redaction
                        |
              SQLite durable buffer  <-- offline-first, capped, oldest-dropped
                        |
              OTLP/JSON export (batched, retried with backoff)
                        |
                        v
              your OTLP backend (Splunk / Datadog / Grafana / Collector)
```

- **Hook shim** (`llm-monitor hook`) is the only thing on the host tool's
  critical path. It tries the daemon over a local socket (Unix domain socket /
  Windows named pipe via `interprocess`) with a 250ms deadline; on timeout or
  daemon-not-running it falls back to writing a JSONL spool file and
  autospawns the daemon. It never blocks the host tool and never fails loudly
  — a broken hook must not break Claude Code, opencode, or Codex.
- **Daemon** (`llm-monitor daemon`) does everything else off that critical
  path: per-tool adapter parsing → secret redaction → durable SQLite buffering
  → batched OTLP/JSON export with exponential backoff. It also drains the
  spool directory and polls remote config.
- **Install** (`llm-monitor install`) detects installed tools by home-dir
  presence (`~/.claude`, `~/.config/opencode`, `~/.codex`) and idempotently
  wires each one — see the per-tool fidelity table above. `--dry-run` prints
  planned changes without writing.

## Troubleshooting

- `llm-monitor status` — prints the resolved data dir, effective config
  (endpoint, batch size, flush interval, redaction on/off), buffered event
  count, and whether the daemon socket is reachable.
- **Offline / collector unreachable**: events keep flowing into the SQLite
  buffer (`<data-dir>/events.db`) instead of being dropped; `buffered events`
  in `status` grows. Once the collector is reachable again, the export loop's
  next attempt drains and exports the backlog — nothing needs to be restarted
  manually. If `buffer.max_events` is reached, oldest events are dropped to
  keep disk usage bounded.
- **Spool directory** (`<data-dir>/spool/*.jsonl`): written by the hook shim
  when it can't reach the daemon within its deadline (daemon not yet started,
  or briefly wedged). The daemon drains this directory every 5s once running;
  files with corrupt/unparseable content are dropped (logged as a warning)
  rather than blocking the drain loop.
- **Hook not firing**: confirm `llm-monitor install` actually wrote entries —
  check `~/.claude/settings.json` (`hooks.*`), `~/.config/opencode/plugin/llm-monitor.ts`,
  or `~/.codex/config.toml` (`notify`, `[otel]`). Re-run `llm-monitor install`
  (idempotent) if entries are missing.
- **Codex config not touched**: install never overwrites an existing `notify`
  or `[otel]` block — it warns on stderr and leaves it alone so it can't
  silently break another integration. Remove the conflicting block manually
  (or point it at llm-monitor yourself) if you want Codex wired.

## Known limitations (v1)

- No OS service management (`launchd`/`systemd`/Windows service) — the daemon
  is autospawned by the first hook invocation instead.
- Remote config is trusted over HTTPS; no detached-signature verification yet.
- Bash tool parsing only extracts FQDNs, not file writes via `>`/`tee`.
- No Claude Code transcript-path mining for token/model usage stats.
