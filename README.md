# argus

A single cross-platform Rust binary that gives security/platform teams visibility
into how AI coding agents are used: which prompts are sent, which tools/files/FQDNs
they touch, which skills/subagents run — captured through each tool's native
hook/plugin surface (no TLS proxying, no MITM) and exported as OTLP/JSON logs to
any observability backend (Splunk, Datadog, Grafana, an OTel Collector, ...).

Supports **Claude Code**, **opencode**, **OpenAI Codex**, and **GitHub Copilot CLI**.

## Quick start

```bash
cargo install --path .          # or grab a release binary
argus install             # detects installed tools, wires hooks/plugins/config
```

Point the daemon at your collector — edit `<data-dir>/config.toml`:

```toml
[export]
otlp_endpoint = "https://otel-collector.internal:4318"
```

(`<data-dir>` is `~/Library/Application Support/argus` on macOS,
`~/.local/share/argus` on Linux, `%APPDATA%\argus` on Windows —
see [Architecture](#architecture).)

For fleet-wide rollout, skip local `config.toml` entirely and set:

```toml
[remote]
url = "https://config.internal/argus.toml"
```

The daemon polls that URL (ETag-conditional) and caches the result to disk, so
policy still applies offline after the first successful fetch. Remote config
always wins over the local file — see [Config reference](#config-reference).

Run `argus status` any time to see the resolved config, buffered event
count, and whether the daemon is reachable. Run `argus uninstall` to
cleanly remove all wiring.

## Per-tool fidelity

Each tool exposes a different amount of detail through its hook/plugin API;
argus captures everything each surface offers.

| Signal                      |        Claude Code         |       opencode        |          Codex          |    Copilot CLI    |
| --------------------------- | :------------------------: | :-------------------: | :---------------------: | :---------------: |
| Prompts                     |             Y              |           Y           |            Y            |         Y         |
| Assistant messages          |          Y (Stop)          |           Y           |      Y (Stop hook)      |         —         |
| Tool use (pre/post)         |             Y              |           Y           |            Y            |         Y         |
| Tool outputs                |             Y              |           Y           |            Y            |         Y         |
| Tool failures               |             Y              |           —           | Y (post incl. non-zero) |         Y         |
| File paths touched          |             Y              |           Y           |     Y (apply_patch)     |         Y         |
| FQDNs contacted             |             Y              |           Y           |            Y            |         Y         |
| Skill/command invocations   |             Y              | Y (command.executed)  |            —            |         —         |
| Subagent runs               |       Y (start+stop)       |           —           |            Y            |         Y         |
| Permission requests         |     Y (request+denied)     |   Y (asked+replied)   |            Y            |         Y         |
| Compaction                  | Y (pre+post, token counts) | Y (session.compacted) |            Y            |      Y (pre)      |
| Errors                      |      Y (StopFailure)       |   Y (session.error)   |            —            | Y (errorOccurred) |
| Config/instructions changes |             Y              |           —           |            —            |         —         |
| Session lifecycle           |             Y              |           Y           |            Y            |         Y         |

Codex is wired three ways at once: its hooks system (`~/.codex/hooks.json`,
Claude-compatible payloads — note new hooks need one-time trust via `/hooks`
inside Codex), the `notify` hook for turn completion on older versions, and
OTLP logs (`[otel]` in `config.toml`) for token/model telemetry.

### Claude Code hooks deliberately not wired

- `MessageDisplay` — fires on every rendered assistant-message chunk
  (hot-path cost); the final text is already captured via
  `Stop.last_assistant_message`.
- `UserPromptExpansion` — expansion input is already captured at
  `UserPromptSubmit`.
- `FileChanged` — requires literal filename matchers, not wildcardable.
- `WorktreeCreate`/`WorktreeRemove` — `WorktreeCreate` interprets hook stdout
  as a replacement worktree path and a non-zero exit fails creation; too
  risky for observe-only wiring.
- `Setup`, `TeammateIdle`, `Elicitation`/`ElicitationResult` — control-flow
  hooks that expect decision output; `Elicitation` form content is
  user-sensitive.

## Config reference

Resolved with precedence **defaults < local `config.toml` < cached/fresh remote
config** (remote is fleet policy and always wins, so a compromised or
uncooperative developer machine can't locally weaken it). All keys are optional;
unset keys keep their default.

| Key                          | Default            | Meaning                                                                                                                                                                                                          |
| ---------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `remote.url`                 | _(unset)_          | HTTPS URL polled for fleet-wide config.                                                                                                                                                                          |
| `remote.poll_interval_secs`  | `300`              | Poll interval (floor `30`).                                                                                                                                                                                      |
| `export.otlp_endpoint`       | _(unset)_          | OTLP/JSON logs endpoint (`POST {endpoint}/v1/logs`). No endpoint = events stay buffered locally.                                                                                                                 |
| `export.headers`             | `{}`               | Extra HTTP headers sent with each export (e.g. auth).                                                                                                                                                            |
| `export.batch_size`          | `256`              | Max events per export batch.                                                                                                                                                                                     |
| `export.flush_interval_secs` | `10`               | Export loop interval; backs off exponentially (capped ~30x) on repeated failures.                                                                                                                                |
| `capture.prompts`            | `true`             | Capture prompt text. `false` → events still emitted, text replaced with `[not captured]` (metadata-only mode).                                                                                                   |
| `capture.tool_inputs`        | `true`             | Capture tool-call input JSON. `false` → tool events still emitted (name, files, FQDNs) without the input payload.                                                                                                |
| `capture.tool_outputs`       | `true`             | Capture tool result/output JSON on post-tool events. `false` → output field left null.                                                                                                                           |
| `capture.assistant_messages` | `true`             | Capture assistant message text (Claude Code/Codex `Stop`, opencode `chat.message`). `false` → assistant-message events suppressed.                                                                               |
| `capture.max_field_bytes`    | `65536`            | Per-field size cap (serialized bytes) for prompt text, assistant text, tool input/output. Oversized text gets `…[truncated]`; oversized JSON is replaced with `{"_truncated":true,"_bytes":n}`. `0` = unlimited. |
| `redaction.enabled`          | `true`             | Run the built-in secret scrubber before anything is buffered or exported.                                                                                                                                        |
| `redaction.extra_patterns`   | `[]`               | Additional regexes scrubbed the same way as built-ins (invalid patterns are skipped with a warning, not fatal).                                                                                                  |
| `buffer.max_events`          | `100000`           | SQLite buffer cap; oldest events are dropped once full (offline-first, not unbounded).                                                                                                                           |
| `codex.otlp_listen`          | `"127.0.0.1:4327"` | Local address the daemon listens on for Codex's `[otel]` OTLP/JSON export.                                                                                                                                       |
| `integrity.enabled`          | `true`             | Periodically re-verify the daemon's own hook/plugin wiring is intact. A tampered/removed hook emits an `event.type=integrity`, `integrity.status=broken` record at `WARN`. On by default (security control).      |
| `integrity.interval_secs`    | `3600`             | Wiring self-check interval (floor `30`). Broken findings re-emit each cycle until re-install, so the alert stays live.                                                                                            |

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
  set `capture.prompts = false` and `capture.tool_inputs = false` — argus
  still emits metadata (which tool ran, which files, which hosts, session
  lifecycle) with content fields replaced by a `[not captured]` marker.

## Architecture

```
 Claude Code hook / opencode plugin / Codex notify+otel
                    |
                    v
        argus hook  (hot path: parse stdin JSON, forward, exit)
             |                     |
        IPC (< 250ms)        spool fallback (JSONL on disk)
             |                     |
             +----------+----------+
                        v
                 argus daemon
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

- **Hook shim** (`argus hook`) is the only thing on the host tool's
  critical path. It tries the daemon over a local socket (Unix domain socket /
  Windows named pipe via `interprocess`) with a 250ms deadline; on timeout or
  daemon-not-running it falls back to writing a JSONL spool file and
  autospawns the daemon. It never blocks the host tool and never fails loudly
  — a broken hook must not break Claude Code, opencode, or Codex.
- **Daemon** (`argus daemon`) does everything else off that critical
  path: per-tool adapter parsing → secret redaction → durable SQLite buffering
  → batched OTLP/JSON export with exponential backoff. It also drains the
  spool directory and polls remote config.
- **Install** (`argus install`) detects installed tools by home-dir
  presence (`~/.claude`, `~/.config/opencode`, `~/.codex`, `~/.copilot`) and
  idempotently wires each one — see the per-tool fidelity table above.
  `--dry-run` prints planned changes without writing.

## Troubleshooting

- `argus status` — prints the resolved data dir, effective config
  (endpoint, batch size, flush interval, redaction on/off), buffered event
  count, and whether the daemon socket is reachable.
- `argus check` — one-shot integrity self-check for fleet monitoring;
  exits `0` (intact) or `2` (something broken). No daemon required. Intended for
  an MDM compliance script (Jamf Extension Attribute / Intune) or any monitoring
  agent on the endpoint's poll cycle — the pull-based counterpart to the
  daemon's `integrity` events. Checks two things (both by default; scope with
  `--hooks` / `--config`):
  - **hooks** — each detected tool still carries the `argus` wiring.
  - **config** — a remote policy (`[remote].url`) is loaded and effective, and
    the effective config matches it. Fails if the host isn't policy-managed, the
    policy never loaded (no/invalid cache → running on local/defaults), or a
    policy key isn't reflected. Note: because the loader is
    `defaults < local < remote`, a value the policy sets can't be weakened
    locally — so this verifies policy is *in force* rather than spot-checking
    individual keys (which a targeted edit would slip past).
    Pass **`--remote-url <URL>`** (the canonical policy URL, from your MDM) so
    the check fails if `remote.url` was **removed or repointed** to another
    policy server — otherwise the check trusts whatever URL the local config
    declares. Example: `argus check --remote-url https://config.internal/argus.toml`
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
- **Hook not firing**: confirm `argus install` actually wrote entries —
  check `~/.claude/settings.json` (`hooks.*`), `~/.config/opencode/plugin/argus.ts`,
  `~/.codex/config.toml` (`notify`, `[otel]`), `~/.codex/hooks.json`, or
  `~/.copilot/hooks/argus.json`. Re-run `argus install`
  (idempotent) if entries are missing. Codex hooks additionally need one-time
  trust: run `/hooks` inside Codex and trust the argus entries.
- **Codex config not touched**: install never overwrites an existing `notify`
  or `[otel]` block — it warns on stderr and leaves it alone so it can't
  silently break another integration. Remove the conflicting block manually
  (or point it at argus yourself) if you want Codex wired.

## Known limitations (v1)

- No OS service management (`launchd`/`systemd`/Windows service) — the daemon
  is autospawned by the first hook invocation instead.
- Remote config is trusted over HTTPS; no detached-signature verification yet.
- Bash tool parsing only extracts FQDNs, not file writes via `>`/`tee`.
- No Claude Code transcript-path mining for token/model usage stats.
- Claude Code `MessageDisplay` and `FileChanged` are deliberately not wired —
  see the wired-hooks notes in [Per-tool fidelity](#per-tool-fidelity).
