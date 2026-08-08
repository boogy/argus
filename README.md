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
| `export.max_batch_bytes`     | `3 MiB`            | Max serialized bytes per export batch, whichever binds first. Collectors reject on request size, and 256 tool results carrying file contents are orders of magnitude larger than 256 prompts. `0` = no limit. An event bigger than the whole budget is still sent, alone. |
| `export.flush_interval_secs` | `10`               | Export loop interval; backs off exponentially (capped ~30x) on retryable failures (5xx, `408`, `429`, timeouts). A `4xx` refusal is not retried — see below.                                                     |
| `capture.prompts`            | `true`             | Capture prompt text. `false` → events still emitted, text replaced with `[not captured]` (metadata-only mode).                                                                                                   |
| `capture.tool_inputs`        | `true`             | Capture tool-call input JSON. `false` → tool events still emitted (name, files, FQDNs) without the input payload.                                                                                                |
| `capture.tool_outputs`       | `true`             | Capture tool result/output JSON on post-tool events. `false` → output field left null.                                                                                                                           |
| `capture.assistant_messages` | `true`             | Capture assistant message text (Claude Code/Codex `Stop`, opencode `chat.message`). `false` → assistant-message events suppressed.                                                                               |
| `capture.max_field_bytes`    | `65536`            | Per-field size cap (serialized bytes) for prompt text, assistant text, tool input/output. Oversized text gets `…[truncated]`; oversized JSON is replaced with `{"_truncated":true,"_bytes":n}`. `0` = unlimited. |
| `redaction.enabled`          | `true`             | Run the built-in secret scrubber before anything is buffered or exported.                                                                                                                                        |
| `redaction.extra_patterns`   | `[]`               | Additional regexes scrubbed the same way as built-ins (invalid patterns are skipped with a warning, not fatal).                                                                                                  |
| `buffer.max_events`          | `100000`           | SQLite buffer cap; oldest events are dropped once full (offline-first, not unbounded).                                                                                                                           |
| `buffer.max_bytes`           | `268435456`        | Second cap, on stored event text (256 MiB). A row cap is not a disk bound — 100k pasted file contents is a very different size from 100k prompts. Whichever binds first wins; both are re-read on a config reload. Counted in UTF-8 bytes, so a buffer of CJK or emoji-bearing prompts holds what it says. |
| `spool.max_bytes`            | `67108864`         | Ceiling on the hand-off spool (64 MiB). It grows exactly while the daemon is down and nothing is draining it; over the cap the oldest undelivered files are deleted and the count rides out on the next envelope as an `event.type=loss`, `loss.reason=spool_full` record. Read fresh on every hook, so a change applies immediately. |
| `codex.otlp_listen`          | `127.0.0.1:4xxxx`  | Local address the daemon listens on for Codex's `[otel]` OTLP/JSON export. The port defaults to one derived from the data directory (40000–49151), because loopback is machine-wide, not per-user: on a shared fixed port the second account's daemon fails to bind while its Codex keeps posting prompts into the *first* account's audit trail. The receiver requires a bearer token (see below); posts without it get `401` and are not recorded. |
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
- The one exception is the developer payload recorder: setting
  `ARGUS_RECORD_DIR` makes the hook shim dump every envelope **raw**, before
  redaction, so adapters can be written against what a tool actually sends.
  It is off unless that variable is set, writes owner-only (0600) files, and
  `make record-fixtures` redacts on the way into `tests/fixtures/`. See
  [docs/adding-a-tool.md](docs/adding-a-tool.md).

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
  critical path. It tries the daemon over a local socket (Unix domain socket at
  `<data-dir>/argus.sock`; on Windows a named pipe `\\.\pipe\argus-<id>`, where
  `<id>` is a hash of the data directory — the pipe namespace is machine-global
  and flat, so without it every account on the machine would share one endpoint
  and hook payloads would reach whichever daemon bound first) with a 250ms
  deadline. The daemon refuses to bind an endpoint another account owns rather
  than reporting it as "already running" — a squatted socket that looks like a
  healthy install is a silent kill switch. The endpoint is also reachable by
  this account only: mode `0600` in a `0700` directory on Unix, and on Windows
  a protected DACL granting one SID, replacing the default pipe descriptor's
  read access for Everyone and for the anonymous account. On timeout or
  daemon-not-running it falls back to writing a JSONL spool file and
  autospawns the daemon. It never blocks the host tool and never fails loudly
  — a broken hook must not break Claude Code, opencode, or Codex.
- **Daemon** (`argus daemon`) does everything else off that critical
  path: per-tool adapter parsing → secret redaction → durable SQLite buffering
  → batched OTLP/JSON export with exponential backoff. It also drains the
  spool directory and polls remote config.

  Export is at-least-once: a batch is deleted only after a 2xx, so a collector
  outage costs nothing. A **refusal** is settled differently from an outage. A
  `4xx` other than `408`/`429` means the collector read the request and said no
  — an oversized record, a schema a validator rejects, a revoked key — and
  re-sending it can only fail again. Retrying forever would park that batch at
  the head of the queue while newer events pile up behind it and are eventually
  evicted to make room: the one refused batch would cost every event after it.
  So a refused batch is dropped, and a `loss` event naming the status and the
  collector's own error text takes its place in the queue, which is what makes
  the gap visible at the far end rather than an absence nobody can date.

- **Codex OTLP receiver** is the one input that is not a local socket, because
  Codex exports over HTTP. Loopback is not an authentication boundary — every
  process on the machine, under any account, can post to `127.0.0.1` — so the
  receiver requires a bearer token: 256 bits generated at install into
  `<data-dir>/codex-otlp.token` (mode `0600`, in the `0700` data directory) and
  copied into Codex's `[otel]` exporter headers. Without it, anything on the
  box could write fabricated prompts and tool calls into the record of what the
  agents did. A post without the token gets `401` and is not parsed, forwarded
  or buffered. If Codex telemetry stops arriving, its `config.toml` is carrying
  a token this install does not know (a restored profile, a wiped data
  directory); the daemon logs this once and `argus install` re-wires it.
- **Install** (`argus install`) detects installed tools from four independent
  signals and idempotently wires each one — see the per-tool fidelity table
  above. `--dry-run` prints planned changes, and the signals behind them,
  without writing anything.

  | Signal       | What it reads                                                          |
  | ------------ | ---------------------------------------------------------------------- |
  | `config dir` | `~/.claude`, `~/.codex`, `~/.copilot`, `$XDG_CONFIG_HOME/opencode` (`%APPDATA%\opencode` on Windows), honouring `COPILOT_HOME`/`CODEX_HOME` |
  | `binary`     | the tool's binary on `PATH` **and** in the per-user prefixes a hook's `PATH` often omits (`~/.local/bin`, `~/.npm-global/bin`, `%APPDATA%\npm`, scoop shims, …); on Windows the candidates come from `PATHEXT` |
  | `npm`        | that binary's real path resolving inside `node_modules/<package>/`      |
  | `brew`       | …or inside `Cellar/<formula>/`                                          |

  A config directory only appears once a tool has been *run*, so binary and
  package signals are what let argus wire a freshly installed agent. In the
  other direction, a binary whose name is an ordinary word (`codex`) is never
  proof by itself — it counts only when a config dir or package provenance
  corroborates it, otherwise a machine that has never had Codex gets wired and
  then reported as broken forever.

## Troubleshooting

- `argus status` — prints the resolved data dir, effective config
  (endpoint, batch size, flush interval, redaction on/off), every detected tool
  with the signals it was detected by, buffered event count, and whether the
  daemon socket is reachable. A tool listed as `binary` with no `config dir`
  has been installed but never run; a tool you expected and don't see is a
  detection gap, not a wiring one.
- `argus check` — one-shot integrity self-check for fleet monitoring;
  exits `0` (intact) or `2` (something broken). No daemon required. Intended for
  an MDM compliance script (Jamf Extension Attribute / Intune) or any monitoring
  agent on the endpoint's poll cycle — the pull-based counterpart to the
  daemon's `integrity` events. Checks two things (both by default; scope with
  `--hooks` / `--config`):
  - **hooks** — each detected tool still carries the `argus` wiring, *and* that
    wiring can still fire: the binary each hook command names is resolved and
    must be executable, files argus owns must be non-empty and still contain
    the commands they were installed with, and Codex's `config.toml` `notify`
    argv and `[otel]` block are verified alongside `hooks.json`. The `[otel]`
    block is held to the endpoint this install actually listens on, not merely
    to looking like ours: a `config.toml` still naming a previous install's
    port is wired to a receiver nothing answers on, and reporting that as
    intact would be worse than reporting nothing. The same applies to the
    bearer token in that block: a Codex presenting a token this install does
    not know is refused on every turn, which looks exactly like a Codex nobody
    is using. The error says the token is wrong, never what it is — `check`
    output is collected and indexed by whatever is polling it.
    **Upgrading to 0.3.0 can flip hosts to broken that previously reported
    intact** — that is the fix, not a regression. Wiring baked against a binary
    that has since moved (a `brew upgrade` that bumps the Cellar prefix, an
    `npm` reinstall, `cargo install` to a new root) has not been capturing
    anything; `check` simply says so now. `argus install` re-points it, and
    installs now bake the stable `PATH` alias rather than the resolved real
    path, so the next upgrade doesn't repeat it.
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
  manually. If `buffer.max_events` or `buffer.max_bytes` is reached, oldest
  events are dropped to keep disk usage bounded, and the gap is exported as an
  `event.type=loss` record at `WARN` rather than left as a silent absence.
- **Spool directory** (`<data-dir>/spool/*.jsonl`): written by the hook shim
  when it can't reach the daemon within its deadline (daemon not yet started,
  or briefly wedged). The daemon drains this directory every 5s once running,
  256 files per pass and oldest first, deleting each file only after its events
  are committed to the buffer — so a crash mid-drain costs a duplicate rather
  than an event. Files with corrupt/unparseable content are dropped (logged as
  a warning) rather than blocking the drain loop. `spool.max_bytes` bounds the
  directory: past the cap the oldest undelivered files are deleted, and the
  count is exported as an `event.type=loss`, `loss.reason=spool_full` record at
  `WARN`.
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
