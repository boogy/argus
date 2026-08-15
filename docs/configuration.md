# Configuration

argus reads configuration from three layers — built-in defaults, a local
`config.toml`, and (optionally) remote fleet policy — and this page covers
all three, plus the environment variables mostly used for tests.

## Remote config

For fleet-wide rollout, skip local `config.toml` entirely and set:

```toml
[remote]
url = "https://config.internal/argus.toml"
```

The daemon polls that URL (ETag-conditional) and caches the result to disk, so
policy still applies offline after the first successful fetch. Remote config
always wins over the local file — see [Config reference](#config-reference).

## Config reference

Resolved with precedence **defaults < local `config.toml` < cached/fresh remote
config** (remote is fleet policy and always wins, so a compromised or
uncooperative developer machine can't locally weaken it). All keys are optional;
unset keys keep their default.

### `[remote]`

| Key                         | Default   | Meaning                                 |
| --------------------------- | --------- | --------------------------------------- |
| `remote.url`                | _(unset)_ | HTTPS URL polled for fleet-wide config. |
| `remote.poll_interval_secs` | `300`     | Poll interval (floor `30`).             |

### `[export]`

| Key                          | Default   | Meaning                                                                                                                                  |
| ---------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `export.otlp_endpoint`       | _(unset)_ | OTLP/JSON logs endpoint (`POST {endpoint}/v1/logs`). No endpoint = events stay buffered locally.                                         |
| `export.headers`             | `{}`      | Extra HTTP headers sent with each export (e.g. auth).                                                                                    |
| `export.batch_size`          | `256`     | Max events per export batch.                                                                                                             |
| `export.max_batch_bytes`     | `3 MiB`   | Max serialized bytes per export batch, whichever binds first (`0` = no limit). See [notes](#notes-on-specific-keys).                     |
| `export.gzip`                | `false`   | Compress the request body (`Content-Encoding: gzip`). Off by default. See [notes](#notes-on-specific-keys).                              |
| `export.flush_interval_secs` | `10`      | Export loop interval; backs off exponentially on retryable failures (5xx, `408`, `429`, timeouts). See [notes](#notes-on-specific-keys). |

### `[capture]`

| Key                          | Default     | Meaning                                                                                                                                                                                           |
| ---------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `capture.prompts`            | `true`      | Capture prompt text. `false` → text replaced with `[not captured]` (metadata-only mode).                                                                                                          |
| `capture.tool_inputs`        | `true`      | Capture tool-call input JSON. `false` → tool events keep name/files/FQDNs but drop the input payload.                                                                                             |
| `capture.tool_outputs`       | `true`      | Capture tool result/output JSON on post-tool events. `false` → output field left null.                                                                                                            |
| `capture.assistant_messages` | `true`      | Capture assistant message text (Claude Code/Codex `Stop`, opencode `chat.message`). `false` → suppressed.                                                                                         |
| `capture.max_field_bytes`    | `65536`     | Per-field size cap (serialized bytes) for prompt/assistant text, tool input/output, and each JSON string leaf (`0` = unlimited). See [notes](#notes-on-specific-keys).                            |
| `capture.truncate_mode`      | `head`      | What survives the cap: `head`, `head_tail`, or `drop`. See [notes](#notes-on-specific-keys).                                                                                                      |
| `capture.file_contents.*`    | off         | Capture the contents of files a tool touched. Off by default — see [File-content capture](capture.md#file-content-capture).                                                                       |
| `capture.cloud_identity`     | `true`      | Record the agent's cloud identity (role, account, credentials in scope) as `cloud.*` attributes — see [Cloud identity](capture.md#cloud-identity). `false` → attribute omitted.                   |
| `capture.mcp_endpoints`      | `false`     | Resolve MCP server names to their endpoint and export as `mcp.endpoint`. Off by default (those config files sit next to credentials) — see [Where the server is](capture.md#where-the-server-is). |

### `[redaction]`

| Key                        | Default | Meaning                                                                                                         |
| -------------------------- | ------- | --------------------------------------------------------------------------------------------------------------- |
| `redaction.enabled`        | `true`  | Run the built-in secret scrubber before anything is buffered or exported.                                       |
| `redaction.extra_patterns` | `[]`    | Additional regexes scrubbed the same way as built-ins (invalid patterns are skipped with a warning, not fatal). |

### `[buffer]` / `[spool]`

| Key                 | Default     | Meaning                                                                                |
| ------------------- | ----------- | -------------------------------------------------------------------------------------- |
| `buffer.max_events` | `100000`    | SQLite buffer cap; oldest events are dropped once full (offline-first, not unbounded). |
| `buffer.max_bytes`  | `268435456` | Second cap, on stored event text (256 MiB). See [notes](#notes-on-specific-keys).      |
| `spool.max_bytes`   | `67108864`  | Ceiling on the hand-off spool (64 MiB). See [notes](#notes-on-specific-keys).          |

### `[codex]` / `[integrity]`

| Key                       | Default           | Meaning                                                                                                                                                                                                      |
| ------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `codex.otlp_listen`       | `127.0.0.1:4xxxx` | Local address the daemon listens on for Codex's `[otel]` OTLP/JSON export. See [notes](#notes-on-specific-keys).                                                                                             |
| `integrity.enabled`       | `true`            | Periodically re-verify the daemon's own hook/plugin wiring is intact; on by default (security control). A tampered/removed hook emits an `event.type=integrity`, `integrity.status=broken` record at `WARN`. |
| `integrity.interval_secs` | `3600`            | Wiring self-check interval (floor `30`). Broken findings re-emit each cycle until re-install, so the alert stays live.                                                                                       |
| `integrity.managed`       | `false`           | Also verify the machine-wide (`--managed`) layer each cycle. Set it where `install --managed` ran: with it on, a missing managed artifact is a finding rather than an unmanaged machine.                      |

### `[health]`

| Key                    | Default | Meaning                                                                                                                                          |
| ---------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `health.enabled`       | `true`  | Emit a periodic `event.type=health` heartbeat at `INFO` (`WARN` while anything is broken), whether or not there is other traffic.                 |
| `health.interval_secs` | `300`   | Heartbeat interval (floor `30`). Re-read each cycle, so a fleet can shorten it by policy without restarting anything. See [notes](#notes-on-specific-keys). |

### Notes on specific keys

**`export.max_batch_bytes`** — Collectors reject on request size, and 256 tool
results carrying file contents are orders of magnitude larger than 256
prompts. An event bigger than the whole budget is still sent, alone.

**`export.gzip`** — OTLP/HTTP receivers _should_ accept a gzipped body but are
not required to, and one that does not answers `4xx` — a refusal, which drops
the batch rather than retrying it. Turn it on once you know the collector
decodes it.

**`export.flush_interval_secs`** — Backoff is exponential, capped at ~30x the
interval. A `4xx` refusal is not retried, unlike `5xx`/`408`/`429`/timeouts.

**`capture.max_field_bytes`** — Capping the leaves rather than the whole
value is what keeps a large `Write` from costing its own `file_path`: the
record used to say something big was written and not what. A structure that
is still 16× the cap after that (or nested past 32 levels) is replaced
wholesale with `{"_truncated":true,…}`.

**`capture.truncate_mode`** — `head` keeps the first bytes plus
`…[truncated]`; `head_tail` keeps both ends with `…[truncated]…` between;
`drop` discards the content entirely (`[truncated]`). `head` is the default
because it is what argus has always stored, and a default that changes what
an existing deployment keeps is a silent rewrite of its records. `head_tail`
is usually the better setting to choose: the answer is often at the end — a
diff's outcome, a stack trace's cause — and `head` alone truncates exactly
that away. Cuts land on character boundaries; a multi-byte character is never
split.

**`buffer.max_bytes`** — A row cap is not a disk bound: 100k pasted file
contents is a very different size from 100k prompts. Whichever cap binds
first wins; both are re-read on a config reload. Counted in UTF-8 bytes, so a
buffer of CJK or emoji-bearing prompts holds what it says.

**`spool.max_bytes`** — Grows exactly while the daemon is down and nothing is
draining it. Over the cap, the oldest undelivered files are deleted and the
count rides out on the next envelope as an `event.type=loss`,
`loss.reason=spool_full` record. Read fresh on every hook, so a change
applies immediately.

**`health.interval_secs`** — Everything else argus emits is a consequence of
the watched tool doing something, which makes a killed daemon, a deleted data
directory, a blocked collector and an unopened laptop all arrive as the same
thing: nothing. The heartbeat is what makes the first three alertable — _host
enrolled, no `argus.health` in N minutes_ — so it is emitted unconditionally,
including on a completely idle machine. Each one carries the install id and
version, uptime, the age and ok/broken counts of the last self-check, the
config fingerprint and policy URL, buffer and spool depth, cumulative drops,
the effective data directory and binary path, and the names (never the values)
of any `ARGUS_*` override in force. A `startup` and a `shutdown` record bracket
every run, so a stop somebody asked for does not read like one nobody did.

**`codex.otlp_listen`** — The port defaults to one derived from the data
directory (40000–49151), because loopback is machine-wide, not per-user: on
a shared fixed port the second account's daemon fails to bind while its
Codex keeps posting prompts into the _first_ account's audit trail. The
receiver requires a bearer token (see below); posts without it get `401`
and are not recorded.

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

## Environment variables

Mostly for tests and for running argus somewhere other than a real home
directory; none are needed for an ordinary install.

| Variable             | Effect                                                                                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ARGUS_DATA_DIR`     | Override the data directory (buffer, spool, socket, config, Codex token).                                                                                                         |
| `ARGUS_HOME`         | Override the home directory `install`/`uninstall`/`check` resolve tool config against.                                                                                            |
| `ARGUS_SOCKET`       | Exact socket path (or Windows pipe name) instead of one derived from the data directory.                                                                                          |
| `ARGUS_BIN`          | Path baked into the hook commands `install` writes, instead of the running binary's.                                                                                              |
| `ARGUS_BIN_DIRS`     | Replace the directories detection searches for tool binaries.                                                                                                                     |
| `ARGUS_SYSTEM_ROOT`  | Treat this directory as the system root for `--managed`. Marked "not the real machine", so the privilege check is skipped and the round-trip tests can sweep all three platforms. |
| `ARGUS_NO_AUTOSPAWN` | Stop the hook shim starting a daemon; it spools instead.                                                                                                                          |
| `ARGUS_RECORD_DIR`   | Dump every envelope **raw, before redaction**, for writing adapters. Off unless set; see [Privacy and redaction](privacy.md#privacy-and-redaction).                               |

---

Back to the [project README](../README.md).
