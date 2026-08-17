# Configuration

argus reads configuration from four layers — built-in defaults, a local
`config.toml`, (optionally) remote fleet policy, and (optionally) a
machine-wide file only an administrator can write — and this page covers
all four, plus the environment variables that move it off those layers and
what the machine-wide file does about them.

## Remote config

For fleet-wide rollout, skip local `config.toml` entirely and set:

```toml
[remote]
url = "https://config.internal/argus.toml"
```

The daemon polls that URL (ETag-conditional) and caches the result to disk, so
policy still applies offline after the first successful fetch. Remote config
always wins over the local file — see [Config reference](#config-reference).

### Signing it

The cache is a file in the user's own data directory. Without a signature,
"the fleet says capture is off" is a claim any account can make with one
`cat > remote-config.cache.toml`, and a `check` that only diffs the cache
against the effective config confirms it.

Pin a key in the [machine-wide file](#machine-wide-config) — nowhere else, since
a key the user can choose is a key they can sign their own policy with:

```toml
[remote]
url = "https://config.internal/argus.toml"
public_key = "kPqjmS…"   # base64, 32 bytes
```

The daemon then fetches `<url>.sig` alongside the body — a base64 ed25519
detached signature over the exact bytes served — and **refuses to cache or
apply a body that does not verify**. A cache that stops verifying later is
skipped by the loader and reported BROKEN by `argus check`. Hosts with no
machine-wide file pin nothing and behave exactly as before.

Generate the key pair and sign a policy with stock OpenSSL:

```sh
openssl genpkey -algorithm ed25519 -out policy-key.pem            # keep offline
openssl pkey -in policy-key.pem -pubout -outform DER |
  tail -c 32 | base64                                             # → public_key
openssl pkeyutl -sign -rawin -inkey policy-key.pem \
  -in argus.toml | base64 > argus.toml.sig                        # serve beside it
```

Serve `argus.toml.sig` from the same host — the signature URL is formed before
any query string, so `…/argus.toml?host=x` fetches `…/argus.toml.sig?host=x`.
Re-sign whenever the body changes, including whitespace: the signature covers
bytes, not the parsed table. A body and a signature that disagree stop policy
from applying at all, which is the fail-closed half of the trade.

## Machine-wide config

The layer above remote policy, and the only one on a developer's machine that
the developer cannot write:

| Platform    | Path                              |
| ----------- | --------------------------------- |
| macOS/Linux | `/etc/argus/config.toml`          |
| Windows     | `C:\ProgramData\argus\config.toml` |

Installed by `argus install --managed --policy <file>`, which validates it
first and copies it verbatim (see
[Installation](installation.md#the-policy-the-layer-enforces)).

It outranks the remote cache deliberately. That cache
(`remote-config.cache.toml`) lives in the per-user data directory under a
predictable name, so "policy said so" is a claim any account can make by
writing the file itself — a layer beneath it would be advisory. Everything a
fleet needs pinned beyond a user's reach belongs here; the remote URL stays the
way to change it without touching every host — and pinning `[remote]
public_key` here makes the cache prove where it came from, so live policy is
not the weaker option ([Signing it](#signing-it)).

Two consequences worth knowing:

- A key this file does **not** name is still the user's to set. Pin what you
  need enforced — `argus check` only reports keys some policy actually sets, so
  an unpinned key is by construction user-controlled.
- A file the loader would skip is not a weaker policy, it is *no* policy: the
  host silently falls back to the user's own config. `argus check` reports a
  malformed or type-invalid machine-wide file as BROKEN rather than absent, and
  `install --managed --policy` refuses to write one in the first place.

`ARGUS_SYSTEM_ROOT` does not move this path. It redirects where an *install*
writes, and it comes out of the watched agent's environment like any other
variable — a layer a line in `~/.zshrc` could switch off would not be one.

### It has to be a file the user could not have written

The layer outranks everything below it because an ordinary account cannot write
it, so argus checks that this is true before reading a word of it:

| Platform    | Accepted when                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------ |
| macOS/Linux | the file and every directory above it are owned by `uid 0` and are not group- or world-writable         |
| Windows     | the file and every directory above it are owned by `LocalSystem`, `BUILTIN\Administrators` or `TrustedInstaller` |

`install --managed --policy` produces exactly that (`0644` in a `0755`
directory, written as root; created by an elevated process on Windows), so a
deployed policy passes. A file that does not is treated as **no layer at all**
— the host goes back to being an unmanaged one — and `argus check` reports it.

This is not bookkeeping. `%ProgramData%` grants standard accounts the right to
create files and directories, and the creator owns what it creates, so on a
Windows host the fleet never managed, a user could write
`C:\ProgramData\argus\config.toml` themselves. Without the ownership test that
file would outrank the remote policy, deny nothing, and turn `argus check`'s
honest "this host is not policy-managed" into "machine-wide config in force".
Reading it as no layer gives its author only the unmanaged host they already
had. (They cannot overwrite a file an administrator already deployed either
way; the exposure was the *unmanaged* host that looked managed.)

The Windows test is ownership, not a full ACL walk. An administrator who
deliberately loosens the ACL on their own machine-wide file is an administrator
choosing to, not a bypass.

### It also turns the environment variables off

Deploying this file makes the host managed, and on a managed host the `ARGUS_*`
variables in [Environment variables](#environment-variables) stop being
honoured unless the file says otherwise:

```toml
[policy]
allow_env_overrides = true   # default: false wherever this file exists
```

Those variables are read out of the *watched agent's* environment — the shim is
a child of the tool it monitors, so anything in a shell profile reaches it. One
line moves the buffer, the spool, the socket and the config to a directory with
no daemon behind it, which is a bypass of everything else this file pins. Hosts
with no machine-wide file are unaffected: there is nobody there to enforce it
for, and they keep the variables exactly as before.

A denied variable is *ignored*, not fatal — argus falls back to the installed
default, which is the configuration you chose — and it is reported either way:
the shim stamps the names it found into every event as `env.overrides`, and the
heartbeat carries `health.env_overrides`. Names only, never values. An attempt
is a better thing for a SIEM to hold than a silence.

### It can refuse a user-scope uninstall

```toml
[policy]
allow_user_uninstall = false   # default: true, on every host
```

`argus uninstall` and `argus uninstall --project` then fail without
root/Administrator. The default is the other way round from
`allow_env_overrides`, and deliberately: an override redirects capture while
leaving every file in place, so it is a bypass that looks like an install,
while a user-scope uninstall removes wiring that same account could have
deleted by hand. Refusing it by default would only move the same act somewhere
argus never sees.

Set or not, **the attempt is exported before anything is unwired** — an
`integrity` record at WARN, `integrity.status` = `uninstalled` when it goes
ahead and `uninstall_refused` when this key stops it, carrying the host, the
user and this install's `service.instance.id`. It is sent synchronously, in the
uninstalling process, because the daemon that would otherwise have carried it
is about to stop; if the collector cannot be reached it goes to the local
buffer instead, and the command still succeeds. A collector you can knock over
must not be a way to make the record never happen.

Unlike the environment gate, a machine-wide file that no longer parses is read
as one that never set this key. A typo would otherwise lock every account on
the host out of an act it can perform with `rm` regardless — and `argus check`
reports that file as BROKEN either way.

A machine-wide file that is not valid TOML denies them too. A typo should not be
worth more to somebody evading monitoring than deleting the file, which they
cannot do; `argus check` reports it as BROKEN, so the typo does not stay hidden.

## Config reference

Resolved with precedence **defaults < local `config.toml` < cached/fresh remote
config < machine-wide `config.toml`**. Fleet policy always wins over the local
file, and the administrator-owned file wins over everything, so a compromised or
uncooperative developer machine can't locally weaken either. All keys are
optional; unset keys keep their default.

### `[remote]`

| Key                         | Default   | Meaning                                 |
| --------------------------- | --------- | --------------------------------------- |
| `remote.url`                | _(unset)_ | HTTPS URL polled for fleet-wide config. |
| `remote.poll_interval_secs` | `300`     | Poll interval (floor `30`).             |
| `remote.public_key`         | _(unset)_ | base64 ed25519 key remote policy must verify against. Only honoured from the machine-wide layer — see [Signing it](#signing-it). |

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
| `integrity.binary_sha256` | unset             | The sha256 of the release the fleet deployed, lowercase hex. Set it and every host reports whether the binary it runs is that one. See [notes](#notes-on-specific-keys).                                     |

### `[health]`

| Key                    | Default | Meaning                                                                                                                                          |
| ---------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `health.enabled`       | `true`  | Emit a periodic `event.type=health` heartbeat at `INFO` (`WARN` while anything is broken), whether or not there is other traffic.                 |
| `health.interval_secs` | `300`   | Heartbeat interval (floor `30`). Re-read each cycle, so a fleet can shorten it by policy without restarting anything. See [notes](#notes-on-specific-keys). |

### `[policy]`

What an *account* on this machine may do to argus, as opposed to what argus
captures. Only ever read from the machine-wide layer — a permission the
constrained party grants itself is not a permission.

| Key                         | Default | Meaning                                                                                                                                    |
| --------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `policy.allow_env_overrides` | `false` where a machine-wide file exists, `true` where none does | Honour the `ARGUS_*` variables out of the watched agent's environment. See [It also turns the environment variables off](#it-also-turns-the-environment-variables-off). |
| `policy.allow_user_uninstall` | `true` | Let an ordinary account run `argus uninstall` (user or `--project` scope). `false` refuses it without root. See [It can refuse a user-scope uninstall](#it-can-refuse-a-user-scope-uninstall). |

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

**`integrity.binary_sha256`** — A hook entry that survives every wiring check
still only proves _which path_ runs; replacing the binary at that path with
`#!/bin/sh\nexit 0` leaves the whole install intact and captures nothing.
Unpinned, argus compares each hook's program against the binary it is itself
running, which already catches that and any wrapper around it. Pinning goes one
further, because a comparison a machine makes against itself is one its owner
can satisfy twice: publish the digest of the release you deployed and every host
reports whether it is running that build (`check`) and repeats the answer to the
collector (`health.binary_pin_ok`), where the machine's owner cannot reach it.
Get the value from the release's `SHA256SUMS`, or `shasum -a 256 $(which argus)`.
Set it in the layer users cannot edit, and only ever to a digest you published:
a wrong pin reports the whole fleet as tampered with and buries the host that
is. Publishing a new release un-pins nothing — update the digest with it, or
every upgraded host is a finding.

**`health.interval_secs`** — Everything else argus emits is a consequence of
the watched tool doing something, which makes a killed daemon, a deleted data
directory, a blocked collector and an unopened laptop all arrive as the same
thing: nothing. The heartbeat is what makes the first three alertable — _host
enrolled, no `argus.health` in N minutes_ — so it is emitted unconditionally,
including on a completely idle machine. Each one carries the install id and
version, uptime, the age and ok/broken counts of the last self-check, the
config fingerprint and policy URL, buffer and spool depth, cumulative drops,
the effective data directory, the binary path and its sha256 (with the verdict
against `integrity.binary_sha256` where one is pinned), and the names (never the values)
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

The ones marked **gated** are read out of the watched agent's environment, so a
line in a shell profile reaches the shim. On a host with a [machine-wide
config](#machine-wide-config) they are ignored unless that file sets
`[policy] allow_env_overrides = true`; on every other host they behave exactly
as they always did. Set or not, honoured or not, their names travel with the
events as `env.overrides`.

| Variable             | Effect                                                                                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ARGUS_DATA_DIR`     | **gated.** Override the data directory (buffer, spool, socket, config, Codex token).                                                                                              |
| `ARGUS_HOME`         | **gated.** Override the home directory `install`/`uninstall`/`check` resolve tool config against.                                                                                 |
| `ARGUS_SOCKET`       | **gated.** Exact socket path (or Windows pipe name) instead of one derived from the data directory.                                                                               |
| `ARGUS_BIN`          | **gated.** Path baked into the hook commands `install` writes, instead of the running binary's.                                                                                    |
| `ARGUS_BIN_DIRS`     | Replace the directories detection searches for tool binaries.                                                                                                                     |
| `ARGUS_SYSTEM_ROOT`  | **gated.** Treat this directory as the system root for `--managed`. Marked "not the real machine", so the privilege check is skipped and the round-trip tests can sweep all three platforms. It never moves the machine-wide config path itself. |
| `ARGUS_NO_AUTOSPAWN` | **gated.** Stop the hook shim starting a daemon; it spools instead.                                                                                                               |
| `ARGUS_RECORD_DIR`   | **gated.** Dump every envelope **raw, before redaction**, for writing adapters. Off unless set; see [Privacy and redaction](privacy.md#privacy-and-redaction).                     |
| `ARGUS_LOG`          | The daemon's own stderr log level (`error`…`trace`, default `info`). Not gated: local logging only, it changes nothing about what is captured or exported.                          |

---

Back to the [project README](../README.md).
