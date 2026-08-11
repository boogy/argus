# argus

A single cross-platform Rust binary that gives security/platform teams visibility
into how AI coding agents are used: which prompts are sent, which tools/files/FQDNs
they touch, which skills/subagents run — captured through each tool's native
hook/plugin surface (no TLS proxying, no MITM) and exported as OTLP/JSON logs to
any observability backend (Splunk, Datadog, Grafana, an OTel Collector, ...).

Supports **Claude Code**, **opencode**, **OpenAI Codex**, **GitHub Copilot CLI**, and **pi**.

## Quick start

```bash
cargo install --path .          # or grab a release binary
argus install             # detects installed tools, wires hooks/plugins/config
```

There are three install scopes, and they are independent — a machine can carry
all three at once:

| Command                          | Writes into                                   | Who can remove it            |
| -------------------------------- | --------------------------------------------- | ---------------------------- |
| `argus install`                  | this user's config (`~/.claude`, `~/.codex`, …) | the user                     |
| `argus install --project <dir>`  | a repository (`<dir>/.codex/hooks.json`)        | anyone who can push          |
| `argus install --managed`        | an administrator-owned system root              | root/Administrator only      |

`--dry-run` prints the plan, and the detection signals behind it, without
writing anything.

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

| Signal                      |        Claude Code         |       opencode        |          Codex          |    Copilot CLI    |          pi           |
| --------------------------- | :------------------------: | :-------------------: | :---------------------: | :---------------: | :-------------------: |
| Prompts                     |             Y              |           Y           |            Y            |         Y         |           Y           |
| Prompt rewritten en route    |             —              |           —           |            —            | Y (userPromptTransformed) |           —           |
| Assistant messages          |          Y (Stop)          |           Y           |      Y (Stop hook)      | Y (subagent only) |           —           |
| Tool use (pre/post)         |             Y              |           Y           |            Y            |         Y         |           Y           |
| Tool outputs                |             Y              |           Y           |            Y            |         Y         |     Y (text parts)    |
| Tool failures               |             Y              |           —           | Y (post incl. non-zero) |         Y         |      Y (isError)      |
| File paths touched          |             Y              |           Y           |     Y (apply_patch)     |         Y         |           Y           |
| FQDNs contacted             |             Y              |           Y           |            Y            |         Y         |           Y           |
| Skill/command invocations   |             Y              | Y (command.executed)  |            —            |         —         |           —           |
| Slash-command expansion     |     Y (expanded text)      |           —           |            —            |         —         |           —           |
| Subagent runs               |       Y (start+stop)       |           —           |            Y            | Y (start+stop)    |           —           |
| Permission requests         |     Y (request+denied)     |  Y (request+reply)    |            Y            |         Y         |     — (no event)      |
| Compaction                  | Y (pre+post, token counts) | Y (session.compacted) |            Y            |      Y (pre)      | Y (pre+post, before)  |
| Errors                      |      Y (StopFailure)       |   Y (session.error)   |            —            | Y (errorOccurred) |   Y (turn_end stop)   |
| Config/instructions changes |             Y              |           —           |            —            |         —         |           —           |
| Directory scope changes     |        Y (/add-dir)        |           —           |            —            |         —         |           —           |
| Session lifecycle           |             Y              |           Y           |            Y            |         Y         |           Y           |
| Model, tokens, cost per turn |             —              |  Y (message.updated)  |            —            |         —         |     Y (turn_end)      |
| Interactive shells (pty)    |             —              |  Y (created+exited)   |            —            |         —         |    Y (user_bash `!`)  |
| File contents               |         Y (opt-in)         |      Y (opt-in)       |       Y (opt-in)        |    Y (opt-in)     |      Y (opt-in)       |

Copilot's `userPromptTransformed` is the one row with no equivalent elsewhere,
and the reason it is wired: it reports what was *actually* sent to the model
after every hook, plugin and enterprise policy in the chain had a turn at
editing it. An instruction spliced in there appears nowhere else — the user
never typed it, and the transcript just shows the model obeying it. Both halves
ride in one `prompt_transformed` event (`original` and `transformed`, each
redacted), with a `prompt.rewritten` attribute so a SIEM can alert on the edit
without diffing two prompt bodies on every turn. `capture.prompts = false`
suppresses both halves.

pi's two dashes are absences in pi, not gaps in argus. It has **no permission
event at all** — gating a tool call is an extension's own `tool_call` handler
returning `{block, reason}`, so there is nothing to observe and argus records
what ran rather than what was asked. And it has no assistant-message event that
carries the text: `turn_end` hands over the finished message, which argus reads
for the model, tokens, cost and stop reason. The `!`-prefixed shell command is
pi's answer to opencode's pty — a command the user runs directly, which never
passes through `tool_call`, and whose `!!` form the transcript itself never
records either.

The file-contents row is uniform across all five because it is the one feature
that does not read a tool's vocabulary. Enrichment runs on every tool event
whatever produced it, and picks candidates out of the input by shape — the
file-path keys the adapters already agree on, an `apply_patch` body, an `edits`
array — so a surface gets file capture by carrying a path, not by being on a
list. See [File-content capture](#file-content-capture); it is off by default.

A row saying `Y` means the event is recorded, not that every field in it is.
Four that used to be read past are now kept, because each is the part of its
event a reviewer would actually look for. A compaction's `custom_instructions`
/ `customInstructions`: compaction is the one point where the session's own
history is rewritten, and after the rewrite the request to leave something out
is the only surviving evidence that it was ever there — so it is captured,
redacted, and exported as a `compact.directed` boolean for alerting. A
notification's `title`, which is usually the only part a human reads. An
error's `name` and `recoverable`, which are what make errors groupable and
what separate a retried blip from a session that stopped working. And a
Copilot subagent's `agentDescription` (the task it was spawned for) plus its
`response`, recorded as an assistant message rather than buried in a session
blob so that capping, redaction and `capture.assistant_messages = false` apply
to it like any other. Copilot's `error.stack` is deliberately dropped: it is
unbounded and describes the host tool's own file layout, not the session.

Codex is wired three ways at once: its hooks system (`~/.codex/hooks.json`,
Claude-compatible payloads — note new hooks need one-time trust via `/hooks`
inside Codex), the `notify` hook for turn completion on older versions, and
OTLP logs (`[otel]` in `config.toml`) for token/model telemetry.

### Claude Code hooks deliberately not wired

- `MessageDisplay` — fires on every rendered assistant-message chunk
  (hot-path cost); the final text is already captured via
  `Stop.last_assistant_message`.
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
| `export.gzip`                | `false`            | Compress the request body (`Content-Encoding: gzip`). Off by default: OTLP/HTTP receivers *should* accept a gzipped body but are not required to, and one that does not answers `4xx` — a refusal, which drops the batch rather than retrying it. Turn it on once you know the collector decodes it. |
| `export.flush_interval_secs` | `10`               | Export loop interval; backs off exponentially (capped ~30x) on retryable failures (5xx, `408`, `429`, timeouts). A `4xx` refusal is not retried — see below.                                                     |
| `capture.prompts`            | `true`             | Capture prompt text. `false` → events still emitted, text replaced with `[not captured]` (metadata-only mode).                                                                                                   |
| `capture.tool_inputs`        | `true`             | Capture tool-call input JSON. `false` → tool events still emitted (name, files, FQDNs) without the input payload.                                                                                                |
| `capture.tool_outputs`       | `true`             | Capture tool result/output JSON on post-tool events. `false` → output field left null.                                                                                                                           |
| `capture.assistant_messages` | `true`             | Capture assistant message text (Claude Code/Codex `Stop`, opencode `chat.message`). `false` → assistant-message events suppressed.                                                                               |
| `capture.max_field_bytes`    | `65536`            | Per-field size cap (serialized bytes) for prompt text, assistant text, tool input/output, and each string *leaf* inside a JSON payload. Capping the leaves rather than the whole value is what keeps a large `Write` from costing its own `file_path`: the record used to say something big was written and not what. A structure that is still 16× the cap after that (or nested past 32 levels) is replaced wholesale with `{"_truncated":true,…}`. `0` = unlimited. |
| `capture.truncate_mode`      | `head_tail`        | What survives the cap: `head` (first bytes + `…[truncated]`), `head_tail` (both ends, `…[truncated]…` between), `drop` (`[truncated]`, content discarded). `head_tail` is the default because the answer is usually at the end — a diff's outcome, a stack trace's cause — and `head` alone truncates exactly that away. Cuts land on character boundaries; a multi-byte character is never split. |
| `capture.file_contents.*`    | off                | Capture the contents of files a tool touched. Off by default, whole table documented in [File-content capture](#file-content-capture). |
| `capture.cloud_identity`     | `true`             | Record which cloud identity the agent was holding — assumed role, account, subscription, project, cluster — and name the credential variables it had in scope. Whole section in [Cloud identity](#cloud-identity). `false` → no `cloud.*` attribute on any event. |
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

## File-content capture

A tool call records that `Write` touched `src/deploy.rs`. What it wrote is a
different question, and the one an investigation actually asks. Turning this on
attaches a `file_contents` array to tool events — one entry per file, each with
the path, the action (`read`, `written`, `edited`, `patched`), where the bytes
came from (`payload` or `disk`), the size, the mtime, a `sha256`, and the
content when policy allows it.

It is **off by default**, and deliberately so: it is the one setting that turns
an audit trail into a copy of source code.

```toml
[capture.file_contents]
enabled = true
```

| Key                                   | Default                                                    | Meaning                                                                                                                                                                                                      |
| ------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `capture.file_contents.enabled`       | `false`                                                     | Master switch. Off means no `file_contents` key at all — not an empty array on every tool call in every session.                                                                                             |
| `capture.file_contents.mode`          | `payload`                                                   | Where bytes may come from. `payload`: only what the hook already carried (a `Write`'s content, an `Edit`'s two halves, a patch body) — exact, race-free, **zero I/O**. `disk`: read the file. `both`: the payload when it carried one, the disk otherwise. |
| `capture.file_contents.include`       | `[]`                                                        | Regexes on the path. Empty means no restriction — an `include` matching nothing would be an enabled feature that captures nothing.                                                                            |
| `capture.file_contents.exclude`       | `node_modules`, `.git`, `*.lock`/`*.min.js`, `.env*`, `*.pem`, `.ssh/`, `*_rsa`, `*.p12` | Regexes applied after `include`; a tie goes to the exclusion. Writing your own list **replaces** these rather than adding to them — a config that states a whole policy should not silently keep ours.        |
| `capture.file_contents.max_bytes`     | `32768`                                                     | Per file. A payload body over this is kept truncated; a file on *disk* over it is measured and not read at all (see below). Bounded by `capture.max_field_bytes` regardless.                                  |
| `capture.file_contents.max_files`     | `10`                                                        | Per event, so one `apply_patch` across forty files cannot become forty bodies in one record.                                                                                                                  |
| `capture.file_contents.max_total_bytes` | `262144`                                                  | Per event, across all files, and shared by both halves — `both` is not quietly twice the number written here.                                                                                                 |
| `capture.file_contents.skip_binary`   | `true`                                                      | Drop content that is not text: invalid UTF-8, or any control byte other than tab/CR/LF in the first 8 KiB. Metadata is still recorded.                                                                        |
| `capture.file_contents.hash`          | `true`                                                      | Record `sha256`, size and mtime **even where content is withheld**. This is what keeps an excluded file visible as *touched*, and what lets two captures of one path be told apart.                           |
| `capture.file_contents.read_timeout_ms` | `2000`                                                    | How long one file's stat-and-read may take before the daemon stops waiting and records it as unreadable. `0` waits forever.                                                                                    |

Every file that is *named* appears in the record, whether or not its content
does. A withheld body carries a `skipped` reason — `excluded`, `too_large`,
`binary`, `budget`, `unreadable` — which is exported as an attribute, because a
policy excluding more than its author intended otherwise looks exactly like a
quiet week.

What the disk half will not do:

- **Follow a symlink.** `/tmp/x -> ~/.ssh/id_rsa` is the oldest way to get a
  privileged reader to fetch something on your behalf, and it walks straight
  past an `exclude` list that matches on the path the *agent* said. The stat
  refuses the link, and the open refuses it again (`O_NOFOLLOW`) because a stat
  and an open are two syscalls and swapping the path in between is the whole
  point of the gap. A refused link is reported without even its target's size.
- **Open anything that is not a regular file.** `read()` on a fifo never
  returns; a daemon that opened one would stop enriching events entirely.
- **Read a file bigger than the cap.** It is measured, not truncated: reading
  2 GiB off disk to keep 32 KiB is I/O for a prefix of a file you could not see
  anyway. Size and mtime are still reported.
- **Ship the contents of an excluded file.** With `hash = true` an excluded
  file is opened, hashed, and its bytes dropped — the digest is what makes one
  `.env` the same `.env` across forty sessions. With `hash = false` it is never
  opened at all.
- **Wait forever.** A read that stops returning — a network mount that goes
  away mid-read — is abandoned after `read_timeout_ms` and reported as
  unreadable. Nothing here can *cancel* that read (a thread parked in the
  kernel is not interruptible from userspace); what the deadline bounds is the
  blast radius, so one dead mount costs one stuck thread instead of every event
  behind it.

Captured bodies go through the redactor like any other field, before anything
is buffered or exported. Two consequences worth stating plainly: the `sha256`
is of the bytes the tool actually handled, not of the scrubbed copy — a digest
of a redaction marker matches nothing — and a body that was truncated carries
no digest at all, for the same reason.

One interaction is worth knowing before you rely on this: `capture.tool_inputs
= false` disables file capture entirely, both halves. The files a call touched
are found in its input, so an event with no input has no candidates to read —
including for `disk` mode, which needs the path even though it does not need
the body. The `files` list is unaffected: such an event still *names* every
file and describes none of them.

`disk` mode reads the file a moment *after* the tool acted, so what it records
is the state that resulted, not necessarily the state the tool wrote — which is
also how it shows a change the tool did not make, such as a formatter that ran
afterwards. `payload` mode has the opposite property and no I/O; `both` is the
one that answers "what does this file look like now" for a call that named a
file without quoting it.

"Named without quoting it" means the read family specifically — a tool whose
name says it read the file. A `Grep`'s `path` is a directory to search and a
`Bash`'s `command` is not a path at all, so neither produces anything to
capture in any mode. Opening those would mean spending I/O on strings that were
never claimed to be files, chosen by the agent being monitored.

## Cloud identity

An event says an agent ran `terraform apply`. The question an incident actually
asks is *as whom* — which role it had assumed, which account, which cluster.
Nothing in a hook payload carries that; the environment does, and the hook shim
is spawned by the agent and inherits it.

So the shim reads it, and every event from that envelope carries it as
`cloud.*` attributes — indexable, groupable, joinable against the provider's own
audit log:

```
cloud.aws.role_arn        = arn:aws:iam::123456789012:role/prod-admin
cloud.aws.account_id      = 123456789012
cloud.aws.region          = eu-west-1
cloud.azure.subscription_id, cloud.azure.tenant_id, cloud.azure.client_id
cloud.gcp.project, cloud.gcp.account, cloud.gcp.credentials_file
cloud.k8s.api_host, cloud.k8s.kubeconfig, cloud.k8s.context
cloud.vault.addr, cloud.vault.namespace
cloud.github.repository, cloud.cloudflare.account_id, cloud.doppler.project, …
```

Two disjoint kinds of variable, and the split is the whole design:

- **Identifiers** are an explicit allowlist, captured **by value**. Every one is
  something the provider already writes into its own audit log: a role ARN, an
  account id, a project, a profile name, an access key **id**. They say who the
  agent was; none of them authenticates as anyone.
- **Credentials** are everything whose *name* says it holds secret material
  (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_API_KEY`, `*_PRIVATE_KEY`, …). Only
  the **name** is recorded — the value is never read at all. They arrive as one
  attribute, `cloud.credentials_present=AWS_SECRET_ACCESS_KEY,GITHUB_TOKEN`,
  which answers "what did this session have in scope" for free.

Anything matching neither is ignored. An agent's environment on a developer's
machine holds their entire shell, and a monitoring tool that shipped it
wholesale would be the largest thing it had to defend. The allowlist is
deliberately not exhaustive and no heuristic ever inspects a *value*: a provider
argus does not know yet is a missing attribute, never a leaked one.

The read happens as close to the agent as possible, because that is the only
place the agent's environment exists — the daemon was started from somewhere
else entirely, and its environment describes whoever started it. For Claude
Code, Copilot CLI and Codex's `notify` that is the hook shim; for opencode and
pi it is the plugin itself, which writes its own envelope over the socket and
only falls back to the shim. The two allowlists are pinned to each other by a
test, so one cannot drift from the other.

The *policy* is applied in the daemon: `capture.cloud_identity = false` in fleet
config switches it off everywhere without reinstalling a single hook.

**One channel cannot carry it.** Codex's `[otel]` export posts to the daemon
over HTTP from Codex's own process, so those records arrive with no identity
attached; the same session's `notify` events do carry one. Nothing can be
inferred for the HTTP path without labelling an agent's telemetry with whatever
credentials the daemon's own environment happens to hold, which would be worse
than the gap.

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

### The spool holds un-redacted payloads on disk

"Before anything touches disk" is true of the buffer and the exporter. It is
**not** true of the hand-off spool, and the difference is worth being explicit
about, because it is the one place a secret exists on disk in the clear.

Redaction runs in the daemon. The shim runs in the host tool's process, on the
critical path, with a 250 ms budget — it cannot compile a dozen regexes and
walk a payload there without becoming the thing it was written to avoid. So
when the daemon is not reachable, the shim writes the envelope to
`<data-dir>/spool/` exactly as the tool sent it, secrets included, and the
daemon redacts it on the way in when it drains.

What bounds that window:

- Spool files are written owner-only (`0600`) into a `0700` directory, so the
  exposure is to this account and to root, not to the machine.
- The spool exists only while the daemon is down; the shim autospawns it, and
  a drained file is deleted only after its events reach the buffer.
- `spool.max_bytes` caps the directory, so an unbounded outage does not become
  an unbounded pile of un-redacted payloads.

What does **not** bound it: the `capture.*` switches. Those are enforced in the
daemon's adapters, so `capture.prompts = false` means the prompt is never
stored or exported — it does not mean an un-drained spool file lacks it. The
one thing they do keep out of the spool is what the daemon adds later: a file
read off disk under `capture.file_contents` happens in the daemon's enrichment
stage, so it never passes through a spool file at all.

Treat `<data-dir>` as sensitive, on the same footing as the buffer database and
the Codex receiver token that already live there.

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
       Stage A: adapter parse (per-tool), one task
                        |
       Stage B: enrich — file capture, redaction, field caps
                (blocking pool, several batches at once)
                        |
       Stage C: SQLite write, one task, in arrival order
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

  Every hook entry argus writes carries an explicit timeout, because the
  defaults are written for hooks that do work: Copilot reads an omitted
  `timeoutSec` as 30 seconds. Ten is what argus writes, and that is already
  forty times the shim's own 250 ms deadline — it is slack, not a requirement.
  Shutdown hooks (Codex `SessionEnd`, Copilot `sessionEnd`) get three, since
  there the timeout is time the user spends watching the CLI refuse to exit,
  and an event lost at shutdown is the cheapest one to lose: the shim has
  already spooled it.

- **opencode plugin** talks to the same socket from inside the editor process,
  so it carries the fallback itself: an event the socket will not take is
  handed to `argus hook`, which spools it. "Will not take" is deliberately not
  the same as "has not sent yet". A stream write returns `false` once the
  stream is over its high-water mark, but the frame is queued and still goes
  out; sending it again through the fallback is how one tool call became two
  rows. The plugin instead tracks unflushed bytes and diverts only what it has
  not already queued, capped at 1 MiB so a daemon that stops reading cannot
  grow the editor's memory without bound. `tests/plugin/` drives the real
  plugin against a stalled reader to hold that line — the pre-fix shim scores
  400 envelopes for 200 events there.

  That transport is not opencode's. It lives in `plugins/shared/transport.ts`
  and is joined onto each host's adapter half at build time, so every
  TypeScript plugin argus installs derives its socket path, its FNV
  discriminator and its envelope frame from one copy. A second copy would not
  fail loudly if it drifted: the plugin would still load and still forward, it
  would just stop finding the daemon and spawn a process per event forever.
  The join happens in Rust rather than through a relative import because a
  plugin host loads exactly one file, and an import that resolves here need
  not resolve in someone else's config directory. The two halves are checked
  as one — `check` looks for a marker from each, and the plugin test runs the
  composed file rather than either fragment.

  Because the composed file is embedded in the binary rather than read from
  disk at install time, `check` can hold the installed copy to it exactly: the
  plugin and the pi extension must be byte-identical to what this binary
  writes, and a mismatch is reported with both sha256 prefixes. Markers alone
  would not be enough for a file a runtime loads as code — every marker
  survives having a payload appended after them — and the same comparison
  names the quieter case, a plugin left over from an older argus that keeps
  its markers while speaking an older frame to the daemon.

  opencode discovers plugins under `plugin/` *or* `plugins/` — both spellings
  are in its own documentation — so argus writes into whichever the config
  directory already has, preferring the one that already holds an `argus.ts`.
  A reinstall therefore updates the copy opencode is loading instead of
  leaving a stale one in the other directory, and a first install joins the
  user's plugins rather than creating a second, one-file collection beside
  them. `check` and `uninstall` resolve the same way.

  Two fields the plugin is the only possible source of: the working directory
  — opencode hands it to a plugin once, at load, and never repeats it on an
  event, so without the plugin sending it every opencode event was `cwd: null`
  and invisible to anything scoped to a repository — and the tool `callID`,
  which is what pairs a `before` with its `after`. Both halves are tested:
  `tests/plugin/opencode_payload.mjs` asserts the plugin puts them on the
  wire, because a field the plugin stops sending breaks no Rust test on its
  own — the adapter reads `None` and the column just goes quietly empty.

  opencode is also the one surface that reports what a turn cost, so it is the
  one that gets a `usage` event: model, provider, the five token counts and the
  host tool's own cost figure, each its own field rather than a JSON blob —
  spend-per-session has to be a query for the number to ever get looked at.
  Token volume is also the cheapest thing that separates a session doing work
  from one looping on the same failure. The streaming filter lives in the
  plugin: `message.updated` fires on every delta and only the last one carries
  totals, so the plugin forwards it only once the turn is marked complete, and
  the partial receipts never leave the editor process. `meta.model` is
  `provider/model`, because the same model name is served by more than one
  provider and which one saw the turn is the question being asked.

  The forwarded-event list is checked against opencode's own `Event` union
  rather than against documentation. That audit removed `permission.asked`,
  which never existed: it had a `BUS_FORWARD` entry, an adapter arm and a
  fixture — three consistent artefacts describing an event opencode has never
  emitted — and it held the only mapping to a `requested` permission action, so
  no query for permission requests on opencode ever matched. `permission.updated`
  *is* the ask, and now says so; it also carries the `callID` of the tool call
  it gates, so the prompt and the call join. A test walks `BUS_FORWARD` out of
  the plugin source and asserts each name reaches a real adapter arm, because
  the failure mode is silent: a forwarded event with no arm is not dropped, it
  arrives as an unqueryable blob that still counts as an event in every report.

  The same audit added what was genuinely missing. A pty is a command with a
  pid that never passes through `tool.execute.*` — the one way to run something
  in opencode and leave no trace in the tool record — so `pty.created` and
  `pty.exited` become a `pre`/`post` `ToolUse` pair joined by the pty's id,
  with FQDNs scanned from the program *and* its arguments. As a session note
  they would have been command executions invisible to every query about
  command executions. `message.removed` is the only notice that part of the
  transcript stopped existing, and `vcs.branch.updated` says which branch a
  session's `cwd` was on, which is what makes a file edit mean anything.
  `lsp.*`, `message.part.*`, `tui.*` and `installation.update-available` stay
  out: high-frequency, UI-only, or a poll result rather than a state change.
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
  | `config dir` | `~/.claude`, `~/.codex`, `~/.copilot`, `~/.pi/agent`, `$XDG_CONFIG_HOME/opencode` (`%APPDATA%\opencode` on Windows), honouring `COPILOT_HOME`/`CODEX_HOME` |
  | `binary`     | the tool's binary on `PATH` **and** in the per-user prefixes a hook's `PATH` often omits (`~/.local/bin`, `~/.npm-global/bin`, `%APPDATA%\npm`, scoop shims, …); on Windows the candidates come from `PATHEXT` |
  | `npm`        | that binary's real path resolving inside `node_modules/<package>/`      |
  | `brew`       | …or inside `Cellar/<formula>/`                                          |

  A config directory only appears once a tool has been *run*, so binary and
  package signals are what let argus wire a freshly installed agent. In the
  other direction, a binary whose name is an ordinary word (`codex`) is never
  proof by itself — it counts only when a config dir or package provenance
  corroborates it, otherwise a machine that has never had Codex gets wired and
  then reported as broken forever.

- **Repository-level wiring** (`argus install --project <dir>`) writes
  `<dir>/.codex/hooks.json` and nothing else, so anyone running Codex inside
  that checkout is captured without a per-machine hook install. `uninstall
  --project <dir>` reverses it, and `check --project <dir>` verifies it
  alongside the user-level wiring — a repository nothing wired is silent rather
  than broken.

  Three things this is not. It is **not** a way to ship settings: machine-level
  config stays out of the repository, most of all Codex's `[otel]` block, whose
  `authorization` header carries this install's receiver token — committing that
  publishes the one secret standing between the audit trail and anything else on
  the machine that can reach loopback. It is **not** self-contained: the hook
  command names the `argus` binary, which still has to be on `PATH` on every
  machine that clones the repository, and Codex loads a repository's hooks only
  once that `.codex/` layer is trusted there, per user, via `/hooks`. And it is
  **not** enforcement — anyone who can push to the repository can also delete
  what it writes. It is a convenience for teams that already ship argus in their
  image. Project hooks are additive in Codex, so this never competes with a
  user-level install; the two both run.

  Only Codex is wired this way today. Claude Code has an equivalent project
  layer (`<repo>/.claude/settings.json`) that is simply not wired yet; Copilot's
  hook file is a machine-level path with no repository equivalent, and the
  opencode plugin is loaded from the user's config directory, not contributed by
  a repository.

## Machine-wide wiring (`--managed`)

`argus install --managed` writes into the administrator-owned layer each tool
reads *above* the user's own config. That layer is the only wiring an ordinary
account cannot edit away, which is the whole point: a user-scope install is a
file in the user's home directory, and anyone who can be captured by it can also
delete it.

It needs root/Administrator. `--dry-run` does not — it writes nothing — but it
says so on stderr when the real install would fail, because "the preview worked"
must not read as "the install will".

| Tool        | macOS                                          | Linux              | Windows                          |
| ----------- | ---------------------------------------------- | ------------------ | -------------------------------- |
| Claude Code | `/Library/Application Support/ClaudeCode/`      | `/etc/claude-code/`| `C:\Program Files\ClaudeCode\`   |
| Codex       | `/etc/codex/`                                   | `/etc/codex/`      | `C:\ProgramData\OpenAI\Codex\`   |

Both were read out of the shipped binaries rather than from documentation, which
is how the two surprises here were found: macOS Codex uses `/etc/codex` like
Linux and has no `Library/Application Support` location, and the same Codex
setting is spelled `managed_dir` on unix and `windows_managed_dir` on Windows,
with the binary treating both-at-once as a conflict.

**Claude Code** gets one file, `managed-settings.json`: argus's hook entries plus
two pinned settings.

- `disableAllHooks = false` — the switch that would otherwise turn every hook off
  from a file the user owns. Pinning it is what actually protects capture.
- `allowManagedHooksOnly = true` — restricts execution to hooks in *this* file.
  argus's are in it, so its capture is unaffected. **The user's own hooks stop
  running.** That is a real cost and a deliberate one: it is what an
  administrator deploying this layer is asking for, and `check --managed` reports
  it flipped back rather than letting the posture drift.

Claude Code also honours `managed-settings.d/*.json` beside that file, a Windows
registry policy under `HKLM\SOFTWARE\Policies\ClaudeCode`, and the macOS MDM
domain `com.anthropic.claudecode`. argus reads the drop-in directory (a kill
switch hidden there counts) but writes only the file: an MDM that can set a
policy key does not need argus to set it, and a registry value argus wrote would
be invisible to the file-based `check`.

**Codex** gets three files, and the order they are written in matters:

1. `hooks/hooks.json` — argus's entries, inside the managed hooks directory.
2. `config.toml` — `[hooks] managed_dir` (or `windows_managed_dir`) pointing at
   that directory. Written **only if absent**: a `managed_dir` already set is an
   administrator's own hooks directory, and breaking hooks argus knows nothing
   about is worse than reporting the conflict, which is what `check --managed`
   then does.
3. `requirements.toml` — `allow_managed_hooks_only = true`. Codex's layer
   precedence puts the system `config.toml` below MDM and enterprise-managed
   config, so enforcement has to live in `requirements.toml`; this is the one
   value argus overwrites, and re-running the install is the documented repair
   for finding it flipped.

(3) tells Codex to run managed hooks *and nothing else*, so writing it before (1)
exists would leave the machine running no hooks at all — for the length of an
install, not an instant. Hence the order, which is asserted by a test.

Deliberately not written into Codex's managed layer: `notify` and `[otel]`, which
carry this install's receiver token and per-user OTLP port — a machine-wide file
is world-readable, so that would hand every account on the host a credential in
exchange for wiring that can only be right for one of them. Also not written is a
`feature_requirements` pin: the field exists but its inner schema is not readable
from the shipped binaries, and a `requirements.toml` Codex rejects for an unknown
field is a config-load failure for *every* user on the machine. That gap is
covered from the other side — `check` reports `[features] hooks = false` wherever
someone sets it, machine-wide layer included.

Copilot CLI, opencode and pi have no machine-wide layer wired: Copilot's hook
file is already a per-user path with no administrator equivalent, and the
opencode and pi extensions are loaded from the user's config directory.

`argus check --managed` verifies the layer and exits `2` if anything is missing
or flipped. Unlike `--project`, a *missing* managed artifact is BROKEN rather
than silent — passing the flag asserts the layer should be there. Reading it
needs no privilege, so an MDM compliance script can run it as the logged-in user.

### The multi-user consequence

`--managed` wires **tools, not users**, and everything on the receiving end of a
hook is per-user. Two things follow, and neither is optional:

- **The `argus` binary must be executable by every account on the machine.** The
  hook command is a path baked into a file every user reads; installed somewhere
  only root can execute, every hook on the machine fails.
- **Each account needs its own running daemon.** The socket (`0600` in a `0700`
  directory), the Codex OTLP port (derived from the data directory, deliberately
  not fixed) and the SQLite buffer are all per-user by construction — that is
  what stops one account's Codex posting prompts into another's audit trail. One
  machine-wide hook plus one daemon means every other account spools to disk and
  exports nothing.

The daemon autospawns from the first hook invocation, so in practice this is
satisfied as soon as each user runs an agent once — but a fleet rollout that
assumes a single daemon covers the host will be wrong about every account but
one.

## Environment variables

Mostly for tests and for running argus somewhere other than a real home
directory; none are needed for an ordinary install.

| Variable             | Effect                                                                                       |
| -------------------- | -------------------------------------------------------------------------------------------- |
| `ARGUS_DATA_DIR`     | Override the data directory (buffer, spool, socket, config, Codex token).                     |
| `ARGUS_HOME`         | Override the home directory `install`/`uninstall`/`check` resolve tool config against.        |
| `ARGUS_SOCKET`       | Exact socket path (or Windows pipe name) instead of one derived from the data directory.      |
| `ARGUS_BIN`          | Path baked into the hook commands `install` writes, instead of the running binary's.          |
| `ARGUS_BIN_DIRS`     | Replace the directories detection searches for tool binaries.                                 |
| `ARGUS_SYSTEM_ROOT`  | Treat this directory as the system root for `--managed`. Marked "not the real machine", so the privilege check is skipped and the round-trip tests can sweep all three platforms. |
| `ARGUS_NO_AUTOSPAWN` | Stop the hook shim starting a daemon; it spools instead.                                      |
| `ARGUS_RECORD_DIR`   | Dump every envelope **raw, before redaction**, for writing adapters. Off unless set; see [Privacy and redaction](#privacy-and-redaction). |

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
    intact would be worse than reporting nothing. Each hook entry must also be
    byte-for-byte the entry this argus writes, not merely present and
    ours-marked: a command retargeted at another adapter still resolves and
    still fires, and files the wrong events under the wrong tool — rows that
    look real. `timeout: 0` and a second hook body appended inside our own
    entry pass every earlier test too. Codex additionally records trust against
    a hook's *current hash*, so an altered entry there is skipped until
    re-trusted via `/hooks` — reported as `hooks altered`, remedied by
    `argus install`, which refreshes its own entries in place. The same applies
    to the bearer token in the `[otel]` block: a Codex presenting a token this
    install does not know is refused on every turn, which looks exactly like a Codex nobody
    is using. The error says the token is wrong, never what it is — `check`
    output is collected and indexed by whatever is polling it.
    **Upgrading to 0.3.0 can flip hosts to broken that previously reported
    intact** — that is the fix, not a regression. Wiring baked against a binary
    that has since moved (a `brew upgrade` that bumps the Cellar prefix, an
    `npm` reinstall, `cargo install` to a new root) has not been capturing
    anything; `check` simply says so now. `argus install` re-points it, and
    installs now bake the stable `PATH` alias rather than the resolved real
    path, so the next upgrade doesn't repeat it.

    Wiring that is intact is not the same as wiring that runs, so `check` also
    reads the settings that leave every entry in place and stop it firing.
    Every one of these passes the wiring checks above — that is what makes them
    worth a separate read.

    **Claude Code** resolves hooks through four such settings, read out of the
    shipped `cli.js` rather than from documentation:

    | Setting                                  | Effect                       |
    | ---------------------------------------- | ---------------------------- |
    | `disableAllHooks` (machine-wide layer)   | nothing runs, managed or not |
    | `disableAllHooks` (user `settings.json`) | only machine-wide hooks run  |
    | `allowManagedHooksOnly`                  | only machine-wide hooks run  |
    | `strictPluginOnlyCustomization`          | only machine-wide hooks run  |

    Three of the four restrict execution to the machine-wide layer and only the
    first stops that layer too. `strictPluginOnlyCustomization` appears in no
    documentation — it is either `true` or a list of the customizations it
    covers, and only the list containing `hooks` reaches ours. All four are read
    from the machine-wide file *and* from `managed-settings.d/*.json` beside it,
    since a switch hidden in a drop-in counts exactly as much.

    The three "only machine-wide hooks run" rows are reported only where argus
    is *not* itself in that layer. Where it is (after `install --managed`), a
    rule keeping only managed hooks changes nothing about its capture, and
    reporting it would fire on every host the managed install has run on —
    argus's own pin reported as argus's own kill switch.

    **Codex**: `[features] hooks = false` (and its deprecated `codex_hooks`
    alias) and `allow_managed_hooks_only = true`, which keeps only
    administrator-managed hooks. Both are read from `config.toml` and
    `requirements.toml` in **both** the user directory and the machine-wide
    layer, which outranks it — a switch set there is the one that decides. A
    file of either name that no longer parses is itself a finding, because Codex
    cannot read it either. `allow_managed_hooks_only` gets the same
    argus-is-the-managed-hook suppression as Claude Code, applied to the user
    file too, since the question is whether argus's hooks are managed and not
    who set the flag. `[features] hooks = false` gets no such escape: it stops
    every hook on the machine.

    **Copilot**: `disableAllHooks: true` at the top of argus's own
    `~/.copilot/hooks/argus.json`, plus the same does-it-still-parse test, since
    marker text survives trailing garbage that makes the document unloadable.

    **opencode and pi** have no equivalent setting. pi's extensions are loaded
    by presence, so removing one is the only way to disable it — and there is
    nothing silent to detect, because the wiring check already sees it gone.

    Two limits worth stating: `disableAllHooks` in a *repository*
    `settings.json` skips every hook from every source for sessions in that
    repository, which no machine-level check can see; and a `disableAllHooks` in
    someone else's hooks file is file-scoped, disables their hooks rather than
    ours, and is deliberately not reported.
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

  Two more scopes can be added to any of the above: `--project <dir>` for a
  repository's wiring (missing is silent), and `--managed` for the
  administrator-owned layer (missing is BROKEN — see
  [Machine-wide wiring](#machine-wide-wiring---managed)).
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
  `~/.codex/config.toml` (`notify`, `[otel]`), `~/.codex/hooks.json`,
  `~/.copilot/hooks/argus.json`, or `~/.pi/agent/extensions/argus.ts`. Re-run `argus install`
  (idempotent) if entries are missing — it also **refreshes** an argus entry
  that an older release wrote, so an upgrade that changes a hook's command or
  timeout reaches hosts that are already wired. Hooks beside ours are left
  alone. Codex hooks additionally need one-time trust: run `/hooks` inside
  Codex and trust the argus entries, and re-trust after any upgrade that
  rewrote them — Codex records trust against a hook's current hash and skips
  changed hooks until reviewed.
- **Codex config not touched**: install never overwrites an existing `notify`
  or `[otel]` block — it warns on stderr and leaves it alone so it can't
  silently break another integration. Remove the conflicting block manually
  (or point it at argus yourself) if you want Codex wired.

## Known limitations (v1)

- No OS service management (`launchd`/`systemd`/Windows service) — the daemon
  is autospawned by the first hook invocation instead.
- Remote config is trusted over HTTPS; no detached-signature verification yet.
- Bash tool parsing only extracts FQDNs, not file writes via `>`/`tee`. A file
  written that way is invisible to file-content capture too — nothing names it,
  so there is no candidate to read.
- No Claude Code transcript-path mining for token/model usage stats.
- The hand-off spool holds un-redacted payloads while the daemon is down — see
  [The spool holds un-redacted payloads on disk](#the-spool-holds-un-redacted-payloads-on-disk).
- Claude Code `MessageDisplay` and `FileChanged` are deliberately not wired —
  see the wired-hooks notes in [Per-tool fidelity](#per-tool-fidelity).
