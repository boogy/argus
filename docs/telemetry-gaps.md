# Telemetry gap review — what more we can capture

Code review of the adapters, extractors, plugin shim, and event model
(2026-07-11), focused on two questions: what session context and what network
activity is available at each hook surface but not yet captured.

## Network connections

### 1. FQDN extraction only sees three top-level keys

`NET_KEYS = ["url", "command", "query"]` in `src/adapters/mod.rs:39`, checked
only at the top level of the tool input. Anything nested is missed — MCP tools
(`mcp__server__tool`) take arbitrary nested JSON, and multi-field inputs
(e.g. headers, bodies, env vars) are never scanned.

**Fix:** recursively walk every string value in the input and run
`extract_fqdns` over it. Cost is negligible (inputs are already size-capped).

### 2. Scheme-required regex misses most non-HTTP egress

`extract_fqdns` (`src/adapters/mod.rs:117`) only matches `http(s)://` URLs.
Not captured from Bash/shell commands:

- schemeless hosts: `curl example.com/x`, `wget example.com`
- SSH-family: `git clone git@github.com:org/repo`, `ssh host`, `scp`, `rsync`
- other protocols: `ftp://`, `nc host 4444`, `telnet`, `dig`/`nslookup` lookups
- implied registries: `pip install` / `npm install` / `cargo add`
  (`--index-url`/`--registry` overrides are the security-relevant part)
- proxy env vars in commands: `HTTP_PROXY=http://...`
- IPv6 literals (documented out of scope today)

**Fix:** per-command extraction for a small set of known network binaries
(curl, wget, git, ssh, scp, rsync, nc, pip, npm, …) plus a generic
`scheme://host` matcher beyond http.

### 3. Only the hostname survives — port, scheme, and path are dropped

`https://exfil.example.com:8443/upload?d=...` is stored as
`exfil.example.com`. For security triage, scheme + port (and optionally path)
distinguish "read docs" from "POST to an unusual port".

**Fix:** add a `urls` field (full sanitized URL, credentials stripped —
the regex already skips userinfo) next to `fqdns` on `ToolUse`, or store
`host:port` when a non-default port is present.

### 4. Tool outputs are never scanned

Extraction runs on `tool_input` only. Post-tool outputs can reveal network
facts the input can't: redirect targets from WebFetch, URLs in WebSearch
results, resolved hosts in command output.

**Fix:** run `extract_fqdns` over the output JSON on `post` events and merge
into `fqdns` (input-derived and output-derived can be distinguished with a
separate field if needed).

### 5. Codex OTLP tool events extract no files and few FQDNs

`codex.rs:64-72`: `files: vec![]` always; FQDNs come only from
`command`/`arguments` attributes. `apply_patch` content arriving via OTLP
attributes is never mined for file paths even though `extract_patch_files`
exists.

**Fix:** call `extract_files_for_tool(tool, &attrs)` and reuse the patch
extractor on the joined text blob.

### 6. MCP server inventory

Tool names like `mcp__github__create_issue` identify the MCP server, and
`.mcp.json` / `~/.claude/settings.json` list server endpoints/commands. Today
MCP calls are just generic `tool_use` rows.

**Fix (cheap):** when a tool name matches `mcp__<server>__<tool>`, split it and
record `mcp_server` (e.g. in `Meta` or on `ToolUse`). **Fix (richer):** at
install/ConfigChange time, snapshot configured MCP servers and their URLs as a
`session`/`file_change` detail — that maps server names to actual endpoints.

### 7. Bash file activity (known limitation, worth closing)

Writes via `>`, `>>`, `tee`, and `cp/mv/rm` targets are invisible to
`extract_files_for_tool`. A light shell-word pass over Bash commands for
redirection targets and file-verb arguments would close most of it.

## Session context

### 8. Event timestamps are wrong for spooled events

`Event::new` stamps `ts = Utc::now()` **at daemon parse time**
(`src/event.rs:128`), and `Envelope.received_at` (set by the shim/plugin at
capture time) is never used. Normally the gap is milliseconds, but events
spooled while the daemon is down get stamped hours/days late when drained.

**Fix:** thread `env.received_at` into the adapters and use it as `ts`
(keep parse time as a secondary field if useful). This is the single biggest
fidelity fix in this list.

### 9. opencode drops model, token, and cost data it already receives

The plugin forwards only `message.role` (`plugins/opencode/llm-monitor.ts:103`),
but opencode's assistant message object carries `modelID`, `providerID`,
token counts, and cost. That's per-turn usage telemetry — currently discarded
in the shim, so no adapter change can recover it.

**Fix:** forward `message.id`, `modelID`, `providerID`, `tokens`, `cost` from
the plugin; map `modelID` → `meta.model` and add token/cost to a new event
field or `Session` detail.

### 10. opencode: no cwd, and callID is dropped

- Events from opencode always have `cwd: null`; the plugin has access to the
  app/project directory and worktree and could send it.
- The plugin sends `callID` for tool events but `opencode.rs` ignores it — so
  pre/post tool events can't be paired (no duration, no output↔input join).
  Map `callID` → `meta.turn_id` (or a dedicated `call_id`).

### 11. No pre/post correlation → no tool durations anywhere

Same story for the other tools: if the hook payload carries a call id
(Claude Code payloads carry `tool_use_id` on recent versions; verify per tool),
capture it. With a call id, tool latency, hung-tool detection, and
output-to-input joins all become simple queries. Without it, only heuristic
(same session, adjacent seq) pairing is possible.

### 12. Transcript mining (already a known limitation, high value)

`meta.transcript_path` is captured for Claude Code and Copilot but never read.
An opt-in, daemon-side pass at `SessionEnd`/`Stop` could extract per-turn
model, token usage, cost, and timing from the transcript JSONL — the data the
hook surface itself never provides. Keep it off the hot path and behind a
`capture.transcripts` flag (transcripts are sensitive).

### 13. Git/repo context enrichment

`cwd` is captured, but "which repo/org does this session touch" requires the
consumer to guess. At `SessionStart` (daemon-side, not in the shim) read
`.git/HEAD` and `git config --get remote.origin.url` under `cwd` and attach
`repo.remote`/`repo.branch` to the session event. Cheap, and it turns FQDN/file
reports into per-repo reports.

### 14. Environment/process context

Events carry `host` + `username` only. Cheap additions at event-creation time:
tool version (Claude Code sends `version`/`model` in some payloads; Copilot has
a version field), the monitor's own version (already on the OTLP scope but not
in `body`), and parent PID/tty for correlating simultaneous sessions.

### 15. Codex OTLP: unmapped event names land in `raw`

Only `codex.user_prompt`, `codex.tool_decision`, `codex.tool_result`,
`codex.conversation_starts` are mapped. Codex's OTel stream also emits
API-request/turn events with model and token attributes; today they land as
`raw` (so they're not lost — run the `raw` inventory query from
`querying-local-database.md` on a machine with Codex traffic and map what
shows up, especially anything with token counts).

### 16. Copilot payload fields worth auditing

The adapter keeps `agentName` and `transcriptPath` but nothing else from the
envelope. Copilot payloads also carry a per-turn id and timestamps on some
events; audit a live capture (`raw` rows + spool files) and lift what exists
into `Meta`.

## Small correctness/efficiency fixes found on the way

- `hostname()` (`src/event.rs:142`) spawns the `hostname` process **per
  event**. Cache it in a `OnceLock`.
- `extract_files_for_tool` calls `out.dedup()` without sorting — only adjacent
  duplicates are removed (apply_patch touching the same file twice keeps
  both). Sort first or dedup via a set, preserving first-seen order if needed.
- `EventKind::Permission.action` doc comment says `"requested" | "denied" |
"replied"` but opencode also emits `"updated"` — update the comment.

## Suggested priority

1. **#8 spool timestamps** — silent data-quality bug.
2. **#1/#2/#3 network extraction** (recursive scan, non-HTTP schemes, ports) —
   directly answers "what did the agent talk to".
3. **#9/#10 opencode plugin fields** — model/tokens/cost/cwd/callID are free;
   the data is already in-process.
4. **#5 Codex file extraction**, **#6 MCP server tagging** — small adapter changes.
5. **#11 call-id capture** → durations.
6. **#12 transcript mining**, **#13 git enrichment** — bigger, opt-in features.
