# Telemetry gap review — what more we can capture

Code review of the adapters, extractors, plugin shim, and event model
(2026-07-11), focused on two questions: what session context and what network
activity is available at each hook surface but not yet captured.

Items closed since are annotated in place with the task that closed them and
what the implementation decided where it differed from the fix sketched here.
Everything without a **Closed** note is still open; [Status](#status) lists
both sides so a reader does not have to scan for the absence of a label.

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

Still open, and it costs more than it did: file-content capture keys off the
same `FILE_KEYS` path spellings, so a file written through a redirect is not
merely unnamed — it is the one write whose *contents* no capture mode can
reach, because nothing in the payload says which file to read.

## Session context

### 8. Event timestamps are wrong for spooled events

`Event::new` stamps `ts = Utc::now()` **at daemon parse time**
(`src/event.rs:128`), and `Envelope.received_at` (set by the shim/plugin at
capture time) is never used. Normally the gap is milliseconds, but events
spooled while the daemon is down get stamped hours/days late when drained.

**Fix:** thread `env.received_at` into the adapters and use it as `ts`
(keep parse time as a secondary field if useful). This is the single biggest
fidelity fix in this list.

**Closed (T6b).** Not threaded into the adapters: every event an envelope
produces has its `ts` overwritten with `envelope.received_at` at the single
point where parsing returns (`harness/mod.rs`). Threading it through five
adapters would have made correctness depend on each of them remembering, and
the one that forgot would be invisible — a plausible timestamp is the failure
mode nobody notices. Parse time is not kept as a second field: it answers no
question about the session, only about the daemon.

### 9. opencode drops model, token, and cost data it already receives

The plugin forwards only `message.role` (`plugins/opencode/argus.ts:103`),
but opencode's assistant message object carries `modelID`, `providerID`,
token counts, and cost. That's per-turn usage telemetry — currently discarded
in the shim, so no adapter change can recover it.

**Fix:** forward `message.id`, `modelID`, `providerID`, `tokens`, `cost` from
the plugin; map `modelID` → `meta.model` and add token/cost to a new event
field or `Session` detail.

**Closed (T13e).** Of the two options in that fix, the new event kind rather
than `Session.detail`: a receipt buried in a JSON blob can only be aggregated
by parsing every row, and cost-per-session is exactly the query that has to be
cheap for the number to ever get looked at. `EventKind::Usage` carries the five
counts, the cost, and the stop reason as separate fields; `redact.rs` and
`export.rs` match `EventKind` exhaustively, so the variant forced both to say
what they do with it.

`meta.model` is `providerID/modelID`, not `modelID` alone — the same model name
is served by more than one provider, and which one saw the turn is the whole
question a policy about third-party models is asking. `messageID` →
`meta.turn_id`, which is what a turn id is; `callID` already took
`meta.tool_use_id` in T13d.

The filter that keeps this off the hot path lives in the plugin, not the
adapter: `message.updated` fires on every streamed delta and only the last one
carries totals, so the plugin forwards it only when
`info.role === "assistant" && info.time.completed`. The partial receipts never
leave the editor process, and the daemon never has to guess which of a dozen
frames was final.

### 10. opencode: no cwd, and callID is dropped

- Events from opencode always have `cwd: null`; the plugin has access to the
  app/project directory and worktree and could send it.
- The plugin sends `callID` for tool events but `opencode.rs` ignores it — so
  pre/post tool events can't be paired (no duration, no output↔input join).
  Map `callID` → `meta.turn_id` (or a dedicated `call_id`).

**Closed (T13d).** The plugin sends `cwd` on every hook, taken from the
`directory` opencode hands it at load (`worktree` only as a fallback — the two
differ inside a git worktree). `callID` maps to `meta.tool_use_id`, the field
Claude Code's `tool_use_id` already uses, rather than to `turn_id`: a turn and
a call are not the same thing, and one turn holds many calls.

### 11. No pre/post correlation → no tool durations anywhere

Same story for the other tools: if the hook payload carries a call id
(Claude Code payloads carry `tool_use_id` on recent versions; verify per tool),
capture it. With a call id, tool latency, hung-tool detection, and
output-to-input joins all become simple queries. Without it, only heuristic
(same session, adjacent seq) pairing is possible.

**Closed for three of five.** Claude Code carries `tool_use_id` (T10b) and,
since it reports one directly, `duration_ms` (T10c) — a measured duration
beats one subtracted from two timestamps stamped on different sides of a
socket. opencode maps `callID` (T13d), pi its tool-call id (T14a); opencode's
permission events carry the same id, so a prompt joins the call it gated
rather than being matched by adjacency.

Still open for Codex and Copilot, whose payloads have not been audited for an
id — see #16. Neither reports a duration either, so those two are the pairs
that remain heuristic.

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

**Partly closed.** `meta.model` is carried where the surface reports it, and
the per-event process spawn behind `host`/`username` is gone (T6a). Tool
version, monitor version in the body, and PID/tty remain open.

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

  **Closed (T6a).** Host *and* username behind one `OnceLock`, since both were
  paying per event and both are constant for the life of a process.

- `extract_files_for_tool` calls `out.dedup()` without sorting — only adjacent
  duplicates are removed (apply_patch touching the same file twice keeps
  both). Sort first or dedup via a set, preserving first-seen order if needed.

  **Closed (T10f).** Sorted before the dedup. First-seen order was not worth
  preserving: nothing consumes the list positionally, and a sorted list is the
  one that compares equal across two captures of the same call.

- `EventKind::Permission.action` doc comment says `"requested" | "denied" |
"replied"` but opencode also emits `"updated"` — update the comment.

  **Closed, the other way round.** The comment was right and the adapter was
  wrong: `permission.updated` *is* opencode's ask — it carries the tool type,
  the pattern matched, and the call gated. The mapping to `requested` lived in
  an arm for `permission.asked`, an event opencode has never emitted, so every
  permission request on opencode arrived labelled `updated` and a query for
  requests matched nothing. `updated` now maps to `requested`.

## Status

Closed:

- **#8** spooled-event timestamps (T6b) — the item this list called its single
  biggest fidelity fix.
- **#9** opencode model/tokens/cost (T13e), as an `EventKind::Usage` rather
  than a JSON blob on the session.
- **#10** opencode `cwd` and `callID` (T13d).
- **#11** call ids, for Claude Code (T10b), opencode (T13d) and pi (T14a),
  plus a reported tool duration on Claude Code (T10c).
- **#14** in part: the per-event `hostname` spawn (T6a).
- Both remaining small fixes: the unsorted `dedup` (T10f) and opencode's
  permission action, which turned out to be an adapter bug rather than a stale
  comment.

Open, in the order this list would still do them:

1. **#1/#2/#3 network extraction** — recursive scan of nested strings,
   non-HTTP schemes and schemeless hosts, and port/scheme retention. Untouched,
   and still the group that answers "what did the agent talk to".
2. **#4** output scanning, **#5** Codex file extraction (`files: vec![]` is
   still literal in `codex.rs`), **#6** MCP server tagging.
3. **#7** Bash file activity — now also the one write file capture cannot see.
4. **#11** for Codex and Copilot, and **#16**, which is the audit that would
   tell us whether their payloads carry an id at all.
5. **#12** transcript mining, **#13** git enrichment, **#15** Codex `raw`
   inventory, and the rest of **#14**.

Not on this list because it postdates it: file-content capture, which answers
"what did the agent write" — a question this review did not ask. Off by
default; see the README.

## Suggested priority (as first written)

1. **#8 spool timestamps** — silent data-quality bug.
2. **#1/#2/#3 network extraction** (recursive scan, non-HTTP schemes, ports) —
   directly answers "what did the agent talk to".
3. **#9/#10 opencode plugin fields** — model/tokens/cost/cwd/callID are free;
   the data is already in-process.
4. **#5 Codex file extraction**, **#6 MCP server tagging** — small adapter changes.
5. **#11 call-id capture** → durations.
6. **#12 transcript mining**, **#13 git enrichment** — bigger, opt-in features.
