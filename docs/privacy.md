# Privacy and redaction

What argus scrubs before data leaves the machine, and the one place — the
hand-off spool — where that guarantee does not yet apply.

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
  [adding-a-tool.md](adding-a-tool.md).

## The spool holds un-redacted payloads on disk

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
the Codex receiver token that already live there. See [Data
directory](architecture.md#data-directory) for where it is per platform.

---

Back to the [project README](../README.md).
