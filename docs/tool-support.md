# Per-tool fidelity

Each tool exposes a different amount of detail through its hook/plugin API;
argus captures everything each surface offers.

| Signal                        |        Claude Code         |       opencode        |          Codex          |        Copilot CLI        |          pi          |
| ----------------------------- | :------------------------: | :-------------------: | :---------------------: | :-----------------------: | :------------------: |
| Prompts                       |             Y              |           Y           |            Y            |             Y             |          Y           |
| Prompt rewritten en route     |             —              |           —           |            —            | Y (userPromptTransformed) |          —           |
| Assistant messages            |          Y (Stop)          |           Y           |      Y (Stop hook)      |     Y (subagent only)     |          —           |
| Tool use (pre/post)           |             Y              |           Y           |            Y            |             Y             |          Y           |
| Tool outputs                  |             Y              |           Y           |            Y            |             Y             |    Y (text parts)    |
| Tool failures                 |             Y              |           —           | Y (post incl. non-zero) |             Y             |     Y (isError)      |
| Call id (pairs pre with post) |             Y              |      Y (callID)       |       Y (call_id)       |       — (adjacency)       |          Y           |
| Tool duration reported        |             Y              |           —           |     Y (duration_ms)     |             —             |          —           |
| File paths touched            |             Y              |           Y           | Y (incl. shell patches) |             Y             |          Y           |
| FQDNs + endpoints contacted   |             Y              |           Y           |            Y            |             Y             |          Y           |
| Skill/command invocations     |             Y              | Y (command.executed)  |            —            |             —             |          —           |
| Slash-command expansion       |     Y (expanded text)      |           —           |            —            |             —             |          —           |
| Subagent runs                 |       Y (start+stop)       |           —           |            Y            |      Y (start+stop)       |          —           |
| Permission requests           |     Y (request+denied)     |   Y (request+reply)   |  Y (decision recorded)  |             Y             |     — (no event)     |
| Compaction                    | Y (pre+post, token counts) | Y (session.compacted) |            Y            |          Y (pre)          | Y (pre+post, before) |
| Errors                        |      Y (StopFailure)       |   Y (session.error)   |            —            |     Y (errorOccurred)     |  Y (turn_end stop)   |
| Config/instructions changes   |             Y              |           —           |            —            |             —             |          —           |
| Directory scope changes       |        Y (/add-dir)        |           —           |            —            |             —             |          —           |
| Session lifecycle             |             Y              |           Y           |            Y            |             Y             |          Y           |
| Model, tokens, cost per turn  |             —              |  Y (message.updated)  |            —            |             —             |     Y (turn_end)     |
| Interactive shells (pty)      |             —              |  Y (created+exited)   |            —            |             —             |  Y (user_bash `!`)   |
| File contents                 |         Y (opt-in)         |      Y (opt-in)       |       Y (opt-in)        |        Y (opt-in)         |      Y (opt-in)      |

The notes below expand on the rows that need more than one word of context.

**Copilot's `userPromptTransformed`** is the one row with no equivalent
elsewhere. It reports what was _actually_ sent to the model after every hook,
plugin and enterprise policy in the chain had a turn at editing it — that's
the reason it's wired.

- An instruction spliced in there appears nowhere else: the user never typed
  it, and the transcript just shows the model obeying it.
- Both halves ride in one `prompt_transformed` event (`original` and
  `transformed`, each redacted), with a `prompt.rewritten` attribute so a SIEM
  can alert on the edit without diffing two prompt bodies on every turn.
- `capture.prompts = false` suppresses both halves.

**pi's two dashes** are absences in pi, not gaps in argus.

- No permission event at all: gating a tool call is an extension's own
  `tool_call` handler returning `{block, reason}`, so there is nothing to
  observe and argus records what ran rather than what was asked.
- No assistant-message event that carries the text: `turn_end` hands over the
  finished message, which argus reads for the model, tokens, cost and stop
  reason.
- The `!`-prefixed shell command is pi's answer to opencode's pty — a command
  the user runs directly, which never passes through `tool_call`, and whose
  `!!` form the transcript itself never records either.

**Call id** is what makes a `pre` and a `post` the same tool call rather than
two events that happen to be adjacent.

- Two `bash` calls in one turn are otherwise indistinguishable, so a call that
  hung — a `pre` whose `post` never came — reads exactly like one that
  finished.
- Copilot's dash is an absence in Copilot: no documented payload carries a
  call id, so its pairing is adjacency within a session. argus reads the
  field anyway under the spellings Copilot uses elsewhere, so a build that
  starts sending one is paired properly that day.
- Where a duration is reported, it is the tool's own measurement rather than
  one subtracted from two timestamps stamped on either side of a socket; the
  other three surfaces report none, and argus does not invent one.

**File contents** is uniform across all five tools because it is the one
feature that does not read a tool's vocabulary.

- Enrichment runs on every tool event whatever produced it, and picks
  candidates out of the input by shape — the file-path keys the adapters
  already agree on, an `apply_patch` body, an `edits` array — so a surface
  gets file capture by carrying a path, not by being on a list.
- See [File-content capture](capture.md#file-content-capture); it is off by
  default.

**File paths** includes the files a shell command names, on every surface,
because a `>` redirect writes a file that no path key in the payload
mentions.

- Two shapes are read out of a command line and no others: the target of a
  redirection (`> out.txt`, `>> log`, `2> err.log`), and the arguments of the
  few programs whose whole job is to move bytes between paths — `cp`, `mv`,
  `rm`, `tee`, `touch`, and `sed` when it edits in place.
- `cat /etc/passwd` names nothing; a longer verb table would fill `files`
  with whichever argument happened to look like a path, and that field is
  read as _what this session touched_.
- Descriptors (`2>&1`), `/dev/null`, globs and unexpanded variables are not
  paths and are dropped.
- The files such a command **writes** — a redirect target, a `cp`
  destination — are also capture candidates in `disk` mode; a `cp` source and
  an `rm` argument are listed as touched but never opened, the first because
  the shell read it rather than the tool, the second because it is gone.

**A `Y` in the table means the event is recorded, not that every field in it
is.** Four fields that used to be read past are now kept, because each is the
part of its event a reviewer would actually look for:

- **Compaction's `custom_instructions` / `customInstructions`** — compaction
  is the one point where the session's own history is rewritten, and after
  the rewrite the request to leave something out is the only surviving
  evidence that it was ever there. So it is captured, redacted, and exported
  as a `compact.directed` boolean for alerting.
- **A notification's `title`** — usually the only part a human reads.
- **An error's `name` and `recoverable`** — what make errors groupable and
  what separate a retried blip from a session that stopped working.
- **A Copilot subagent's `agentDescription`** (the task it was spawned for)
  plus its `response`, recorded as an assistant message rather than buried in
  a session blob, so capping, redaction and
  `capture.assistant_messages = false` apply to it like any other.
- Copilot's `error.stack` is deliberately dropped: it is unbounded and
  describes the host tool's own file layout, not the session.

**Codex** is wired three ways at once: its hooks system
(`~/.codex/hooks.json`, Claude-compatible payloads — note new hooks need
one-time trust via `/hooks` inside Codex), the `notify` hook for turn
completion on older versions, and OTLP logs (`[otel]` in `config.toml`) for
token/model telemetry.

## Claude Code hooks deliberately not wired

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

---

Back to the [project README](../README.md).
