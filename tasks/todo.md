# argus implementation ledger

Tracks progress against `/Users/bogdan/.claude/plans/how-can-we-better-elegant-engelbart.md`
(harness detection, hook parity, and granular capture).

## Resume procedure

A box below flips to `[x]` only after `make verify` passes **and** the commit
for that task has landed — the ledger can be stale, so cross-check it:

```sh
git log --oneline | grep -E '^[0-9a-f]+ T[0-9]+:'   # tasks actually landed — the source of truth
git status --porcelain                              # must be empty between tasks
```

- Clean tree → find the lowest-numbered unchecked task whose dependencies are
  all in the log, and start it.
- Dirty tree → a task was cut off mid-edit. Finish it or reverse the edits by
  hand (reverse each `Edit`, or `cp` from a backup). Never `git checkout
  <file>`, `git restore`, `git stash`, or `git reset --hard` — those destroy
  uncommitted work beyond the edit being undone. Then re-run `make verify`
  before flipping the box.

One branch-less commit per task on `develop`, message subject prefixed `T<n>: `.

## Tasks

- [x] **T1** — CI matrix. Dependency: none.
  Files: `.github/workflows/ci.yml`, `tasks/todo.md`, `tasks/lessons.md`
  Note: T1 landed with `make verify` failing on the *pre-existing* baseline
  (57 fmt diffs + 7 clippy errors — the repo had never been verified on the
  current toolchain; see `tasks/lessons.md`). Mostly repaired in `cfd499e`, a
  separate non-`T`-prefixed commit. `cfd499e` does **not** verify on its own:
  `src/install.rs` and `src/integrity.rs` were reformatted by the same
  `cargo fmt` run but T2 had already rewritten them, so their fmt fix is
  inside `934a097`. `934a097` is the first commit on `develop` where
  `make verify` passes end to end.

- [x] **T2** — `trait Harness` + `Artifact` refactor. Dependency: T1.
  Files: new `src/harness/*`, `src/install.rs`, `src/integrity.rs`, `src/adapters/mod.rs`, `src/redact.rs`, `src/lib.rs`, `docs/adding-a-tool.md`
  Note: also fixed three bugs the duplication was hiding — orphaned empty
  hook keys on uninstall (incl. sweeping ones left by older installs),
  ownership by `"argus"`-anywhere substring, and unquoted hook commands.
  `Scope::Managed`, `Signal::{Binary,NpmGlobal,Brew}` and `KillSwitch` are
  declared but not yet populated (T4/T11/T12/T15), marked in-source.

- [x] **T3** — Make `check` prove capture actually works. Dependency: T2.
  Files: `src/integrity.rs`, `src/install.rs`, `src/harness/{codex,copilot,opencode,mod}.rs`, `README.md`, `docs/adding-a-tool.md`
  Note: `check` no longer accepts presence as proof — it resolves the program
  in every hook command (deduped, so a moved binary reports once), rejects
  empty/marker-less owned files, and verifies Codex `config.toml` (`notify`
  argv element-wise via `TomlEditOp.argv_tail`, plus `[otel]`) which was
  previously never checked at all. Install now bakes the stable `PATH` alias
  (`install_path`) rather than `current_exe()`, whose symlink resolution names
  a Cellar path the next brew upgrade deletes. `Artifact::OwnedFile` gained
  `markers` (raw-text, JSON-escaped substrings) and `commands` (unescaped,
  program must resolve) — they cannot be one field. opencode is a deliberate
  exception: its plugin speaks the socket, so it has no command to resolve and
  stays ok when the binary is gone. Release note added to `README.md`: this
  flips previously-intact hosts to broken, which is the fix, not a regression.
  Mutation-verified: each of the five new guarantees was neutralized in turn
  and the matching tests failed. Untested seam: the `stable_alias` call inside
  `install_path` (`current_exe()` isn't controllable in-process); the function
  itself is tested directly.

- [x] **T4** — Cross-platform detection. Dependency: T3.
  Files: new `src/detect.rs`, `src/harness/mod.rs`, `src/install.rs`, `src/main.rs`,
  `src/harness/{claude_code,codex,copilot,opencode}.rs`, `src/integrity.rs`,
  `README.md`, `docs/adding-a-tool.md`
  Detection is now four independent signals (config dir, binary, npm, brew)
  instead of one home-dir `is_dir()`, which was wrong in both directions: it
  missed a tool installed but never run, and it fired on a leftover empty
  directory. Everything read from the outside world — **including the
  platform** — arrives through `detect::Env`, so Windows `PATHEXT`, `%APPDATA%`
  and verbatim `\\?\` paths are unit-tested from macOS; nothing in `detect.rs`
  branches on `cfg!`. Provenance canonicalizes the found binary and matches
  `/node_modules/<pkg>/` or `/cellar/<formula>/` on a lowercased, `/`-normalized
  path. A *generic* binary name (`codex` — LaTeX tooling ships one too) needs
  corroboration from another signal before it counts.
  Two deliberate asymmetries, each guarded by a test: `install` acts on any
  signal (so a fresh agent is wired before its first run) but `check` requires
  `Signal::ConfigDir`, or a host that merely has `claude` on `PATH` and was
  never wired would report broken forever and break the MDM exit-code contract.
  And nothing creates `config_home` except the artifact writers themselves —
  that is precisely what makes `--dry-run` provably write nothing.
  New `ARGUS_BIN_DIRS` pins the searched prefixes; it is both the test isolation
  seam (otherwise the suite asserts on whatever the developer has installed) and
  the supported way to point a locked-down deployment at known prefixes.
  Mutation-verified: generic-corroboration, the `check` ConfigDir filter, the
  dry-run guard, `PATHEXT` handling, `\`→`/` normalization and the user-prefix
  search were each neutralized in turn and the matching tests failed. Two
  mutations did *not* bite and both were real findings, not test gaps: the
  Windows extension check in `is_executable` was redundant with `exe_names`
  (simplified, comment corrected), and an explicit `create_dir_all(config_home)`
  in `install` was dead because every writer creates its own parent chain
  (deleted rather than shipped untested). Real machine: `install --dry-run`
  reports claude-code via config dir+binary+npm and opencode via
  config dir+binary+brew, and nothing else.

- [x] **T5** — Payload recorder. Dependency: T3.
  Files: new `src/record.rs`, new `tests/fixtures.rs`, new `tests/fixtures/**`,
  `src/hook.rs`, `src/lib.rs`, `src/main.rs`, `Makefile`, `README.md`,
  `docs/adding-a-tool.md`
  `ARGUS_RECORD_DIR` makes the shim dump every envelope verbatim before
  anything parses or redacts it; `make record-fixtures` (hidden
  `argus record-fixtures` subcommand) promotes a recording directory into
  `tests/fixtures/<harness>/<event>.json`. The split matters: a recording is
  raw and stays on the machine that made it (0600, under `target/`), a fixture
  is committed, so promotion redacts, normalises `received_at` and collapses
  repeats — re-running it on unchanged recordings leaves the tree clean.
  Event labels come from each tool's own name field with the `--event` hint
  winning, so fixture names are in the tool's vocabulary (`PreToolUse`,
  `tool.execute.before`, `agent-turn-complete`). That label is a path
  component built from payload content, so it is slugged and dot-only names
  are rejected.
  32 doc-derived seed fixtures across all four harnesses; `tests/fixtures.rs`
  asserts each one parses into a *recognised* event, so an adapter that falls
  through to `Raw` fails the suite instead of silently capturing nothing.
  Mutation-verified: colliding recording filenames, a cached record dir,
  inverted label precedence, an allowed `..` label, un-normalised timestamps,
  skipped redaction, and a renamed adapter arm each failed the matching test.
  One test was found to be weak in the process and fixed: `starts_with` is
  lexical, so `into/../x` passed a traversal check it should have failed.
  **Gates Wave 2 sign-off:** the seeds are doc-derived. Codex, Copilot and
  pi.dev are not installed here, so their mappings stay provisional until a
  human records a real session and re-runs `make record-fixtures`.

- [x] **T6** — Hot-path hardening. Dependency: T3.
  Split along the pre-marked line: T6a = per-event CPU + Windows console;
  T6b = SQLite/config/exporter; T6c = data directory, which came out of T6b
  as its own commit rather than sharing one — it is a data-location change,
  not a cost change, and the only one of the three that can move a user's
  existing files.

  - [x] **T6a** — Per-event cost. Files: `src/event.rs`, `src/redact.rs`,
    `src/hook.rs`, `src/record.rs`
    `Event::new` spawned `hostname(1)` for **every event** — a `fork`+`exec` on
    the daemon's hot path for an answer that cannot change while the process
    lives. Host and username now resolve once through a `OnceLock`. The
    guarantee is otherwise unfalsifiable (cached and uncached produce identical
    events), so a `#[cfg(test)]` probe counter makes it assertable; the test
    asserts the absolute count, not a delta, so it holds under any test order.
    `Redactor` gained a `RegexSet` prefilter and `scrub_str` now returns
    `Cow<str>`: one pass says which rules could match, so ordinary prose — very
    nearly all of the stream — is not copied at all, and a string that does
    match is rewritten once per *matching* rule instead of once per rule
    (previously 10 full-string rewrites per string, unconditionally). Rule and
    set indices are built from one filtered list so an uncompilable custom
    pattern cannot misalign them, and the set falls open (`""` per rule) if it
    ever fails to build — never closed.
    `CREATE_NO_WINDOW` on both Windows spawns (daemon autospawn, `hostname`):
    under a GUI-launched agent there is no console to inherit, so each spawn
    flashed a window at the user.
    Mutation-verified: dropping the `OnceLock`, building the set from `BUILTIN`
    alone (misaligning custom-rule indices), and copying unconditionally each
    failed the matching test. Untested seam: the two `#[cfg(windows)]` blocks
    are compiled by the CI Windows job but asserted by nothing — the local
    cross-check is blocked, `libsqlite3-sys` needs a mingw C toolchain.
  - [x] **T6b** — SQLite/config/exporter. Files: `src/buffer.rs`,
    `src/daemon.rs`, `src/export.rs`, `src/harness/mod.rs`, `src/redact.rs`,
    new `tests/throughput.rs`
    Four costs, each paid per event or per flush cycle for no benefit.
    `Buffer::push_batch` writes a whole fan-out under one transaction and trims
    once at the end; one host payload routinely becomes several events, and each
    used to charge its own implicit transaction *and* its own `ORDER BY seq DESC
    ... OFFSET` scan to enforce a cap only the last of them could cross. `push`
    is now a batch of one, so the cap semantics are unchanged.
    `peek_batch` reads the rows out and releases the connection before
    deserializing them — the JSON work needs no database, and holding the lock
    across it stalled every arriving event behind the export loop.
    The daemon reached into the `RwLock` three times per envelope, each time
    cloning the **entire** `Config` to read one field; `Pipeline` caches the
    redactor and the capture settings and rebuilds only when a fingerprint says
    the config behind them changed. `capture` had to be added to that
    fingerprint — it was absent while it was re-read per event, and caching it
    without widening the fingerprint would have made live config changes
    silently never take effect.
    `Exporter` shares one process-wide `reqwest::Client`. It was rebuilt every
    flush, discarding all keep-alive connections and paying a fresh TCP+TLS
    handshake to the collector every ten seconds, forever.
    `Event.ts` is now the envelope's `received_at`, stamped at the single
    `harness::parse` choke point so no adapter can forget and the unknown-source
    `Raw` fallback is covered too (telemetry-gaps #8). Without it an outage
    erased the timeline spooling exists to preserve: an hour of work landing on
    the collector as one spike at drain time.
    Three more `#[cfg(test)]` probe counters (`TRIMS`, `CLIENT_BUILDS`,
    `REDACTOR_BUILDS`) make the invisible guarantees assertable; `peek_batch`'s
    lock scope is guarded by a `try_lock` assertion instead, having no natural
    test. Mutation-verified, six of six: trimming per event, holding the lock
    across deserialization, dropping `capture` from the fingerprint, rebuilding
    the pipeline unconditionally, building a client per `Exporter`, and dropping
    the `ts` stamp each failed the matching test.
    `tests/throughput.rs` asserts floors, not rates — CI runners are too noisy
    to gate on a number, so each bound is set where only a structural regression
    can cross it, and the real figures are printed for a human.
  - [x] **T6c** — Data directory. Files: `src/paths.rs`, `src/daemon.rs`
    The buffer lived in `dirs::data_dir()`, which on Windows is *Roaming*
    AppData: synchronised to a file server at logon and logoff on any
    domain-joined machine. It copies `events.db`, `-wal` and `-shm`
    independently and at moments of its own choosing, so what reaches the
    server is a torn snapshot — and what comes back at the next logon can land
    on top of a newer local buffer. Roaming a security audit trail to every
    machine the user logs into is a poor idea on its own merits besides. Now
    `data_local_dir()`, which is the same path off Windows (verified on this
    machine: both resolve to `~/Library/Application Support`), so nothing moves
    there and `legacy_data_dir()` is `None`.
    An existing roaming buffer is migrated once, at daemon startup, under the
    single-instance socket so two daemons cannot race. Copy-then-verify and
    never destructive: each file is read back byte-identical (streamed, since
    the buffer is capped in rows and not bytes) and the source directory is
    removed only when every last file passes. A still-running old daemon holds
    `-wal`/`-shm` under a mandatory lock on Windows, so those copies can fail
    while the database itself succeeds — tolerated, and it costs only the
    cleanup. The skip guard tests for `events.db` at the destination rather
    than for a non-empty directory, because a hook firing before the first
    daemon start spools a file there, and that must not strand the user's
    history in the old location forever.
    Mutation-verified, four of four: trusting the copy without reading it back,
    dropping the existing-buffer guard, guarding on a non-empty directory
    instead of on the buffer, and removing the source unconditionally each
    failed the matching test. The copier is injected, so the locked-file and
    truncated-write paths are exercised on a platform that has neither.

- [ ] **T7** — Durability and loss visibility. Dependency: T6.
  Files: `src/buffer.rs`, `src/spool.rs`, `src/config.rs`, `src/event.rs`, `src/hook.rs`
  Split four ways, one behavioural change each — the row bundles four of them
  across five files, past the sizing rule. T7a = loss visibility for buffer
  overflow; T7b = shim stdin truncation (a new `Envelope` field, and the 24
  literals across 12 files that come with it); T7c = the byte caps, re-read
  live; T7d = the incremental crash-safe spool drain.

  - [x] **T7a** — Overflow is visible. Files: `src/event.rs`, `src/buffer.rs`,
    `src/daemon.rs`, `src/export.rs`, `src/redact.rs`
    A buffer at its cap dropped its oldest rows silently, which for a security
    monitor is the worst-shaped failure available: a busy hour and a quiet one
    reach the collector looking identical, and the hours most likely to
    overflow are the ones most worth having. `EventKind::Loss` now states the
    gap — mechanism, count, and a human-readable detail — and exports at
    `WARN`, alongside the failed-integrity check as the other record that must
    not scroll past in an `INFO` firehose.
    The count is a counter on `Buffer`, not a row written at trim time: the
    trim happens exactly when there is no room, so writing the marker there
    spends the one thing that just ran out, and a burst trimming on every push
    would fill the cap with markers describing the events they displaced. It is
    coalesced into one record per flush cycle instead, which costs a marker if
    the process dies in between — the cheaper of the two failures.
    The test caught a real feedback loop before the commit: inserting the
    marker into an already-full buffer evicts one further event, so charging
    that eviction to the loss count left a residue of one, which the next flush
    reported with another marker, which evicted another event — a permanent
    self-sustaining alarm on a completely idle machine. The write path is now
    split, a counting `push_batch` over a non-counting `append`, and the marker
    goes through `append`: its own displacement folds into the gap it already
    describes. Concurrent writers' losses are untouched and roll into the next
    flush.
    Mutation-verified, four of four: routing the marker through `push_batch`,
    reading the counter instead of draining it, dropping the trim count in
    `push_batch`, and dropping the `WARN` severity arm each failed the matching
    test. `scrub_event` still matches `EventKind` exhaustively, so the compiler
    forced a redaction decision on the new variant rather than letting it
    default to unscrubbed.
  - [x] **T7b** — Shim stdin truncation is reported. Files: `src/hook.rs`,
    `src/event.rs`, `src/harness/mod.rs`, `src/spool.rs`, plus `truncated: false`
    at the 17 remaining `Envelope` literals
    `read_capped` capped stdin at 8 MiB and told nobody, so an oversized tool
    result arrived looking like a complete one. It now reads one byte *past*
    the cap — without that byte a payload ending exactly at the cap and one cut
    off are indistinguishable — and returns whether there was more.
    A second, worse bug fell out of the same read: `read_to_string` over a
    `Take` that ends mid-codepoint returns `InvalidData` **and leaves the
    buffer untouched**, so the entire 8 MiB was discarded to avoid half a
    character. For non-ASCII text a byte cap lands mid-character most of the
    time. The read is byte-oriented now and backs up to the last boundary.
    The flag rides on the `Envelope` rather than being reported by the shim:
    the shim is a short-lived process on the host tool's critical path, with no
    buffer and no exporter, and has no business making a second IPC round trip
    to say the first one was incomplete. The daemon turns it into an
    `EventKind::Loss` at the `harness::parse` choke point, *ahead* of the
    events it qualifies — a truncated payload usually still parses, since it is
    the tail that is missing, so the caveat cannot be inferred from a parse
    failure and a reader seeing a tool call with no result needs it before
    drawing the obvious wrong conclusion. Attributed to the host tool, not to
    argus: which agent emitted an 8 MiB payload is the actionable half.
    Mutation-verified, four of four — but the fourth exposed a hole first.
    Dropping the extra byte, dropping the boundary backup, and silencing the
    `parse` arm each failed a test; dropping the flag from the wire
    (`skip_serializing`) passed everything, because the shim and the daemon are
    different processes and nothing asserted the flag survived between them.
    `a_truncation_survives_the_spool` closes that, and fails under the mutation.
  - [x] **T7c** — `buffer.max_bytes`, re-read live. Files: `src/config.rs`,
    `src/buffer.rs`, `src/daemon.rs`, `src/main.rs`, `README.md`,
    `docs/querying-local-database.md`
    `max_events` was never a disk bound: 100k rows sized against ordinary
    prompts is a very different quantity of disk from 100k rows of pasted file
    contents, and the machine runs out of space during precisely the incident
    the buffer exists to record. `buffer.max_bytes` (256 MiB) caps the stored
    text; whichever cap binds first wins, and rows the byte cap destroys are
    counted as loss exactly like rows the row cap destroys.
    The trim is one statement — a newest-first running `SUM(LENGTH(body))`
    window, delete everything past the cap — with the newest row exempt. An
    event larger than the whole cap would otherwise delete itself and leave an
    empty buffer, which is the one outcome worse than storing it; same
    reasoning as the existing `max_events.max(1)` clamp, and `set_limits`
    clamps both caps for the same reason: a `max_bytes = 0` typo must not
    switch the audit trail off.
    The byte total is kept in memory so the cap costs an addition per write
    rather than a `SUM` scan, and is deliberately allowed to drift **upward**
    only — `ack` and the row trim delete bytes without decrementing it, and a
    transaction that fails to commit leaves its addition behind. An
    overestimate triggers a trim early and the trim recounts exactly, so the
    drift costs a scan and can never lose an event; drifting the other way
    would silently blow past the cap.
    Both caps now live in `AtomicU64` and are re-applied from the cached
    `Pipeline` on every envelope. A `Buffer` handed its limits at startup keeps
    enforcing them for the life of the daemon, so an operator raising a cap
    *because* the buffer is overflowing would have to restart the process that
    is losing their events. `c.buffer` had to join the pipeline fingerprint for
    the same reason `capture` did in T6b — cached without it, a reload would
    never take effect.
    Mutation-verified, six of six: seeding the byte count at zero on reopen,
    dropping the newest-row exemption, making `set_limits` a no-op, dropping
    `c.buffer` from the fingerprint, skipping the byte trim, and taking a zero
    cap literally each failed the matching test.
    Untested seam: the `buffer.set_limits(&pipeline.buffer)` call inside
    `run()`'s per-envelope closure. `set_limits` and the fingerprint are each
    tested, but the line joining them sits in `run()`, which has no unit test
    at all. T16 splits that closure out; it becomes testable there.
  - [x] **T7d** — Incremental spool drain, delete after the buffer commits.
    Files: `src/spool.rs`, `src/daemon.rs`
    The spool exists so that a daemon outage costs nothing, and it was the one
    place in the pipeline where a crash cost an event outright: `drain()`
    unlinked each file and *then* handed the envelope back, so a kill anywhere
    between the unlink and the SQLite commit destroyed the only copy. Split into
    `take` (read, leave in place) and `discard` (delete), with the daemon
    calling `discard` only after `push_batch` has committed. Delete-after-commit
    can duplicate an event if the process dies in the window; the pipeline is
    at-least-once already, and a duplicate is the failure that leaves evidence.
    The replay also moved off its own spawned task and onto the daemon's event
    loop, on a 5s tick, because that is where the buffer handle lives and where
    a commit result can decide whether the file dies. Which makes the pass
    synchronous with live traffic, so it is bounded: `DRAIN_BATCH = 256` files,
    oldest first. Unbounded, a daemon returning after a day would stall every
    live envelope behind tens of thousands of files; newest-first would keep
    re-reading the same tail while the oldest starve behind the bound. Names
    are UUIDs and carry no order, so the sort is by mtime.
    `drain()` survives as take-and-delete for callers that cannot lose what
    they are handed (tests, `status`). A corrupt file is still deleted inside
    `take` — no amount of retrying will commit it.
    Mutation-verified, three of three: discarding before the commit, ignoring
    the batch bound, and reversing the sort each failed the matching test.
    Untested seam: the `Err(_) => false` arm of `run()`'s per-envelope closure
    — the arm that makes a failed `push_batch` keep the file. `replay_spool`'s
    half of the contract is tested by injecting both a failing and a
    succeeding closure, but the real closure lives in `run()`, which still has
    no unit test. Same seam as T7c's `set_limits` line, and T16 splits it out.
  - [x] **T7e** — `spool.max_bytes`. Split out of T7c: the spool cap is a
    different mechanism in a different process (the shim writes it, and the
    daemon may be down — which is exactly when the spool grows), and reporting
    the drops needs a channel the shim can afford on the host tool's critical
    path.
    Files: `src/config.rs`, `src/spool.rs`, `src/event.rs`, `src/hook.rs`,
    `src/harness/mod.rs`, `README.md`, `docs/querying-local-database.md`
    `spool.max_bytes` (64 MiB — smaller than the buffer's, because the buffer
    is the archive and the spool is a few minutes of hand-off that happened to
    become a few days) is enforced in `spool::append` before the write, oldest
    first, with the incoming envelope always written afterwards. An envelope
    larger than the whole cap therefore clears the directory and lands anyway:
    refusing it would trade a bounded overrun for a guaranteed hole, the same
    call the buffer's newest-row exemption makes.
    That exemption is also why there is no `.max(1)` clamp on the cap, unlike
    the buffer's. `max_bytes = 0` already degrades to "hold exactly one file",
    never to "capture nothing", so the clamp changed no observable behavior —
    mutation-checked by putting it back and watching nothing fail. Shipped as a
    comment instead of as unfalsifiable defensiveness, same call as T4's dead
    `create_dir_all`.
    Reporting reuses T7b's channel rather than inventing one: `Envelope` gains
    `dropped: u64`, `append` re-serializes the envelope with the count once it
    knows it, and `harness::parse` turns a non-zero count into a `spool_full`
    `Loss` ahead of the event, exactly as `truncated` becomes `stdin_truncated`.
    The shim is a short-lived process on the host tool's critical path with no
    buffer and no exporter; the one thing it does have is an envelope already
    on its way to something that does. No feedback loop of the T7a kind: a
    marker is only ever attached to a real incoming write, so an idle machine
    trims nothing and reports nothing.
    Live config comes free here — the shim is a fresh process per hook, so
    `config::load()` on every call *is* the current answer, including one the
    operator changed because their disk was filling. The only way to get it
    wrong would be to cache it, and a test raising the cap between two batches
    holds that line.
    Cost: one `read_dir` plus a `stat` per file per spooled write. Affordable
    because the cap is what keeps the file count small — uncapped, the
    directory grows without bound and every later pass over it, including the
    daemon's own replay, degrades with it.
    Mutation-verified, seven of seven: never enforcing the cap, trimming newest
    first, never attaching the count, dropping the count on the wire
    (`skip_serializing`), suppressing the `Loss` in `parse`, freezing the cap
    at the compiled default, and refusing the oversized envelope each failed
    the matching test.
    Also fixed in passing: T7b's `stdin_truncated` detail string had a run of
    ~25 spaces in it from an unescaped multi-line `format!`.

- [ ] **T8** — Transport security. Dependency: T3.
  Files: `src/paths.rs`, `src/ipc.rs`, `src/adapters/codex.rs`, `src/install.rs`, `Cargo.toml`
  Split by the sizing rule — four independent behavioral changes across two
  transports, one of which (the Windows DACL) has an unresolved feasibility
  question the plan asks to settle before writing code.
  - [x] **T8a** — Bounded IPC frame. Files: `src/ipc.rs`
    Framing is newline-delimited and the socket answers to every process
    running as this user, so "one frame" meant "whatever the peer sends until
    it chooses to send a newline". The cost is not a rejected event: it is the
    daemon dying to the OOM reaper while holding the only copy of everything
    not yet exported. `MAX_FRAME_BYTES` is 16 MiB — twice what a legitimate
    shim can produce, since its stdin is capped at 8 MiB (T7b) and JSON
    escaping only doubles on text that is almost entirely control bytes.
    Reassembly moved off `lines()` onto a `fill_buf`/`consume` loop, because
    `next_line` is exactly the unbounded accumulator being removed. An
    oversized frame is discarded and the reader resynchronises on the next
    newline, matching how a malformed frame is already handled: a peer that
    sent one bad frame has not earned the right to end the conversation for
    the good frames queued behind it. The overflow flag deliberately outlives
    the chunk that set it, or the tail of a discarded frame gets parsed as the
    head of the next one, and nothing is kept from an overflowed frame — half
    an envelope is not a smaller envelope, and holding it spends exactly the
    memory the cap exists to save.
    The bound is invisible in the output — a daemon that buffers 2 GiB and one
    that refuses emit identical events right until the first is killed — so
    `PEAK_FRAME_BYTES` records the high-water mark, the same falsifiable-probe
    pattern as `IDENTITY_PROBES` and `CLIENT_BUILDS`.
    Mutation-verified, five of five: removing the bound, forgetting the
    overflow flag between chunks, keeping the overflowed prefix, tearing down
    the connection on a bad frame, and dropping the trailing unterminated
    frame each failed the matching test. The last of those was found *by* the
    mutation — the EOF-without-newline path was inherited from `lines()` and
    had never been tested, and it is the opencode plugin's path.
  - [x] **T8b** — Per-user endpoint name. Files: `src/paths.rs`,
    `plugins/opencode/argus.ts`, `README.md`
    Unix already had one: the socket is a file inside the per-user data
    directory, so the filesystem namespaces it. The Windows pipe namespace is
    machine-global and flat, and `\\.\pipe\argus` was a single name every
    account on the machine raced for — the loser's hook payloads, raw and
    pre-redaction because redaction is daemon-side, went to whoever won.
    Keyed on the data directory rather than the user name: it is what the Unix
    path is already keyed on, it makes `ARGUS_DATA_DIR` read the way it behaves
    (two data directories are two installs, not one shared daemon), it keeps
    the user name out of anything that enumerates `\\.\pipe\`, and it cannot
    produce a character the pipe namespace rejects.
    FNV-1a spelled out rather than `DefaultHasher`, whose output is explicitly
    not stable across Rust releases — a toolchain bump would rename the
    endpoint and cut every running daemon off from its shims. `windows_pipe_name`
    is compiled on all platforms on purpose: a guarantee testable only on the
    platform CI runs least often is one nobody notices breaking.
    Case-folded and stripped of a trailing separator because the two
    implementations do not read the directory from the same place — Rust via
    `SHGetKnownFolderPath`, the plugin via `%LOCALAPPDATA%`. They agree on the
    directory, not necessarily its spelling, and a split there looks exactly
    like a daemon that is not running.
    **The plan's upgrade note (line 441) asked for a fallback probe of the
    legacy name for one release. Deliberately not shipped:** it would reopen
    the hole this task closes, and it is unnecessary. Daemon and shim are one
    binary, so the only window is an old daemon still resident while a new shim
    runs; the shim then fails to connect and spools, and the next daemon start
    replays it. T7d/T7e made that path lossless — the spool is exactly the
    mechanism for this.
    Mutation-verified, five of five: reverting to the global name, dropping the
    case fold, dropping the trailing-separator trim, and perturbing the FNV
    basis each failed the matching test; changing the hash constant in the
    *TypeScript* failed `the_opencode_plugin_still_hashes_the_same_way`. That
    last guard checks constants, not algorithms — but silent cross-language
    drift is the failure that actually happens here, and it is invisible: the
    plugin keeps working, one spawned process per event.
  - [x] **T8c** — Unix: bind only an endpoint we own. Files: `src/ipc.rs`,
    `src/daemon.rs`, `Cargo.toml`, `README.md`
    `bind` read *any* successful `Stream::connect` as "our daemon is already
    running" and exited quietly, so a squatter got the same answer as a healthy
    install: argus never starts, `status` reports a reachable daemon, and the
    hook payloads — raw, since redaction is daemon-side — go to whoever is
    listening. For a security monitor that is the worst outcome available,
    because the absence of events reads as the absence of activity. `bind` now
    checks ownership *before* liveness and reports a foreign owner as its own
    error; `daemon::run` logs the reason instead of printing "already running"
    over everything.
    Two checks, because they fail independently: the socket file's uid, and the
    directory's — anyone who can write the directory can replace the socket
    whatever the socket says. `symlink_metadata` rather than `metadata`, or a
    planted symlink reports its target's owner instead of the planter's.
    Skipped under `ARGUS_SOCKET`: an explicit path is the user's choice the way
    `ARGUS_DATA_DIR` is, and silently chmodding `/tmp` is not ours to do.
    `create_dir_all` on the way past fixes a latent bug found here — `bind` is
    the first thing `run` does, so before this a first `argus daemon` on a
    machine no hook had fired on failed on the missing data directory and
    logged "daemon already running".
    Socket mode 0600 via `interprocess`'s `ListenerOptionsExt::mode`, which
    `fchmod`s before `bind` and so has no umask race. Darwin returns
    `Unsupported` (`fchmod` on a socket is `EINVAL`) and leaves no file behind,
    so the retry without it is correct rather than a workaround: Darwin ignores
    socket modes on connect anyway, and the 0700 directory is what carries the
    guarantee there. `MODE_FALLBACKS` exists because that difference is
    otherwise invisible — on Darwin "mode applied" and "mode never asked for"
    produce byte-identical sockets, so a bind that stopped requesting it would
    ship green. The test asserts the property (nothing outside this uid can
    reach the endpoint) rather than a mode, since the two platforms reach it
    differently and either mode alone would be wrong on one of them.
    Direct `libc` dependency added for `getuid`, unix-only; already in the tree
    under `interprocess` and `rusqlite`.
    Mutation-verified, five of five: skipping the whole check, accepting a
    foreign uid, leaving the directory as found, never requesting the socket
    mode, and reporting a foreign owner as "daemon already running" each failed
    the matching test. The fourth only bites because of `MODE_FALLBACKS`; the
    fifth needed a second attempt — the first kept the format arguments, so the
    substrings the test looked for survived a message that no longer said
    anything, and the test was strengthened to assert the two cases *differ*.
    Known gap, deliberate: distinguishing a foreign-owned symlink from our own
    needs a second uid, so `symlink_metadata` vs `metadata` is unfalsifiable
    without root. Not faked with a mock filesystem — the check is one `stat`
    syscall, and a mock of it would only assert that the mock was called.
  - [x] **T8d** — Windows: owner-only DACL on the pipe. Files: `src/ipc.rs`,
    `Cargo.toml`, `Makefile`, `README.md`
    **The plan's feasibility worry does not hold** — `interprocess 2.4.2` ships
    `os::windows::local_socket::ListenerOptionsExt::security_descriptor` and
    `SecurityDescriptor::deserialize` (SDDL), so no raw `CreateNamedPipeW`.
    A pipe created with no descriptor gets the default one, which
    `CreateNamedPipe` documents as granting *read access to Everyone and to the
    anonymous account*. T8b gave each install its own pipe *name*, but a name in
    an enumerable namespace is not a permission: any other logged-in user could
    connect, occupy the single listening instance, and hold hook payloads out
    while `status` still reported a healthy daemon. The DACL is `D:P(A;;GA;;;
    <sid>)` — protected, so nothing is inherited, and one ACE naming the SID
    read from this process's token. No `BA` entry: an administrator can take
    ownership regardless, and writing the grant down would only make the ACL lie
    about who normally reads the events.
    SID from the token rather than the user name, which is ambiguous between a
    local and a domain account and is not what SDDL wants anyway. The
    `GetTokenInformation` buffer is a `Vec<u64>`, not a `Vec<u8>`: it is cast to
    a struct holding a pointer, and 1-byte alignment would make that unsound.
    `owner_only_sddl` is deliberately not `#[cfg(windows)]`, same reasoning as
    `paths::windows_pipe_name` in T8b — the string is where the guarantee lives,
    and a guarantee testable only on the platform CI runs least often is one
    nobody notices breaking.
    Two tests. `the_pipe_is_granted_to_one_account_and_no_group` runs
    everywhere and is mutation-verified two of two: dropping `P` and re-adding
    an Everyone ACE each failed it. `nothing_outside_this_account_can_reach_the_
    bound_pipe` binds and reads the DACL back with `GetNamedSecurityInfoW`,
    asserting ACE count and SID rather than the whole descriptor, because the
    object manager maps `GA` to the pipe's specific rights when it assigns the
    descriptor — so the mask read back is not the mask written.
    New `make check-windows`: generates a `zig cc` wrapper (filtering the
    `--target=` that cc-rs adds and zig rejects) and runs clippy for
    `x86_64-pc-windows-gnu`. Not wired into `verify`, which must stay runnable
    on a fresh clone without zig. Verified falsifiable — a deliberate type error
    in the `#[cfg(windows)]` test failed the cross-check, so `--all-targets`
    does reach that module.
    Known gap, deliberate: dropping `.security_descriptor(...)` from the bind is
    caught only by the Windows test, which no local run executes. Nothing short
    of a Windows host or a push to CI closes that, and faking it with a mock
    listener would assert only that the mock was called.
  - [x] **T8e** — Per-user Codex OTLP port, and `check` held to it. Files:
    `src/paths.rs`, `src/config.rs`, `src/harness/mod.rs`, `src/harness/codex.rs`,
    `src/install.rs`, `README.md`
    T8b and T8d namespaced the *pipe*; the Codex receiver was still on a fixed
    `127.0.0.1:4327`. Loopback is machine-wide, not per-user, so that port was
    the same cross-account collision T8b fixed, one layer down and quieter: the
    second account's daemon failed to bind and logged its listener disabled,
    while that account's Codex — configured with the identical fixed port — went
    on posting prompts into the *first* account's audit trail and out through
    the first account's exporter. Neither side saw anything wrong. The port is
    now derived from the data directory through the same discriminator as the
    pipe name, into 40000..49152: above what anything common registers, and
    below where the kernel starts drawing ephemeral source ports, which a stable
    choice inside that range would lose a race against now and then.
    Changing the port opened a second, worse hole. `ours_markers` deliberately
    lists `LEGACY_ENDPOINT` so `uninstall` still recognises what older versions
    wrote, and `check` passed on *any* marker match — so a host upgraded into
    the new port would keep a `config.toml` naming the old one, capture nothing,
    and be reported intact. New `TomlEditOp::must_point_at` makes `check` demand
    the exact current endpoint for that edit while uninstall keeps the broad
    markers, and the error names the endpoint and says to re-run `argus install`.
    Three mutations. Reverting `otlp_port` to the fixed constant failed both new
    `paths` tests and `config::defaults_when_no_files`. Neutralising the
    `must_point_at` arm in `verify` failed the stale-endpoint test.
    The third **did not bite**, and that was the useful one: dropping
    `must_point_at` from the Codex `otel` op left the suite green, because the
    stale-endpoint test builds its own `TomlEditOp` and so proved the mechanism
    while proving nothing about any harness switching it on — the gap and the
    bug were the same shape. Closed with
    `an_edit_naming_our_receiver_demands_that_exact_receiver`, which walks every
    harness's artifacts and requires that an edit writing this install's
    endpoint declare it, and asserts it found at least one such edit so the test
    cannot quietly degrade into guarding nothing. Re-run, the mutation fails it.
    Three tests already pinned `127.0.0.1:4327` as a literal and broke here;
    each was rewritten to assert the property (loopback host, port in band,
    agreement with the loaded config) rather than the constant — their failing
    was the evidence the change reached what installs actually write.
  - [x] **T8f** — Bearer token on the Codex OTLP receiver. Files:
    `src/adapters/codex.rs`, `src/harness/codex.rs`, `src/harness/mod.rs`,
    `src/paths.rs`, `README.md`
    The receiver is the one input that is not a local socket, because Codex
    exports over HTTP — and loopback is not an authentication boundary. Every
    process on the machine, under any account, could post to it, which meant
    anything on the box could write fabricated prompts and tool calls into the
    record of what the agents did: a security trail its own subject can author.
    T8e's per-user port did not touch this; a listening port is not a secret,
    `lsof` prints it.
    256 bits as two v4 UUIDs (`uuid` is already in the tree; an RNG crate would
    be new supply chain for the same bytes), in `<data-dir>/codex-otlp.token`,
    opened `0600` rather than chmod'ed after — the window between a
    default-mode create and the chmod is the whole of what the file protects.
    Read back rather than rotated, since `install` copies it into Codex's
    `[otel]` headers and a daemon minting a fresh one per start would refuse the
    client it wired. `401`, not `404`, for our path without it: telling a Codex
    whose token went stale "not found" sends whoever debugs it hunting a routing
    problem that does not exist.
    The token is resolved *before* the bind and a failure disables the listener:
    a receiver that cannot tell Codex from anything else still fills the trail
    and still looks healthy in `status`, which is worse than no receiver.
    Six mutations, five bit: accept-everything failed the unauthenticated and
    wrong-token tests; header-presence-only failed wrong-token; case-sensitive
    scheme and header matching failed the RFC 9110 test; dropping `0600` and
    rotating on every call each failed the token-file test.
    The sixth **did not bite** and found a real hole rather than a test gap:
    `install` writing no `Bearer` header at all left the suite green — a Codex
    401'd on every turn, and quiet from both ends, since the receiver logs once
    per process and Codex treats its own export failures as its own business.
    Closed with `install_hands_codex_the_token_the_receiver_will_ask_for`; the
    mutation now fails it.
    An existing test caught a real bug during the work: `dry_run_creates_nothing`
    failed because `artifacts()` minted the token on demand and `--dry-run`
    calls `artifacts()`. Split into `existing_token` (read-only, used by
    artifacts, so `check` and `uninstall` are also read-only) and `shared_token`
    (read-or-create, called once by a non-dry install and by the daemon).
    Known gap, deliberate → **T8g**: `check` verifies the endpoint but not the
    header, so a `config.toml` carrying a token the receiver no longer accepts
    still reports intact. `must_point_at` is a single value and its error names
    it, which a bearer token must not be; closing it properly needs the field to
    carry a label beside each needle, and that is its own change.
  - [x] **T8g** — `check` catches a Codex wired with a token this receiver will
    not accept, without printing the token. Files: `src/harness/mod.rs`,
    `src/harness/codex.rs`, `README.md`
    `must_point_at: Option<String>` became `must_carry: Vec<Required>`, where
    `Required { what, needle, present }` separates the thing demanded from the
    words the error uses. That separation is the point, not tidiness: `check` is
    built for MDM compliance scripts and monitoring agents, so its output is
    written somewhere it will be collected, indexed and read by more people than
    the account that owns the secret. An error that quoted the needle to explain
    the mismatch would publish the token to exactly that audience.
    `present: false` inverts the test, which is what the no-token-on-disk case
    needs: the current token is unknowable, but *any* `Bearer ` header is still
    wrong — the next daemon start mints a replacement and refuses whatever that
    config presents. That is the restored-profile shape: the Codex config came
    back, the `0700` data directory did not.
    Four mutations, all bit: a harness declaring no token requirement failed
    `install_hands_codex_the_token_the_receiver_will_ask_for`; a `verify` whose
    predicate never matches failed both that and the stale-endpoint test;
    ignoring `present` failed the new test's inverted case; and printing
    `r.needle` in place of `r.what` failed it too — the "never prints the token"
    assertion has teeth rather than being documentation.

- [ ] **T9** — Export correctness. Dependency: T3.
  Files: `src/export.rs`, `src/buffer.rs`, `Cargo.toml`
  Three behavioral changes, so three commits under the sizing rule.
  - [x] **T9a** — Permanent vs transient export failures. Files:
    `src/export.rs`, `src/daemon.rs`, `README.md`
    Every non-2xx retried forever, which is right for an outage and wrong for a
    refusal. A `4xx` means the collector read the request and said no — one
    oversized record, a schema a validator dislikes, a revoked key — so the
    batch sat at the head of the queue being re-sent every cycle while newer
    events piled up behind it and were evicted to make room. The refused batch
    was lost either way; what the retry loop added was losing everything after
    it, silently.
    `Rejection::{Transient, Permanent}` splits the two at the point where the
    status code is still in hand. `408` and `429` stay transient: they refuse
    the moment, not the payload, and 429 is precisely what backoff exists for —
    classifying it permanent would discard the batches sent when a fleet is
    busiest.
    A refusal acks and leaves a record in the batch's place. `EventKind::Loss`
    rather than the `Error` the plan named: this is a gap in the stream, which
    is what T7 built `Loss` for — it carries a count and exports at `WARN`,
    where `Error` carries neither and would ride the INFO firehose alongside
    the events it says are missing.
    That record is itself exported, hence two bounds on it. The collector's
    error text is cut to one line and 200 chars, or an HTML error page becomes a
    batch that grows every time it is refused. And a batch consisting only of
    these records is acked *without* leaving another, or a collector refusing
    everything would mint one new event per flush cycle forever and the queue
    would never reach empty — the wedge this task removes, rebuilt out of its
    own remedy.
    `export_once` was extracted so the settlement rules are one function rather
    than two divergent copies (the loop and the shutdown flush), and so they are
    testable against a real buffer and a real collector.
    Eight mutations, seven bit immediately: nothing permanent, `408`/`429`
    permanent, no ack on refusal, ack on a transient failure, no record left
    behind, and the amplification guard removed each failed a test.
    The eighth — dropping the line split in the error text — **did not bite**,
    a test gap rather than a hole: the one body it was checked against was
    9 000 characters on its first line, so the length bound alone satisfied
    every assertion. A short first line followed by a stack trace discriminates;
    with that added, both the split and the length bound fail independently.
  - [x] **T9b** — Byte-budgeted export batches. Files: `src/buffer.rs`,
    `src/daemon.rs`, `src/config.rs`, `README.md`
    A batch was bounded by rows alone, and a row count says nothing about a
    request size: 256 tool results carrying file contents are orders of
    magnitude larger than 256 prompts, and a collector rejects on bytes. With
    T9a in place that rejection is now survivable rather than a wedge, but the
    batch is still lost — `export.max_batch_bytes` (3 MiB, under the OTel
    Collector's 4 MiB HTTP default) is what keeps it from being built.
    Computed in SQL as a running `SUM` over `seq`, so an oversized backlog
    costs one query rather than a deserialize-then-discard pass over rows the
    batch cannot carry. The sum is monotonic over `seq`, so the rows that pass
    are always a prefix — no gap can open mid-batch that `ack`, which deletes
    by a single high-water seq, would then delete rows out of.
    The first row is exempt from the budget. A batch that would otherwise be
    empty is a queue that never moves: one oversized event would be re-peeked
    forever while everything behind it aged out. Sent alone, a collector that
    cannot take it refuses it, and T9a settles a refusal.
    Found while writing it: SQLite's `LENGTH` on a TEXT value counts
    *characters*, and every size here is quoted in bytes — to the operator in
    `buffer.max_bytes` and to a collector that rejects on request size. A buffer
    of CJK or emoji-bearing prompts was holding up to three times what it was
    told to, and `total_bytes` reseeds the in-memory running total whose own
    doc says it may drift only upward. `CAST(body AS BLOB)` in all three places
    makes `LENGTH` count octets.
    Seven mutations, four bit immediately: no budget in the query, no exemption
    for the first row, and character-counting in either the batch query or the
    trim each failed a test.
    Three did not. Character-counting in `total_bytes` was an untested real
    guarantee — exactly the downward drift its own comment forbids — now covered
    by `the_running_byte_total_is_measured_in_bytes`. The other two were the
    mechanism-vs-wiring shape again: nothing proved the export loop passed the
    *configured* budget, or the configured row cap, to the batch it built. The
    row cap gap predates this change and was inherited by the refactor. Both are
    now covered by an `export_once` against a real buffer and collector, which
    asserts on what was acked rather than on what was configured.
  - [x] **T9c** — Optional request gzip. Files: `Cargo.toml`, `src/config.rs`,
    `src/export.rs`, `README.md`
    `reqwest`'s `gzip` feature was already on and decompresses *responses*
    only; nothing in it touches what we send. `flate2` is the new dep, wrapping
    the serialized batch in a gzip container under `Content-Encoding: gzip`.
    Off by default, and that is the whole design decision: an OTLP/HTTP receiver
    *should* accept a gzipped body but is not required to, and one that cannot
    answers `4xx` — which since T9a is a refusal that drops the batch instead of
    retrying it. Defaulting this on would trade audit data for bandwidth against
    a collector nobody asked, so it is the operator's call.
    The body is now serialized once by hand rather than via `.json()`, so both
    legs send identical bytes and only the framing differs — and both legs must
    now set `Content-Type` themselves, which `.json()` used to do.
    Four mutations, all bit: ignoring the config flag, announcing `gzip` over an
    uncompressed body, compressing without announcing it, and dropping the
    `Content-Type` that `.json()` used to supply. The last one initially bit only
    on the compressed leg — the uncompressed leg's media type was unguarded, so
    the test now asserts it on both.

- [ ] **T10** — Claude Code field-mismatch fixes. Dependency: T4, T5.
  Files: `src/adapters/claude_code.rs`, `src/adapters/mod.rs`, `src/harness/claude_code.rs`
  Split under the sizing rule: T10a wrong field names on the non-tool arms,
  T10b `Meta` gains `tool_use_id`/`effort`, T10c `ToolUse` gains
  `duration_ms`/`interrupted`, T10d `StopFailure`'s last assistant message,
  T10e the three unwired hooks, T10f `extract_files_for_tool`'s sortless
  `dedup`.
  - [x] **T10a** — Wrong field names on the non-tool arms. Files:
    `src/adapters/claude_code.rs`, five new `tests/fixtures/claude-code/*.json`
    The plan's finding table was derived from the published hook docs. Those
    docs disagree with the shipping product, so the names came instead from the
    payload constructors and Zod schemas inside the installed Claude Code binary
    (2.1.224) — `grep -a -o` over the bundled JS.
    Against that ground truth three of the plan's six claimed mismatches are not
    bugs in this version: `PreCompact`/`PostCompact` really do send `trigger`
    (not `triggered_by`), `CwdChanged` really does send `old_cwd`/`new_cwd` (not
    `directory`), and `SubagentStart`'s `agent_id`/`agent_type` are already in
    `Meta`. `models[]` is compiled out of 2.1.224 entirely.
    Four that are real, all fixed here:
    - `StopFailure` was read backwards. `error` is the *type* — an enum
      (`rate_limit`, `authentication_failed`, `invalid_request`, …) — and
      `error_details` is the prose. We were putting the enum variant where the
      message goes and leaving `context` permanently `"unknown"`.
    - `ConfigChange` read `path`; the payload says `file_path`. Not in the
      plan's table at all — found only because the binary was consulted.
    - `InstructionsLoaded` read `path`/`reason`; the payload says
      `file_path`/`memory_type`, and the tier is the finding: a `Managed`
      instructions file is administrator-controlled, a `Local` one is not, so
      the tier now rides in the action as `instructions_loaded:<tier>`.
    - `TaskCreated`/`TaskCompleted` are flat and carry no `status` (the status
      is the hook name), with `task_subject`/`task_description` and
      `teammate_name`/`team_name` for who it was handed to — not the nested
      `task.*` object the plan assumed.
    The new tests parse committed fixtures rather than inline literals: a
    fixture is what a real recording overwrites, so a payload that renames a
    field fails here instead of silently emptying a column in production.
    Five mutations, all bit: each of the four corrected names reverted one at a
    time, plus re-nesting the task fields. `ConfigChange`'s path was caught only
    by the new fixture test — the pre-existing test asserts its `action` and
    never looked at `path`, which is how the bug survived this long.
    Deferred on purpose: capping `task_description` waits for T17, the
    truncation rework.
  - [x] **T10b** — `Meta` gains `tool_use_id` and `effort`. Files:
    `src/event.rs`, `src/adapters/claude_code.rs`, `src/export.rs`,
    `tests/fixtures/claude-code/{Pre,Post}ToolUse.json`,
    `docs/querying-local-database.md`
    Both were in every Claude payload and neither was read. `tool_use_id` is
    the only thing that pairs a `pre` with its `post` — two `Bash` calls in one
    turn are otherwise indistinguishable, so a `pre` whose call hung or was
    killed could not be told from one that completed. `effort` arrives as
    `{"level": …}`, so the level is lifted out to keep `Meta` a flat string map;
    it matters because it is a knob the *prompt* can move, and a session that
    quietly drops to the cheapest setting before doing something sensitive is
    worth being able to see.
    The pairing test asserts the two legs share an id rather than that an id is
    present — an id on only one leg pairs nothing.
    Five mutations, all bit. Two of them were the mechanism-vs-wiring shape
    again and target `export.rs`, not the adapter: a `Meta` field nobody exports
    is a field nobody can query, so dropping either attribute from the OTLP
    attribute list must fail, and does.
  - [x] **T10c** — `ToolUse` gains `duration_ms` and `interrupted`. Files:
    `src/event.rs`, `src/adapters/{claude_code,codex,copilot,opencode}.rs`,
    `src/export.rs`, `src/redact.rs`, two fixtures,
    `docs/querying-local-database.md`
    `PostToolUse` sends `duration_ms`; `PostToolUseFailure` sends both that and
    `is_interrupt`. The interrupt flag is the one that changes a reading: an
    interrupted `Bash` may have run half its command, which looks like a failure
    in the record but is a human pressing stop. Stored as `interrupted` — this
    is our schema, not theirs — and only serialized/exported when true, because
    an attribute on every row is one nobody reads.
    The other three adapters pass `None`/`false` explicitly; their hook surfaces
    carry neither, and T11–T13 revisit that.
    `redact.rs`'s exhaustive match did its job and refused to compile until both
    new fields were named. Both are listed `_` with a note: a duration and a
    stopped-by-a-human flag cannot carry a secret.
    Five mutations, all bit — including one asserting the *absence* of the two
    attributes on a `pre` leg, which is the half a "does it export?" test misses.
  - [x] **T10d** — `StopFailure` surfaces `last_assistant_message`. Files:
    `src/adapters/claude_code.rs`
    The payload has carried it all along and only `Stop`/`SubagentStop` read it,
    so a turn that ended in an error lost the half-finished message that says
    what the turn was *trying* to do — which is the part worth having when the
    turn failed. All three now go through one `push_last_message`, so a third
    caller cannot quietly forget the `assistant_messages` capture flag.
    Three mutations. Two bit immediately. The third — deleting the
    `!text.is_empty()` guard — did **not**, and that guard predates this change:
    nothing anywhere asserted that an empty `last_assistant_message` produces no
    event. It does now, and the mutation bites. A blank message row reads as
    "the model said nothing", which is a claim; no row is the absence of one.

  - [x] **T10e** — Wire the three unwired hooks. Files:
    `src/adapters/claude_code.rs`, `src/harness/claude_code.rs`,
    `tests/fixtures.rs`, 3 new fixtures, `README.md`,
    `docs/querying-local-database.md`
    `DirectoryAdded` → `FileChange { path, action: "directory_added:<how>" }`:
    `/add-dir` widens the tree the agent may reach, which is a scope change and
    belongs with the other scope-shaped facts. `UserPromptExpansion` → one
    `Session` carrying `expansion_type`/`command_name`/`command_args`/
    `command_source` plus the expanded text behind `capture.prompts`.
    `PostToolBatch` → `Session` carrying **only** each call's `tool_name` and
    `tool_use_id`: the batch's finding is the grouping, and the inputs and
    outputs already arrived on their own `PostToolUse` events, so repeating
    them would spend the buffer's byte cap on a copy.
    The README's stated reason for leaving `UserPromptExpansion` unwired —
    "expansion input is already captured at `UserPromptSubmit`" — is false in
    2.1.224: the binary has both as separate generators, and `UserPromptSubmit`
    carries what the human typed, not what the command body expanded it into.
    That body lives in a file they are not looking at when they type it, which
    is the whole reason to capture it. Corrected in the README, and the
    fidelity table gained rows for both new signals.
    Eight mutations, all bite. Three of them (M6–M8) delete a `HookEvent` entry
    rather than touching the parser, and before this task **none of those would
    have bitten**: `integrity.rs`'s wiring test builds its `settings.json` from
    `EVENTS` itself, so it can never notice an event missing from that list.
    A parser arm for a hook `install` never subscribes to is dead code that
    looks, from every query afterwards, exactly like a hook that never fires —
    the same mechanism-vs-wiring gap as T8e/T9b/T10b. `tests/fixtures.rs` now
    asserts every claude-code fixture's `hook_event_name` appears in `EVENTS`.

  - [x] **T10f** — `extract_files_for_tool` deduped without sorting. Files:
    `src/adapters/mod.rs`
    `Vec::dedup` only drops *adjacent* duplicates, and the two sources here
    interleave: an `apply_patch` naming `a.rs` in `file_path` and again in a
    patch header that also touches `b.rs` yields `[a.rs, b.rs, a.rs]`, which a
    bare `dedup` leaves alone. Its two siblings, `extract_net_for_tool` and
    `extract_fqdns`, both sorted already — this one was the odd one out. A file
    counted twice inflates every "how often was this touched" query, which is
    the query the `files` array exists to answer. One mutation, bites.

- [ ] **T11** — Codex parity. Dependency: T4, T5.
  Files: `src/adapters/codex.rs`, `src/harness/codex.rs`, `src/integrity.rs`
  Split under the sizing rule — five independent behavioral changes: T11a
  `SessionEnd`, T11b kill-switch detection in `check`, T11c install refreshes
  its own stale hook entries, T11d hook-trust drift in `check`, T11e
  project-level `<repo>/.codex/hooks.json`. Codex is **not installed on this machine**, so
  every payload assertion stays doc-derived, as the plan requires.
  - [x] **T11a** — Subscribe to Codex `SessionEnd`, timeout 3. Files:
    `src/harness/codex.rs`, `src/harness/mod.rs`, `src/install.rs`,
    `tests/fixtures.rs`, new `tests/fixtures/codex/SessionEnd.json`
    The adapter already understood `SessionEnd` — it goes through the shared
    Claude-shaped parser — so this was purely a missing subscription: a parser
    arm nobody could reach. `HookEvent::with_timeout` is new; the default 10 s
    is slack rather than a requirement (the shim gives up on the daemon after
    250 ms and spools instead), and on a hook Codex runs while it is exiting
    that slack is time the user spends watching the CLI refuse to quit.
    Three mutations, all bite. Dropping the subscription fails two independent
    tests — the install test, which spells the wired list out rather than
    reading `EVENTS`, and the fixtures wiring test from T10e, now generalized
    to every `hook_event_name` harness. `install.rs` never asserted a timeout
    reached the file at all before this, so a per-event timeout would have
    been a comment.
  - [x] **T11b** — Detect Codex kill switches in `check`. Files:
    `src/harness/codex.rs`, `src/install.rs`
    `KillSwitch` and `Harness::kill_switches` were T2 scaffolding no harness
    populated, so `check` could read a byte-perfect `hooks.json` and report
    "wired" about a tool capturing nothing — worse than reporting nothing,
    because someone believes it. Three settings do that: `[features] hooks =
    false`, its deprecated-but-live alias `codex_hooks`, and
    `allow_managed_hooks_only = true`, which keeps only administrator-managed
    hooks and so lists ours and never runs it. Both `config.toml` and
    `requirements.toml` are read — the docs name the latter for the managed
    setting, and it is a file argus never writes.
    Six mutations, all bite — but only after two were fixed for biting
    nothing. The `allow_managed_hooks_only` case first passed for the wrong
    reason: a bare key appended to the end of a TOML file lands *inside* the
    preceding `[otel]` table, not at top level, so the edit the test thought
    it made was never made. Test edits now go through `toml_edit`. The
    unparseable-config case also passed with the arm deleted, because artifact
    verification already parses `config.toml` and reports the same words; it
    now targets `requirements.toml`, which nothing else opens.
    The plan's "untrusted/changed hook hashes" is not implementable as
    written — Codex's trust-store filename is undocumented, so there is no
    file to read. Moved to T11d as hash drift recorded at install time, which
    is the same signal from the side we control.
  - [x] **T11c** — `install` refreshes its own stale hook entries. Files:
    `src/harness/mod.rs`, `src/install.rs`, `README.md`
    Prerequisite for T11d, and a bug on its own. `apply` skipped any event
    that already carried an argus entry, so the entry the *first* install
    wrote was the entry forever: T11a changed `SessionEnd`'s timeout from 10
    to 3, and no already-wired host would ever have received it short of
    uninstalling. Now the entry is replaced in place — the same rule
    `OwnedFile` already used ("versioned with the binary, so a stale copy must
    be replaced"), and idempotent for the same reason.
    Ownership still decides: only an entry carrying our marker is replaced, a
    hand-written hook in the same array is not ours to touch.
    Three mutations, all bite. The first version of the test did not catch
    replacing whichever entry came first, because it appended the foreign hook
    *after* ours — with ours at index 0, "the entry that is ours" and "the
    first entry" are the same edit. The foreign hook now goes in ahead of ours.
  - [x] **T11d** — `check` reports hook entries that are not the ones argus
    writes. Files: `src/harness/mod.rs`, `src/integrity.rs`, `README.md`
    The plan's "untrusted/changed hook hashes" without reading Codex's trust
    store, whose filename is undocumented. Codex records trust against a
    hook's *current hash* and skips changed hooks until re-reviewed, so the
    observable half is whether the entry is still the one argus wrote — and
    T11c is what makes that comparison legitimate, since install now refreshes
    its own entries rather than leaving a stale one forever.
    Applies to every `JsonHooks` harness, not just Codex: a command retargeted
    at another adapter (`--source claude-code` → `--source codex`) resolves,
    fires, and files events under the wrong tool; `timeout: 0` is wired and
    never completes; a second hook body appended *inside* our marked entry
    runs under our marker. None is missing, none fails command resolution, so
    all three read as wired before this.
    Five mutations, all bite. The fifth is the finding: `wired_claude_home`
    built its settings.json by iterating `EVENTS`, the same constant `check`
    reads, and wrote an entry install never writes (no `type`, no `timeout`,
    no `matcher`). It now installs for real — restoring the hand-built version
    fails the healthy-install tests, which is the correct signal that the
    fixture was fiction. Same shape as T10e.
  - [x] **T11e** — Project-level `<repo>/.codex/hooks.json`. Files:
    `src/harness/mod.rs`, `src/harness/{codex,claude_code,copilot,opencode}.rs`,
    `src/install.rs`, `src/integrity.rs`, `src/main.rs`, `README.md`
    `install/uninstall/check --project <dir>` wire one repository so anyone
    running Codex inside it is captured without a per-machine hook install.
    `Scope::Project` is a strictly *smaller* install than `User`, not a variant
    of it: hooks only. Machine-level settings must not go into a repository —
    Codex's `[otel]` block carries this install's receiver token, and a token
    committed is a token handed to everyone who can clone it. Harnesses with
    nothing to contribute return no artifacts, so only Codex is wired today.
    Detection has no part in it: the operator named the directory, and a
    repository that has never been opened in the tool has no `.codex/` yet,
    which is exactly the case wiring it ahead of time is for. A repository
    nothing wired is *silent* rather than broken, the same rule detection
    follows for an absent tool — otherwise every checkout on the machine makes
    the exit code meaningless. Because Codex project hooks are additive
    ("higher-precedence layers don't replace lower-precedence hooks"), a repo
    file can never be a kill switch, and a broken repository is a finding *on
    top of* the user-level result rather than instead of it.
    Six mutations, all bite. The token assertion walks the whole repository
    tree rather than checking the one file expected to be absent — the
    guarantee is that the secret is nowhere under the repository — and it was
    confirmed to fire on its own, with the narrower `config.toml` assertion
    removed, rather than only behind it.
    Not enforcement, and documented as such: the hook command names a binary
    that must already be on `PATH` in every clone, Codex loads a repository's
    hooks only once that `.codex/` layer is trusted there per user, and anyone
    who can push can delete what this writes.

- [ ] **T12** — Copilot parity. Dependency: T4, T5.
  Files: `src/adapters/copilot.rs`, `src/harness/copilot.rs`
  Split per the plan's sizing rule into four independent behavioral changes:
  T12a `userPromptTransformed`, T12b `disableAllHooks` detection in `check`,
  T12c the unmapped payload fields, T12d per-event `timeoutSec`. Copilot CLI is
  **not installed on this machine**, so every payload assertion is doc-derived
  from <https://docs.github.com/en/copilot/reference/hooks-reference> and
  <https://docs.github.com/en/copilot/reference/hooks-configuration>.
  - [x] **T12a** — Capture the prompt as rewritten en route. Files:
    `src/event.rs`, `src/redact.rs`, `src/export.rs`,
    `src/adapters/copilot.rs`, `src/harness/copilot.rs`, `src/install.rs`,
    `tests/fixtures.rs`, new `tests/fixtures/copilot/userPromptTransformed.json`
    `userPromptTransformed` reports what was actually sent to the model after
    every hook, plugin and enterprise policy in the chain had a turn at editing
    it. An instruction spliced in there is invisible in every other record of
    the session: the user never typed it, and the transcript shows only the
    model obeying it.
    New `EventKind::PromptTransformed { original, transformed }` rather than
    reusing `Prompt`, because the two answer different questions and an audit
    trail needs both. Both halves come from the one payload, so the comparison
    needs no join and does not depend on `userPromptSubmitted` having fired;
    both are redacted, and `capture.prompts = false` suppresses both — half of
    a suppressed pair is still the prompt. Export carries a `prompt.rewritten`
    attribute so a SIEM alerts on the edit without diffing two prompt bodies
    per turn.
    Six mutations, all bite, and the redaction one is listed twice on purpose:
    an arm that scrubs `original` and forgets `transformed` passes with a
    single case. Dropping the subscription first failed only the install test —
    the fixtures wiring test read `hook_event_name`, and Copilot names its
    event in `envelope.event` instead (its native payloads carry no event
    field, which is why install passes `--event`). That test now consults both,
    which brings every Copilot and opencode fixture under it for the first
    time.
  - [x] **T12b** — Detect the settings that leave the wiring in place and stop
    it running. Files: `src/harness/copilot.rs`, `src/harness/mod.rs` (stale
    doc), `src/install.rs`, `README.md`.
    Copilot's `disableAllHooks: true` at the top of argus's own
    `~/.copilot/hooks/argus.json`, plus the file no longer parsing as JSON.
    Both pass every check argus already made — the markers are still in the
    text, the binary still resolves — so `check` reported "present" about a
    tool capturing nothing.
    Scope decided from the doc's own wording rather than guessed: *"Inside a
    single `.github/hooks/*.json` file — only the hooks declared in that file
    are skipped"*, so a `disableAllHooks` in someone else's hooks file is not
    our finding and is deliberately not reported. The session-wide form is
    *"At the top level of repository `settings.json` … Every hook from every
    source … is skipped for sessions in that repository"*, which a
    machine-level check cannot see; `check --project` reaches only Codex today,
    so this is documented as a limit instead of half-implemented.
    `hooks_path()` extracted so the artifact and the kill-switch read cannot
    drift onto different paths — a kill switch looked for in a file nobody
    writes reports healthy forever.
    Three mutations, all bite: neutralising the `disableAllHooks` arm, the
    unreadable-JSON arm (nothing else catches it — `OwnedFile` verification is
    substring-based), and relaxing `== Some(true)` to `.is_some()`, which the
    explicit `disableAllHooks: false` case exists to catch, since the
    documented example writes that key.
  - [x] **T12c** — Map the payload fields that were being read past. Files:
    `src/event.rs`, `src/redact.rs`, `src/export.rs`,
    `src/adapters/copilot.rs`, `src/adapters/claude_code.rs`, fixtures,
    `README.md`.
    Four new `EventKind` fields: `Notification.title`, `Compact.instructions`,
    `Error.name`, `Error.recoverable`. Adding them broke every construction
    site (E0063 ×3) and every destructuring pattern (E0027 ×3), which is the
    forcing function working as designed — and both exhaustive matches
    (`redact::scrub_event`, `export::record`) had to be extended by hand
    before it compiled, so none of the four could ship unscrubbed or
    unexported.
    `Compact.instructions` is the one that matters: compaction rewrites the
    session's own history, and afterwards the request to leave something out
    is the only surviving evidence it was there. `Compact` moved out of
    redact's no-op group for it, and `compact.directed` is exported as a
    boolean so a SIEM can alert without reading prose.
    Not speculative for Claude Code either — `title` and `custom_instructions`
    are in the payload constructors inside the shipped binary (2.1.224), so
    both adapters map them.
    Copilot's `subagentStop.response` is emitted as a second
    `EventKind::AssistantMessage` rather than stuffed into `Session.detail`,
    which is what makes capping, redaction and `capture.assistant_messages`
    apply to it; an empty response emits no second event. `meta.agent_type`
    now prefers `agentType` (the kind) over `agentName` (the instance) —
    grouping by a per-instance name is no grouping at all — and `meta.agent_id`
    is populated. Empty `customInstructions` is filtered to `None` in both
    adapters: `Some("")` reads downstream as a directed compaction.
    Deliberately dropped: `error.stack` (unbounded, and describes the host
    tool's file layout, not the session) and `toolResult.resultType` (the doc
    says it is always `"success"`; failures arrive on `postToolUseFailure`).
    Nineteen mutations, all bite — each of the four field mappings in both
    adapters, both empty-string filters, the `agentType`/`agentName`
    preference, `agent_id`, the subagent-answer emission with its capture gate
    and its empty-response guard, all three new redaction arms, and all three
    new export attributes.
  - [x] **T12d** — Per-event `timeoutSec`. Files: `src/harness/copilot.rs`,
    `src/install.rs`, `tests/fixtures.rs`, `README.md`.
    Copilot's `EVENTS` was a `&[&str]` and the writer baked a flat
    `"timeoutSec": 10`, so there was nowhere to say that one event should be
    treated differently. Now `&[HookEvent]`, the same type Claude Code and
    Codex use, which also removes the special case in
    `every_hook_we_parse_is_a_hook_we_subscribe_to`. `HookEvent::matcher` is
    unread for Copilot — its entries are `{type, bash, powershell,
    timeoutSec}` with no matcher concept — and that is noted where the list is
    declared.
    `sessionEnd` drops to 3, the same treatment and the same reasoning as the
    Codex shutdown hook in T11a: there the timeout is time the user watches
    the CLI refuse to exit, and the shim has already spooled the event.
    The documented default matters here — Copilot reads an *omitted*
    `timeoutSec` as 30 — so the test now asserts a value per event rather than
    one number for all fourteen, and says why an absent key would be wrong.
    Two mutations, both bite: `sessionEnd` back to `HookEvent::new`, and
    `ev.timeout` back to a literal `10`.

- [ ] **T13** — opencode + shared TS transport. Dependency: T4, T5.
  Files: `plugins/opencode/argus.ts` + new shared TS transport, `src/adapters/opencode.rs`, `src/harness/opencode.rs`
  - [x] **T13a** — Stop sending the same event twice. Files:
    `plugins/opencode/argus.ts`, new `tests/opencode_plugin.rs`, new
    `tests/plugin/opencode_transport.mjs`, `README.md`.
    `sock.write()` returns `false` when the stream is over its high-water
    mark. The frame is queued and goes out on drain — that is backpressure,
    not refusal — but the shim returned that boolean as "the socket did not
    take it" and spawned the fallback binary for the same event. Under a
    stalled reader the driver measures **400 envelopes for 200 events** on the
    old code, which is what double-counted tool calls look like in a dashboard.
    Fixed by tracking unflushed bytes (the per-frame write callback is the
    `drain` event at frame granularity) and checking the cap *before* writing,
    so the fallback only ever gets an event the socket has not also queued.
    Capped at 1 MiB: a stream accepts writes while connecting and while the
    kernel buffer is full, so an unread daemon would otherwise grow the
    editor's memory without bound.
    First test in this repo that runs the TypeScript. Node 24 loads the
    plugin's `.ts` directly (type stripping), so no build step. The driver
    stalls the reader on purpose and asserts three things: no duplicate
    session IDs, socket + spawned == events sent, and that the overflow path
    actually ran — without the last one a fast reader would make it pass
    vacuously.
    Two traps found while writing it: the plugin's hooks are `async` but
    synchronous inside, so `await`ing them in a loop drains only microtasks
    and libuv never connects the socket (`setImmediate` between events fixes
    it); and a missing `node` **fails** rather than skips, since a silent skip
    reports the same green as a real run — `ARGUS_SKIP_PLUGIN_TESTS=1` is the
    deliberate opt-out. Unix only: the driver's stand-in binary is a `sh`
    script.
    Verified by reverting the fix in place: the driver goes from
    `200 -> 16 socket + 184 spawned, no duplicates` to `400`.
  - [x] **T13b** — Extract the transport into one shared module. Files: new
    `plugins/shared/transport.ts`, `plugins/opencode/argus.ts`,
    `src/harness/opencode.rs`, `src/paths.rs`, `tests/opencode_plugin.rs`,
    `tests/plugin/opencode_transport.mjs`, `README.md`.
    T14 adds a second TypeScript plugin host, which would have meant a second
    copy of the socket path, the FNV discriminator and the envelope frame —
    the three things that must agree with the Rust side and the three things a
    copy drifts on silently. A drifted copy still loads and still forwards; it
    just stops finding the daemon and spawns a process per event forever.
    Split as transport (shared) + adapter (host's own event vocabulary), joined
    by `shim_source()` in Rust rather than by a relative import between two
    installed files: a plugin host loads exactly one file, and an import that
    resolves on this machine need not resolve in someone else's config
    directory. `strings` on the shipped opencode binary yielded no discovery
    glob, so guessing whether a second file would even be loaded was not an
    option worth taking.
    Consequence, and the reason two tests changed: `plugins/opencode/argus.ts`
    on its own no longer runs — `send` is not in scope. The Node driver and the
    `paths.rs` hash test now both read `shim_source()`, i.e. the exact bytes
    install writes, which is what they should have been reading all along.
    A third marker, `send("opencode"`, ties the installed file to this harness
    so a transport-only file fails `check` instead of installing quietly.
    Four mutations, all bite: shim = transport only (install-check, driver);
    shim = adapter only (install-check, paths-hash, driver); driver reads the
    adapter fragment (driver); paths test reads the adapter fragment
    (paths-hash). `paths-hash` passing under transport-only is not a miss — the
    FNV constants live in the transport. A fifth, compound, confirms the layers
    are independent: transport-only *with* the new marker removed passes
    `check` and is caught only by the driver.
  - [x] **T13c** — Accept both `plugin/` and `plugins/`. Files:
    `src/harness/opencode.rs`, `src/install.rs`, `README.md`.
    Ground truth, not guesswork: the shipped opencode 1.18.10 binary carries
    its own docs, and they say auto-discovery covers "any `*.ts` or `*.js`
    file in `.opencode/plugin/` or `.opencode/plugins/`". argus wrote the
    singular unconditionally, which put a second one-file directory beside a
    user's populated `plugins/` — loaded fine, just not where its owner would
    look for it.
    `plugin_dir()` resolves in three passes: a directory already holding
    `argus.ts` wins outright, then any existing directory, then the singular.
    The first pass is the one that matters on a machine with both spellings —
    that copy is the one opencode is loading, so updating the other would
    leave the stale one running. Because `install`, `check` and `uninstall`
    all go through `artifacts()`, they resolve identically; the probe reads
    state install itself creates and uninstall removes last.
    Four mutations, each caught by the test that names the case: always
    singular (both new tests); drop the existing-`argus.ts` pass (reinstall);
    drop the existing-directory pass (join-existing); default flipped to
    plural (the three tests that assume the fresh-install path).
  - [x] **T13d** — cwd and callID (telemetry-gaps #10). Files:
    `plugins/opencode/argus.ts`, `src/adapters/opencode.rs`, new
    `tests/plugin/opencode_payload.mjs`, `tests/opencode_plugin.rs`,
    `docs/telemetry-gaps.md`, `README.md`.
    Both fields are ones only the plugin can supply. opencode hands a plugin
    its `directory` once, at load, and never repeats it on an event — so every
    opencode event was `cwd: null` while every other harness reported one,
    which silently excluded opencode from anything scoped to a repository.
    `worktree` is the fallback, not the preference: inside a git worktree the
    two differ and `directory` is where the session actually runs.
    `callID` the plugin was already sending and the adapter was already
    dropping. Mapped to `meta.tool_use_id` — the field Claude Code's
    `tool_use_id` uses — rather than to `turn_id` as the gap doc suggested: a
    turn holds many calls, so pairing on `turn_id` would pair the wrong ones.
    New driver `opencode_payload.mjs`, because the plugin half is untestable
    from Rust: a field the plugin stops sending breaks nothing, the adapter
    just reads `None` forever. It asserts the wire format of all four hooks
    and that the bus filter still filters. `ARGUS_BIN` deliberately points at
    a non-existent file so a missed socket fails loudly instead of being
    counted as delivered by a stand-in.
    Six mutations, all bite, split across the halves they belong to: adapter
    cwd → `None` and callID → `None` (adapter tests); plugin drops cwd, drops
    callID, prefers `worktree` over `directory`, or forwards every bus event
    (driver). Also: the two drivers write per-name shim files — one shared
    path would race and the loser would import a half-written file.

  - [x] **T13e** — model, tokens, cost (telemetry-gaps #9). Files:
    `src/event.rs`, `src/redact.rs`, `src/export.rs`,
    `src/adapters/opencode.rs`, `plugins/opencode/argus.ts`,
    `tests/plugin/opencode_payload.mjs`, new
    `tests/fixtures/opencode/message.updated.json`,
    `docs/telemetry-gaps.md`, `README.md`.
    The gap doc offered two shapes — a new event field or `Session.detail` —
    and this took the first. A receipt buried in a JSON blob can only be
    aggregated by parsing every row, and cost-per-session has to be a cheap
    query for anyone to ever look at the number. `EventKind::Usage` holds the
    five counts, the cost and the stop reason as separate fields. It is also
    self-enforcing: `redact.rs` and `export.rs` match `EventKind` with no
    catch-all, so adding the variant was a compile error in both until each
    said what it does with it. Export names the attributes after OTel's GenAI
    conventions so they aggregate next to anything else reporting LLM usage.
    `cost` is recorded, never derived — a price table living in argus would be
    wrong the week after a provider changed one.
    `meta.model` is `providerID/modelID`. A bare model name is not unique;
    which provider served the turn is the whole question a policy about
    third-party models asks. `messageID` → `meta.turn_id`.
    The streaming filter lives in the plugin, not the adapter.
    `message.updated` fires on every delta and only the last carries totals,
    so the plugin forwards it only when `role === "assistant"` **and**
    `time.completed` is set. The partial receipts never leave the editor
    process and the daemon never has to pick which frame was final.
    Thirteen mutations, all bite. Adapter: arm never matches, model
    unqualified, cache-read zeroed, reasoning read from the wrong pointer,
    `finish` dropped, `turn_id` dropped. Redact: the `finish` scrub removed —
    which needed a `Usage` case added to `new_kinds_are_scrubbed` first, since
    without it the arm was untested and the mutation would have survived.
    Export: an attribute renamed, `cost` dropped. Plugin: the
    `time.completed` gate removed, the `role` gate removed, `tokens` dropped,
    `providerID` dropped — all four caught by `opencode_payload.mjs`, which
    now fires three `message.updated` variants and asserts exactly one
    envelope comes out.

  - [x] **T13f** — `BUS_FORWARD` audited against opencode's real event
    vocabulary. Files: `plugins/opencode/argus.ts`,
    `src/adapters/opencode.rs`, `tests/fixtures/opencode/` (deleted
    `permission.asked.json`, added `permission.updated.json` and
    `permission.replied.json`), `README.md`.
    Ground truth is the `Event` union in the installed SDK
    (`~/.config/opencode/node_modules/@opencode-ai/sdk/dist/gen/types.gen.d.ts`,
    32 members), not documentation. It has no `permission.asked` — which
    argus forwarded, had an adapter arm for, and shipped a fixture of. Three
    artefacts agreeing with each other and with nothing real. Worse than
    dead code: it held the only mapping to a `requested` permission action,
    so a query for permission requests on opencode matched nothing, while
    the events that *were* the requests arrived labelled `updated`.
    `permission.updated` is the ask — it carries the whole `Permission`
    (type, pattern, `callID`) — and now maps to `requested` and puts
    `callID` in `meta.tool_use_id`, joining the prompt to the call it gated.
    `permission.replied` carries only the answer, so it has no call id and
    the test asserts it stays `None`.
    New `every_forwarded_bus_event_has_an_arm` parses `BUS_FORWARD` out of
    `shim_source()` and pushes each name through the adapter. Nothing made
    the two halves agree before. The failure it catches is silent: a
    forwarded event with no arm is not lost, it becomes an unqueryable blob
    that still counts as an event in every report — which is what coverage
    looks like from the outside.
    Five mutations, all bite: the ask relabelled `updated`, `callID`
    dropped, an adapter arm made unreachable, `permission.asked` put back
    into `BUS_FORWARD` (the exact regression, now caught), and the plugin's
    set renamed so the parse finds nothing.
    Deliberately still not forwarded, having now looked at each: `lsp.*`
    (high frequency, no security signal), `message.part.*` (stream deltas —
    the hot path this list exists to stay off), `tui.*` (UI only),
    `installation.update-available` (the result of a poll, not a state
    change). The real events worth adding — `pty.*`, `message.removed`,
    `vcs.branch.updated` — are T13g, because each needs a mapping decision
    rather than a list entry.

  - [x] **T13g** — forward the events T13f's audit found missing. Files:
    `plugins/opencode/argus.ts`, `src/adapters/opencode.rs`,
    `tests/plugin/opencode_payload.mjs`, new
    `tests/fixtures/opencode/pty.created.json` and
    `tests/fixtures/opencode/vcs.branch.updated.json`, `README.md`.
    `pty.created`/`pty.exited` are the reason this task exists. A pty is a
    command with a pid that never passes through `tool.execute.*` — the one
    way to run something in opencode and leave nothing in the tool record.
    They map to a `pre`/`post` `ToolUse` pair joined by the pty's id, not to
    a `Session` note: as a session note a terminal would be a command
    execution invisible to every query about command executions, which is
    the hole forwarding it was meant to close. FQDNs are scanned from the
    program *and* its args joined — opencode splits them, so a host named in
    `args` is invisible to a scan of `command` alone. A non-zero `exitCode`
    becomes `error`; zero does not, and an absent code (`pty.created`) is
    neither.
    `message.removed` and `vcs.branch.updated` join the `Session` arm — the
    first is the only notice that part of the transcript stopped existing,
    the second says which branch the session's `cwd` was on.
    The pty exposed a live bug in the plugin's generic forward:
    `properties.info.id` was used as a session-id fallback unconditionally,
    and `info` is the Session only on `session.*`. On a pty it is the
    terminal, so every pty would have been filed under a session of its own
    that nothing else ever joined. The fallback is now scoped to `session.*`.
    Eleven mutations, all bite. Adapter: `info` not flattened, args not
    scanned, exit 0 treated as failure, the pty id dropped, phase pinned to
    `pre`, the arm made unreachable, and each of the two new `Session` names
    removed (caught by `every_forwarded_bus_event_has_an_arm`, which was the
    point of building it in T13f). Plugin: pty dropped from `BUS_FORWARD`,
    the `info.id` fallback left unqualified, and the fallback removed
    entirely — the last two proving the scope is pinned from both sides.

- [x] **T14a** — pi.dev adapter. Dependency: T4, T5.
  Files: new `src/adapters/pi.rs`, `src/adapters/mod.rs`
  Split from T14: `tests/fixtures.rs` dispatches through `argus::harness::parse`
  over `HARNESSES`, so pi fixtures cannot pass before `Pi` is registered, and
  registering the harness before the adapter exists has nothing to dispatch to.
  T14a is the adapter alone — nothing routes to it yet — and T14b registers it.

  pi is not installed here, so the event vocabulary is taken from the type
  definitions in `@earendil-works/pi-coding-agent@0.84.1` and
  `@earendil-works/pi-ai@0.84.1`, not from prose docs — the T13f lesson, where
  `permission.asked` had an entry, an arm and a fixture and has never fired.
  The plan lists 15 pi events; the real `ExtensionAPI.on()` overload set has 33.
  Every name the plan lists is real, the list is merely partial.

  Two findings that shaped the mapping. **pi has no permission event** — gating
  is an extension's own `tool_call` handler returning `{block, reason}` — so
  there is no `Permission` arm, because an arm for one would be `permission.asked`
  again. And **pi never reports the size a compaction came out at**: only
  `tokensBefore` exists on both `CompactionPreparation` and `CompactionEntry`,
  so `tokens_after` stays `None` rather than being guessed at.

  `reasoning` is a *subset* of `output` in pi's `Usage`, not a sibling of it,
  so the two are stored side by side and never summed.

  Twenty-four mutations, all bite: session id and cwd dropped; both capture
  gates removed; `excludeFromContext` dropped and `user_bash` host extraction
  removed (a `!` command never passes through `tool_call`, so it is the one way
  to run something invisible to every query about commands); `toolCallId`
  dropped and file extraction skipped on the post leg; the failure-without-
  output-capture fallback removed; each usage field zeroed; the turn-index
  fallback for `turn_id` removed; provider qualification dropped; the compact
  phase pinned, its trigger folded to `auto`, `tokensBefore` dropped, the
  empty-instructions filter removed; the envelope keys left in `Session.detail`;
  `meta.model` dropped from `model_select`; and unknown events routed away
  from `Raw`.

- [x] **T14b** — pi.dev extension, harness registration and fixtures. Dependency: T14a.
  Files: new `plugins/pi/argus.ts`, new `src/harness/pi.rs`, `src/harness/mod.rs`,
  new `tests/fixtures/pi/*.json` (9), new `tests/plugin/pi_payload.mjs`,
  new `tests/pi_plugin.rs`, `src/install.rs`, `src/detect.rs`, `README.md`

  Twelve of pi's 33 events are forwarded; the file lists the other twenty-one
  and why each is not, so an absence reads as a decision rather than an
  oversight.

  Two of those decisions come from reading `dist/core/extensions/runner.js`
  rather than the docs. `emitProjectTrustEvent` dereferences `.trusted` on
  whatever the handler returns, so **`project_trust` is not subscribed to** —
  there is no return value that means "no opinion", and an observability
  extension has no business voting on a trust decision anyway. And
  `emitToolCall` calls the handler with **no try/catch**, so a throw there
  aborts the user's tool call: `base()` swallows its own failure, and it
  catches the cwd read and the session lookup separately so a broken session
  manager costs the session id and not also the field that decides which
  repository an event belongs to.

  `install` writes `~/.pi/agent/extensions/argus.ts`. pi also loads
  `<repo>/.pi/extensions/*.ts`, in its own process with no sandbox — argus
  declines to write there, and `a_project_install_writes_no_pi_extension` is
  what keeps that a decision: a repository must not turn monitoring on for
  whoever clones it.

  Twenty-two mutations, all bite. Plugin: the `turn_end` assistant filter
  removed; `images`/`messages`/`toolResults` forwarded whole instead of as
  counts; `inputSource` renamed back onto the envelope's own `source` key; the
  session lookup left able to throw, and its catch merged with the cwd read so
  a failure costs both; `project_trust` subscribed to; `tool_call` returning an
  object pi reads as a block; `user_bash` losing the directory it ran in; image
  parts kept in a tool result; both compaction sizes read off the wrong object;
  `responseModel` ignored; the whole `preparation` forwarded; and a
  subscription renamed to an unforwarded event (caught by the new
  `every_forwarded_event_has_an_arm`, which reads the `pi.on(...)` calls out of
  the composed shim — pi has no manifest, so that is the only place the
  subscription list exists). Harness: the `extensions/` path component dropped,
  the project guard removed, the `send("pi"` marker changed, `rel` shortened to
  `.pi`.

  Two mutations survived the first pass and were not shrugged off. Making `pi`
  a non-generic binary probe, and emptying its npm list, both stayed green: the
  registry-wide sweeps in `detect.rs` *skip* a harness that declares neither, so
  pi could quietly opt out of the corroboration rule without a test noticing.
  `a_bare_pi_on_path_is_not_pi_dev_but_one_from_npm_is` now pins it directly —
  it is the shortest name argus probes for, and a bare one taken as proof would
  have argus write an extension into a `~/.pi` that pi.dev never made. A third
  survivor was an invalid mutation, not a gap: one try block around both reads
  is equivalent as long as the cwd is read first, so it was rewritten to put
  the throwing read first, and then it bit.

- [ ] **T15** — `install --managed`. Dependency: T10, T11, T12, T13, T14.
  Files: `src/harness/*` (`Scope::Managed` arms), `src/install.rs`, `src/integrity.rs`, `src/main.rs`

  Split under the ~6-file rule: T15a the scope itself, T15b Claude Code's
  managed layer, T15c the kill switches argus does not yet detect, T15d Codex,
  T15e the docs.

- [x] **T15a** — the managed scope, with no harness claiming it yet.
  Dependency: T14b.
  Files: `src/harness/mod.rs`, `src/install.rs`, `src/integrity.rs`, `src/main.rs`

  `--managed` on `install`, `uninstall` and `check`, and the machinery three
  layers of guard keep pointed at the machine rather than at whoever ran
  `sudo`. No harness declares a `ManagedDir` yet, so the flag currently wires
  nothing and says so — T15b and T15c fill it in without touching this.

  The failure being engineered out is specific: the admin runs as root, so
  `dirs::home_dir()` is *root's* home, and all five harnesses guard only
  `Scope::Project` — under `Scope::Managed` they fall through to their user
  artifact. A `sudo argus install --managed` written naively wires `/root` and
  monitors nobody, while reporting success. Hence:

  1. `ManagedDir { rel, platform }` is resolved against a system root, never
     through `Env::home`, and `platform` is required rather than optional —
     every documented managed layer sits somewhere different per OS, so a
     missing entry means "no layer here", not "the same path works".
  2. `managed_detection` returns `None` for a harness that declares nothing,
     so `artifacts(_, Scope::Managed)` is never *called* on the four that
     would answer with a user path.
  3. `escapes_managed_root` is the backstop: any artifact outside the root is
     refused for the whole harness before a single one is applied. Uninstall
     refuses on the same grounds and for a sharper reason — reverting an
     `OwnedFile` deletes it, so obeying would remove a file argus never wrote.

  `ARGUS_SYSTEM_ROOT` redirects the root so the round-trip tests use the real
  relative paths against a temp dir; it grants no privilege, and `require_admin`
  is gated on `SystemRoot::real` rather than on the variable being unset.
  `is_admin` is `geteuid()` on unix and `CheckTokenMembership` against the
  built-in Administrators alias on Windows (its two RIDs are spelled out rather
  than dragging in `Win32_System_SystemServices` for two stable integers).
  `--dry-run` deliberately does *not* demand privilege — requiring root to
  preview a plan only stops an admin checking what they are about to do — but
  warns, so "the preview worked" cannot read as "the install will".

  `check --managed` inverts `check_project`'s rule: a repository nothing wired
  is silent, but a *missing* managed artifact is BROKEN, because passing the
  flag is the operator asserting the layer should be there. That is what makes
  the exit code 2 when someone deletes the file.

  Five mutations, all bite: the containment guard neutered; `ManagedDir`
  ignoring the platform it is declared for; a missing managed file made silent
  the way a project's is; uninstall's refusal dropped; and the test root
  reporting itself as the real machine (which would have made every run demand
  root). The refusal test drives a stub harness reproducing the exact bug —
  a `ManagedDir` declared, `Scope::Managed` unhandled — and asserts both the
  error and that the user-scope file was not written.

  Ground truth for T15b/T15c, read out of the shipped binaries rather than the
  plan's prose, since three details differ from it:
  - Claude Code carries `/Library/Application Support/ClaudeCode`,
    `C:\Program Files\ClaudeCode` and `/etc/claude-code` in one table, plus
    `managed-settings.d/`. `allowManagedHooksOnly`, verbatim: "When true (and
    set in managed settings), only hooks from managed settings run. User,
    project, and local hooks are ignored." So it is only safe once argus's own
    entries are in `managed-settings.json` — and it deliberately stops the
    user's other hooks, which T15d must document.
  - Claude Code also has `disableAllHooks`, which argus does not detect and
    `KillSwitch`'s comment currently denies exists. Policy settings win, so
    pinning `disableAllHooks: false` is its analogue of Codex's pinned feature.
  - Codex's `requirements.toml` is not what the plan describes:
    `allow_managed_hooks_only` is top-level, features are pinned through
    `feature_requirements` (there is no `[features]` table there), and managed
    hooks are not inline — `[hooks] managed_dir` / `windows_managed_dir` point
    at a directory the hook file lives in. Layers: `/etc/codex/config.toml`,
    `/etc/codex/requirements.toml`, `/etc/codex/managed_config.toml` (legacy);
    on Windows resolved through `SHGetKnownFolderPath(FOLDERID_ProgramData)`
    with `OpenAI`/`Codex` as the subpath. Its `HookEventsToml` variants match
    `codex::EVENTS` exactly, so the hooks schema needs no change.

- [x] **T15b** — Claude Code's managed layer, and the settings that decide
  whether hooks run at all. Dependency: T15a.
  Files: `src/harness/mod.rs`, `src/harness/claude_code.rs`, `src/harness/codex.rs`

  `MANAGED_DIRS` are the three paths read out of the shipped binary, and
  `artifacts` becomes an exhaustive `match scope` rather than an
  `if scope == Scope::Project` guard — the fall-through that T15a's third
  guard exists to catch is now impossible to write here at all.

  The new thing is `Artifact::JsonHooks::pinned`: top-level settings argus
  holds beside the hooks, for the one case where a perfectly wired file still
  captures nothing. Claude Code's settings precedence is
  `user → project → local → flag → policy`, policy highest, so a value pinned
  in `managed-settings.json` cannot be weakened from a file a user owns.

  - `disableAllHooks: false` is the pin that protects capture. It is the
    switch that would otherwise turn every hook off, and it is what makes the
    managed layer worth anything.
  - `allowManagedHooksOnly: true` does *not* protect argus — argus's entries
    are in this file, so its capture is identical either way. What it does is
    stop the user's own hooks. That is a real cost, taken deliberately: it is
    what an administrator deploying a machine-wide layer is asking for, and
    the plan's bar for `check --managed` ("exits 2 when … the enforcement key
    flipped") only means something if the key is unconditional. Documented in
    T15e, where an operator will actually read it.

  The three verbs treat pins differently, and each difference is load-bearing:
  `apply` *sets* rather than merges; `verify` checks them *before* the hooks,
  since a flipped key makes every other result meaningless; `revert` removes a
  pin only while its value is still the one argus wrote — an administrator who
  has since changed it has taken it over, and uninstalling argus is not a
  reason to rewrite their policy.

  Seven mutations, all bite. The seventh did not, at first: giving the *user*
  scope the same pins was invisible to every test, which is argus writing
  `allowManagedHooksOnly` into `~/.claude/settings.json` and silently killing
  the user's own hooks in their own config. Fixed by the invariant it was
  missing — only `Scope::Managed` may pin anything, swept over every shipped
  harness so a new one cannot introduce it either.

- [x] **T15c** — the Claude Code kill switches argus could not see.
  Dependency: T15b.
  Files: `src/harness/claude_code.rs`, `src/harness/mod.rs`, `src/install.rs`

  `KillSwitch`'s own comment said Claude Code documents no equivalent setting.
  It documents four, and the shipped `cli.js` resolves hooks like this:

  ```text
  policy.disableAllHooks                      -> {}            // nothing runs
  policy.allowManagedHooksOnly                -> policy.hooks  // only managed
  policy.strictPluginOnlyCustomization(hooks) -> policy.hooks  // only managed
  merged.disableAllHooks                      -> policy.hooks  // only managed
  otherwise                                   -> merged.hooks
  ```

  Three of the four restrict execution to the machine-wide layer and only the
  first stops that layer too. `strictPluginOnlyCustomization` appears in no
  plan or doc — it is either `true` or a list of the customizations it covers,
  and only the list containing `hooks` reaches ours.

  The reads are therefore in two places: `~/.claude/settings.json` for the
  merged `disableAllHooks`, and the machine-wide file *plus*
  `managed-settings.d/*.json` for the other three, since Claude Code reads the
  drop-in directory and a switch hidden there counts exactly as much.

  The one restriction deliberately *not* reported is a restriction argus
  survives: where argus's own entries are in the managed file, a rule keeping
  only managed hooks changes nothing about its capture. Reporting it would
  fire on every host `install --managed` has been run on, which is the same
  false-confidence failure as reporting "wired" about a dead host, in reverse.
  Hence the `managed_wired` test — and hence `disableAllHooks` staying fatal
  regardless, because that one stops the managed layer too.

  Six mutations, all bite, including the `managed_wired` skip and the drop-in
  directory scan.

- [x] **T15d** — Codex's machine-wide layer. Dependency: T15a.
  Files: `src/harness/codex.rs`, `src/harness/mod.rs`

  Three files, not one, and the enforcement lives in a different file from the
  hooks it enforces. Read out of the shipped binaries (darwin and windows),
  because the plan's prose covered none of it:

  * `/etc/codex` on **both** macOS and Linux — there is no
    `Library/Application Support/Codex` — and `ProgramData/OpenAI/Codex` on
    Windows, from `FOLDERID_ProgramData`.
  * Layer precedence is MDM, then managed config (system), then
    enterprise-managed, then *user*, then project. The system `config.toml` is
    the weakest layer, so the enforcement cannot live there:
    `allow_managed_hooks_only` goes in `requirements.toml`.
  * `ConfigRequirementsToml` has no `hooks` member, so `managed_dir` is a
    `config.toml` field — and Windows spells it `windows_managed_dir`, with the
    binary reporting the two as conflicting. Exactly one is written per
    platform, which is why `Scope::Managed` now carries a `Platform`: macOS and
    Linux share a path, so nothing else can tell them apart.

  Order matters more than any single file: `allow_managed_hooks_only` tells
  Codex to run managed hooks *and nothing else*, so writing it before
  `hooks.json` exists would leave the machine running no hooks at all, for the
  length of an install rather than an instant. Hooks are written first and the
  test asserts it.

  The two TOML edits differ deliberately. The `config.toml` pointer is
  `only_if_absent` — a `managed_dir` already set is an administrator's own
  hooks directory, and breaking hooks argus knows nothing about is worse than
  reporting the conflict. The `requirements.toml` flag overwrites, because it
  is argus's pin and re-running the install is the documented repair, as it is
  for Claude Code's pinned settings.

  Not written: `notify` and `[otel]`, which carry this install's receiver token
  and would hand it to every account on a multi-user host in exchange for
  wiring that can only be right for one of them; and `feature_requirements`,
  whose inner schema is not readable from either binary — a `requirements.toml`
  Codex rejects for an unknown field is a config-load failure for everyone on
  the machine. That gap is covered from the detection side instead, by the
  existing `[features] hooks = false` kill-switch read.

  Seven mutations, all bite, including the ordering and both `only_if_absent`
  choices.

- [x] **T15e** — the Codex kill switches argus could not see. Dependency: T15d.
  Files: `src/harness/codex.rs`, `src/install.rs`

  The reads only ever opened `~/.codex`. Codex's machine-wide layer outranks
  the user layer, so `allow_managed_hooks_only` or `[features] hooks = false`
  set there is the value that actually decides — and was invisible.

  Both directories are now swept, and T15d created the false alarm this has to
  avoid: argus writes `allow_managed_hooks_only = true` itself, so reporting it
  unconditionally would fire on every host `install --managed` has run on, with
  argus's own pin reported as argus's own kill switch. It is therefore reported
  only where argus is *not* in the machine-wide hooks directory — the same
  `managed_wired` test as Claude Code (T15c), and applied to the user file too,
  since the question is whether argus's hooks are managed, not who set the flag.

  `[features] hooks = false` gets no such escape: it stops every hook on the
  machine, managed or not.

  Six mutations, all bite. A seventh — passing the wrong `source` to `is_ours`
  — was **discarded rather than accepted as surviving**: `is_ours` matches on
  the marker key argus writes, so `source` only affects legacy entries and the
  mutation was semantically equivalent. Replaced with one that asserts the
  suppression is *conditional* (assume argus is always the managed hook, and a
  genuinely blinded host reads as healthy), which does bite.

- [x] **T15f** — document the machine-wide layer and everything around it.
  Dependency: T15e.
  Files: `README.md`, `docs/adding-a-tool.md`

  `--managed` shipped across T15a–T15e without a word of user-facing
  documentation, and the three install scopes had never been shown side by side.
  README gains: the scope table in Quick start, a **Machine-wide wiring**
  section (per-platform paths, what each tool's layer contains and why, what is
  deliberately not written, `check --managed` semantics), an **Environment
  variables** table, and a rewritten kill-switch section covering Claude Code's
  four settings, Codex's now-two-directory read, and the
  argus-is-the-managed-hook suppression both share.

  The multi-user consequence gets its own subsection, because it is the part a
  fleet rollout gets wrong: `--managed` wires *tools*, not users, so the binary
  has to be executable by every account and every account needs its own daemon
  — the socket, the Codex OTLP port and the buffer are all per-user by
  construction, which is exactly what stops one account's Codex writing into
  another's audit trail.

  `docs/adding-a-tool.md` was written before `Scope` existed. It now documents
  `artifacts(d, scope)` and the `Managed(Platform)` arm (including that
  `d.config_home` is the system directory, never a home directory, because the
  command runs under `sudo`), `pinned`, `managed_dirs()`, `kill_switches()` with
  the suppression rule, and `must_carry`/`only_if_absent` on `TomlEdit`.

  `docs/telemetry-gaps.md` is deliberately untouched: the gaps it lists are what
  T16–T18 close, so it is annotated after them, in T19.

- [ ] **T16** — Pipeline restructure (A/B/C stages). Dependency: T7.
  Files: `src/daemon.rs`, new `src/enrich.rs`, `src/ipc.rs`

  Split into T16a (byte-bounded ingress) and T16b (the A/B/C stage split with
  its ordered shutdown drain), per the sizing rule.

- [x] **T16a** — bound the ingress queue by bytes as well as rows.
  Dependency: T7.
  Files: `src/ipc.rs`, `src/daemon.rs`, `src/adapters/codex.rs`

  The daemon's ingress channel was `mpsc::channel::<Envelope>(1024)`: a row
  count and nothing else. Every producer is capped per item — a socket frame at
  `MAX_FRAME_BYTES` (16 MiB), an OTLP body at 10 MB — but the *queue* was not,
  so a legal worst case was a thousand 16 MiB frames, 16 GiB resident, in the
  one process that has to survive the incident it is recording.

  `ipc::Ingress`/`IngressRx` replace the raw channel: the same bounded `mpsc`
  plus a `Semaphore` charged in bytes, the permit riding along inside the queued
  item so the budget describes what is *queued* rather than what has ever been
  sent. `Ingress::channel()` takes no arguments — the limits live in the module,
  so no call site can quietly wire an unbounded one; `with_limits` exists for
  tests that need a budget reachable in milliseconds.

  Two decisions worth recording. The charge is an estimate (`admission_bytes`
  walks the parsed payload, no allocation) rather than a re-serialization, which
  would cost more than the queueing it governs. And it is clamped to the whole
  budget, so an envelope larger than the budget still passes once the queue
  drains instead of waiting forever for permits that cannot exist.

  Reaching either bound blocks the sender. That is the design, not a
  compromise: the shim's own send deadline then fires and the payload goes to
  the spool, so backpressure costs latency, never events.

  Six mutations, all biting. The fifth — `try_send`, dropping on a full queue —
  **survived the first run**, because the only test then written exercised the
  byte bound, where blocking happens on the semaphore before `try_send` is ever
  reached. Investigated rather than shrugged off: the row bound is a second,
  independent way to find the queue full, and it had no test. Added
  `a_full_row_bound_blocks_rather_than_dropping` (one row, a generous byte
  budget, so only the row count can bind), and the mutation bites.

- [x] **T16b** — split the daemon pipeline into three stages.
  Dependency: T16a.
  Files: new `src/enrich.rs`, `src/daemon.rs`, `src/lib.rs`

  One task did everything between the socket and SQLite: parse, redact, write.
  Redaction — a dozen compiled regexes over every string in every event — was
  the slowest step and the one step that could not be scaled, because it shared
  a thread with the write that has to be serialised anyway.

  Now Stage A (parse, no lock, no disk) hands a batch to Stage B (`enrich`, on
  the blocking pool, `available_parallelism().clamp(2, 8)` at a time) and Stage
  C (`write_loop`, the only writer and the only place a spool file is
  destroyed).

  The hard part is that a parallel stage must not reorder the trail — "the file
  was read, then the request went out" and its reverse are different incidents.
  Stage A creates a `oneshot` per batch and puts the *receiver* in Stage C's
  FIFO queue at submission time; Stage C awaits them in that order. Parallelism
  is bounded by a semaphore, ordering by the queue, and the two are independent.
  The test throttle *decays* (batch 0 slowest) precisely so this is falsifiable:
  under a flat delay a completion-ordered pipeline would look perfectly ordered.

  Delete-after-commit survived the move. The commit is no longer visible from
  `replay_spool`, so the spool path travels with the batch as `Pending::origin`
  and Stage C unlinks it inside the `Ok(())` arm alone. A dead worker leaves the
  file, so the batch replays. Shutdown drains in stage order through one
  extracted `drain()` that the ctrl-c path and all four pipeline tests call, so
  a missing `writer.await` fails tests rather than only production.

  Seven mutations. Two **survived the first run** and were investigated, not
  shrugged off. The write-queue depth had no test of its own: the backpressure
  test slows the enrichers, so the worker semaphore always blocked first and the
  queue was never reached — `a_full_write_queue_blocks_stage_a_as_well` parks
  Stage C on a batch that never finishes enriching, leaving the queue as the only
  bound that can bind. And nothing asserted Stage B still *redacts*: with
  `scrub_event` removed every test passed and the buffer quietly filled with
  secrets, which is exactly the refactor a stage boundary invites.
  `the_pipeline_redacts_before_anything_reaches_the_buffer` closes it. All seven
  bite now.

- [ ] **T17** — Truncation rework. Dependency: T16.
  Files: `src/adapters/mod.rs`, `src/config.rs`, `src/redact.rs`

- [ ] **T18** — File-content capture. Dependency: T17.
  Files: `src/enrich.rs`, `src/config.rs`, `src/event.rs`, `src/redact.rs`, `src/export.rs`, `Cargo.toml`

- [ ] **T19** — Docs. Dependency: T18.
  Files: `docs/adding-a-tool.md`, `README.md`, `docs/telemetry-gaps.md`

## Dependency graph (from the plan)

```
T1 ─► T2 ─► T3 ─┬─► T4 ─┬─► T10, T11, T12, T13, T14 ──► T15
                ├─► T5 ──┘
                ├─► T6 ─► T7 ─► T16 ─► T17 ─► T18 ─► T19
                ├─► T8
                └─► T9
```
