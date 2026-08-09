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
  T10b tool-arm extras, T10c `effort.level` into `Meta`, T10d the three
  unwired hooks, T10e `extract_files_for_tool`'s sortless `dedup`.
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

- [ ] **T11** — Codex parity. Dependency: T4, T5.
  Files: `src/adapters/codex.rs`, `src/harness/codex.rs`, `src/integrity.rs`

- [ ] **T12** — Copilot parity. Dependency: T4, T5.
  Files: `src/adapters/copilot.rs`, `src/harness/copilot.rs`

- [ ] **T13** — opencode + shared TS transport. Dependency: T4, T5.
  Files: `plugins/opencode/argus.ts` + new shared TS transport, `src/adapters/opencode.rs`, `src/harness/opencode.rs`

- [ ] **T14** — pi.dev harness. Dependency: T4, T5.
  Files: new `src/adapters/pi.rs`, new `plugins/pi/argus.ts`, new `src/harness/pi.rs`

- [ ] **T15** — `install --managed`. Dependency: T10, T11, T12, T13, T14.
  Files: `src/harness/*` (`Scope::Managed` arms), `src/install.rs`, `src/integrity.rs`, `src/main.rs`

- [ ] **T16** — Pipeline restructure (A/B/C stages). Dependency: T7.
  Files: `src/daemon.rs`, new `src/enrich.rs`, `src/ipc.rs`

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
