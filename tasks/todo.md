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

- [ ] **T8** — Transport security. Dependency: T3.
  Files: `src/paths.rs`, `src/ipc.rs`, `src/adapters/codex.rs`, `src/install.rs`, `Cargo.toml`

- [ ] **T9** — Export correctness. Dependency: T3.
  Files: `src/export.rs`, `src/buffer.rs`, `Cargo.toml`

- [ ] **T10** — Claude Code field-mismatch fixes. Dependency: T4, T5.
  Files: `src/adapters/claude_code.rs`, `src/adapters/mod.rs`, `src/harness/claude_code.rs`

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
