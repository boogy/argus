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

- [ ] **T5** — Payload recorder. Dependency: T3.
  Files: `src/hook.rs`, `Makefile`, `tests/fixtures/**`

- [ ] **T6** — Hot-path hardening. Dependency: T3.
  Files: `src/paths.rs`, `src/event.rs`, `src/redact.rs`, `src/buffer.rs`, `src/daemon.rs`, `src/export.rs`, `src/hook.rs`
  (Split point if it runs long: T6a = `OnceLock` + `RegexSet` + `CREATE_NO_WINDOW`; T6b = SQLite/config/exporter changes.)

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
