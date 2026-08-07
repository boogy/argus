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
  Note: T1's own `make verify` was green on clippy + test; `fmt-check` on the
  pre-existing baseline was repaired in a separate, non-`T`-prefixed commit
  (the repo had never been fmt-checked on the current toolchain — see
  `tasks/lessons.md`).

- [ ] **T2** — `trait Harness` + `Artifact` refactor. Dependency: T1.
  Files: new `src/harness/*`, `src/install.rs`, `src/integrity.rs`, `src/adapters/mod.rs`, `src/redact.rs`, `src/lib.rs`

- [ ] **T3** — Make `check` prove capture actually works. Dependency: T2.
  Files: `src/integrity.rs`, `src/install.rs`, `src/harness/{codex,mod}.rs`

- [ ] **T4** — Cross-platform detection. Dependency: T3.
  Files: new `src/detect.rs`, `src/harness/mod.rs`, `src/install.rs`, `src/main.rs`

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
