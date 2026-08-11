# Adding a new tool

argus supports a tool when three pieces exist:

1. **Adapter** — `src/adapters/<tool>.rs` exposing
   `pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event>`.
   Map the tool's payloads onto `EventKind` variants; use the shared helpers
   (`extract_files_for_tool`, `extract_net_for_tool`, `cap_text`, `cap_value`)
   and honor every `CaptureCfg` flag. Unknown payloads → `EventKind::Raw`
   (never drop data).
2. **Delivery** — get the tool to run `argus hook --source <tool>`
   with JSON on stdin (add `--event <name>` per hook entry if the payload
   carries no event-name field), or speak the daemon's socket/OTLP surface
   directly for in-process plugins.
3. **Harness** — `src/harness/<tool>.rs` with an `impl Harness`, plus one row
   in `HARNESSES` in `src/harness/mod.rs`. That single row is what makes the
   tool detectable, installable, uninstallable, checkable *and* parseable, so
   a tool can no longer be half-registered.

The `Harness` impl is declarative — describe the tool, don't write install
logic:

- `probes()` — the evidence that the tool is installed. Four independent kinds,
  and a tool is detected if *any* of them fires:
  - `config_dirs` — where the tool's config lives. Each entry has an optional
    env root (`("CODEX_HOME", "")`, `("XDG_CONFIG_HOME", "opencode")`), a
    home-relative default, and an optional `platform` that scopes it to one OS.
    **Declaration order is install order**: the first entry is where argus
    writes when nothing exists on disk yet, so put the tool's own preferred
    location first and platform-specific variants after it.
  - `binaries` — the executable names to look for, on `PATH` *and* in the
    per-user prefixes a hook's `PATH` routinely omits. Use `BinaryProbe::new`
    for a name only this tool would own, and `BinaryProbe::generic` for an
    ordinary word someone else might ship (`codex`); a generic name alone
    never counts as detection, it only strengthens another signal.
  - `npm_packages` / `brew_formulae` — the package names this tool ships
    under. Detection canonicalizes the binary it found and checks whether the
    real path runs through `node_modules/<package>/` or `Cellar/<formula>/`.
    That is what corroborates a generic name, and it is what tells `status`
    *how* the tool got there.

  A config directory only exists once the tool has been **run**, so a
  binary-or-package signal is what lets argus wire a freshly-installed agent
  before its first launch. Everything detection reads from the outside world —
  including the platform — arrives through `detect::Env`, so a Windows layout
  is unit-testable from macOS; never reach for `cfg!` here.
- `artifacts(d, scope)` — the files argus writes. `OwnedFile` for a file with
  our own name (overwritten on install, deleted on uninstall); `JsonHooks` to
  merge entries into a shared hooks JSON; `TomlEdit` for key-level edits into
  shared TOML. Generic `install`/`uninstall`/`check` drive all three, and every
  `JsonHooks` entry is stamped `"_argus": true` so uninstall removes exactly
  what we added.

  `scope` is `User`, `Project`, or `Managed(Platform)`, and the arms are
  genuinely different files rather than subsets of each other. Return an empty
  `Vec` for a scope the tool has no layer for — that is not an error, it is how
  `install --project` stays silent about tools a repository cannot carry.
  `Managed` carries the platform because a machine-wide install is the one case
  where argus writes artifacts for a platform it may not be running on (the
  round-trip tests sweep all three), and because the layers genuinely differ:
  Codex spells one setting `managed_dir` on unix and `windows_managed_dir` on
  Windows. Under `Managed`, `d.config_home` is the *system* directory — never a
  home directory. The command runs under `sudo`, so anything derived from the
  invoking user would resolve to root's home and monitor nobody; the harness
  layer enforces this centrally by refusing any artifact that lands outside the
  system root.

  `JsonHooks` also carries `pinned`: top-level settings set (not merged) beside
  the hooks, for the machine-wide scope only — a test asserts no other scope
  pins anything, since a pin in a user file would silently disable the user's
  own hooks in their own config.
- `managed_dirs()` — the system directories for `Scope::Managed`, one per
  platform, relative to the system root. Defaults to empty, which means the tool
  has no machine-wide layer and `--managed` skips it.
- `kill_switches(d)` — settings that leave every hook entry in place, correct
  and ours, and still stop it running. Reporting "wired" about a tool capturing
  nothing is worse than reporting nothing, because someone believes it. Read
  these from the shipped binary, not from documentation: every one argus checks
  today was found that way, and two of them are documented nowhere. If argus's
  own machine-wide install *sets* one of these (Claude Code's
  `allowManagedHooksOnly`, Codex's `allow_managed_hooks_only`), suppress the
  finding where argus is itself in the managed layer — otherwise the check fires
  on every host `install --managed` has run on.
- `parse()` — delegate to the adapter from step 1.

Never build a hook command with `format!("{exe} …")`: call `hook_command`,
which quotes the program path for the target shell (and emits PowerShell's `&`
call operator). An unquoted path breaks on any install location containing a
space. It also resolves the binary through `install_path`, which prefers the
stable `PATH` alias over `current_exe()` — the latter reports the symlink
*target*, a path the next package upgrade deletes.

`check` has to be able to prove capture can happen, not just that files exist,
so give it something falsifiable per artifact:

- `OwnedFile` — `markers` are literal substrings that must still be on disk
  (for a hooks file, one per event). They are matched against the raw text, so
  write them the way the file stores them — JSON-escaped inside JSON. Put any
  hook command whose program must resolve in `commands` instead, unescaped;
  leave it empty for a file that reaches the daemon without invoking the
  binary. A test asserts every marker really is in the contents `install`
  writes, so a bad marker fails the suite rather than every user's `check`.
- `TomlEdit` — set `argv_tail` when the value is an argv array starting with
  the argus binary, and `check` compares the trailing arguments element-wise
  and resolves element 0. Otherwise `ours_markers` is used as a substring test.
  Set `must_carry` when being *ours* is not enough and the value has to match
  **this** install: `ours_markers` deliberately still recognises what older
  argus versions wrote, so uninstall cleans up after them — but a config
  pointing at a port nothing listens on, or presenting a token the receiver
  refuses, captures nothing, and matching a legacy marker would report that as
  wired. `check` uses `must_carry` instead whenever it is non-empty.
  `only_if_absent` decides what happens when a value is already there: leave an
  administrator's or user's own content alone and let `check` report the
  conflict, or overwrite because the value is argus's own pin and re-running the
  install is the documented repair.

Anything left unverified is silently permanent: before this, a `TomlEdit` was
never checked at all, so a half-installed Codex reported healthy forever.

## What a `ToolUse` owes the pipeline

An adapter builds `EventKind::ToolUse` with `file_contents: vec![]` and leaves
it that way. File capture runs in the daemon's enrichment stage, not at parse
time, because it does filesystem I/O and parsing is a single task the whole
socket queues behind. There is nothing per-tool to write.

Two fields decide whether that stage can do anything, and both are the
adapter's to get right:

- **The path key.** Candidates are picked out of `input` by shape, not by tool
  name: a recognized path key, plus `content`/`contents` (a write),
  `new_string`/`newString`/`new_str` (an edit), an `edits` array, or an
  `apply_patch` body. If the new tool spells its path something not in
  `FILE_KEYS` (`src/adapters/mod.rs`), add it there — the same list feeds
  `extract_files_for_tool`, so a missing spelling costs the `files` list as
  well as the capture, and both failures look like a tool that touches no
  files.
- **`Event::cwd`.** A relative path is only a file once you know where it was
  said. Resolving one against the daemon's working directory would name a
  different file with the same name, so an event that carries a relative path
  and no `cwd` is recorded as `unreadable` rather than guessed at. If the
  tool's payload carries a project or session directory, map it.

Content the payload already carried needs no I/O and no `cwd` — it is captured
in `payload` mode, which is the default. It is read out of the `input` the
adapter kept, which has two consequences. Cap that input with the shared
`cap_value`/`cap_text` and nothing else: they keep both ends and leave
redaction headroom, where a hand-rolled truncation hands the capture a middle
it will report as a tail. And `capture.tool_inputs = false` nulls that input,
which takes file capture with it — both halves, since the disk half also finds
its paths there. The `files` list is read from the raw payload and is
unaffected, so such an event still names every file and describes none of them.

## Fixtures

Adapters written from documentation are guesses about field names, and a wrong
guess is invisible in production — a mismatched field just looks like an event
that never arrived. So capture what the tool really sends:

```sh
eval "$(make record)"     # exports ARGUS_RECORD_DIR
# ...use the agent normally, then in another shell:
make record-fixtures      # -> tests/fixtures/<harness>/<event>.json
unset ARGUS_RECORD_DIR
```

Recording dumps every envelope the shim handles, verbatim and un-redacted,
which is why `RECORD_DIR` lives under `target/`. Promotion is the step whose
output is committed, so it redacts, normalizes the timestamp, and collapses
repeats of an event into one file — re-running it on unchanged recordings
leaves the tree clean.

`tests/fixtures.rs` then asserts every fixture parses into a *recognized*
event. A fixture that falls through to `EventKind::Raw` means the adapter does
not understand its own tool, which is exactly the drift this exists to catch.
The fixtures in the repo today are doc-derived seeds: replacing one with a real
recording is how a mapping stops being provisional.

Rules that keep the pipeline safe and fast:

- Hooks are observe-only: exit 0, print nothing to stdout.
- The shim is the only thing on the host tool's critical path — adapters run
  in the daemon and may be as thorough as they need to be.
- Any new text-bearing `EventKind` field must be given OTLP attributes in
  `export.rs`. `Redactor::scrub_event` destructures every variant exhaustively,
  so a new field is a compile error there until you decide whether to scrub it.
