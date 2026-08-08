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

- `probes()` — where the tool's config lives, so detection finds it.
- `artifacts()` — the files argus writes. `OwnedFile` for a file with our own
  name (overwritten on install, deleted on uninstall); `JsonHooks` to merge
  entries into a shared hooks JSON; `TomlEdit` for key-level edits into shared
  TOML. Generic `install`/`uninstall`/`check` drive all three, and every
  `JsonHooks` entry is stamped `"_argus": true` so uninstall removes exactly
  what we added.
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

Anything left unverified is silently permanent: before this, a `TomlEdit` was
never checked at all, so a half-installed Codex reported healthy forever.

Rules that keep the pipeline safe and fast:

- Hooks are observe-only: exit 0, print nothing to stdout.
- The shim is the only thing on the host tool's critical path — adapters run
  in the daemon and may be as thorough as they need to be.
- Any new text-bearing `EventKind` field must be given OTLP attributes in
  `export.rs`. `Redactor::scrub_event` destructures every variant exhaustively,
  so a new field is a compile error there until you decide whether to scrub it.
