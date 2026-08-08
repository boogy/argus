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
space.

Rules that keep the pipeline safe and fast:

- Hooks are observe-only: exit 0, print nothing to stdout.
- The shim is the only thing on the host tool's critical path — adapters run
  in the daemon and may be as thorough as they need to be.
- Any new text-bearing `EventKind` field must be given OTLP attributes in
  `export.rs`. `Redactor::scrub_event` destructures every variant exhaustively,
  so a new field is a compile error there until you decide whether to scrub it.
