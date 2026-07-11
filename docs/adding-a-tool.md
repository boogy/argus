# Adding a new tool

llm-monitor supports a tool when three pieces exist:

1. **Adapter** — `src/adapters/<tool>.rs` exposing
   `pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event>`.
   Map the tool's payloads onto `EventKind` variants; use the shared helpers
   (`extract_files_for_tool`, `extract_net_for_tool`, `cap_text`, `cap_value`)
   and honor every `CaptureCfg` flag. Unknown payloads → `EventKind::Raw`
   (never drop data). Register it in `ADAPTERS` in `src/adapters/mod.rs`.
2. **Delivery** — get the tool to run `llm-monitor hook --source <tool>`
   with JSON on stdin (add `--event <name>` per hook entry if the payload
   carries no event-name field), or speak the daemon's socket/OTLP surface
   directly for in-process plugins.
3. **Install wiring** — an `install_<tool>` function in `src/install.rs`:
   detect by config-dir presence, edit additively + idempotently, tag every
   entry with `llm-monitor`, and implement the exact reverse in `uninstall`.

Rules that keep the pipeline safe and fast:

- Hooks are observe-only: exit 0, print nothing to stdout.
- The shim is the only thing on the host tool's critical path — adapters run
  in the daemon and may be as thorough as they need to be.
- Any new text-bearing `EventKind` field must be scrubbed in
  `Redactor::scrub_event` and given OTLP attributes in `export.rs`.
