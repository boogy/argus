//! The pi extension is TypeScript, so the only way to test it is to run it.
//! `tests/plugin/pi_payload.mjs` imports the real extension and exercises it;
//! this file is what puts it behind `make verify`.
//!
//! The shared transport is covered once, by `tests/opencode_plugin.rs` — it is
//! the same bytes in both composed shims, and testing it twice would only make
//! the second copy look independent.

/// The extension half of the contract with `src/adapters/pi.rs`: every handler
/// must put `cwd` and `sessionID` into the envelope, transcripts must stay off
/// the wire, and the `tool_call` handler must be incapable of throwing.
///
/// A field the extension stops sending breaks no Rust test on its own. The
/// adapter reads `None`, every event still parses, and the column just goes
/// empty — which is why this asserts on the wire format rather than on what the
/// adapter makes of it.
///
/// Unix only: the driver serves a unix socket, and the Windows transport takes
/// a different path entirely. The extension code under test is the same on both.
#[cfg(unix)]
#[test]
fn every_handler_sends_the_fields_the_adapter_reads() {
    run_driver("pi_payload.mjs");
}

#[cfg(unix)]
fn run_driver(name: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let driver = root.join("tests/plugin").join(name);

    // The driver runs the composed shim, not the source fragment: install joins
    // the shared transport onto pi's half, and only the joined file is a thing
    // that runs. Written next to the driver so its relative imports —
    // currently only the type-only `@earendil-works/pi-coding-agent` — resolve
    // the same way they will in `~/.pi/agent/extensions`.
    let shim = root.join(format!("target/pi-shim.{name}.ts"));
    std::fs::write(&shim, argus::harness::pi::shim_source()).unwrap();

    // Deliberately not a silent skip. The extension is the only thing standing
    // between pi and the daemon; a run that quietly does not test it reports
    // the same green as a run that does. Opting out has to be a decision
    // somebody made on purpose.
    let out = match std::process::Command::new("node")
        .arg(&driver)
        .arg(&shim)
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            if std::env::var_os("ARGUS_SKIP_PLUGIN_TESTS").is_some() {
                eprintln!("skipping {name}: node not runnable ({e})");
                return;
            }
            panic!(
                "could not run node for {name} ({e}). The pi extension is \
                 TypeScript and cannot be tested without a runtime — install \
                 Node, or set ARGUS_SKIP_PLUGIN_TESTS=1 to accept an untested \
                 extension."
            );
        }
    };
    assert!(
        out.status.success(),
        "{name} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
