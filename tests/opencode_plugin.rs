//! The opencode shim is TypeScript, so the only way to test it is to run it.
//! `tests/plugin/*.mjs` are drivers that import the real plugin and exercise
//! one property each; this file is what puts them behind `make verify`.

/// One event must produce exactly one envelope even when the daemon has
/// stopped reading.
///
/// `Socket.write()` returns `false` when the stream is over its high-water
/// mark. That is backpressure, not refusal — the frame is queued and goes out
/// on drain — but the shim used to return that boolean as "the socket did not
/// take it" and then spawn the fallback binary for the same event. Under a
/// stalled reader the driver measures 400 envelopes for 200 events with that
/// version, which is exactly the shape of double-counted tool calls in a
/// dashboard nobody can explain.
///
/// Unix only: the driver writes a `#!/bin/sh` stand-in for the argus binary so
/// that an event taking the fallback is counted the same way as one taking the
/// socket, and the Windows shim would need a different program entirely. The
/// transport code under test is the same on both.
#[cfg(unix)]
#[test]
fn one_event_is_one_envelope_even_when_the_socket_is_backed_up() {
    run_driver("opencode_transport.mjs");
}

#[cfg(unix)]
fn run_driver(name: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let driver = root.join("tests/plugin").join(name);

    // The driver runs the composed shim, not the source fragment: install
    // joins the shared transport onto opencode's half, and only the joined
    // file is a thing that runs. Written next to the driver so its relative
    // imports — currently only the type-only `@opencode-ai/plugin` — resolve
    // the same way they will in the user's config directory.
    let shim = root.join("target/opencode-shim.test.ts");
    std::fs::write(&shim, argus::harness::opencode::shim_source()).unwrap();

    // Deliberately not a silent skip. The plugin is the only thing standing
    // between opencode and the daemon; a run that quietly does not test it
    // reports the same green as a run that does. Opting out has to be a
    // decision somebody made on purpose.
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
                "could not run node for {name} ({e}). The opencode shim is \
                 TypeScript and cannot be tested without a runtime — install \
                 Node, or set ARGUS_SKIP_PLUGIN_TESTS=1 to accept an untested \
                 plugin."
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
