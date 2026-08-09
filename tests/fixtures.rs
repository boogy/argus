//! Every committed fixture must still parse.
//!
//! `tests/fixtures/<harness>/<event>.json` is what `make record-fixtures`
//! produces from a recorded session (see `src/record.rs`). The seed set is
//! doc-derived — Codex, Copilot and pi.dev are not installed on the machine
//! this was written on — so these tests are what stops a doc-derived guess
//! from rotting silently: replace a fixture with a real recording and any
//! adapter that was wrong about a field name fails here rather than in
//! production, where a mismatch just looks like an event that never arrived.

use argus::config::CaptureCfg;
use argus::event::{Envelope, EventKind};
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixtures() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for harness in std::fs::read_dir(fixture_root())
        .expect("fixtures dir")
        .flatten()
    {
        if !harness.path().is_dir() {
            continue;
        }
        for f in std::fs::read_dir(harness.path()).unwrap().flatten() {
            if f.path().extension().is_some_and(|e| e == "json") {
                out.push(f.path());
            }
        }
    }
    out.sort();
    assert!(
        !out.is_empty(),
        "no fixtures found under {:?}",
        fixture_root()
    );
    out
}

fn load(path: &Path) -> Envelope {
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{} is not an Envelope: {e}", path.display()))
}

/// The layout is load-bearing: the adapter a fixture exercises is chosen by
/// its directory, and `record-fixtures` overwrites by `<source>/<label>`. A
/// hand-edited file in the wrong directory would test the wrong adapter.
#[test]
fn fixture_paths_match_the_envelopes_they_hold() {
    for path in fixtures() {
        let envelope = load(&path);
        let dir = path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();
        let stem = path.file_stem().unwrap().to_string_lossy();
        assert_eq!(
            dir,
            envelope.source,
            "{} sits under the wrong harness",
            path.display()
        );
        assert_eq!(
            stem,
            argus::record::label(&envelope),
            "{} would be re-promoted under a different name",
            path.display()
        );
    }
}

/// A fixture that parses to `Raw` is an adapter that does not understand its
/// own tool's event — the exact failure this fixture set exists to catch.
#[test]
fn every_fixture_parses_into_a_recognised_event() {
    for path in fixtures() {
        let envelope = load(&path);
        let events = argus::harness::parse(envelope.clone(), &CaptureCfg::default());
        assert!(!events.is_empty(), "{} produced no events", path.display());
        for e in &events {
            assert_eq!(e.source, envelope.source, "{}", path.display());
            assert!(
                !matches!(e.kind, EventKind::Raw { .. }),
                "{} fell through to Raw: the adapter does not handle this event",
                path.display()
            );
        }
    }
}

/// Parsing an event proves nothing if nobody subscribed to it: `install`
/// writes exactly the hooks in `EVENTS`, so an adapter arm for a hook that is
/// not in that list is dead code that looks, from every query afterwards, like
/// a hook that simply never fires.
///
/// Copilot names the event in `envelope.event` rather than the payload — its
/// native camelCase payloads carry no event field at all, which is why install
/// passes `--event <name>` — so both places are consulted. Codex also receives
/// `notify` and OTLP payloads, which arrive by other routes and name no hook;
/// harnesses and fixtures with no name are skipped rather than failed.
#[test]
fn every_hook_we_parse_is_a_hook_we_subscribe_to() {
    let wired = |source: &str| -> Vec<&'static str> {
        // Copilot's list is plain strings; the other two carry a per-event
        // timeout alongside the name.
        if source == "copilot" {
            return argus::harness::copilot::EVENTS.to_vec();
        }
        let events = match source {
            "claude-code" => argus::harness::claude_code::EVENTS,
            "codex" => argus::harness::codex::EVENTS,
            _ => &[],
        };
        events.iter().map(|e| e.name).collect()
    };
    for path in fixtures() {
        let envelope = load(&path);
        let Some(hook) = envelope
            .event
            .as_deref()
            .or_else(|| envelope.payload["hook_event_name"].as_str())
        else {
            continue;
        };
        let wired = wired(&envelope.source);
        if wired.is_empty() {
            continue;
        }
        assert!(
            wired.contains(&hook),
            "{} parses {hook}, which install never subscribes to",
            path.display()
        );
    }
}

/// Wave 2 is implementable without a live session only if every harness has
/// something to work against.
#[test]
fn every_harness_has_fixtures() {
    for h in argus::harness::HARNESSES {
        let dir = fixture_root().join(h.id());
        let count = std::fs::read_dir(&dir)
            .map(|rd| rd.flatten().count())
            .unwrap_or(0);
        assert!(count >= 3, "{} has {count} fixtures in {:?}", h.id(), dir);
    }
}
