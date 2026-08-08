//! Cost of the per-event path, asserted from outside the crate.
//!
//! These are *floors*, not benchmarks. CI runners are shared and noisy, so
//! nothing here gates on a rate; each bound is chosen so that only a
//! structural regression — a process spawn per event, a full config clone per
//! event, a rewrite of every string against every rule — can cross it. The
//! measured numbers are printed (`cargo test -- --nocapture`) so a human can
//! see the real figure without a machine having to agree on one.

use argus::config::{CaptureCfg, RedactionCfg};
use argus::event::{Envelope, Event, EventKind};

/// Ten thousand events in under two seconds. Resolving the hostname used to
/// spawn `hostname(1)` inside `Event::new`; a fork+exec is on the order of a
/// millisecond even on fast hardware, which puts the old code at ten seconds
/// or more for this loop. Anything that does per-event work of that magnitude
/// fails here, and a machine slow enough to fail it honestly could not run the
/// daemon either.
#[test]
fn constructing_events_does_not_spawn_a_process_each_time() {
    const N: usize = 10_000;
    let start = std::time::Instant::now();
    let mut hosts = 0usize;
    for i in 0..N {
        let e = Event::new(
            "claude-code",
            Some("s1".into()),
            None,
            EventKind::Prompt {
                text: format!("prompt {i}"),
            },
        );
        if !e.host.is_empty() {
            hosts += 1;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(hosts, N, "every event still gets a host");
    println!(
        "Event::new x{N}: {elapsed:?} ({:.1} us/event)",
        elapsed.as_secs_f64() * 1e6 / N as f64
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "{N} events took {elapsed:?}; that is process-spawn territory"
    );
}

/// Redaction sees every string the pipeline carries, and almost none of them
/// contain a secret. Ten patterns applied unconditionally to a full copy of
/// each string is the regression this guards.
#[test]
fn redacting_clean_text_is_cheap() {
    const N: usize = 20_000;
    let redactor = argus::redact::Redactor::new(&RedactionCfg::default());
    let text = "please read src/daemon.rs and explain how the export loop \
                decides when to give up on a batch, then suggest a smaller \
                shape for it that keeps the backoff behaviour intact";
    let start = std::time::Instant::now();
    let mut kept = 0usize;
    for _ in 0..N {
        kept += redactor.scrub_str(text).len();
    }
    let elapsed = start.elapsed();
    assert_eq!(kept, text.len() * N, "clean text must survive unchanged");
    println!(
        "scrub_str x{N}: {elapsed:?} ({:.1} us/string)",
        elapsed.as_secs_f64() * 1e6 / N as f64
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "{N} clean strings took {elapsed:?}"
    );
}

/// The whole point of spooling is that an event survives the daemon being
/// down. If it then exports stamped with the moment the daemon happened to
/// drain it, the outage erases the timeline it was supposed to preserve: an
/// hour of work lands on the collector as one spike, in drain order.
#[test]
fn a_spooled_envelope_keeps_its_capture_time() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("ARGUS_DATA_DIR", dir.path());
    }
    let captured_at = chrono::Utc::now() - chrono::Duration::hours(3);
    let envelope = Envelope {
        source: "claude-code".into(),
        received_at: captured_at,
        truncated: false,
        event: None,
        payload: serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "s1",
            "prompt": "written while the daemon was down",
        }),
    };
    argus::spool::append(&envelope).unwrap();

    let drained = argus::spool::drain().unwrap();
    assert_eq!(drained.len(), 1, "the spooled envelope comes back");
    let events =
        argus::adapters::parse(drained.into_iter().next().unwrap(), &CaptureCfg::default());
    assert!(!events.is_empty(), "the spooled payload still parses");
    for e in &events {
        assert_eq!(
            e.ts, captured_at,
            "event carries the drain time, not the capture time"
        );
    }
    unsafe {
        std::env::remove_var("ARGUS_DATA_DIR");
    }
}

/// An unknown source falls through to `Raw`, and that path builds its event
/// by hand — it has to be stamped too, or the fallback silently reintroduces
/// the bug for exactly the payloads nobody has a mapping for yet.
#[test]
fn the_unknown_source_fallback_is_stamped_too() {
    let captured_at = chrono::Utc::now() - chrono::Duration::minutes(90);
    let events = argus::adapters::parse(
        Envelope {
            source: "some-tool-we-do-not-know".into(),
            received_at: captured_at,
            truncated: false,
            event: None,
            payload: serde_json::json!({"anything": true}),
        },
        &CaptureCfg::default(),
    );
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].kind, EventKind::Raw { .. }));
    assert_eq!(events[0].ts, captured_at);
}
