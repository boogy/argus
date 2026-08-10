//! Stage B of the daemon pipeline: everything done to a parsed batch between
//! the socket and the buffer.
//!
//! It lives on its own because it is the only stage that is both expensive and
//! parallelisable. Parsing is cheap, and the SQLite write has to be serialised
//! whatever else happens; redaction — a dozen compiled regexes over every
//! string in every event — is neither. Running it inline on the single
//! consumer made the slowest step the one step that could not be scaled, which
//! is the wrong way round.
//!
//! Stage B runs on the blocking pool, several batches at a time, and is
//! deliberately synchronous: it is CPU work and (from T18) file reads, not I/O
//! the async runtime can interleave.

use crate::event::Event;
use crate::redact::Redactor;

/// Redact one parsed batch.
///
/// Takes the whole batch rather than one event so that later additions with
/// per-*event* budgets — file-content capture — have somewhere to enforce them
/// that isn't a global.
pub fn enrich(events: Vec<Event>, redactor: &Redactor) -> Vec<Event> {
    #[cfg(test)]
    slow_down();
    events
        .into_iter()
        .map(|e| redactor.scrub_event(e))
        .collect()
}

/// Test-only throttle. Backpressure is only observable when Stage B is slower
/// than its producer, and a redactor fast enough to be worth shipping cannot
/// be made slow by feeding it more data — a test that tried would be timing a
/// regex engine rather than the pipeline around it.
///
/// The delay *decays*: the first batch waits `SLOW_MICROS`, and each one after
/// it waits `SLOW_STEP_MICROS` less. That is what makes ordering falsifiable.
/// Under a flat delay, batches finish in the order they started whatever Stage
/// C does, so a pipeline that emitted them as they completed would look
/// perfectly ordered; make the earlier batches the slower ones and the two
/// behaviours produce opposite output.
#[cfg(test)]
static SLOW_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static SLOW_STEP_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
static SLOW_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn set_delay(base_micros: u64, step_micros: u64) {
    use std::sync::atomic::Ordering::Relaxed;
    SLOW_MICROS.store(base_micros, Relaxed);
    SLOW_STEP_MICROS.store(step_micros, Relaxed);
    SLOW_CALLS.store(0, Relaxed);
}

#[cfg(test)]
fn slow_down() {
    use std::sync::atomic::Ordering::Relaxed;
    let base = SLOW_MICROS.load(Relaxed);
    if base == 0 {
        return;
    }
    let nth = SLOW_CALLS.fetch_add(1, Relaxed);
    let micros = base.saturating_sub(SLOW_STEP_MICROS.load(Relaxed).saturating_mul(nth));
    if micros > 0 {
        std::thread::sleep(std::time::Duration::from_micros(micros));
    }
}
