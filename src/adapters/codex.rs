use crate::config::{CaptureCfg, Config};
use crate::event::{Envelope, Event, EventKind};
use serde_json::Value;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::Sender;

pub fn parse(payload: &Value, _capture: &CaptureCfg) -> Vec<Event> {
    vec![Event::new(
        "codex",
        None,
        None,
        EventKind::Raw {
            payload: payload.clone(),
        },
    )]
}

/// Codex OTLP receiver stub. Task 13 replaces this with a real listener that
/// accepts OTLP-formatted events from the Codex CLI's `notify` hook and
/// forwards parsed envelopes into `tx`.
pub async fn otlp_listener(_cfg: Arc<RwLock<Config>>, _tx: Sender<Envelope>) {}
