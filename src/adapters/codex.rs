use crate::config::CaptureCfg;
use crate::event::{Event, EventKind};
use serde_json::Value;

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
