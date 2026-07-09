use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Raw frame sent by the hook shim. The shim never parses tool payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub source: String,
    pub received_at: DateTime<Utc>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub username: String,
    pub source: String,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Prompt {
        text: String,
    },
    ToolUse {
        tool: String,
        phase: String,
        input: serde_json::Value,
        files: Vec<String>,
        fqdns: Vec<String>,
    },
    Skill {
        name: String,
        args: Option<String>,
    },
    Agent {
        agent_type: String,
        description: Option<String>,
    },
    Session {
        action: String,
    },
    Raw {
        payload: serde_json::Value,
    },
}

impl Event {
    pub fn new(
        source: &str,
        session_id: Option<String>,
        cwd: Option<String>,
        kind: EventKind,
    ) -> Self {
        Event {
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now(),
            host: hostname(),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".into()),
            source: source.to_string(),
            session_id,
            cwd,
            kind,
        }
    }
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_json() {
        let e = Event::new(
            "claude-code",
            Some("sess-1".into()),
            Some("/repo".into()),
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "pre".into(),
                input: serde_json::json!({"file_path": "/repo/a.rs"}),
                files: vec!["/repo/a.rs".into()],
                fqdns: vec![],
            },
        );
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.source, "claude-code");
        assert!(matches!(back.kind, EventKind::ToolUse { .. }));
        assert!(!back.id.is_empty());
        assert!(!back.host.is_empty());
    }

    #[test]
    fn envelope_roundtrips() {
        let env = Envelope {
            source: "opencode".into(),
            received_at: chrono::Utc::now(),
            payload: serde_json::json!({"event": "tool.execute.before"}),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.source, "opencode");
    }

    #[test]
    fn event_kind_is_flattened_at_top_level() {
        let e = Event::new(
            "claude-code",
            None,
            None,
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "pre".into(),
                input: serde_json::json!({}),
                files: vec![],
                fqdns: vec![],
            },
        );
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "tool_use");
        assert_eq!(v["tool"], "Write");
        assert!(
            v.get("kind").is_none(),
            "kind must be flattened, not nested"
        );
        assert!(v.get("id").is_some());
    }
}
