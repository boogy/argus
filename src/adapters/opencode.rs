use crate::adapters::extract_fqdns;
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind};
use serde_json::Value;

pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let p = &env.payload;
    let session_id = p.get("sessionID").and_then(Value::as_str).map(String::from);
    let mk = |kind| Event::new("opencode", session_id.clone(), None, kind);
    let event = p.get("event").and_then(Value::as_str).unwrap_or("");

    match event {
        "chat.message" => {
            let is_user = p.pointer("/message/role").and_then(Value::as_str) == Some("user");
            if !is_user {
                return vec![];
            }
            let text = if capture.prompts {
                p.get("parts")
                    .and_then(Value::as_array)
                    .map(|parts| {
                        parts
                            .iter()
                            .filter_map(|part| part.get("text").and_then(Value::as_str))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default()
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "tool.execute.before" | "tool.execute.after" => {
            let tool = p
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let args = p.get("args").cloned().unwrap_or(Value::Null);
            let files = ["filePath", "path"]
                .iter()
                .filter_map(|k| args.get(k).and_then(Value::as_str))
                .map(String::from)
                .collect();
            let mut fqdns: Vec<String> = vec![];
            for key in ["url", "command"] {
                if let Some(s) = args.get(key).and_then(Value::as_str) {
                    fqdns.extend(extract_fqdns(s));
                }
            }
            let phase = if event.ends_with("before") {
                "pre"
            } else {
                "post"
            }
            .to_string();
            let input = if capture.tool_inputs {
                args
            } else {
                Value::Null
            };
            vec![mk(EventKind::ToolUse {
                tool,
                phase,
                input,
                output: Value::Null,
                error: None,
                files,
                fqdns,
            })]
        }
        "session.created" | "session.idle" => vec![mk(EventKind::Session {
            action: event.into(),
            detail: Value::Null,
        })],
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope {
            source: "opencode".into(),
            received_at: chrono::Utc::now(),
            event: None,
            payload,
        }
    }

    #[test]
    fn user_message_becomes_prompt() {
        let events = adapters::parse(
            env(json!({
                "event": "chat.message", "sessionID": "oc1",
                "message": {"role": "user"}, "parts": [{"type": "text", "text": "add tests"}]
            })),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "add tests"));
        assert_eq!(events[0].session_id.as_deref(), Some("oc1"));
    }

    #[test]
    fn tool_execute_maps_files_and_fqdns() {
        let events = adapters::parse(
            env(json!({
                "event": "tool.execute.before", "sessionID": "oc1",
                "tool": "write", "args": {"filePath": "/repo/x.ts", "content": "..."}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { tool, files, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(tool, "write");
        assert_eq!(files, &vec!["/repo/x.ts".to_string()]);

        let events = adapters::parse(
            env(json!({
                "event": "tool.execute.before", "tool": "bash",
                "args": {"command": "curl https://registry.npmjs.org/x"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(fqdns, &vec!["registry.npmjs.org".to_string()]);
    }

    #[test]
    fn non_user_message_is_ignored() {
        let events = adapters::parse(
            env(json!({
                "event": "chat.message", "sessionID": "oc1",
                "message": {"role": "assistant"}, "parts": [{"type": "text", "text": "hi"}]
            })),
            &CaptureCfg::default(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn capture_flags_suppress_content() {
        let cfg = CaptureCfg {
            prompts: false,
            tool_inputs: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(
            env(json!({
                "event": "chat.message", "message": {"role": "user"},
                "parts": [{"type": "text", "text": "secret"}]
            })),
            &cfg,
        );
        let EventKind::Prompt { text } = &events[0].kind else {
            panic!()
        };
        assert_eq!(text, "[not captured]");

        let events = adapters::parse(
            env(json!({
                "event": "tool.execute.before", "tool": "write",
                "args": {"filePath": "/a.ts", "content": "secret"}
            })),
            &cfg,
        );
        let EventKind::ToolUse { input, files, .. } = &events[0].kind else {
            panic!()
        };
        assert!(input.is_null());
        assert_eq!(files.len(), 1, "metadata still extracted");
    }

    #[test]
    fn session_and_unknown_events_map() {
        let events = adapters::parse(
            env(json!({"event": "session.created", "sessionID": "s"})),
            &CaptureCfg::default(),
        );
        assert!(
            matches!(&events[0].kind, EventKind::Session { action, .. } if action == "session.created")
        );
        let events = adapters::parse(
            env(json!({"event": "mystery.event"})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }

    #[test]
    fn tool_execute_after_maps_to_post_phase() {
        let events = adapters::parse(
            env(json!({"event": "tool.execute.after", "tool": "bash"})),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "post");
    }
}
