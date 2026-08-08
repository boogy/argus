//! GitHub Copilot CLI adapter. Hook entries are installed per-event with an
//! explicit `--event <name>` hint because Copilot's native camelCase payloads
//! carry no event-name field. PascalCase/snake_case payloads (VS Code
//! compatible style, with `hook_event_name`) are also accepted.
use crate::adapters::{cap_text, cap_value, extract_files_for_tool, extract_net_for_tool};
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind, Meta};
use serde_json::{Value, json};

/// Get the camelCase field, falling back to its snake_case twin.
fn field<'a>(p: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    p.get(camel).or_else(|| p.get(snake))
}

fn sfield(p: &Value, camel: &str, snake: &str) -> Option<String> {
    field(p, camel, snake)
        .and_then(Value::as_str)
        .map(String::from)
}

/// Normalize event names across both styles to camelCase.
fn event_name(env: &Envelope) -> String {
    if let Some(e) = &env.event {
        return e.clone();
    }
    match env.payload.get("hook_event_name").and_then(Value::as_str) {
        Some("SessionStart") => "sessionStart".into(),
        Some("SessionEnd") => "sessionEnd".into(),
        Some("UserPromptSubmit") => "userPromptSubmitted".into(),
        Some("PreToolUse") => "preToolUse".into(),
        Some("PostToolUse") => "postToolUse".into(),
        Some("PostToolUseFailure") => "postToolUseFailure".into(),
        Some("ErrorOccurred") => "errorOccurred".into(),
        Some("Stop") => "agentStop".into(),
        Some("SubagentStop") => "subagentStop".into(),
        Some("PreCompact") => "preCompact".into(),
        Some("Notification") => "notification".into(),
        Some("PermissionRequest") => "permissionRequest".into(),
        Some(other) => other.into(),
        None => String::new(),
    }
}

pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let p = &env.payload;
    let session_id = sfield(p, "sessionId", "session_id");
    let cwd = p.get("cwd").and_then(Value::as_str).map(String::from);
    let meta = Meta {
        agent_type: sfield(p, "agentName", "agent_name"),
        transcript_path: sfield(p, "transcriptPath", "transcript_path"),
        ..Meta::default()
    };
    let mk = |kind| {
        let mut e = Event::new("copilot", session_id.clone(), cwd.clone(), kind);
        e.meta = meta.clone();
        e
    };
    let max = capture.max_field_bytes;
    let name = event_name(env);

    match name.as_str() {
        "userPromptSubmitted" => {
            let text = if capture.prompts {
                cap_text(p.get("prompt").and_then(Value::as_str).unwrap_or(""), max)
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "preToolUse" | "postToolUse" | "postToolUseFailure" => {
            let tool = sfield(p, "toolName", "tool_name").unwrap_or_else(|| "unknown".into());
            let args = field(p, "toolArgs", "tool_input")
                .cloned()
                .unwrap_or(Value::Null);
            let files = extract_files_for_tool(&tool, &args);
            let fqdns = extract_net_for_tool(&tool, &args);
            let phase = match name.as_str() {
                "preToolUse" => "pre",
                "postToolUse" => "post",
                _ => "error",
            };
            let output = if name == "postToolUse" && capture.tool_outputs {
                cap_value(
                    field(p, "toolResult", "tool_result")
                        .cloned()
                        .unwrap_or(Value::Null),
                    max,
                )
            } else {
                Value::Null
            };
            vec![mk(EventKind::ToolUse {
                tool,
                phase: phase.into(),
                input: if capture.tool_inputs {
                    cap_value(args, max)
                } else {
                    Value::Null
                },
                output,
                error: p
                    .get("error")
                    .and_then(Value::as_str)
                    .map(|e| cap_text(e, max)),
                files,
                fqdns,
            })]
        }
        "permissionRequest" => vec![mk(EventKind::Permission {
            tool: sfield(p, "toolName", "tool_name").unwrap_or_else(|| "unknown".into()),
            action: "requested".into(),
            input: if capture.tool_inputs {
                cap_value(
                    field(p, "toolArgs", "tool_input")
                        .cloned()
                        .unwrap_or(Value::Null),
                    max,
                )
            } else {
                Value::Null
            },
        })],
        "errorOccurred" => vec![mk(EventKind::Error {
            message: cap_text(
                p.pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                max,
            ),
            context: sfield(p, "errorContext", "error_context").unwrap_or_else(|| "unknown".into()),
        })],
        "notification" => vec![mk(EventKind::Notification {
            message: cap_text(p.get("message").and_then(Value::as_str).unwrap_or(""), max),
            category: sfield(p, "notification_type", "notificationType")
                .unwrap_or_else(|| "unknown".into()),
        })],
        "preCompact" => vec![mk(EventKind::Compact {
            phase: "pre".into(),
            trigger: p
                .get("trigger")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            tokens_before: None,
            tokens_after: None,
        })],
        "sessionStart" | "sessionEnd" | "agentStop" | "subagentStart" | "subagentStop" => {
            vec![mk(EventKind::Session {
                action: name.clone(),
                detail: json!({
                    "source": field(p, "source", "source").cloned().unwrap_or(Value::Null),
                    "reason": field(p, "reason", "reason").cloned().unwrap_or(Value::Null),
                    "stop_reason": field(p, "stopReason", "stop_reason").cloned().unwrap_or(Value::Null),
                }),
            })]
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(event: &str, payload: serde_json::Value) -> Envelope {
        Envelope {
            source: "copilot".into(),
            received_at: chrono::Utc::now(),
            event: Some(event.into()),
            payload,
        }
    }

    #[test]
    fn prompt_and_session_events() {
        let events = adapters::parse(
            env(
                "userPromptSubmitted",
                json!({"sessionId": "cp1", "cwd": "/repo", "prompt": "add tests"}),
            ),
            &CaptureCfg::default(),
        );
        assert_eq!(events[0].source, "copilot");
        assert_eq!(events[0].session_id.as_deref(), Some("cp1"));
        assert_eq!(events[0].cwd.as_deref(), Some("/repo"));
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "add tests"));

        let events = adapters::parse(
            env(
                "sessionStart",
                json!({"sessionId": "cp1", "source": "startup"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Session { action, .. } if action == "sessionStart"));
    }

    #[test]
    fn tool_use_pre_post_and_failure() {
        let events = adapters::parse(
            env(
                "preToolUse",
                json!({"sessionId": "cp1", "toolName": "bash",
                       "toolArgs": {"command": "curl https://api.github.com/x"}}),
            ),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse {
            tool, phase, fqdns, ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!((tool.as_str(), phase.as_str()), ("bash", "pre"));
        assert_eq!(fqdns, &vec!["api.github.com".to_string()]);

        let events = adapters::parse(
            env(
                "postToolUse",
                json!({"sessionId": "cp1", "toolName": "create",
                       "toolArgs": {"path": "/repo/new.ts"},
                       "toolResult": {"resultType": "success", "textResultForLlm": "created"}}),
            ),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse {
            phase,
            files,
            output,
            ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!(phase, "post");
        assert_eq!(files, &vec!["/repo/new.ts".to_string()]);
        assert_eq!(output["textResultForLlm"], "created");

        let events = adapters::parse(
            env(
                "postToolUseFailure",
                json!({"sessionId": "cp1", "toolName": "bash",
                       "toolArgs": {"command": "make"}, "error": "exit 2"}),
            ),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, error, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "error");
        assert_eq!(error.as_deref(), Some("exit 2"));
    }

    #[test]
    fn error_notification_permission_subagent_compact() {
        let events = adapters::parse(
            env(
                "errorOccurred",
                json!({"sessionId": "cp1",
                       "error": {"message": "model timeout", "name": "TimeoutError"},
                       "errorContext": "model_call", "recoverable": true}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Error { message, context } if message == "model timeout" && context == "model_call"));

        let events = adapters::parse(
            env(
                "notification",
                json!({"sessionId": "cp1", "message": "done",
                       "notification_type": "agent_completed"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Notification { category, .. } if category == "agent_completed"));

        let events = adapters::parse(
            env(
                "permissionRequest",
                json!({"sessionId": "cp1", "toolName": "bash",
                       "toolArgs": {"command": "rm -rf"}}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Permission { action, .. } if action == "requested"));

        let events = adapters::parse(
            env(
                "subagentStart",
                json!({"sessionId": "cp1", "agentName": "reviewer",
                       "transcriptPath": "/t/sub.json"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Session { action, .. } if action == "subagentStart"));
        assert_eq!(events[0].meta.agent_type.as_deref(), Some("reviewer"));
        assert_eq!(
            events[0].meta.transcript_path.as_deref(),
            Some("/t/sub.json")
        );

        let events = adapters::parse(
            env("preCompact", json!({"sessionId": "cp1", "trigger": "auto"})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Compact { phase, trigger, .. } if phase == "pre" && trigger == "auto"));
    }

    #[test]
    fn pascal_case_payload_without_event_hint_still_parses() {
        let envp = Envelope {
            source: "copilot".into(),
            received_at: chrono::Utc::now(),
            event: None,
            payload: json!({"hook_event_name": "UserPromptSubmit",
                            "session_id": "cp2", "prompt": "hello"}),
        };
        let events = adapters::parse(envp, &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "hello"));
    }

    #[test]
    fn unknown_event_is_raw() {
        let events = adapters::parse(
            env("someFutureEvent", json!({"sessionId": "cp1"})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }
}
