use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind};
use serde_json::Value;

pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let p = &env.payload;
    let session_id = p
        .get("sessionID")
        .and_then(Value::as_str)
        .or_else(|| p.pointer("/properties/sessionID").and_then(Value::as_str))
        .map(String::from);
    let cwd = p.get("cwd").and_then(Value::as_str).map(String::from);
    let mk = |kind| Event::new("opencode", session_id.clone(), cwd.clone(), kind);
    let event = p.get("event").and_then(Value::as_str).unwrap_or("");
    let max = capture.max_field_bytes;
    let props = p.get("properties").cloned().unwrap_or(Value::Null);

    match event {
        "chat.message" => {
            let role = p
                .pointer("/message/role")
                .and_then(Value::as_str)
                .unwrap_or("");
            let joined = |cap: bool| -> String {
                if !cap {
                    return "[not captured]".into();
                }
                crate::adapters::cap_text(
                    &p.get("parts")
                        .and_then(Value::as_array)
                        .map(|parts| {
                            parts
                                .iter()
                                .filter_map(|part| part.get("text").and_then(Value::as_str))
                                .collect::<Vec<_>>()
                                .join("\n")
                        })
                        .unwrap_or_default(),
                    max,
                )
            };
            match role {
                "user" => vec![mk(EventKind::Prompt {
                    text: joined(capture.prompts),
                })],
                "assistant" if capture.assistant_messages => {
                    vec![mk(EventKind::AssistantMessage { text: joined(true) })]
                }
                _ => vec![],
            }
        }
        "tool.execute.before" | "tool.execute.after" => {
            let tool = p
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let args = p.get("args").cloned().unwrap_or(Value::Null);
            let files = crate::adapters::extract_files_for_tool(&tool, &args);
            let fqdns = crate::adapters::extract_net_for_tool(&tool, &args);
            let phase = if event.ends_with("before") {
                "pre"
            } else {
                "post"
            }
            .to_string();
            let input = if capture.tool_inputs {
                crate::adapters::cap_value(args, max)
            } else {
                Value::Null
            };
            let output = if event.ends_with("after") && capture.tool_outputs {
                crate::adapters::cap_value(p.get("result").cloned().unwrap_or(Value::Null), max)
            } else {
                Value::Null
            };
            let mut ev = mk(EventKind::ToolUse {
                tool,
                phase,
                input,
                output,
                error: None,
                // opencode's plugin events carry neither.
                duration_ms: None,
                interrupted: false,
                files,
                fqdns,
            });
            // The plugin has always sent this and the adapter has always
            // dropped it. It is the only thing that pairs the `before` with
            // the `after`: two `bash` calls in a turn are otherwise
            // indistinguishable, so a call that hung — a `pre` whose `post`
            // never arrived — could not be told from one that finished.
            ev.meta.tool_use_id = p.get("callID").and_then(Value::as_str).map(String::from);
            vec![ev]
        }
        "permission.asked" | "permission.replied" | "permission.updated" => {
            let action = match event {
                "permission.asked" => "requested",
                "permission.replied" => "replied",
                _ => "updated",
            };
            vec![mk(EventKind::Permission {
                tool: props
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .into(),
                action: action.into(),
                input: crate::adapters::cap_value(props.clone(), max),
            })]
        }
        "file.edited" | "file.watcher.updated" => {
            let path = props
                .get("file")
                .or_else(|| props.get("path"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let action = if event == "file.edited" {
                "edited"
            } else {
                "watcher_updated"
            };
            vec![mk(EventKind::FileChange {
                path,
                action: action.into(),
            })]
        }
        "command.executed" => vec![mk(EventKind::Skill {
            name: props
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            args: props
                .get("arguments")
                .and_then(Value::as_str)
                .map(String::from),
        })],
        e if e.starts_with("session.")
            || e == "todo.updated"
            || e == "server.connected"
            || e == "installation.updated" =>
        {
            vec![mk(EventKind::Session {
                action: event.into(),
                detail: crate::adapters::cap_value(props.clone(), max),
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

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope {
            source: "opencode".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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

    /// Every other harness reports where the session is running; opencode
    /// reported `null`, which silently excluded its events from anything
    /// scoped to a repository.
    #[test]
    fn events_carry_the_working_directory_the_plugin_reports() {
        for payload in [
            json!({"event": "chat.message", "cwd": "/repo",
                   "message": {"role": "user"}, "parts": [{"text": "hi"}]}),
            json!({"event": "tool.execute.before", "cwd": "/repo", "tool": "bash",
                   "args": {"command": "ls"}}),
            json!({"event": "session.error", "cwd": "/repo", "properties": {}}),
        ] {
            let events = adapters::parse(env(payload.clone()), &CaptureCfg::default());
            assert_eq!(events[0].cwd.as_deref(), Some("/repo"), "payload {payload}");
        }
    }

    /// The `before` and the `after` of one call are otherwise
    /// indistinguishable from a second call of the same tool in the same turn,
    /// so without this there is no duration and no way to spot a call whose
    /// `after` never arrived.
    #[test]
    fn tool_events_keep_the_call_id_that_pairs_them() {
        let ids: Vec<_> = ["tool.execute.before", "tool.execute.after"]
            .iter()
            .map(|event| {
                let events = adapters::parse(
                    env(json!({"event": event, "sessionID": "oc1", "tool": "bash",
                               "callID": "call_7", "args": {"command": "ls"}})),
                    &CaptureCfg::default(),
                );
                events[0].meta.tool_use_id.clone()
            })
            .collect();
        assert_eq!(
            ids,
            vec![Some("call_7".into()), Some("call_7".into())],
            "both legs must carry the same id"
        );
    }

    #[test]
    fn non_user_non_assistant_message_is_ignored() {
        let events = adapters::parse(
            env(json!({
                "event": "chat.message", "sessionID": "oc1",
                "message": {"role": "system"}, "parts": [{"type": "text", "text": "hi"}]
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
    fn assistant_message_is_captured() {
        let events = adapters::parse(
            env(json!({
                "event": "chat.message", "sessionID": "oc1",
                "message": {"role": "assistant"},
                "parts": [{"type": "text", "text": "All tests pass."}]
            })),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::AssistantMessage { text } if text == "All tests pass."));
    }

    #[test]
    fn assistant_message_respects_capture_flag() {
        let cfg = CaptureCfg {
            assistant_messages: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(
            env(
                json!({"event": "chat.message", "message": {"role": "assistant"},
                       "parts": [{"type": "text", "text": "secret"}]}),
            ),
            &cfg,
        );
        assert!(events.is_empty());
    }

    #[test]
    fn tool_execute_after_captures_result() {
        let events = adapters::parse(
            env(json!({
                "event": "tool.execute.after", "sessionID": "oc1", "tool": "bash",
                "result": {"title": "ls", "output": "a.ts\nb.ts", "metadata": {}}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, output, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "post");
        assert_eq!(output["output"], "a.ts\nb.ts");
    }

    #[test]
    fn permission_events_map() {
        for (event, action) in [
            ("permission.asked", "requested"),
            ("permission.replied", "replied"),
        ] {
            let events = adapters::parse(
                env(json!({"event": event, "sessionID": "oc1",
                           "properties": {"type": "bash", "pattern": "rm *"}})),
                &CaptureCfg::default(),
            );
            let EventKind::Permission { action: a, .. } = &events[0].kind else {
                panic!()
            };
            assert_eq!(a, action, "event {event}");
        }
    }

    #[test]
    fn file_edited_maps_to_file_change() {
        let events = adapters::parse(
            env(json!({"event": "file.edited", "sessionID": "oc1",
                       "properties": {"file": "/repo/src/app.ts"}})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::FileChange { path, action } if path == "/repo/src/app.ts" && action == "edited"));
    }

    #[test]
    fn command_executed_maps_to_skill() {
        let events = adapters::parse(
            env(json!({"event": "command.executed", "sessionID": "oc1",
                       "properties": {"command": "commit", "arguments": "-m fix"}})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Skill { name, .. } if name == "commit"));
    }

    #[test]
    fn session_bus_events_map_to_session_kind() {
        for event in ["session.error", "session.compacted", "session.deleted"] {
            let events = adapters::parse(
                env(json!({"event": event, "sessionID": "oc1", "properties": {"x": 1}})),
                &CaptureCfg::default(),
            );
            assert!(
                matches!(&events[0].kind,
                    EventKind::Session { action, .. } if action == event),
                "event {event}"
            );
        }
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
