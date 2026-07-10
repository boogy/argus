use crate::adapters::extract_fqdns;
use crate::config::CaptureCfg;
use crate::event::{Event, EventKind};
use serde_json::Value;

pub fn parse(p: &Value, capture: &CaptureCfg) -> Vec<Event> {
    let session_id = p
        .get("session_id")
        .and_then(Value::as_str)
        .map(String::from);
    let cwd = p.get("cwd").and_then(Value::as_str).map(String::from);
    let hook = p
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mk = |kind| Event::new("claude-code", session_id.clone(), cwd.clone(), kind);

    match hook {
        "UserPromptSubmit" => {
            let text = if capture.prompts {
                p.get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "PreToolUse" | "PostToolUse" => {
            let tool = p
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let input = p.get("tool_input").cloned().unwrap_or(Value::Null);
            let files = extract_files(&tool, &input);
            let fqdns = extract_net(&tool, &input);
            let phase = if hook == "PreToolUse" { "pre" } else { "post" }.to_string();
            let kept_input = if capture.tool_inputs {
                input.clone()
            } else {
                Value::Null
            };
            let mut events = vec![mk(EventKind::ToolUse {
                tool: tool.clone(),
                phase,
                input: kept_input,
                files,
                fqdns,
            })];
            if hook == "PreToolUse" {
                match tool.as_str() {
                    "Skill" => events.push(mk(EventKind::Skill {
                        name: input
                            .get("skill")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .into(),
                        args: input.get("args").and_then(Value::as_str).map(String::from),
                    })),
                    "Task" | "Agent" => events.push(mk(EventKind::Agent {
                        agent_type: input
                            .get("subagent_type")
                            .and_then(Value::as_str)
                            .unwrap_or("general-purpose")
                            .into(),
                        description: input
                            .get("description")
                            .and_then(Value::as_str)
                            .map(String::from),
                    })),
                    _ => {}
                }
            }
            events
        }
        "SessionStart" | "SessionEnd" | "Stop" | "SubagentStop" | "PreCompact" | "Notification" => {
            vec![mk(EventKind::Session {
                action: hook.to_string(),
            })]
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

fn extract_files(tool: &str, input: &Value) -> Vec<String> {
    match tool {
        "Write" | "Edit" | "NotebookEdit" | "Read" => input
            .get("file_path")
            .or_else(|| input.get("notebook_path"))
            .and_then(Value::as_str)
            .map(|s| vec![s.to_string()])
            .unwrap_or_default(),
        _ => vec![],
    }
}

fn extract_net(tool: &str, input: &Value) -> Vec<String> {
    match tool {
        "WebFetch" => input
            .get("url")
            .and_then(Value::as_str)
            .map(extract_fqdns)
            .unwrap_or_default(),
        "Bash" => input
            .get("command")
            .and_then(Value::as_str)
            .map(extract_fqdns)
            .unwrap_or_default(),
        _ => vec![],
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
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            payload,
        }
    }

    #[test]
    fn user_prompt_submit_becomes_prompt_event() {
        let events = adapters::parse(
            env(json!({
                "session_id": "abc", "cwd": "/repo",
                "hook_event_name": "UserPromptSubmit",
                "prompt": "refactor the auth module"
            })),
            &CaptureCfg::default(),
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].session_id.as_deref(), Some("abc"));
        let EventKind::Prompt { text } = &events[0].kind else {
            panic!("wrong kind")
        };
        assert_eq!(text, "refactor the auth module");
    }

    #[test]
    fn write_tool_extracts_file_path() {
        let events = adapters::parse(
            env(json!({
                "session_id": "abc", "cwd": "/repo",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": "/repo/src/db.rs", "content": "fn x() {}"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { tool, files, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(tool, "Write");
        assert_eq!(files, &vec!["/repo/src/db.rs".to_string()]);
    }

    #[test]
    fn bash_and_webfetch_extract_fqdns() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "Bash",
                "tool_input": {"command": "curl https://evil.example.com/x && wget http://cdn.foo.io/pkg"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else {
            panic!()
        };
        assert!(fqdns.contains(&"evil.example.com".to_string()));
        assert!(fqdns.contains(&"cdn.foo.io".to_string()));

        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "WebFetch",
                "tool_input": {"url": "https://docs.rs/tokio", "prompt": "read"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(fqdns, &vec!["docs.rs".to_string()]);
    }

    #[test]
    fn skill_and_agent_tools_emit_dedicated_events() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "Skill",
                "tool_input": {"skill": "commit", "args": "-m fix"}
            })),
            &CaptureCfg::default(),
        );
        assert_eq!(events.len(), 2, "ToolUse + Skill");
        assert!(events.iter().any(|e| matches!(&e.kind,
            EventKind::Skill { name, .. } if name == "commit")));

        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "Task",
                "tool_input": {"subagent_type": "Explore", "description": "find auth code", "prompt": "..."}
            })),
            &CaptureCfg::default(),
        );
        assert!(events.iter().any(|e| matches!(&e.kind,
            EventKind::Agent { agent_type, .. } if agent_type == "Explore")));
    }

    #[test]
    fn capture_flags_suppress_content() {
        let cfg = CaptureCfg {
            prompts: false,
            tool_inputs: false,
        };
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "UserPromptSubmit", "prompt": "secret plans"
            })),
            &cfg,
        );
        let EventKind::Prompt { text } = &events[0].kind else {
            panic!()
        };
        assert_eq!(text, "[not captured]");

        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "Write",
                "tool_input": {"file_path": "/repo/a.rs", "content": "secret"}
            })),
            &cfg,
        );
        let EventKind::ToolUse { input, files, .. } = &events[0].kind else {
            panic!()
        };
        assert!(input.is_null(), "content suppressed");
        assert_eq!(files.len(), 1, "metadata (paths) still captured");
    }

    #[test]
    fn post_tool_use_skill_does_not_double_emit() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PostToolUse", "tool_name": "Skill",
                "tool_input": {"skill": "commit"}
            })),
            &CaptureCfg::default(),
        );
        assert_eq!(
            events.len(),
            1,
            "PostToolUse must emit only ToolUse, no Skill event"
        );
    }

    #[test]
    fn notebook_edit_extracts_notebook_path() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "NotebookEdit",
                "tool_input": {"notebook_path": "/repo/nb.ipynb"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { files, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(files, &vec!["/repo/nb.ipynb".to_string()]);
    }

    #[test]
    fn session_and_unknown_events() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "SessionStart", "session_id": "abc"
            })),
            &CaptureCfg::default(),
        );
        assert!(
            matches!(&events[0].kind, EventKind::Session { action } if action == "SessionStart")
        );

        let events = adapters::parse(
            env(json!({"hook_event_name": "SomethingNew"})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }
}
