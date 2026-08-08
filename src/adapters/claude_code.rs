use crate::adapters::{cap_text, cap_value, extract_files_for_tool, extract_net_for_tool};
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind, Meta};
use serde_json::{Value, json};

pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    parse_hook("claude-code", &env.payload, capture)
}

fn s(p: &Value, k: &str) -> Option<String> {
    p.get(k).and_then(Value::as_str).map(String::from)
}

fn meta_of(p: &Value) -> Meta {
    Meta {
        turn_id: s(p, "prompt_id").or_else(|| s(p, "turn_id")),
        agent_id: s(p, "agent_id"),
        agent_type: s(p, "agent_type"),
        permission_mode: s(p, "permission_mode"),
        model: s(p, "model"),
        transcript_path: s(p, "transcript_path"),
    }
}

/// Shared parser for Claude-shaped hook payloads (`hook_event_name` +
/// snake_case fields). Codex's hooks system emits the same shape, so the
/// codex adapter delegates here with `source = "codex"`.
pub(crate) fn parse_hook(source: &'static str, p: &Value, capture: &CaptureCfg) -> Vec<Event> {
    let session_id = s(p, "session_id");
    let cwd = s(p, "cwd");
    let meta = meta_of(p);
    let mk = |kind| {
        let mut e = Event::new(source, session_id.clone(), cwd.clone(), kind);
        e.meta = meta.clone();
        e
    };
    let hook = p
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let max = capture.max_field_bytes;

    match hook {
        "UserPromptSubmit" => {
            let text = if capture.prompts {
                cap_text(p.get("prompt").and_then(Value::as_str).unwrap_or(""), max)
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "PreToolUse" | "PostToolUse" | "PostToolUseFailure" => {
            let tool = s(p, "tool_name").unwrap_or_else(|| "unknown".into());
            let input = p.get("tool_input").cloned().unwrap_or(Value::Null);
            let files = extract_files_for_tool(&tool, &input);
            let fqdns = extract_net_for_tool(&tool, &input);
            let phase = match hook {
                "PreToolUse" => "pre",
                "PostToolUse" => "post",
                _ => "error",
            }
            .to_string();
            let output = if hook == "PostToolUse" && capture.tool_outputs {
                cap_value(
                    p.get("tool_response")
                        .or_else(|| p.get("tool_result"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    max,
                )
            } else {
                Value::Null
            };
            let error = if hook == "PostToolUseFailure" {
                p.get("error")
                    .and_then(Value::as_str)
                    .map(|e| cap_text(e, max))
            } else {
                None
            };
            let kept_input = if capture.tool_inputs {
                cap_value(input.clone(), max)
            } else {
                Value::Null
            };
            let mut events = vec![mk(EventKind::ToolUse {
                tool: tool.clone(),
                phase,
                input: kept_input,
                output,
                error,
                files,
                fqdns,
            })];
            if hook == "PreToolUse" {
                match tool.as_str() {
                    "Skill" => events.push(mk(EventKind::Skill {
                        name: s(&input, "skill").unwrap_or_else(|| "unknown".into()),
                        args: s(&input, "args"),
                    })),
                    "Task" | "Agent" => events.push(mk(EventKind::Agent {
                        agent_type: s(&input, "subagent_type")
                            .unwrap_or_else(|| "general-purpose".into()),
                        description: s(&input, "description"),
                    })),
                    _ => {}
                }
            }
            events
        }
        "PermissionRequest" | "PermissionDenied" => {
            let action = if hook == "PermissionRequest" {
                "requested"
            } else {
                "denied"
            };
            vec![mk(EventKind::Permission {
                tool: s(p, "tool_name").unwrap_or_else(|| "unknown".into()),
                action: action.into(),
                input: if capture.tool_inputs {
                    cap_value(p.get("tool_input").cloned().unwrap_or(Value::Null), max)
                } else {
                    Value::Null
                },
            })]
        }
        "Notification" => vec![mk(EventKind::Notification {
            message: cap_text(p.get("message").and_then(Value::as_str).unwrap_or(""), max),
            category: s(p, "type")
                .or_else(|| s(p, "notification_type"))
                .unwrap_or_else(|| "unknown".into()),
        })],
        "Stop" | "SubagentStop" => {
            let mut events = vec![mk(EventKind::Session {
                action: hook.into(),
                detail: Value::Null,
            })];
            if capture.assistant_messages
                && let Some(text) = p.get("last_assistant_message").and_then(Value::as_str)
                && !text.is_empty()
            {
                events.push(mk(EventKind::AssistantMessage {
                    text: cap_text(text, max),
                }));
            }
            events
        }
        "SessionStart" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({"source": p.get("source").cloned().unwrap_or(Value::Null)}),
        })],
        "SessionEnd" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({"reason": p.get("reason").cloned().unwrap_or(Value::Null)}),
        })],
        "SubagentStart" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: Value::Null,
        })],
        "PreCompact" | "PostCompact" => vec![mk(EventKind::Compact {
            phase: if hook == "PreCompact" { "pre" } else { "post" }.into(),
            trigger: s(p, "trigger").unwrap_or_else(|| "unknown".into()),
            tokens_before: p.get("tokens_before").and_then(Value::as_u64),
            tokens_after: p.get("tokens_after").and_then(Value::as_u64),
        })],
        "StopFailure" => vec![mk(EventKind::Error {
            message: cap_text(
                p.get("error_message").and_then(Value::as_str).unwrap_or(""),
                max,
            ),
            context: s(p, "error_type").unwrap_or_else(|| "unknown".into()),
        })],
        "ConfigChange" => vec![mk(EventKind::FileChange {
            path: s(p, "path").unwrap_or_default(),
            action: format!(
                "config_changed:{}",
                p.get("source").and_then(Value::as_str).unwrap_or("unknown")
            ),
        })],
        "InstructionsLoaded" => vec![mk(EventKind::FileChange {
            path: s(p, "path").unwrap_or_default(),
            action: "instructions_loaded".into(),
        })],
        "CwdChanged" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({
                "old_cwd": p.get("old_cwd").cloned().unwrap_or(Value::Null),
                "new_cwd": p.get("new_cwd").cloned().unwrap_or(Value::Null),
            }),
        })],
        "TaskCreated" | "TaskCompleted" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({
                "task": p.get("task").cloned().unwrap_or(Value::Null),
                "task_id": p.get("task_id").cloned().unwrap_or(Value::Null),
                "status": p.get("status").cloned().unwrap_or(Value::Null),
            }),
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
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            event: None,
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
            ..CaptureCfg::default()
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
    fn post_tool_use_captures_tool_response() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PostToolUse", "tool_name": "Bash",
                "tool_input": {"command": "ls"},
                "tool_response": {"stdout": "a.rs\nb.rs"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, output, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "post");
        assert_eq!(output["stdout"], "a.rs\nb.rs");
    }

    #[test]
    fn post_tool_use_failure_maps_to_error_phase() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                "tool_input": {"command": "make"}, "error": "exit 2: no rule"
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, error, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "error");
        assert_eq!(error.as_deref(), Some("exit 2: no rule"));
    }

    #[test]
    fn permission_hooks_map_to_permission_events() {
        for (hook, action) in [
            ("PermissionRequest", "requested"),
            ("PermissionDenied", "denied"),
        ] {
            let events = adapters::parse(
                env(json!({"hook_event_name": hook, "tool_name": "Bash",
                           "tool_input": {"command": "rm -rf /"}})),
                &CaptureCfg::default(),
            );
            let EventKind::Permission {
                tool, action: a, ..
            } = &events[0].kind
            else {
                panic!()
            };
            assert_eq!(tool, "Bash");
            assert_eq!(a, action);
        }
    }

    #[test]
    fn stop_emits_session_and_assistant_message() {
        let events = adapters::parse(
            env(json!({"hook_event_name": "Stop",
                       "last_assistant_message": "done, tests pass"})),
            &CaptureCfg::default(),
        );
        assert!(events.iter().any(|e| matches!(&e.kind,
            EventKind::Session { action, .. } if action == "Stop")));
        assert!(events.iter().any(|e| matches!(&e.kind,
            EventKind::AssistantMessage { text } if text == "done, tests pass")));
    }

    #[test]
    fn assistant_message_respects_capture_flag() {
        let cfg = CaptureCfg {
            assistant_messages: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(
            env(json!({"hook_event_name": "Stop", "last_assistant_message": "secret"})),
            &cfg,
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(&e.kind, EventKind::AssistantMessage { .. }))
        );
    }

    #[test]
    fn session_start_and_end_carry_detail() {
        let events = adapters::parse(
            env(
                json!({"hook_event_name": "SessionStart", "source": "resume",
                       "model": "claude-fable-5"}),
            ),
            &CaptureCfg::default(),
        );
        let EventKind::Session { action, detail } = &events[0].kind else {
            panic!()
        };
        assert_eq!(action, "SessionStart");
        assert_eq!(detail["source"], "resume");
        assert_eq!(events[0].meta.model.as_deref(), Some("claude-fable-5"));

        let events = adapters::parse(
            env(json!({"hook_event_name": "SessionEnd", "reason": "logout"})),
            &CaptureCfg::default(),
        );
        let EventKind::Session { detail, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(detail["reason"], "logout");
    }

    #[test]
    fn subagent_and_meta_context() {
        let events = adapters::parse(
            env(json!({"hook_event_name": "SubagentStart", "agent_id": "a1",
                       "agent_type": "Explore", "permission_mode": "acceptEdits",
                       "transcript_path": "/t/x.jsonl", "prompt_id": "p1"})),
            &CaptureCfg::default(),
        );
        let e = &events[0];
        assert!(matches!(&e.kind, EventKind::Session { action, .. } if action == "SubagentStart"));
        assert_eq!(e.meta.agent_id.as_deref(), Some("a1"));
        assert_eq!(e.meta.agent_type.as_deref(), Some("Explore"));
        assert_eq!(e.meta.permission_mode.as_deref(), Some("acceptEdits"));
        assert_eq!(e.meta.transcript_path.as_deref(), Some("/t/x.jsonl"));
        assert_eq!(e.meta.turn_id.as_deref(), Some("p1"));
    }

    #[test]
    fn compact_notification_error_config_and_cwd_events() {
        let events = adapters::parse(
            env(json!({"hook_event_name": "PostCompact", "trigger": "auto",
                       "tokens_before": 150000, "tokens_after": 30000})),
            &CaptureCfg::default(),
        );
        let EventKind::Compact {
            phase,
            trigger,
            tokens_before,
            tokens_after,
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!((phase.as_str(), trigger.as_str()), ("post", "auto"));
        assert_eq!((*tokens_before, *tokens_after), (Some(150000), Some(30000)));

        let events = adapters::parse(
            env(
                json!({"hook_event_name": "Notification", "message": "needs input",
                       "type": "idle_prompt"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Notification { category, .. } if category == "idle_prompt"));

        let events = adapters::parse(
            env(
                json!({"hook_event_name": "StopFailure", "error_type": "rate_limit",
                       "error_message": "429"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Error { context, .. } if context == "rate_limit"));

        let events = adapters::parse(
            env(
                json!({"hook_event_name": "ConfigChange", "source": "user_settings",
                       "path": "/h/.claude/settings.json"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::FileChange { action, .. } if action == "config_changed:user_settings"));

        let events = adapters::parse(
            env(
                json!({"hook_event_name": "InstructionsLoaded", "path": "/r/CLAUDE.md",
                       "reason": "session_start"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::FileChange { path, action } if path == "/r/CLAUDE.md" && action == "instructions_loaded"));

        let events = adapters::parse(
            env(json!({"hook_event_name": "CwdChanged", "old_cwd": "/a", "new_cwd": "/b"})),
            &CaptureCfg::default(),
        );
        let EventKind::Session { action, detail } = &events[0].kind else {
            panic!()
        };
        assert_eq!(action, "CwdChanged");
        assert_eq!(detail["new_cwd"], "/b");
    }

    #[test]
    fn grep_glob_read_paths_are_extracted() {
        for (tool, key) in [("Grep", "path"), ("Glob", "path"), ("Read", "file_path")] {
            let events = adapters::parse(
                env(json!({"hook_event_name": "PreToolUse", "tool_name": tool,
                           "tool_input": {key: "/repo/src"}})),
                &CaptureCfg::default(),
            );
            let EventKind::ToolUse { files, .. } = &events[0].kind else {
                panic!()
            };
            assert_eq!(files, &vec!["/repo/src".to_string()], "tool {tool}");
        }
    }

    #[test]
    fn oversized_fields_are_capped() {
        let cfg = CaptureCfg {
            max_field_bytes: 64,
            ..CaptureCfg::default()
        };
        let big = "z".repeat(10_000);
        let events = adapters::parse(
            env(
                json!({"hook_event_name": "PostToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "ls"}, "tool_response": {"stdout": big}}),
            ),
            &cfg,
        );
        let EventKind::ToolUse { output, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(output["_truncated"], true);
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
            matches!(&events[0].kind, EventKind::Session { action, .. } if action == "SessionStart")
        );

        let events = adapters::parse(
            env(json!({"hook_event_name": "SomethingNew"})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }
}
