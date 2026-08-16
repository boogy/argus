use crate::adapters::{
    cap_text, cap_value, extract_files_for_tool, extract_net_for_tool, extract_net_from_output,
};
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
        tool_use_id: s(p, "tool_use_id"),
        // Stamped from the envelope in `harness::parse`, for every source at
        // once — an adapter that forgot would make a redirected host look
        // like an ordinary one.
        env_overrides: Vec::new(),
        // `effort` is an object, `{"level": "high"}` — the level is the part
        // worth carrying, and lifting it here keeps `Meta` a flat string map.
        effort: p
            .pointer("/effort/level")
            .and_then(Value::as_str)
            .map(String::from),
        // Derived from the tool's name by `harness::parse`, for every source
        // at once — nothing in the payload says it.
        mcp_server: None,
        // Resolved from config files in `enrich`, behind its own opt-in.
        mcp_endpoint: None,
    }
}

/// `Stop`, `SubagentStop` and `StopFailure` all carry the turn's last assistant
/// message under the same name and behind the same capture flag. Kept in one
/// place so a third caller cannot quietly forget the flag.
fn push_last_message(
    events: &mut Vec<Event>,
    p: &Value,
    capture: &CaptureCfg,
    mk: &impl Fn(EventKind) -> Event,
) {
    if capture.assistant_messages
        && let Some(text) = p.get("last_assistant_message").and_then(Value::as_str)
        && !text.is_empty()
    {
        events.push(mk(EventKind::AssistantMessage {
            text: cap_text(text, capture.max_field_bytes),
        }));
    }
}

/// Shared parser for Claude-shaped hook payloads (`hook_event_name` +
/// snake_case fields). Codex's hooks system emits the same shape, so the
/// codex adapter delegates here with `source = "codex"`.
///
/// Field names here are taken from the payload constructors and Zod schemas
/// inside the installed Claude Code binary (2.1.224), not from the published
/// hook docs — the two disagree, and a name that disagrees costs an
/// always-empty field that looks exactly like an event that never fired.
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
            let net = extract_net_for_tool(&tool, &input);
            let phase = match hook {
                "PreToolUse" => "pre",
                "PostToolUse" => "post",
                _ => "error",
            }
            .to_string();
            let raw_output = p
                .get("tool_response")
                .or_else(|| p.get("tool_result"))
                .cloned()
                .unwrap_or(Value::Null);
            // Scanned before the `tool_outputs` check and before the cap, for
            // the same reason the input is: which hosts a call touched is
            // metadata, and switching off the payload is a decision about
            // storing text, not about going blind.
            let out_net = extract_net_from_output(&raw_output).minus(&net);
            let output = if hook == "PostToolUse" && capture.tool_outputs {
                cap_value(raw_output, max)
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
                duration_ms: p.get("duration_ms").and_then(Value::as_u64),
                // Only the failure leg carries it, and only there does the
                // distinction matter: it says a human stopped the call rather
                // than the call going wrong.
                interrupted: p
                    .get("is_interrupt")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                files,
                fqdns: net.fqdns,
                endpoints: net.endpoints,
                output_fqdns: out_net.fqdns,
                output_endpoints: out_net.endpoints,
                file_contents: vec![],
            })];
            if hook == "PreToolUse" {
                // `args` and `description` are tool input under another name:
                // a slash command's arguments and an agent's brief are both
                // free text the user typed or pasted. A deployment that turned
                // `tool_inputs` off asked for that not to leave the machine,
                // and it does not stop asking because the field is spelled
                // differently. The *name* stays either way — that is the
                // record of what ran, which is what capture is for.
                let arg = |key| capture.tool_inputs.then(|| s(&input, key)).flatten();
                match tool.as_str() {
                    "Skill" => events.push(mk(EventKind::Skill {
                        name: s(&input, "skill").unwrap_or_else(|| "unknown".into()),
                        args: arg("args"),
                    })),
                    "Task" | "Agent" => events.push(mk(EventKind::Agent {
                        agent_type: s(&input, "subagent_type")
                            .unwrap_or_else(|| "general-purpose".into()),
                        description: arg("description"),
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
            // Sent alongside `message` (`{ hook_event_name: "Notification",
            // message, title, notification_type }` in the shipped binary) and
            // dropped until now.
            title: s(p, "title").map(|t| cap_text(&t, max)),
        })],
        "Stop" | "SubagentStop" => {
            let mut events = vec![mk(EventKind::Session {
                action: hook.into(),
                detail: Value::Null,
            })];
            push_last_message(&mut events, p, capture, &mk);
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
            // `custom_instructions` in the payload, `nullable()` in the
            // binary's own schema — so absent, null and empty all arrive and
            // all mean the same thing.
            instructions: s(p, "custom_instructions")
                .filter(|i| !i.is_empty())
                .map(|i| cap_text(&i, max)),
        })],
        // `error` is the *type* — one of an enum (`rate_limit`,
        // `authentication_failed`, `invalid_request`, …) — and `error_details`
        // is the prose. Reading them the other way round put an enum variant
        // where the message goes and left the context always "unknown".
        "StopFailure" => {
            let mut events = vec![mk(EventKind::Error {
                message: cap_text(
                    p.get("error_details").and_then(Value::as_str).unwrap_or(""),
                    max,
                ),
                context: s(p, "error").unwrap_or_else(|| "unknown".into()),
                // Claude Code's `error` is already the type and it is put in
                // `context`; there is no second name and no recoverability
                // flag in this payload.
                name: None,
                recoverable: None,
            })];
            // A turn that ended in an error still says what the model had got
            // to before it did — and that half-finished message is the part
            // that says what the turn was *trying* to do.
            push_last_message(&mut events, p, capture, &mk);
            events
        }
        "ConfigChange" => vec![mk(EventKind::FileChange {
            path: s(p, "file_path").unwrap_or_default(),
            action: format!(
                "config_changed:{}",
                p.get("source").and_then(Value::as_str).unwrap_or("unknown")
            ),
        })],
        // `memory_type` is the tier the file came from (`User`, `Project`,
        // `Local`, `Managed`). Which tier is the finding: a `Managed`
        // instructions file is administrator-controlled, a `Local` one is not.
        "InstructionsLoaded" => vec![mk(EventKind::FileChange {
            path: s(p, "file_path").unwrap_or_default(),
            action: format!(
                "instructions_loaded:{}",
                p.get("memory_type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
        })],
        // `/add-dir`, or the SDK's `register_repo_root`, widening what the
        // agent is allowed to reach. `source` says which, and the two are not
        // equally interesting: a human typing `/add-dir` chose the expansion,
        // an SDK caller may have been talked into it.
        "DirectoryAdded" => vec![mk(EventKind::FileChange {
            path: s(p, "directory").unwrap_or_default(),
            action: format!(
                "directory_added:{}",
                p.get("source").and_then(Value::as_str).unwrap_or("unknown")
            ),
        })],
        // A slash command or MCP prompt turning into the text the model
        // actually reads. `UserPromptSubmit` carries what the human typed;
        // this carries what it became — and the gap between the two is the
        // whole point, because the expansion body lives in a file the human
        // is not looking at when they type the command.
        "UserPromptExpansion" => {
            let prompt = if capture.prompts {
                cap_text(p.get("prompt").and_then(Value::as_str).unwrap_or(""), max)
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Session {
                action: hook.into(),
                detail: json!({
                    "expansion_type": p.get("expansion_type").cloned().unwrap_or(Value::Null),
                    "command_name": p.get("command_name").cloned().unwrap_or(Value::Null),
                    "command_args": p.get("command_args").cloned().unwrap_or(Value::Null),
                    // Which tier defined the command — a project-level one is
                    // repo-controlled, so whoever can push can change it.
                    "command_source": p.get("command_source").cloned().unwrap_or(Value::Null),
                    "prompt": prompt,
                }),
            })]
        }
        // The finding here is the *grouping*: which calls the model chose to
        // run in one parallel batch. Every call's input and output already
        // arrived on its own `PostToolUse`, so repeating them would double the
        // bytes against the buffer's caps for nothing — the ids are what stitch
        // this row back to those.
        "PostToolBatch" => {
            let tool_calls: Vec<Value> = p
                .get("tool_calls")
                .and_then(Value::as_array)
                .map(|calls| {
                    calls
                        .iter()
                        .map(|c| {
                            json!({
                                "tool_name": c.get("tool_name").cloned().unwrap_or(Value::Null),
                                "tool_use_id": c.get("tool_use_id").cloned().unwrap_or(Value::Null),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            vec![mk(EventKind::Session {
                action: hook.into(),
                detail: json!({ "tool_calls": tool_calls }),
            })]
        }
        "CwdChanged" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({
                "old_cwd": p.get("old_cwd").cloned().unwrap_or(Value::Null),
                "new_cwd": p.get("new_cwd").cloned().unwrap_or(Value::Null),
            }),
        })],
        // The payload is flat, not a nested `task` object, and carries no
        // `status` — the status is the hook name. `teammate_name`/`team_name`
        // are who the task was handed to.
        "TaskCreated" | "TaskCompleted" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({
                "task_id": p.get("task_id").cloned().unwrap_or(Value::Null),
                "task_subject": p.get("task_subject").cloned().unwrap_or(Value::Null),
                "task_description": p.get("task_description").cloned().unwrap_or(Value::Null),
                "teammate_name": p.get("teammate_name").cloned().unwrap_or(Value::Null),
                "team_name": p.get("team_name").cloned().unwrap_or(Value::Null),
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
            env_overrides: Vec::new(),
            cloud_identity: Default::default(),
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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
        let EventKind::ToolUse {
            fqdns, endpoints, ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert!(fqdns.contains(&"evil.example.com".to_string()));
        assert!(fqdns.contains(&"cdn.foo.io".to_string()));
        // The adapter has to carry both halves out of the extractor; keeping
        // only `fqdns` loses the scheme silently, and nothing else here would
        // notice.
        assert!(endpoints.contains(&"https://evil.example.com".to_string()));
        assert!(endpoints.contains(&"http://cdn.foo.io".to_string()));

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

    /// A fetch that was redirected reached a host the input never named, and
    /// the input is the only place anything looked before now.
    #[test]
    fn a_result_names_the_host_the_request_did_not() {
        let payload = json!({
            "hook_event_name": "PostToolUse", "tool_name": "WebFetch",
            "tool_input": {"url": "https://docs.example.com/guide"},
            "tool_response": {
                "finalUrl": "https://cdn.exfil.example.net:8443/guide",
                "text": "see also https://docs.example.com/guide",
            }
        });
        let events = adapters::parse(env(payload.clone()), &CaptureCfg::default());
        let EventKind::ToolUse {
            fqdns,
            output_fqdns,
            output_endpoints,
            ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!(fqdns, &vec!["docs.example.com".to_string()]);
        assert_eq!(
            output_fqdns,
            &vec!["cdn.exfil.example.net".to_string()],
            "the redirect target is the finding, and the echoed request is not"
        );
        assert_eq!(
            output_endpoints,
            &vec!["https://cdn.exfil.example.net:8443".to_string()]
        );

        // Switching off output capture is a decision about storing text. Which
        // hosts a call reached is metadata, and it survives — the same rule
        // `capture.tool_inputs` has always followed for `files` and `fqdns`.
        let capture = CaptureCfg {
            tool_outputs: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(env(payload), &capture);
        let EventKind::ToolUse {
            output,
            output_fqdns,
            ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert!(output.is_null(), "the payload was stored anyway");
        assert_eq!(output_fqdns, &vec!["cdn.exfil.example.net".to_string()]);
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

    /// `args` and `description` are tool input under another name, and a
    /// deployment that turned `tool_inputs` off does not stop meaning it
    /// because the field is spelled differently. The skill and agent names
    /// are the record of what ran and survive either way.
    #[test]
    fn skill_args_and_agent_descriptions_respect_the_tool_input_flag() {
        let cfg = CaptureCfg {
            tool_inputs: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "Skill",
                "tool_input": {"skill": "deploy", "args": "--token=abcdefgh12345678"}
            })),
            &cfg,
        );
        let skill = events
            .iter()
            .find_map(|e| match &e.kind {
                EventKind::Skill { name, args } => Some((name, args)),
                _ => None,
            })
            .expect("a skill event");
        assert_eq!(skill.0, "deploy", "the skill name is metadata, not content");
        assert_eq!(skill.1.as_deref(), None, "args shipped: {:?}", skill.1);

        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "Task",
                "tool_input": {"subagent_type": "Explore", "description": "creds are in vault X"}
            })),
            &cfg,
        );
        let agent = events
            .iter()
            .find_map(|e| match &e.kind {
                EventKind::Agent {
                    agent_type,
                    description,
                } => Some((agent_type, description)),
                _ => None,
            })
            .expect("an agent event");
        assert_eq!(agent.0, "Explore", "the agent type is metadata");
        assert_eq!(
            agent.1.as_deref(),
            None,
            "description shipped: {:?}",
            agent.1
        );
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

        // A turn that ended with no assistant text must not produce an empty
        // message event: a blank row reads as "the model said nothing", which
        // is a claim, where no row at all is the absence of one.
        let events = adapters::parse(
            env(json!({"hook_event_name": "Stop", "last_assistant_message": ""})),
            &CaptureCfg::default(),
        );
        assert_eq!(events.len(), 1, "{:?}", events);
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
            ..
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
                json!({"hook_event_name": "StopFailure", "error": "rate_limit",
                       "error_details": "429"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::Error { context, .. } if context == "rate_limit"));

        let events = adapters::parse(
            env(
                json!({"hook_event_name": "ConfigChange", "source": "user_settings",
                       "file_path": "/h/.claude/settings.json"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::FileChange { action, .. } if action == "config_changed:user_settings"));

        let events = adapters::parse(
            env(
                json!({"hook_event_name": "InstructionsLoaded", "file_path": "/r/CLAUDE.md",
                       "memory_type": "Project"}),
            ),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::FileChange { path, action }
                if path == "/r/CLAUDE.md" && action == "instructions_loaded:Project"));

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
        let EventKind::ToolUse { input, output, .. } = &events[0].kind else {
            panic!()
        };
        let stdout = output["stdout"].as_str().expect("stdout survives the cap");
        assert!(stdout.contains("…[truncated]…"), "not capped: {stdout}");
        // Parsing caps to `max + REDACTION_HEADROOM`; `enrich` cuts it to `max`
        // once the redactor has had whole tokens to look at.
        assert!(
            stdout.len() < 64 + adapters::REDACTION_HEADROOM + 32,
            "cap not applied: {}",
            stdout.len()
        );
        assert_eq!(
            input["command"], "ls",
            "an oversized output cost the input that produced it"
        );
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

    /// Parse the committed fixture rather than an inline literal: a fixture is
    /// what a real recording overwrites, so a payload that renames a field
    /// fails here instead of silently emptying a column in production.
    fn from_fixture(name: &str) -> Vec<crate::event::Event> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/claude-code")
            .join(format!("{name}.json"));
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let envelope: Envelope = serde_json::from_str(&text).unwrap();
        adapters::parse(envelope, &CaptureCfg::default())
    }

    fn file_change(name: &str) -> (String, String) {
        let events = from_fixture(name);
        let EventKind::FileChange { path, action } = &events[0].kind else {
            panic!("{name} is not a FileChange: {:?}", events[0].kind)
        };
        (path.clone(), action.clone())
    }

    /// The payload calls it `file_path`; reading `path` left every one of these
    /// with an empty path, which downstream is indistinguishable from a hook
    /// that never fired.
    #[test]
    fn instructions_loaded_carries_its_file_and_tier() {
        let (path, action) = file_change("InstructionsLoaded");
        assert_eq!(path, "/Users/dev/project/CLAUDE.md");
        // The tier is the finding: Managed is administrator-controlled, Local
        // is not.
        assert_eq!(action, "instructions_loaded:Project");
    }

    #[test]
    fn a_config_change_carries_the_file_that_changed() {
        let (path, action) = file_change("ConfigChange");
        assert_eq!(path, "/Users/dev/project/.claude/settings.json");
        assert_eq!(action, "config_changed:projectSettings");
    }

    /// Both fields are in the payloads the shipped binary builds —
    /// `{hook_event_name: "Notification", message, title, notification_type}`
    /// and `{hook_event_name: "PreCompact", trigger, custom_instructions}` —
    /// and both were being read past. The compaction one matters most: it is
    /// the moment the session's own history is rewritten, and after the
    /// rewrite the request to drop something is the only record that it was
    /// ever there.
    #[test]
    fn a_notification_keeps_its_title_and_a_compaction_its_instructions() {
        let EventKind::Notification { title, .. } = &from_fixture("Notification")[0].kind else {
            panic!()
        };
        assert_eq!(title.as_deref(), Some("Permission required"));

        let events = adapters::parse(
            env(json!({"hook_event_name": "PreCompact", "trigger": "manual",
                       "custom_instructions": "leave out the token I pasted"})),
            &CaptureCfg::default(),
        );
        let EventKind::Compact { instructions, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(
            instructions.as_deref(),
            Some("leave out the token I pasted")
        );

        // The binary's own schema says `custom_instructions` is nullable, and
        // the automatic path sends `""`. Neither is somebody asking for
        // something, and `Some("")` downstream reads as if it were.
        let EventKind::Compact { instructions, .. } = &from_fixture("PreCompact")[0].kind else {
            panic!()
        };
        assert_eq!(*instructions, None);
    }

    /// `error` is the enum variant and `error_details` the prose. Swapped, the
    /// context was always "unknown" and the message always empty.
    #[test]
    fn a_stop_failure_separates_the_error_type_from_its_prose() {
        let events = from_fixture("StopFailure");
        let EventKind::Error {
            message, context, ..
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(context, "rate_limit");
        assert_eq!(message, "429 from the API after 3 retries");
    }

    /// The payload is flat and carries no `status`; the hook name is the status.
    #[test]
    fn a_task_event_carries_the_flat_task_fields() {
        for hook in ["TaskCreated", "TaskCompleted"] {
            let events = from_fixture(hook);
            let EventKind::Session { action, detail } = &events[0].kind else {
                panic!("{hook}: {:?}", events[0].kind)
            };
            assert_eq!(action, hook);
            assert_eq!(detail["task_id"], "task-42");
            assert_eq!(
                detail["task_subject"],
                "Add a regression test for the retry path"
            );
            assert_eq!(
                detail["task_description"],
                "Cover the 503 case in export_once."
            );
            assert_eq!(detail["teammate_name"], "reviewer");
            assert_eq!(detail["team_name"], "argus");
        }
    }

    /// The point of the id is that both legs of one call carry the *same* one.
    /// An id present on only one leg pairs nothing, so assert the pairing, not
    /// the presence.
    #[test]
    fn both_legs_of_one_tool_call_carry_the_same_id() {
        let pre = from_fixture("PreToolUse");
        let post = from_fixture("PostToolUse");
        assert_eq!(
            pre[0].meta.tool_use_id.as_deref(),
            Some("toolu_01AbCdEfGhIjKlMnOpQrStUv")
        );
        assert_eq!(pre[0].meta.tool_use_id, post[0].meta.tool_use_id);
    }

    /// A turn that ended in an error still says what the model had got to; that
    /// half-finished message is what says what the turn was trying to do.
    #[test]
    fn a_failed_turn_still_reports_its_last_assistant_message() {
        let events = from_fixture("StopFailure");
        assert!(matches!(&events[0].kind, EventKind::Error { .. }));
        assert!(
            matches!(&events[1].kind,
                EventKind::AssistantMessage { text } if text == "Retrying the request."),
            "{:?}",
            events.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );

        // And it is the same flag that gates it on the success path — a third
        // caller that forgot would leak content the operator switched off.
        let off = CaptureCfg {
            assistant_messages: false,
            ..CaptureCfg::default()
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/claude-code/StopFailure.json");
        let envelope: Envelope =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(adapters::parse(envelope, &off).len(), 1);
    }

    /// A duration exists only once the call has run, and an interruption is a
    /// human stopping the call rather than the call going wrong — so the two
    /// failure legs must not read alike.
    #[test]
    fn a_finished_call_carries_its_duration_and_says_who_ended_it() {
        let dur = |events: &[crate::event::Event]| match &events[0].kind {
            EventKind::ToolUse {
                duration_ms,
                interrupted,
                ..
            } => (*duration_ms, *interrupted),
            other => panic!("{other:?}"),
        };
        assert_eq!(dur(&from_fixture("PreToolUse")), (None, false));
        assert_eq!(dur(&from_fixture("PostToolUse")), (Some(1843), false));
        assert_eq!(dur(&from_fixture("PostToolUseFailure")), (Some(12), false));

        let cancelled = adapters::parse(
            env(
                json!({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                       "tool_input": {"command": "sleep 600"},
                       "error": "interrupted", "is_interrupt": true, "duration_ms": 4000}),
            ),
            &CaptureCfg::default(),
        );
        assert_eq!(dur(&cancelled), (Some(4000), true));
    }

    /// `effort` arrives as an object; `Meta` holds the level.
    #[test]
    fn the_effort_level_is_lifted_out_of_its_object() {
        assert_eq!(
            from_fixture("PreToolUse")[0].meta.effort.as_deref(),
            Some("high")
        );
        // An `effort` that is not the expected shape must not become a level.
        let events = adapters::parse(
            env(json!({"hook_event_name": "SessionStart", "effort": "high"})),
            &CaptureCfg::default(),
        );
        assert_eq!(events[0].meta.effort, None);
    }

    /// `/add-dir` widens the tree the agent may reach, so it has to arrive as a
    /// scope change and say which mechanism widened it.
    #[test]
    fn adding_a_directory_records_the_path_and_who_added_it() {
        assert_eq!(
            file_change("DirectoryAdded"),
            (
                "/Users/dev/other-project".into(),
                "directory_added:slash_command".into()
            )
        );
    }

    /// The expanded text is the part `UserPromptSubmit` cannot show: the human
    /// typed `/deploy staging`, and this is what that became.
    #[test]
    fn a_slash_command_records_what_it_expanded_into() {
        let events = from_fixture("UserPromptExpansion");
        assert_eq!(events.len(), 1, "{events:?}");
        let EventKind::Session { action, detail } = &events[0].kind else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(action, "UserPromptExpansion");
        assert_eq!(detail["command_name"], json!("deploy"));
        assert_eq!(detail["command_args"], json!("staging"));
        assert_eq!(detail["expansion_type"], json!("slash_command"));
        // Which tier defined the command: a project-level one is repo-controlled.
        assert_eq!(detail["command_source"], json!("project"));
        assert!(
            detail["prompt"].as_str().unwrap().contains("staging"),
            "{detail}"
        );

        // The expansion body is prompt text, so the prompt switch has to reach
        // it — capturing it here would otherwise be a hole in a flag people
        // turn off precisely to keep prompt text off disk.
        let off = CaptureCfg {
            prompts: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(
            env(json!({"hook_event_name": "UserPromptExpansion",
                       "command_name": "deploy", "prompt": "secret expansion"})),
            &off,
        );
        let EventKind::Session { detail, .. } = &events[0].kind else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(detail["prompt"], json!("[not captured]"));
    }

    /// The batch is worth recording for the grouping alone; its calls' inputs
    /// and outputs already arrived on their own `PostToolUse` events, and
    /// carrying them twice would spend the buffer's byte cap on a copy.
    #[test]
    fn a_tool_batch_records_the_grouping_and_not_a_second_copy_of_it() {
        let events = from_fixture("PostToolBatch");
        assert_eq!(events.len(), 1, "{events:?}");
        let EventKind::Session { action, detail } = &events[0].kind else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(action, "PostToolBatch");
        assert_eq!(
            detail["tool_calls"],
            json!([
                {"tool_name": "Read", "tool_use_id": "toolu_03BatchRead"},
                {"tool_name": "Bash", "tool_use_id": "toolu_04BatchBash"},
            ])
        );
        let text = serde_json::to_string(detail).unwrap();
        assert!(!text.contains("api.example.com"), "{text}");
        assert!(!text.contains("numLines"), "{text}");
    }
}
