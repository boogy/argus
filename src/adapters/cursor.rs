//! Cursor adapter. Cursor sends one JSON payload on stdin for each hook. The
//! payload has `hook_event_name` and snake_case fields. The same `hooks.json`
//! applies to the IDE agent and to the `agent` CLI.
//!
//! Field names come from <https://cursor.com/docs/agent/hooks>. A
//! `sessionStart` from Cursor.app confirmed the common fields.
use crate::adapters::{
    cap_text, cap_value, extract_files_for_tool, extract_net_for_tool, extract_net_from_output,
};
use crate::aiid::AiIdentity;
use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind, Meta};
use serde_json::{Value, json};

fn s(p: &Value, k: &str) -> Option<String> {
    p.get(k).and_then(Value::as_str).map(String::from)
}

/// The value of `k`, or null. For the `detail` of a session event.
fn v(p: &Value, k: &str) -> Value {
    p.get(k).cloned().unwrap_or(Value::Null)
}

pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let p = &env.payload;
    let hook = p
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    // `conversation_id` is on every agent event. `session_id` is only on
    // `sessionStart` and `sessionEnd`, and it has the same value.
    let session_id = s(p, "conversation_id").or_else(|| s(p, "session_id"));
    // The Agents window can run without a repository. Then `workspace_roots`
    // is empty and the event has no `cwd`.
    let cwd = s(p, "cwd").or_else(|| {
        p.pointer("/workspace_roots/0")
            .and_then(Value::as_str)
            .map(String::from)
    });
    let meta = Meta {
        turn_id: s(p, "generation_id"),
        agent_id: s(p, "subagent_id"),
        agent_type: s(p, "subagent_type"),
        model: s(p, "model"),
        transcript_path: s(p, "transcript_path"),
        tool_use_id: s(p, "tool_use_id"),
        mcp_server: s(p, "mcp_server_name"),
        // Cursor puts the login in each payload. Only a session start records
        // it, as for the other tools.
        ai_identity: if capture.ai_identity && hook == "sessionStart" {
            AiIdentity {
                email: s(p, "user_email").filter(|e| !e.is_empty()),
                ..Default::default()
            }
        } else {
            AiIdentity::default()
        },
        ..Meta::default()
    };
    let mk = |kind| {
        let mut e = Event::new("cursor", session_id.clone(), cwd.clone(), kind);
        e.meta = meta.clone();
        e
    };
    let max = capture.max_field_bytes;

    match hook {
        "beforeSubmitPrompt" => {
            let text = if capture.prompts {
                cap_text(p.get("prompt").and_then(Value::as_str).unwrap_or(""), max)
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "preToolUse" | "postToolUse" | "postToolUseFailure" => {
            let tool = s(p, "tool_name").unwrap_or_else(|| "unknown".into());
            let args = v(p, "tool_input");
            let files = extract_files_for_tool(&tool, &args);
            let net = extract_net_for_tool(&tool, &args);
            let raw_output = v(p, "tool_output");
            let out_net = extract_net_from_output(&raw_output).minus(&net);
            let output = if hook == "postToolUse" && capture.tool_outputs {
                cap_value(raw_output, max)
            } else {
                Value::Null
            };
            vec![mk(EventKind::ToolUse {
                tool,
                phase: match hook {
                    "preToolUse" => "pre",
                    "postToolUse" => "post",
                    _ => "error",
                }
                .into(),
                input: if capture.tool_inputs {
                    cap_value(args, max)
                } else {
                    Value::Null
                },
                output,
                error: s(p, "error_message").map(|e| cap_text(&e, max)),
                duration_ms: p.get("duration").and_then(Value::as_u64),
                interrupted: p.get("is_interrupt").and_then(Value::as_bool) == Some(true),
                files,
                fqdns: net.fqdns,
                endpoints: net.endpoints,
                output_fqdns: out_net.fqdns,
                output_endpoints: out_net.endpoints,
                file_contents: vec![],
            })]
        }
        "afterFileEdit" => match s(p, "file_path") {
            Some(path) => vec![mk(EventKind::FileChange {
                path,
                action: "edited".into(),
            })],
            None => vec![mk(EventKind::Raw { payload: p.clone() })],
        },
        "afterAgentResponse" => {
            let text = p.get("text").and_then(Value::as_str).unwrap_or("");
            if !capture.assistant_messages || text.is_empty() {
                return Vec::new();
            }
            vec![mk(EventKind::AssistantMessage {
                text: cap_text(text, max),
            })]
        }
        "preCompact" => vec![mk(EventKind::Compact {
            phase: "pre".into(),
            trigger: s(p, "trigger").unwrap_or_else(|| "unknown".into()),
            tokens_before: p.get("context_tokens").and_then(Value::as_u64),
            tokens_after: None,
            instructions: None,
        })],
        "sessionStart" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({
                "composer_mode": v(p, "composer_mode"),
                "is_background_agent": v(p, "is_background_agent"),
            }),
        })],
        "sessionEnd" => vec![mk(EventKind::Session {
            action: hook.into(),
            detail: json!({
                "reason": v(p, "reason"),
                "final_status": v(p, "final_status"),
                "duration_ms": v(p, "duration_ms"),
            }),
        })],
        "stop" => {
            let mut events = vec![mk(EventKind::Session {
                action: hook.into(),
                detail: json!({ "status": v(p, "status"), "loop_count": v(p, "loop_count") }),
            })];
            // The IDE puts the token counts of the turn on `stop`. The CLI
            // sends no `stop`. `afterAgentResponse` has the same counts, but
            // `capture.assistant_messages` can drop that event.
            if p.get("input_tokens").is_some() {
                let n = |k: &str| p.get(k).and_then(Value::as_u64).unwrap_or(0);
                events.push(mk(EventKind::Usage {
                    input_tokens: n("input_tokens"),
                    output_tokens: n("output_tokens"),
                    reasoning_tokens: 0,
                    cache_read_tokens: n("cache_read_tokens"),
                    cache_write_tokens: n("cache_write_tokens"),
                    cost: 0.0,
                    finish: s(p, "status"),
                }));
            }
            events
        }
        "subagentStart" => vec![mk(EventKind::Session {
            action: hook.into(),
            // The task is the only record of the work the subagent got.
            detail: json!({
                "task": s(p, "task").map(|t| cap_text(&t, max)),
                "subagent_model": v(p, "subagent_model"),
            }),
        })],
        "subagentStop" => {
            let mut events = vec![mk(EventKind::Session {
                action: hook.into(),
                detail: json!({
                    "status": v(p, "status"),
                    "duration_ms": v(p, "duration_ms"),
                    "tool_call_count": v(p, "tool_call_count"),
                }),
            })];
            if capture.assistant_messages
                && let Some(text) = s(p, "summary").filter(|t| !t.is_empty())
            {
                events.push(mk(EventKind::AssistantMessage {
                    text: cap_text(&text, max),
                }));
            }
            events
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::{Value, json};

    fn env(payload: Value) -> Envelope {
        Envelope {
            ai_env: Default::default(),
            env_overrides: Vec::new(),
            cloud_identity: Default::default(),
            source: "cursor".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload,
        }
    }

    fn common(event: &str) -> Value {
        json!({
            "hook_event_name": event,
            "conversation_id": "c-1",
            "generation_id": "g-1",
            "model": "auto",
            "cursor_version": "3.0.0",
            "workspace_roots": ["/repo"],
            "user_email": "john.doe@example.com",
            "transcript_path": null,
        })
    }

    fn with(event: &str, extra: Value) -> Value {
        let mut p = common(event);
        for (k, x) in extra.as_object().unwrap() {
            p[k] = x.clone();
        }
        p
    }

    #[test]
    fn session_start_records_the_login_and_the_conversation() {
        let events = adapters::parse(
            env(with(
                "sessionStart",
                json!({"session_id": "c-1", "composer_mode": "agent"}),
            )),
            &CaptureCfg::default(),
        );
        let e = &events[0];
        assert_eq!(e.source, "cursor");
        assert_eq!(e.session_id.as_deref(), Some("c-1"));
        assert_eq!(e.cwd.as_deref(), Some("/repo"));
        assert_eq!(e.meta.turn_id.as_deref(), Some("g-1"));
        assert_eq!(
            e.meta.ai_identity.email.as_deref(),
            Some("john.doe@example.com")
        );
        assert!(matches!(&e.kind, EventKind::Session { action, .. } if action == "sessionStart"));

        // Off means off, and other events never carry the login.
        let off = CaptureCfg {
            ai_identity: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(env(common("sessionStart")), &off);
        assert_eq!(events[0].meta.ai_identity.email, None);
        let events = adapters::parse(env(common("stop")), &CaptureCfg::default());
        assert_eq!(events[0].meta.ai_identity.email, None);
    }

    #[test]
    fn stop_records_the_token_counts_of_the_turn() {
        let p = with(
            "stop",
            json!({"status": "completed", "input_tokens": 1200, "output_tokens": 300,
                   "cache_read_tokens": 800, "cache_write_tokens": 0}),
        );
        let events = adapters::parse(env(p), &CaptureCfg::default());
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[1].kind,
            EventKind::Usage { input_tokens: 1200, output_tokens: 300, cache_read_tokens: 800,
                               cache_write_tokens: 0, finish: Some(f), .. } if f == "completed"
        ));
        // The CLI has no counts. Then `stop` gives only the session event.
        let events = adapters::parse(env(common("stop")), &CaptureCfg::default());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn an_empty_workspace_gives_no_cwd() {
        let mut p = common("stop");
        p["workspace_roots"] = json!([]);
        let events = adapters::parse(env(p), &CaptureCfg::default());
        assert_eq!(events[0].cwd, None);
    }

    #[test]
    fn prompt_obeys_capture_prompts() {
        let p = with("beforeSubmitPrompt", json!({"prompt": "add tests"}));
        let events = adapters::parse(env(p.clone()), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "add tests"));
        let off = CaptureCfg {
            prompts: false,
            ..CaptureCfg::default()
        };
        let events = adapters::parse(env(p), &off);
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "[not captured]"));
    }

    #[test]
    fn tool_events_map_each_phase() {
        let input = json!({"command": "curl https://api.example.com/x", "cwd": "/repo"});
        let pre = with(
            "preToolUse",
            json!({"tool_name": "Shell", "tool_input": input, "tool_use_id": "t-1", "cwd": "/repo/sub"}),
        );
        let events = adapters::parse(env(pre), &CaptureCfg::default());
        let e = &events[0];
        assert_eq!(e.cwd.as_deref(), Some("/repo/sub"));
        assert_eq!(e.meta.tool_use_id.as_deref(), Some("t-1"));
        let EventKind::ToolUse {
            tool, phase, fqdns, ..
        } = &e.kind
        else {
            panic!("{:?}", e.kind)
        };
        assert_eq!((tool.as_str(), phase.as_str()), ("Shell", "pre"));
        assert!(fqdns.iter().any(|f| f == "api.example.com"), "{fqdns:?}");

        let post = with(
            "postToolUse",
            json!({"tool_name": "Shell", "tool_input": input, "tool_output": "ok", "duration": 42}),
        );
        let events = adapters::parse(env(post), &CaptureCfg::default());
        assert!(matches!(&events[0].kind,
            EventKind::ToolUse { phase, output, duration_ms: Some(42), .. }
                if phase == "post" && output == "ok"));

        let fail = with(
            "postToolUseFailure",
            json!({"tool_name": "Shell", "tool_input": input,
                   "error_message": "exit 1", "is_interrupt": true}),
        );
        let events = adapters::parse(env(fail), &CaptureCfg::default());
        assert!(matches!(&events[0].kind,
            EventKind::ToolUse { phase, error: Some(err), interrupted: true, .. }
                if phase == "error" && err == "exit 1"));
    }

    #[test]
    fn file_edit_and_response() {
        let events = adapters::parse(
            env(with(
                "afterFileEdit",
                json!({"file_path": "/repo/a.rs", "edits": []}),
            )),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind,
            EventKind::FileChange { path, action } if path == "/repo/a.rs" && action == "edited"));

        let resp = with("afterAgentResponse", json!({"text": "Done."}));
        let events = adapters::parse(env(resp.clone()), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::AssistantMessage { text } if text == "Done."));
        let off = CaptureCfg {
            assistant_messages: false,
            ..CaptureCfg::default()
        };
        assert!(adapters::parse(env(resp), &off).is_empty());
    }

    #[test]
    fn subagent_stop_keeps_its_summary() {
        let p = with(
            "subagentStop",
            json!({"subagent_type": "explore", "status": "completed", "summary": "Found 3 files."}),
        );
        let events = adapters::parse(env(p), &CaptureCfg::default());
        assert_eq!(events[0].meta.agent_type.as_deref(), Some("explore"));
        assert!(matches!(&events[1].kind,
            EventKind::AssistantMessage { text } if text == "Found 3 files."));
    }

    #[test]
    fn an_unknown_event_is_kept_raw() {
        let events = adapters::parse(env(common("workspaceOpen")), &CaptureCfg::default());
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }
}
