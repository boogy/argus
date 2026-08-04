use crate::adapters::extract_fqdns;
use crate::config::{CaptureCfg, Config};
use crate::event::{Envelope, Event, EventKind};
use serde_json::{json, Value};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::Sender;

/// Parses either a flattened OTLP logRecord (`{"event_name": ..., "attributes": {...}}`)
/// or a raw Codex `notify` payload (top-level `{"type": "agent-turn-complete", ...}`,
/// delivered via `argus hook --source codex`).
pub fn parse(env: &Envelope, capture: &CaptureCfg) -> Vec<Event> {
    let p = &env.payload;
    // Codex's hooks system emits Claude-compatible payloads (hook_event_name,
    // snake_case fields, plus turn_id) — reuse the shared parser.
    if p.get("hook_event_name").is_some() {
        return crate::adapters::claude_code::parse_hook("codex", p, capture);
    }
    let attrs = p.get("attributes").cloned().unwrap_or(json!({}));
    let session_id = attrs
        .get("conversation.id")
        .and_then(Value::as_str)
        .map(String::from);
    let mk = |kind| Event::new("codex", session_id.clone(), None, kind);
    let name = p.get("event_name").and_then(Value::as_str).unwrap_or("");

    match name {
        "codex.user_prompt" => {
            let text = if capture.prompts {
                attrs
                    .get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or("[not exported by codex]")
                    .into()
            } else {
                "[not captured]".into()
            };
            vec![mk(EventKind::Prompt { text })]
        }
        "codex.tool_decision" | "codex.tool_result" => {
            let tool = attrs
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into();
            let text_blob = [attrs.get("command"), attrs.get("arguments")]
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            let phase = if name.ends_with("decision") {
                "pre"
            } else {
                "post"
            }
            .into();
            let input = if capture.tool_inputs {
                crate::adapters::cap_value(attrs.clone(), capture.max_field_bytes)
            } else {
                Value::Null
            };
            vec![mk(EventKind::ToolUse {
                tool,
                phase,
                input,
                output: Value::Null,
                error: None,
                files: vec![],
                fqdns: extract_fqdns(&text_blob),
            })]
        }
        "codex.conversation_starts" => vec![mk(EventKind::Session {
            action: "start".into(),
            detail: Value::Null,
        })],
        // Codex `notify` delivers raw JSON like {"type": "agent-turn-complete", ...}
        // (top-level, not wrapped in a "notify" key).
        _ if p.get("type").and_then(Value::as_str) == Some("agent-turn-complete") => {
            vec![mk(EventKind::Session {
                action: "turn-complete".into(),
                detail: Value::Null,
            })]
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

pub async fn bind_listener(cfg: Arc<RwLock<Config>>) -> anyhow::Result<TcpListener> {
    let addr = cfg.read().unwrap().codex.otlp_listen.clone();
    Ok(TcpListener::bind(addr).await?)
}

/// Codex OTLP/JSON receiver: minimal HTTP/1.1 server bound to
/// `codex.otlp_listen` (loopback by default) that accepts `POST /v1/logs`
/// and forwards parsed logRecords into `tx`. Never crashes the daemon: a
/// bind failure just disables the listener, and per-connection errors
/// (bad HTTP, oversized bodies, malformed JSON) are dropped silently.
pub async fn otlp_listener(cfg: Arc<RwLock<Config>>, tx: Sender<Envelope>) {
    match bind_listener(cfg).await {
        Ok(listener) => serve(listener, tx).await,
        Err(e) => tracing::warn!("codex otlp listener disabled: {e}"),
    }
}

const MAX_BODY_BYTES: usize = 10_000_000;

/// Minimal HTTP/1.1 server: enough for Codex's OTLP/JSON POSTs on localhost.
pub async fn serve(listener: TcpListener, tx: Sender<Envelope>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let tx = tx.clone();
        tokio::spawn(handle_conn(stream, tx));
    }
}

async fn handle_conn(stream: tokio::net::TcpStream, tx: Sender<Envelope>) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        handle_conn_inner(stream, tx),
    )
    .await;
}

async fn handle_conn_inner(mut stream: tokio::net::TcpStream, tx: Sender<Envelope>) {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    // Read until end of headers, then content-length worth of body.
    let (headers_end, content_length) = loop {
        let Ok(n) = stream.read(&mut tmp).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            let len = String::from_utf8_lossy(&buf[..pos])
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok())
                .unwrap_or(0);
            // Reject oversized/bogus Content-Length before any arithmetic
            // with it: an attacker-controlled huge value (e.g. usize::MAX)
            // would otherwise overflow `headers_end + content_length` or
            // panic slicing `buf`.
            if len > MAX_BODY_BYTES {
                return;
            }
            break (pos, len);
        }
        if buf.len() > MAX_BODY_BYTES {
            return;
        }
    };
    // content_length <= MAX_BODY_BYTES and headers_end <= MAX_BODY_BYTES
    // (enforced by the header-growth cap above), so this addition cannot
    // overflow usize.
    let body_end = headers_end + content_length;
    while buf.len() < body_end {
        let Ok(n) = stream.read(&mut tmp).await else {
            return;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if buf.len() < body_end {
        return;
    }
    let head = String::from_utf8_lossy(&buf[..headers_end]);
    let ok = head.starts_with("POST /v1/logs ") || head.starts_with("POST /v1/logs?");
    if ok {
        if let Ok(v) = serde_json::from_slice::<Value>(&buf[headers_end..body_end]) {
            for record in flatten_otlp_records(&v) {
                let _ = tx
                    .send(Envelope {
                        source: "codex".into(),
                        received_at: chrono::Utc::now(),
                        event: None,
                        payload: record,
                    })
                    .await;
            }
        }
    }
    let status = if ok { "200 OK" } else { "404 Not Found" };
    let _ = stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{{}}"
            )
            .as_bytes(),
        )
        .await;
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// OTLP JSON -> flat {"event_name", "attributes": {k: v}} records.
fn flatten_otlp_records(v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let records = v
        .pointer("/resourceLogs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|rl| rl.pointer("/scopeLogs").and_then(Value::as_array))
        .flatten()
        .filter_map(|sl| sl.pointer("/logRecords").and_then(Value::as_array))
        .flatten();
    for rec in records {
        let name = rec
            .get("eventName")
            .and_then(Value::as_str)
            .or_else(|| rec.pointer("/body/stringValue").and_then(Value::as_str))
            .unwrap_or("");
        let mut attrs = serde_json::Map::new();
        for a in rec
            .get("attributes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(k), Some(val)) = (a.get("key").and_then(Value::as_str), a.get("value"))
            else {
                continue;
            };
            let flat = val
                .get("stringValue")
                .cloned()
                .or_else(|| val.get("intValue").cloned())
                .or_else(|| val.get("boolValue").cloned())
                .unwrap_or(Value::Null);
            attrs.insert(k.to_string(), flat);
        }
        out.push(json!({"event_name": name, "attributes": attrs}));
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::adapters;
    use crate::config::CaptureCfg;
    use crate::event::{Envelope, EventKind};
    use serde_json::json;

    fn env(payload: serde_json::Value) -> Envelope {
        Envelope {
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            event: None,
            payload,
        }
    }

    #[test]
    fn codex_hook_payloads_parse_like_claude_shape() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "UserPromptSubmit", "session_id": "cx-h1",
                "turn_id": "t1", "cwd": "/repo", "model": "gpt-5-codex",
                "prompt": "fix the tests"
            })),
            &CaptureCfg::default(),
        );
        assert_eq!(events[0].source, "codex");
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "fix the tests"));
        assert_eq!(events[0].meta.turn_id.as_deref(), Some("t1"));
        assert_eq!(events[0].meta.model.as_deref(), Some("gpt-5-codex"));
    }

    #[test]
    fn codex_apply_patch_extracts_file_paths() {
        let events = adapters::parse(
            env(json!({
                "hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                "tool_input": {"input": "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n*** End Patch"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { files, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(files, &vec!["src/lib.rs".to_string()]);
    }

    #[test]
    fn codex_otlp_and_notify_paths_still_work() {
        // regression guard: shape (b) and (c) untouched
        let events = adapters::parse(
            env(json!({"event_name": "codex.user_prompt",
                       "attributes": {"conversation.id": "cx1", "prompt": "hello"}})),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Prompt { .. }));
        let events = adapters::parse(
            env(json!({"type": "agent-turn-complete"})),
            &CaptureCfg::default(),
        );
        assert!(
            matches!(&events[0].kind, EventKind::Session { action, .. } if action == "turn-complete")
        );
    }

    #[test]
    fn codex_user_prompt_maps_to_prompt() {
        let events = adapters::parse(
            env(json!({
                "event_name": "codex.user_prompt",
                "attributes": {"conversation.id": "cx1", "prompt": "write a script"}
            })),
            &CaptureCfg::default(),
        );
        assert!(matches!(&events[0].kind, EventKind::Prompt { text } if text == "write a script"));
        assert_eq!(events[0].session_id.as_deref(), Some("cx1"));
    }

    #[test]
    fn codex_tool_decision_maps_to_tool_use_with_fqdns() {
        let events = adapters::parse(
            env(json!({
                "event_name": "codex.tool_decision",
                "attributes": {"tool_name": "shell", "decision": "approved",
                               "command": "curl https://pypi.org/simple/requests"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { tool, fqdns, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(tool, "shell");
        assert_eq!(fqdns, &vec!["pypi.org".to_string()]);
    }

    #[test]
    fn codex_tool_result_maps_to_post_phase() {
        let events = adapters::parse(
            env(json!({
                "event_name": "codex.tool_result",
                "attributes": {"tool_name": "shell", "command": "echo hi"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "post");
    }

    #[test]
    fn agent_turn_complete_maps_to_session_turn_complete() {
        let events = adapters::parse(
            env(json!({"type": "agent-turn-complete"})),
            &CaptureCfg::default(),
        );
        assert!(
            matches!(&events[0].kind, EventKind::Session { action, .. } if action == "turn-complete")
        );
    }

    #[tokio::test]
    async fn oversized_content_length_does_not_panic_and_listener_survives() {
        let cfg = std::sync::Arc::new(std::sync::RwLock::new(crate::config::Config::default()));
        cfg.write().unwrap().codex.otlp_listen = "127.0.0.1:0".into();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx));
        // hostile request: absurd Content-Length, no body
        {
            use tokio::io::AsyncWriteExt;
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(b"POST /v1/logs HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n")
                .await
                .unwrap();
            let _ = s.shutdown().await;
        }
        // listener must still answer a subsequent well-formed request
        let body = serde_json::json!({"resourceLogs":[{"scopeLogs":[{"logRecords":[{"eventName":"codex.conversation_starts","attributes":[]}]}]}]});
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logs"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "listener survived hostile request"
        );
    }

    #[tokio::test]
    async fn wrong_path_returns_404() {
        let cfg = std::sync::Arc::new(std::sync::RwLock::new(crate::config::Config::default()));
        cfg.write().unwrap().codex.otlp_listen = "127.0.0.1:0".into();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx));
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logsXXX"))
            .body("x")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404);
    }

    #[tokio::test]
    async fn otlp_listener_accepts_json_logs_and_forwards_envelopes() {
        let cfg = std::sync::Arc::new(std::sync::RwLock::new(crate::config::Config::default()));
        cfg.write().unwrap().codex.otlp_listen = "127.0.0.1:0".into();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx));

        let body = json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
            "eventName": "codex.user_prompt",
            "attributes": [{"key": "prompt", "value": {"stringValue": "hello"}}]
        }]}]}]});
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logs"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        let envelope = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(envelope.source, "codex");
        assert_eq!(envelope.payload["event_name"], "codex.user_prompt");
        assert_eq!(envelope.payload["attributes"]["prompt"], "hello");
    }
}
