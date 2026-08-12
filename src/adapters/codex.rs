use crate::config::{CaptureCfg, Config};
use crate::event::{Envelope, Event, EventKind};
use crate::ipc::Ingress;
use serde_json::{Value, json};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The first of several spellings of one OTLP attribute.
///
/// A present-but-empty attribute is not an answer, so it does not stop the
/// search: a build that sends `call_id: ""` alongside a filled `tool_call_id`
/// has a call id, and stopping at the empty one would report that it has none.
fn attr_str(attrs: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| {
            attrs
                .get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .map(String::from)
}

/// An OTLP attribute that is a number, whether or not it arrived as one.
///
/// Attribute values are scalars of a declared type, and which type a producer
/// declares for a duration is not something a consumer gets to rely on —
/// Codex's own stream sends `success` as the string `"true"`. Reading only
/// `as_u64` would drop the field on the builds that send `"8123"`, and a
/// dropped duration is indistinguishable from a tool that reported none.
fn attr_u64(attrs: &Value, key: &str) -> Option<u64> {
    let v = attrs.get(key)?;
    v.as_u64()
        .or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
        .or_else(|| v.as_str()?.trim().parse().ok())
}

/// An OTLP attribute that is a boolean, whether or not it arrived as one.
fn attr_bool(attrs: &Value, key: &str) -> Option<bool> {
    let v = attrs.get(key)?;
    v.as_bool().or_else(|| match v.as_str()?.trim() {
        "true" | "True" | "1" => Some(true),
        "false" | "False" | "0" => Some(false),
        _ => None,
    })
}

/// Three payload shapes reach this, from three different transports: a
/// Claude-shaped hook payload (`hook_event_name`), which is handed straight to
/// the shared parser; a flattened OTLP logRecord
/// (`{"event_name": ..., "attributes": {...}}`) from the receiver below; and a
/// raw Codex `notify` payload (top-level `{"type": "agent-turn-complete", ...}`,
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
    // The ids Codex's OTLP stream carries, under whichever spelling this
    // build uses. A call id is what pairs a decision with its result: two
    // `shell` calls in a turn are otherwise indistinguishable, so a `pre`
    // that never got its `post` — a call that hung, or was killed — reads
    // exactly like one that completed. Reading several spellings rather than
    // one is not guesswork: they are names for the same field, and the cost
    // of a spelling this build does not send is `None`, which is what the
    // field held before.
    let meta = crate::event::Meta {
        tool_use_id: attr_str(
            &attrs,
            &["call_id", "tool_call_id", "call.id", "tool.call_id"],
        ),
        turn_id: attr_str(&attrs, &["turn_id", "turn.id"]),
        model: attr_str(&attrs, &["model", "gen_ai.request.model"]),
        ..Default::default()
    };
    let mk = |kind| {
        let mut e = Event::new("codex", session_id.clone(), None, kind);
        e.meta = meta.clone();
        e
    };
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
                .to_string();
            // OTLP attribute values are scalars, so a tool's arguments arrive
            // as a *string* holding JSON. Parsed back, because everything that
            // reads a tool input — path keys, nested `command` arrays — reads
            // structure, and a call whose arguments stayed a string is a call
            // whose file was never named.
            let args = attrs
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .or_else(|| attrs.get("arguments").cloned())
                .unwrap_or(Value::Null);
            // Kept as the two fields rather than one joined blob: `command` is
            // a shell command, which is read as one — a `curl example.com`
            // there names a host no URL scan would see — while `arguments` is
            // a tool's own JSON, where only a stated protocol counts.
            let blob_net = crate::adapters::extract_net_for_tool(
                &tool,
                &serde_json::json!({
                    "command": attrs.get("command").cloned().unwrap_or(Value::Null),
                    "arguments": args.clone(),
                }),
            );
            let mut files = crate::adapters::extract_files_for_tool(&tool, &attrs);
            files.extend(crate::adapters::extract_files_for_tool(&tool, &args));
            // Patch headers are read whatever the tool is called, unlike in
            // the shared extractor, which gates them on the name. Codex
            // applies patches two ways — the `apply_patch` tool, and a `shell`
            // call with the patch on stdin — and the second is the one that
            // rewrites files while naming none. `*** Update File:` at the head
            // of a line is not a shape ordinary arguments take, so believing
            // it costs nothing that guessing at paths would.
            for s in [attrs.get("command"), attrs.get("arguments")]
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                files.extend(crate::adapters::extract_patch_files(s));
            }
            files.sort();
            files.dedup();
            // A result that reports `success = false` is the error leg, the
            // same as a non-zero hook payload. Without this the only record of
            // a failed Codex tool call is an attribute inside `input`, where
            // no "what failed" query looks.
            let failed = attr_bool(&attrs, "success") == Some(false);
            let phase = match (name.ends_with("decision"), failed) {
                (true, _) => "pre",
                (false, false) => "post",
                (false, true) => "error",
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
                // `codex.tool_result` reports `success` and `duration_ms` and
                // no result text, so this leg has nothing to read hosts out
                // of. Codex's hook payloads do carry one, and they leave for
                // the shared parser several lines above, which scans it.
                output_fqdns: vec![],
                output_endpoints: vec![],
                error: None,
                // `codex.tool_result` reports how long the call took, and a
                // duration the tool measured beats one subtracted from two
                // timestamps stamped on either side of a socket. Nothing here
                // reports an interruption.
                duration_ms: attr_u64(&attrs, "duration_ms"),
                interrupted: false,
                files,
                fqdns: blob_net.fqdns,
                endpoints: blob_net.endpoints,
                file_contents: vec![],
            })]
        }
        "codex.conversation_starts" => vec![mk(EventKind::Session {
            action: "start".into(),
            detail: Value::Null,
        })],
        // Codex `notify` delivers raw JSON like {"type": "agent-turn-complete", ...}
        // (top-level, not wrapped in a "notify" key).
        _ if p.get("type").and_then(Value::as_str) == Some("agent-turn-complete") => {
            let mut e = mk(EventKind::Session {
                action: "turn-complete".into(),
                detail: Value::Null,
            });
            // This payload spells it with a hyphen, and it is the id the hook
            // leg puts on every tool call of the turn — so the notification
            // that a turn ended joins the calls it ended.
            e.meta.turn_id = p
                .get("turn-id")
                .or_else(|| p.get("turn_id"))
                .and_then(Value::as_str)
                .map(String::from);
            vec![e]
        }
        _ => vec![mk(EventKind::Raw { payload: p.clone() })],
    }
}

pub async fn bind_listener(cfg: Arc<RwLock<Config>>) -> anyhow::Result<TcpListener> {
    let addr = cfg.read().unwrap().codex.otlp_listen.clone();
    Ok(TcpListener::bind(addr).await?)
}

/// The token if one has already been minted, without minting one.
///
/// Split out because `artifacts` is called by `install --dry-run`, by `check`
/// and by `uninstall`, none of which may write: a dry run that created this
/// file would be reporting what it *would* do while doing something.
pub fn existing_token() -> Option<String> {
    let token = std::fs::read_to_string(crate::paths::codex_token_path())
        .ok()?
        .trim()
        .to_string();
    (!token.is_empty()).then_some(token)
}

/// The secret Codex presents on every OTLP post, created on first use.
///
/// Loopback is not an authentication boundary. Any process on the machine,
/// under any account, can connect to `127.0.0.1` and post — so until this,
/// anything at all could write fabricated prompts and tool calls into the
/// audit trail, which is a poor property for the record of what the agents on
/// this machine did. The per-user port from T8e narrowed *who collides*, not
/// who can reach it: a listening port is not a secret, `lsof` lists it.
///
/// Read back rather than regenerated, because `install` copies this same value
/// into Codex's `[otel]` headers — rotating it on every daemon start would
/// leave every already-wired Codex talking to a receiver that now refuses it.
///
/// Two v4 UUIDs, so 244 random bits — 128 each, less the six that the version
/// and variant fields pin to fixed values. `uuid` is already in the tree, and
/// pulling in an RNG crate to reach a round 256 would be new supply chain for
/// a difference nothing can exploit.
pub fn shared_token() -> anyhow::Result<String> {
    if let Some(token) = existing_token() {
        return Ok(token);
    }
    let path = crate::paths::codex_token_path();
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    }
    // Opened `0600` rather than chmod'ed after: between a default-mode create
    // and the chmod there is a window in which the secret is on disk and
    // world-readable, and that window is the whole of what this file protects.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    {
        use std::io::Write;
        opts.open(&path)?.write_all(token.as_bytes())?;
    }
    Ok(token)
}

/// Codex OTLP/JSON receiver: minimal HTTP/1.1 server bound to
/// `codex.otlp_listen` (loopback by default) that accepts `POST /v1/logs`
/// and forwards parsed logRecords into `tx`. Never crashes the daemon: a
/// bind failure just disables the listener, and per-connection errors
/// (bad HTTP, oversized bodies, malformed JSON) are dropped silently.
pub async fn otlp_listener(cfg: Arc<RwLock<Config>>, tx: Ingress) {
    // Resolved before the bind, and fatal to the listener if it fails: a
    // receiver that cannot tell Codex from anything else on loopback is worse
    // than no receiver, because it still fills the trail and still looks
    // healthy in `status`.
    let token = match shared_token() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("codex otlp listener disabled: no receiver token: {e}");
            return;
        }
    };
    match bind_listener(cfg).await {
        Ok(listener) => serve(listener, tx, token).await,
        Err(e) => tracing::warn!("codex otlp listener disabled: {e}"),
    }
}

const MAX_BODY_BYTES: usize = 10_000_000;

/// Minimal HTTP/1.1 server: enough for Codex's OTLP/JSON POSTs on localhost.
pub async fn serve(listener: TcpListener, tx: Ingress, token: String) {
    let token: Arc<str> = token.into();
    let mut backoff = crate::ipc::AcceptBackoff::new();
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                backoff.reset();
                let tx = tx.clone();
                tokio::spawn(handle_conn(stream, tx, token.clone()));
            }
            // Same hazard as the hook socket's accept loop, and the same
            // reason it matters more here than the count of connections
            // suggests: this receiver and that socket share one process and
            // one descriptor table, so a spin on either starves both.
            Err(e) => backoff.wait("codex otlp receiver", &e.to_string()).await,
        }
    }
}

async fn handle_conn(stream: tokio::net::TcpStream, tx: Ingress, token: Arc<str>) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        handle_conn_inner(stream, tx, token),
    )
    .await;
}

async fn handle_conn_inner(mut stream: tokio::net::TcpStream, tx: Ingress, token: Arc<str>) {
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
    // `content_length` is at most MAX_BODY_BYTES, checked above, and
    // `headers_end` is within one 4 KiB read of it: the growth check runs on
    // every iteration that does not find the terminator. Both are therefore
    // around ten megabytes, so this addition cannot overflow usize.
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
    let addressed = head.starts_with("POST /v1/logs ") || head.starts_with("POST /v1/logs?");
    // Authenticated before parsed, so an unauthenticated caller cannot even
    // reach the JSON path: nothing is forwarded, and the body is not touched.
    let authenticated = bearer(&head).is_some_and(|t| same_secret(t, &token));
    if addressed && !authenticated {
        warn_once_about_rejections();
    }
    let ok = addressed && authenticated;
    if ok && let Ok(v) = serde_json::from_slice::<Value>(&buf[headers_end..body_end]) {
        for record in flatten_otlp_records(&v) {
            tx.send(Envelope {
                // Empty, and it cannot be otherwise: this arrived over HTTP
                // from Codex's own process, so the only environment reachable
                // here is the daemon's — whoever started the daemon, not the
                // agent. Codex's `notify` events run the shim and do carry an
                // identity; these are the same session seen from a channel
                // that cannot. Filling it in from `std::env` here would label
                // an agent's telemetry with a stranger's credentials.
                cloud_identity: Default::default(),
                source: "codex".into(),
                received_at: chrono::Utc::now(),
                truncated: false,
                dropped: 0,
                event: None,
                payload: record,
            })
            .await;
        }
    }
    // 404 for a path we do not serve, 401 for ours without the secret: saying
    // "not found" to a Codex whose token has gone stale would send whoever
    // debugs it looking for a routing problem that isn't there.
    let status = match (addressed, authenticated) {
        (true, true) => "200 OK",
        (true, false) => "401 Unauthorized",
        _ => "404 Not Found",
    };
    let _ = stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{{}}"
            )
            .as_bytes(),
        )
        .await;
}

/// The credential out of an `Authorization: Bearer <token>` request line.
///
/// Header names and the scheme are both case-insensitive per RFC 9110, and
/// reqwest, Codex and curl do not agree on how they spell either — matching
/// only the capitalisation we happen to write would reject a well-formed
/// client and look exactly like a wrong token.
fn bearer(head: &str) -> Option<&str> {
    let line = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))?;
    let value = line.split_once(':')?.1.trim();
    let (scheme, credential) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| credential.trim())
}

/// Compared without an early exit on the first differing byte.
///
/// The length is allowed to leak — it is fixed and public — but the bytes are
/// not: `==` on strings stops at the first mismatch, and over enough requests
/// that timing recovers the secret one byte at a time. The attacker here is
/// already local, which is precisely why they can measure it well.
fn same_secret(presented: &str, expected: &str) -> bool {
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Once per process: a rejected post means Codex is wired with a stale token
/// or none, which is a silent capture outage — but the same misconfiguration
/// repeats on every turn, and a per-request log would bury the daemon's own
/// output in it.
fn warn_once_about_rejections() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            "rejected an unauthenticated POST to the codex otlp receiver. If Codex \
             telemetry has stopped arriving, its config.toml carries a token this \
             install does not know; re-run `argus install`."
        );
    });
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
            cloud_identity: Default::default(),
            source: "codex".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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

    /// The OTLP leg named no file at all, so a Codex session's edits were
    /// invisible to every "what did this touch" query — and to file-content
    /// capture, which keys off the same list.
    #[test]
    fn codex_otlp_tool_calls_name_the_files_they_touch() {
        let files = |attrs: serde_json::Value| {
            let events = adapters::parse(
                env(json!({"event_name": "codex.tool_decision", "attributes": attrs})),
                &CaptureCfg::default(),
            );
            let EventKind::ToolUse { files, .. } = &events[0].kind else {
                panic!()
            };
            files.clone()
        };
        // The attribute map *is* this leg's tool input — it is what lands in
        // `input` — so a path key sitting in it names a file, on the same
        // terms as everywhere else.
        assert_eq!(
            files(json!({"tool_name": "read_file", "path": "/repo/src/d.rs"})),
            vec!["/repo/src/d.rs".to_string()]
        );
        // `arguments` is a string over OTLP, and the path is inside it.
        assert_eq!(
            files(json!({"tool_name": "read_file",
                         "arguments": r#"{"file_path": "/repo/src/a.rs"}"#})),
            vec!["/repo/src/a.rs".to_string()]
        );
        // The patch tool, named as such.
        assert_eq!(
            files(json!({"tool_name": "apply_patch",
                         "arguments": r#"{"input": "*** Begin Patch\n*** Update File: src/b.rs\n@@\n*** End Patch"}"#})),
            vec!["src/b.rs".to_string()]
        );
        // The same patch applied through the shell, which is the case the
        // tool-name gate in the shared extractor cannot see.
        assert_eq!(
            files(json!({"tool_name": "shell",
                         "command": "apply_patch <<'EOF'\n*** Add File: docs/c.md\nEOF"})),
            vec!["docs/c.md".to_string()]
        );
        // And a command that merely mentions paths still names none: `files`
        // is what a reviewer reads as "the tool opened this".
        assert!(files(json!({"tool_name": "shell", "command": "cat /etc/passwd"})).is_empty());
    }

    /// Parsing `arguments` back into JSON is what lets the nested `command`
    /// be read as a command rather than as prose — the schemeless host in it
    /// is invisible to a URL scan.
    #[test]
    fn a_command_nested_in_the_arguments_json_still_names_its_hosts() {
        let events = adapters::parse(
            env(json!({
                "event_name": "codex.tool_decision",
                "attributes": {"tool_name": "shell",
                               "arguments": r#"{"command": ["bash", "-lc", "curl mirror.example.org/x"]}"#}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { fqdns, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(fqdns, &vec!["mirror.example.org".to_string()]);
    }

    /// A Codex tool call over OTLP could be timed and paired by nothing: the
    /// duration the result *reports* was dropped, and the call id that says
    /// which decision this result belongs to was never read. Both were sitting
    /// in the attributes.
    #[test]
    fn a_codex_tool_result_carries_its_duration_and_the_call_it_belongs_to() {
        let events = adapters::parse(
            env(json!({
                "event_name": "codex.tool_result",
                "attributes": {"conversation.id": "cx1", "tool_name": "shell",
                               "call_id": "call-7", "turn_id": "turn-3",
                               "model": "gpt-5-codex", "command": "cargo build",
                               "duration_ms": 8123, "success": "true"}
            })),
            &CaptureCfg::default(),
        );
        assert_eq!(events[0].meta.tool_use_id.as_deref(), Some("call-7"));
        assert_eq!(events[0].meta.turn_id.as_deref(), Some("turn-3"));
        assert_eq!(events[0].meta.model.as_deref(), Some("gpt-5-codex"));
        let EventKind::ToolUse {
            phase, duration_ms, ..
        } = &events[0].kind
        else {
            panic!()
        };
        assert_eq!(phase, "post");
        assert_eq!(*duration_ms, Some(8123));

        // An attribute value is a scalar of whichever type the producer
        // declared, and Codex already sends one boolean as a string. A
        // fractional millisecond is a millisecond; a negative one is not a
        // duration, and a wrong number is worse than a missing one.
        for (value, want) in [
            (json!("250"), Some(250)),
            (json!(" 250 "), Some(250)),
            (json!(12.7), Some(12)),
            (json!(-5), None),
            (json!("soon"), None),
        ] {
            let events = adapters::parse(
                env(json!({
                    "event_name": "codex.tool_result",
                    "attributes": {"tool_name": "shell", "duration_ms": value,
                                   "call_id": "", "tool_call_id": "call-8",
                                   "gen_ai.request.model": "gpt-5"}
                })),
                &CaptureCfg::default(),
            );
            // An attribute that is present but empty is not an answer: the
            // filled spelling next to it is.
            assert_eq!(events[0].meta.tool_use_id.as_deref(), Some("call-8"));
            assert_eq!(events[0].meta.model.as_deref(), Some("gpt-5"));
            let EventKind::ToolUse { duration_ms, .. } = &events[0].kind else {
                panic!()
            };
            assert_eq!(*duration_ms, want, "duration_ms = {value}");
        }
    }

    /// A failed tool call is the one a reviewer looks for, and it used to be
    /// recorded as a successful one with an attribute buried in `input`.
    #[test]
    fn a_codex_tool_result_that_failed_is_the_error_leg() {
        // Whichever way this build spells a boolean. Anything that is not a
        // "no" leaves the result where it was: a `success` nobody can read is
        // not a failure.
        for (value, want) in [
            (json!("false"), "error"),
            (json!("False"), "error"),
            (json!("0"), "error"),
            (json!(false), "error"),
            (json!("true"), "post"),
            (json!("True"), "post"),
            (json!("1"), "post"),
            (json!(true), "post"),
            (json!("maybe"), "post"),
        ] {
            let events = adapters::parse(
                env(json!({
                    "event_name": "codex.tool_result",
                    "attributes": {"tool_name": "shell", "command": "cargo build",
                                   "success": value}
                })),
                &CaptureCfg::default(),
            );
            let EventKind::ToolUse { phase, .. } = &events[0].kind else {
                panic!()
            };
            assert_eq!(phase, want, "success = {value}");
        }
        // A decision is still a decision: nothing has failed yet.
        let events = adapters::parse(
            env(json!({
                "event_name": "codex.tool_decision",
                "attributes": {"tool_name": "shell", "success": "false"}
            })),
            &CaptureCfg::default(),
        );
        let EventKind::ToolUse { phase, .. } = &events[0].kind else {
            panic!()
        };
        assert_eq!(phase, "pre");
    }

    /// The turn-complete notification and the tool calls of that turn are the
    /// same turn, and the hyphen is the only thing that used to keep them
    /// apart.
    #[test]
    fn a_finished_turn_names_the_turn_that_finished() {
        for key in ["turn-id", "turn_id"] {
            let events = adapters::parse(
                env(json!({"type": "agent-turn-complete", key: "turn-42"})),
                &CaptureCfg::default(),
            );
            assert_eq!(events[0].meta.turn_id.as_deref(), Some("turn-42"), "{key}");
        }
        let events = adapters::parse(
            env(json!({"type": "agent-turn-complete"})),
            &CaptureCfg::default(),
        );
        assert_eq!(events[0].meta.turn_id, None);
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

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Returns the bound address and the receiving end, so each test says only
    /// what it is actually about.
    async fn receiver() -> (std::net::SocketAddr, crate::ipc::IngressRx) {
        let cfg = std::sync::Arc::new(std::sync::RwLock::new(crate::config::Config::default()));
        cfg.write().unwrap().codex.otlp_listen = "127.0.0.1:0".into();
        let (tx, rx) = crate::ipc::Ingress::with_limits(8, 1 << 20);
        let bound = super::bind_listener(cfg).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx, TOKEN.into()));
        (addr, rx)
    }

    fn logs() -> serde_json::Value {
        json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
            "eventName": "codex.user_prompt",
            "attributes": [{"key": "prompt", "value": {"stringValue": "forged"}}]
        }]}]}]})
    }

    /// The whole point. Loopback is reachable by every process and every
    /// account on the machine, so without this any of them could write
    /// prompts and tool calls into the audit trail of what the *agents* did —
    /// a security record its subject can author. Rejecting must also mean
    /// forwarding nothing: a 401 that still enqueued the body would be the
    /// same hole with a different status line.
    #[tokio::test]
    async fn an_unauthenticated_post_is_rejected_and_forwards_nothing() {
        let (addr, mut rx) = receiver().await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logs"))
            .json(&logs())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a rejected post still reached the pipeline"
        );
    }

    /// Presenting *a* bearer token is not presenting *the* one — the check has
    /// to compare the credential, not merely notice the header.
    #[tokio::test]
    async fn a_wrong_token_is_rejected() {
        let (addr, mut rx) = receiver().await;
        for wrong in [
            format!("Bearer {}", "f".repeat(TOKEN.len())),
            format!("Bearer {}", &TOKEN[..TOKEN.len() - 1]),
            format!("Bearer {TOKEN}extra"),
            "Bearer".into(),
            format!("Basic {TOKEN}"),
        ] {
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/v1/logs"))
                .header("authorization", &wrong)
                .json(&logs())
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 401, "accepted {wrong:?}");
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a rejected post still reached the pipeline"
        );
    }

    /// Both the header name and the scheme are case-insensitive per RFC 9110.
    /// Codex, curl and reqwest do not agree on how they spell either, so
    /// matching our own capitalisation would reject a correct client and be
    /// indistinguishable from a wrong token.
    #[tokio::test]
    async fn the_scheme_and_header_name_are_matched_case_insensitively() {
        let (addr, mut rx) = receiver().await;
        for header in ["AUTHORIZATION", "authorization"] {
            for scheme in ["Bearer", "bearer", "BEARER"] {
                let resp = reqwest::Client::new()
                    .post(format!("http://{addr}/v1/logs"))
                    .header(header, format!("{scheme} {TOKEN}"))
                    .json(&logs())
                    .send()
                    .await
                    .unwrap();
                assert!(
                    resp.status().is_success(),
                    "{header}: {scheme} was rejected"
                );
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
    }

    /// `install` copies the token into Codex's config once; a daemon that
    /// minted a fresh one per start would refuse the very client it wired.
    #[test]
    fn the_token_is_created_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let first = super::shared_token().unwrap();
        assert_eq!(first.len(), 64, "256 bits of secret, hex encoded");
        assert_eq!(super::shared_token().unwrap(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(crate::paths::codex_token_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the token is a bearer credential; anything else on the machine \
                 that can read it can post to the receiver"
            );
        }
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    #[tokio::test]
    async fn oversized_content_length_does_not_panic_and_listener_survives() {
        let cfg = std::sync::Arc::new(std::sync::RwLock::new(crate::config::Config::default()));
        cfg.write().unwrap().codex.otlp_listen = "127.0.0.1:0".into();
        let (tx, _rx) = crate::ipc::Ingress::with_limits(8, 1 << 20);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx, TOKEN.into()));
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
            .header("authorization", format!("Bearer {TOKEN}"))
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
        let (tx, _rx) = crate::ipc::Ingress::with_limits(8, 1 << 20);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx, TOKEN.into()));
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logsXXX"))
            .header("authorization", format!("Bearer {TOKEN}"))
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
        let (tx, mut rx) = crate::ipc::Ingress::with_limits(8, 1 << 20);
        let bound = super::bind_listener(cfg.clone()).await.unwrap();
        let addr = bound.local_addr().unwrap();
        tokio::spawn(super::serve(bound, tx, TOKEN.into()));

        let body = json!({"resourceLogs": [{"scopeLogs": [{"logRecords": [{
            "eventName": "codex.user_prompt",
            "attributes": [{"key": "prompt", "value": {"stringValue": "hello"}}]
        }]}]}]});
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/logs"))
            .header("authorization", format!("Bearer {TOKEN}"))
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
