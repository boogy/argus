use crate::config::ExportCfg;
use crate::event::{Event, EventKind};
use anyhow::{Context, Result};
use serde_json::{Value, json};

pub fn to_otlp_body(events: &[Event]) -> Value {
    let (host, user) = events
        .first()
        .map(|e| (e.host.clone(), e.username.clone()))
        .unwrap_or_default();
    let records: Vec<Value> = events.iter().map(record).collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                attr("service.name", "argus"),
                attr("host.name", &host),
                attr("user.name", &user),
            ]},
            "scopeLogs": [{
                "scope": { "name": "argus", "version": env!("CARGO_PKG_VERSION") },
                "logRecords": records
            }]
        }]
    })
}

fn attr(k: &str, v: &str) -> Value {
    json!({ "key": k, "value": { "stringValue": v } })
}

fn record(e: &Event) -> Value {
    let mut attrs = vec![attr("source", &e.source)];
    if let Some(s) = &e.session_id {
        attrs.push(attr("session.id", s));
    }
    if let Some(c) = &e.cwd {
        attrs.push(attr("cwd", c));
    }
    let event_type = match &e.kind {
        EventKind::Prompt { .. } => "prompt",
        EventKind::AssistantMessage { .. } => "assistant_message",
        EventKind::ToolUse {
            tool,
            phase,
            files,
            fqdns,
            error,
            ..
        } => {
            attrs.push(attr("tool.name", tool));
            attrs.push(attr("tool.phase", phase));
            if error.is_some() {
                attrs.push(attr("tool.failed", "true"));
            }
            if !files.is_empty() {
                attrs.push(attr("file.paths", &files.join(",")));
            }
            if !fqdns.is_empty() {
                attrs.push(attr("net.fqdns", &fqdns.join(",")));
            }
            "tool_use"
        }
        EventKind::Skill { name, .. } => {
            attrs.push(attr("skill.name", name));
            "skill"
        }
        EventKind::Agent { agent_type, .. } => {
            attrs.push(attr("agent.type", agent_type));
            "agent"
        }
        EventKind::Permission { tool, action, .. } => {
            attrs.push(attr("tool.name", tool));
            attrs.push(attr("permission.action", action));
            "permission"
        }
        EventKind::Notification { category, .. } => {
            attrs.push(attr("notification.category", category));
            "notification"
        }
        EventKind::Compact { phase, trigger, .. } => {
            attrs.push(attr("compact.phase", phase));
            attrs.push(attr("compact.trigger", trigger));
            "compact"
        }
        EventKind::FileChange { path, action } => {
            attrs.push(attr("file.paths", path));
            attrs.push(attr("file.action", action));
            "file_change"
        }
        EventKind::Error { context, .. } => {
            attrs.push(attr("error.context", context));
            "error"
        }
        EventKind::Session { action, .. } => {
            attrs.push(attr("session.action", action));
            "session"
        }
        EventKind::Raw { .. } => "raw",
        EventKind::Integrity {
            status,
            tool,
            detail,
        } => {
            attrs.push(attr("integrity.status", status));
            attrs.push(attr("integrity.tool", tool));
            attrs.push(attr("integrity.detail", detail));
            "integrity"
        }
    };
    for (key, val) in [
        ("turn.id", &e.meta.turn_id),
        ("agent.id", &e.meta.agent_id),
        ("agent.type", &e.meta.agent_type),
        ("permission.mode", &e.meta.permission_mode),
        ("llm.model", &e.meta.model),
    ] {
        if let Some(v) = val
            && !attrs.iter().any(|a| a["key"] == *key)
        {
            attrs.push(attr(key, v));
        }
    }
    attrs.insert(0, attr("event.type", event_type));
    // Broken wiring is the one finding a SIEM should alert on, so lift it out
    // of the INFO stream everything else rides in.
    let severity = match &e.kind {
        EventKind::Integrity { status, .. } if status != "ok" => "WARN",
        _ => "INFO",
    };
    json!({
        "timeUnixNano": (e.ts.timestamp_nanos_opt().unwrap_or(0)).to_string(),
        "severityText": severity,
        "body": { "stringValue": serde_json::to_string(e).unwrap_or_default() },
        "attributes": attrs
    })
}

pub struct Exporter {
    client: reqwest::Client,
    endpoint: Option<String>,
    headers: std::collections::BTreeMap<String, String>,
}

impl Exporter {
    pub fn new(cfg: &ExportCfg) -> Self {
        Exporter {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
            endpoint: cfg.otlp_endpoint.clone(),
            headers: cfg.headers.clone(),
        }
    }

    pub async fn export(&self, events: &[Event]) -> Result<()> {
        let endpoint = self
            .endpoint
            .as_ref()
            .context("no otlp_endpoint configured")?;
        let mut req = self
            .client
            .post(format!("{}/v1/logs", endpoint.trim_end_matches('/')))
            .json(&to_otlp_body(events));
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        req.send().await?.error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventKind};

    #[test]
    fn otlp_body_shape_is_valid() {
        let e = Event::new(
            "claude-code",
            Some("s1".into()),
            None,
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "pre".into(),
                input: serde_json::json!({}),
                output: serde_json::Value::Null,
                error: None,
                files: vec!["/a.rs".into()],
                fqdns: vec![],
            },
        );
        let body = to_otlp_body(std::slice::from_ref(&e));
        let records = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
        assert_eq!(records.as_array().unwrap().len(), 1);
        let rec = &records[0];
        assert!(rec["timeUnixNano"].is_string());
        let attrs = rec["attributes"].as_array().unwrap();
        let get = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].as_str().unwrap().to_string())
        };
        assert_eq!(get("event.type").as_deref(), Some("tool_use"));
        assert_eq!(get("tool.name").as_deref(), Some("Write"));
        assert_eq!(get("session.id").as_deref(), Some("s1"));
    }

    #[test]
    fn new_kinds_and_meta_export_attributes() {
        let mut e = Event::new(
            "copilot",
            Some("s".into()),
            None,
            EventKind::Permission {
                tool: "bash".into(),
                action: "requested".into(),
                input: serde_json::json!({}),
            },
        );
        e.meta.agent_type = Some("Explore".into());
        let body = to_otlp_body(std::slice::from_ref(&e));
        let attrs = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"].clone();
        let get = |k: &str| {
            attrs
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["key"] == k)
                .map(|a| a["value"]["stringValue"].as_str().unwrap().to_string())
        };
        assert_eq!(get("event.type").as_deref(), Some("permission"));
        assert_eq!(get("tool.name").as_deref(), Some("bash"));
        assert_eq!(get("permission.action").as_deref(), Some("requested"));
        assert_eq!(get("agent.type").as_deref(), Some("Explore"));
    }

    #[tokio::test]
    async fn export_posts_to_v1_logs_and_errors_on_500() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut count = 0;
            for mut req in server.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let url = req.url().to_string();
                let status = if url == "/v1/logs" {
                    count += 1;
                    if count == 1 { 200 } else { 500 }
                } else {
                    500
                };
                let _ = req.respond(tiny_http::Response::empty(status));
                let _ = tx.send(url);
            }
        });
        let cfg = crate::config::ExportCfg {
            otlp_endpoint: Some(format!("http://{addr}")),
            ..Default::default()
        };
        let exporter = Exporter::new(&cfg);
        let e = Event::new(
            "codex",
            None,
            None,
            EventKind::Session {
                action: "start".into(),
                detail: serde_json::Value::Null,
            },
        );
        exporter.export(std::slice::from_ref(&e)).await.unwrap();
        assert_eq!(rx.recv().unwrap(), "/v1/logs");

        let err = exporter.export(std::slice::from_ref(&e)).await;
        assert!(
            err.is_err(),
            "non-2xx must surface as Err for at-least-once redelivery"
        );
    }
}
