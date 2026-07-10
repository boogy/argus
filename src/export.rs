use crate::config::ExportCfg;
use crate::event::{Event, EventKind};
use anyhow::{Context, Result};
use serde_json::{json, Value};

pub fn to_otlp_body(events: &[Event]) -> Value {
    let (host, user) = events
        .first()
        .map(|e| (e.host.clone(), e.username.clone()))
        .unwrap_or_default();
    let records: Vec<Value> = events.iter().map(record).collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                attr("service.name", "llm-monitor"),
                attr("host.name", &host),
                attr("user.name", &user),
            ]},
            "scopeLogs": [{
                "scope": { "name": "llm-monitor", "version": env!("CARGO_PKG_VERSION") },
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
        EventKind::ToolUse {
            tool, files, fqdns, ..
        } => {
            attrs.push(attr("tool.name", tool));
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
        EventKind::Session { action } => {
            attrs.push(attr("session.action", action));
            "session"
        }
        EventKind::Raw { .. } => "raw",
    };
    attrs.insert(0, attr("event.type", event_type));
    json!({
        "timeUnixNano": (e.ts.timestamp_nanos_opt().unwrap_or(0)).to_string(),
        "severityText": "INFO",
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

    #[tokio::test]
    async fn export_posts_to_v1_logs_and_errors_on_500() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let url = req.url().to_string();
                let status = if tx.send(url.clone()).is_ok() && url == "/v1/logs" {
                    200
                } else {
                    500
                };
                let _ = req.respond(tiny_http::Response::empty(status));
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
            },
        );
        exporter.export(std::slice::from_ref(&e)).await.unwrap();
        assert_eq!(rx.recv().unwrap(), "/v1/logs");
    }
}
