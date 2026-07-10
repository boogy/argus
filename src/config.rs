use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub remote: RemoteCfg,
    pub export: ExportCfg,
    pub capture: CaptureCfg,
    pub redaction: RedactionCfg,
    pub buffer: BufferCfg,
    pub codex: CodexCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RemoteCfg {
    pub url: Option<String>,
    pub poll_interval_secs: u64,
}
impl Default for RemoteCfg {
    fn default() -> Self {
        Self {
            url: None,
            poll_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ExportCfg {
    pub otlp_endpoint: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CaptureCfg {
    pub prompts: bool,
    pub tool_inputs: bool,
}
impl Default for CaptureCfg {
    fn default() -> Self {
        Self {
            prompts: true,
            tool_inputs: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RedactionCfg {
    pub enabled: bool,
    pub extra_patterns: Vec<String>,
}
impl Default for RedactionCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            extra_patterns: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BufferCfg {
    pub max_events: u64,
}
impl Default for BufferCfg {
    fn default() -> Self {
        Self {
            max_events: 100_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CodexCfg {
    pub otlp_listen: String,
}
impl Default for CodexCfg {
    fn default() -> Self {
        Self {
            otlp_listen: "127.0.0.1:4327".into(),
        }
    }
}

/// defaults <- local file <- cached remote (remote is fleet policy, wins).
pub fn load() -> Config {
    let mut merged = toml::Table::new();
    for path in [
        crate::paths::config_path(),
        crate::paths::cached_remote_config_path(),
    ] {
        if let Ok(text) = std::fs::read_to_string(&path) {
            match text.parse::<toml::Table>() {
                Ok(table) => deep_merge(&mut merged, table),
                Err(e) => tracing::warn!("ignoring invalid config {path:?}: {e}"),
            }
        }
    }
    // Fix batch/flush defaults that Default::default() can't express as non-zero.
    let mut cfg: Config = toml::Table::try_into(merged).unwrap_or_default();
    if cfg.export.batch_size == 0 {
        cfg.export.batch_size = 256;
    }
    if cfg.export.flush_interval_secs == 0 {
        cfg.export.flush_interval_secs = 10;
    }
    cfg
}

fn deep_merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(bt)), toml::Value::Table(ot)) => deep_merge(bt, ot),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// Returns Ok(None) on 304; Ok(Some((body, etag))) on 200.
pub async fn fetch_remote(
    url: &str,
    etag: Option<&str>,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let mut req = client.get(url);
    if let Some(tag) = etag {
        req = req.header("If-None-Match", tag);
    }
    let resp = req.send().await?;
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    let new_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = resp.text().await?;
    // Validate before caching: a bad remote config must not poison the agent.
    body.parse::<toml::Table>()?;
    Ok(Some((body, new_etag)))
}

/// Daemon task: poll remote config, atomically cache, hot-swap shared config.
pub async fn poll_loop(shared: std::sync::Arc<std::sync::RwLock<Config>>) {
    let mut etag: Option<String> = None;
    loop {
        let (url, interval) = {
            let cfg = shared.read().unwrap();
            (cfg.remote.url.clone(), cfg.remote.poll_interval_secs)
        };
        if let Some(url) = url {
            match fetch_remote(&url, etag.as_deref()).await {
                Ok(Some((body, new_etag))) => {
                    etag = new_etag;
                    let cache = crate::paths::cached_remote_config_path();
                    let tmp = cache.with_extension("tmp");
                    if std::fs::write(&tmp, &body)
                        .and_then(|_| std::fs::rename(&tmp, &cache))
                        .is_ok()
                    {
                        *shared.write().unwrap() = load();
                        tracing::info!("remote config applied");
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("remote config fetch failed (using cache): {e}"),
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval.max(30))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_no_files() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        let cfg = load();
        assert!(cfg.redaction.enabled);
        assert!(cfg.capture.prompts);
        assert_eq!(cfg.remote.poll_interval_secs, 300);
        assert_eq!(cfg.codex.otlp_listen, "127.0.0.1:4327");
    }

    #[test]
    fn remote_cache_overrides_local_file() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("LLM_MONITOR_DATA_DIR", dir.path());
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            crate::paths::config_path(),
            "[capture]\nprompts = true\n[export]\notlp_endpoint = \"http://local:4318\"\n",
        )
        .unwrap();
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[capture]\nprompts = false\n",
        )
        .unwrap();
        let cfg = load();
        assert!(!cfg.capture.prompts, "remote policy must win");
        assert_eq!(
            cfg.export.otlp_endpoint.as_deref(),
            Some("http://local:4318"),
            "local keys absent from remote survive"
        );
    }

    #[tokio::test]
    async fn fetch_remote_honors_etag_304() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let has_etag = req.headers().iter().any(|h| h.field.equiv("If-None-Match"));
                let resp = if has_etag {
                    tiny_http::Response::empty(304).boxed()
                } else {
                    tiny_http::Response::from_string("[capture]\nprompts = false\n")
                        .with_status_code(200)
                        .with_header("ETag: \"v1\"".parse::<tiny_http::Header>().unwrap())
                        .boxed()
                };
                let _ = req.respond(resp);
            }
        });
        let url = format!("http://{addr}/cfg.toml");
        let (body, etag) = fetch_remote(&url, None).await.unwrap().unwrap();
        assert!(body.contains("prompts = false"));
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(fetch_remote(&url, etag.as_deref()).await.unwrap().is_none());
    }
}
