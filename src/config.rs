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
    pub integrity: IntegrityCfg,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ExportCfg {
    pub otlp_endpoint: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
}
impl Default for ExportCfg {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            headers: BTreeMap::new(),
            batch_size: 256,
            flush_interval_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CaptureCfg {
    pub prompts: bool,
    pub tool_inputs: bool,
    pub tool_outputs: bool,
    pub assistant_messages: bool,
    /// Per-field size cap (bytes of serialized content) applied to prompt
    /// text, assistant text, tool input/output. 0 = unlimited.
    pub max_field_bytes: usize,
}
impl Default for CaptureCfg {
    fn default() -> Self {
        Self {
            prompts: true,
            tool_inputs: true,
            tool_outputs: true,
            assistant_messages: true,
            max_field_bytes: 65536,
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

/// Wiring self-check. On by default: a security control that silently stops
/// capturing is worse than none, so the daemon periodically re-verifies its
/// own hook/plugin wiring and reports tampering. `interval_secs` floored at 30.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IntegrityCfg {
    pub enabled: bool,
    pub interval_secs: u64,
}
impl Default for IntegrityCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
        }
    }
}

/// defaults <- local file <- cached remote (remote is fleet policy, wins).
///
/// Each layer is validated to deserialize as a `Config` overlay on its own,
/// and again after merging, before being kept. A syntactically-valid but
/// type-mismatched layer (e.g. `poll_interval_secs = "sixty"`) is skipped
/// with a warning instead of poisoning the whole merged config back to
/// `Config::default()`.
pub fn load() -> Config {
    merged_table().try_into::<Config>().unwrap_or_default()
}

/// The merged config as a raw TOML table (defaults omitted — only what the
/// files actually set), same precedence as `load`: local file, then cached
/// remote (remote wins). Exposed so the integrity check can compare the
/// *effective* config against the remote policy without re-implementing the
/// merge.
pub fn merged_table() -> toml::Table {
    let mut merged = toml::Table::new();
    for path in [
        crate::paths::config_path(),
        crate::paths::cached_remote_config_path(),
    ] {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let table = match text.parse::<toml::Table>() {
            Ok(table) => table,
            Err(e) => {
                tracing::warn!("ignoring invalid config {path:?}: {e}");
                continue;
            }
        };
        if let Err(e) = table.clone().try_into::<Config>() {
            tracing::warn!("ignoring type-mismatched config {path:?}: {e}");
            continue;
        }
        let mut candidate = merged.clone();
        deep_merge(&mut candidate, table);
        match candidate.clone().try_into::<Config>() {
            Ok(_) => merged = candidate,
            Err(e) => tracing::warn!("ignoring config {path:?}: merge invalidates config: {e}"),
        }
    }
    merged
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
                    // Gate the cache write on Config-shape validity, not just TOML
                    // syntax: a type-mismatched remote body must not overwrite the
                    // last-known-good cache.
                    match body
                        .parse::<toml::Table>()
                        .and_then(|t| t.try_into::<Config>())
                    {
                        Ok(_) => {
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
                        Err(e) => tracing::warn!("rejecting invalid remote config: {e}"),
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
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
        let cfg = load();
        assert!(cfg.redaction.enabled);
        assert!(cfg.capture.prompts);
        assert_eq!(cfg.remote.poll_interval_secs, 300);
        assert_eq!(cfg.codex.otlp_listen, "127.0.0.1:4327");
    }

    #[test]
    fn remote_cache_overrides_local_file() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
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

    #[test]
    fn type_mismatched_remote_layer_is_skipped_not_poisoning() {
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ARGUS_DATA_DIR", dir.path()); }
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(
            crate::paths::config_path(),
            "[export]\notlp_endpoint = \"http://local:4318\"\n",
        )
        .unwrap();
        // syntactically valid TOML, wrong type for poll_interval_secs
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[remote]\npoll_interval_secs = \"sixty\"\n",
        )
        .unwrap();
        let cfg = load();
        assert_eq!(
            cfg.export.otlp_endpoint.as_deref(),
            Some("http://local:4318"),
            "local layer must survive a bad remote layer"
        );
        assert_eq!(
            cfg.remote.poll_interval_secs, 300,
            "bad remote field falls back to default"
        );
    }

    #[test]
    fn capture_defaults_include_outputs_and_caps() {
        let cfg = Config::default();
        assert!(cfg.capture.tool_outputs);
        assert!(cfg.capture.assistant_messages);
        assert_eq!(cfg.capture.max_field_bytes, 65536);
    }

    #[test]
    fn export_cfg_default_has_nonzero_batch_and_flush() {
        let cfg = Config::default();
        assert_eq!(cfg.export.batch_size, 256);
        assert_eq!(cfg.export.flush_interval_secs, 10);
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

    #[test]
    fn integrity_defaults_on_hourly() {
        let cfg = Config::default();
        assert!(cfg.integrity.enabled, "on by default (security control)");
        assert_eq!(cfg.integrity.interval_secs, 3600);
    }
}
