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
    pub spool: SpoolCfg,
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
    /// Ceiling on the serialized size of one export batch, in bytes. 0 =
    /// unlimited.
    ///
    /// A count of events says nothing about the size of a request: 256 tool
    /// results carrying file contents are three orders of magnitude larger than
    /// 256 prompts, and collectors reject on bytes, not on rows.
    pub max_batch_bytes: u64,
    /// Compress the request body with gzip.
    ///
    /// Off by default, and deliberately: OTLP/HTTP receivers *should* accept a
    /// gzipped body but are not required to, and one that does not answers a
    /// `4xx` — which, since T9a, is a refusal that drops the batch rather than
    /// retrying it. Turning this on against the wrong collector trades
    /// bandwidth for audit data, so it is the operator's call, not a default.
    pub gzip: bool,
    pub flush_interval_secs: u64,
}
impl Default for ExportCfg {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            headers: BTreeMap::new(),
            batch_size: 256,
            // Under the 4 MiB default request limit of the OTel Collector's
            // HTTP receiver, with room for the OTLP envelope around the bodies.
            max_batch_bytes: 3 * 1024 * 1024,
            gzip: false,
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
    /// What a string that exceeds `max_field_bytes` is reduced to.
    pub truncate_mode: TruncateMode,
    pub file_contents: FileContentsCfg,
}
impl Default for CaptureCfg {
    fn default() -> Self {
        Self {
            prompts: true,
            tool_inputs: true,
            tool_outputs: true,
            assistant_messages: true,
            max_field_bytes: 65536,
            truncate_mode: TruncateMode::default(),
            file_contents: FileContentsCfg::default(),
        }
    }
}

/// What an agent actually wrote into your files, not just which files it named.
///
/// Off by default, and that default is not timidity. Everything else argus
/// captures is a description of an action; this is the content itself, and on
/// a developer's machine that content is the largest concentration of
/// credentials, customer data and unreleased work in one place. Turning it on
/// is a decision about what a SIEM is allowed to hold, and it belongs to
/// whoever runs the SIEM.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct FileContentsCfg {
    pub enabled: bool,
    pub mode: ContentMode,
    /// Regexes on the normalized path. Empty means "no restriction" — an
    /// `include` that matched nothing would be an enabled feature that
    /// captures nothing, which reads as a bug rather than a policy.
    pub include: Vec<String>,
    /// Regexes on the normalized path, applied after `include`. Wins on a tie:
    /// a deployment that both included `/src/` and excluded `/src/.env` meant
    /// the exclusion.
    pub exclude: Vec<String>,
    /// Per file. Larger files are captured truncated, with the marker.
    pub max_bytes: usize,
    /// Per event, so one `apply_patch` across forty files cannot become forty
    /// file bodies in one record.
    pub max_files: usize,
    /// Per event, across all files. `max_bytes × max_files` is the worst case
    /// without it, which at the defaults is ten times what anyone wants in a
    /// single log record.
    pub max_total_bytes: usize,
    pub skip_binary: bool,
    /// Record `sha256`, size and mtime even where content is withheld. This is
    /// what makes an excluded file still visible as *touched*, and what lets
    /// two captures of one path be told apart.
    pub hash: bool,
    /// How long one file's stat-and-read may take before the daemon stops
    /// waiting for it and records the file as unreadable. `0` waits forever.
    ///
    /// A read that has stopped returning cannot be cancelled: a process parked
    /// in the kernel on a dead NFS mount is not interruptible from userspace,
    /// and nothing here pretends otherwise. What this bounds is the *blast
    /// radius* — the pipeline gets an answer and moves on, and an unreachable
    /// mount costs one stuck thread rather than every event behind it.
    ///
    /// Local reads take microseconds, so the default is two orders of
    /// magnitude of slack over anything healthy.
    pub read_timeout_ms: u64,
}

impl Default for FileContentsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: ContentMode::default(),
            include: vec![],
            // Secrets and noise. These keep content out while `hash` still
            // records that the file was touched — reading `.env` is a finding
            // on its own, and reporting it does not require shipping it.
            exclude: [
                "/node_modules/",
                r"/\.git/",
                r"\.(lock|min\.js)$",
                r"/\.env",
                r"\.pem$",
                r"/\.ssh/",
                "_rsa$",
                r"\.p12$",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            max_bytes: 32768,
            max_files: 10,
            max_total_bytes: 262144,
            skip_binary: true,
            hash: true,
            read_timeout_ms: 2000,
        }
    }
}

/// Where captured bytes may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentMode {
    /// Only what the hook payload already carried: `Write.content`, an
    /// `Edit`'s two halves, a patch body. Exact, race-free, and zero I/O —
    /// it is what the tool said it was about to do.
    #[default]
    Payload,
    /// Read the file. Answers for the calls a payload describes but does not
    /// quote — a `Read`, a `Grep`, an edit whose result nothing carried — and
    /// shows changes the tool did not make, like a formatter that ran after
    /// it, at the cost of reading the state a moment *after* the tool acted.
    ///
    /// It does not reach a file the payload never named: a `Bash` with a `>`
    /// redirect carries a command, not a path, and no mode captures that.
    Disk,
    Both,
}

/// Which end of an oversized string is worth keeping.
///
/// There is no right answer, which is why it is a setting. A command's
/// intent is at the front; a diff's outcome and a stack trace's cause are at
/// the back, so `head` alone can truncate away the only part anyone would
/// read. `drop` is for deployments that would rather store a placeholder than
/// risk a fragment of a large file in the SIEM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncateMode {
    /// Keep the beginning. The historical behaviour, and the default.
    #[default]
    Head,
    /// Keep both ends, three quarters at the front.
    HeadTail,
    /// Keep neither: the field becomes a marker.
    Drop,
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
    /// Ceiling on the stored event text, in bytes.
    ///
    /// `max_events` alone is not a disk bound. A 100k-event cap sized against
    /// ordinary prompts becomes tens of gigabytes the first time a session
    /// starts pasting whole files into tool results, and the machine runs out
    /// of disk during precisely the incident the buffer exists to record.
    /// Whichever of the two caps binds first wins.
    pub max_bytes: u64,
}
impl Default for BufferCfg {
    fn default() -> Self {
        Self {
            max_events: 100_000,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

/// On-disk ceiling for the hand-off spool.
///
/// The spool is what the shim writes when the daemon will not answer, so it
/// grows exactly while nothing is draining it — a daemon that crashes on a
/// Friday and a fleet of agents that keep working all weekend. Uncapped, the
/// one component that must never harm the host tool ends up filling its disk.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SpoolCfg {
    pub max_bytes: u64,
}
impl Default for SpoolCfg {
    fn default() -> Self {
        // Smaller than the buffer's: the buffer is the archive, the spool is a
        // few minutes of hand-off that happens to have become a few days.
        Self {
            max_bytes: 64 * 1024 * 1024,
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
            otlp_listen: crate::paths::default_otlp_listen(),
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
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let cfg = load();
        assert!(cfg.redaction.enabled);
        assert!(cfg.capture.prompts);
        assert_eq!(cfg.remote.poll_interval_secs, 300);
        // Loopback is machine-wide, so the port cannot be: see
        // `paths::otlp_port`. Asserted as a property, since the value depends
        // on the temporary data directory this test happens to get.
        let (host, port) = cfg.codex.otlp_listen.rsplit_once(':').unwrap();
        assert_eq!(host, "127.0.0.1", "the receiver must stay off the network");
        let port: u16 = port.parse().unwrap();
        assert!(
            (40_000..49_152).contains(&port),
            "port {port} is outside the band reserved for per-install endpoints"
        );
    }

    #[test]
    fn remote_cache_overrides_local_file() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
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
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
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
        assert_eq!(
            cfg.capture.truncate_mode,
            TruncateMode::Head,
            "the default must stay the historical behaviour"
        );
    }

    /// The one setting whose default is a policy decision rather than a
    /// convenience: on, it puts file bodies in the SIEM.
    #[test]
    fn file_content_capture_is_off_until_someone_turns_it_on() {
        let d = FileContentsCfg::default();
        assert!(!d.enabled);
        assert_eq!(d.mode, ContentMode::Payload, "the zero-I/O mode by default");
        assert!(d.skip_binary);
        assert!(d.hash, "an excluded file must still be visible as touched");
        assert!(
            d.include.is_empty(),
            "an include list nobody asked for would silently narrow capture"
        );
        // The exclusions are the shipped policy. Losing one is not a
        // regression a compiler can catch.
        for pat in [r"/\.env", r"/\.ssh/", r"\.pem$", "_rsa$", "/node_modules/"] {
            assert!(d.exclude.iter().any(|p| p == pat), "lost exclusion {pat}");
        }
        // max_bytes × max_files without it, which is 320 KB in one record.
        assert!(d.max_total_bytes < d.max_bytes * d.max_files);
    }

    #[test]
    fn the_file_contents_table_parses_the_way_the_docs_write_it() {
        let cfg: Config = toml::from_str(
            r#"
            [capture.file_contents]
            enabled = true
            mode = "both"
            include = ['/src/']
            exclude = ['/vendor/']
            max_bytes = 512
            max_files = 3
            max_total_bytes = 1024
            skip_binary = false
            hash = false
            read_timeout_ms = 500
            "#,
        )
        .unwrap();
        let fc = &cfg.capture.file_contents;
        assert!(fc.enabled);
        assert_eq!(fc.mode, ContentMode::Both);
        assert_eq!(fc.include, vec!["/src/".to_string()]);
        // A user-supplied list replaces the defaults rather than adding to
        // them: a deployment that writes its own `exclude` is stating a whole
        // policy, and silently keeping ours would make its config a lie in the
        // other direction.
        assert_eq!(fc.exclude, vec!["/vendor/".to_string()]);
        assert_eq!(fc.max_bytes, 512);
        assert_eq!(fc.max_files, 3);
        assert_eq!(fc.max_total_bytes, 1024);
        assert!(!fc.skip_binary);
        assert!(!fc.hash);
        assert_eq!(fc.read_timeout_ms, 500);

        // Sibling settings in `[capture]` survive the nested table.
        assert!(cfg.capture.prompts);
        assert!(
            toml::from_str::<Config>("[capture.file_contents]\nmode = \"stdin\"\n").is_err(),
            "an unknown mode was accepted"
        );
    }

    /// The realistic way this table gets written: one line to turn it on. If
    /// that does not parse, the whole config is rejected at startup — and if it
    /// parses to a zeroed struct, the shipped exclusions are gone and the very
    /// first capture ships `.env`.
    #[test]
    fn turning_capture_on_takes_one_line_and_keeps_the_shipped_policy() {
        let cfg: Config =
            toml::from_str("[capture.file_contents]\nenabled = true\n").expect("minimal table");
        let fc = &cfg.capture.file_contents;
        assert!(fc.enabled);
        let d = FileContentsCfg::default();
        assert_eq!(fc.exclude, d.exclude, "the shipped exclusions were dropped");
        assert_eq!(fc.max_bytes, d.max_bytes);
        assert_eq!(fc.max_files, d.max_files);
        assert_eq!(fc.max_total_bytes, d.max_total_bytes);
        assert_eq!(fc.mode, d.mode);
        assert_eq!(fc.skip_binary, d.skip_binary);
        assert_eq!(fc.hash, d.hash);
        // A default of zero here would be "wait forever" — the one value that
        // turns the deadline off for everyone who never wrote the line.
        assert_eq!(fc.read_timeout_ms, d.read_timeout_ms);
        assert!(d.read_timeout_ms > 0, "the shipped default is no deadline");
    }

    /// The mode is written in a config file, in snake_case, or it is a knob
    /// nobody can reach.
    #[test]
    fn truncate_mode_is_spelled_the_way_the_docs_spell_it() {
        for (text, want) in [
            ("head", TruncateMode::Head),
            ("head_tail", TruncateMode::HeadTail),
            ("drop", TruncateMode::Drop),
        ] {
            let cfg: Config =
                toml::from_str(&format!("[capture]\ntruncate_mode = \"{text}\"\n")).unwrap();
            assert_eq!(cfg.capture.truncate_mode, want, "for {text:?}");
        }
        // And a typo is a rejected layer, not a silent change of behaviour:
        // `load` logs and drops the file, leaving the defaults in place.
        assert!(
            toml::from_str::<Config>("[capture]\ntruncate_mode = \"tail\"\n").is_err(),
            "an unknown mode was accepted"
        );
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
