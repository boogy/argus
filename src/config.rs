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
    pub health: HealthCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RemoteCfg {
    pub url: Option<String>,
    pub poll_interval_secs: u64,
    /// base64 ed25519 public key that remote policy must verify against.
    ///
    /// Only read from the machine-wide layer — see [`crate::policysig`] for
    /// why a key the watched user could set would prove nothing. It is
    /// declared here so a machine-wide file that sets it still deserializes
    /// as a `Config`; the loader would otherwise skip the whole layer over an
    /// unknown key, turning "sign the policy" into "apply no policy at all".
    pub public_key: Option<String>,
}
impl Default for RemoteCfg {
    fn default() -> Self {
        Self {
            url: None,
            poll_interval_secs: 300,
            public_key: None,
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
    /// `4xx` — which is a refusal, so the batch is dropped rather than
    /// retried. Turning this on against the wrong collector trades
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
    /// Record which cloud identity the agent held — the assumed role, the
    /// subscription, the project — and name the credential variables it had in
    /// scope. See [`crate::cloudid`] for what is read by value and what is
    /// only ever named.
    ///
    /// On by default, and unlike file contents that is not a close call: an
    /// allowlist of identifiers a provider already writes into its own audit
    /// log is the cheapest thing argus captures and the one that makes the
    /// rest attributable. Off, an event says a tool ran `terraform apply`;
    /// on, it says which account it ran against.
    pub cloud_identity: bool,
    /// Resolve `mcp.server` to where that server actually is, by reading the
    /// host tools' MCP config files. See [`crate::mcpcfg`] for which files and
    /// what is never read out of them.
    ///
    /// Off by default, for the reason file capture is: it reads a file on
    /// disk that the agent never sent, and those files sit next to
    /// credentials. On, every MCP call and permission event also says whether
    /// the server is a local package or somebody else's HTTPS endpoint.
    pub mcp_endpoints: bool,
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
            cloud_identity: true,
            mcp_endpoints: false,
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
    /// Per event, across all files. Without it the worst case is
    /// `max_bytes × max_files` — 320 KB at the defaults, against the 256 KB
    /// this holds it to. The margin is small until one of the other two is
    /// raised, which is the point: this is the cap that stays put when a
    /// deployment decides it wants 1 MiB files or forty of them.
    pub max_total_bytes: usize,
    pub skip_binary: bool,
    /// Digest an excluded file's bytes anyway, so it stays visible as *touched*
    /// and two captures of one path can be told apart.
    ///
    /// This is what makes `disk` mode open a file policy has already excluded:
    /// the bytes are hashed and dropped, and no content of one reaches the
    /// snapshot. `payload` mode has no such trade to make — an excluded file
    /// stops at the filter, before any digest — so there the setting decides
    /// nothing. Size is recorded in both modes whatever this says, and mtime
    /// only in `disk`, which is the only one that stats a file at all.
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
    /// The default is two seconds, against local reads that take microseconds.
    /// Nothing healthy is anywhere near it: the value is sized for the pause a
    /// spun-down disk or a slow network mount can still recover from, not for
    /// the normal case.
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
    /// Only what the hook payload already carried: `Write.content`, the *new*
    /// half of an `Edit`, a patch body. Exact, race-free, and zero I/O — it is
    /// what the tool said it was about to do. What an edit replaced is not
    /// captured: the question this answers is what the file now says.
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
    /// Whether this machine is supposed to carry the `--managed` layer.
    ///
    /// Off by default and set by fleet policy, because it is the operator who
    /// deployed the layer who knows it should be there — and because
    /// `check_managed` treats a *missing* managed artifact as tampering, which
    /// is the right answer on a machine that was wired that way and pure noise
    /// on one that never was. On a fleet, this belongs in the policy the user
    /// cannot edit; a local `false` then loses to it, which is the point.
    pub managed: bool,
    /// The sha256 the fleet expects the argus binary to have, lowercase hex.
    ///
    /// Without it, "is this the real argus" can only be answered relative to
    /// the binary asking — which is the right answer for a laptop and a weak
    /// one for a fleet, because a machine where *both* copies were replaced
    /// agrees with itself. Set in policy to the digest of the release that was
    /// deployed, this makes the hook's program answerable to something the user
    /// cannot rewrite.
    ///
    /// Unset by default: a wrong pin reports every machine as tampered with,
    /// so it has to be a deliberate act by whoever publishes the release.
    pub binary_sha256: Option<String>,
}
impl Default for IntegrityCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            managed: false,
            binary_sha256: None,
        }
    }
}

/// Liveness heartbeat. On by default, and for a stronger reason than the
/// integrity check: every way of defeating capture — killing the daemon,
/// deleting its data directory, blocking the collector — ends in silence, and
/// silence is indistinguishable from an idle machine unless something is
/// expected to arrive on a schedule.
///
/// Five minutes by default: short enough that an absence alert fires within a
/// coffee break, long enough that a fleet of ten thousand costs the collector
/// about thirty events a second. `interval_secs` is floored at 30 for the same
/// reason the integrity interval is — a typo must not turn the heartbeat into
/// the load.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HealthCfg {
    pub enabled: bool,
    pub interval_secs: u64,
}
impl Default for HealthCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 300,
        }
    }
}

/// defaults <- local file <- cached remote <- machine-wide file.
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
/// files actually set), same precedence as `load`. Exposed so the integrity
/// check can compare the *effective* config against the remote policy without
/// re-implementing the merge.
///
/// The order is the order of trust, and the last layer is the point of the
/// list: the local file and the remote *cache* both live in the per-user data
/// directory, so a user who would rather not be monitored can write either of
/// them by hand — hand-authoring a permissive `remote-config.cache.toml` is
/// not even a subtle trick. The machine-wide file is the only layer whose
/// contents an ordinary account cannot choose, so it is the only one that can
/// end an argument, and it goes on top.
///
/// A fleet that wants live policy control still has it: leave a key out of the
/// machine-wide file and the remote policy decides it. What the machine-wide
/// file pins, it pins for good.
///
/// The remote cache carries one extra condition the other two layers do not:
/// where the machine-wide layer pins `[remote] public_key`, a cache that does
/// not verify against it is skipped entirely rather than applied — a
/// hand-written cache is then not policy, it is a file.
pub fn merged_table() -> toml::Table {
    let mut merged = toml::Table::new();
    for (path, signed) in [
        (crate::paths::config_path(), false),
        (crate::paths::cached_remote_config_path(), true),
        (crate::paths::system_config_path(), false),
    ] {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // The cache claims to speak for the fleet, and it is a file in the
        // user's own directory. Where a key is pinned, checking that claim
        // here rather than only in `check` is what makes signing prevention
        // instead of a report filed after the policy already applied.
        if signed && let Err(e) = crate::policysig::check_cache(&text) {
            tracing::warn!("ignoring unverified remote policy {path:?}: {e}");
            continue;
        }
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

/// The machine-wide layer as the loader sees it.
///
/// Separate from [`merged_table`], which only needs to know what to apply,
/// because the *reason* a machine-wide file is not applying is the interesting
/// half: an administrator's typo silently reverts a whole fleet to whatever
/// each user's own config says, and nothing would otherwise say so.
pub enum SystemLayer {
    /// No machine-wide file — an ordinary, unmanaged host.
    Absent,
    /// Present, and skipped by the loader for the reason given.
    Skipped(String),
    Present(toml::Table),
}

/// Read and validate the machine-wide layer, exactly as [`merged_table`] does.
pub fn system_layer() -> SystemLayer {
    let path = crate::paths::system_config_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return SystemLayer::Absent;
    };
    let table = match text.parse::<toml::Table>() {
        Ok(t) => t,
        Err(e) => {
            return SystemLayer::Skipped(format!("{} is not valid TOML: {e}", path.display()));
        }
    };
    if let Err(e) = table.clone().try_into::<Config>() {
        return SystemLayer::Skipped(format!(
            "{} does not match the config schema: {e}",
            path.display()
        ));
    }
    SystemLayer::Present(table)
}

pub(crate) fn deep_merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(bt)), toml::Value::Table(ot)) => deep_merge(bt, ot),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// One fetched policy: the body the server served, its ETag, and — when this
/// host pins a key — the detached signature that says the server is the one
/// that served it.
#[derive(Debug)]
pub struct RemotePolicy {
    pub body: String,
    pub etag: Option<String>,
    /// base64 ed25519 signature over `body`, `None` on a host pinning no key.
    pub signature: Option<String>,
}

/// Returns Ok(None) on 304; Ok(Some(policy)) on 200.
///
/// Where a key is pinned this also fetches `<url>.sig` and verifies the body
/// before returning it, so an unsigned or mismatched body never reaches the
/// caching path at all. A signature the server cannot produce is an error and
/// not a downgrade: the caller keeps polling and keeps running on the last
/// cache that *did* verify, which is the behaviour a policy server rolled back
/// mid-deploy deserves.
pub async fn fetch_remote(url: &str, etag: Option<&str>) -> anyhow::Result<Option<RemotePolicy>> {
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

    let signature = match crate::policysig::pinned_key() {
        None => None,
        Some(key) => {
            let sig_url = crate::policysig::sig_url(url);
            let sig = client
                .get(&sig_url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            crate::policysig::verify(body.as_bytes(), &sig, &key)
                .map_err(|e| anyhow::anyhow!("policy at {url} failed verification: {e}"))?;
            Some(sig)
        }
    };
    Ok(Some(RemotePolicy {
        body,
        etag: new_etag,
        signature,
    }))
}

/// One poll's worth of "the server sent a new body": validate it, cache it,
/// hot-swap the shared config.
///
/// Split out of [`poll_loop`] so the one thing that matters here — that `etag`
/// advances only once the body is actually on disk — can be asserted without
/// running a loop whose shortest cycle is 30 seconds.
fn apply_remote(
    shared: &std::sync::RwLock<Config>,
    etag: &mut Option<String>,
    policy: &RemotePolicy,
) {
    let body = &policy.body;
    // Gate the cache write on Config-shape validity, not just TOML syntax: a
    // type-mismatched remote body must not overwrite the last-known-good cache.
    match body
        .parse::<toml::Table>()
        .and_then(|t| t.try_into::<Config>())
    {
        Ok(_) => {
            let cache = crate::paths::cached_remote_config_path();
            let tmp = cache.with_extension("tmp");
            // The signature first, and deliberately: the loader refuses a pair
            // that does not match, so a crash between the two writes leaves a
            // cache that is skipped rather than one that is trusted. Fetching
            // it again next poll is the cheap half of that trade.
            if let Some(sig) = &policy.signature {
                let path = crate::paths::cached_remote_config_sig_path();
                if let Err(e) = std::fs::write(&path, sig) {
                    tracing::warn!("could not cache policy signature at {path:?}: {e}");
                    return;
                }
            }
            match std::fs::write(&tmp, body).and_then(|()| std::fs::rename(&tmp, &cache)) {
                Ok(()) => {
                    // Only now. An ETag committed ahead of the write makes
                    // every later poll a 304 for a body that was never cached,
                    // so a single failed write — a full disk, a data directory
                    // an admin has locked down — stops fleet policy from *ever*
                    // being applied again, on the quiet path where 304 means
                    // "you already have it". The daemon would look healthy
                    // while running on local config alone.
                    *etag = policy.etag.clone();
                    *shared.write().unwrap() = load();
                    tracing::info!("remote config applied");
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    tracing::warn!(
                        "could not cache remote config at {cache:?}, \
                         refetching next poll: {e}"
                    );
                }
            }
        }
        Err(e) => tracing::warn!("rejecting invalid remote config: {e}"),
    }
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
                Ok(Some(policy)) => apply_remote(&shared, &mut etag, &policy),
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

    /// What a poll produces on a host that pins no key: a body, an ETag, and
    /// nothing vouching for either.
    fn unsigned(body: &str) -> RemotePolicy {
        RemotePolicy {
            body: body.into(),
            etag: Some("\"v1\"".into()),
            signature: None,
        }
    }

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
        let got = fetch_remote(&url, None).await.unwrap().unwrap();
        assert!(got.body.contains("prompts = false"));
        assert_eq!(got.etag.as_deref(), Some("\"v1\""));
        assert!(
            fetch_remote(&url, got.etag.as_deref())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The fetch path has to refuse before the caching path runs: a body that
    /// reaches the cache is a body that applies on the next load, whatever a
    /// later check says about it. So the interesting assertion is not the
    /// error — it is the empty data directory afterwards.
    #[tokio::test]
    async fn a_policy_body_the_key_does_not_cover_is_never_cached() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let (sk, pk) = crate::policysig::testkeys::keypair();
        let sys = dir.path().join("system.toml");
        std::fs::write(&sys, format!("[remote]\npublic_key = \"{pk}\"\n")).unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);

        // The server serves a policy, and a signature over a *different* one —
        // which is what a rewritten body on a compromised mirror looks like,
        // and also what a policy server that forgot to re-sign looks like.
        let served = "[capture]\nprompts = false\n";
        let sig = crate::policysig::testkeys::sign(&sk, "[capture]\nprompts = true\n");
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let body = if req.url().ends_with(".sig") {
                    sig.clone()
                } else {
                    served.to_string()
                };
                let _ = req.respond(tiny_http::Response::from_string(body));
            }
        });
        let url = format!("http://{addr}/cfg.toml");

        let err = fetch_remote(&url, None).await.unwrap_err().to_string();
        assert!(err.contains("failed verification"), "{err}");
        assert!(
            !crate::paths::cached_remote_config_path().exists(),
            "a body that does not verify still reached the cache"
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// And the other half: a correctly signed policy still gets fetched,
    /// cached with its signature, and applied. A control that also blocks the
    /// legitimate path is a control nobody deploys.
    #[tokio::test]
    async fn a_correctly_signed_policy_is_fetched_cached_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let (sk, pk) = crate::policysig::testkeys::keypair();
        let sys = dir.path().join("system.toml");
        std::fs::write(&sys, format!("[remote]\npublic_key = \"{pk}\"\n")).unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);

        let served = "[capture]\nprompts = false\n";
        // Trailing newline, exactly as `base64 > policy.toml.sig` writes it.
        let sig = format!("{}\n", crate::policysig::testkeys::sign(&sk, served));
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_string();
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let body = if req.url().ends_with(".sig") {
                    sig.clone()
                } else {
                    served.to_string()
                };
                let _ = req.respond(tiny_http::Response::from_string(body));
            }
        });

        let policy = fetch_remote(&format!("http://{addr}/cfg.toml"), None)
            .await
            .unwrap()
            .unwrap();
        let shared = std::sync::RwLock::new(Config::default());
        apply_remote(&shared, &mut None, &policy);
        assert!(!shared.read().unwrap().capture.prompts);
        assert!(!load().capture.prompts, "the cache must survive a reload");
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    #[test]
    fn a_failed_cache_write_does_not_burn_the_etag() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let cache = crate::paths::cached_remote_config_path();
        // Occupy the cache path with a non-empty directory: the rename cannot
        // land on it on any platform, which is the disk-full/locked-down case
        // without needing either.
        std::fs::create_dir_all(cache.join("blocker")).unwrap();

        let shared = std::sync::RwLock::new(Config::default());
        let mut etag: Option<String> = None;
        apply_remote(
            &shared,
            &mut etag,
            &unsigned("[capture]\nprompts = false\n"),
        );
        assert_eq!(
            etag, None,
            "the etag advanced past a body that never reached the cache, so every \
             later poll 304s and this policy is never applied"
        );
        assert!(
            shared.read().unwrap().capture.prompts,
            "config was hot-swapped from a cache write that failed"
        );

        // Same body once the path is writable: now it must stick.
        std::fs::remove_dir_all(&cache).unwrap();
        apply_remote(
            &shared,
            &mut etag,
            &unsigned("[capture]\nprompts = false\n"),
        );
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert!(!shared.read().unwrap().capture.prompts);
        assert!(
            !cache.with_extension("tmp").exists(),
            "tmp file left behind"
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    #[test]
    fn integrity_defaults_on_hourly() {
        let cfg = Config::default();
        assert!(cfg.integrity.enabled, "on by default (security control)");
        assert_eq!(cfg.integrity.interval_secs, 3600);
    }

    /// The whole point of a root-owned layer: the two files the watched user
    /// *can* write must not be able to unpick it. The remote cache matters as
    /// much as the user's own config here — it lives in the user's data dir
    /// under a predictable name, so "policy said so" is a claim any account
    /// can make by writing the file itself.
    #[test]
    fn neither_user_file_can_weaken_what_the_machine_wide_layer_pins() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        std::fs::write(
            crate::paths::config_path(),
            "[capture]\nprompts = false\n[redaction]\nenabled = false\n",
        )
        .unwrap();
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[capture]\nprompts = false\n[export]\notlp_endpoint = \"http://mine:4318\"\n",
        )
        .unwrap();
        let sys = dir.path().join("system.toml");
        std::fs::write(
            &sys,
            "[capture]\nprompts = true\n[redaction]\nenabled = true\n\
             [export]\notlp_endpoint = \"http://fleet:4318\"\n",
        )
        .unwrap();

        let before = load();
        assert!(!before.capture.prompts, "without the layer, the user wins");

        let _guard = crate::paths::SystemConfig::set(&sys);
        let cfg = load();
        assert!(cfg.capture.prompts, "the layer outranks the user's config");
        assert!(cfg.redaction.enabled, "and cannot be turned off locally");
        assert_eq!(
            cfg.export.otlp_endpoint.as_deref(),
            Some("http://fleet:4318"),
            "nor can capture be repointed by hand-writing the policy cache"
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// The bypass this whole module exists for: `cat > remote-config.cache.toml`
    /// is a one-line way to tell a monitored machine that the fleet wants
    /// nothing captured. Where the layer pins a key, that file has to be
    /// skipped — not merely reported later, since a policy reported after it
    /// applied has already applied.
    #[test]
    fn a_policy_cache_nobody_signed_is_not_policy() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let (sk, pk) = crate::policysig::testkeys::keypair();
        let body = "[capture]\nprompts = false\n";
        std::fs::write(crate::paths::cached_remote_config_path(), body).unwrap();

        assert!(
            !load().capture.prompts,
            "unpinned, the cache is policy as it always was"
        );

        let sys = dir.path().join("system.toml");
        std::fs::write(&sys, format!("[remote]\npublic_key = \"{pk}\"\n")).unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);
        assert!(
            load().capture.prompts,
            "a hand-written cache set capture and no key vouched for it"
        );

        // The genuine article, and the one edit that would make it useful to
        // somebody who would rather not be watched.
        let sig = crate::paths::cached_remote_config_sig_path();
        std::fs::write(&sig, crate::policysig::testkeys::sign(&sk, body)).unwrap();
        assert!(!load().capture.prompts, "the signed policy must apply");
        std::fs::write(
            crate::paths::cached_remote_config_path(),
            "[capture]\nprompts = false\ntool_inputs = false\n",
        )
        .unwrap();
        assert!(
            load().capture.tool_inputs,
            "one line added to a signed policy left it applying"
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// A key the layer does not mention stays the user's to set. A layer that
    /// swallowed everything would force operators to restate every default,
    /// and an unrestated key would silently revert.
    #[test]
    fn the_machine_wide_layer_only_governs_the_keys_it_names() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        std::fs::write(
            crate::paths::config_path(),
            "[capture]\ntool_outputs = false\n[export]\nbatch_size = 7\n",
        )
        .unwrap();
        let sys = dir.path().join("system.toml");
        // Away from the default, so "the layer applied" and "nobody applied
        // anything" cannot look the same.
        std::fs::write(&sys, "[capture]\nprompts = false\n").unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);

        let cfg = load();
        assert!(!cfg.capture.prompts, "the key the layer names");
        assert!(!cfg.capture.tool_outputs, "a sibling key it never named");
        assert_eq!(cfg.export.batch_size, 7);
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// A malformed machine-wide file is the dangerous failure: the loader skips
    /// it exactly as it skips a bad remote layer, so the host keeps running on
    /// the user's own config while `/etc/argus/config.toml` sits there looking
    /// like the machine is governed. `system_layer` has to be able to say so,
    /// which is what lets `check` report it instead of passing.
    #[test]
    fn a_machine_wide_layer_the_loader_would_skip_is_reported_not_silent() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path().join("system.toml");

        let _guard = crate::paths::SystemConfig::set(&sys);
        assert!(
            matches!(system_layer(), SystemLayer::Absent),
            "no file at all is an ordinary unmanaged host, not a fault"
        );

        std::fs::write(&sys, "[capture\nprompts = true\n").unwrap();
        let SystemLayer::Skipped(why) = system_layer() else {
            panic!("invalid TOML must not read as a layer in force");
        };
        assert!(why.contains("not valid TOML"), "{why}");

        // Parses, but the loader would still throw it away.
        std::fs::write(&sys, "[export]\nbatch_size = \"lots\"\n").unwrap();
        let SystemLayer::Skipped(why) = system_layer() else {
            panic!("a type-mismatched layer must not read as in force");
        };
        assert!(why.contains("config schema"), "{why}");

        std::fs::write(&sys, "[export]\nbatch_size = 50\n").unwrap();
        assert!(matches!(system_layer(), SystemLayer::Present(_)));
    }
}
