//! Where an MCP server actually is.
//!
//! [`crate::adapters::mcp_server`] reads *which* server a call went to out of
//! the tool's own name. That name is a label the host tool chose; it says
//! nothing about what is on the other end. `mcp__github__create_issue` is a
//! call to something called `github`, which is either a package running as a
//! child process on this machine or an HTTPS endpoint belonging to whoever
//! controls that hostname, and an inventory of third-party reach that cannot
//! tell those two apart is not an inventory.
//!
//! The mapping lives in the host tools' own config files, so this is the
//! second thing argus reads from disk rather than from a payload — and it is
//! gated like the first. Those files carry credentials: an `env` block with
//! the server's API keys, sometimes a token in an argument or a URL. Three
//! rules follow from that, and they are the whole security story here:
//!
//! 1. `env` is never read. Not redacted, not hashed — never looked at.
//! 2. Only `command`/`args`/`url` are read, and each is sanitized on the way
//!    out: a URL loses its userinfo and its query string, an argument whose
//!    *name* says credential loses its value.
//! 3. The result still goes through the ordinary redactor in
//!    [`crate::enrich`], which catches by shape what rule 2 catches by name.
//!
//! Off by default (`capture.mcp_endpoints`), on the same argument file capture
//! is: reading a file on disk that the agent never sent is a different kind of
//! collection from recording what it did send, and turning it on belongs to
//! whoever runs the SIEM.

use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

/// A server location is an identifier, not a document. Anything longer than
/// this is a command line with a payload in it, and the tail of that is worth
/// less than the risk of shipping it.
pub const MAX_ENDPOINT_BYTES: usize = 512;

/// Config files above this are not config files. `~/.claude.json` is the
/// reason the cap is megabytes rather than kilobytes — it holds session state
/// beside the server list, and skipping it would skip the file where
/// `claude mcp add` puts servers by default.
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// How long a parsed file is trusted before its mtime is checked again.
///
/// `~/.claude.json` is rewritten continuously by a running session, so an
/// mtime check alone would re-parse megabytes of JSON on almost every event.
/// The cost of the floor is that a server added mid-session takes this long to
/// be named, against a cost with no floor that scales with event rate.
const RECHECK: Duration = Duration::from_secs(15);

/// Separates a project path from a server name in a cache key, because it
/// cannot occur in either.
const SCOPE_SEP: char = '\0';

struct Cached {
    /// `None` for a file that does not exist — a negative result worth keeping,
    /// since most machines have most of these files missing.
    stamp: Option<(SystemTime, u64)>,
    checked: Instant,
    servers: HashMap<String, String>,
}

/// Parsed server lists, keyed by the file they came from.
#[derive(Default)]
pub struct Resolver {
    cache: Mutex<HashMap<PathBuf, Cached>>,
}

pub fn resolver() -> &'static Resolver {
    static R: OnceLock<Resolver> = OnceLock::new();
    R.get_or_init(Resolver::default)
}

impl Resolver {
    /// Where `server` is, according to the first config file that names it.
    ///
    /// Order is the host tools' own: a project file beats the user's, because
    /// that is which one the agent was actually running under.
    pub fn endpoint(&self, server: &str, cwd: Option<&str>) -> Option<String> {
        for path in candidate_files(cwd) {
            if let Some(e) = self.lookup(&path, server, cwd) {
                return Some(e);
            }
        }
        None
    }

    fn lookup(&self, path: &Path, server: &str, cwd: Option<&str>) -> Option<String> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = cache
            .get(path)
            .is_some_and(|c| c.checked.elapsed() < RECHECK);
        if !fresh {
            let stamp = std::fs::metadata(path)
                .ok()
                .and_then(|m| Some((m.modified().ok()?, m.len())));
            let unchanged = cache.get(path).is_some_and(|c| c.stamp == stamp);
            let servers = if unchanged {
                None
            } else {
                Some(stamp.map(|_| parse(path)).unwrap_or_default())
            };
            let entry = cache.entry(path.to_path_buf()).or_insert(Cached {
                stamp: None,
                checked: Instant::now(),
                servers: HashMap::new(),
            });
            entry.checked = Instant::now();
            entry.stamp = stamp;
            if let Some(s) = servers {
                entry.servers = s;
            }
        }
        let entry = cache.get(path)?;
        // The project-scoped list first: a server configured for this
        // directory is the one this call reached, whatever a server of the
        // same name elsewhere points at.
        cwd.and_then(|c| entry.servers.get(&format!("{c}{SCOPE_SEP}{server}")))
            .or_else(|| entry.servers.get(server))
            .cloned()
    }

    /// Test-only: forget everything, so one test's temp config cannot be read
    /// through another's cached parse.
    #[cfg(test)]
    pub fn clear(&self) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// Every file that can say where an MCP server is, most specific first.
///
/// The list is the union of five tools' conventions rather than a per-source
/// lookup, and deliberately: the tool that *made* the call is known, but a
/// server is routinely configured once and reached from whichever agent is
/// open. Reading a file the calling tool does not use costs a `stat` and can
/// only add a name that is genuinely configured on this machine.
fn candidate_files(cwd: Option<&str>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(cwd) = cwd {
        let dir = Path::new(cwd);
        v.push(dir.join(".mcp.json"));
        v.push(dir.join("opencode.json"));
        v.push(dir.join(".codex").join("config.toml"));
    }
    let home = crate::install::home();
    v.push(home.join(".claude.json"));
    v.push(home.join(".claude").join("settings.json"));
    v.push(home.join(".copilot").join("mcp-config.json"));
    v.push(home.join(".config").join("opencode").join("opencode.json"));
    v.push(home.join(".codex").join("config.toml"));
    v
}

/// One config file's servers, flattened to `name` → endpoint, with
/// project-scoped entries under `<project>\0<name>`.
fn parse(path: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(meta) = std::fs::metadata(path) else {
        return out;
    };
    if meta.len() > MAX_CONFIG_BYTES {
        tracing::debug!(
            "mcp config {} is {} bytes, over the {MAX_CONFIG_BYTES} cap; not read",
            path.display(),
            meta.len()
        );
        return out;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    // TOML and JSON both deserialize into the same tree, so one extractor
    // reads Codex's `config.toml` and everyone else's JSON.
    let doc: Value = if path.extension().is_some_and(|e| e == "toml") {
        match toml::from_str(&text) {
            Ok(v) => v,
            Err(_) => return out,
        }
    } else {
        match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => return out,
        }
    };
    collect(&doc, "", &mut out);
    // Claude Code's local-scope servers — what `claude mcp add` writes by
    // default — live under the project they were added in, not beside the
    // user-scope ones. Skipping them would miss the common case.
    if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
        for (project, v) in projects {
            collect(v, &format!("{project}{SCOPE_SEP}"), &mut out);
        }
    }
    out
}

/// The three spellings of "the server map", from one file into one flat map.
fn collect(doc: &Value, prefix: &str, out: &mut HashMap<String, String>) {
    for key in ["mcpServers", "mcp_servers", "mcp"] {
        let Some(map) = doc.get(key).and_then(Value::as_object) else {
            continue;
        };
        for (name, entry) in map {
            if let Some(ep) = endpoint_of(entry) {
                out.insert(format!("{prefix}{name}"), ep);
            }
        }
    }
}

/// One server entry reduced to where it is, or nothing.
///
/// Nothing is the right answer for an entry this does not understand: a
/// server named with no location is already recorded by `mcp.server`, and
/// inventing a location for it would put something that is not true into the
/// one field that is supposed to say where the fleet reaches.
fn endpoint_of(entry: &Value) -> Option<String> {
    if let Some(url) = entry.get("url").and_then(Value::as_str) {
        return Some(cap(sanitize_url(url)));
    }
    let command = entry.get("command")?;
    let mut parts: Vec<String> = match command {
        // opencode spells a local server as one argv array.
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => return None,
    };
    if let Some(args) = entry.get("args").and_then(Value::as_array) {
        parts.extend(args.iter().filter_map(Value::as_str).map(String::from));
    }
    if parts.is_empty() {
        return None;
    }
    let argv: Vec<String> = parts.iter().map(|p| sanitize_arg(p)).collect();
    // Prefixed so the field answers "local or remote" without a join: a
    // deployment asking which of its agents reach off the machine greps for
    // the ones that are not `stdio:`.
    Some(cap(format!("stdio:{}", argv.join(" "))))
}

/// A URL without the parts that carry credentials.
///
/// Both are cut rather than redacted, because neither is part of *where* the
/// server is: `user:pass@` is who we are to it, and a query string on an MCP
/// endpoint is routinely the whole authentication (`?key=…`). What remains —
/// scheme, host, port, path — is the answer to the question being asked.
fn sanitize_url(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or("");
    let Some((scheme, rest)) = url.split_once("//") else {
        return url.to_string();
    };
    match rest.split_once('@') {
        Some((_userinfo, host)) => format!("{scheme}//{host}"),
        None => url.to_string(),
    }
}

/// An argument whose *name* says it carries a credential, with the value
/// taken out.
///
/// The redactor in [`crate::enrich`] catches secrets by shape, which is what
/// catches a token that looks like one. This catches the other half: an
/// `--api-key=hunter2` is not a shape anything recognises, and the thing that
/// makes it a secret is the word in front of it.
fn sanitize_arg(arg: &str) -> String {
    let Some((name, value)) = arg.split_once('=') else {
        return arg.to_string();
    };
    if value.is_empty() || !secret_named(name) {
        return arg.to_string();
    }
    format!("{name}=[REDACTED:mcp-arg]")
}

fn secret_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "credential",
    ]
    .iter()
    .any(|w| lower.contains(w))
}

fn cap(mut s: String) -> String {
    if s.len() <= MAX_ENDPOINT_BYTES {
        return s;
    }
    // On a char boundary, because the truncation of a multi-byte path must not
    // produce a string that cannot be serialized.
    let mut end = MAX_ENDPOINT_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `ARGUS_HOME` is process-wide, so the tests that set it take one lock and
    /// clear the resolver cache: a second test reading the first one's parse of
    /// a path that no longer exists would pass for the wrong reason.
    fn home_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    #[test]
    fn a_stdio_server_is_the_command_that_runs_it_and_a_remote_one_is_its_url() {
        assert_eq!(
            endpoint_of(&json!({"command": "npx", "args": ["-y", "@mcp/github"]})),
            Some("stdio:npx -y @mcp/github".into())
        );
        // opencode spells the same thing as one argv array.
        assert_eq!(
            endpoint_of(&json!({"type": "local", "command": ["bun", "x", "srv"]})),
            Some("stdio:bun x srv".into())
        );
        assert_eq!(
            endpoint_of(&json!({"type": "remote", "url": "https://mcp.example.com/sse"})),
            Some("https://mcp.example.com/sse".into())
        );
        // An entry that says where it is *and* how to run it is remote: the URL
        // is the end the call actually goes to.
        assert_eq!(
            endpoint_of(&json!({"url": "https://a.example/x", "command": "npx"})),
            Some("https://a.example/x".into())
        );
        // Nothing to say beats something invented.
        for silent in [
            json!({"env": {"TOKEN": "abc"}}),
            json!({"command": []}),
            json!({"command": 7}),
            json!({}),
        ] {
            assert_eq!(endpoint_of(&silent), None, "{silent}");
        }
    }

    /// The endpoint is where the server is, and neither of these is: one is who
    /// we are to it and the other is how we prove it.
    #[test]
    fn a_url_keeps_its_location_and_loses_its_credentials() {
        for (url, want) in [
            (
                "https://u:p@mcp.example.com/sse",
                "https://mcp.example.com/sse",
            ),
            (
                "https://mcp.example.com/sse?key=hunter2",
                "https://mcp.example.com/sse",
            ),
            (
                "https://mcp.example.com/sse#frag",
                "https://mcp.example.com/sse",
            ),
            ("https://tok@mcp.example.com", "https://mcp.example.com"),
            (
                "https://mcp.example.com:8443/x",
                "https://mcp.example.com:8443/x",
            ),
            ("not a url", "not a url"),
        ] {
            assert_eq!(sanitize_url(url), want, "{url}");
        }
    }

    /// A token in an argument is not a shape any redactor recognises — what
    /// makes it a secret is the word in front of it.
    #[test]
    fn an_argument_that_says_it_is_a_credential_loses_its_value() {
        let got = endpoint_of(&json!({
            "command": "srv",
            "args": ["--api-key=hunter2", "--TOKEN=x", "--port=8080", "--url=https://a.example",
                     "--flag", "--token=", "@scope/pkg"]
        }))
        .unwrap();
        // `--port` and `--url` keep their values: they say where the server is,
        // which is the question. `--token=` keeps its empty one — blanking a
        // value that is already absent only invents a credential.
        assert_eq!(
            got,
            "stdio:srv --api-key=[REDACTED:mcp-arg] --TOKEN=[REDACTED:mcp-arg] --port=8080 \
             --url=https://a.example --flag --token= @scope/pkg"
        );
    }

    /// Three-byte characters, deliberately: the cap is not a multiple of three,
    /// so a cut that ignores boundaries lands inside one — and `truncate`
    /// panics rather than producing something a serializer would reject.
    #[test]
    fn a_long_command_line_is_cut_on_a_character_boundary() {
        assert_ne!(MAX_ENDPOINT_BYTES % 3, 0, "the padding no longer straddles");
        let long = "€".repeat(MAX_ENDPOINT_BYTES);
        let got = cap(long);
        assert!(got.len() <= MAX_ENDPOINT_BYTES + '…'.len_utf8());
        assert!(got.ends_with('…'));
        assert!(got.trim_end_matches('…').chars().all(|c| c == '€'));
        assert_eq!(cap("short".into()), "short");
    }

    /// Five tools, four config dialects, one question.
    #[test]
    fn every_dialect_a_host_tool_writes_is_read() {
        let _g = home_lock();
        let home = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ARGUS_HOME", home.path()) };
        resolver().clear();

        write(
            &home.path().join(".claude.json"),
            &json!({"mcpServers": {"userwide": {"command": "npx", "args": ["srv"]},
                                   "dup": {"url": "https://user-scope.example/mcp"}},
                    "projects": {proj.path().to_str().unwrap():
                                 {"mcpServers": {"local": {"url": "https://local.example/mcp"},
                                                 "dup": {"url": "https://this-project.example/mcp"}}}}})
            .to_string(),
        );
        write(
            &home.path().join(".copilot").join("mcp-config.json"),
            &json!({"mcpServers": {"cop": {"command": "cop-srv"}}}).to_string(),
        );
        write(
            &home
                .path()
                .join(".config")
                .join("opencode")
                .join("opencode.json"),
            &json!({"mcp": {"oc": {"type": "local", "command": ["oc-srv", "--x"]}}}).to_string(),
        );
        write(
            &home.path().join(".codex").join("config.toml"),
            "[mcp_servers.cdx]\ncommand = \"cdx-srv\"\nargs = [\"--stdio\"]\n",
        );
        write(
            &proj.path().join(".mcp.json"),
            &json!({"mcpServers": {"scoped": {"url": "https://proj.example/mcp"}}}).to_string(),
        );

        let cwd = proj.path().to_str().unwrap();
        let r = resolver();
        assert_eq!(
            r.endpoint("userwide", Some(cwd)).as_deref(),
            Some("stdio:npx srv")
        );
        assert_eq!(
            r.endpoint("local", Some(cwd)).as_deref(),
            Some("https://local.example/mcp")
        );
        assert_eq!(
            r.endpoint("cop", Some(cwd)).as_deref(),
            Some("stdio:cop-srv")
        );
        assert_eq!(
            r.endpoint("oc", Some(cwd)).as_deref(),
            Some("stdio:oc-srv --x")
        );
        assert_eq!(
            r.endpoint("cdx", Some(cwd)).as_deref(),
            Some("stdio:cdx-srv --stdio")
        );
        assert_eq!(
            r.endpoint("scoped", Some(cwd)).as_deref(),
            Some("https://proj.example/mcp")
        );
        // One file, one name, two answers: the entry filed under this project
        // is the one this call reached.
        assert_eq!(
            r.endpoint("dup", Some(cwd)).as_deref(),
            Some("https://this-project.example/mcp")
        );
        assert_eq!(
            r.endpoint("dup", None).as_deref(),
            Some("https://user-scope.example/mcp")
        );
        // A server nobody configured has no endpoint, and a project-scoped one
        // is not visible from outside its project.
        assert_eq!(r.endpoint("nowhere", Some(cwd)), None);
        assert_eq!(r.endpoint("scoped", None), None);

        unsafe { std::env::remove_var("ARGUS_HOME") };
        resolver().clear();
    }

    /// Same name, two files. The one the agent was running under wins, because
    /// that is the server the call actually reached.
    #[test]
    fn a_project_server_beats_a_user_wide_one_of_the_same_name() {
        let _g = home_lock();
        let home = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ARGUS_HOME", home.path()) };
        resolver().clear();

        write(
            &home.path().join(".claude.json"),
            &json!({"mcpServers": {"github": {"url": "https://user.example/mcp"}}}).to_string(),
        );
        write(
            &proj.path().join(".mcp.json"),
            &json!({"mcpServers": {"github": {"url": "https://project.example/mcp"}}}).to_string(),
        );

        assert_eq!(
            resolver()
                .endpoint("github", Some(proj.path().to_str().unwrap()))
                .as_deref(),
            Some("https://project.example/mcp")
        );
        assert_eq!(
            resolver().endpoint("github", None).as_deref(),
            Some("https://user.example/mcp")
        );

        unsafe { std::env::remove_var("ARGUS_HOME") };
        resolver().clear();
    }

    /// `~/.claude.json` is megabytes and a live session rewrites it constantly,
    /// so re-reading it per event would re-parse it per event. The cost of the
    /// floor is this: a server added a moment ago is not named yet.
    #[test]
    fn a_config_file_is_not_re_read_for_every_event() {
        let _g = home_lock();
        let home = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("ARGUS_HOME", home.path()) };
        resolver().clear();
        let cwd = proj.path().to_str().unwrap();

        let path = proj.path().join(".mcp.json");
        write(
            &path,
            &json!({"mcpServers": {"first": {"url": "https://a.example/mcp"}}}).to_string(),
        );
        assert_eq!(
            resolver().endpoint("first", Some(cwd)).as_deref(),
            Some("https://a.example/mcp")
        );

        write(
            &path,
            &json!({"mcpServers": {"first": {"url": "https://b.example/mcp"}}}).to_string(),
        );
        assert_eq!(
            resolver().endpoint("first", Some(cwd)).as_deref(),
            Some("https://a.example/mcp"),
            "the file was parsed again within the re-check window"
        );

        unsafe { std::env::remove_var("ARGUS_HOME") };
        resolver().clear();
    }

    /// A config file argus cannot read is a config file with no servers in it,
    /// not a reason for the daemon to stop enriching.
    #[test]
    fn an_unreadable_or_oversized_config_names_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(parse(&missing).is_empty());

        let broken = dir.path().join("broken.json");
        write(&broken, "{ not json");
        assert!(parse(&broken).is_empty());

        let broken_toml = dir.path().join("broken.toml");
        write(&broken_toml, "not = = toml");
        assert!(parse(&broken_toml).is_empty());

        let huge = dir.path().join("huge.json");
        write(
            &huge,
            &json!({"mcpServers": {"x": {"command": "srv"},
                                   "pad": {"command": "x".repeat(MAX_CONFIG_BYTES as usize)}}})
            .to_string(),
        );
        assert!(parse(&huge).is_empty(), "an oversized file was read");
    }

    /// `env` is where the credentials are, and it is the one key this never
    /// looks at — not to redact it, not to hash it.
    #[test]
    fn the_env_block_is_never_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        write(
            &path,
            &json!({"mcpServers": {"gh": {"command": "srv",
                                          "env": {"GITHUB_TOKEN": "ghp_supersecretvalue"}}}})
            .to_string(),
        );
        let got = parse(&path);
        assert_eq!(got.get("gh").map(String::as_str), Some("stdio:srv"));
        assert!(
            !got.values().any(|v| v.contains("supersecret")),
            "an env value reached an endpoint: {got:?}"
        );
    }
}
