# Capture and enrichment

The four opt-in and always-on enrichment stages that turn a bare tool call
into an investigable record: file contents, network connections, MCP server
identity, and the cloud credentials the agent was holding.

## File-content capture

A tool call records that `Write` touched `src/deploy.rs` — not what it
wrote, the question an investigation actually asks. Enabling this adds a
`file_contents` array to tool events: per file, the path, the action
(`read`, `written`, `edited`, `patched`), the byte source (`payload` or
`disk`), size, mtime, `sha256`, and the content when policy allows.

**Off by default**, deliberately: it's the one setting that turns an audit
trail into a copy of source code.

```toml
[capture.file_contents]
enabled = true
```

| Key                                     | Default                                                                                  | Meaning                                                                                                                                                                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `capture.file_contents.enabled`         | `false`                                                                                  | Master switch. Off means no `file_contents` key at all, not an empty array on every call.                                                                                                                                       |
| `capture.file_contents.mode`            | `payload`                                                                                | Byte source. `payload`: only what the hook already carried (a `Write`'s content, an `Edit`'s two halves, a patch body) — exact, race-free, **zero I/O**. `disk`: read the file. `both`: payload when available, disk otherwise. |
| `capture.file_contents.include`         | `[]`                                                                                     | Path regexes. Empty means no restriction — a non-matching `include` would silently capture nothing.                                                                                                                             |
| `capture.file_contents.exclude`         | `node_modules`, `.git`, `*.lock`/`*.min.js`, `.env*`, `*.pem`, `.ssh/`, `*_rsa`, `*.p12` | Regexes applied after `include`; ties go to exclusion. A custom list **replaces** the default, not adds to it.                                                                                                                  |
| `capture.file_contents.max_bytes`       | `32768`                                                                                  | Per file. A payload body over this is truncated; a disk file over it is measured, never read. Also bounded by `capture.max_field_bytes`.                                                                                        |
| `capture.file_contents.max_files`       | `10`                                                                                     | Per event — one `apply_patch` across forty files cannot become forty bodies in one record.                                                                                                                                      |
| `capture.file_contents.max_total_bytes` | `262144`                                                                                 | Per event, across all files, shared by both halves — `both` isn't quietly twice this budget.                                                                                                                                    |
| `capture.file_contents.skip_binary`     | `true`                                                                                   | Drops non-text content: invalid UTF-8, or a control byte other than tab/CR/LF in the first 8 KiB. Metadata still recorded.                                                                                                      |
| `capture.file_contents.hash`            | `true`                                                                                   | Records `sha256`, size, mtime **even when content is withheld** — keeps an excluded file visible as _touched_ and comparable across captures.                                                                                   |
| `capture.file_contents.read_timeout_ms` | `2000`                                                                                   | Max time one file's stat-and-read may take before it's marked unreadable. `0` waits forever.                                                                                                                                    |

Every named file appears in the record, whether or not its content does. A
withheld body carries a `skipped` reason — `excluded`, `too_large`, `binary`,
`budget`, `unreadable` — exported as an attribute, so over-exclusion is
visible rather than looking like a quiet week.

`include`/`exclude` matching is case-insensitive on Windows and macOS and
case-sensitive on Linux, following each platform's default filesystem: a
`.ssh/` rule excludes `.SSH/` too where the filesystem itself treats them as
the same directory, and leaves them distinct where it doesn't.

What the disk half will not do:

- **Follow a symlink.** `/tmp/x -> ~/.ssh/id_rsa` is the oldest trick for
  getting a privileged reader to fetch something on your behalf, and it
  slips past an `exclude` list that only matches the path the _agent_ named.
  The stat refuses the link; the open refuses it again (`O_NOFOLLOW`), since
  swapping the path between those two syscalls is the whole point of the
  gap. A refused link is reported without even its target's size.
- **Open anything that is not a regular file.** `read()` on a fifo never
  returns; a daemon that opened one would stop enriching events entirely.
- **Read a file bigger than the cap.** It's measured, not truncated: reading
  2 GiB off disk to keep 32 KiB is I/O for a prefix you couldn't see anyway.
  Size and mtime are still reported.
- **Ship the contents of an excluded file.** With `hash = true` an excluded
  file is opened, hashed, and its bytes dropped — the digest is what makes
  one `.env` the same `.env` across forty sessions. With `hash = false` it's
  never opened at all.
- **Wait forever.** A read that stops returning — a network mount that goes
  away mid-read — is abandoned after `read_timeout_ms` and marked unreadable.
  Nothing here can _cancel_ that read (a thread parked in the kernel isn't
  interruptible from userspace); the deadline just bounds the blast radius,
  so one dead mount costs one stuck thread, not every event behind it.

Captured bodies pass through the redactor like any other field, before
buffering or export. Two consequences:

- `sha256` hashes the bytes the tool actually handled, not the scrubbed
  copy — a digest of a redaction marker would match nothing.
- A truncated body carries no digest at all, for the same reason.

One interaction worth knowing: `capture.tool_inputs = false` disables file
capture entirely, both halves. A call's files come from its input, so an
event with no input has none to read — even for `disk` mode, which needs
the path but not the body. The `files` list is unaffected: such an event
still _names_ every file and describes none.

`disk` mode reads the file a moment _after_ the tool acted, so it records
the resulting state, not necessarily what the tool wrote — it can therefore
show a change the tool didn't make, like a formatter running afterwards.
`payload` mode is the opposite: exact, but no I/O. `both` answers "what does
this file look like now" for a call that named a file without quoting it.

That phrase means the read family specifically — a tool whose name says it
read the file. A `Grep`'s `path` is a directory to search, and a `Bash`'s
`command` isn't a path at all, so neither yields anything to capture in any
mode: opening those would spend I/O on strings never claimed to be files,
chosen by the agent being monitored.

## Network extraction

Every tool call is scanned for the connections it names. The result lands in
two arrays — `fqdns`, the bare hostnames, and `endpoints`,
`scheme://host[:port]` for each that came with a protocol — exported as
`net.fqdns` and `net.endpoints`.

The scan walks the whole input rather than a fixed list of keys: an MCP
tool's arguments are arbitrary nested JSON, and a URL is as likely in a
header, a body, or an `argv` element as in a top-level `url`. Any
`scheme://host` matches, not only `http(s)` — `ssh://`, `ftp://`,
`postgres://`, `git+ssh://` are the same question with a different prefix.

A value under `command`, `cmd` or `script` is read a second way, as a shell
command, since a command names hosts without ever writing a scheme. If the
program is a known network client (`curl`, `git`, `ssh`, `psql`, `kubectl`,
…), its dotted arguments are hosts and `user@host:path` is an scp target.

A registry or proxy flag (`--index-url`, `--extra-index-url`, `--registry`,
`--trusted-host`, `--proxy`, `--repository-url`) is read whatever the program
is. That is the point of it: `pip` and `npm` are not network clients, and
`pip install --index-url pypi.internal/simple pkg` is exactly the redirected
fetch worth seeing. The flag is what makes the value a host, so no guess
about the program is needed.

Two limits are deliberate:

- **A schemeless host is believed only inside a network command, or after a
  flag that names one.** Prose, diffs and error messages are full of dotted
  tokens — `crates.io`, `main.rs`, `v1.2.3` — and a `|` or `&&` starts a new
  command whose own first word has to earn it again. A hostname invented from
  prose is a connection the agent never made, sitting in the one field a
  reviewer trusts to be literal.
- **An endpoint keeps the scheme and the stated port, nothing else.** A port
  is recorded only when the call wrote one down, so `:443` always means "the
  agent chose 443," not "the scheme's default." Path and query are dropped
  rather than sanitized: a presigned URL carries its credential in the query
  string, so a field that holds paths eventually holds a secret.

IPv6 literals are out of scope.

The result of a call is scanned too, into its own pair — `output_fqdns` and
`output_endpoints`, exported as `net.output_fqdns` and `net.output_endpoints`.
That's where a followed redirect or a search result's host shows up. They
stay separate from `fqdns` because a result is content the agent fetched, not
an instruction it issued: merged, any page with a link on it would pollute
the field meant to answer "what did this call connect to." For the same
reason, results are scanned only for URLs, not read as commands — a result
quoting a `curl` line is quoting, not running. Hosts the input already named
are subtracted, so these fields hold only what the request didn't say, and
they're filled even when `tool_outputs` capture is off: which hosts a call
touched is metadata, independent of storing the output text.

## MCP servers

An MCP tool is code the agent's vendor didn't write, reached over a
connection nothing else in the record describes — so a call to one is
recorded with the server it went to, as `mcp.server` (`mcp_server` in the
event body). The name is read off the tool: `mcp__github__create_issue` is
the `github` server. It's stamped on permission prompts too, not just calls:
a call asked about and refused is the same third-party reach as one that
ran, and a server appearing only in denials is the more interesting of the
two.

Only the `mcp__<server>__<tool>` spelling is believed. Looser conventions — a
`-` or a single `_` between server and tool — split an ordinary tool name
just as cleanly as an MCP one, and a server invented from `write_file` would
add something that doesn't exist to the inventory of what the fleet reaches.

### Where the server is

A name isn't a location. `github` is either a package running as a child
process on this machine, or an HTTPS endpoint belonging to whoever controls
that hostname — an inventory that can't tell those apart isn't one. With
`capture.mcp_endpoints = true`, a call also carries `mcp.endpoint`
(`mcp_endpoint` in the event body): the server's URL if remote, or
`stdio:<command args>` if local. One field rather than two, prefixed, so
"which of my agents reach off this machine" is a query for the rows that
aren't `stdio:`, not a join.

It's resolved from the host tools' own config files. The first one that names
the server wins, and they are consulted in this order:

1. `.mcp.json`, beside the project
2. `opencode.json`, beside the project
3. `.codex/config.toml`, beside the project
4. `~/.claude.json` (including per-project servers `claude mcp add` writes by
   default)
5. `~/.claude/settings.json`
6. `~/.copilot/mcp-config.json`
7. `~/.config/opencode/opencode.json`
8. `~/.codex/config.toml`

A project file wins over a user-wide one of the same name, since that's the
server the call actually reached. All eight are consulted regardless of which
tool made the call: a server is configured once and reached from whichever
agent is open. Reading a file the calling tool doesn't use costs a `stat` and
can only add a name genuinely configured on this machine.

Off by default, because those files sit next to credentials. Three rules
follow:

- The `env` block is never read — not redacted, not hashed, never looked at.
- A URL loses its userinfo and query string, both authentication rather than
  location.
- An argument whose _name_ says credential (`--api-key=…`) loses its value,
  then the ordinary redactor runs over the result, catching by shape what
  that catches by name.

Files over 4 MiB are skipped and endpoints are capped at 512 bytes.

Each file is re-read at most every 15 seconds rather than per event —
`~/.claude.json` is megabytes and a live session rewrites it continuously.
A server added mid-session is named a few seconds later: a small staleness
traded for not re-parsing a multi-megabyte file on every event.

## Cloud identity

An event says an agent ran `terraform apply`. What an incident actually needs
to know is _as whom_ — which role, which account, which cluster. Nothing in
a hook payload carries that; the environment does, and the hook shim is
spawned by the agent and inherits it.

So the shim reads it, and every event from that envelope carries it as
`cloud.*` attributes — indexable, groupable, joinable against the provider's
own audit log:

```
cloud.aws.role_arn        = arn:aws:iam::123456789012:role/prod-admin
cloud.aws.account_id      = 123456789012
cloud.aws.sso_role_name   = AdministratorAccess
cloud.aws.region          = eu-west-1
cloud.azure.subscription_id, cloud.azure.tenant_id, cloud.azure.client_id
cloud.gcp.project, cloud.gcp.account, cloud.gcp.credentials_file
cloud.k8s.api_host, cloud.k8s.kubeconfig, cloud.k8s.context
cloud.vault.addr, cloud.vault.namespace
cloud.github.repository, cloud.cloudflare.account_id, cloud.doppler.project, …
```

Two disjoint kinds of variable, and the split is the whole design:

- **Identifiers** are an explicit allowlist, captured **by value**. Each is
  something the provider already writes into its own audit log: a role ARN,
  an account id, a project, a profile name, an access key **id**. They say
  who the agent was; none of them authenticates as anyone.
- **Credentials** are anything whose _name_ says it holds secret material
  (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_API_KEY`, `*_PRIVATE_KEY`, …). Only
  the **name** is recorded — the value is never read. They arrive as one
  attribute, `cloud.credentials_present=AWS_SECRET_ACCESS_KEY,GITHUB_TOKEN`,
  answering "what did this session have in scope" for free.

Anything matching neither is ignored. An agent's environment on a
developer's machine holds their entire shell, and shipping it wholesale
would be the largest thing a monitoring tool had to defend. The allowlist is
deliberately not exhaustive, and no heuristic ever inspects a _value_: a
provider argus doesn't know yet is a missing attribute, never a leaked one.

**The files behind the variables.** `AWS_PROFILE=prod` says which profile,
not which role — the role lives in `~/.aws/config` under `[profile prod]`.
So the same two files an SDK beside the agent would resolve are read as well:

- `~/.aws/config` (or `AWS_CONFIG_FILE`), the section the environment
  selects, defaulting to `[default]` exactly as the SDKs do → `role_arn`,
  `role_session_name`, `sso_account_id`, `sso_role_name`, `region`.
- gcloud's application-default credentials — `GOOGLE_APPLICATION_CREDENTIALS`,
  else `CLOUDSDK_CONFIG`, else the well-known path → `client_email`,
  `project_id`, `quota_project_id`, `type` (service account, user, federated).

Same rule as the environment: an explicit list of identifying fields, no
credential. The ADC document's `private_key` and `refresh_token` aren't on
the list, and `~/.aws/credentials` — the file holding the secret access
key — is never opened at all. A variable always outranks a file, since a
variable is what the agent's process was told and a file only what would be
resolved from it. Reads are capped at 256 KiB, happen once per process, and
are silent on failure: this is the agent's hot path, so a missing or
unreadable file costs an attribute, never an event.

The read happens as close to the agent as possible, since that's the only
place its environment exists — the daemon was started from somewhere else
entirely, and its own environment describes whoever started it. For Claude
Code, Copilot CLI and Codex's `notify`, that's the hook shim; for opencode
and pi it's the plugin itself, which writes its own envelope over the
socket and falls back to the shim only otherwise. The two allowlists are
pinned to each other by a test, so one can't drift from the other.

The _policy_ is applied in the daemon: `capture.cloud_identity = false` in
fleet config switches it off everywhere without reinstalling a single hook.

**One channel can't carry it.** Codex's `[otel]` export posts to the daemon
over HTTP from Codex's own process, so those records arrive with no
identity attached, though the same session's `notify` events do carry one.
Nothing can be inferred for the HTTP path without labelling an agent's
telemetry with whatever credentials the daemon's own environment happens to
hold — worse than the gap.

---

Back to the [project README](../README.md).
