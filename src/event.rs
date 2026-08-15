use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Raw frame sent by the hook shim or a plugin. Neither parses tool payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub source: String,
    pub received_at: DateTime<Utc>,
    /// Optional event-name hint passed as `--event` by installs whose tool
    /// payloads carry no event-name field (Copilot's camelCase payloads).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Set when the shim's stdin hit `hook::MAX_STDIN_BYTES` and the tail was
    /// discarded. Travels with the envelope rather than being reported from
    /// the shim, because the shim is a short-lived process on the host tool's
    /// critical path: it has no buffer, no exporter and no business making a
    /// second IPC round trip to say that the first one was incomplete.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// How many older spooled envelopes were deleted to make room for this
    /// one. Rides along for the same reason `truncated` does: the shim that
    /// notices the deletion has no way to report it, and this envelope is
    /// already on its way to somebody who does.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dropped: u64,
    /// Which cloud identity the agent held when it fired this hook.
    ///
    /// Collected wherever the envelope is built, never in the daemon: the shim
    /// is a child of the host agent and inherits its environment, and the
    /// plugins run inside the agent's own process, where the daemon's
    /// environment describes only whoever started the daemon. So the shim
    /// fills it for Claude Code, Copilot and Codex's `notify`, and
    /// `plugins/shared/transport.ts` fills it for opencode and pi. One channel
    /// cannot: the Codex OTLP receiver is handed HTTP requests from Codex's own
    /// process, with no environment of the agent's to read.
    ///
    /// Defaulted rather than optional so an older spooled envelope, or one
    /// from a plugin that never learned the field, deserializes as "nothing
    /// known" instead of failing.
    #[serde(
        default,
        skip_serializing_if = "crate::cloudid::CloudIdentity::is_empty"
    )]
    pub cloud_identity: crate::cloudid::CloudIdentity,
    pub payload: serde_json::Value,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Cross-tool context attached to every event. Adapters populate whatever
/// their hook surface exposes; all fields optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_path: Option<String>,
    /// The host tool's own id for one tool call. The pre-event and the
    /// post-event of a single call carry the same one, which is the only way
    /// to pair them: two `Bash` calls in a turn are otherwise indistinguishable,
    /// so without this a `pre` that never got its `post` — a call that hung, or
    /// was killed — cannot be told from one that completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    /// How hard the model was asked to think on this turn. Not a performance
    /// note: it is a knob the *prompt* can move, so a session that quietly
    /// drops to the cheapest setting before doing something sensitive is a
    /// thing worth being able to see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// The MCP server a tool call went to, when the tool's name says so.
    ///
    /// An MCP tool is code the agent's own vendor did not write, reached over
    /// a connection nothing else in this record describes — so "which server"
    /// is a different question from "which tool", and the one an inventory of
    /// third-party reach is asking. Without it every `mcp__*` call is an
    /// ordinary tool row and the servers are countable only by string
    /// surgery in the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    /// Where that server is: an `https://…` for a remote one, or
    /// `stdio:<command args>` for a package running as a child process.
    ///
    /// `mcp_server` is a name the host tool chose, and a name is not a
    /// location — `github` is either a vendor's endpoint or somebody's fork
    /// running locally, and an inventory of third-party reach that cannot tell
    /// those apart is not one. Resolved from the tools' own config files by
    /// [`crate::mcpcfg`] and off by default, because that means reading a file
    /// the agent never sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_endpoint: Option<String>,
}

impl Meta {
    pub fn is_empty(&self) -> bool {
        *self == Meta::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub username: String,
    pub source: String,
    pub session_id: Option<String>,
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Meta::is_empty")]
    pub meta: Meta,
    /// Who the agent was to the outside world when this happened.
    ///
    /// Stamped in [`crate::harness::parse`] from the envelope rather than by
    /// each adapter, for the same reason `ts` is: an adapter that forgot would
    /// lose it silently, and the gap would look like an agent that simply held
    /// no credentials.
    #[serde(
        default,
        skip_serializing_if = "crate::cloudid::CloudIdentity::is_empty"
    )]
    pub cloud_identity: crate::cloudid::CloudIdentity,
    #[serde(flatten)]
    pub kind: EventKind,
}

/// What one file looked like at the moment a tool touched it.
///
/// Metadata and content are deliberately separable. The default `exclude` list
/// keeps `.env`, keys and lockfiles out of *content* while still recording
/// that they were read or written — "an agent opened your SSH key" is the
/// finding, and it does not require shipping the key to reach it. So `path`,
/// `action` and `source` are recorded whatever becomes of `content`, and
/// `skipped` says which rule made that call rather than leaving the omission
/// indistinguishable from a file that was empty.
///
/// The rest is narrower, and the difference is where the bytes came from. A
/// disk snapshot stats the file before deciding anything, so an excluded one
/// still carries its size and mtime, and — when `hash` is on, which is what
/// opens it at all — its digest. A payload snapshot has no stat to reuse: its
/// `bytes` is the length of what the tool said it would write, and an exclusion
/// stops it before the digest. A file nothing could be learned about at all,
/// `unreadable`, reports zero bytes, because zero is what was measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: String,
    pub action: FileAction,
    /// Size of the file as touched, not of `content` — those differ whenever
    /// `truncated` is set, and the difference is the point.
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<DateTime<Utc>>,
    /// Where the bytes came from. A payload snapshot is exactly what the tool
    /// said it would write; a disk snapshot is what was there when the daemon
    /// looked, which is a slightly later and racier question.
    pub source: SnapshotSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<SkipReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAction {
    Written,
    Edited,
    Read,
    Patched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSource {
    Payload,
    Disk,
}

/// Why `content` is absent. A closed set rather than a free-form string: these
/// are what a query groups by when asking "what is this deployment not
/// capturing, and is that the config or a failure?"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// An `exclude` pattern matched, or `include` did not.
    Excluded,
    Binary,
    TooLarge,
    /// Missing, unreadable, a symlink, or the read timed out.
    Unreadable,
    /// The per-event file or byte budget was already spent.
    Budget,
}

/// `ToolUse` is much larger than the other variants and is meant to be: it is
/// the kind that carries the whole record of a call — input, output, files,
/// hosts, contents — while `Prompt` carries a string. Boxing a field to get
/// under clippy's 200-byte spread would buy nothing here. An event is
/// constructed once per hook invocation, moved a handful of times, and
/// serialised; at that rate the few hundred bytes a `Prompt` wastes by sharing
/// a layout with `ToolUse` are far cheaper than an indirection on the field
/// every consumer pattern-matches. Boxing would also hide the growth rather
/// than stop it — the spread crosses the threshold again a field or two later.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Prompt {
        text: String,
    },
    /// Something between the user and the model rewrote the prompt.
    ///
    /// Kept separate from [`EventKind::Prompt`] rather than replacing it,
    /// because the two answer different questions and an audit trail needs
    /// both: what the human asked for, and what was actually sent on their
    /// behalf. A hook, a plugin or an enterprise policy sits in that gap, and
    /// an instruction inserted there is invisible in every other record of the
    /// session — the user never typed it and the transcript shows the model
    /// obeying it. Both halves ride in one event so the comparison needs no
    /// join and survives the other hook not firing.
    PromptTransformed {
        original: String,
        transformed: String,
    },
    AssistantMessage {
        text: String,
    },
    ToolUse {
        tool: String,
        phase: String, // "pre" | "post" | "error"
        input: serde_json::Value,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        output: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// Wall-clock time the call took, as the host tool measured it. On the
        /// `pre` leg there is nothing to measure yet, so it is absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// The call ended because a human stopped it, not because it failed.
        /// Worth separating: an interrupted `Bash` may have run half its
        /// command, which reads as a failure but is not one.
        #[serde(default, skip_serializing_if = "is_false")]
        interrupted: bool,
        files: Vec<String>,
        fqdns: Vec<String>,
        /// `scheme://host[:port]` for each connection the call named with a
        /// protocol. `fqdns` answers "which host"; this answers "which
        /// service, on which port" — the difference between an agent reading
        /// documentation and one posting to `:8443`.
        ///
        /// `serde(default)` for the same reason as `file_contents`: a daemon
        /// reading its own older buffer must not choke on a row written before
        /// the field existed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        endpoints: Vec<String>,
        /// Hosts the call's *result* named that its input did not — the
        /// redirect that was followed, the host a search result pointed at,
        /// the endpoint an error message quoted.
        ///
        /// Kept apart from `fqdns` rather than merged into it, because the two
        /// are different claims. `fqdns` is what the agent asked for;
        /// `output_fqdns` is what came back, and what comes back includes every
        /// link on a page the agent merely read. Merging them would let a
        /// fetched document put hostnames into the field a reviewer uses to
        /// answer "what did this agent connect to".
        ///
        /// Present on `post` legs only, and only for what the input did not
        /// already say — a result usually echoes the URL it was handed.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        output_fqdns: Vec<String>,
        /// `scheme://host[:port]` for the same, on the same terms.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        output_endpoints: Vec<String>,
        /// What the files in this call actually contained.
        ///
        /// `serde(default)` is what keeps rows already sitting in a buffer
        /// readable after an upgrade: the daemon that reads them may be newer
        /// than the one that wrote them, and a buffer that cannot be drained
        /// is a buffer that grows until the disk cap deletes evidence.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        file_contents: Vec<FileSnapshot>,
    },
    Skill {
        name: String,
        args: Option<String>,
    },
    Agent {
        agent_type: String,
        description: Option<String>,
    },
    Permission {
        tool: String,
        action: String, // "requested" | "denied" | "replied"
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        input: serde_json::Value,
    },
    Notification {
        message: String,
        category: String,
        /// The short label shown above `message`. Optional in the payload and
        /// often the only part a human reads, so a record that keeps the body
        /// and drops this one describes a different notification than the one
        /// that appeared on screen.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    Compact {
        phase: String,   // "pre" | "post"
        trigger: String, // "manual" | "auto"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tokens_before: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tokens_after: Option<u64>,
        /// What the compaction was told to keep or leave out.
        ///
        /// Compaction is the one point where the session's own history is
        /// rewritten, and these instructions decide what survives the rewrite.
        /// "Summarize the work but leave out the credentials I used" is a
        /// reasonable thing for a developer to type and an unreasonable thing
        /// for an audit trail to lose: after the compaction the transcript no
        /// longer holds what was dropped, so the request to drop it is the
        /// only remaining evidence.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        instructions: Option<String>,
    },
    FileChange {
        path: String,
        action: String,
    },
    Error {
        message: String,
        context: String,
        /// The error's own type, where the host tool reports one separately
        /// from the prose. `context` says which part of the system failed
        /// (`model_call`, `tool_execution`, …) and this says what failed
        /// there — the two together are what makes an error groupable across
        /// sessions, which a free-text message never is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Whether the host tool expects to carry on. The distinction is the
        /// whole difference between a retried blip and a session that stopped
        /// working, and both arrive here looking identical otherwise. `None`
        /// where the tool does not say.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recoverable: Option<bool>,
    },
    Session {
        action: String,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        detail: serde_json::Value,
    },
    /// What one assistant turn consumed, as the host tool accounts for it.
    ///
    /// Not billing trivia. Token volume is the cheapest signal that separates
    /// a session doing real work from one looping on the same failure, and
    /// spend per session is the number that makes an exfiltration-by-a-
    /// thousand-prompts pattern visible at all. The model itself rides in
    /// `meta.model`, because "which model saw this" is a question asked of
    /// every event, not only of the one carrying the receipt.
    ///
    /// Counts are separate fields rather than a JSON blob so they can be
    /// summed without parsing, and the cache legs are separate from the rest
    /// because they are the difference between a long session that is cheap
    /// and one that is not.
    Usage {
        input_tokens: u64,
        output_tokens: u64,
        /// Tokens spent thinking rather than answering. Priced differently by
        /// most providers, and a turn that reasons at length before acting is
        /// a different shape of turn.
        reasoning_tokens: u64,
        cache_read_tokens: u64,
        cache_write_tokens: u64,
        /// The host tool's own figure, in the host tool's own currency.
        /// Recorded rather than derived: a price table living in argus would
        /// be wrong the week after a provider changed one.
        cost: f64,
        /// Why the turn stopped, where the tool says. A turn cut off by a
        /// token ceiling costs the same as one that finished and means
        /// something entirely different.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finish: Option<String>,
    },
    Raw {
        payload: serde_json::Value,
    },
    /// Self-check on the daemon's own hook/plugin wiring. `status` is "ok" or
    /// "broken"; a broken finding means capture for `tool` is (partly) blind —
    /// the wiring was removed or altered. Emitted by the integrity loop.
    Integrity {
        status: String,
        tool: String,
        detail: String,
    },
    /// Events this daemon destroyed rather than delivered.
    ///
    /// Silent loss is the failure mode a monitoring tool cannot afford: a
    /// buffer that quietly discards its oldest rows under load looks exactly
    /// like a quiet afternoon, and the periods most likely to overflow it are
    /// the periods most worth having. `reason` is the mechanism; `count` is
    /// how many events the gap accounts for — destroyed outright, or, for a
    /// payload cut off at the shim's stdin cap, delivered incomplete.
    Loss {
        reason: String,
        count: u64,
        detail: String,
    },
    /// The daemon saying it is still here, and under what conditions.
    ///
    /// Every other event in this enum describes something the host tool did.
    /// This one describes argus, and it is the only event emitted when nothing
    /// happens at all — which is the point. A monitoring tool's failures are
    /// *silent*: a killed daemon, a deleted data directory, a firewall rule
    /// against the collector and a laptop nobody opened all produce exactly the
    /// same thing at the SIEM, which is nothing. A heartbeat turns three of
    /// those four into an alertable absence, and carries with it the state a
    /// responder would otherwise have to go to the endpoint to read.
    ///
    /// Deliberately unconditional. The integrity loop reports only what is
    /// broken, because a per-tool "still fine" every hour is noise; but that
    /// leaves "nothing is broken" and "no check has run since the daemon died"
    /// indistinguishable, and `checks_age_secs` is what separates them.
    Health {
        /// `startup`, `interval`, or `shutdown`. A graceful stop is a record
        /// rather than a silence; a `SIGKILL` still falls through to absence.
        reason: String,
        /// This install's identity. A new one under a known `host.name` is a
        /// wiped data directory — see [`crate::buffer::Buffer::install_id`].
        install_id: String,
        version: String,
        uptime_secs: u64,
        /// How long ago the integrity summary below was taken. `None` means no
        /// check has completed yet in this process.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checks_age_secs: Option<u64>,
        /// Tools checked and found intact.
        checks_ok: u32,
        /// `tool: detail` for everything currently broken, bounded — the list
        /// is a summary, and the integrity events carry each finding in full.
        broken: Vec<String>,
        /// Identifies the config the daemon is *running on*, not the file on
        /// disk: a policy edited but not reloaded shows the old value here.
        config_fingerprint: String,
        /// The policy URL in force, so a repoint is visible at the collector
        /// rather than only to a `check` nobody ran.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_url: Option<String>,
        /// Queue depth. Heartbeats arriving with a growing buffer are an export
        /// that is failing while capture still works — a different fault, and a
        /// different fix, from either half being down.
        buffer_events: u64,
        buffer_bytes: u64,
        spool_files: u64,
        spool_bytes: u64,
        /// Losses since this daemon started. Cumulative rather than a delta:
        /// the `Loss` records carry the deltas, and a total that resets says
        /// the process restarted.
        dropped_total: u64,
        unreadable_total: u64,
        /// Where this daemon is actually reading and writing, and what binary
        /// it is. Both are redirectable by environment variable, so both are
        /// stated rather than assumed to be the installed ones.
        data_dir: String,
        binary: String,
        /// Names — never values — of the `ARGUS_*` overrides in force. An
        /// override is a supported debugging affordance and a supported way to
        /// step out from under policy; saying which are set makes the second
        /// one visible without breaking the first.
        env_overrides: Vec<String>,
    },
}

impl EventKind {
    /// The tool this event is about, for the two kinds that name one.
    ///
    /// A permission prompt is included on purpose: an MCP call that was asked
    /// about and refused is the same third-party reach as one that ran, and a
    /// server that only ever appears in denials is the more interesting of
    /// the two.
    pub fn tool_name(&self) -> Option<&str> {
        match self {
            EventKind::ToolUse { tool, .. } | EventKind::Permission { tool, .. } => Some(tool),
            _ => None,
        }
    }
}

impl Event {
    pub fn new(
        source: &str,
        session_id: Option<String>,
        cwd: Option<String>,
        kind: EventKind,
    ) -> Self {
        let identity = identity();
        Event {
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now(),
            host: identity.host.clone(),
            username: identity.username.clone(),
            source: source.to_string(),
            session_id,
            cwd,
            meta: Meta::default(),
            // Not the `identity` above, which is this host and user. Filled in
            // by `harness::parse` from the envelope, because only the shim
            // that ran inside the agent could have seen it.
            cloud_identity: crate::cloudid::CloudIdentity::default(),
            kind,
        }
    }
}

/// Visit every string in an event that came from outside argus.
///
/// Every variant and every field is named — no `..`, no `_ =>`. This is the
/// point of the match: a new field on `EventKind` that carries text from the
/// host tool must not quietly ship to the SIEM unscrubbed and uncapped, so it
/// has to become a compile error here instead. Fields deliberately left alone
/// are still listed, prefixed `_`, so skipping one is a decision on the record
/// rather than an oversight.
///
/// Redaction and truncation share this walk rather than each keeping their own
/// copy of it, so the two can never disagree about which fields are user
/// content — a field capped but not scrubbed is a leak, and one scrubbed but
/// not capped is unbounded.
pub fn visit_strings(kind: &mut EventKind, f: &mut impl FnMut(&mut String)) {
    match kind {
        EventKind::Prompt { text } | EventKind::AssistantMessage { text } => f(text),
        // Both halves are prompt text and both can carry a secret — the
        // rewritten one especially, since whatever a policy hook splices in is
        // not something the user chose to type.
        EventKind::PromptTransformed {
            original,
            transformed,
        } => {
            f(original);
            f(transformed);
        }
        EventKind::ToolUse {
            tool: _,
            phase: _,
            input,
            output,
            error,
            // A duration and a cancelled-by-a-human flag: neither can carry a
            // secret, so neither is visited.
            duration_ms: _,
            interrupted: _,
            // Paths, hostnames and hashes: extracted from fields that are
            // themselves visited, and none of them is free text a secret can
            // hide in. Scrubbing them would corrupt the identifiers every
            // query joins on.
            files: _,
            fqdns: _,
            endpoints: _,
            output_fqdns: _,
            output_endpoints: _,
            file_contents,
        } => {
            visit_json_strings(input, f);
            visit_json_strings(output, f);
            if let Some(err) = error {
                f(err);
            }
            for snap in file_contents {
                // Whole files, read off disk or lifted out of a payload —
                // the single largest concentration of credentials argus
                // handles, and the reason capture is off by default.
                if let Some(c) = &mut snap.content {
                    f(c);
                }
            }
        }
        // `name`/`agent_type` are tool identifiers, not user content.
        EventKind::Skill { name: _, args } => {
            if let Some(a) = args {
                f(a);
            }
        }
        EventKind::Agent {
            agent_type: _,
            description,
        } => {
            if let Some(d) = description {
                f(d);
            }
        }
        EventKind::Permission {
            tool: _,
            action: _,
            input,
        } => visit_json_strings(input, f),
        EventKind::Notification {
            message,
            // Visited despite reading like a category. No adapter gets it from
            // an enumeration: Copilot takes it from `notificationType` and
            // Claude Code from `type`, both free-form strings a plugin author
            // chooses. It is also the one field here its adapters do not pass
            // through `cap_text`, so skipping it left it unbounded as well as
            // unredacted.
            category,
            title,
        } => {
            f(message);
            f(category);
            if let Some(t) = title {
                f(t);
            }
        }
        EventKind::Error {
            message,
            // Visited for the same reason as `name`: whatever the throwing
            // code called its error class, and code that builds a class name
            // by interpolation puts the interpolated value here. Claude Code
            // puts its error class in this field and Copilot puts free-form
            // `errorContext` in it, so the vocabulary is nobody's to enumerate.
            context,
            name,
            // A boolean.
            recoverable: _,
        } => {
            f(message);
            f(context);
            if let Some(n) = name {
                f(n);
            }
        }
        EventKind::Session { action: _, detail } => visit_json_strings(detail, f),
        // Counts and a price. `finish` is the provider's own stop reason — a
        // fixed vocabulary in every provider that documents one — but it is
        // the only string here, and a provider is free to put an error string
        // in it, so it is visited anyway.
        EventKind::Usage {
            input_tokens: _,
            output_tokens: _,
            reasoning_tokens: _,
            cache_read_tokens: _,
            cache_write_tokens: _,
            cost: _,
            finish,
        } => {
            if let Some(fin) = finish {
                f(fin);
            }
        }
        EventKind::Raw { payload } => visit_json_strings(payload, f),
        // Everything but `instructions` is enumerated or a count. That one is
        // free text the user typed, and it is typed at the moment they are
        // deciding what the transcript should stop holding.
        EventKind::Compact {
            phase: _,
            trigger: _,
            tokens_before: _,
            tokens_after: _,
            instructions,
        } => {
            if let Some(i) = instructions {
                f(i);
            }
        }
        // Argus's own prose or an identifier — in neither case free text a
        // secret hides in. An integrity `detail` is written by this crate, and
        // a `FileChange` path is the same kind of identifier as `files` above:
        // scrubbing it would corrupt what every query joins on.
        EventKind::FileChange { path: _, action: _ }
        | EventKind::Integrity {
            status: _,
            tool: _,
            detail: _,
        } => {}
        // Argus writes all three of these itself; nothing here came from the
        // host tool. `detail` is visited anyway, since it is the one field a
        // future reason could reasonably widen to carry a path.
        EventKind::Loss {
            reason: _,
            count: _,
            detail,
        } => f(detail),
        // Argus describing itself. Every field is a count, an enumerated word,
        // or an identifier this crate produced — and the two that look like
        // free text are not: `broken` is `Finding` prose written here, and
        // `env_overrides` holds variable *names*, never their values, exactly
        // so that a path a user chose cannot ride out in it. Scrubbing the
        // paths that remain (`data_dir`, `binary`) would corrupt the thing the
        // record exists to state, which is where this daemon was pointed.
        EventKind::Health {
            reason: _,
            install_id: _,
            version: _,
            uptime_secs: _,
            checks_age_secs: _,
            checks_ok: _,
            broken: _,
            config_fingerprint: _,
            policy_url: _,
            buffer_events: _,
            buffer_bytes: _,
            spool_files: _,
            spool_bytes: _,
            dropped_total: _,
            unreadable_total: _,
            data_dir: _,
            binary: _,
            env_overrides: _,
        } => {}
    }
}

fn visit_json_strings(v: &mut serde_json::Value, f: &mut impl FnMut(&mut String)) {
    match v {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(|x| visit_json_strings(x, f)),
        serde_json::Value::Object(o) => o.values_mut().for_each(|x| visit_json_strings(x, f)),
        _ => {}
    }
}

/// Who and where this process is. Neither answer can change while the process
/// runs, and resolving the host costs a *process spawn*, so it is resolved
/// once and reused. Before this, a busy session paid a `fork`+`exec` for every
/// single event on the daemon's hot path.
struct Identity {
    host: String,
    username: String,
}

/// Counts trips to the OS. Only the test that pins the caching behavior reads
/// it; without it the guarantee is unfalsifiable — a per-event spawn and a
/// cached one produce identical events.
#[cfg(test)]
pub(crate) static IDENTITY_PROBES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn identity() -> &'static Identity {
    static IDENTITY: std::sync::OnceLock<Identity> = std::sync::OnceLock::new();
    IDENTITY.get_or_init(|| {
        #[cfg(test)]
        IDENTITY_PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Identity {
            host: hostname(),
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".into()),
        }
    })
}

fn hostname() -> String {
    let mut cmd = std::process::Command::new("hostname");
    #[cfg(windows)]
    {
        // Same reason as the daemon autospawn: a bare `Command` under a
        // GUI-launched agent flashes a console window at the user.
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(crate::hook::CREATE_NO_WINDOW);
    }
    cmd.output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_json() {
        let e = Event::new(
            "claude-code",
            Some("sess-1".into()),
            Some("/repo".into()),
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "pre".into(),
                input: serde_json::json!({"file_path": "/repo/a.rs"}),
                output: serde_json::Value::Null,
                error: None,
                duration_ms: None,
                interrupted: false,
                files: vec!["/repo/a.rs".into()],
                fqdns: vec![],
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![],
            },
        );
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.source, "claude-code");
        assert!(matches!(back.kind, EventKind::ToolUse { .. }));
        assert!(!back.id.is_empty());
        assert!(!back.host.is_empty());
    }

    #[test]
    fn envelope_roundtrips() {
        let env = Envelope {
            cloud_identity: Default::default(),
            source: "opencode".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({"event": "tool.execute.before"}),
        };
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert_eq!(back.source, "opencode");
    }

    #[test]
    fn old_serialized_events_still_deserialize() {
        // An event written by the previous binary version (no meta, no output/
        // error on tool_use, no detail on session) must round-trip.
        let old = r#"{"id":"x","ts":"2026-07-11T00:00:00Z","host":"h","username":"u",
            "source":"claude-code","session_id":null,"cwd":null,
            "type":"tool_use","tool":"Write","phase":"pre","input":{},"files":[],"fqdns":[]}"#;
        let e: Event = serde_json::from_str(old).unwrap();
        let EventKind::ToolUse {
            output,
            error,
            file_contents,
            ..
        } = &e.kind
        else {
            panic!()
        };
        assert!(output.is_null());
        assert!(error.is_none());
        // The rows already in somebody's buffer when they upgrade. A buffer
        // that cannot be drained grows until the disk cap starts deleting the
        // oldest evidence in it.
        assert!(file_contents.is_empty());
        assert!(e.meta.is_empty());

        let old_session = r#"{"id":"x","ts":"2026-07-11T00:00:00Z","host":"h","username":"u",
            "source":"claude-code","session_id":null,"cwd":null,
            "type":"session","action":"Stop"}"#;
        let e: Event = serde_json::from_str(old_session).unwrap();
        assert!(matches!(&e.kind, EventKind::Session { detail, .. } if detail.is_null()));
    }

    /// A snapshot has two shapes — one with content, one that says why there
    /// is none — and both have to survive the buffer.
    #[test]
    fn file_snapshots_round_trip_in_both_shapes() {
        let captured = FileSnapshot {
            path: "/repo/a.rs".into(),
            action: FileAction::Written,
            bytes: 12,
            sha256: Some("abc123".into()),
            mtime: Some(chrono::Utc::now()),
            source: SnapshotSource::Payload,
            content: Some("fn main() {}".into()),
            truncated: true,
            skipped: None,
        };
        let withheld = FileSnapshot {
            path: "/repo/.env".into(),
            action: FileAction::Read,
            bytes: 400,
            sha256: Some("def456".into()),
            mtime: None,
            source: SnapshotSource::Disk,
            content: None,
            truncated: false,
            skipped: Some(SkipReason::Excluded),
        };
        let e = Event::new(
            "claude-code",
            None,
            None,
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "post".into(),
                input: serde_json::json!({}),
                output: serde_json::Value::Null,
                error: None,
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns: vec![],
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![captured.clone(), withheld.clone()],
            },
        );
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["file_contents"][1]["skipped"], "excluded");
        assert_eq!(v["file_contents"][1]["action"], "read");
        assert_eq!(v["file_contents"][1]["source"], "disk");
        // The withheld one still carries what a query needs to know the file
        // was touched at all — that is the whole point of separating them.
        assert_eq!(v["file_contents"][1]["sha256"], "def456");
        assert!(v["file_contents"][1].get("content").is_none());

        let back: Event = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        let EventKind::ToolUse { file_contents, .. } = &back.kind else {
            panic!()
        };
        assert_eq!(file_contents[0], captured);
        assert_eq!(file_contents[1], withheld);
    }

    /// Capture is off by default, so almost every tool call in almost every
    /// deployment has no snapshots. An empty array on each of them is bytes
    /// through the buffer, the 4 MiB export body and the collector, forever,
    /// to say nothing.
    #[test]
    fn a_call_that_captured_nothing_carries_no_snapshot_key() {
        let e = Event::new(
            "claude-code",
            None,
            None,
            EventKind::ToolUse {
                tool: "Bash".into(),
                phase: "pre".into(),
                input: serde_json::json!({}),
                output: serde_json::Value::Null,
                error: None,
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns: vec![],
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![],
            },
        );
        let v = serde_json::to_value(&e).unwrap();
        assert!(
            v.get("file_contents").is_none(),
            "an empty snapshot list must not be serialized: {v}"
        );
    }

    #[test]
    fn empty_meta_is_not_serialized() {
        let e = Event::new("t", None, None, EventKind::Prompt { text: "x".into() });
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("meta").is_none(), "empty meta must be skipped");
    }

    #[test]
    fn populated_meta_round_trips() {
        let mut e = Event::new("t", None, None, EventKind::Prompt { text: "x".into() });
        e.meta.agent_type = Some("Explore".into());
        e.meta.model = Some("claude-fable-5".into());
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.meta.agent_type.as_deref(), Some("Explore"));
    }

    #[test]
    fn new_kinds_round_trip_with_snake_case_tags() {
        let cases = vec![
            (
                EventKind::AssistantMessage { text: "hi".into() },
                "assistant_message",
            ),
            (
                EventKind::Permission {
                    tool: "Bash".into(),
                    action: "requested".into(),
                    input: serde_json::json!({}),
                },
                "permission",
            ),
            (
                EventKind::Notification {
                    message: "m".into(),
                    category: "idle_prompt".into(),
                    title: None,
                },
                "notification",
            ),
            (
                EventKind::Compact {
                    phase: "post".into(),
                    trigger: "auto".into(),
                    tokens_before: Some(1000),
                    tokens_after: Some(200),
                    instructions: None,
                },
                "compact",
            ),
            (
                EventKind::FileChange {
                    path: "/x".into(),
                    action: "edited".into(),
                },
                "file_change",
            ),
            (
                EventKind::Error {
                    message: "boom".into(),
                    context: "rate_limit".into(),
                    name: None,
                    recoverable: None,
                },
                "error",
            ),
        ];
        for (kind, tag) in cases {
            let v = serde_json::to_value(Event::new("t", None, None, kind)).unwrap();
            assert_eq!(v["type"], tag);
        }
    }

    #[test]
    fn envelope_event_hint_defaults_to_none() {
        let s = r#"{"source":"copilot","received_at":"2026-07-11T00:00:00Z","payload":{}}"#;
        let env: Envelope = serde_json::from_str(s).unwrap();
        assert!(env.event.is_none());
    }

    #[test]
    fn event_kind_is_flattened_at_top_level() {
        let e = Event::new(
            "claude-code",
            None,
            None,
            EventKind::ToolUse {
                tool: "Write".into(),
                phase: "pre".into(),
                input: serde_json::json!({}),
                output: serde_json::Value::Null,
                error: None,
                duration_ms: None,
                interrupted: false,
                files: vec![],
                fqdns: vec![],
                endpoints: vec![],
                output_fqdns: vec![],
                output_endpoints: vec![],
                file_contents: vec![],
            },
        );
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "tool_use");
        assert_eq!(v["tool"], "Write");
        assert!(
            v.get("kind").is_none(),
            "kind must be flattened, not nested"
        );
        assert!(v.get("id").is_some());
    }

    #[test]
    fn identity_is_resolved_once_no_matter_how_many_events() {
        for _ in 0..64 {
            let e = Event::new(
                "t",
                None,
                None,
                EventKind::Prompt {
                    text: "hello".into(),
                },
            );
            assert!(!e.host.is_empty());
            assert!(!e.username.is_empty());
        }
        // Other tests in this binary also build events, so the assertion is on
        // the absolute count, not a delta — under any ordering the OS is asked
        // exactly once. Resolving the host spawns `hostname(1)`; doing that per
        // event is the difference between a syscall and a fork on the hot path.
        assert_eq!(
            super::IDENTITY_PROBES.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "host/username must be resolved once per process, not per event"
        );
    }
}
