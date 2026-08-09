use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Raw frame sent by the hook shim. The shim never parses tool payloads.
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
    #[serde(flatten)]
    pub kind: EventKind,
}

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
            kind,
        }
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
        let EventKind::ToolUse { output, error, .. } = &e.kind else {
            panic!()
        };
        assert!(output.is_null());
        assert!(error.is_none());
        assert!(e.meta.is_empty());

        let old_session = r#"{"id":"x","ts":"2026-07-11T00:00:00Z","host":"h","username":"u",
            "source":"claude-code","session_id":null,"cwd":null,
            "type":"session","action":"Stop"}"#;
        let e: Event = serde_json::from_str(old_session).unwrap();
        assert!(matches!(&e.kind, EventKind::Session { detail, .. } if detail.is_null()));
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
