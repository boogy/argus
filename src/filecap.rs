//! Deciding which files may have their contents captured.
//!
//! Separate from the capture itself because the decision is the security
//! boundary and the capture is plumbing. Everything here is pure: a path in, a
//! verdict out, no I/O — so the rule that keeps `.ssh/id_rsa` out of the SIEM
//! can be tested exhaustively without a filesystem, and the same verdict
//! applies whether the bytes came from a hook payload or a disk read.

use crate::config::{CaptureCfg, ContentMode, FileContentsCfg};
use crate::event::{EventKind, FileAction, FileSnapshot, SkipReason, SnapshotSource};
use regex::RegexSet;
use serde_json::Value;

/// Compiled `include`/`exclude`, built once per config generation.
///
/// Cached alongside the `Redactor` for the same reason: these regexes are
/// matched against every path in every tool call, and recompiling them per
/// event is the kind of cost that only shows up under the load it matters at.
#[derive(Debug)]
pub struct PathFilter {
    /// `None` means "no include list", which is not the same as an empty set:
    /// an empty `RegexSet` matches nothing, and a filter that admits nothing
    /// is an enabled feature that captures nothing.
    include: Option<RegexSet>,
    exclude: RegexSet,
    /// Set when a pattern would not compile. The filter then refuses
    /// everything — see [`PathFilter::allows`].
    broken: bool,
}

/// Windows writes `C:\repo\node_modules\x` and every default `exclude` here is
/// written with forward slashes, so without this the shipped policy silently
/// fails to match on exactly the platform where `--managed` deployments live,
/// and argus captures the files it was configured to skip.
pub fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

impl PathFilter {
    pub fn new(cfg: &FileContentsCfg) -> Self {
        // Windows paths are case-insensitive, so `\NODE_MODULES\` and
        // `\node_modules\` name one directory and must match one rule. Unix
        // paths are not, and folding case there would exclude files a
        // deployment did not ask to exclude.
        Self::with_case_folding(cfg, cfg!(windows))
    }

    /// Split out so the folding itself is testable on every platform. Built
    /// under `cfg!(windows)` it would only ever be exercised on Windows CI,
    /// which is precisely where nobody looks first.
    fn with_case_folding(cfg: &FileContentsCfg, fold_case: bool) -> Self {
        let build = |pats: &[String]| -> Result<RegexSet, regex::Error> {
            regex::RegexSetBuilder::new(pats)
                .case_insensitive(fold_case)
                .build()
        };
        let mut broken = false;
        let exclude = build(&cfg.exclude).unwrap_or_else(|e| {
            // Fails closed, unlike every other invalid-pattern path in this
            // codebase. A dropped redaction rule scrubs less than asked; a
            // dropped *exclusion* ships the file it names, and the files it
            // names are `.env` and `id_rsa`.
            tracing::error!(
                "file_contents.exclude did not compile, capturing no contents at all: {e}"
            );
            broken = true;
            RegexSet::empty()
        });
        let include = if cfg.include.is_empty() {
            None
        } else {
            Some(build(&cfg.include).unwrap_or_else(|e| {
                tracing::error!("file_contents.include did not compile, capturing nothing: {e}");
                broken = true;
                RegexSet::empty()
            }))
        };
        PathFilter {
            include,
            exclude,
            broken,
        }
    }

    /// Whether this path's *content* may be captured. Metadata is not gated by
    /// it: a file excluded here is still reported as touched.
    pub fn allows(&self, path: &str) -> bool {
        if self.broken {
            return false;
        }
        let p = normalize(path);
        if self.exclude.is_match(&p) {
            return false;
        }
        match &self.include {
            Some(inc) => inc.is_match(&p),
            None => true,
        }
    }
}

/// One file a tool call said something about, and the bytes the call itself
/// carried for it.
///
/// `content` is `None` for a call that names a file without quoting it — a
/// `Read`, a `Grep`. Payload mode has nothing to say about those, which is
/// exactly where disk mode earns its keep.
#[derive(Debug)]
pub struct Candidate {
    pub path: String,
    pub action: FileAction,
    pub content: Option<String>,
}

/// Content keys, in the order a tool is likely to use them. `content` covers
/// Claude Code's and opencode's `Write`; the `new_*` spellings are the half of
/// an edit that describes the file's resulting state.
const CONTENT_KEYS: &[&str] = &["content", "contents"];
const NEW_KEYS: &[&str] = &["new_string", "newString", "new_str"];

/// What a tool call claims about the files it names.
///
/// Deliberately keyed on the *shape* of the input rather than on a table of
/// tool names: five harnesses spell the same three operations six ways, and a
/// name table is a thing that silently stops covering a tool the day it is
/// renamed. A payload with a path key and a `content` key is a write in any
/// dialect.
pub fn candidates(tool: &str, input: &Value) -> Vec<Candidate> {
    let t = tool.to_ascii_lowercase();
    if t == "apply_patch" || t == "applypatch" {
        return patch_candidates(input);
    }
    let Some(path) = crate::adapters::FILE_KEYS
        .iter()
        .find_map(|k| input.get(k).and_then(Value::as_str))
    else {
        return vec![];
    };
    let one = |action, content| {
        vec![Candidate {
            path: path.to_string(),
            action,
            content,
        }]
    };
    if let Some(c) = CONTENT_KEYS
        .iter()
        .find_map(|k| input.get(k).and_then(Value::as_str))
    {
        return one(FileAction::Written, Some(c.to_string()));
    }
    if let Some(c) = NEW_KEYS
        .iter()
        .find_map(|k| input.get(k).and_then(Value::as_str))
    {
        return one(FileAction::Edited, Some(c.to_string()));
    }
    // A batched edit. The halves are joined rather than reported separately
    // because they describe one file, and a snapshot per hunk would make the
    // per-event file budget count hunks instead of files.
    if let Some(edits) = input.get("edits").and_then(Value::as_array) {
        let joined: Vec<&str> = edits
            .iter()
            .filter_map(|e| {
                NEW_KEYS
                    .iter()
                    .find_map(|k| e.get(k).and_then(Value::as_str))
            })
            .collect();
        if !joined.is_empty() {
            return one(FileAction::Edited, Some(joined.join("\n")));
        }
    }
    if t.contains("read") {
        return one(FileAction::Read, None);
    }
    vec![]
}

fn patch_candidates(input: &Value) -> Vec<Candidate> {
    let mut out = vec![];
    if let Some(s) = input.as_str() {
        out.extend(split_patch(s));
    }
    for v in input.as_object().into_iter().flat_map(|o| o.values()) {
        if let Some(s) = v.as_str() {
            out.extend(split_patch(s));
        }
    }
    out
}

/// A patch names several files in one string, and the interesting question is
/// what happened to each of them — so the body is split at its headers rather
/// than attributed whole to every file it touches.
fn split_patch(patch: &str) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = vec![];
    for line in patch.lines() {
        let header = ["*** Add File: ", "*** Update File: ", "*** Delete File: "]
            .iter()
            .find_map(|p| line.strip_prefix(p));
        if let Some(path) = header {
            out.push(Candidate {
                path: path.trim().to_string(),
                action: FileAction::Patched,
                content: Some(String::new()),
            });
        } else if let Some(last) = out.last_mut() {
            let body = last.content.get_or_insert_with(String::new);
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// C0 control bytes that are not whitespace. The classic heuristic, and the
/// reason it is worth having: a captured binary is bytes nobody can read, in a
/// field every downstream query treats as text.
pub fn looks_binary(s: &str) -> bool {
    s.bytes()
        .take(8192)
        .any(|b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r'))
}

/// What one truncation marker costs, reserved out of the remaining byte budget
/// so the cut fits inside it.
const MARKER_BYTES: usize = 32;

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Capture what the payload already carried, into `file_contents`.
///
/// Runs *before* redaction, so the copy is scrubbed by the same walk that
/// scrubs the input it came from. A capture that ran afterwards would be the
/// one field in the event nobody had looked at.
pub fn capture_from_payload(kind: &mut EventKind, capture: &CaptureCfg, filter: &PathFilter) {
    let cfg = &capture.file_contents;
    if !cfg.enabled || cfg.mode == ContentMode::Disk {
        return;
    }
    let EventKind::ToolUse {
        tool,
        input,
        file_contents,
        ..
    } = kind
    else {
        return;
    };
    let mut budget = cfg.max_total_bytes;
    for mut c in candidates(tool, input) {
        // The count is capped, not just the bytes: a forty-file patch would
        // otherwise put forty records in one event however small each is. The
        // `files` list still names every one of them, so what is lost here is
        // the content, not the fact that the file was touched.
        if file_contents.len() >= cfg.max_files {
            break;
        }
        let Some(body) = c.content.take() else {
            continue;
        };
        file_contents.push(snapshot(&c, &body, capture, filter, &mut budget));
    }
}

fn snapshot(
    c: &Candidate,
    body: &str,
    capture: &CaptureCfg,
    filter: &PathFilter,
    budget: &mut usize,
) -> FileSnapshot {
    let cfg = &capture.file_contents;
    let mut snap = FileSnapshot {
        path: c.path.clone(),
        action: c.action,
        bytes: body.len() as u64,
        sha256: None,
        mtime: None,
        source: SnapshotSource::Payload,
        content: None,
        truncated: false,
        skipped: None,
    };
    // Policy first, then cost, then budget: an excluded file must report the
    // reason it was excluded even on an event that had run out of room, or a
    // deployment cannot tell a policy from a full record.
    if !filter.allows(&c.path) {
        snap.skipped = Some(SkipReason::Excluded);
        return snap;
    }
    if cfg.skip_binary && looks_binary(body) {
        snap.skipped = Some(SkipReason::Binary);
        return snap;
    }
    if *budget == 0 {
        snap.skipped = Some(SkipReason::Budget);
        return snap;
    }
    // `max_field_bytes` caps every string in the event afterwards, so a
    // `max_bytes` above it would be trimmed by a later stage that does not set
    // the flag — leaving a truncated body claiming to be whole. Clamping here
    // covers the parse-time cap too: that one cut to `max_field_bytes` plus
    // headroom, so anything longer than this ceiling was already a prefix and
    // is flagged as one, and no digest of a prefix reaches the wire.
    let ceiling = match capture.max_field_bytes {
        0 => cfg.max_bytes,
        n => cfg.max_bytes.min(n),
    };
    let kept = if body.len() <= ceiling && body.len() <= *budget {
        body.to_string()
    } else {
        // `cap_mode` spends its markers on top of what it keeps, so a cut made
        // to exactly the remaining budget overshoots it by the marker. Once per
        // truncated file that is the difference between a budget and a
        // suggestion.
        let room = ceiling.min(budget.saturating_sub(MARKER_BYTES));
        if room == 0 {
            snap.skipped = Some(if ceiling == 0 {
                SkipReason::TooLarge
            } else {
                SkipReason::Budget
            });
            return snap;
        }
        snap.truncated = true;
        crate::adapters::cap_mode(body, room, capture.truncate_mode)
    };
    if cfg.hash && !snap.truncated {
        snap.sha256 = Some(sha256_hex(body.as_bytes()));
    }
    *budget = budget.saturating_sub(kept.len());
    snap.content = Some(kept);
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(include: &[&str], exclude: &[&str]) -> FileContentsCfg {
        FileContentsCfg {
            include: include.iter().map(|s| (*s).to_string()).collect(),
            exclude: exclude.iter().map(|s| (*s).to_string()).collect(),
            ..FileContentsCfg::default()
        }
    }

    /// The shipped policy has to hold on the platform it is least likely to be
    /// tested on. A `C:\repo\node_modules\` path that misses `/node_modules/`
    /// is a config that reads as protective and is not.
    #[test]
    fn the_default_exclusions_match_windows_paths_too() {
        let f = PathFilter::new(&FileContentsCfg::default());
        for path in [
            r"C:\repo\node_modules\pkg\index.js",
            r"C:\Users\dev\.ssh\id_rsa",
            r"C:\repo\.env",
            r"C:\repo\.env.local",
            r"C:\repo\certs\server.pem",
            r"C:\repo\Cargo.lock",
            r"C:\repo\.git\config",
            r"C:\repo\keys\backup.p12",
            r"C:\Users\dev\.ssh\deploy_rsa",
        ] {
            assert!(!f.allows(path), "should be excluded: {path}");
            assert!(
                !f.allows(&path.replace('\\', "/")),
                "should be excluded: {path} (unix form)"
            );
        }
        assert!(f.allows(r"C:\repo\src\main.rs"));
        assert!(f.allows("/repo/src/main.rs"));
    }

    /// `C:\Repo\NODE_MODULES\` and `C:\repo\node_modules\` are one directory,
    /// and the shipped `exclude` list is written in lower case. Without case
    /// folding the default policy misses half the paths on the platform
    /// `--managed` deployments actually run on.
    #[test]
    fn windows_case_folding_is_what_makes_the_default_policy_hold() {
        let d = FileContentsCfg::default();
        let shouty = r"C:\Repo\NODE_MODULES\pkg\Index.js";
        let key = r"C:\Users\Dev\.SSH\ID_RSA";

        let win = PathFilter::with_case_folding(&d, true);
        assert!(!win.allows(shouty), "case-folded match missed: {shouty}");
        assert!(!win.allows(key), "case-folded match missed: {key}");

        // And not folded elsewhere: on Unix those are genuinely different
        // files, and excluding them would be excluding paths nobody named.
        let unix = PathFilter::with_case_folding(&d, false);
        assert!(unix.allows(shouty));
        assert!(unix.allows(key));
        // The lower-case forms are excluded on both.
        assert!(!unix.allows(r"C:\repo\node_modules\pkg\index.js"));
    }

    /// An empty `include` is "everything the excludes allow", not "nothing".
    #[test]
    fn an_empty_include_list_is_not_an_empty_allow_list() {
        let f = PathFilter::new(&cfg(&[], &[]));
        assert!(f.allows("/anything/at/all.rs"));
    }

    #[test]
    fn include_narrows_and_exclude_still_wins() {
        let f = PathFilter::new(&cfg(&["/src/"], &[r"/src/secrets\.rs$"]));
        assert!(f.allows("/repo/src/main.rs"));
        assert!(!f.allows("/repo/docs/readme.md"), "outside include");
        assert!(
            !f.allows("/repo/src/secrets.rs"),
            "a path both included and excluded was meant to be excluded"
        );
    }

    /// Every other invalid pattern in this codebase is warned about and
    /// dropped. An exclusion cannot be: dropping it captures the file it
    /// names, and the files it names are the ones nobody wants captured.
    #[test]
    fn an_uncompilable_exclusion_stops_capture_rather_than_widening_it() {
        let f = PathFilter::new(&cfg(&[], &["[unclosed"]));
        assert!(
            !f.allows("/repo/src/main.rs"),
            "a broken exclude list must fail closed, not open"
        );
    }

    #[test]
    fn an_uncompilable_include_also_fails_closed() {
        let f = PathFilter::new(&cfg(&["(unclosed"], &[]));
        assert!(!f.allows("/repo/src/main.rs"));
    }

    // --- payload capture ---

    fn on(f: impl FnOnce(&mut FileContentsCfg)) -> CaptureCfg {
        let mut fc = FileContentsCfg {
            enabled: true,
            ..FileContentsCfg::default()
        };
        f(&mut fc);
        CaptureCfg {
            file_contents: fc,
            ..CaptureCfg::default()
        }
    }

    fn snaps(tool: &str, input: Value, capture: &CaptureCfg) -> Vec<FileSnapshot> {
        let filter = PathFilter::new(&capture.file_contents);
        let mut kind = EventKind::ToolUse {
            tool: tool.into(),
            phase: "post".into(),
            input,
            output: Value::Null,
            error: None,
            duration_ms: None,
            interrupted: false,
            files: vec![],
            fqdns: vec![],
            file_contents: vec![],
        };
        capture_from_payload(&mut kind, capture, &filter);
        match kind {
            EventKind::ToolUse { file_contents, .. } => file_contents,
            other => panic!("not a tool use: {other:?}"),
        }
    }

    /// A known answer, because a digest is only checkable against one computed
    /// somewhere else. Comparing it against this module's own output would
    /// still pass if the hex encoding dropped every leading zero — and the
    /// digest of `abc` has one.
    #[test]
    fn the_digest_is_a_sha256_in_lower_case_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"").len(), 64);
    }

    #[test]
    fn a_write_is_captured_with_a_digest_of_what_it_wrote() {
        let out = snaps(
            "Write",
            serde_json::json!({"file_path": "/repo/src/main.rs", "content": "fn main() {}"}),
            &on(|_| {}),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path, "/repo/src/main.rs");
        assert_eq!(out[0].action, FileAction::Written);
        assert_eq!(out[0].source, SnapshotSource::Payload);
        assert_eq!(out[0].content.as_deref(), Some("fn main() {}"));
        assert_eq!(out[0].bytes, 12);
        assert!(!out[0].truncated);
        assert_eq!(out[0].skipped, None);
        assert_eq!(
            out[0].sha256.as_deref(),
            Some(&sha256_hex(b"fn main() {}")[..]),
            "the digest is of the bytes the payload carried"
        );
    }

    /// Off is off. The one default in this crate whose cost is measured in
    /// somebody else's credentials.
    #[test]
    fn nothing_is_captured_until_the_feature_is_enabled() {
        let mut c = on(|_| {});
        c.file_contents.enabled = false;
        assert!(
            snaps(
                "Write",
                serde_json::json!({"file_path": "/a.rs", "content": "x"}),
                &c
            )
            .is_empty()
        );
    }

    /// `disk` means disk. A deployment that chose it to avoid trusting what a
    /// tool claims must not get the claim anyway.
    #[test]
    fn disk_mode_takes_nothing_from_the_payload() {
        let c = on(|fc| fc.mode = ContentMode::Disk);
        assert!(
            snaps(
                "Write",
                serde_json::json!({"file_path": "/a.rs", "content": "x"}),
                &c
            )
            .is_empty()
        );
    }

    /// The whole argument for separating metadata from content: an agent
    /// writing `.env` is the finding, and reporting it does not require
    /// shipping the file.
    #[test]
    fn an_excluded_file_is_still_reported_as_touched() {
        let out = snaps(
            "Write",
            serde_json::json!({"file_path": "/repo/.env", "content": "AWS_SECRET_ACCESS_KEY=x"}),
            &on(|_| {}),
        );
        assert_eq!(out.len(), 1, "the exclusion silenced the file entirely");
        assert_eq!(out[0].skipped, Some(SkipReason::Excluded));
        assert_eq!(out[0].content, None, "an excluded file's body was shipped");
        assert_eq!(out[0].path, "/repo/.env");
        assert_eq!(out[0].bytes, 23);
    }

    #[test]
    fn a_binary_body_is_reported_and_not_shipped() {
        let out = snaps(
            "Write",
            serde_json::json!({"file_path": "/repo/a.bin", "content": "MZ\u{0}\u{1}\u{2}payload"}),
            &on(|_| {}),
        );
        assert_eq!(out[0].skipped, Some(SkipReason::Binary));
        assert_eq!(out[0].content, None);

        let kept = snaps(
            "Write",
            serde_json::json!({"file_path": "/repo/a.bin", "content": "MZ\u{0}\u{1}\u{2}payload"}),
            &on(|fc| fc.skip_binary = false),
        );
        assert!(kept[0].content.is_some(), "skip_binary = false was ignored");
    }

    /// A truncated body must not carry a digest: it would be a hash that
    /// matches no file anywhere, and correlating on it silently finds nothing.
    #[test]
    fn an_oversized_body_is_truncated_and_loses_its_digest() {
        let body = "x".repeat(5000);
        let out = snaps(
            "Write",
            serde_json::json!({"file_path": "/repo/big.rs", "content": body}),
            &on(|fc| fc.max_bytes = 100),
        );
        assert!(out[0].truncated);
        assert_eq!(out[0].sha256, None, "a digest of a prefix reached the wire");
        assert_eq!(out[0].bytes, 5000, "the real size was lost");
        let kept = out[0].content.as_deref().unwrap();
        assert!(kept.len() < 100 + 32, "not capped: {} bytes", kept.len());
        assert!(kept.contains("[truncated]"));
    }

    /// `max_field_bytes` is the ceiling over every string in an event, applied
    /// after this stage. A `max_bytes` above it would be cut by that later pass
    /// instead, leaving a body flagged whole that is not.
    #[test]
    fn the_global_field_cap_still_wins_and_the_flag_says_so() {
        let body = "x".repeat(5000);
        let c = CaptureCfg {
            max_field_bytes: 200,
            ..on(|fc| fc.max_bytes = 100_000)
        };
        let out = snaps(
            "Write",
            serde_json::json!({"file_path": "/repo/big.rs", "content": body}),
            &c,
        );
        assert!(out[0].truncated, "capped elsewhere without saying so");
        assert_eq!(out[0].sha256, None);
        assert!(out[0].content.as_deref().unwrap().len() < 200 + 32);
    }

    #[test]
    fn an_edit_captures_the_state_the_file_is_moving_to() {
        for input in [
            serde_json::json!({"file_path": "/a.rs", "old_string": "a", "new_string": "b"}),
            serde_json::json!({"filePath": "/a.rs", "oldString": "a", "newString": "b"}),
            serde_json::json!({"path": "/a.rs", "edits": [{"new_string": "b"}]}),
        ] {
            let out = snaps("Edit", input.clone(), &on(|_| {}));
            assert_eq!(out.len(), 1, "missed an edit dialect: {input}");
            assert_eq!(out[0].action, FileAction::Edited);
            assert_eq!(out[0].content.as_deref(), Some("b"), "for {input}");
        }
    }

    /// A `Read` names a file without quoting it. Payload mode has nothing to
    /// say, and an empty snapshot would be a row that answers no question.
    #[test]
    fn a_call_that_only_names_a_file_yields_no_payload_snapshot() {
        for (tool, input) in [
            ("Read", serde_json::json!({"file_path": "/a.rs"})),
            ("Grep", serde_json::json!({"path": "/repo"})),
            ("Bash", serde_json::json!({"command": "ls"})),
        ] {
            assert!(
                snaps(tool, input, &on(|_| {})).is_empty(),
                "{tool} invented a snapshot"
            );
        }
    }

    #[test]
    fn a_patch_gives_each_file_its_own_section() {
        let patch = "*** Begin Patch\n\
                     *** Update File: src/a.rs\n\
                     +let a = 1;\n\
                     *** Add File: src/b.rs\n\
                     +let b = 2;\n\
                     *** End Patch\n";
        let out = snaps(
            "apply_patch",
            serde_json::json!({"patch": patch}),
            &on(|_| {}),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].path, "src/a.rs");
        assert_eq!(out[0].action, FileAction::Patched);
        assert_eq!(out[0].content.as_deref(), Some("+let a = 1;\n"));
        assert_eq!(out[1].path, "src/b.rs");
        assert_eq!(
            out[1].content.as_deref(),
            Some("+let b = 2;\n*** End Patch\n"),
            "the trailing sentinel belongs to the last file's section"
        );
    }

    /// One `apply_patch` across forty files is the shape that turns a feature
    /// with a per-file cap into an unbounded record.
    #[test]
    fn both_per_event_budgets_bound_one_patch() {
        let mut patch = String::from("*** Begin Patch\n");
        for i in 0..40 {
            patch.push_str(&format!("*** Update File: src/f{i}.rs\n"));
            patch.push_str(&"+x\n".repeat(200));
        }
        let out = snaps(
            "apply_patch",
            serde_json::json!({"patch": patch}),
            &on(|fc| {
                fc.max_files = 5;
                fc.max_total_bytes = 1000;
            }),
        );
        assert_eq!(out.len(), 5, "the file budget did not bound the record");
        let total: usize = out
            .iter()
            .map(|s| s.content.as_deref().unwrap_or("").len())
            .sum();
        assert!(total <= 1000, "the byte budget was overrun: {total}");
        assert!(
            out.iter().any(|s| s.skipped == Some(SkipReason::Budget)),
            "a file dropped for budget did not say so: {out:?}"
        );
    }
}
