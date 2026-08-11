//! Deciding which files may have their contents captured, and capturing them.
//!
//! The decision — [`PathFilter`] — is the security boundary, and it is pure: a
//! path in, a verdict out, no I/O, so the rule that keeps `.ssh/id_rsa` out of
//! the SIEM can be tested exhaustively without a filesystem, and the same
//! verdict applies whether the bytes came from a hook payload or a disk read.
//!
//! The capture around it comes in two halves that answer different questions.
//! The payload half is what the tool *said* it would write: exact, race-free,
//! and already in memory. The disk half is what is *there*, which is the only
//! half that sees a `Bash` with a `>` redirect, a `sed -i`, or a formatter that
//! ran afterwards — at the cost of real I/O against paths an untrusted agent
//! chose.

use crate::config::{CaptureCfg, ContentMode, FileContentsCfg};
use crate::event::{Event, EventKind, FileAction, FileSnapshot, SkipReason, SnapshotSource};
use chrono::{DateTime, Utc};
use regex::RegexSet;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// Capture the files a tool call touched, into `file_contents`.
///
/// Runs *before* redaction, so the copy is scrubbed by the same walk that
/// scrubs the input it came from. A capture that ran afterwards would be the
/// one field in the event nobody had looked at.
///
/// Both halves share one set of per-event budgets. Running them with a budget
/// each would make `mode = "both"` quietly twice as expensive as the number in
/// the config file.
pub fn capture(event: &mut Event, capture: &CaptureCfg, filter: &PathFilter) {
    let cfg = &capture.file_contents;
    if !cfg.enabled {
        return;
    }
    // Copied out before the borrow below: a patch names `src/a.rs`, and which
    // file that is depends on where the session is, not on where the daemon
    // happens to have been started.
    let cwd = event.cwd.clone();
    let EventKind::ToolUse {
        tool,
        input,
        file_contents,
        ..
    } = &mut event.kind
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
        let snap = match c.content.take() {
            // `disk` means disk: a deployment that chose it did so to stop
            // trusting what a tool claims, and handing it the claim anyway
            // would be answering a different question.
            Some(body) if cfg.mode != ContentMode::Disk => {
                payload_snapshot(&c, &body, capture, filter, &mut budget)
            }
            // A call that only named a file — a `Read`, a `Grep` — is where
            // disk mode earns its keep, and the one thing payload mode has
            // nothing to say about.
            _ if cfg.mode != ContentMode::Payload => {
                disk_snapshot(&c, cwd.as_deref(), capture, filter, &mut budget)
            }
            _ => continue,
        };
        file_contents.push(snap);
    }
}

/// Everything known about a file before anything has been read or decided.
fn blank(c: &Candidate, bytes: u64, source: SnapshotSource) -> FileSnapshot {
    FileSnapshot {
        path: c.path.clone(),
        action: c.action,
        bytes,
        sha256: None,
        mtime: None,
        source,
        content: None,
        truncated: false,
        skipped: None,
    }
}

/// The largest body that may reach the wire whole.
///
/// `max_field_bytes` caps every string in the event afterwards, so a
/// `max_bytes` above it would be trimmed by a later stage that does not set the
/// `truncated` flag — leaving a cut body claiming to be whole.
fn content_ceiling(capture: &CaptureCfg) -> usize {
    match capture.max_field_bytes {
        0 => capture.file_contents.max_bytes,
        n => capture.file_contents.max_bytes.min(n),
    }
}

fn payload_snapshot(
    c: &Candidate,
    body: &str,
    capture: &CaptureCfg,
    filter: &PathFilter,
    budget: &mut usize,
) -> FileSnapshot {
    let cfg = &capture.file_contents;
    let mut snap = blank(c, body.len() as u64, SnapshotSource::Payload);
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
    // The ceiling covers the parse-time cap too: that one cut to
    // `max_field_bytes` plus headroom, so anything longer than this was
    // already a prefix and is flagged as one, and no digest of a prefix
    // reaches the wire.
    let ceiling = content_ceiling(capture);
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

/// A relative path is only a file once you know where it was said.
///
/// Resolving one against the daemon's own working directory would name a
/// different file with the same name — and reading *that* is worse than
/// reading nothing, because the record would look like a successful capture.
fn resolve(path: &str, cwd: Option<&str>) -> Option<PathBuf> {
    let p = Path::new(path);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    Some(Path::new(cwd?).join(p))
}

/// Open without following a link, on the platforms that can say so.
///
/// The stat below already refuses a symlink, but a stat and an open are two
/// syscalls with a gap between them, and the whole point of the gap to an
/// attacker is to swap the path for a link to something better. `O_NOFOLLOW`
/// closes it: the open itself fails rather than reading whatever the link now
/// points at.
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the link, not its target, so a
        // junction or a symlink fails here instead of resolving elsewhere.
        opts.custom_flags(0x0020_0000);
    }
    opts.open(path)
}

/// The file's bytes, or `None` if it turned out to have more than `limit`.
///
/// The caller has already sized the file with a stat, but a stat and a read are
/// two syscalls: a file that grew in between comes back as a prefix, and a
/// digest of a prefix matches no file anywhere. Reading one byte past the limit
/// is what makes that detectable rather than silent.
fn read_capped(path: &Path, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    open_no_follow(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut buf)?;
    Ok((buf.len() <= limit).then_some(buf))
}

/// Everything one disk snapshot asks of the filesystem, in a single call —
/// because it is the call that has to be given up on, and giving up on half of
/// a stat-then-read leaves the other half still running.
struct Probe {
    bytes: u64,
    mtime: Option<DateTime<Utc>>,
    /// `Ok(Some)` are the bytes; `Ok(None)` means nothing was read *on
    /// purpose*; `Err` is the reason the file has no content to report.
    body: Result<Option<Vec<u8>>, SkipReason>,
}

/// Stat first, and without following: the stat is what decides this is a thing
/// that can be read at all, which is the difference between a bounded read and
/// a `read()` on a fifo that never returns. Everything the stat knows — size,
/// mtime — is reported whether or not the content is, because "the agent read
/// your `.env`" is the finding and it does not require shipping the file.
fn probe(path: &Path, ceiling: usize, want_body: bool) -> Probe {
    let unreadable = Probe {
        bytes: 0,
        mtime: None,
        body: Err(SkipReason::Unreadable),
    };
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return unreadable;
    };
    // A symlink lands here as a symlink and is refused: following one reads a
    // file the tool never named, and `/tmp/x -> ~/.ssh/id_rsa` is the oldest
    // way to get a privileged reader to fetch something on your behalf — one
    // that would walk straight past an `exclude` list matching on the path the
    // agent said. Everything else that is not a regular file — fifo, device,
    // directory — is refused for the reason the stat comes first at all: those
    // reads are unbounded.
    if !md.is_file() {
        return unreadable;
    }
    let mut p = Probe {
        bytes: md.len(),
        mtime: md.modified().ok().map(DateTime::<Utc>::from),
        body: Ok(None),
    };
    // Unlike a payload body, an oversized file is not truncated. The payload
    // is in memory whether we want it or not, so keeping a prefix costs
    // nothing; reading a 2 GiB file off disk to keep 32 KiB of it is I/O this
    // daemon chose to do, for a prefix of a file it could not see anyway. The
    // size is still reported, which is what a query asking "what is this
    // deployment not capturing" needs.
    if md.len() > ceiling as u64 {
        p.body = Err(SkipReason::TooLarge);
        return p;
    }
    if !want_body {
        return p;
    }
    match read_capped(path, ceiling) {
        Ok(Some(b)) => {
            // The size now describes the same bytes a digest will: the file may
            // have been rewritten shorter between the stat and the read, and a
            // record whose two halves describe two versions is worse than one
            // that describes the later.
            p.bytes = b.len() as u64;
            p.body = Ok(Some(b));
        }
        // It grew between the stat and the read.
        Ok(None) => p.body = Err(SkipReason::TooLarge),
        Err(_) => p.body = Err(SkipReason::Unreadable),
    }
    p
}

/// Run the filesystem work with a deadline, giving up on the *answer* rather
/// than on the thread.
///
/// Nothing here cancels a read. A thread parked in the kernel on a mount that
/// stopped answering is not interruptible from userspace, and this does not
/// pretend to make it so — it hands that thread its own stack and stops waiting
/// for it. That is the whole difference between one lost thread and a Stage B
/// that never returns, taking the socket's backpressure with it.
///
/// A deadline of `0` means the caller wants no deadline, and gets the read
/// inline: no channel, no thread, no spawn cost per file.
fn with_deadline<T: Send + 'static>(ms: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    #[cfg(test)]
    record_deadline(ms);
    if ms == 0 {
        return Some(f());
    }
    // Capacity one so the worker's send never waits for a reader: a read that
    // finishes just after we stopped caring should end its thread, not park it
    // on a rendezvous with nobody.
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_millis(ms)).ok()
}

/// Test-only record of the deadline the last read was given. A timeout is only
/// observable by waiting for it, so a test that the *configured* number is the
/// one being used would otherwise have to be a slow test or a flaky one.
#[cfg(test)]
static LAST_DEADLINE_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

#[cfg(test)]
fn record_deadline(ms: u64) {
    LAST_DEADLINE_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}

/// What the file looks like now, rather than what the call claimed it would.
///
/// The policy half — which file, whether it may be read at all, what the bytes
/// are allowed to become. Everything that touches the filesystem is in
/// [`probe`], one call behind one deadline.
fn disk_snapshot(
    c: &Candidate,
    cwd: Option<&str>,
    capture: &CaptureCfg,
    filter: &PathFilter,
    budget: &mut usize,
) -> FileSnapshot {
    let cfg = &capture.file_contents;
    let mut snap = blank(c, 0, SnapshotSource::Disk);
    let Some(path) = resolve(&c.path, cwd) else {
        snap.skipped = Some(SkipReason::Unreadable);
        return snap;
    };
    let ceiling = content_ceiling(capture);
    let allowed = filter.allows(&c.path);
    // An excluded file is still opened when `hash` is on, and that is the
    // deliberate part: the digest is what makes one `.env` the same `.env`
    // across forty sessions. It is computed and the bytes are dropped — no
    // content of an excluded file reaches the snapshot below.
    let want_body = allowed || cfg.hash;
    let Some(p) = with_deadline(cfg.read_timeout_ms, move || {
        probe(&path, ceiling, want_body)
    }) else {
        // The read is still running somewhere, and may still be running when
        // the process exits. What it is not doing is holding up the batch.
        snap.skipped = Some(SkipReason::Unreadable);
        return snap;
    };
    snap.bytes = p.bytes;
    snap.mtime = p.mtime;
    let buf = match p.body {
        Ok(Some(b)) => b,
        Ok(None) => {
            snap.skipped = Some(SkipReason::Excluded);
            return snap;
        }
        Err(reason) => {
            snap.skipped = Some(reason);
            return snap;
        }
    };
    if cfg.hash {
        snap.sha256 = Some(sha256_hex(&buf));
    }
    if !allowed {
        snap.skipped = Some(SkipReason::Excluded);
        return snap;
    }
    // Bytes that are not text are binary by the same argument `looks_binary`
    // makes: a field every downstream query treats as text is the wrong place
    // for them.
    let text = match String::from_utf8(buf) {
        Ok(t) => t,
        Err(e) if !cfg.skip_binary => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        Err(_) => {
            snap.skipped = Some(SkipReason::Binary);
            return snap;
        }
    };
    if cfg.skip_binary && looks_binary(&text) {
        snap.skipped = Some(SkipReason::Binary);
        return snap;
    }
    if text.len() > *budget {
        snap.skipped = Some(SkipReason::Budget);
        return snap;
    }
    *budget -= text.len();
    snap.content = Some(text);
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
        snaps_in(tool, input, capture, None)
    }

    fn snaps_in(
        tool: &str,
        input: Value,
        capture: &CaptureCfg,
        cwd: Option<&str>,
    ) -> Vec<FileSnapshot> {
        let filter = PathFilter::new(&capture.file_contents);
        let kind = EventKind::ToolUse {
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
        let mut event = Event::new("claude-code", None, cwd.map(str::to_string), kind);
        super::capture(&mut event, capture, &filter);
        match event.kind {
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
    /// tool claims must not get the claim anyway — here the named file does not
    /// exist, so the honest answer is that nothing was read.
    #[test]
    fn disk_mode_takes_nothing_from_the_payload() {
        let c = on(|fc| fc.mode = ContentMode::Disk);
        let out = snaps(
            "Write",
            serde_json::json!({"file_path": "/nonexistent/a.rs", "content": "x"}),
            &c,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, SnapshotSource::Disk);
        assert_eq!(out[0].content, None, "the payload's claim was shipped");
        assert_eq!(out[0].skipped, Some(SkipReason::Unreadable));
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

    // --- disk capture ---

    fn disk() -> CaptureCfg {
        on(|fc| fc.mode = ContentMode::Disk)
    }

    /// Reads the file the way a `Read` tool call would name it: absolute path,
    /// no content in the payload at all.
    fn read_of(dir: &std::path::Path, name: &str, capture: &CaptureCfg) -> FileSnapshot {
        let path = dir.join(name).to_string_lossy().into_owned();
        let mut out = snaps("Read", serde_json::json!({ "file_path": path }), capture);
        assert_eq!(out.len(), 1, "expected exactly one snapshot");
        out.remove(0)
    }

    /// The whole reason disk mode exists: a call that only names a file says
    /// nothing about its contents, and that is most of what an agent does.
    #[test]
    fn disk_mode_reads_what_the_payload_never_carried() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let snap = read_of(dir.path(), "main.rs", &disk());
        assert_eq!(snap.source, SnapshotSource::Disk);
        assert_eq!(snap.action, FileAction::Read);
        assert_eq!(snap.content.as_deref(), Some("fn main() {}"));
        assert_eq!(snap.bytes, 12);
        assert_eq!(snap.skipped, None);
        assert!(!snap.truncated);
        assert_eq!(
            snap.sha256.as_deref(),
            Some(&sha256_hex(b"fn main() {}")[..])
        );
        assert!(snap.mtime.is_some(), "a disk snapshot with no mtime");
    }

    /// `hash = false` is a deployment saying it does not want digests of its
    /// files leaving the machine. The disk path has to enforce that on its own:
    /// unlike the payload path, it has the bytes in hand either way, so the
    /// cheap thing to do is hash them regardless.
    #[test]
    fn hashing_off_means_no_digest_even_when_the_bytes_were_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        let mut c = disk();
        c.file_contents.hash = false;

        let snap = read_of(dir.path(), "main.rs", &c);
        assert_eq!(snap.content.as_deref(), Some("fn main() {}"));
        assert_eq!(snap.sha256, None, "a digest nobody asked for");
    }

    /// `payload` mode does no I/O. A deployment that left the mode alone and
    /// turned capture on did not agree to the daemon opening files.
    #[test]
    fn payload_mode_never_touches_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        let path = dir.path().join("main.rs").to_string_lossy().into_owned();
        assert!(
            snaps(
                "Read",
                serde_json::json!({ "file_path": path }),
                &on(|_| {})
            )
            .is_empty(),
            "payload mode read a file off disk"
        );
    }

    /// `both` is not "twice": the payload half is exact and free, so it answers
    /// for the calls that carry a body, and the disk half answers for the rest.
    #[test]
    fn both_mode_prefers_the_payload_and_falls_back_to_the_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "on disk").unwrap();
        let path = dir.path().join("a.rs").to_string_lossy().into_owned();
        let c = on(|fc| fc.mode = ContentMode::Both);

        let written = snaps(
            "Write",
            serde_json::json!({"file_path": path, "content": "in payload"}),
            &c,
        );
        assert_eq!(written.len(), 1, "one call, one snapshot");
        assert_eq!(written[0].source, SnapshotSource::Payload);
        assert_eq!(written[0].content.as_deref(), Some("in payload"));

        let read = snaps("Read", serde_json::json!({ "file_path": path }), &c);
        assert_eq!(read[0].source, SnapshotSource::Disk);
        assert_eq!(read[0].content.as_deref(), Some("on disk"));
    }

    /// A symlink is how you get a reader to fetch a file nobody named — and it
    /// walks straight past an `exclude` list, which matches on the path the
    /// agent said, not on the path it resolves to.
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_reported_and_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_rsa"), "PRIVATE KEY").unwrap();
        std::os::unix::fs::symlink(dir.path().join("id_rsa"), dir.path().join("innocent.txt"))
            .unwrap();

        let snap = read_of(dir.path(), "innocent.txt", &disk());
        assert_eq!(snap.content, None, "the link's target was shipped");
        assert_eq!(snap.skipped, Some(SkipReason::Unreadable));
        assert_eq!(snap.sha256, None, "the target was read to hash it");
        // Not even measured. A stat that followed the link would refuse the
        // read and still record the target's size and mtime — which is how
        // large `id_rsa` is and when it last changed, for a file the tool
        // never named.
        assert_eq!(snap.bytes, 0, "the link's target was measured");
        assert_eq!(snap.mtime, None, "the link's target was measured");
    }

    /// Why the stat comes first. A `read()` on a fifo with no writer never
    /// returns, so a daemon that opened one would stop enriching events at all
    /// — this test hangs rather than fails if that guarantee goes.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_never_opened() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");

        let snap = read_of(dir.path(), "pipe", &disk());
        assert_eq!(snap.skipped, Some(SkipReason::Unreadable));
        assert_eq!(snap.content, None);
    }

    #[test]
    fn a_directory_is_not_a_file_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let snap = read_of(dir.path(), "sub", &disk());
        assert_eq!(snap.skipped, Some(SkipReason::Unreadable));
    }

    /// A patch header says `src/a.rs`. Which file that is depends on the
    /// session's cwd — resolving it against the daemon's would read a
    /// different file with the same name and record it as a success.
    #[test]
    fn a_relative_path_is_resolved_against_the_session_cwd() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), "let a = 1;").unwrap();
        let input = serde_json::json!({"file_path": "src/a.rs"});

        let here = snaps_in(
            "Read",
            input.clone(),
            &disk(),
            Some(&dir.path().to_string_lossy()),
        );
        assert_eq!(here[0].content.as_deref(), Some("let a = 1;"));

        let nowhere = snaps_in("Read", input, &disk(), None);
        assert_eq!(
            nowhere[0].skipped,
            Some(SkipReason::Unreadable),
            "a relative path was resolved against the daemon's own cwd"
        );
        assert_eq!(nowhere[0].content, None);
    }

    /// The exclusion is about content, not about the file's existence: the
    /// digest is what makes one `.env` the same `.env` across forty sessions,
    /// and it is not the file.
    #[test]
    fn an_excluded_file_is_hashed_on_disk_but_never_shipped() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "AWS_SECRET_ACCESS_KEY=x").unwrap();

        let snap = read_of(dir.path(), ".env", &disk());
        assert_eq!(snap.skipped, Some(SkipReason::Excluded));
        assert_eq!(snap.content, None, "an excluded file's body was shipped");
        assert_eq!(
            snap.sha256.as_deref(),
            Some(&sha256_hex(b"AWS_SECRET_ACCESS_KEY=x")[..])
        );
        assert_eq!(snap.bytes, 23);

        // And with hashing off there is no reason to open it at all.
        let mut c = disk();
        c.file_contents.hash = false;
        let unopened = read_of(dir.path(), ".env", &c);
        assert_eq!(unopened.skipped, Some(SkipReason::Excluded));
        assert_eq!(unopened.sha256, None);
        assert_eq!(
            unopened.bytes, 23,
            "the size came from the stat, not a read"
        );
    }

    /// With hashing off there is no reason to open an excluded file at all,
    /// and "no reason" has to mean "does not" — an unreadable `.env` that comes
    /// back as `unreadable` is one that was opened.
    #[cfg(unix)]
    #[test]
    fn an_excluded_file_is_not_opened_when_hashing_is_off() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads it regardless, so the test proves nothing
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "AWS_SECRET_ACCESS_KEY=x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut c = disk();
        c.file_contents.hash = false;

        let snap = read_of(dir.path(), ".env", &c);
        assert_eq!(
            snap.skipped,
            Some(SkipReason::Excluded),
            "an excluded file was opened for no one"
        );
        assert_eq!(snap.bytes, 23, "the size came from the stat, not a read");
    }

    /// An oversized file is reported by size and not read. Truncating a payload
    /// body is free — it is already in memory; reading gigabytes off disk to
    /// keep the first page of it is not.
    #[test]
    fn a_file_over_the_cap_is_measured_rather_than_read() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.rs"), "x".repeat(5000)).unwrap();
        let mut c = disk();
        c.file_contents.max_bytes = 100;

        let snap = read_of(dir.path(), "big.rs", &c);
        assert_eq!(snap.skipped, Some(SkipReason::TooLarge));
        assert_eq!(snap.content, None);
        assert!(!snap.truncated, "nothing was truncated; nothing was read");
        assert_eq!(snap.bytes, 5000, "the size is what the record is for");
        assert_eq!(snap.sha256, None, "a digest of a file nobody read");
    }

    /// The global field cap applies to a disk body for the reason it applies to
    /// a payload one: a later stage would cut it without setting the flag.
    #[test]
    fn the_global_field_cap_bounds_a_disk_read_too() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.rs"), "x".repeat(5000)).unwrap();
        let c = CaptureCfg {
            max_field_bytes: 200,
            ..disk()
        };
        assert_eq!(
            read_of(dir.path(), "big.rs", &c).skipped,
            Some(SkipReason::TooLarge)
        );
    }

    /// Two ways a file is not text, and both have to be caught: control bytes
    /// inside otherwise valid UTF-8, and bytes that are not UTF-8 at all.
    #[test]
    fn a_binary_file_on_disk_is_measured_and_not_shipped() {
        let dir = tempfile::tempdir().unwrap();
        let control = [0x4d, 0x5a, 0x00, 0x01]; // valid UTF-8, not text
        let invalid = [0x4d, 0x5a, 0xff, 0xfe]; // not UTF-8 at all
        std::fs::write(dir.path().join("control.bin"), control).unwrap();
        std::fs::write(dir.path().join("invalid.bin"), invalid).unwrap();

        for (name, bytes) in [("control.bin", control), ("invalid.bin", invalid)] {
            let snap = read_of(dir.path(), name, &disk());
            assert_eq!(snap.skipped, Some(SkipReason::Binary), "{name}");
            assert_eq!(snap.content, None, "{name}");
            assert_eq!(
                snap.sha256.as_deref(),
                Some(&sha256_hex(&bytes)[..]),
                "a file that is not shipped is still identified: {name}"
            );
        }

        // `skip_binary = false` means both of them come through, the invalid
        // one decoded lossily rather than dropped.
        let mut c = disk();
        c.file_contents.skip_binary = false;
        for name in ["control.bin", "invalid.bin"] {
            let snap = read_of(dir.path(), name, &c);
            assert!(
                snap.content.is_some(),
                "skip_binary = false ignored: {name}"
            );
            assert_eq!(snap.skipped, None, "{name}");
        }
    }

    /// The stat sized the file; the read is a second syscall against a path an
    /// untrusted agent chose. A file that grew in between comes back as a
    /// prefix, and a digest of a prefix matches no file anywhere — so the read
    /// asks for one byte more than it will accept.
    #[test]
    fn a_read_that_hits_its_limit_is_refused_rather_than_returned_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ten.txt");
        std::fs::write(&path, "0123456789").unwrap();

        assert_eq!(read_capped(&path, 10).unwrap().unwrap().len(), 10);
        assert_eq!(read_capped(&path, 100).unwrap().unwrap().len(), 10);
        assert!(
            read_capped(&path, 9).unwrap().is_none(),
            "returned a prefix"
        );
        assert!(
            read_capped(&path, 3).unwrap().is_none(),
            "returned a prefix"
        );
    }

    /// The stat refuses a symlink, but a stat and an open are two syscalls with
    /// a gap, and swapping the path for a link is the whole point of the gap.
    /// The open has to refuse one on its own.
    #[cfg(unix)]
    #[test]
    fn the_read_itself_refuses_to_follow_a_link() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_rsa"), "PRIVATE KEY").unwrap();
        let link = dir.path().join("innocent.txt");
        std::os::unix::fs::symlink(dir.path().join("id_rsa"), &link).unwrap();

        assert!(
            read_capped(&link, 4096).is_err(),
            "the open followed a link the stat had already refused"
        );
    }

    /// "Measured rather than read" is only a claim until the file cannot be
    /// read at all: a capture that opened it anyway would report `unreadable`
    /// here instead of the size the record exists to carry.
    #[cfg(unix)]
    #[test]
    fn an_oversized_file_is_not_opened_at_all() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root reads it regardless, so the test proves nothing
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.rs");
        std::fs::write(&path, "x".repeat(5000)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut c = disk();
        c.file_contents.max_bytes = 100;

        let snap = read_of(dir.path(), "big.rs", &c);
        assert_eq!(
            snap.skipped,
            Some(SkipReason::TooLarge),
            "an oversized file was opened before its size was checked"
        );
        assert_eq!(snap.bytes, 5000);
    }

    /// The two halves share one budget. A `mode = "both"` that gave each half
    /// its own would be quietly twice the number written in the config.
    #[test]
    fn the_per_event_byte_budget_covers_disk_reads() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..4 {
            std::fs::write(dir.path().join(format!("f{i}.rs")), "y".repeat(300)).unwrap();
        }
        let paths: Vec<String> = (0..4)
            .map(|i| {
                dir.path()
                    .join(format!("f{i}.rs"))
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        let patch: String = paths
            .iter()
            .map(|p| format!("*** Update File: {p}\n+y\n"))
            .collect();
        let mut c = disk();
        c.file_contents.max_total_bytes = 700;

        let out = snaps("apply_patch", serde_json::json!({ "patch": patch }), &c);
        assert_eq!(out.len(), 4, "every file is still named");
        let total: usize = out
            .iter()
            .map(|s| s.content.as_deref().unwrap_or("").len())
            .sum();
        assert!(total <= 700, "the byte budget was overrun: {total}");
        assert!(
            out.iter().any(|s| s.skipped == Some(SkipReason::Budget)),
            "a file dropped for budget did not say so: {out:?}"
        );
    }

    /// The hazard the deadline exists for, staged with the one thing that
    /// reliably never returns: a read on a fifo with no writer. Stat-first
    /// keeps that path out of `probe`, but a mount that stops answering
    /// mid-read is the same shape and cannot be staged in a unit test — so the
    /// read is called directly here, exactly as `probe` would call it.
    ///
    /// Without the deadline this test does not fail. It hangs, forever, which
    /// is precisely what it is asserting about Stage B.
    #[cfg(unix)]
    #[test]
    fn a_read_that_never_returns_is_given_up_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pipe");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");

        let started = std::time::Instant::now();
        let out = with_deadline(200, move || read_capped(&path, 4096).ok().flatten());
        assert!(out.is_none(), "a read that never returned returned");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "waited {:?} on a read that was supposed to be abandoned",
            started.elapsed()
        );
    }

    /// The deadline is a limit, not a policy of impatience: work that finishes
    /// inside it comes back whole.
    #[test]
    fn a_read_that_finishes_in_time_is_not_thrown_away() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.rs");
        std::fs::write(&path, "let a = 1;").unwrap();
        let got = with_deadline(60_000, move || read_capped(&path, 4096).unwrap());
        assert_eq!(got.flatten().as_deref(), Some(&b"let a = 1;"[..]));
    }

    /// A timeout is only observable by waiting for it, so the plumbing —
    /// configured number in, same number used — is checked directly rather
    /// than by a test that would have to be slow to be honest.
    #[test]
    fn the_configured_deadline_is_the_one_the_read_gets() {
        use std::sync::atomic::Ordering::Relaxed;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "let a = 1;").unwrap();
        let mut c = disk();
        c.file_contents.read_timeout_ms = 1234;

        LAST_DEADLINE_MS.store(u64::MAX, Relaxed);
        let snap = read_of(dir.path(), "a.rs", &c);
        assert_eq!(snap.content.as_deref(), Some("let a = 1;"));
        assert_eq!(
            LAST_DEADLINE_MS.load(Relaxed),
            1234,
            "the read was given a deadline nobody configured"
        );
    }

    /// `0` is the deployment that would rather block than lose a capture, and
    /// it has to mean *wait* — a zero passed through to `recv_timeout` would
    /// expire before any read could finish and turn the feature off silently.
    #[test]
    fn a_deadline_of_zero_waits_rather_than_capturing_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "let a = 1;").unwrap();
        let mut c = disk();
        c.file_contents.read_timeout_ms = 0;

        let snap = read_of(dir.path(), "a.rs", &c);
        assert_eq!(snap.content.as_deref(), Some("let a = 1;"));
        assert_eq!(snap.skipped, None);
    }
}
