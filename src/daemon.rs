use crate::{
    adapters, buffer::Buffer, config, config::ExportCfg, event::Envelope, event::Event,
    event::EventKind, export::Exporter, filecap::PathFilter, ipc, redact::Redactor, spool,
};
use anyhow::Result;
use std::sync::{Arc, RwLock};

/// Zero is a valid (explicit) config value elsewhere, but here it would make
/// the export loop busy-spin or peek zero-sized batches forever, so treat an
/// explicit zero as "use the default".
fn effective_flush_secs(cfg: &ExportCfg) -> u64 {
    if cfg.flush_interval_secs == 0 {
        10
    } else {
        cfg.flush_interval_secs
    }
}

fn effective_batch_size(cfg: &ExportCfg) -> usize {
    if cfg.batch_size == 0 {
        256
    } else {
        cfg.batch_size
    }
}

/// Both bounds on one batch. The row count is what the user tunes; the byte
/// budget is what the collector actually enforces.
fn batch_bounds(cfg: &ExportCfg) -> (usize, u64) {
    (effective_batch_size(cfg), cfg.max_batch_bytes)
}

pub async fn run() -> Result<()> {
    // First, before anything that can block: a stop request during startup is
    // not a rare case, it is what a supervisor restarting the service sends.
    let mut shutdown = Shutdown::new();
    // Single-instance guard: if another daemon already holds the socket, exit
    // cleanly rather than fighting over it.
    // Not always "already running" — `bind` also refuses an endpoint another
    // account owns, and reporting that as the ordinary case is how a squatted
    // socket stays invisible.
    let listener = match ipc::Listener::bind() {
        Ok(listener) => listener,
        // Only our own daemon holding the endpoint is a clean exit. Reporting
        // the rest that way — a squatted socket, an unwritable directory —
        // told every supervisor watching (systemd, launchd, a Jamf check)
        // that a process which records nothing had done its job, so the one
        // failure that silences the whole install is the one nobody is paged
        // for.
        Err(e) if e.downcast_ref::<ipc::AlreadyRunning>().is_some() => {
            tracing::info!("not starting: {e:#}");
            return Ok(());
        }
        Err(e) => return Err(e.context("cannot listen for hook events")),
    };
    // Before anything opens the buffer: an upgrade may need to bring one over
    // from the pre-0.2 location. Only the daemon does this, and only while it
    // holds the single-instance socket, so two of them cannot race over it.
    match crate::paths::migrate_legacy_data_dir() {
        crate::paths::Migration::Skipped => {}
        crate::paths::Migration::Moved { files } => {
            tracing::info!("migrated {files} files from the previous data directory")
        }
        crate::paths::Migration::Partial { files, left } => tracing::warn!(
            "migrated {files} files from the previous data directory; {} could not be copied \
             and were left in place: {left:?}",
            left.len()
        ),
    }
    crate::paths::create_private_dir(&crate::paths::data_dir())?;

    let shared_cfg = Arc::new(RwLock::new(config::load()));
    tokio::spawn(config::poll_loop(shared_cfg.clone()));

    let (tx, mut rx) = ipc::Ingress::channel();
    tokio::spawn(listener.accept_loop(tx.clone()));

    // Codex has no hook surface and speaks OTLP instead, so its events arrive
    // over a loopback HTTP listener rather than the socket. Same ingress queue
    // either way, so everything downstream is unaware of the difference.
    tokio::spawn(crate::adapters::codex::otlp_listener(
        shared_cfg.clone(),
        tx.clone(),
    ));

    let buffer = Arc::new(Buffer::open(&with_cfg(&shared_cfg, |c| c.buffer.clone()))?);

    let export_handle = tokio::spawn(export_loop(buffer.clone(), shared_cfg.clone()));
    tokio::spawn(crate::integrity::integrity_loop(
        shared_cfg.clone(),
        buffer.clone(),
    ));

    // Stages B and C. Stage A is this function's own loop.
    let (stages, writer) = Stages::spawn(buffer.clone(), stage_b_workers(), WRITE_QUEUE);

    // Pipeline: parse -> redact -> buffer. Both derived pieces are rebuilt
    // only when the fingerprint says the config behind them changed.
    let mut stage_a = StageA {
        pipeline: Pipeline::build(&shared_cfg),
        cfg: shared_cfg.clone(),
        buffer: buffer.clone(),
        stages,
    };

    // Spool replay: envelopes written while the daemon was down, or while the
    // shim could not reach it inside its deadline. It runs on this loop rather
    // than on a task of its own because a spool file may only be deleted once
    // its events are in the buffer, and the deletion is now Stage C's to do —
    // the origin path travels with the batch. First tick fires immediately, so
    // a backlog starts draining at startup.
    let mut spool_tick = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                tracing::info!("shutdown signal received, draining queued envelopes and flushing final batch");
                // Drain in stage order — A, then B, then C — because each
                // stage's work only exists once the one before it has handed
                // it over. Draining C first would flush an empty writer while
                // a worker still held the last batch.
                //
                // Stage A: whatever is already queued in the channel, so it
                // isn't silently dropped on shutdown.
                while let Some(envelope) = rx.try_recv() {
                    stage_a.accept(envelope, None).await;
                }
                // Stages B and C.
                drain(stage_a, writer).await;
                // Stop the export loop before the final flush so the two
                // can't race and double-export the same batch (harmless
                // under at-least-once, but noisy).
                export_handle.abort();
                final_flush(&buffer, &shared_cfg).await;
                break;
            }
            maybe_envelope = rx.recv() => {
                let Some(envelope) = maybe_envelope else { break };
                stage_a.accept(envelope, None).await;
            }
            _ = spool_tick.tick() => {
                replay_spool(&mut stage_a).await;
            }
        }
    }
    Ok(())
}

/// The operating system asking this process to stop.
///
/// Ctrl-C is how a developer stops the daemon; SIGTERM is how everything else
/// does — `systemctl stop`, launchd, a container runtime, a package upgrade,
/// `pkill argus`. Waiting only on the first left the ordinary shutdown taking
/// the signal's default disposition and dying on the spot, skipping the staged
/// drain and the final flush: every envelope still in the pipeline, and every
/// event buffered since the last export tick, gone. Those are the last events
/// before the machine went down, which is the window the buffer exists to
/// survive.
///
/// Built before the loop, never inside it. A handler is only installed when
/// its stream is created, and a select branch is not created until it is first
/// polled — so wiring this up lazily leaves a window across the whole of
/// startup where a stop request is still fatal. Startup is not a rare moment
/// to be signalled: it is exactly when a supervisor restarting the service
/// sends one.
struct Shutdown {
    #[cfg(unix)]
    term: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
}

impl Shutdown {
    fn new() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            // Nothing sane to fall back to if a handler cannot be installed,
            // so the daemon runs on without it: the default disposition still
            // stops the process, just without the drain.
            let install = |kind: SignalKind, name: &str| match signal(kind) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!("cannot listen for {name}; it will not drain cleanly: {e}");
                    None
                }
            };
            Shutdown {
                term: install(SignalKind::terminate(), "SIGTERM"),
                interrupt: install(SignalKind::interrupt(), "SIGINT"),
            }
        }
        #[cfg(not(unix))]
        Shutdown {}
    }

    /// Resolves on the first stop request that arrives.
    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            async fn next(s: &mut Option<tokio::signal::unix::Signal>) {
                match s {
                    Some(s) => {
                        s.recv().await;
                    }
                    // Parked, not resolved: a missing handler must not read as
                    // a signal that never came.
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                _ = next(&mut self.term) => {}
                _ = next(&mut self.interrupt) => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// Shut the pipeline down in stage order: A, then B, then C.
///
/// Dropping Stage A closes the queue into Stage C, and the writer task returns
/// once it has drained what is already in it — including the batches still
/// being enriched, since each one is awaited in submission order. Awaiting the
/// writer is the whole of stage C's drain: without it the process exits while
/// the last batches are still in flight, which is precisely the shutdown that
/// loses the events an operator most wanted to see.
async fn drain(stage_a: StageA, writer: tokio::task::JoinHandle<()>) {
    drop(stage_a);
    let _ = writer.await;
}

/// How many envelopes may be under enrichment at once.
///
/// Small on purpose. Stage B is CPU work on the blocking pool, and the point
/// of the bound is that a burst waits in the ingress queue — where it is
/// counted and byte-capped — instead of fanning out into an unbounded pile of
/// blocking tasks each holding a decoded payload.
fn stage_b_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4)
}

/// How many enriched batches may queue ahead of the single writer.
const WRITE_QUEUE: usize = 256;

/// A batch on its way to the buffer, and what may be deleted once it lands.
struct Pending {
    /// Resolved by the Stage B worker. Awaiting these in the order they were
    /// submitted is what keeps a parallel stage from reordering events.
    done: tokio::sync::oneshot::Receiver<Vec<Event>>,
    /// The spool file this batch came from, if any. Deleted only after the
    /// transaction commits: committing first can duplicate an event if the
    /// process dies in the window, and a duplicate is the failure that leaves
    /// evidence.
    origin: Option<std::path::PathBuf>,
}

/// Handle on Stage B (parallel enrichment) and Stage C (the single writer).
struct Stages {
    workers: Arc<tokio::sync::Semaphore>,
    write_tx: tokio::sync::mpsc::Sender<Pending>,
}

impl Stages {
    fn spawn(
        buffer: Arc<Buffer>,
        workers: usize,
        queue: usize,
    ) -> (Stages, tokio::task::JoinHandle<()>) {
        let (write_tx, write_rx) = tokio::sync::mpsc::channel(queue);
        let handle = tokio::spawn(write_loop(buffer, write_rx));
        (
            Stages {
                workers: Arc::new(tokio::sync::Semaphore::new(workers)),
                write_tx,
            },
            handle,
        )
    }

    /// Hand a parsed batch to Stage B and reserve its place in Stage C's
    /// queue. Returns once the batch has been *accepted*, not once it has
    /// landed — but it does not return while the pipeline is full, which is
    /// the whole mechanism: the caller stops draining the ingress queue, the
    /// shim's send deadline fires, and the payload goes to the spool.
    async fn submit(
        &self,
        events: Vec<Event>,
        redactor: Arc<Redactor>,
        paths: Arc<PathFilter>,
        capture: config::CaptureCfg,
        origin: Option<std::path::PathBuf>,
    ) {
        let Ok(permit) = self.workers.clone().acquire_owned().await else {
            return;
        };
        let (done_tx, done) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _ = done_tx.send(crate::enrich::enrich(events, &redactor, &capture, &paths));
        });
        let _ = self.write_tx.send(Pending { done, origin }).await;
    }
}

/// Stage C. The only writer, so the SQLite transaction is never contended,
/// and the only place a spool file is destroyed.
async fn write_loop(buffer: Arc<Buffer>, mut rx: tokio::sync::mpsc::Receiver<Pending>) {
    while let Some(Pending { done, origin }) = rx.recv().await {
        // An `Err` here is a Stage B worker that panicked. Its batch is gone
        // either way; what matters is that the spool file is not, so a replay
        // gets another chance at it.
        let Ok(events) = done.await else {
            tracing::error!("an enrichment worker died; its batch was not written");
            continue;
        };
        // One payload commonly becomes several events; write them together.
        match buffer.push_batch(&events) {
            Ok(()) => {
                if let Some(path) = origin {
                    spool::discard(&path);
                }
            }
            Err(e) => tracing::error!("buffer push failed: {e}"),
        }
    }
}

/// Stage A: parse, and hand off. Deliberately holds no lock and touches no
/// disk, because it is the one stage that cannot be run in parallel with
/// itself — everything it does is on the path of every envelope.
struct StageA {
    pipeline: Pipeline,
    cfg: Arc<RwLock<config::Config>>,
    buffer: Arc<Buffer>,
    stages: Stages,
}

impl StageA {
    async fn accept(&mut self, envelope: Envelope, origin: Option<std::path::PathBuf>) {
        self.pipeline.refresh(&self.cfg);
        // Two relaxed stores; the caps a reload changed take effect on the very
        // next write rather than at the next daemon restart. An operator who
        // raises a cap because the buffer is overflowing is not in a position
        // to be told to restart the thing that is losing their events.
        self.buffer.set_limits(&self.pipeline.buffer);
        let events = adapters::parse(envelope, &self.pipeline.capture);
        self.stages
            .submit(
                events,
                self.pipeline.redactor.clone(),
                self.pipeline.paths.clone(),
                self.pipeline.capture.clone(),
                origin,
            )
            .await;
    }
}

/// Export task: every `flush_interval_secs` (or sooner while backing off from
/// a failure), peek a batch and try to export it. On success the batch is
/// acked (at-least-once: only after a 2xx). On a retryable failure the batch
/// stays buffered and the wait grows exponentially, capped at ~30x the flush
/// interval (~5 min at the default 10s flush).
async fn export_loop(buffer: Arc<Buffer>, cfg: Arc<RwLock<config::Config>>) {
    let mut backoff = 1u64;
    loop {
        let (flush, bounds, exporter) = {
            let export_cfg = with_cfg(&cfg, |c| c.export.clone());
            (
                effective_flush_secs(&export_cfg),
                batch_bounds(&export_cfg),
                Exporter::new(&export_cfg),
            )
        };
        let wait = flush.saturating_mul(backoff).min(flush.saturating_mul(30));
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

        record_losses(&buffer);
        match export_once(&buffer, &exporter, bounds).await {
            Attempt::Failed => backoff = (backoff * 2).min(30),
            // A buffer we could not read says nothing about the collector, so
            // it neither backs off nor clears a backoff already in progress.
            Attempt::Unreadable => {}
            Attempt::Idle | Attempt::Sent | Attempt::Dropped => backoff = 1,
        }
    }
}

/// What one export attempt did. The loop reads this to decide the next wait,
/// and the shutdown flush reuses the same settlement rules.
#[derive(Debug, PartialEq, Eq)]
enum Attempt {
    Unreadable,
    Idle,
    Sent,
    /// The collector refused the batch for good. It has been dropped from the
    /// queue and a record of the gap left in its place.
    Dropped,
    Failed,
}

/// The `reason` on the record left behind by a refused batch. Also what stops
/// that record from becoming a batch of its own that gets refused, recorded,
/// refused…: a collector rejecting *everything* would otherwise mint one new
/// event per flush cycle forever, and the queue would never drain.
const EXPORT_REJECTED: &str = "export_rejected";

/// Peek one batch, send it, and settle it.
///
/// The settlement is the point. A 2xx acks. A retryable failure leaves the
/// batch alone. A refusal — the collector read the request and said no — acks
/// as well, because the alternative is a queue whose head can never be
/// delivered and never be discarded: it is re-sent every cycle while newer
/// events pile up behind it and are eventually evicted to make room. The batch
/// is lost either way at that point; the difference is whether the events
/// behind it are lost too, and whether anyone downstream is told.
async fn export_once(buffer: &Buffer, exporter: &Exporter, bounds: (usize, u64)) -> Attempt {
    let Ok(batch) = buffer.peek_batch(bounds.0, bounds.1) else {
        return Attempt::Unreadable;
    };
    if batch.is_empty() {
        return Attempt::Idle;
    }
    let last_seq = batch.last().unwrap().0;
    let events: Vec<_> = batch.iter().map(|(_, e)| e.clone()).collect();
    match exporter.export(&events).await {
        Ok(()) => {
            let _ = buffer.ack(last_seq, events.len());
            Attempt::Sent
        }
        Err(crate::export::Rejection::Transient(e)) => {
            tracing::warn!("export failed, will retry: {e}");
            Attempt::Failed
        }
        Err(crate::export::Rejection::Permanent { status, detail }) => {
            tracing::error!(
                "collector refused {} events with {status} ({detail}); dropping the batch so \
                 the queue keeps moving",
                events.len()
            );
            let _ = buffer.ack(last_seq, events.len());
            if !is_gap_record(&events) {
                let _ = buffer.push(&Event::new(
                    "argus",
                    None,
                    None,
                    EventKind::Loss {
                        reason: EXPORT_REJECTED.into(),
                        count: events.len() as u64,
                        detail: format!("collector returned {status}: {detail}"),
                    },
                ));
            }
            Attempt::Dropped
        }
    }
}

/// Whether a batch is made of nothing but earlier reports of refusal.
fn is_gap_record(events: &[Event]) -> bool {
    events
        .iter()
        .all(|e| matches!(&e.kind, EventKind::Loss { reason, .. } if reason == EXPORT_REJECTED))
}

/// Replay one bounded batch of spooled envelopes, deleting each file only once
/// its events are committed to the buffer.
///
/// The ordering is the whole point. The spool exists so that a daemon outage
/// costs nothing, and the old code deleted the file *before* handing the
/// envelope on — so a crash anywhere between the unlink and the SQLite commit
/// destroyed the one copy that existed. Committing first can duplicate an
/// event if the process dies in the window; the pipeline is at-least-once
/// already, and a duplicate is the failure that leaves evidence.
///
/// The commit is no longer visible from here — it happens in Stage C, several
/// stages downstream — so the path travels with the batch instead, and Stage C
/// unlinks it. The rule is unchanged; only who enforces it moved.
async fn replay_spool(stage_a: &mut StageA) -> usize {
    let mut replayed = 0;
    for (path, envelope) in spool::take(spool::DRAIN_BATCH) {
        stage_a.accept(envelope, Some(path)).await;
        replayed += 1;
    }
    replayed
}

/// Fold any buffer overflow since the last flush into the queue, ahead of the
/// batch it is about to describe.
///
/// Done here rather than at trim time because the trim happens precisely when
/// the buffer has no room: writing the marker there would evict another event
/// to make space for the news that events are being evicted.
fn record_losses(buffer: &Buffer) {
    if let Err(e) = buffer.flush_loss_record() {
        tracing::error!("could not record buffer overflow: {e}");
    }
}

/// Best-effort final export on graceful shutdown; never blocks longer than
/// one export attempt and swallows failures (the batch stays buffered for
/// the next daemon run either way).
async fn final_flush(buffer: &Buffer, cfg: &Arc<RwLock<config::Config>>) {
    record_losses(buffer);
    let export_cfg = with_cfg(cfg, |c| c.export.clone());
    let bounds = batch_bounds(&export_cfg);
    let exporter = Exporter::new(&export_cfg);
    export_once(buffer, &exporter, bounds).await;
}

/// Everything the per-envelope path derives from config, plus the fingerprint
/// it was derived from.
///
/// The config sits behind an `RwLock` a poll loop may rewrite at any moment,
/// and the previous code reached into it three times per envelope — each time
/// cloning the *entire* `Config` (every table in it, remote URL, headers, the
/// lot) to read one field. The regexes were already cached; the capture
/// settings were not, and paid a full clone per event to read five booleans.
struct Pipeline {
    redactor: Arc<Redactor>,
    /// Compiled once per config generation, for the same reason the redactor
    /// is: these regexes are matched against every path in every tool call.
    paths: Arc<PathFilter>,
    capture: config::CaptureCfg,
    buffer: config::BufferCfg,
    fingerprint: String,
}

impl Pipeline {
    fn build(cfg: &Arc<RwLock<config::Config>>) -> Self {
        let (redactor, paths, capture, buffer) = with_cfg(cfg, |c| {
            (
                Arc::new(Redactor::new(&c.redaction)),
                Arc::new(PathFilter::new(&c.capture.file_contents)),
                c.capture.clone(),
                c.buffer.clone(),
            )
        });
        Pipeline {
            redactor,
            paths,
            capture,
            buffer,
            fingerprint: config_fingerprint(cfg),
        }
    }

    /// Cheap on the common path: one string compare against a live config
    /// read, and a rebuild only when it differs.
    fn refresh(&mut self, cfg: &Arc<RwLock<config::Config>>) {
        let current = config_fingerprint(cfg);
        if current != self.fingerprint {
            *self = Pipeline::build(cfg);
            self.fingerprint = current;
        }
    }
}

fn with_cfg<T>(cfg: &Arc<RwLock<config::Config>>, f: impl FnOnce(&config::Config) -> T) -> T {
    f(&cfg.read().unwrap_or_else(|e| e.into_inner()))
}

/// Must cover every field [`Pipeline`] caches, or a live config reload leaves
/// the daemon running on the old value forever. `capture` was absent while it
/// was re-read per event; caching it makes its inclusion load-bearing.
fn config_fingerprint(cfg: &Arc<RwLock<config::Config>>) -> String {
    with_cfg(cfg, |c| {
        format!(
            "{}:{:?}:{:?}:{:?}",
            c.redaction.enabled, c.redaction.extra_patterns, c.capture, c.buffer
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> Arc<RwLock<config::Config>> {
        Arc::new(RwLock::new(config::Config::default()))
    }

    /// A daemon that cannot listen has to say so in the only language a
    /// supervisor reads. Exiting 0 makes systemd and launchd record a clean
    /// run, so the machine keeps a daemon that captures nothing and no monitor
    /// ever notices.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unbindable_endpoint_is_a_failed_start() {
        let sock = std::env::temp_dir().join(format!(
            "lm-daemon-missing-{}/nowhere/argus.sock",
            std::process::id()
        ));
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &sock);
        }
        let started = run().await;
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
        assert!(
            started.is_err(),
            "the daemon reported success without a socket to listen on"
        );
    }

    /// Anything the pipeline caches must show up in the fingerprint. The
    /// alternative is not a slow daemon but a wrong one: a live config change
    /// that never takes effect, with nothing to indicate it was ignored.
    #[test]
    fn every_cached_setting_invalidates_the_pipeline() {
        let cfg = shared();
        let mut pipeline = Pipeline::build(&cfg);
        let before = pipeline.fingerprint.clone();

        cfg.write().unwrap().capture.prompts = !config::CaptureCfg::default().prompts;
        assert_ne!(
            config_fingerprint(&cfg),
            before,
            "a capture change must invalidate the cached pipeline"
        );
        pipeline.refresh(&cfg);
        assert_eq!(
            pipeline.capture.prompts,
            !config::CaptureCfg::default().prompts,
            "refresh must pick the new capture settings up"
        );

        // The capture table is nested, and `{:?}` on the outer struct is only
        // load-bearing as long as every inner one is in it. A deployment that
        // tightens `exclude` and sees no change until the next restart has
        // been shipping the files it just banned.
        let after_prompts = pipeline.fingerprint.clone();
        cfg.write()
            .unwrap()
            .capture
            .file_contents
            .exclude
            .push("/secrets/".into());
        assert_ne!(
            config_fingerprint(&cfg),
            after_prompts,
            "a file_contents change must invalidate the cached pipeline"
        );
        pipeline.refresh(&cfg);
        assert!(
            pipeline
                .capture
                .file_contents
                .exclude
                .iter()
                .any(|p| p == "/secrets/"),
            "refresh must pick the new exclusions up"
        );

        let after_capture = pipeline.fingerprint.clone();
        cfg.write().unwrap().redaction.extra_patterns = vec!["ACME-[0-9]{6}".into()];
        assert_ne!(
            config_fingerprint(&cfg),
            after_capture,
            "a redaction change must invalidate the cached pipeline"
        );
        pipeline.refresh(&cfg);
        let scrubbed = pipeline
            .redactor
            .scrub_str("badge ACME-123456")
            .into_owned();
        assert!(
            scrubbed.contains("[REDACTED:custom-0]"),
            "refresh must rebuild the regexes: {scrubbed}"
        );

        let after_redaction = pipeline.fingerprint.clone();
        cfg.write().unwrap().buffer.max_bytes = 4096;
        assert_ne!(
            config_fingerprint(&cfg),
            after_redaction,
            "a buffer cap change must invalidate the cached pipeline"
        );
        pipeline.refresh(&cfg);
        assert_eq!(
            pipeline.buffer.max_bytes, 4096,
            "refresh must pick the new caps up, or the daemon enforces the old \
             one until someone restarts it"
        );
    }

    fn envelope(n: u32) -> Envelope {
        Envelope {
            cloud_identity: Default::default(),
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "UserPromptSubmit",
                "prompt": format!("p{n}"),
            }),
        }
    }

    /// Stage A wired to a real Stage B and C, with bounds a test can reach.
    fn stages_for(
        buffer: &Arc<Buffer>,
        workers: usize,
        queue: usize,
    ) -> (StageA, tokio::task::JoinHandle<()>) {
        let cfg = shared();
        let (stages, writer) = Stages::spawn(buffer.clone(), workers, queue);
        (
            StageA {
                pipeline: Pipeline::build(&cfg),
                cfg,
                buffer: buffer.clone(),
                stages,
            },
            writer,
        )
    }

    fn prompts_in_buffer(buffer: &Buffer) -> Vec<String> {
        buffer
            .peek_batch(usize::MAX, u64::MAX)
            .unwrap()
            .into_iter()
            .filter_map(|(_, e)| match e.kind {
                EventKind::Prompt { text } => Some(text),
                _ => None,
            })
            .collect()
    }

    /// The spool is the thing that makes a daemon outage free, and deleting a
    /// file before its contents are committed made it the one place where a
    /// crash cost an event outright.
    ///
    /// The commit is no longer visible from the replay loop — it happens in
    /// Stage C — so this asserts the rule where it now lives: a batch that
    /// never reached the buffer must leave its spool file behind, and one that
    /// did must not.
    #[tokio::test]
    async fn a_spool_file_outlives_the_replay_that_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = Arc::new(buffer_in(dir.path()));
        for i in 0..3 {
            spool::append(&envelope(i)).unwrap();
        }

        // A batch that never reaches the buffer — here because its enrichment
        // worker died — must leave every file exactly where it found it. This
        // is the kill-mid-drain case, minus the kill.
        let orphan = spool::take(usize::MAX)[0].0.clone();
        let (write_tx, write_rx) = tokio::sync::mpsc::channel(4);
        let writer = tokio::spawn(write_loop(buffer.clone(), write_rx));
        let (done_tx, done) = tokio::sync::oneshot::channel::<Vec<Event>>();
        drop(done_tx);
        write_tx
            .send(Pending {
                done,
                origin: Some(orphan),
            })
            .await
            .unwrap();
        drop(write_tx);
        writer.await.unwrap();
        assert_eq!(
            spool::take(usize::MAX).len(),
            3,
            "a batch that was never committed destroyed the only copy of the events"
        );

        // And a replay that does commit may only delete once it has: the
        // files are still there the moment `replay_spool` returns, because
        // nothing has been written yet.
        let (mut stage_a, writer) = stages_for(&buffer, 2, 8);
        assert_eq!(replay_spool(&mut stage_a).await, 3);
        drain(stage_a, writer).await;
        assert!(
            spool::take(usize::MAX).is_empty(),
            "committed envelopes left their spool files behind, so they replay forever"
        );
        assert_eq!(prompts_in_buffer(&buffer), ["p0", "p1", "p2"]);
    }

    /// Backpressure, not loss. When Stage B cannot keep up, Stage A has to
    /// wait — which stops it draining the ingress queue, which is what makes
    /// the shim's send deadline fire and spool the payload. Every one of those
    /// steps is a delay; none of them is a discarded event.
    #[tokio::test]
    async fn a_slow_stage_b_backpressures_rather_than_dropping_events() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = Arc::new(buffer_in(dir.path()));
        // One worker, a one-deep queue: the pipeline is full after the second
        // batch and every submission after that has to wait for a real one to
        // finish.
        let (mut stage_a, writer) = stages_for(&buffer, 1, 1);
        crate::enrich::set_delay(20_000, 0);

        let started = std::time::Instant::now();
        for i in 0..8 {
            stage_a.accept(envelope(i), None).await;
        }
        let submitting = started.elapsed();
        crate::enrich::set_delay(0, 0);

        drain(stage_a, writer).await;

        assert!(
            submitting >= std::time::Duration::from_millis(100),
            "submission took {submitting:?}: Stage A did not wait for a full pipeline, so              the queue ahead of it is unbounded after all"
        );
        assert_eq!(
            prompts_in_buffer(&buffer),
            ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"],
            "events were dropped rather than delayed"
        );
    }

    /// Two different bounds sit on either side of Stage B: how many batches may
    /// be enriched at once, and how many finished ones may queue ahead of the
    /// writer. A test that only slows the enrichers cannot tell them apart —
    /// the worker semaphore blocks first and the queue is never reached.
    ///
    /// So park Stage C on a batch that never finishes enriching. Nothing is
    /// waiting on an enricher after that, and the only thing left that can make
    /// Stage A wait is the depth of the queue in front of the writer.
    #[tokio::test]
    async fn a_full_write_queue_blocks_stage_a_as_well() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = Arc::new(buffer_in(dir.path()));
        // Eight enrichers for four batches: Stage B has a permit to spare for
        // every submission this test makes.
        let (mut stage_a, _writer) = stages_for(&buffer, 8, 1);

        let (never, done) = tokio::sync::oneshot::channel::<Vec<Event>>();
        stage_a
            .stages
            .write_tx
            .send(Pending { done, origin: None })
            .await
            .unwrap();
        // Give Stage C the chance to take it and park.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let submitting = tokio::time::timeout(std::time::Duration::from_millis(250), async {
            for i in 0..4 {
                stage_a.accept(envelope(i), None).await;
            }
        })
        .await;
        assert!(
            submitting.is_err(),
            "four batches queued ahead of a stalled writer without waiting: the queue \
             between Stage B and Stage C grows without bound"
        );
        drop(never);
    }

    /// Redaction is the entire reason Stage B exists as a stage. Moving it off
    /// the single consumer is only safe if it still happens, and the stage
    /// boundary is exactly where a refactor can drop it silently: everything
    /// downstream keeps working, and the buffer quietly fills with secrets.
    #[tokio::test]
    async fn the_pipeline_redacts_before_anything_reaches_the_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = Arc::new(buffer_in(dir.path()));
        let (mut stage_a, writer) = stages_for(&buffer, 2, 8);

        let mut secret = envelope(0);
        secret.payload["prompt"] =
            serde_json::json!("use sk-ant-api03-AbCd1234567890abcdef1234 for this");
        stage_a.accept(secret, None).await;
        drain(stage_a, writer).await;

        let prompts = prompts_in_buffer(&buffer);
        assert_eq!(prompts.len(), 1, "the batch never landed: {prompts:?}");
        assert!(
            !prompts[0].contains("sk-ant-api03"),
            "an unredacted key reached the buffer: {}",
            prompts[0]
        );
        assert!(
            prompts[0].contains("[REDACTED:anthropic-key]"),
            "the prompt lost its key without being redacted: {}",
            prompts[0]
        );
    }

    /// Stage B runs several batches at once; the buffer must still see them in
    /// the order they arrived. Ordering is most of what a security trail is
    /// for — "the file was read, then the request went out" and the reverse
    /// are different incidents.
    ///
    /// The throttle decays, so batch 0 is the slowest and batch 7 the
    /// fastest: a Stage C that wrote batches as they *finished* would produce
    /// exactly the reverse of this.
    #[tokio::test]
    async fn parallel_enrichment_does_not_reorder_events() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = Arc::new(buffer_in(dir.path()));
        let (mut stage_a, writer) = stages_for(&buffer, 8, 64);
        crate::enrich::set_delay(40_000, 5_000);

        for i in 0..8 {
            stage_a.accept(envelope(i), None).await;
        }
        crate::enrich::set_delay(0, 0);
        drain(stage_a, writer).await;

        assert_eq!(
            prompts_in_buffer(&buffer),
            ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"],
            "a parallel Stage B reordered the trail"
        );
    }

    /// End to end: the overflow has to reach the queue that gets exported,
    /// not just a counter someone might read.
    #[test]
    fn an_overflow_reaches_the_export_queue_as_an_event() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let buffer = Buffer::open(&config::BufferCfg {
            max_events: 3,
            max_bytes: u64::MAX,
        })
        .unwrap();
        for i in 0..5 {
            let e = crate::event::Event::new(
                "claude-code",
                None,
                None,
                crate::event::EventKind::Prompt {
                    text: format!("p{i}"),
                },
            );
            buffer.push(&e).unwrap();
        }
        record_losses(&buffer);
        let queued = buffer.peek_batch(10, 0).unwrap();
        let loss = queued
            .iter()
            .find_map(|(_, e)| match &e.kind {
                crate::event::EventKind::Loss { count, .. } => Some(*count),
                _ => None,
            })
            .expect("the drop record must be queued for export");
        assert_eq!(loss, 2);
        record_losses(&buffer);
        assert_eq!(
            buffer
                .peek_batch(10, 0)
                .unwrap()
                .iter()
                .filter(|(_, e)| matches!(e.kind, crate::event::EventKind::Loss { .. }))
                .count(),
            1,
            "a quiet flush must not re-report a gap it already reported"
        );
    }

    /// An unchanged config must not rebuild anything — the rebuild recompiles
    /// every redaction regex, which is exactly what the fingerprint exists to
    /// avoid doing per event.
    #[test]
    fn an_unchanged_config_does_not_rebuild() {
        use std::sync::atomic::Ordering::Relaxed;
        let cfg = shared();
        let mut pipeline = Pipeline::build(&cfg);
        let before = crate::redact::REDACTOR_BUILDS.load(Relaxed);
        for _ in 0..100 {
            pipeline.refresh(&cfg);
        }
        assert_eq!(
            crate::redact::REDACTOR_BUILDS.load(Relaxed),
            before,
            "an unchanged config recompiled the redaction patterns"
        );

        cfg.write().unwrap().redaction.enabled = !config::RedactionCfg::default().enabled;
        pipeline.refresh(&cfg);
        pipeline.refresh(&cfg);
        assert_eq!(
            crate::redact::REDACTOR_BUILDS.load(Relaxed),
            before + 1,
            "a change rebuilds exactly once, then settles"
        );
    }

    /// A collector answering a fixed status, and the exporter pointed at it.
    fn collector(status: u16) -> (Exporter, std::net::SocketAddr) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = match server.server_addr() {
            tiny_http::ListenAddr::IP(a) => a,
            #[allow(unreachable_patterns)]
            other => panic!("unexpected listen address {other:?}"),
        };
        std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let _ = req.respond(
                    tiny_http::Response::from_string("no").with_status_code(status as u32),
                );
            }
        });
        let cfg = config::ExportCfg {
            otlp_endpoint: Some(format!("http://{addr}")),
            ..Default::default()
        };
        (Exporter::new(&cfg), addr)
    }

    fn buffer_in(dir: &std::path::Path) -> Buffer {
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir);
        }
        Buffer::open(&config::BufferCfg::default()).unwrap()
    }

    fn prompt(n: u32) -> Event {
        Event::new(
            "claude-code",
            None,
            None,
            EventKind::Prompt {
                text: format!("p{n}"),
            },
        )
    }

    /// The wedge this exists to prevent: a batch the collector will never
    /// accept, sitting at the head of the queue forever while everything
    /// behind it is eventually evicted to make room.
    #[tokio::test]
    async fn a_refused_batch_drains_and_leaves_a_record_of_the_gap() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = buffer_in(dir.path());
        let (exporter, _addr) = collector(400);
        for i in 0..3 {
            buffer.push(&prompt(i)).unwrap();
        }

        assert_eq!(
            export_once(&buffer, &exporter, (100, 0)).await,
            Attempt::Dropped,
            "a 400 must settle the batch, not park it"
        );
        let left = buffer.peek_batch(100, 0).unwrap();
        assert_eq!(left.len(), 1, "the three refused events must be gone");
        match &left[0].1.kind {
            EventKind::Loss {
                reason,
                count,
                detail,
            } => {
                assert_eq!(reason, EXPORT_REJECTED);
                assert_eq!(*count, 3, "the gap must say how many events it covers");
                assert!(detail.contains("400"), "{detail}");
            }
            other => panic!("expected a loss record, got {other:?}"),
        }

        // …and the record of the gap does not itself become an endless source
        // of new records when the collector refuses that too.
        assert_eq!(
            export_once(&buffer, &exporter, (100, 0)).await,
            Attempt::Dropped
        );
        assert!(buffer.is_empty().unwrap(), "the queue must reach empty");
        assert_eq!(
            export_once(&buffer, &exporter, (100, 0)).await,
            Attempt::Idle
        );
    }

    /// The other half: an outage must not be mistaken for a refusal, or a
    /// collector restart would silently destroy everything queued during it.
    #[tokio::test]
    async fn an_outage_keeps_the_batch_for_the_next_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = buffer_in(dir.path());
        let (exporter, _addr) = collector(503);
        for i in 0..3 {
            buffer.push(&prompt(i)).unwrap();
        }

        assert_eq!(
            export_once(&buffer, &exporter, (100, 0)).await,
            Attempt::Failed
        );
        assert_eq!(
            buffer.len().unwrap(),
            3,
            "a retryable failure must leave the batch buffered"
        );
    }

    /// The budget is only worth having if the loop passes the configured one:
    /// a bound that never leaves the config file bounds nothing, and the
    /// difference is invisible until a collector starts refusing requests.
    #[tokio::test]
    async fn the_export_loop_sends_no_more_than_the_configured_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let buffer = buffer_in(dir.path());
        let (exporter, addr) = collector(200);
        for i in 0..10 {
            buffer.push(&prompt(i)).unwrap();
        }
        // Summed from the stored bodies, not assumed uniform: a timestamp
        // serializes to a different width from one event to the next.
        let four: u64 = buffer
            .peek_batch(4, 0)
            .unwrap()
            .iter()
            .map(|(_, e)| serde_json::to_string(e).unwrap().len() as u64)
            .sum();

        let cfg = config::ExportCfg {
            otlp_endpoint: Some(format!("http://{addr}")),
            max_batch_bytes: four,
            ..Default::default()
        };
        assert_eq!(
            export_once(&buffer, &exporter, batch_bounds(&cfg)).await,
            Attempt::Sent
        );
        assert_eq!(
            buffer.len().unwrap(),
            6,
            "the configured budget must reach the batch, not just the config"
        );

        // The row cap is wired through the same call and is just as invisible
        // when it isn't.
        let by_rows = config::ExportCfg {
            batch_size: 2,
            max_batch_bytes: 0,
            ..cfg
        };
        assert_eq!(
            export_once(&buffer, &exporter, batch_bounds(&by_rows)).await,
            Attempt::Sent
        );
        assert_eq!(buffer.len().unwrap(), 4, "the configured row cap too");
    }
}
