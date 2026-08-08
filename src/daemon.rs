use crate::{
    adapters, buffer::Buffer, config, config::ExportCfg, event::Envelope, export::Exporter, ipc,
    redact::Redactor, spool,
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

pub async fn run() -> Result<()> {
    // Single-instance guard: if another daemon already holds the socket, exit
    // cleanly rather than fighting over it.
    let Ok(listener) = ipc::Listener::bind() else {
        tracing::info!("daemon already running; exiting");
        return Ok(());
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
    std::fs::create_dir_all(crate::paths::data_dir())?;

    let shared_cfg = Arc::new(RwLock::new(config::load()));
    tokio::spawn(config::poll_loop(shared_cfg.clone()));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(1024);
    tokio::spawn(listener.accept_loop(tx.clone()));

    // Codex OTLP receiver (Task 13 wires real events into tx; stub for now).
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

    // Pipeline: parse -> redact -> buffer. Both derived pieces are rebuilt
    // only when the fingerprint says the config behind them changed.
    let mut pipeline = Pipeline::build(&shared_cfg);

    // Shared by both select arms so a drained-on-shutdown envelope goes
    // through the exact same parse -> redact -> buffer pipeline as one
    // received during normal operation.
    // Spool replay: envelopes written while the daemon was down, or while the
    // shim could not reach it inside its deadline. It runs on this loop rather
    // than on a task of its own because a spool file may only be deleted once
    // its events are in the buffer, and the buffer is here. First tick fires
    // immediately, so a backlog starts draining at startup.
    let mut spool_tick = tokio::time::interval(std::time::Duration::from_secs(5));

    let mut process = |envelope: Envelope| -> bool {
        pipeline.refresh(&shared_cfg);
        // Two relaxed stores; the caps a reload changed take effect on the very
        // next write rather than at the next daemon restart. An operator who
        // raises a cap because the buffer is overflowing is not in a position
        // to be told to restart the thing that is losing their events.
        buffer.set_limits(&pipeline.buffer);
        let events: Vec<_> = adapters::parse(envelope, &pipeline.capture)
            .into_iter()
            .map(|e| pipeline.redactor.scrub_event(e))
            .collect();
        // One payload commonly becomes several events; write them together.
        // The bool is what makes delete-after-commit possible: only a caller
        // that knows the transaction committed may destroy its source.
        match buffer.push_batch(&events) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("buffer push failed: {e}");
                false
            }
        }
    };

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown signal received, draining queued envelopes and flushing final batch");
                // Drain whatever is already queued in the channel so it
                // isn't silently dropped on shutdown.
                while let Ok(envelope) = rx.try_recv() {
                    process(envelope);
                }
                // Stop the export loop before the final flush so the two
                // can't race and double-export the same batch (harmless
                // under at-least-once, but noisy).
                export_handle.abort();
                final_flush(&buffer, &shared_cfg).await;
                break;
            }
            maybe_envelope = rx.recv() => {
                let Some(envelope) = maybe_envelope else { break };
                process(envelope);
            }
            _ = spool_tick.tick() => {
                replay_spool(&mut process);
            }
        }
    }
    Ok(())
}

/// Export task: every `flush_interval_secs` (or sooner while backing off from
/// a failure), peek a batch and try to export it. On success the batch is
/// acked (at-least-once: only after a 2xx). On failure the batch stays
/// buffered and the wait grows exponentially, capped at ~30x the flush
/// interval (~5 min at the default 10s flush).
async fn export_loop(buffer: Arc<Buffer>, cfg: Arc<RwLock<config::Config>>) {
    let mut backoff = 1u64;
    loop {
        let (flush, batch_size, exporter) = {
            let export_cfg = with_cfg(&cfg, |c| c.export.clone());
            (
                effective_flush_secs(&export_cfg),
                effective_batch_size(&export_cfg),
                Exporter::new(&export_cfg),
            )
        };
        let wait = flush.saturating_mul(backoff).min(flush.saturating_mul(30));
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

        record_losses(&buffer);
        let Ok(batch) = buffer.peek_batch(batch_size) else {
            continue;
        };
        if batch.is_empty() {
            backoff = 1;
            continue;
        }
        let events: Vec<_> = batch.iter().map(|(_, e)| e.clone()).collect();
        match exporter.export(&events).await {
            Ok(()) => {
                let _ = buffer.ack(batch.last().unwrap().0);
                backoff = 1;
            }
            Err(e) => {
                tracing::warn!("export failed, will retry: {e}");
                backoff = (backoff * 2).min(30);
            }
        }
    }
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
fn replay_spool(process: &mut impl FnMut(Envelope) -> bool) -> usize {
    let mut replayed = 0;
    for (path, envelope) in spool::take(spool::DRAIN_BATCH) {
        if process(envelope) {
            spool::discard(&path);
            replayed += 1;
        }
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
    let batch_size = effective_batch_size(&export_cfg);
    let Ok(batch) = buffer.peek_batch(batch_size) else {
        return;
    };
    if batch.is_empty() {
        return;
    }
    let exporter = Exporter::new(&export_cfg);
    let events: Vec<_> = batch.iter().map(|(_, e)| e.clone()).collect();
    if exporter.export(&events).await.is_ok() {
        let _ = buffer.ack(batch.last().unwrap().0);
    }
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
    redactor: Redactor,
    capture: config::CaptureCfg,
    buffer: config::BufferCfg,
    fingerprint: String,
}

impl Pipeline {
    fn build(cfg: &Arc<RwLock<config::Config>>) -> Self {
        let (redactor, capture, buffer) = with_cfg(cfg, |c| {
            (
                Redactor::new(&c.redaction),
                c.capture.clone(),
                c.buffer.clone(),
            )
        });
        Pipeline {
            redactor,
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

    /// The spool is the thing that makes a daemon outage free, and deleting a
    /// file before its contents are committed made it the one place where a
    /// crash cost an event outright.
    #[test]
    fn a_spool_file_outlives_the_replay_that_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let env = |n: u32| Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            event: None,
            payload: serde_json::json!({
                "hook_event_name": "UserPromptSubmit",
                "prompt": format!("p{n}"),
            }),
        };
        for i in 0..3 {
            spool::append(&env(i)).unwrap();
        }

        // A replay that cannot commit must leave every file exactly where it
        // found it — this is the kill-mid-drain case, minus the kill.
        assert_eq!(replay_spool(&mut |_| false), 0);
        assert_eq!(
            spool::take(usize::MAX).len(),
            3,
            "a failed commit destroyed the only copy of the events"
        );

        // And a replay that does commit may only delete once it has.
        let mut seen = 0;
        let replayed = replay_spool(&mut |_| {
            assert_eq!(
                spool::take(usize::MAX).len(),
                3 - seen,
                "the file was deleted before its envelope was committed"
            );
            seen += 1;
            true
        });
        assert_eq!(replayed, 3);
        assert!(spool::take(usize::MAX).is_empty());
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
        let queued = buffer.peek_batch(10).unwrap();
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
                .peek_batch(10)
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
}
