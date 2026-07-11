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
    std::fs::create_dir_all(crate::paths::data_dir())?;

    let shared_cfg = Arc::new(RwLock::new(config::load()));
    tokio::spawn(config::poll_loop(shared_cfg.clone()));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Envelope>(1024);
    tokio::spawn(listener.accept_loop(tx.clone()));

    // Spool drain: pick up events written while the daemon was down (or the
    // hook shim couldn't reach it within its deadline).
    let spool_tx = tx.clone();
    tokio::spawn(async move {
        loop {
            for env in spool::drain().unwrap_or_default() {
                let _ = spool_tx.send(env).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    // Codex OTLP receiver (Task 13 wires real events into tx; stub for now).
    tokio::spawn(crate::adapters::codex::otlp_listener(
        shared_cfg.clone(),
        tx.clone(),
    ));

    let max_events = read_cfg(&shared_cfg).buffer.max_events;
    let buffer = Arc::new(Buffer::open(max_events)?);

    let export_handle = tokio::spawn(export_loop(buffer.clone(), shared_cfg.clone()));

    // Pipeline: parse -> redact -> buffer. Redactor rebuilt when redaction
    // config changes (cheap fingerprint check, avoids rebuilding regexes on
    // every event).
    let mut redactor = Redactor::new(&read_cfg(&shared_cfg).redaction);
    let mut redactor_gen = config_fingerprint(&shared_cfg);

    // Shared by both select arms so a drained-on-shutdown envelope goes
    // through the exact same parse -> redact -> buffer pipeline as one
    // received during normal operation.
    let mut process = |envelope: Envelope| {
        let current = config_fingerprint(&shared_cfg);
        if current != redactor_gen {
            redactor = Redactor::new(&read_cfg(&shared_cfg).redaction);
            redactor_gen = current;
        }
        let capture = read_cfg(&shared_cfg).capture.clone();
        for event in adapters::parse(envelope, &capture) {
            let event = redactor.scrub_event(event);
            if let Err(e) = buffer.push(&event) {
                tracing::error!("buffer push failed: {e}");
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
            let export_cfg = read_cfg(&cfg).export.clone();
            (
                effective_flush_secs(&export_cfg),
                effective_batch_size(&export_cfg),
                Exporter::new(&export_cfg),
            )
        };
        let wait = flush.saturating_mul(backoff).min(flush.saturating_mul(30));
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;

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

/// Best-effort final export on graceful shutdown; never blocks longer than
/// one export attempt and swallows failures (the batch stays buffered for
/// the next daemon run either way).
async fn final_flush(buffer: &Buffer, cfg: &Arc<RwLock<config::Config>>) {
    let export_cfg = read_cfg(cfg).export.clone();
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

fn read_cfg(cfg: &Arc<RwLock<config::Config>>) -> config::Config {
    cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
}

fn config_fingerprint(cfg: &Arc<RwLock<config::Config>>) -> String {
    let c = cfg.read().unwrap_or_else(|e| e.into_inner());
    format!("{}:{:?}", c.redaction.enabled, c.redaction.extra_patterns)
}
