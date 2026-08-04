use crate::event::Envelope;
use crate::paths;
use anyhow::{anyhow, Result};
use interprocess::local_socket::{
    tokio::{prelude::*, Stream as AsyncStream},
    traits::Stream as _,
    GenericFilePath, ListenerOptions, Stream, ToFsName,
};
#[cfg(windows)]
use interprocess::local_socket::{GenericNamespaced, ToNsName};
use tokio::io::{AsyncBufReadExt, BufReader};

// `GenericFilePath` maps to a plain filesystem path for a Unix-domain socket on
// Unix. On Windows, `interprocess`'s `GenericFilePath` only accepts paths already
// shaped `\\.\pipe\...` (or `\\HOST\pipe\...`) and rejects everything else,
// including arbitrary `ARGUS_SOCKET` overrides such as `C:\Temp\x.sock` or a
// test's `temp_dir()` path. So on Windows we detect an already-pipe-shaped name and
// pass it through via `GenericFilePath`; otherwise we take just the final path
// component (stripping any directory) and map it via `GenericNamespaced`, which
// prepends `\\.\pipe\` itself, yielding a working named pipe for any override.
#[cfg(unix)]
fn name() -> Result<interprocess::local_socket::Name<'static>> {
    Ok(paths::socket_name()
        .to_fs_name::<GenericFilePath>()?
        .into_owned())
}

#[cfg(windows)]
fn name() -> Result<interprocess::local_socket::Name<'static>> {
    let raw = paths::socket_name();
    if raw.to_ascii_lowercase().starts_with(r"\\.\pipe\") {
        return Ok(raw.to_fs_name::<GenericFilePath>()?.into_owned());
    }
    // Arbitrary override path: use only the final component as the namespaced
    // name so `GenericNamespaced` can prepend `\\.\pipe\` and produce a valid name.
    let leaf = std::path::Path::new(&raw)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or(raw);
    Ok(leaf.to_ns_name::<GenericNamespaced>()?.into_owned())
}

/// Blocking one-shot send used by the hook shim hot path.
pub fn send(envelope: &Envelope) -> Result<()> {
    use std::io::Write;
    let mut conn = Stream::connect(name()?)?;
    let mut frame = serde_json::to_vec(envelope)?;
    frame.push(b'\n');
    conn.write_all(&frame)?;
    conn.flush()?;
    Ok(())
}

/// Best-effort connectivity probe used by `argus status`: true if a
/// daemon is currently listening on the configured socket. Opens and
/// immediately drops the connection; sends nothing.
pub fn is_daemon_running() -> bool {
    let Ok(n) = name() else { return false };
    Stream::connect(n).is_ok()
}

pub struct Listener {
    inner: interprocess::local_socket::tokio::Listener,
}

impl Listener {
    pub fn bind() -> Result<Self> {
        // Liveness probe: if a daemon is already listening on this socket,
        // connecting succeeds. Bail out rather than stealing the socket out
        // from under a live daemon (which would keep running orphaned). The
        // probe connection is dropped immediately; the accept side already
        // tolerates a zero-byte connection (`lines.next_line()` returns
        // `Ok(None)` on EOF and the handler just exits).
        if let Ok(n) = name() {
            if Stream::connect(n).is_ok() {
                return Err(anyhow!("daemon already running"));
            }
        }
        // No live daemon: remove a stale socket file left by a crashed
        // daemon (Unix only) before binding.
        #[cfg(unix)]
        let _ = std::fs::remove_file(paths::socket_name());
        let inner = ListenerOptions::new().name(name()?).create_tokio()?;
        Ok(Listener { inner })
    }

    pub async fn accept_loop(self, tx: tokio::sync::mpsc::Sender<Envelope>) {
        loop {
            let Ok(conn) = self.inner.accept().await else {
                continue;
            };
            let tx = tx.clone();
            tokio::spawn(async move { handle(conn, tx).await });
        }
    }
}

async fn handle(conn: AsyncStream, tx: tokio::sync::mpsc::Sender<Envelope>) {
    let mut lines = BufReader::new(conn).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<Envelope>(&line) {
            Ok(env) => {
                let _ = tx.send(env).await;
            }
            Err(e) => tracing::warn!("dropping malformed frame: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Envelope;

    #[tokio::test]
    async fn shim_send_reaches_daemon_listener() {
        let sock = std::env::temp_dir().join(format!("lm-ipc-{}.sock", std::process::id()));
        unsafe { std::env::set_var("ARGUS_SOCKET", &sock); }

        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            event: None,
            payload: serde_json::json!({"hook_event_name": "UserPromptSubmit"}),
        };
        let env2 = env.clone();
        tokio::task::spawn_blocking(move || send(&env2).unwrap())
            .await
            .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.source, "claude-code");
        unsafe { std::env::remove_var("ARGUS_SOCKET"); }
    }

    /// A malformed (non-JSON) frame must be logged and dropped, not crash the
    /// accept loop or the connection — a valid frame sent afterwards on the same
    /// connection must still arrive through the channel.
    #[tokio::test]
    async fn malformed_frame_is_dropped_without_crashing_loop() {
        let sock =
            std::env::temp_dir().join(format!("lm-ipc-malformed-{}.sock", std::process::id()));
        unsafe { std::env::set_var("ARGUS_SOCKET", &sock); }

        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            event: None,
            payload: serde_json::json!({"hook_event_name": "UserPromptSubmit"}),
        };
        let env2 = env.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            use std::io::Write;
            let mut conn = Stream::connect(name()?)?;
            // Malformed line first: not valid JSON at all.
            conn.write_all(b"not json at all\n")?;
            // Then a well-formed envelope on the same connection.
            let mut frame = serde_json::to_vec(&env2)?;
            frame.push(b'\n');
            conn.write_all(&frame)?;
            conn.flush()?;
            Ok(())
        })
        .await
        .unwrap()
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.source, "claude-code");
        unsafe { std::env::remove_var("ARGUS_SOCKET"); }
    }

    #[tokio::test]
    async fn second_bind_fails_while_daemon_alive() {
        let sock = std::env::temp_dir().join(format!("lm-ipc-guard-{}.sock", std::process::id()));
        unsafe { std::env::set_var("ARGUS_SOCKET", &sock); }
        let listener = Listener::bind().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let second = tokio::task::spawn_blocking(Listener::bind).await.unwrap();
        assert!(
            second.is_err(),
            "second bind must fail while first daemon is alive"
        );
        unsafe { std::env::remove_var("ARGUS_SOCKET"); }
    }
}
