use crate::event::Envelope;
use crate::paths;
use anyhow::Result;
use interprocess::local_socket::{
    tokio::{prelude::*, Stream as AsyncStream},
    traits::Stream as _,
    GenericFilePath, ListenerOptions, Stream, ToFsName,
};
use tokio::io::{AsyncBufReadExt, BufReader};

// `GenericFilePath` is documented to work on both platforms: on Unix it maps to a
// plain filesystem path for a Unix-domain socket; on Windows it accepts paths that
// already start with `\\.\pipe\` (which is exactly what `paths::socket_name()`
// produces by default) and passes them through unchanged. Using it uniformly here
// (rather than `GenericNamespaced` on Windows) keeps `LLM_MONITOR_SOCKET` working
// as an override on every platform and avoids double-prefixing the pipe name.
fn name() -> Result<interprocess::local_socket::Name<'static>> {
    Ok(paths::socket_name()
        .to_fs_name::<GenericFilePath>()?
        .into_owned())
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

pub struct Listener {
    inner: interprocess::local_socket::tokio::Listener,
}

impl Listener {
    pub fn bind() -> Result<Self> {
        // Remove a stale socket file left by a crashed daemon (Unix only).
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
        std::env::set_var("LLM_MONITOR_SOCKET", &sock);

        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
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
        std::env::remove_var("LLM_MONITOR_SOCKET");
    }
}
