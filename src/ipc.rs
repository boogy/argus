use crate::event::Envelope;
use crate::paths;
use anyhow::{Result, anyhow};
use interprocess::local_socket::{
    GenericFilePath, ListenerOptions, Stream, ToFsName,
    tokio::{Stream as AsyncStream, prelude::*},
    traits::Stream as _,
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
        if let Ok(n) = name()
            && Stream::connect(n).is_ok()
        {
            return Err(anyhow!("daemon already running"));
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

/// Largest single frame the daemon will assemble from a connection.
///
/// The socket is reachable by every process running as this user, and framing
/// is newline-delimited, so "one frame" was previously "everything the peer
/// sends until it feels like sending a newline". A `yes | argus-socket` — or a
/// host tool that dumps a core file into a hook payload — grew a `Vec` in the
/// daemon until the kernel killed it, taking the whole audit trail with it.
///
/// 16 MiB is twice what a legitimate shim can produce: its stdin is capped at
/// [`crate::hook::MAX_STDIN_BYTES`] (8 MiB) and JSON escaping only exceeds 2x
/// on text that is almost entirely control bytes.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Read newline-delimited frames without letting any one of them grow past
/// [`MAX_FRAME_BYTES`].
///
/// An oversized frame is discarded and the reader resynchronises on the next
/// newline, so the connection survives it exactly as it survives a malformed
/// one — a peer that sends one bad frame has not earned the right to end the
/// conversation for the good frames behind it.
async fn handle(conn: AsyncStream, tx: tokio::sync::mpsc::Sender<Envelope>) {
    let mut reader = BufReader::new(conn);
    let mut frame: Vec<u8> = Vec::new();
    let mut overflowed = false;
    loop {
        // `fill_buf` borrows the reader for as long as its slice lives, and
        // `consume` needs the borrow back, so the decision is made and the
        // bytes copied inside this scope and only the counts escape it.
        let (consumed, complete) = {
            let Ok(buf) = reader.fill_buf().await else {
                break;
            };
            if buf.is_empty() {
                break; // EOF
            }
            match buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    push_bounded(&mut frame, &buf[..i], &mut overflowed);
                    (i + 1, true)
                }
                None => {
                    push_bounded(&mut frame, buf, &mut overflowed);
                    (buf.len(), false)
                }
            }
        };
        reader.consume(consumed);
        if complete {
            dispatch(&mut frame, &mut overflowed, &tx).await;
        }
    }
    // A last frame with no trailing newline is still a frame; the previous
    // line-based reader delivered it and dropping it here would lose the final
    // event of every shim that forgets the terminator.
    dispatch(&mut frame, &mut overflowed, &tx).await;
}

/// Append `chunk` unless doing so would breach the cap, in which case record
/// that this frame is already unusable and stop copying. Deliberately does not
/// keep a truncated prefix: half an envelope is not a smaller envelope, and
/// holding onto it only spends the memory the cap exists to save.
fn push_bounded(frame: &mut Vec<u8>, chunk: &[u8], overflowed: &mut bool) {
    if *overflowed || frame.len() + chunk.len() > MAX_FRAME_BYTES {
        *overflowed = true;
        frame.clear();
        return;
    }
    frame.extend_from_slice(chunk);
    #[cfg(test)]
    PEAK_FRAME_BYTES.fetch_max(frame.len(), std::sync::atomic::Ordering::Relaxed);
}

/// High-water mark of the reassembly buffer. The whole point of the cap is a
/// number that never appears in the output: a daemon that buffers 2 GiB and
/// one that refuses to produce byte-for-byte identical events right up until
/// the first is killed. Recording the peak is what makes the difference
/// assertable.
#[cfg(test)]
pub(crate) static PEAK_FRAME_BYTES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

async fn dispatch(
    frame: &mut Vec<u8>,
    overflowed: &mut bool,
    tx: &tokio::sync::mpsc::Sender<Envelope>,
) {
    if std::mem::take(overflowed) {
        tracing::warn!("dropping frame over the {MAX_FRAME_BYTES}-byte limit");
        frame.clear();
        return;
    }
    if frame.is_empty() {
        return;
    }
    match serde_json::from_slice::<Envelope>(frame) {
        Ok(env) => {
            let _ = tx.send(env).await;
        }
        Err(e) => tracing::warn!("dropping malformed frame: {e}"),
    }
    frame.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Envelope;

    #[tokio::test]
    async fn shim_send_reaches_daemon_listener() {
        let sock = std::env::temp_dir().join(format!("lm-ipc-{}.sock", std::process::id()));
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &sock);
        }

        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
    }

    /// A malformed (non-JSON) frame must be logged and dropped, not crash the
    /// accept loop or the connection — a valid frame sent afterwards on the same
    /// connection must still arrive through the channel.
    #[tokio::test]
    async fn malformed_frame_is_dropped_without_crashing_loop() {
        let sock =
            std::env::temp_dir().join(format!("lm-ipc-malformed-{}.sock", std::process::id()));
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &sock);
        }

        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
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
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
    }

    /// The socket answers to every process running as this user, and framing is
    /// newline-delimited — so before the cap, "one frame" meant "whatever the
    /// peer sends until it chooses to send a newline". The failure is not a
    /// rejected event; it is the daemon being killed by the OOM reaper while
    /// holding the only copy of everything not yet exported.
    #[tokio::test]
    async fn an_endless_frame_cannot_grow_the_daemon_without_limit() {
        use std::sync::atomic::Ordering::Relaxed;
        let sock = std::env::temp_dir().join(format!("lm-ipc-huge-{}.sock", std::process::id()));
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &sock);
        }
        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));
        PEAK_FRAME_BYTES.store(0, Relaxed);

        let env = Envelope {
            source: "claude-code".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({"hook_event_name": "UserPromptSubmit"}),
        };
        let env2 = env.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            use std::io::Write;
            let mut conn = Stream::connect(name()?)?;
            // One frame, comfortably past the cap, with no newline in sight.
            let chunk = vec![b'a'; 1024 * 1024];
            for _ in 0..(MAX_FRAME_BYTES / chunk.len() + 2) {
                conn.write_all(&chunk)?;
            }
            conn.write_all(b"\n")?;
            // ...followed by a perfectly good one on the same connection.
            let mut frame = serde_json::to_vec(&env2)?;
            frame.push(b'\n');
            conn.write_all(&frame)?;
            conn.flush()?;
            Ok(())
        })
        .await
        .unwrap()
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the oversized frame took the connection down with it")
            .unwrap();
        assert_eq!(
            got.source, "claude-code",
            "a peer that sent one bad frame must not silence the good ones behind it"
        );
        assert!(
            PEAK_FRAME_BYTES.load(Relaxed) <= MAX_FRAME_BYTES,
            "reassembly reached {} bytes, past the {MAX_FRAME_BYTES}-byte cap",
            PEAK_FRAME_BYTES.load(Relaxed)
        );
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
    }

    /// `send` always terminates its frame, but the accept side is reachable by
    /// anything running as this user — including the opencode plugin, which
    /// speaks this socket from TypeScript. The old line reader delivered a
    /// final unterminated frame on EOF, and quietly losing the last event of
    /// every session that closes without a newline is the kind of gap that
    /// looks like the session simply ended there.
    #[tokio::test]
    async fn a_frame_that_ends_at_eof_instead_of_a_newline_still_arrives() {
        let sock = std::env::temp_dir().join(format!("lm-ipc-eof-{}.sock", std::process::id()));
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &sock);
        }
        let listener = Listener::bind().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));

        let env = Envelope {
            source: "opencode".into(),
            received_at: chrono::Utc::now(),
            truncated: false,
            dropped: 0,
            event: None,
            payload: serde_json::json!({"type": "tool.execute.before"}),
        };
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            use std::io::Write;
            let mut conn = Stream::connect(name()?)?;
            conn.write_all(&serde_json::to_vec(&env)?)?; // no trailing newline
            conn.flush()?;
            Ok(()) // dropping `conn` here is the only end-of-frame signal
        })
        .await
        .unwrap()
        .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("the last frame of the connection was never delivered")
            .unwrap();
        assert_eq!(got.source, "opencode");
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
    }

    /// The accumulator is the thing being bounded, so it is worth pinning
    /// directly: an overflowed frame keeps nothing, and the flag survives until
    /// the frame that tripped it is fully consumed — otherwise the tail of a
    /// discarded frame gets parsed as if it were the start of the next one.
    #[test]
    fn an_overflowed_frame_keeps_nothing_and_stays_overflowed() {
        let mut frame = Vec::new();
        let mut overflowed = false;

        push_bounded(&mut frame, &vec![b'a'; 1024], &mut overflowed);
        assert_eq!(frame.len(), 1024);
        assert!(!overflowed);

        push_bounded(&mut frame, &vec![b'a'; MAX_FRAME_BYTES], &mut overflowed);
        assert!(overflowed);
        assert!(frame.is_empty(), "a partial frame is not a smaller frame");

        // A chunk that would fit on its own must not un-poison the frame it is
        // arriving in the middle of.
        push_bounded(&mut frame, b"}\n", &mut overflowed);
        assert!(overflowed);
        assert!(frame.is_empty());
    }

    #[tokio::test]
    async fn second_bind_fails_while_daemon_alive() {
        let sock = std::env::temp_dir().join(format!("lm-ipc-guard-{}.sock", std::process::id()));
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &sock);
        }
        let listener = Listener::bind().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(listener.accept_loop(tx));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let second = tokio::task::spawn_blocking(Listener::bind).await.unwrap();
        assert!(
            second.is_err(),
            "second bind must fail while first daemon is alive"
        );
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
    }
}
