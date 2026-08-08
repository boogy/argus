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
        // Ownership before liveness, so that "somebody else is holding this
        // name" is never reported as "our daemon is already running".
        #[cfg(unix)]
        prepare_unix_endpoint()?;
        // Liveness probe: if a daemon is already listening on this socket,
        // connecting succeeds. Bail out rather than stealing the socket out
        // from under a live daemon (which would keep running orphaned). The
        // probe connection is dropped immediately; the accept side already
        // tolerates a zero-byte connection (EOF just ends the handler).
        if let Ok(n) = name()
            && Stream::connect(n).is_ok()
        {
            return Err(anyhow!("daemon already running"));
        }
        // No live daemon: remove a stale socket file left by a crashed
        // daemon (Unix only) before binding. Safe to unlink unconditionally
        // only because `prepare_unix_endpoint` has established it is ours.
        #[cfg(unix)]
        let _ = std::fs::remove_file(paths::socket_name());
        #[cfg(any(unix, windows))]
        let inner = create_owner_only()?;
        #[cfg(not(any(unix, windows)))]
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

/// Establish that the endpoint we are about to bind is ours, and that nothing
/// outside this account can reach it.
///
/// `bind` used to read *any* successful `Stream::connect` as "our daemon is
/// already running" and exit quietly. A process squatting the name got exactly
/// the same answer, which is the worst available outcome for a security
/// monitor: argus never starts, `status` cheerfully reports a reachable
/// daemon, and the hook payloads — raw, pre-redaction, redaction being
/// daemon-side — go to whoever is listening. A monitor that can be switched
/// off silently is worse than no monitor, because the absence of events reads
/// as the absence of activity.
///
/// Two things are checked, because they fail independently: a socket file
/// belonging to another uid, and a *directory* another uid can write, which
/// lets them replace the socket whatever the socket itself says.
#[cfg(unix)]
fn prepare_unix_endpoint() -> Result<()> {
    let path = std::path::PathBuf::from(paths::socket_name());
    // SAFETY: `getuid` cannot fail and touches no memory.
    let us = unsafe { libc::getuid() };

    // Only for the endpoint we picked ourselves. `ARGUS_SOCKET` names an exact
    // path the way `ARGUS_DATA_DIR` does, and tightening a directory the user
    // deliberately pointed us at — `/tmp`, a shared runtime dir — is not ours
    // to do.
    if std::env::var_os("ARGUS_SOCKET").is_none()
        && let Some(dir) = path.parent()
    {
        // Also the point at which the data directory first comes into
        // existence on a clean install: `bind` runs before anything else in
        // the daemon, so without this a first `argus daemon` on a machine no
        // hook has fired on yet fails on a missing directory.
        std::fs::create_dir_all(dir)?;
        secure_dir(dir, us)?;
    }

    // `symlink_metadata`, not `metadata`: a symlink pointing somewhere the
    // attacker does own is the cheap version of this attack, and following it
    // would report the target's owner instead of the planter's.
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        check_owner(&meta, &path, us)?;
    }
    Ok(())
}

#[cfg(unix)]
fn secure_dir(dir: &std::path::Path, us: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(dir)?;
    check_owner(&meta, dir, us)?;
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, PermissionsExt::from_mode(0o700))?;
    }
    Ok(())
}

/// Split out and given the uid rather than calling `getuid` inside, because a
/// test cannot create a file owned by somebody else without being root — but
/// it can ask what happens when *we* are somebody else.
#[cfg(unix)]
fn check_owner(meta: &std::fs::Metadata, what: &std::path::Path, us: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != us {
        return Err(anyhow!(
            "{} is owned by uid {}, not {us} — refusing to use it. Another account's daemon, \
             or a process squatting the name; either way the events would not be ours to read.",
            what.display(),
            meta.uid(),
        ));
    }
    Ok(())
}

/// Bind with the socket file readable and writable by this uid only.
///
/// The mode is applied by `fchmod` *before* `bind`, closing the umask race, but
/// `fchmod` on a socket is `EINVAL` on Darwin — which `interprocess` reports as
/// `Unsupported`, and no file is left behind when it does. So the retry is not
/// a workaround: on Darwin the socket's own mode was never what protected it
/// (the kernel ignores it when deciding who may connect), the `0700` directory
/// is. The mode is the belt for the platforms that honour it.
#[cfg(unix)]
fn create_owner_only() -> Result<interprocess::local_socket::tokio::Listener> {
    use interprocess::os::unix::local_socket::ListenerOptionsExt;
    match ListenerOptions::new()
        .name(name()?)
        .mode(0o600)
        .create_tokio()
    {
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            #[cfg(test)]
            MODE_FALLBACKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(ListenerOptions::new().name(name()?).create_tokio()?)
        }
        other => Ok(other?),
    }
}

/// How many times the socket mode was asked for and refused.
///
/// Which branch ran is otherwise invisible from outside, and the two platforms
/// are supposed to disagree here — on Darwin "the mode was applied" and "the
/// mode was never attempted" produce the same bound socket, because the kernel
/// ignores socket modes either way. Counting the refusals is what separates
/// them, and so what lets a machine that takes the fallback still prove the
/// mode is being asked for on the machines that honour it. Same pattern as
/// [`PEAK_FRAME_BYTES`].
#[cfg(all(unix, test))]
pub(crate) static MODE_FALLBACKS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Bind the pipe with a DACL that names this account and nobody else.
///
/// A pipe created with no security descriptor gets the default one, which
/// `CreateNamedPipe` documents as granting full control to LocalSystem, to
/// administrators and to the creator owner — and *read access to Everyone and
/// to the anonymous account*. On a shared machine that is every other logged-in
/// user: they can connect, occupy the listening instance, and hold the pipe
/// open while hook payloads time out behind them. The unique name from
/// [`paths::windows_pipe_name`] keeps two installs from colliding by accident,
/// but a name is not a permission — the pipe namespace is enumerable, so an
/// attacker never has to guess it.
#[cfg(windows)]
fn create_owner_only() -> Result<interprocess::local_socket::tokio::Listener> {
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    Ok(ListenerOptions::new()
        .name(name()?)
        .security_descriptor(owner_only_descriptor()?)
        .create_tokio()?)
}

#[cfg(windows)]
fn owner_only_descriptor()
-> Result<interprocess::os::windows::security_descriptor::SecurityDescriptor> {
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    let sddl = owner_only_sddl(&current_user_sid()?);
    let wide = widestring::U16CString::from_str(&sddl)?;
    SecurityDescriptor::deserialize(&wide)
        .map_err(|e| anyhow!("cannot build the pipe's security descriptor from {sddl:?}: {e}"))
}

/// The pipe's DACL, in [security descriptor string format][sdsf].
///
/// `D:P` makes the DACL *protected*: no ACE is inherited, so nothing granted
/// further up can widen it behind our back. The one ACE allows (`A`) generic-all
/// (`GA`) to a single SID. Deliberately absent: `WD` (Everyone) and `AN`
/// (anonymous), which the default pipe DACL grants read; and `BA`
/// (administrators), because an administrator can take ownership regardless and
/// writing the grant down would only make the ACL lie about who normally reads
/// the events.
///
/// Not `#[cfg(windows)]`, for the same reason as [`paths::windows_pipe_name`]:
/// a guarantee testable only on the platform CI runs least often is one nobody
/// notices breaking.
///
/// [sdsf]: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
pub fn owner_only_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

/// Closes the process token however [`current_user_sid`] leaves.
#[cfg(windows)]
struct TokenHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `OpenProcessToken` and this
        // is the only close, `TokenHandle` being neither `Copy` nor `Clone`.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// This account's SID in string form (`S-1-5-21-…`).
///
/// Read from the process token rather than from the user name: the name is
/// ambiguous across a domain and a local account, and SDDL wants a SID anyway.
#[cfg(windows)]
fn current_user_sid() -> Result<String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut raw_token: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle needing no close, and
    // `raw_token` is a valid out-pointer read only after a success return.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(anyhow!(
            "cannot open this process's token: {}",
            std::io::Error::last_os_error()
        ));
    }
    let token = TokenHandle(raw_token);

    // A `TOKEN_USER` is a header followed by a variable-length SID, so the first
    // call is only there to learn the length; it is expected to fail with
    // `ERROR_INSUFFICIENT_BUFFER` and its return value is deliberately ignored.
    let mut len = 0u32;
    // SAFETY: a null buffer with length 0 is the documented way to ask for the
    // size, and `len` is a valid out-pointer.
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut len) };
    // `u64`, not `u8`: the buffer is cast to a struct holding a pointer, and a
    // `Vec<u8>`'s 1-byte alignment would make that cast unsound.
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` is at least `len` bytes and correctly aligned for `TOKEN_USER`.
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(anyhow!(
            "cannot read this account's SID from the process token: {}",
            std::io::Error::last_os_error()
        ));
    }

    // SAFETY: on success the buffer holds a well-formed `TOKEN_USER`, and the
    // SID it points at lives in the same buffer, so it outlives this borrow.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_str: windows_sys::core::PWSTR = ptr::null_mut();
    // SAFETY: `user.User.Sid` is the SID just read; `sid_str` is a valid
    // out-pointer for a string the call allocates on the local heap.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_str) } == 0 {
        return Err(anyhow!(
            "cannot render this account's SID as a string: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: on success the call wrote a NUL-terminated wide string.
    let sid = unsafe { widestring::U16CStr::from_ptr_str(sid_str) }.to_string_lossy();
    // SAFETY: `ConvertSidToStringSidW` documents `LocalFree` as the way to
    // release what it allocated, and nothing borrows it past `to_string_lossy`.
    unsafe { LocalFree(sid_str.cast()) };
    Ok(sid)
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

    /// The whole point of the ownership check. A test cannot create a file
    /// owned by another uid without being root, so it asks the equivalent
    /// question from the other side: what does argus do when the endpoint it
    /// finds was left by somebody who is not us?
    #[cfg(unix)]
    #[test]
    fn an_endpoint_owned_by_someone_else_is_refused_by_name() {
        // SAFETY: `getuid` cannot fail and touches no memory.
        let us = unsafe { libc::getuid() };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("argus.sock");
        std::fs::write(&path, b"").unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();

        check_owner(&meta, &path, us).expect("our own endpoint must be usable");

        let err = check_owner(&meta, &path, us.wrapping_add(1))
            .expect_err("an endpoint belonging to another account must not be adopted")
            .to_string();
        assert!(
            err.contains("argus.sock") && err.contains(&us.to_string()),
            "the error has to name the endpoint and the owner: {err}"
        );
        // The distinction is the whole fix. `daemon::run` logs this and exits
        // either way; if the two read alike, a squatted endpoint is a line in
        // the log that says the install is healthy.
        assert!(
            !err.starts_with("daemon already running"),
            "a foreign owner must not be reported as our own daemon: {err}"
        );
    }

    /// Ownership of the socket is worth nothing if the directory around it is
    /// writable: anyone who can unlink the socket can put their own there. The
    /// daemon binds before anything else runs, so this is also where the data
    /// directory first gets its mode on a clean install.
    #[cfg(unix)]
    #[test]
    fn a_group_readable_endpoint_directory_is_tightened_before_binding() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: `getuid` cannot fail and touches no memory.
        let us = unsafe { libc::getuid() };
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), PermissionsExt::from_mode(0o755)).unwrap();

        secure_dir(dir.path(), us).unwrap();

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "anyone who can write the directory can replace the socket in it"
        );
    }

    /// Stated as the property that actually matters rather than as a mode,
    /// because the two platforms reach it differently: Linux `fchmod`s the
    /// socket to 0600 before `bind`, Darwin refuses to (and ignores socket
    /// modes on connect anyway), leaving the 0700 directory as the guard.
    /// Asserting either one alone would be green on one platform and wrong on
    /// the other.
    #[cfg(unix)]
    #[tokio::test]
    async fn nothing_outside_this_account_can_reach_the_bound_endpoint() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let data = home.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, PermissionsExt::from_mode(0o755)).unwrap();
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
            std::env::set_var("ARGUS_DATA_DIR", &data);
        }

        use std::sync::atomic::Ordering::Relaxed;
        MODE_FALLBACKS.store(0, Relaxed);
        let _listener = Listener::bind().unwrap();
        // On Darwin the mode is refused and the directory carries the
        // guarantee; anywhere else the mode must have stuck. Either way the
        // request has to have been made — a bind that never asks looks
        // identical here on Darwin, and identical is how it would ship.
        assert_eq!(
            MODE_FALLBACKS.load(Relaxed),
            u8::from(cfg!(target_os = "macos")) as usize,
            "the socket mode was not requested exactly once, or was refused \
             where it should have been honoured"
        );
        let sock_mode = std::fs::metadata(paths::socket_name())
            .unwrap()
            .permissions()
            .mode();
        let dir_mode = std::fs::metadata(&data).unwrap().permissions().mode();
        assert!(
            sock_mode & 0o077 == 0 || dir_mode & 0o077 == 0,
            "socket {:o} inside directory {:o}: reachable by other accounts",
            sock_mode & 0o777,
            dir_mode & 0o777,
        );
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
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
        let err = second
            .err()
            .expect("second bind must fail while first daemon is alive")
            .to_string();
        assert_eq!(
            err, "daemon already running",
            "our own daemon must stay distinguishable from a foreign owner; \
             conflating them is what let a squatter look like a healthy install"
        );
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }
    }

    /// The Windows half of the ownership guarantee, asserted everywhere so it
    /// cannot rot on the platform that is hardest to run. The default pipe DACL
    /// grants Everyone and the anonymous account read access; a DACL that
    /// re-granted either, or that dropped `P` and let an inherited ACE back in,
    /// would still bind and still look healthy.
    #[test]
    fn the_pipe_is_granted_to_one_account_and_no_group() {
        let sddl = owner_only_sddl("S-1-5-21-1-2-3-1001");
        assert!(
            sddl.starts_with("D:P"),
            "an unprotected DACL inherits ACEs from the pipe namespace: {sddl}"
        );
        assert_eq!(
            sddl.matches("(A;").count(),
            1,
            "exactly one account may be granted access: {sddl}"
        );
        assert!(
            sddl.contains(";;;S-1-5-21-1-2-3-1001)"),
            "the one grant must name the account we were given: {sddl}"
        );
        // Everyone, anonymous, authenticated users, administrators, world-ish
        // aliases. Any of these turns the DACL back into the default.
        for group in ["WD", "AN", "AU", "BA", "BU", "IU"] {
            assert!(
                !sddl.contains(&format!(";;;{group})")),
                "{group} must not be granted access to the pipe: {sddl}"
            );
        }
    }

    /// And the same guarantee on the bound pipe itself, since the string above
    /// only proves what we *asked* for. Windows CI runs this; nothing else can.
    ///
    /// Compares ACE count and SID rather than the whole descriptor: the object
    /// manager maps `GA` to the pipe's specific rights when it assigns the
    /// descriptor, so the mask read back is not the mask written.
    #[cfg(windows)]
    #[tokio::test]
    async fn nothing_outside_this_account_can_reach_the_bound_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let pipe = paths::windows_pipe_name(dir.path());
        unsafe {
            std::env::set_var("ARGUS_SOCKET", &pipe);
        }
        let listener = Listener::bind().unwrap();
        let dacl = dacl_of(&pipe);
        drop(listener);
        unsafe {
            std::env::remove_var("ARGUS_SOCKET");
        }

        let dacl = dacl.expect("the DACL of a pipe we just created must be readable");
        let us = current_user_sid().unwrap();
        assert!(
            dacl.starts_with("D:P"),
            "the bound pipe's DACL must stay protected: {dacl}"
        );
        assert_eq!(
            dacl.matches("(A;").count(),
            1,
            "the bound pipe must grant exactly one account, not the default set: {dacl}"
        );
        assert!(
            dacl.contains(&format!(";;;{us})")),
            "the one account granted the pipe must be this one ({us}): {dacl}"
        );
    }

    /// Read a named pipe's DACL back out of the object manager, as SDDL.
    #[cfg(windows)]
    fn dacl_of(pipe: &str) -> Result<String> {
        use std::ptr;
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

        let wide = widestring::U16CString::from_str(pipe)?;
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: all five out-pointers are valid; the four we do not want are
        // null, which the call documents as "do not return this part".
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(anyhow!("GetNamedSecurityInfoW({pipe}) failed with {rc}"));
        }
        let mut out: windows_sys::core::PWSTR = ptr::null_mut();
        // SAFETY: `sd` is the descriptor just returned; `out` is a valid
        // out-pointer for a string the call allocates on the local heap.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut out,
                ptr::null_mut(),
            )
        };
        // SAFETY: both pointers came from local-heap allocations owned by us,
        // and neither is used after this point.
        let text = if ok == 0 {
            Err(anyhow!(
                "cannot render the DACL of {pipe}: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(unsafe { widestring::U16CStr::from_ptr_str(out) }.to_string_lossy())
        };
        unsafe {
            LocalFree(out.cast());
            LocalFree(sd.cast());
        }
        text
    }
}
