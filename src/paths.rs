use std::path::{Path, PathBuf};

/// Where the buffer lives.
///
/// Deliberately *local* rather than roaming. On Windows `dirs::data_dir()` is
/// Roaming AppData, which on a domain-joined machine is synchronised to a file
/// server at logon and logoff — and a SQLite database with a live WAL is close
/// to the worst thing that sync can be handed. It copies `events.db`, `-wal`
/// and `-shm` independently, at moments of its own choosing, so what reaches
/// the server is a torn snapshot; worse, what comes *back* at the next logon
/// can land on top of a newer local buffer. Roaming a security audit trail
/// across every machine the user logs into is not a good idea on its own
/// merits either. Off Windows the two directories are the same path, so this
/// changes nothing there.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ARGUS_DATA_DIR") {
        return PathBuf::from(dir);
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("argus")
}

/// Every environment variable that moves argus off its installed defaults.
///
/// Listed in one place because they are read from the *agent's* environment —
/// argus's shim runs as a child of the tool it watches, so anything in a shell
/// profile reaches it. Each of these is a legitimate debugging affordance and
/// also, used deliberately, a way to point capture at a directory with no
/// daemon behind it. The list exists so that the heartbeat can say which are in
/// force, and so a later gate has one place to consult.
pub const OVERRIDE_ENV: [&str; 6] = [
    "ARGUS_DATA_DIR",
    "ARGUS_SOCKET",
    "ARGUS_HOME",
    "ARGUS_BIN",
    "ARGUS_NO_AUTOSPAWN",
    crate::record::RECORD_DIR_ENV,
];

/// The names from [`OVERRIDE_ENV`] that are actually set, in that order.
///
/// Names only. Their values are paths a user chose, and one of them
/// (`ARGUS_RECORD_DIR`) names a directory holding *pre-redaction* envelopes —
/// reporting where it points would put the location of the unscrubbed copy into
/// the scrubbed stream.
pub fn overrides_in_force() -> Vec<String> {
    OVERRIDE_ENV
        .iter()
        .filter(|k| std::env::var_os(k).is_some())
        .map(|k| (*k).to_string())
        .collect()
}

/// The pre-0.2 location, when it is somewhere other than the current one.
///
/// `None` off Windows, where roaming and local resolve to the same path and
/// there is nothing to move, and `None` under the env override, where the user
/// has said exactly where the data goes.
pub fn legacy_data_dir() -> Option<PathBuf> {
    if std::env::var("ARGUS_DATA_DIR").is_ok() {
        return None;
    }
    let legacy = dirs::data_dir()?.join("argus");
    (legacy != data_dir()).then_some(legacy)
}

/// What a migration attempt actually did, so the daemon can log something true
/// rather than "migrated" regardless.
#[derive(Debug, PartialEq, Eq)]
pub enum Migration {
    /// No legacy directory, or a buffer already exists at the new location.
    Skipped,
    /// Every file copied and read back identical. Removing the source is
    /// attempted after that and its failure ignored: the data is already safe
    /// at the new location, and a directory that outlives the move is litter,
    /// not a loss.
    Moved { files: usize },
    /// Some files did not make it. What copied is usable; the source is left
    /// exactly as it was, because nothing gets deleted that was not verified.
    Partial { files: usize, left: Vec<PathBuf> },
}

type CopyFn = dyn Fn(&Path, &Path) -> std::io::Result<()>;

/// Move a pre-0.2 buffer to the current data directory, if there is one.
pub fn migrate_legacy_data_dir() -> Migration {
    let Some(from) = legacy_data_dir() else {
        return Migration::Skipped;
    };
    migrate(&from, &data_dir(), &|src, dst| {
        std::fs::copy(src, dst).map(|_| ())
    })
}

/// Copy-then-verify, never destructive.
///
/// The old daemon may well still be running: on Windows SQLite holds `-wal`
/// and `-shm` under a mandatory lock, so copying those can fail while
/// everything else succeeds. That is tolerated rather than fatal — a partial
/// move still puts the user's history on local disk — but it forfeits the
/// cleanup. The source directory is removed only once every file has been
/// copied *and* read back byte-identical.
///
/// The copier is injected so the whole thing is exercisable on a platform that
/// has no roaming profile and no mandatory file locks.
fn migrate(from: &Path, to: &Path, copy: &CopyFn) -> Migration {
    if from == to || !from.is_dir() {
        return Migration::Skipped;
    }
    // Presence of the database, not of the directory: a hook that fires before
    // the first daemon start drops a spool file here, and that must not be
    // mistaken for a buffer worth protecting.
    if to.join("events.db").exists() {
        return Migration::Skipped;
    }
    let mut files = Vec::new();
    collect_files(from, from, &mut files);

    let (mut moved, mut left) = (0usize, Vec::new());
    for rel in files {
        let (src, dst) = (from.join(&rel), to.join(&rel));
        let copied = dst
            .parent()
            // On a clean install this is what brings the data directory into
            // existence, ahead of the `Buffer::open` that would otherwise
            // harden it — so it has to create it private itself, or the
            // migrated history sits world-readable until the daemon opens it.
            .map(create_private_dir)
            .unwrap_or(Ok(()))
            .and_then(|()| {
                if dst.exists() {
                    // Something at the destination already owns this name;
                    // leave it be and keep the source copy for the user.
                    return Err(std::io::Error::other("destination exists"));
                }
                copy(&src, &dst)
            })
            .is_ok();
        // `fs::copy` carries the source's mode across, and the source was
        // written by a version that may predate any of this. The copy is the
        // one that lives on, so give it the posture the writers use now.
        #[cfg(unix)]
        if copied {
            let _ =
                std::fs::set_permissions(&dst, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        }
        if copied && same_bytes(&src, &dst).unwrap_or(false) {
            moved += 1;
        } else {
            left.push(rel);
        }
    }

    if left.is_empty() {
        let _ = std::fs::remove_dir_all(from);
        Migration::Moved { files: moved }
    } else {
        Migration::Partial { files: moved, left }
    }
}

fn collect_files(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|e| e.path()) {
        // `symlink_metadata`, not `is_dir`: the latter follows the link, so a
        // symlink pointing at its own ancestor is walked through again and
        // again, stopping only when the accumulated path hits the platform's
        // length limit — hundreds of copies of every real file, each of which
        // `migrate` then dutifully copies into the new data directory before
        // deleting the source. A symlink is treated as an ordinary entry
        // instead: one pointing at a file copies its contents, and one pointing
        // at a directory fails to copy, so it lands in `left` and leaves the
        // migration `Partial` with the source intact — the safe direction.
        let is_dir = std::fs::symlink_metadata(&path).is_ok_and(|md| md.is_dir());
        if is_dir {
            collect_files(&path, base, out);
        } else if let Ok(rel) = path.strip_prefix(base) {
            out.push(rel.to_path_buf());
        }
    }
}

/// Streamed rather than slurped: `buffer.max_bytes` bounds the stored event
/// text, not the file that holds it, and its default leaves room for a database
/// of a few hundred megabytes before indices, a WAL and freed pages are counted.
/// Reading both sides in to compare them would be twice that, at daemon start.
fn same_bytes(a: &Path, b: &Path) -> std::io::Result<bool> {
    let mut a = std::io::BufReader::new(std::fs::File::open(a)?);
    let mut b = std::io::BufReader::new(std::fs::File::open(b)?);
    let (mut ba, mut bb) = ([0u8; 8192], [0u8; 8192]);
    loop {
        let (na, nb) = (fill(&mut a, &mut ba)?, fill(&mut b, &mut bb)?);
        if na != nb || ba[..na] != bb[..nb] {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
    }
}

/// `read` is allowed to return short for any reason; a short read must not be
/// read as a difference between the two files.
fn fill(r: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

pub fn spool_dir() -> PathBuf {
    data_dir().join("spool")
}

pub fn db_path() -> PathBuf {
    data_dir().join("events.db")
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.toml")
}

pub fn cached_remote_config_path() -> PathBuf {
    data_dir().join("remote-config.cache.toml")
}

/// Where the machine-wide config layer lives under `root`.
///
/// Takes the root and the platform rather than reading either, so `install
/// --managed` writes it in the same place `check --managed` looks for it, and
/// so the suite exercises the Windows layout everywhere — the rule the rest of
/// the machine-wide layer already follows.
pub fn system_config_path_in(root: &Path, platform: crate::detect::Platform) -> PathBuf {
    root.join(match platform {
        crate::detect::Platform::Windows => "ProgramData/argus/config.toml",
        crate::detect::Platform::Linux | crate::detect::Platform::MacOS => "etc/argus/config.toml",
    })
}

/// What tests treat as the machine-wide config layer.
///
/// [`system_config_path`] deliberately ignores `ARGUS_SYSTEM_ROOT` (see there),
/// so tests cannot reach it by redirecting the root the way the managed-layer
/// tests do — and must not fall back to the host's real `/etc/argus`, which
/// would make the suite depend on the developer's own machine. Unset means "no
/// machine-wide layer", which is what an ordinary host has.
#[cfg(test)]
pub(crate) static SYSTEM_CONFIG: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Points [`system_config_path`] at `path` until it is dropped.
///
/// A guard rather than a setter because the layer outranks everything: a test
/// that returned early — or failed an assertion — while it was still pointing
/// at its own temp file would hand that file to every test after it, and the
/// symptom would be some unrelated test's config quietly coming back wrong.
#[cfg(test)]
pub(crate) struct SystemConfig;

#[cfg(test)]
impl SystemConfig {
    pub(crate) fn set(path: impl Into<PathBuf>) -> Self {
        *SYSTEM_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(path.into());
        Self
    }
}

#[cfg(test)]
impl Drop for SystemConfig {
    fn drop(&mut self) {
        *SYSTEM_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// The machine-wide config layer: the one file deciding what argus does that
/// an ordinary account cannot write.
///
/// Unlike every other machine-wide path, this one does **not** honour
/// `ARGUS_SYSTEM_ROOT`. That variable comes out of the watched agent's
/// environment like any other, and a layer that stops applying because a line
/// in `~/.zshrc` pointed argus at an empty directory is not a layer — it is a
/// suggestion. The redirect stays where it is useful and harmless: choosing
/// where an *install* writes.
pub fn system_config_path() -> PathBuf {
    #[cfg(test)]
    {
        return SYSTEM_CONFIG
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default();
    }
    #[cfg(not(test))]
    {
        let platform = crate::detect::Platform::host();
        let root = Path::new(match platform {
            crate::detect::Platform::Windows => "C:\\",
            crate::detect::Platform::Linux | crate::detect::Platform::MacOS => "/",
        });
        system_config_path_in(root, platform)
    }
}

/// The secret Codex presents to this install's OTLP receiver.
///
/// Inside the data directory rather than beside Codex's own config, because
/// this directory is the one argus keeps at `0700` and can say something about.
pub fn codex_token_path() -> PathBuf {
    data_dir().join("codex-otlp.token")
}

/// Name used by `interprocess` local sockets. Filesystem path on Unix,
/// named pipe on Windows. Env override keeps parallel tests isolated.
pub fn socket_name() -> String {
    if let Ok(name) = std::env::var("ARGUS_SOCKET") {
        return name;
    }
    #[cfg(unix)]
    {
        data_dir().join("argus.sock").to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        windows_pipe_name(&data_dir())
    }
}

/// The Windows endpoint for the install rooted at `dir`.
///
/// Unix needs no such thing: the socket is a file *inside* the per-user data
/// directory, so the filesystem namespaces it. The Windows pipe namespace is
/// machine-global and flat, so the previous `\\.\pipe\argus` was a single name
/// shared by every account on the box. Two users' daemons fought over it and
/// whichever bound first received the other's hook payloads — raw and
/// pre-redaction, since redaction happens daemon-side. Worse, any process at
/// all could pre-create the name and simply be handed them.
///
/// Not `#[cfg(windows)]`: the guarantee is that two users get two names, and a
/// guarantee that can only be tested on the platform CI runs least often is one
/// nobody will notice breaking.
pub fn windows_pipe_name(dir: &Path) -> String {
    format!(r"\\.\pipe\argus-{:016x}", endpoint_discriminator(dir))
}

/// The loopback address this install's Codex OTLP receiver listens on.
pub fn default_otlp_listen() -> String {
    format!("127.0.0.1:{}", otlp_port(&data_dir()))
}

/// The port for the install rooted at `dir`.
///
/// Loopback is machine-wide, not per-user: on the fixed port this replaced, the
/// second account to start a daemon simply failed to bind and logged that its
/// listener was disabled, while its Codex — configured with the same fixed port
/// — went on posting prompts into the *first* account's audit trail and out
/// through that account's exporter. Neither side saw anything wrong.
///
/// 40000..49152 is above the ranges anything common has registered and below
/// the dynamic range the kernel draws outbound source ports from, so a stable
/// choice here does not lose a race with an ephemeral one.
pub fn otlp_port(dir: &Path) -> u16 {
    (40_000 + endpoint_discriminator(dir) % 9_152) as u16
}

/// Per-install discriminator for [`windows_pipe_name`] and [`otlp_port`].
///
/// Keyed on the data directory rather than the user name because that is what
/// the Unix socket path is already keyed on, and it makes `ARGUS_DATA_DIR`
/// behave the way it reads: two data directories are two installs and must not
/// share one daemon. Hashing also means no user name reaches anything that can
/// enumerate `\\.\pipe\`, and no path character has to be reconciled with what
/// the pipe namespace accepts.
///
/// FNV-1a, spelled out, rather than `DefaultHasher`: the daemon, the shim and
/// the opencode TypeScript plugin must all derive the *same* name, and
/// `DefaultHasher`'s output is explicitly not guaranteed stable across Rust
/// releases — a toolchain bump would silently rename the endpoint and cut every
/// running daemon off from its shims. Kept in step with `socketPath()` in
/// `plugins/opencode/argus.ts`; `the_discriminator_is_pinned_to_a_known_value`
/// is what the two implementations are checked against.
pub fn endpoint_discriminator(dir: &Path) -> u64 {
    // Windows paths are case-insensitive, and the two implementations do not
    // read the directory from the same place — this side resolves it through
    // `SHGetKnownFolderPath`, the plugin reads `%LOCALAPPDATA%`. They agree on
    // the directory; they need not agree on how it is spelled.
    let key = dir.to_string_lossy().to_lowercase();
    let key = key.trim_end_matches(['\\', '/']);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Create `dir` and any missing parent, owner-only from the instant each level
/// exists.
///
/// Every directory this crate creates holds pre-redaction payloads — the
/// spool, the buffer, a recording directory — and the mode belongs on the
/// creation rather than on a `set_permissions` after it. A directory made at
/// the umask default and chmodded a moment later is world-readable for that
/// moment, and on a shared machine a moment is all an attacker's inotify watch
/// needs to open what lands there first.
///
/// The chmod is still made, for the case the mode above cannot cover: a
/// directory that already existed keeps whatever mode it was made with, and
/// `DirBuilder` will not touch it. Its failure is ignored, because a
/// pre-existing directory belongs to whoever made it and a shim that cannot
/// re-own one must still be able to spool into it.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        Ok(())
    }
    // Non-Unix platforms don't use POSIX permission bits; ACL-based hardening
    // is out of scope here.
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Create `dir` and any missing parent, traversable by every account.
///
/// The exact inverse of [`create_private_dir`], and it exists because the
/// machine-wide layer is the one place argus writes *for* other users: the
/// policy every account must read, the binary every account's hooks must
/// execute. Those writes happen under `sudo`, so they inherit root's umask,
/// and a hardened host sets it to 077 — which would make the directory 0700
/// and put the file out of reach however carefully the file's own mode was
/// set. `install --managed` would report success and monitor nobody.
///
/// Only levels this call actually creates are chmodded. A directory that was
/// already there belongs to whoever made it, and widening `/usr/local` because
/// argus happened to install underneath it is not argus's decision to make.
pub fn create_shared_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let missing: Vec<PathBuf> = dir
            .ancestors()
            .take_while(|p| !p.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::create_dir_all(dir)?;
        for level in missing {
            std::fs::set_permissions(&level, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Write `body` to `path`, owner-only from the instant the file exists.
///
/// The file counterpart of [`create_private_dir`], and it exists for the same
/// reason: a spooled envelope is raw, so the window between `write` and a
/// `set_permissions` afterwards is a window in which every account on the box
/// can read one. The mode goes on the `open` instead, which leaves no window
/// at all — and, as above, the chmod stays for the one case a creation mode
/// cannot reach, a file that was already there.
pub fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    file.write_all(body)?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_respects_env_override() {
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", "/tmp/lmtest");
        }
        assert_eq!(data_dir(), std::path::PathBuf::from("/tmp/lmtest"));
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    #[test]
    fn derived_paths_live_under_data_dir() {
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", "/tmp/lmtest");
        }
        assert_eq!(spool_dir(), data_dir().join("spool"));
        assert_eq!(db_path(), data_dir().join("events.db"));
        assert_eq!(config_path(), data_dir().join("config.toml"));
        assert_eq!(
            cached_remote_config_path(),
            data_dir().join("remote-config.cache.toml")
        );
        assert!(!socket_name().is_empty());
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    const ALICE: &str = r"C:\Users\alice\AppData\Local\argus";
    const BOB: &str = r"C:\Users\bob\AppData\Local\argus";

    /// The reason the discriminator exists. Before it, every account on a
    /// Windows machine raced for `\\.\pipe\argus`, and the loser's hook
    /// payloads — raw prompts, tool inputs, file paths, all pre-redaction —
    /// went to whoever won.
    #[test]
    fn two_users_do_not_share_one_windows_endpoint() {
        assert_ne!(
            windows_pipe_name(Path::new(ALICE)),
            windows_pipe_name(Path::new(BOB)),
            "two accounts resolved to one pipe; the second user's prompts go to the first"
        );
    }

    /// An override is a separate install with a separate buffer, so it gets a
    /// separate daemon — otherwise `ARGUS_DATA_DIR` moves the database and
    /// leaves the transport pointing at whatever bound the shared name first.
    #[test]
    fn a_different_data_dir_is_a_different_endpoint() {
        assert_ne!(
            windows_pipe_name(Path::new(ALICE)),
            windows_pipe_name(Path::new(r"D:\argus-test")),
        );
    }

    /// Both sides must land on the same name from a directory neither spells
    /// identically: this side resolves it through `SHGetKnownFolderPath`, the
    /// opencode plugin reads `%LOCALAPPDATA%`. A case difference splitting the
    /// endpoint would look exactly like a daemon that is not running.
    #[test]
    fn spelling_of_the_same_directory_does_not_split_the_endpoint() {
        let canonical = endpoint_discriminator(Path::new(ALICE));
        for equivalent in [
            r"c:\users\alice\appdata\local\argus",
            r"C:\USERS\ALICE\APPDATA\LOCAL\ARGUS",
            r"C:\Users\alice\AppData\Local\argus\",
        ] {
            assert_eq!(
                endpoint_discriminator(Path::new(equivalent)),
                canonical,
                "{equivalent} resolved to a different endpoint than {ALICE}"
            );
        }
    }

    /// Pinned because the guarantee is cross-language: `socketPath()` in
    /// `plugins/opencode/argus.ts` reimplements this, and nothing in either
    /// build compares the two. Without a fixed value, "improving" the hash on
    /// one side is a silent, green-tested outage of the plugin's fast path.
    #[test]
    fn the_discriminator_is_pinned_to_a_known_value() {
        assert_eq!(
            windows_pipe_name(Path::new(ALICE)),
            r"\\.\pipe\argus-a82d74d39a3ee778"
        );
        assert_eq!(
            windows_pipe_name(Path::new(BOB)),
            r"\\.\pipe\argus-06ab4e4444656aaf"
        );
    }

    /// Loopback is shared by every account on the machine, so the fixed port
    /// this replaced meant the second user's daemon failed to bind while their
    /// Codex kept posting prompts into the first user's audit trail.
    #[test]
    fn two_users_do_not_share_one_otlp_port() {
        assert_ne!(otlp_port(Path::new(ALICE)), otlp_port(Path::new(BOB)));
    }

    /// Below 49152, where the kernel starts handing out ephemeral source ports
    /// for outbound connections: a stable choice inside that range would lose
    /// the occasional race and disable the listener for the day.
    #[test]
    fn the_otlp_port_stays_out_of_the_ephemeral_range() {
        for dir in [ALICE, BOB, "/home/carol/.local/share/argus", "/"] {
            let port = otlp_port(Path::new(dir));
            assert!(
                (40_000..49_152).contains(&port),
                "{dir} maps to {port}, outside the reserved band"
            );
        }
    }

    /// The pin above only binds this side. Nothing in either build compares the
    /// two implementations, and disagreement is silent: the plugin's socket
    /// simply never connects and every event falls back to spawning the shim
    /// binary — correct, and one process per event. Checking the constants is
    /// not checking the algorithm, but it is the drift that actually happens.
    #[test]
    fn the_opencode_plugin_still_hashes_the_same_way() {
        // The composed shim, not either half: the discriminator lives in the
        // shared transport today, and this test is about what gets installed,
        // not about which file currently holds the arithmetic.
        let shim = crate::harness::opencode::shim_source();
        for constant in ["0xcbf29ce484222325n", "0x100000001b3n", r"pipe\\argus-$"] {
            assert!(
                shim.contains(constant),
                "the opencode plugin no longer derives the endpoint the way \
                 `endpoint_discriminator` does: {constant} is gone"
            );
        }
    }

    #[test]
    fn an_explicit_data_dir_is_never_migrated_out_from_under_the_user() {
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", "/tmp/lmtest");
        }
        assert_eq!(legacy_data_dir(), None);
        assert_eq!(migrate_legacy_data_dir(), Migration::Skipped);
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
        // Whatever the platform, the old location is never the live one — a
        // migration onto itself would delete the directory it just "moved".
        assert_ne!(legacy_data_dir(), Some(data_dir()));
    }

    fn real_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
        std::fs::copy(src, dst).map(|_| ())
    }

    /// A legacy buffer with a spool subdirectory, as it is actually laid out.
    fn legacy_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events.db"), b"sqlite-ish bytes").unwrap();
        std::fs::write(dir.path().join("events.db-wal"), b"write ahead log").unwrap();
        std::fs::create_dir_all(dir.path().join("spool")).unwrap();
        std::fs::write(dir.path().join("spool/a.json"), b"{}").unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The leaf is not the only level that holds payloads. `data_dir/spool` is
    /// created by whoever gets there first, and a chmod applied to the path
    /// that was asked for leaves every directory made on the way to it at the
    /// umask default — world-readable, and holding the same raw envelopes.
    #[cfg(unix)]
    #[test]
    fn every_level_of_a_private_directory_is_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("argus/spool/pending");
        create_private_dir(&leaf).unwrap();
        for level in ["argus", "argus/spool", "argus/spool/pending"] {
            assert_eq!(
                mode_of(&root.path().join(level)),
                0o700,
                "{level} is readable by accounts that are not ours"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_private_file_is_owner_only_and_replaces_what_it_finds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("envelope.json");
        write_private(&path, b"{\"prompt\":\"secret\"}").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        // Shorter than the first write: a create that did not truncate would
        // leave the tail of the previous envelope behind it.
        write_private(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        assert_eq!(mode_of(&path), 0o600);
    }

    /// A migration is the one path that writes the data directory without
    /// going through the spool or the buffer, and `fs::copy` carries the old
    /// mode across — so a buffer written before any of this was hardened stays
    /// exactly as exposed as it was, at its new location.
    #[cfg(unix)]
    #[test]
    fn a_migration_leaves_nothing_readable_behind_it() {
        let from = legacy_tree();
        let to = tempfile::tempdir().unwrap();
        assert_eq!(
            migrate(from.path(), to.path(), &real_copy),
            Migration::Moved { files: 3 }
        );
        assert_eq!(mode_of(&to.path().join("spool")), 0o700);
        for file in ["events.db", "events.db-wal", "spool/a.json"] {
            assert_eq!(
                mode_of(&to.path().join(file)),
                0o600,
                "{file} arrived at the new data directory still readable by everyone"
            );
        }
    }

    #[test]
    fn a_complete_migration_verifies_every_file_then_removes_the_source() {
        let from = legacy_tree();
        let to = tempfile::tempdir().unwrap();
        let result = migrate(from.path(), to.path(), &real_copy);
        assert_eq!(result, Migration::Moved { files: 3 });
        assert_eq!(
            std::fs::read(to.path().join("events.db")).unwrap(),
            b"sqlite-ish bytes"
        );
        assert_eq!(
            std::fs::read(to.path().join("spool/a.json")).unwrap(),
            b"{}"
        );
        assert!(
            !from.path().exists(),
            "a fully verified move must not leave the old copy behind"
        );
    }

    #[test]
    fn a_locked_wal_is_tolerated_and_costs_only_the_cleanup() {
        let from = legacy_tree();
        let to = tempfile::tempdir().unwrap();
        // What a still-running old daemon looks like on Windows.
        let locked = |src: &Path, dst: &Path| -> std::io::Result<()> {
            if src.extension().is_some_and(|e| e == "db-wal") {
                return Err(std::io::Error::other("locked by another process"));
            }
            real_copy(src, dst)
        };
        let result = migrate(from.path(), to.path(), &locked);
        assert_eq!(
            result,
            Migration::Partial {
                files: 2,
                left: vec![PathBuf::from("events.db-wal")]
            }
        );
        assert!(
            to.path().join("events.db").exists(),
            "a locked sidecar must not block the database itself"
        );
        assert!(
            from.path().join("events.db-wal").exists(),
            "nothing unverified may be deleted"
        );
    }

    /// A symlink in the legacy directory is an entry to copy, never a directory
    /// to descend into. One that points at its own ancestor is otherwise
    /// re-walked until the path runs out of length, so a one-file legacy
    /// directory migrates as hundreds of nested duplicates — and the source is
    /// deleted afterwards, because every one of those copies verified.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_descended_into() {
        let from = legacy_tree();
        // spool/loop -> the legacy root itself: the cycle a user creates by
        // symlinking an old data directory back into its own subtree.
        std::os::unix::fs::symlink(from.path(), from.path().join("spool/loop")).unwrap();

        let mut files = Vec::new();
        collect_files(from.path(), from.path(), &mut files);
        assert!(
            files.contains(&PathBuf::from("spool/loop")),
            "the link itself must be recorded, not skipped: {files:?}"
        );
        assert!(
            // `starts_with` is component-wise, so the link itself matches too.
            !files
                .iter()
                .any(|f| f.starts_with("spool/loop") && f.as_path() != Path::new("spool/loop")),
            "walked through the link into the tree it points back at: {files:?}"
        );

        // And the migration keeps the source, because the link cannot be copied.
        let to = tempfile::tempdir().unwrap();
        let result = migrate(from.path(), to.path(), &real_copy);
        assert!(
            matches!(result, Migration::Partial { .. }),
            "a directory that could not be fully copied must not be removed: {result:?}"
        );
        assert!(from.path().join("events.db").exists());
    }

    /// The copy half is the easy half. This is the one that matters: a copier
    /// that reports success while writing garbage must not get the source
    /// deleted.
    #[test]
    fn a_silently_truncated_copy_fails_verification() {
        let from = legacy_tree();
        let to = tempfile::tempdir().unwrap();
        let truncating = |src: &Path, dst: &Path| -> std::io::Result<()> {
            let bytes = std::fs::read(src)?;
            std::fs::write(dst, &bytes[..bytes.len() / 2])
        };
        let result = migrate(from.path(), to.path(), &truncating);
        assert!(
            matches!(result, Migration::Partial { files: 0, .. }),
            "a short write must not pass as a migrated file: {result:?}"
        );
        assert!(from.path().join("events.db").exists());
    }

    #[test]
    fn an_existing_buffer_is_never_overwritten() {
        let from = legacy_tree();
        let to = tempfile::tempdir().unwrap();
        std::fs::write(to.path().join("events.db"), b"the live buffer").unwrap();
        assert_eq!(
            migrate(from.path(), to.path(), &real_copy),
            Migration::Skipped
        );
        assert_eq!(
            std::fs::read(to.path().join("events.db")).unwrap(),
            b"the live buffer"
        );
        assert!(from.path().exists());
    }

    /// A hook can fire before the first daemon start and spool into the new
    /// directory. That is not a buffer worth protecting, and must not strand
    /// the user's history in the old location forever.
    #[test]
    fn a_spool_file_at_the_destination_does_not_block_the_move() {
        let from = legacy_tree();
        let to = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(to.path().join("spool")).unwrap();
        std::fs::write(to.path().join("spool/fresh.json").as_path(), b"{}").unwrap();
        assert_eq!(
            migrate(from.path(), to.path(), &real_copy),
            Migration::Moved { files: 3 }
        );
        assert!(to.path().join("spool/fresh.json").exists());
        assert!(to.path().join("spool/a.json").exists());
    }
}
