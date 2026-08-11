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
            .map(std::fs::create_dir_all)
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
        if path.is_dir() {
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
