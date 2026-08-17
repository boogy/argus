//! Who could have written a path.
//!
//! Every machine-wide control in argus reduces to this one question. Hooks an
//! ordinary account cannot edit buy nothing if the program they run sits in a
//! directory that account owns; a policy file that outranks every other layer
//! is only worth outranking them if an ordinary account could not have written
//! it. Both callers ask the same thing, so they ask it here.
//!
//! The answer is deliberately conservative. Anything this module cannot
//! establish — an unreadable owner, a platform quirk, a missing file — reads as
//! *untrusted*, because the cost of a wrong "safe" is a control that reports
//! itself as enforced while it is not, and that is worse than no control.

use std::path::Path;

/// `Some(why)` when `path`, or any directory on the way to it, is something an
/// account without administrative rights could have written.
///
/// The directories count as much as the file. Write permission on a directory
/// is permission to replace what is in it, whoever owns the thing being
/// replaced — a rename is enough.
pub fn writable_by_non_admin(path: &Path) -> Option<String> {
    let mut here = Some(path);
    while let Some(p) = here {
        if let Some(why) = one(p) {
            return Some(why);
        }
        here = p.parent().filter(|q| *q != p);
    }
    None
}

/// Root, and not writable by anybody else.
#[cfg(unix)]
fn one(p: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::metadata(p) else {
        return Some(format!("{} cannot be read", p.display()));
    };
    if md.uid() != 0 {
        return Some(format!("{} is owned by uid {}", p.display(), md.uid()));
    }
    if md.mode() & 0o022 != 0 {
        return Some(format!(
            "{} is group- or world-writable (mode {:o})",
            p.display(),
            md.mode() & 0o777
        ));
    }
    None
}

/// Owned by an administrative principal.
///
/// Ownership, not the full DACL. Reading every ACE and resolving what each
/// group on it expands to is a different piece of work with far more ways to be
/// subtly wrong, and ownership already answers the case this exists for: a
/// standard account may create files and directories under `%ProgramData%`, and
/// what it creates, it owns. A file planted there is caught by its owner SID
/// alone. What ownership does not catch is an *administrator* who deliberately
/// loosened the ACL on their own machine-wide file — which is an administrator
/// choosing to, not a bypass.
#[cfg(windows)]
fn one(p: &Path) -> Option<String> {
    match owner_sid(p) {
        Err(e) => Some(format!("the owner of {} cannot be read: {e}", p.display())),
        Ok(sid) if administrative(&sid) => None,
        Ok(sid) => Some(format!(
            "{} is owned by {sid}, which is not an administrative account",
            p.display()
        )),
    }
}

/// The SID owning `path`, in string form.
#[cfg(windows)]
fn owner_sid(path: &Path) -> Result<String, std::io::Error> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let wide = widestring::U16CString::from_os_str(path.as_os_str())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is a NUL-terminated wide string alive for the call, and
    // every other pointer is either a valid out-pointer or null for the parts
    // of the descriptor this asks not to be given.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    // `owner` points into `sd`, so the descriptor has to outlive the conversion.
    let mut sid_str: windows_sys::core::PWSTR = ptr::null_mut();
    // SAFETY: on success `owner` is a valid SID inside `sd`, and `sid_str` is a
    // valid out-pointer for a string the call allocates on the local heap.
    let converted = unsafe { ConvertSidToStringSidW(owner, &mut sid_str) } != 0;
    let out = if converted {
        // SAFETY: on success the call wrote a NUL-terminated wide string.
        let s = unsafe { widestring::U16CStr::from_ptr_str(sid_str) }.to_string_lossy();
        // SAFETY: `LocalFree` is the documented release for what
        // `ConvertSidToStringSidW` allocated; nothing borrows it past `s`.
        unsafe { LocalFree(sid_str.cast()) };
        Ok(s)
    } else {
        Err(std::io::Error::last_os_error())
    };
    // SAFETY: `GetNamedSecurityInfoW` documents `LocalFree` as the release for
    // the descriptor it allocated, and `owner` is not read past this point.
    unsafe { LocalFree(sd.cast()) };
    out
}

/// Whether a SID belongs to an account only an administrator commands.
///
/// A closed list of well-known SIDs rather than a group-membership lookup:
/// these three are the principals Windows itself gives ownership to when an
/// elevated process, the OS, or the servicing stack creates something, and they
/// are identical on every machine. Membership lookups would answer a different
/// and much softer question — a domain group *named* like an admin group is
/// still whatever the domain says it is.
#[cfg(any(windows, test))]
fn administrative(sid: &str) -> bool {
    matches!(
        sid,
        // LocalSystem
        "S-1-5-18"
        // BUILTIN\Administrators
        | "S-1-5-32-544"
        // NT SERVICE\TrustedInstaller — owner of most of a serviced install
        | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three the servicing stack and an elevated process actually produce,
    /// and the shape of the one that matters: `S-1-5-21-…` is a local or domain
    /// *account*, which is exactly who plants a file under `%ProgramData%`.
    #[test]
    fn only_the_well_known_administrative_sids_are_administrative() {
        assert!(administrative("S-1-5-18"));
        assert!(administrative("S-1-5-32-544"));
        assert!(administrative(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        ));
        assert!(!administrative(
            "S-1-5-21-1004336348-1177238915-682003330-1001"
        ));
        assert!(!administrative("S-1-5-32-545")); // BUILTIN\Users
        assert!(!administrative("S-1-1-0")); // Everyone
        assert!(!administrative("S-1-5-11")); // Authenticated Users
        assert!(!administrative(""));
    }

    /// A path that does not exist is not a path nobody can write.
    #[test]
    fn an_unreadable_path_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(writable_by_non_admin(&dir.path().join("nothing-here")).is_some());
    }
}
