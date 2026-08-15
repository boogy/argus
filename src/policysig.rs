//! Whether remote fleet policy is *authentic*, not merely present.
//!
//! Everything else about remote policy is a file in the user's own data
//! directory. `remote-config.cache.toml` is what the daemon actually merges,
//! it has a predictable name, and nothing about it says where it came from —
//! so "the fleet's policy says capture is off" was, until this module, a claim
//! any account could make with one `cat > cache.toml`. Checking that the cache
//! matches the local config proves the two agree; it proves nothing about who
//! wrote either.
//!
//! An ed25519 detached signature over the exact bytes the policy server served
//! is what turns that into a claim only the key holder can make. The daemon
//! fetches `<url>.sig` alongside the body, refuses to cache a body that does
//! not verify, and refuses to *apply* a cache that stops verifying later.
//!
//! Ed25519 because the whole verifying key is 32 bytes of base64 — short
//! enough to sit in a config file an administrator reads, and short enough
//! that pinning it is a line of policy rather than a certificate deployment.

use base64::Engine as _;

const KEY_LEN: usize = 32;
const SIG_LEN: usize = 64;

/// The public key this host requires remote policy to verify against, or
/// `None` when it does not pin one.
///
/// Read from the machine-wide layer and nowhere else, which is the entire
/// control. A key taken from the merged config would be a key the watched user
/// can set — and a user who chooses the key can sign their own permissive
/// policy, cache it, and pass every check on the way past. The pin has to come
/// from the one file on the machine they cannot write.
///
/// The consequence is worth stating plainly: on a host with no machine-wide
/// layer, this returns `None` and no signature is checked. That is not a gap
/// this module could close — such a host has nothing an administrator owns, so
/// whatever key it trusted would be the user's to change.
pub fn pinned_key() -> Option<String> {
    let crate::config::SystemLayer::Present(table) = crate::config::system_layer() else {
        return None;
    };
    table
        .get("remote")?
        .as_table()?
        .get("public_key")?
        .as_str()
        .map(str::to_owned)
}

/// Verify `body` against a base64 detached `signature` and base64 `key`.
///
/// The error is prose for an operator, not a type: every caller either logs it
/// or turns it into a `check` finding, and "which of the four ways this failed"
/// has never been a decision either of them makes.
pub fn verify(body: &[u8], signature: &str, key: &str) -> Result<(), String> {
    let key: [u8; KEY_LEN] = decode(key, "[remote].public_key")?;
    let sig: [u8; SIG_LEN] = decode(signature, "policy signature")?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|e| format!("[remote].public_key is not a valid ed25519 key: {e}"))?;
    // `verify_strict`, not `verify`: it rejects the small-order public keys and
    // non-canonical encodings that let one signature verify under more than one
    // key. Policy authenticity is exactly the property those break.
    key.verify_strict(body, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| "signature does not match the policy body".to_string())
}

fn decode<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    // Trimmed, because a `.sig` file written by `base64 > file` ends in a
    // newline and an operator pasting a key into TOML may not notice a space.
    let raw = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|e| format!("{what} is not valid base64: {e}"))?;
    let n = raw.len();
    raw.try_into()
        .map_err(|_| format!("{what} is {n} bytes, expected {N}"))
}

/// Whether the cached policy body on disk may be applied.
///
/// `Ok(())` when this host pins no key: an unmanaged host has no authenticity
/// to check, and failing closed there would break every deployment that never
/// asked for signing.
///
/// Otherwise the signature file beside the cache must exist and cover exactly
/// these bytes. A missing one is a failure and not an exemption — deleting a
/// file is the cheapest attack there is.
pub fn check_cache(body: &str) -> Result<(), String> {
    let Some(key) = pinned_key() else {
        return Ok(());
    };
    let path = crate::paths::cached_remote_config_sig_path();
    let sig = std::fs::read_to_string(&path)
        .map_err(|e| format!("no signature at {}: {e}", path.display()))?;
    verify(body.as_bytes(), &sig, &key)
}

/// Where the detached signature for `url` is fetched from.
///
/// Before the query string, not after it: a policy server that takes
/// `?host=x` still has to be able to serve the signature for what it answered.
pub fn sig_url(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    format!("{}.sig{}", &url[..cut], &url[cut..])
}

/// Signing, which the shipped tool never does — only its tests, and only so
/// they can assert against real signatures rather than against a stub that
/// would pass whatever the code happened to do.
#[cfg(test)]
pub(crate) mod testkeys {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    /// A fixed key pair, so the suite signs without a random source and two
    /// runs produce the same bytes.
    pub(crate) fn keypair() -> (ed25519_dalek::SigningKey, String) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    pub(crate) fn sign(sk: &ed25519_dalek::SigningKey, body: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(sk.sign(body.as_bytes()).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::testkeys::*;
    use super::*;

    /// The property the whole module exists for: a body nobody holding the key
    /// signed does not verify — including the case that actually happens, an
    /// authentic policy with one line edited into it.
    #[test]
    fn only_the_body_that_was_signed_verifies() {
        let (sk, pk) = keypair();
        let body = "[capture]\nprompts = true\n";
        let sig = sign(&sk, body);
        assert_eq!(verify(body.as_bytes(), &sig, &pk), Ok(()));

        let tampered = "[capture]\nprompts = false\n";
        assert!(verify(tampered.as_bytes(), &sig, &pk).is_err());
        // Whitespace is bytes too: the signature covers what was served, not
        // what it parses to.
        assert!(verify(b"[capture]\nprompts = true", &sig, &pk).is_err());

        // Signed by somebody else's key, which is what "I made my own policy
        // server" looks like from here.
        let theirs = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        assert!(verify(body.as_bytes(), &sign(&theirs, body), &pk).is_err());
    }

    /// Malformed input has to be refused, not panic and not pass. `try_into`
    /// on a fixed-size array and `from_bytes` on a 32-byte key are the two
    /// places a wrong length would otherwise become an unwrap.
    #[test]
    fn a_key_or_signature_that_is_not_one_is_an_error_not_a_panic() {
        let (sk, pk) = keypair();
        let body = "[capture]\nprompts = true\n";
        let sig = sign(&sk, body);

        for (s, k, why) in [
            (sig.as_str(), "not base64!!", "base64"),
            ("not base64!!", pk.as_str(), "base64"),
            (sig.as_str(), "c2hvcnQ=", "expected 32"),
            ("c2hvcnQ=", pk.as_str(), "expected 64"),
        ] {
            let e = verify(body.as_bytes(), s, k).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }

    /// Trailing newlines are what `base64 > file` and a copy-paste into TOML
    /// actually produce. Refusing them would make the feature unusable in
    /// exactly the way that gets it turned off.
    #[test]
    fn surrounding_whitespace_does_not_break_a_good_signature() {
        let (sk, pk) = keypair();
        let body = "[capture]\nprompts = true\n";
        let sig = sign(&sk, body);
        assert_eq!(verify(body.as_bytes(), &format!("{sig}\n"), &pk), Ok(()));
        assert_eq!(verify(body.as_bytes(), &sig, &format!("  {pk}\t")), Ok(()));
    }

    /// The pin has to be out of reach of the account it constrains. A user who
    /// could name the key would sign their own policy with the matching secret
    /// and satisfy every check downstream of here.
    #[test]
    fn the_pinned_key_comes_from_the_machine_wide_layer_and_nowhere_else() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let (_, theirs) = keypair();
        let mine = base64::engine::general_purpose::STANDARD.encode([3u8; 32]);
        // Both files the user can write claim a key.
        for path in [
            crate::paths::config_path(),
            crate::paths::cached_remote_config_path(),
        ] {
            std::fs::write(path, format!("[remote]\npublic_key = \"{mine}\"\n")).unwrap();
        }
        assert_eq!(pinned_key(), None, "a key out of a user-writable file");

        let sys = dir.path().join("system.toml");
        std::fs::write(&sys, format!("[remote]\npublic_key = \"{theirs}\"\n")).unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);
        assert_eq!(pinned_key().as_deref(), Some(theirs.as_str()));
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    /// A missing signature file is the cheapest attack on this whole feature,
    /// so it must fail exactly like a wrong one — and on a host that pins
    /// nothing, it must not fail at all.
    #[test]
    fn a_cache_without_a_signature_passes_unpinned_and_fails_pinned() {
        let dir = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("ARGUS_DATA_DIR", dir.path());
        }
        let (sk, pk) = keypair();
        let body = "[capture]\nprompts = false\n";
        assert_eq!(check_cache(body), Ok(()), "no key pinned, nothing to check");

        let sys = dir.path().join("system.toml");
        std::fs::write(&sys, format!("[remote]\npublic_key = \"{pk}\"\n")).unwrap();
        let _guard = crate::paths::SystemConfig::set(&sys);
        assert!(check_cache(body).unwrap_err().contains("no signature"));

        let sig = crate::paths::cached_remote_config_sig_path();
        std::fs::write(&sig, sign(&sk, "[capture]\nprompts = true\n")).unwrap();
        assert!(
            check_cache(body).is_err(),
            "a signature over some other body is not a signature over this one"
        );

        std::fs::write(&sig, sign(&sk, body)).unwrap();
        assert_eq!(check_cache(body), Ok(()));
        unsafe {
            std::env::remove_var("ARGUS_DATA_DIR");
        }
    }

    #[test]
    fn the_signature_url_stays_ahead_of_the_query_string() {
        assert_eq!(sig_url("https://h/p.toml"), "https://h/p.toml.sig");
        assert_eq!(
            sig_url("https://h/p.toml?host=a&v=2"),
            "https://h/p.toml.sig?host=a&v=2"
        );
        assert_eq!(sig_url("https://h/p.toml#x"), "https://h/p.toml.sig#x");
    }
}
