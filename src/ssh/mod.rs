//! SSH passphrase capabilities: the ssh-keygen-backed verifier
//! ([`verify`]) and the OpenSSH askpass provider ([`askpass`]), plus the
//! lenient path discipline both sides share for matching stored
//! passphrases. The public surface is re-exported here; entry points in
//! `main` keep their `gmellon::ssh::` paths.

mod askpass;
mod verify;

pub use askpass::{askpass_provider, parse_askpass_prompt};
pub use verify::{Verdict, askpass_main, verify_passphrase, verify_passphrase_with};

use std::path::{Path, PathBuf};

/// The lenient path discipline for matching a stored SSH key passphrase
/// attribute — the storage join key shared by the `ssh-*` commands and the
/// askpass provider: resolve symlinks and relative paths when the key file
/// is present, and otherwise fall back to the path made absolute verbatim
/// (`std::path::absolute`). A missing file is never an error here — stale
/// stored passphrases are exactly what ssh-remove and ssh-verify exist to
/// address, so the attribute must still match what was stored.
///
/// This is the lenient flavor only. `ssh-add` deliberately keeps its own
/// strict `canonicalize` with a hard error on a missing key: there the
/// canonical path is the storage key *and* the passphrase must be verified
/// against a real file. The asymmetry is policy, not duplication.
pub fn canonical_or_absolute(path: &Path) -> PathBuf {
    match std::fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(_) => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_or_absolute_resolves_symlinks_when_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real.key");
        std::fs::write(&real, b"key material").expect("write key");
        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        assert_eq!(
            canonical_or_absolute(&link),
            std::fs::canonicalize(&real).expect("real key canonicalizes")
        );
    }

    #[test]
    fn canonical_or_absolute_keeps_a_missing_absolute_path_verbatim() {
        // The stale-storage case: the stored attribute must still match
        // what was stored even though the file is gone.
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("gone.key");
        assert_eq!(canonical_or_absolute(&missing), missing);
    }

    #[test]
    fn canonical_or_absolute_makes_a_missing_relative_path_absolute() {
        let relative = std::path::Path::new("gmellon-missing-relative.key");
        let resolved = canonical_or_absolute(relative);
        assert!(resolved.is_absolute(), "relative paths must absolutize");
        assert_eq!(resolved, std::env::current_dir().unwrap().join(relative));
    }
}
