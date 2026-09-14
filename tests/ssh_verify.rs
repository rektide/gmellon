//! Binary-level checks of SSH key passphrase verification.
//!
//! These are ordinary tests — no daemon, bus, or harness environment. They
//! generate real OpenSSH keys with `ssh-keygen` (encrypted ones under a
//! pty, prompt-synchronized, so the passphrase never touches argv) and
//! drive the verdicts through the compiled binary acting as the
//! SSH_ASKPASS program.

// The shared harness module carries more than this binary uses; its other
// items belong to the harness proofs that include it.
#[path = "harness/common/mod.rs"]
#[allow(dead_code)]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use gmellon::ssh::{Verdict, verify_passphrase_with};

fn gmellon_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gmellon"))
}

/// Generate an encrypted key under the shared pty helper: ssh-keygen's
/// generation prompts read piped stdin directly (buffered, so enter+confirm
/// lines slurp together and mismatch), and askpass is not consulted for
/// them. The pty keeps one line per prompt; the passphrase never touches
/// argv.
fn generate_key(directory: &Path, name: &str, passphrase: &str) -> PathBuf {
    let key = directory.join(name);
    let status = common::generate_encrypted_ssh_key(&key, passphrase.as_bytes());
    assert!(
        status.success(),
        "encrypted key generation failed for {name}"
    );
    key
}

/// Generate an unencrypted key: `-N ""` carries no secret on argv.
fn generate_plaintext_key(directory: &Path, name: &str) -> PathBuf {
    let key = directory.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn ssh-keygen for plaintext generation");
    assert!(
        status.success(),
        "plaintext key generation failed for {name}"
    );
    key
}

#[test]
fn correct_passphrase_verifies_and_wrong_one_is_rejected() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let key = generate_key(directory.path(), "id_encrypted", "alpha-pass");

    assert_eq!(
        verify_passphrase_with(&gmellon_binary(), &key, b"alpha-pass"),
        Verdict::Verified
    );
    assert_eq!(
        verify_passphrase_with(&gmellon_binary(), &key, b"not-the-passphrase"),
        Verdict::Rejected
    );
}

#[test]
fn unencrypted_keys_are_detected_as_having_nothing_to_store() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let key = generate_plaintext_key(directory.path(), "id_plain");

    // Any passphrase "succeeds" against a key with no passphrase, so the
    // deliberately-wrong probe succeeds too and the verdict is
    // NotEncrypted rather than Verified.
    assert_eq!(
        verify_passphrase_with(&gmellon_binary(), &key, b"whatever"),
        Verdict::NotEncrypted
    );
}

#[test]
fn empty_passphrase_on_an_encrypted_key_is_rejected() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let key = generate_key(directory.path(), "id_encrypted_empty_probe", "beta-pass");

    assert_eq!(
        verify_passphrase_with(&gmellon_binary(), &key, b""),
        Verdict::Rejected
    );
}

#[test]
fn a_missing_key_file_is_rejected_not_verified() {
    let directory = tempfile::tempdir().expect("scratch directory");
    let missing = directory.path().join("id_absent");

    assert_eq!(
        verify_passphrase_with(&gmellon_binary(), &missing, b"anything"),
        Verdict::Rejected
    );
}
