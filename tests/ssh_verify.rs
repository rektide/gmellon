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

// --- askpass provider: binary-level refusals (no daemon required) ---------

/// Run the compiled binary's hidden `__askpass` entry with one prompt
/// argument, optionally carrying the OpenSSH permission-hint environment.
fn run_askpass(prompt: &str, hint: Option<&str>) -> std::process::Output {
    let mut command = std::process::Command::new(gmellon_binary());
    command
        .arg("__askpass")
        .arg(prompt)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(hint) = hint {
        command.env("SSH_ASKPASS_PROMPT", hint);
    }
    command
        .spawn()
        .expect("spawn gmellon __askpass")
        .wait_with_output()
        .expect("wait for gmellon __askpass")
}

#[test]
fn askpass_refuses_unparseable_prompts_with_empty_stdout() {
    // ssh-keygen -p's pathless prompt shape; garbage. These refusals need
    // no daemon: the parse happens before any bus connection.
    for prompt in ["Enter old passphrase: ", "just some words"] {
        let output = run_askpass(prompt, None);
        assert_eq!(output.status.code(), Some(1), "prompt {prompt:?} must refuse");
        assert!(
            output.stdout.is_empty(),
            "a refusal must write nothing to stdout"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("gmellon askpass:"),
            "the refusal must carry one diagnostic line"
        );
    }
}

#[test]
fn askpass_refuses_permission_and_notification_hints() {
    // SSH_ASKPASS_PROMPT=confirm/none marks yes/no questions and
    // notifications — never passphrase prompts — and must be refused
    // before any keyring interaction.
    for hint in ["confirm", "none"] {
        let output = run_askpass("Enter passphrase for /home/me/.ssh/id_ed25519: ", Some(hint));
        assert_eq!(output.status.code(), Some(1), "hint {hint:?} must refuse");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("non-passphrase prompt"),
            "the refusal must name the hint as the reason"
        );
    }
}

#[test]
fn askpass_multicall_entry_answers_and_refuses_like_the_subcommand() {
    // The multicall entry is selected by argv[0] before clap parsing: a
    // copy of the binary named gmellon-askpass behaves exactly like the
    // hidden subcommand for both refusal shapes.
    let directory = tempfile::tempdir().expect("scratch directory");
    let multicall = directory.path().join("gmellon-askpass");
    std::fs::copy(gmellon_binary(), &multicall).expect("copy binary under multicall name");

    let run = |prompt: &str| {
        std::process::Command::new(&multicall)
            .arg(prompt)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn gmellon-askpass")
            .wait_with_output()
            .expect("wait for gmellon-askpass")
    };

    // A parseable prompt reaches the bus step and fails there — the tempdir
    // path cannot be stored in any keyring, so even a live session bus
    // misses, and a headless environment refuses at the connection step.
    // Either way: exit 1, empty stdout, never a hang or a prompt.
    let probe_dir = tempfile::tempdir().expect("scratch directory");
    let prompt = format!(
        "Enter passphrase for {}: ",
        probe_dir.path().join("id_absent").display()
    );
    let probe = run(&prompt);
    assert_eq!(probe.status.code(), Some(1));
    assert!(probe.stdout.is_empty());
}

#[test]
fn askpass_multicall_selection_requires_the_exact_binary_name() {
    // argv[0] must end in exactly gmellon-askpass: a differently named
    // copy still routes through clap, which rejects the bare prompt as an
    // unknown subcommand.
    let directory = tempfile::tempdir().expect("scratch directory");
    let other = directory.path().join("gmellon-helper");
    std::fs::copy(gmellon_binary(), &other).expect("copy binary under another name");

    let output = std::process::Command::new(&other)
        .arg("Enter passphrase for /x: ")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn gmellon-helper")
        .wait_with_output()
        .expect("wait for gmellon-helper");
    assert_ne!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
}
