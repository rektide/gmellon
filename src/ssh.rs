//! Verification of SSH key passphrases without argv exposure.
//!
//! House policy forbids passwords on the command line (`ssh-keygen -P` is
//! world-readable in `ps`). Instead gmellon runs `ssh-keygen -y -f KEY`
//! with `SSH_ASKPASS` pointed at its own executable and
//! `SSH_ASKPASS_REQUIRE=force`, so ssh-keygen asks the helper for the
//! passphrase. The helper is the hidden `__askpass` subcommand, which reads
//! one line from its stdin — a pipe the parent fills — and prints it. The
//! passphrase therefore travels process-to-process through a pipe and
//! ssh-keygen's memory, never through argv or the environment.
//!
//! Two runs decide the verdict: the real passphrase must succeed, and a
//! deliberately wrong one must fail. A key that accepts both — or rather,
//! accepts the wrong one — has no passphrase to store.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

/// The deliberately wrong passphrase used to detect unencrypted keys.
const WRONG_PROBE: &[u8] = b"gmellon-deliberately-wrong-passphrase-probe";

/// Environment marker selecting askpass mode before argument parsing: the
/// verifier sets it on its ssh-keygen child, and ssh-keygen passes the
/// environment through to the askpass program it execs. This cannot leak
/// anything — a caller that sets it itself only gets its own stdin line
/// echoed back.
const ASKPASS_MARKER: &str = "GMELLON_ASKPASS";

/// Outcome of verifying a passphrase against a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The passphrase decrypts the key, and a wrong passphrase does not.
    Verified,
    /// The passphrase was rejected (or the key could not be read at all).
    Rejected,
    /// The key accepted a deliberately wrong passphrase too: it is not
    /// passphrase-protected, so there is nothing worth storing.
    NotEncrypted,
    /// Verification could not run at all (ssh-keygen missing, spawn
    /// failure). The message describes the cause.
    Unavailable(String),
}

/// Verify `passphrase` against the SSH private key at `key` using
/// `ssh-keygen -y` through the askpass helper.
pub fn verify_passphrase(key: &Path, passphrase: &[u8]) -> Verdict {
    verify_passphrase_with(&askpass_program(), key, passphrase)
}

/// The injectable seam behind [`verify_passphrase`]: `askpass` is the
/// program ssh-keygen should exec (this very executable in production; the
/// compiled binary in integration tests, whose test harness runs in a
/// different executable).
pub fn verify_passphrase_with(askpass: &Path, key: &Path, passphrase: &[u8]) -> Verdict {
    let real = run_ssh_keygen(askpass, key, passphrase);
    let wrong = run_ssh_keygen(askpass, key, WRONG_PROBE);
    match (real, wrong) {
        (RunOutcome::Succeeded, RunOutcome::Succeeded) => Verdict::NotEncrypted,
        (RunOutcome::Succeeded, RunOutcome::Failed) => Verdict::Verified,
        (RunOutcome::Failed, RunOutcome::Succeeded) => Verdict::Unavailable(
            "ssh-keygen accepted a wrong passphrase but rejected the real one; cannot verify"
                .to_owned(),
        ),
        (RunOutcome::Failed, RunOutcome::Failed) => Verdict::Rejected,
        (RunOutcome::Unavailable(reason), _) | (_, RunOutcome::Unavailable(reason)) => {
            Verdict::Unavailable(reason)
        }
    }
}

enum RunOutcome {
    Succeeded,
    Failed,
    Unavailable(String),
}

/// Run `ssh-keygen -y -f key`, feeding `passphrase` through the askpass
/// helper's stdin pipe. `-y` prints the public key on success; stdout is
/// discarded, stderr is captured only to be dropped.
fn run_ssh_keygen(askpass: &Path, key: &Path, passphrase: &[u8]) -> RunOutcome {
    let mut child = match Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(key)
        .env("SSH_ASKPASS", askpass)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env(ASKPASS_MARKER, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RunOutcome::Unavailable(
                "ssh-keygen is not on PATH; it is required to verify the key".to_owned(),
            );
        }
        Err(error) => return RunOutcome::Unavailable(format!("could not run ssh-keygen: {error}")),
    };

    // The askpass helper reads one line from the child's stdin. Write the
    // passphrase with its newline terminator and close the pipe so the
    // helper sees end-of-line; the buffer never grows near the 64 KiB pipe
    // capacity, so this cannot block indefinitely.
    let mut line = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1));
    line.extend_from_slice(passphrase);
    line.push(b'\n');
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(line.as_slice());
        // Closing (dropping) the write end is required even on a failed
        // write so the helper cannot block forever on a partial line.
        drop(stdin);
    }

    match child.wait() {
        Ok(status) if status.success() => RunOutcome::Succeeded,
        Ok(_) => RunOutcome::Failed,
        Err(error) => RunOutcome::Unavailable(format!("waiting for ssh-keygen failed: {error}")),
    }
}

/// The absolute path of this very executable, which serves as the askpass
/// program. Absolute so ssh-keygen's PATH lookup cannot substitute another
/// binary.
fn askpass_program() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("gmellon"))
}

/// Askpass-mode entry point (see [`ASKPASS_MARKER`]): read one line from
/// stdin and print it. The passphrase arrives on the verifier's pipe and
/// leaves on stdout for ssh-keygen to capture — never through argv or the
/// environment.
///
/// The read is deliberately **unbuffered, one byte at a time**: ssh-keygen
/// execs this helper once per prompt (generation asks twice), and each
/// invocation shares the same pipe stdin. A buffered reader would slurp
/// every queued line at once, leaving later invocations at end-of-input —
/// the failure that silently produced unencrypted keys. Byte-at-a-time
/// consumption leaves the next line in the pipe for the next invocation.
pub fn askpass_main() -> std::process::ExitCode {
    use std::io::{Read, Write};

    /// Same input cap as the house stdin contract.
    const MAX_LINE: usize = 64 * 1024;

    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8];
    let mut stdin = std::io::stdin().lock();
    loop {
        match stdin.read(&mut byte) {
            Ok(0) => return std::process::ExitCode::from(1), // unterminated: no line
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if line.len() >= MAX_LINE {
                    return std::process::ExitCode::from(1);
                }
                line.push(byte[0]);
            }
            Err(_) => return std::process::ExitCode::from(1),
        }
    }
    // Tolerate a CRLF terminator without adopting its carriage return.
    if line.last() == Some(&b'\r') {
        line.pop();
    }

    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(line.as_slice());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_probe_is_not_empty() {
        assert!(!WRONG_PROBE.is_empty());
    }

    #[test]
    fn askpass_marker_names_an_internal_mode() {
        // The helper is an internal implementation detail selected before
        // argument parsing; its marker never appears in help or completions.
        assert!(!ASKPASS_MARKER.is_empty());
        assert!(ASKPASS_MARKER.starts_with("GMELLON_"));
    }
}
