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

// ---------------------------------------------------------------------------
// Askpass provider mode: answering OpenSSH passphrase prompts from the
// keyring. design/askpass/askpass.glm53.md is the contract and threat
// model; the per-key opt-in attribute is the default-deny gate.
// ---------------------------------------------------------------------------

/// The env hint OpenSSH sets when the askpass program is being used for a
/// yes/no permission question (`confirm`) or a pure notification (`none`).
/// A passphrase provider must never answer those.
const SSH_ASKPASS_PROMPT_HINT: &str = "SSH_ASKPASS_PROMPT";

/// One refusal: nothing on stdout — the askpass contract's clean
/// "don't know" channel is a nonzero exit — and one secret-free line on
/// stderr for the human behind the invoking terminal.
fn askpass_refuse(reason: &str) -> std::process::ExitCode {
    eprintln!("gmellon askpass: {reason}");
    std::process::ExitCode::from(1)
}

/// Extract the key path from an OpenSSH askpass prompt.
///
/// Two shapes exist in the wild (verified against OpenSSH's callers):
/// `ssh` asks ``Enter passphrase for key '/path': `` (single-quoted) and
/// `ssh-add`/`ssh-keygen -f` ask `Enter passphrase for /path: ` (bare,
/// truncated at 100 bytes by ssh-add's `%.100s`). Prompts without a path
/// (`ssh-keygen -p`'s `Enter old passphrase:`) and non-absolute paths do
/// not parse — refusing them is the safe outcome.
pub fn parse_askpass_prompt(prompt: &str) -> Option<PathBuf> {
    let prompt = prompt.trim_end();
    let path = if let Some(quoted) = prompt.strip_prefix("Enter passphrase for key '") {
        // ssh: Enter passphrase for key '<path>': … — the path ends at the
        // closing quote.
        quoted.split('\'').next().unwrap_or_default()
    } else {
        // ssh-add / ssh-keygen -f: Enter passphrase for <path>: … — the
        // terminator is a colon (optionally followed by a space ssh has
        // already trimmed).
        let bare = prompt.strip_prefix("Enter passphrase for ")?;
        bare.strip_suffix(": ").unwrap_or(bare.strip_suffix(':')?)
    };
    if !path.starts_with('/') {
        return None;
    }
    Some(PathBuf::from(path))
}

/// The askpass provider pipeline (design/askpass/askpass.glm53.md): answer
/// one OpenSSH passphrase prompt from gmellon-managed keyring storage, or
/// refuse. Entry points are the multicall `gmellon-askpass` binary name
/// and the hidden `__askpass` subcommand.
///
/// Invariants: never prompts (a locked collection or locked item is a
/// refusal, not a hang — the caller may be headless); never answers
/// permission questions; never answers a key without the
/// `gmellon:askpass=allow` opt-in; on success the decrypted passphrase is
/// the only thing ever written to stdout, with the trailing newline the
/// contract allows ssh to strip.
pub fn askpass_provider(prompt: &std::ffi::OsStr) -> std::process::ExitCode {
    use std::io::Write;

    // 1. Permission confirmations and notifications are not passphrase
    //    prompts; answering them would make gmellon a yes-oracle too.
    if std::env::var_os(SSH_ASKPASS_PROMPT_HINT).is_some_and(|hint| !hint.is_empty()) {
        return askpass_refuse("invoked for a non-passphrase prompt (SSH_ASKPASS_PROMPT hint)");
    }
    // 2. Parse the prompt into an absolute key path.
    let Some(prompt) = prompt.to_str() else {
        return askpass_refuse("prompt is not valid UTF-8");
    };
    let Some(path) = parse_askpass_prompt(prompt) else {
        return askpass_refuse("unrecognized prompt (expected an OpenSSH key passphrase prompt)");
    };
    // Same path discipline as ssh-remove: canonicalize when the key file
    // exists, otherwise keep the verbatim absolute path — the stored
    // attribute is what must match.
    let absolute = std::fs::canonicalize(&path).unwrap_or(path);
    let key_path = absolute.display().to_string();

    // 3. Connect; any service failure is a plain refusal.
    let client = match crate::secret_service::BlockingClient::session() {
        Ok(client) => client,
        Err(error) => return askpass_refuse(&error.to_string()),
    };
    // 4. Exactly one stored item, unlocked, carrying the opt-in grant.
    //    The metadata check happens *before* any secret is read, so a
    //    refusal never decrypts anything.
    let item = match client.ssh_key_item(&key_path) {
        Ok((_collection, item)) => item,
        Err(error) => return askpass_refuse(&error.to_string()),
    };
    if item.locked {
        return askpass_refuse("the stored passphrase is locked; unlock the keyring first");
    }
    if !item.askpass_allowed() {
        return askpass_refuse(
            "no askpass grant for this key; gmellon ssh allow grants one per key",
        );
    }
    // 5. Read and answer: GetSecret under the encrypted session, decrypt,
    //    one line on stdout.
    let secret = match client.ssh_key_secret(&key_path) {
        Ok(secret) => secret,
        Err(error) => return askpass_refuse(&error.to_string()),
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(secret.as_slice())
        .and_then(|()| stdout.write_all(b"\n"))
        .is_err()
    {
        return askpass_refuse("writing the answer to stdout failed");
    }
    if stdout.flush().is_err() {
        return askpass_refuse("flushing the answer to stdout failed");
    }
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

    #[test]
    fn askpass_prompts_parse_into_absolute_key_paths() {
        // ssh (the client) single-quotes the path; ssh-add and ssh-keygen
        // -f leave it bare. Both terminations — colon-space and bare colon
        // after trailing-whitespace trim — must parse.
        assert_eq!(
            parse_askpass_prompt("Enter passphrase for /home/me/.ssh/id_ed25519: "),
            Some(PathBuf::from("/home/me/.ssh/id_ed25519"))
        );
        assert_eq!(
            parse_askpass_prompt("Enter passphrase for /home/me/.ssh/id_ed25519:"),
            Some(PathBuf::from("/home/me/.ssh/id_ed25519"))
        );
        assert_eq!(
            parse_askpass_prompt("Enter passphrase for key '/home/me/.ssh/id_rsa': "),
            Some(PathBuf::from("/home/me/.ssh/id_rsa"))
        );
        assert_eq!(
            parse_askpass_prompt("Enter passphrase for key '/tmp/k':"),
            Some(PathBuf::from("/tmp/k"))
        );
    }

    #[test]
    fn askpass_prompts_without_an_absolute_path_do_not_parse() {
        // ssh-keygen -p asks without any key path; relative paths are not
        // storage keys; the empty quoted path is unbalanced.
        assert_eq!(parse_askpass_prompt("Enter old passphrase: "), None);
        assert_eq!(
            parse_askpass_prompt("Enter new passphrase (empty for no passphrase): "),
            None
        );
        assert_eq!(
            parse_askpass_prompt("Enter passphrase for id_ed25519: "),
            None
        );
        assert_eq!(parse_askpass_prompt("Enter passphrase for key '': "), None);
        assert_eq!(parse_askpass_prompt("unlock"), None);
        assert_eq!(parse_askpass_prompt(""), None);
    }

    #[test]
    fn askpass_prompt_parsing_takes_the_first_quoted_segment() {
        // A path containing a quote terminates the quoted segment early —
        // the remainder is dropped, matching what ssh itself formatted.
        assert_eq!(
            parse_askpass_prompt("Enter passphrase for key '/tmp/a'b': "),
            Some(PathBuf::from("/tmp/a"))
        );
    }
}
