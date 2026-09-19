//! Askpass provider mode: answering OpenSSH passphrase prompts from the
//! keyring. design/askpass/askpass.glm53.md is the contract and threat
//! model; the per-key opt-in attribute is the default-deny gate.

use std::path::PathBuf;

use super::canonical_or_absolute;

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
    // The lenient join-key discipline ([`canonical_or_absolute`]), shared
    // with the ssh-* commands: the stored attribute is what must match.
    let absolute = canonical_or_absolute(&path);
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
