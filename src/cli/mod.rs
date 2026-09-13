use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use gmellon::secret_input::{self, Secret, SecretError};
use gmellon::secret_service::session;
use gmellon::secret_service::{
    BlockingClient, Collection, CollectionId, Error as ServiceError, InterfaceProbe, Item,
    LockOutcome, UnlockOutcome,
};
use gmellon::ssh::{self, Verdict};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_DENIED: u8 = 2;
const EXIT_FAILED: u8 = 3;
const EXIT_NO_DAEMON: u8 = 4;
const DEFAULT_COLLECTION: &str = "login";

/// List, unlock, and re-key GNOME keyring collections without a GUI or PAM.
///
/// Discovery uses the standard Secret Service API; unlocking and re-keying
/// use GNOME Keyring's private, unsupported password interface. Every
/// connection negotiates the encrypted Secret Service session, and
/// passwords are read only from a TTY prompt or stdin — never argv.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    after_help = "unlock and change speak \
                  org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface, a deliberately \
                  undocumented GNOME interface that may change or vanish without notice. \
                  Compatibility limits and verification evidence: doc/status.md"
)]
pub struct Cli {
    /// Print redacted diagnostic events on stderr (operations, results,
    /// lengths). Password bytes and key material are never printed.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List collection IDs, labels, and lock state.
    ///
    /// Deterministic tab-separated ID, LOCKED, and LABEL columns, sorted by
    /// stable collection ID. Control characters in labels are escaped.
    List,

    /// Report service capabilities and collection lock state.
    ///
    /// A prompt-free health report, distinct from `list`'s deterministic
    /// column output: it never prompts, never unlocks or locks anything,
    /// and never calls a password method — the private-interface fact comes
    /// from a read-only D-Bus Introspect probe. Per-collection lines carry
    /// the stable ID and lock state only; labels belong to `list`.
    ///
    /// Exits nonzero only through the existing table: 4 when the Secret
    /// Service is unavailable, 1 when the encrypted session is refused.
    Status,

    /// Unlock an existing collection.
    ///
    /// Prompts for the collection password on the TTY with echo disabled,
    /// or reads one password line from stdin with --stdin. An
    /// already-unlocked collection returns success without reading or
    /// checking a password, and unlocking never locks or relocks a
    /// collection to verify one.
    Unlock {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,

        /// Read one password line from stdin instead of prompting on the TTY.
        #[arg(long)]
        stdin: bool,
    },

    /// Lock an existing collection.
    ///
    /// An explicit state change through the standard Secret Service Lock
    /// API: ordinary unlock never locks anything, and lock is never called
    /// implicitly. Locking is prompt-free; if the service demands an
    /// interactive prompt object, the command fails instead of performing
    /// one. An already-locked collection is a successful no-op.
    Lock {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,
    },

    /// List items inside a collection: labels, lock state, attributes.
    ///
    /// Metadata only — no secret is ever read. Deterministic tab-separated
    /// LABEL, LOCKED, and sorted k=v ATTRIBUTES columns, sorted by label
    /// then attributes. Control characters in labels are escaped.
    Items {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,
    },

    /// List stored SSH key passphrases.
    ///
    /// Every item across all collections whose unique attribute carries
    /// the gcr-ssh-agent ssh-store: prefix, with its owning collection and
    /// lock state. Metadata only; the passphrases are not read.
    SshList,

    /// Store an SSH key passphrase, verified against the key first.
    ///
    /// Prompts for the KEY's passphrase (not the keyring password), checks
    /// it actually decrypts KEY with ssh-keygen, and only then stores it
    /// the way gcr-ssh-agent finds it — in the default collection, keyed by
    /// the key's absolute path. A wrong passphrase stores nothing; an
    /// unencrypted key has nothing to store. Replaces any previously
    /// stored passphrase for the same key.
    SshAdd {
        /// Path to the SSH private key.
        #[arg(value_name = "KEY")]
        key: PathBuf,

        /// Read one passphrase line from stdin instead of prompting on the TTY.
        #[arg(long)]
        stdin: bool,
    },

    /// Remove a stored SSH key passphrase.
    ///
    /// Deletes the item gcr-ssh-agent would read for KEY (exact key-path
    /// match). The key file itself may already be gone — removing a stale
    /// stored passphrase is the point. Exactly one stored item must match;
    /// duplicates are listed by ssh-list and change nothing here.
    SshRemove {
        /// Path to the SSH private key the passphrase was stored for.
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },

    /// Change an existing collection's password.
    ///
    /// Prompts for the current password, then the new password twice on the
    /// TTY; with --stdin reads current, new, and confirmation lines in that
    /// order. A denied current password leaves the old password valid.
    Change {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,

        /// Read current, new, and confirmation lines from stdin.
        #[arg(long)]
        stdin: bool,
    },

    /// Generate shell completions.
    ///
    /// Writes the completion script for SHELL to standard output; redirect
    /// it wherever your shell looks. For zsh:
    ///
    ///   gmellon completions zsh > ~/.zfunc/_gmellon
    ///
    /// with ~/.zfunc on fpath before compinit — or use the bundled zimfw
    /// module, which installs and regenerates the file automatically.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

pub fn run(cli: Cli) -> ExitCode {
    // The tracing subscriber exists only under -v: without the flag no
    // event is ever emitted (or formatted), and RUST_LOG never activates
    // one either.
    if cli.verbose {
        install_verbose_subscriber();
    }
    let code = match cli.command {
        Command::List => list(),
        Command::Status => status(),
        Command::Items { collection } => items(&collection),
        Command::SshList => ssh_list(),
        Command::SshAdd { key, stdin } => ssh_add(&key, stdin),
        Command::SshRemove { key } => ssh_remove(&key),
        Command::Unlock { collection, stdin } => unlock(&collection, stdin),
        Command::Lock { collection } => lock(&collection),
        Command::Change { collection, stdin } => change(&collection, stdin),
        Command::Completions { shell } => completions(shell),
    };
    tracing::info!(exit = code, "exit classified");
    ExitCode::from(code)
}

/// Install the -v diagnostics subscriber on stderr. Every event the code
/// emits carries explicit scalar fields — operation names, results,
/// lengths, outcomes, exit codes — and never password bytes, key material,
/// IV values, ciphertext bodies, or secret-bearing structs.
fn install_verbose_subscriber() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::INFO)
        .try_init()
        .ok();
}

fn list() -> u8 {
    let span = tracing::info_span!("operation", operation = "list");
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.collections() {
            Ok(collections) => {
                print!("{}", render_collections(&collections));
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

fn status() -> u8 {
    let span = tracing::info_span!("operation", operation = "status");
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            // A rejecting daemon still answered the OpenSession negotiation, so
            // the service itself is reachable: the algorithm refusal is a
            // capability fact, reported as lines before the existing exit-1
            // mapping. Collections cannot be listed without a client.
            Err(error @ ServiceError::EncryptedSessionUnsupported) => {
                println!("secret service: org.freedesktop.secrets (reachable)");
                println!(
                    "encrypted session: not negotiated \
                     (dh-ietf1024-sha256-aes128-cbc-pkcs7 refused; no plain-session fallback)"
                );
                return report_service_error(error);
            }
            Err(error) => return report_service_error(error),
        };
        println!("secret service: org.freedesktop.secrets (reachable)");
        println!("encrypted session: negotiated ({})", session::ALGORITHM);
        let probe = client.private_interface_probe();
        tracing::info!(
            private_interface = private_interface_wording(probe),
            "private password interface probed"
        );
        println!(
            "private password interface: {}",
            private_interface_wording(probe)
        );
        match client.collections() {
            Ok(collections) => {
                print!("{}", render_lock_summary(&collections));
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

fn unlock(collection: &str, stdin: bool) -> u8 {
    let id = match CollectionId::new(collection) {
        Ok(id) => id,
        Err(error) => return report_service_error(error),
    };
    let span = tracing::info_span!("operation", operation = "unlock", collection = %id);
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        let selected = match client.collection(&id) {
            Ok(collection) => collection,
            Err(error) => return report_service_error(error),
        };

        if !selected.locked {
            println!("collection {id} is already unlocked; password was not checked");
            return EXIT_OK;
        }

        let secret = if stdin {
            secret_input::read_stdin_line(&mut io::stdin().lock())
        } else {
            secret_input::prompt(&format!("Password for {id}: "))
        };
        let secret = match secret {
            Ok(secret) => secret,
            Err(error) => {
                eprintln!("gmellon: {error}");
                return EXIT_ERROR;
            }
        };

        match client.unlock(&id, secret.as_bytes()) {
            Ok(UnlockOutcome::Unlocked) => {
                println!("unlocked collection {id}");
                tracing::info!(outcome = "Unlocked", "unlock outcome");
                EXIT_OK
            }
            Ok(UnlockOutcome::AlreadyUnlocked) => {
                println!("collection {id} is already unlocked; password was not checked");
                tracing::info!(outcome = "AlreadyUnlocked", "unlock outcome");
                EXIT_OK
            }
            Err(error) => {
                tracing::info!(outcome = denied_wording(&error), "unlock outcome");
                report_service_error(error)
            }
        }
    })
}

/// Lock a collection: an explicit state change, never implicit, never
/// prompting. An already-locked collection is a successful no-op.
fn lock(collection: &str) -> u8 {
    let id = match CollectionId::new(collection) {
        Ok(id) => id,
        Err(error) => return report_service_error(error),
    };
    let span = tracing::info_span!("operation", operation = "lock", collection = %id);
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.lock(&id) {
            Ok(LockOutcome::Locked) => {
                println!("locked collection {id}");
                tracing::info!(outcome = "Locked", "lock outcome");
                EXIT_OK
            }
            Ok(LockOutcome::AlreadyLocked) => {
                println!("collection {id} is already locked");
                tracing::info!(outcome = "AlreadyLocked", "lock outcome");
                EXIT_OK
            }
            Err(error) => {
                tracing::info!(outcome = denied_wording(&error), "lock outcome");
                report_service_error(error)
            }
        }
    })
}

fn change(collection: &str, stdin: bool) -> u8 {
    let id = match CollectionId::new(collection) {
        Ok(id) => id,
        Err(error) => return report_service_error(error),
    };
    let span = tracing::info_span!("operation", operation = "change", collection = %id);
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        if let Err(error) = client.collection(&id) {
            return report_service_error(error);
        }

        let secrets = if stdin {
            read_change_stdin(&mut io::stdin().lock())
        } else {
            read_change_tty(&id)
        };
        let (original, new) = match secrets {
            Ok(secrets) => secrets,
            Err(error) => return report_input_error(error),
        };

        match client.change_password(&id, original.as_bytes(), new.as_bytes()) {
            Ok(()) => {
                println!("changed password for collection {id}");
                tracing::info!(outcome = "Changed", "change outcome");
                EXIT_OK
            }
            Err(error) => {
                tracing::info!(outcome = denied_wording(&error), "change outcome");
                report_service_error(error)
            }
        }
    })
}

/// Outcome word for a failed password exchange: `Denied` only for a
/// password denial, `Failed` for everything else. The distinction is
/// metadata; the error detail stays on the ordinary stderr line.
fn denied_wording(error: &ServiceError) -> &'static str {
    match error {
        ServiceError::PasswordDenied => "Denied",
        _ => "Failed",
    }
}

/// Emit the completion script for one shell. Buffered and written once so
/// a broken pipe reports an exit-1 diagnostic instead of a panic.
/// List a collection's items: metadata only, no secret is read.
fn items(collection: &str) -> u8 {
    let id = match CollectionId::new(collection) {
        Ok(id) => id,
        Err(error) => return report_service_error(error),
    };
    let span = tracing::info_span!("operation", operation = "items", collection = %id);
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.items(&id) {
            Ok(items) => {
                print!("{}", render_items(&items));
                tracing::info!(count = items.len(), "items listed");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// List stored SSH key passphrases across all collections.
fn ssh_list() -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-list");
    span.in_scope(|| {
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.ssh_key_items() {
            Ok(entries) => {
                print!("{}", render_ssh_items(&entries));
                tracing::info!(count = entries.len(), "ssh key items listed");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// Verify a key's passphrase and store it the way gcr-ssh-agent finds it.
fn ssh_add(key: &Path, stdin: bool) -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-add", key = %key.display());
    span.in_scope(|| {
        // The absolute path is the storage key (the unique attribute), so
        // resolve symlinks and relative paths once, up front.
        let canonical = match std::fs::canonicalize(key) {
            Ok(canonical) => canonical,
            Err(error) => {
                eprintln!(
                    "gmellon: cannot resolve key path {}: {error}",
                    key.display()
                );
                return EXIT_ERROR;
            }
        };

        let secret = if stdin {
            secret_input::read_stdin_line(&mut io::stdin().lock())
        } else {
            secret_input::prompt(&format!(
                "SSH key passphrase for {} (the KEY's passphrase, not the keyring password): ",
                canonical.display()
            ))
        };
        let secret = match secret {
            Ok(secret) => secret,
            Err(error) => {
                eprintln!("gmellon: {error}");
                return EXIT_ERROR;
            }
        };

        match ssh::verify_passphrase(&canonical, secret.as_bytes()) {
            Verdict::Verified => {
                tracing::info!(verdict = "Verified", "key passphrase verified");
            }
            Verdict::Rejected => {
                eprintln!(
                    "gmellon: WRONG — that does not unlock {}, nothing stored",
                    canonical.display()
                );
                return EXIT_DENIED;
            }
            Verdict::NotEncrypted => {
                eprintln!(
                    "gmellon: {} is not passphrase-protected; there is nothing to store",
                    canonical.display()
                );
                return EXIT_ERROR;
            }
            Verdict::Unavailable(reason) => {
                eprintln!("gmellon: {reason}");
                return EXIT_ERROR;
            }
        }

        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        // gcr-ssh-agent's libsecret lookup goes to the default-alias
        // collection; store exactly there and say where.
        let target = match client.default_collection() {
            Ok(collection) => collection,
            Err(error) => return report_service_error(error),
        };
        match client.create_ssh_key_item(&target.id, &canonical.display().to_string(), secret.as_bytes())
        {
            Ok(()) => {
                println!(
                    "stored in collection {} & verified against the key",
                    target.id
                );
                tracing::info!(outcome = "Stored", collection = %target.id, "ssh key passphrase stored");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

/// Remove the stored passphrase item for an SSH key. The key file may no
/// longer exist — stale stored passphrases are the point — so the path is
/// only canonicalized when present, and otherwise made absolute verbatim.
fn ssh_remove(key: &Path) -> u8 {
    let span = tracing::info_span!("operation", operation = "ssh-remove", key = %key.display());
    span.in_scope(|| {
        let absolute = match std::fs::canonicalize(key) {
            Ok(canonical) => canonical,
            Err(_) => std::path::absolute(key).unwrap_or_else(|_| key.to_path_buf()),
        };
        let client = match BlockingClient::session() {
            Ok(client) => client,
            Err(error) => return report_service_error(error),
        };
        match client.remove_ssh_key_item(&absolute.display().to_string()) {
            Ok(collection) => {
                println!(
                    "removed stored passphrase for {} from collection {collection}",
                    absolute.display()
                );
                tracing::info!(outcome = "Removed", collection = %collection, "ssh key passphrase removed");
                EXIT_OK
            }
            Err(error) => report_service_error(error),
        }
    })
}

fn render_items(items: &[Item]) -> String {
    let mut output = String::from("LABEL\tLOCKED\tATTRIBUTES\n");
    for item in items {
        let locked = if item.locked { "yes" } else { "no" };
        output.extend(item.label.escape_debug());
        output.push('\t');
        output.push_str(locked);
        output.push('\t');
        let mut first = true;
        for (key, value) in &item.attributes {
            if !first {
                output.push(',');
            }
            first = false;
            output.push_str(key);
            output.push('=');
            output.extend(value.escape_debug());
        }
        output.push('\n');
    }
    output
}

fn render_ssh_items(entries: &[(CollectionId, Item)]) -> String {
    let mut output = String::from("KEY\tCOLLECTION\tLOCKED\n");
    for (collection, item) in entries {
        let locked = if item.locked { "yes" } else { "no" };
        output.extend(item.ssh_key_path().unwrap_or_default().escape_debug());
        output.push('\t');
        output.push_str(collection.as_str());
        output.push('\t');
        output.push_str(locked);
        output.push('\n');
    }
    output
}

fn completions(shell: Shell) -> u8 {
    let span = tracing::info_span!("operation", operation = "completions", shell = %shell);
    span.in_scope(|| {
        let mut command = Cli::command();
        let name = command.get_name().to_owned();
        let mut buffer = Vec::new();
        clap_complete::generate(shell, &mut command, name, &mut buffer);
        tracing::info!(bytes = buffer.len(), "completions generated");
        match io::stdout().write_all(&buffer) {
            Ok(()) => EXIT_OK,
            Err(error) => {
                eprintln!("gmellon: writing completions failed: {error}");
                EXIT_ERROR
            }
        }
    })
}

fn private_interface_wording(probe: InterfaceProbe) -> &'static str {
    match probe {
        InterfaceProbe::Available => "available",
        InterfaceProbe::Unavailable => "unavailable",
        InterfaceProbe::Unknown => "unknown (introspection failed)",
    }
}

fn read_change_stdin(reader: &mut impl io::BufRead) -> Result<(Secret, Secret), SecretError> {
    let original = secret_input::read_stdin_line(reader)?;
    let new = secret_input::read_stdin_confirmed(reader)?;
    Ok((original, new))
}

fn read_change_tty(id: &CollectionId) -> Result<(Secret, Secret), SecretError> {
    let original = secret_input::prompt(&format!("Current password for {id}: "))?;
    let new = secret_input::prompt_confirmed(
        &format!("New password for {id}: "),
        &format!("Confirm new password for {id}: "),
    )?;
    Ok((original, new))
}

fn report_input_error(error: SecretError) -> u8 {
    eprintln!("gmellon: {error}");
    EXIT_ERROR
}

fn report_service_error(error: ServiceError) -> u8 {
    let exit = service_error_exit(&error);
    eprintln!("gmellon: {error}");
    exit
}

fn service_error_exit(error: &ServiceError) -> u8 {
    match error {
        ServiceError::PasswordDenied => EXIT_DENIED,
        ServiceError::PrivateInterfaceUnavailable => EXIT_FAILED,
        ServiceError::ServiceUnavailable => EXIT_NO_DAEMON,
        ServiceError::InvalidCollectionId
        | ServiceError::InvalidCollectionPath { .. }
        | ServiceError::CollectionNotFound { .. }
        | ServiceError::EncryptedSessionUnsupported
        | ServiceError::Session(_)
        | ServiceError::LockPromptRequired
        | ServiceError::LockIncomplete { .. }
        | ServiceError::CollectionLocked { .. }
        | ServiceError::NoDefaultCollection
        | ServiceError::SshKeyItemNotFound { .. }
        | ServiceError::SshKeyItemsAmbiguous { .. }
        | ServiceError::Bus(_) => EXIT_ERROR,
    }
}

fn render_collections(collections: &[Collection]) -> String {
    let mut output = String::from("ID\tLOCKED\tLABEL\n");
    for collection in collections {
        let locked = if collection.locked { "yes" } else { "no" };
        output.push_str(collection.id.as_str());
        output.push('\t');
        output.push_str(locked);
        output.push('\t');
        output.extend(collection.label.escape_debug());
        output.push('\n');
    }
    output
}

/// The `status` collection block: a totals line, then one indented
/// ID-and-lock-state line per collection (already sorted by the client).
fn render_lock_summary(collections: &[Collection]) -> String {
    let locked = collections
        .iter()
        .filter(|collection| collection.locked)
        .count();
    let mut output = format!(
        "collections: {} total, {} locked\n",
        collections.len(),
        locked
    );
    let width = collections
        .iter()
        .map(|collection| collection.id.as_str().len())
        .max()
        .unwrap_or(0);
    for collection in collections {
        let state = if collection.locked {
            "locked"
        } else {
            "unlocked"
        };
        output.push_str(&format!(
            "  {:<width$}  {}\n",
            collection.id.as_str(),
            state,
            width = width
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, ValueEnum};
    use gmellon::secret_service::session::CryptoError;
    use zbus::zvariant::OwnedObjectPath;

    use super::*;

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn verbose_defaults_off() {
        let cli = Cli::try_parse_from(["gmellon", "list"]).unwrap();
        assert!(!cli.verbose);
    }

    #[test]
    fn verbose_is_a_global_flag_in_both_positions() {
        for argv in [
            vec!["gmellon", "-v", "list"],
            vec!["gmellon", "--verbose", "list"],
            vec!["gmellon", "list", "-v"],
            vec!["gmellon", "unlock", "work", "--stdin", "-v"],
        ] {
            let cli = Cli::try_parse_from(argv.clone()).unwrap();
            assert!(cli.verbose, "-v must parse globally for {argv:?}");
        }
    }

    #[test]
    fn help_exposes_collection_commands() {
        let help = Cli::command().render_long_help().to_string();

        for command in ["list", "status", "unlock", "change", "completions"] {
            assert!(help.contains(command), "help omitted {command}");
        }
        assert!(!help.contains("control-dir"));
        assert!(!help.contains("allow-create"));
    }

    #[test]
    fn help_names_the_unsupported_interface_caveat() {
        let help = Cli::command().render_long_help().to_string();

        assert!(
            help.contains("InternalUnsupportedGuiltRiddenInterface"),
            "after_help must name the unsupported private interface"
        );
        assert!(
            help.contains("doc/status.md"),
            "after_help must point at the compatibility document"
        );
        assert!(
            help.contains("may change or vanish"),
            "after_help must stay honest about upstream volatility"
        );
    }

    #[test]
    fn completions_parse_every_advertised_shell_and_reject_others() {
        for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
            let cli = Cli::try_parse_from(["gmellon", "completions", shell]).unwrap();
            assert!(
                matches!(cli.command, Command::Completions { .. }),
                "{shell} must parse"
            );
        }
        assert!(Cli::try_parse_from(["gmellon", "completions", "tcsh"]).is_err());
    }

    #[test]
    fn completions_render_subcommands_for_every_supported_shell() {
        for shell in Shell::value_variants() {
            let mut buffer = Vec::new();
            clap_complete::generate(*shell, &mut Cli::command(), "gmellon", &mut buffer);
            assert!(
                !buffer.is_empty(),
                "completions for {shell:?} must not be empty"
            );
        }

        let mut zsh = Vec::new();
        clap_complete::generate(Shell::Zsh, &mut Cli::command(), "gmellon", &mut zsh);
        let text = String::from_utf8(zsh).expect("zsh completions are UTF-8");
        for subcommand in ["list", "status", "unlock", "change", "completions"] {
            assert!(
                text.contains(subcommand),
                "zsh completions must name the {subcommand} subcommand"
            );
        }
    }

    #[test]
    fn status_rendering_summarizes_lock_state_and_aligns_ids() {
        let collections = [
            Collection {
                id: CollectionId::new("login").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                    .unwrap(),
                label: "Login".to_owned(),
                locked: true,
            },
            Collection {
                id: CollectionId::new("work").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work")
                    .unwrap(),
                label: "Work".to_owned(),
                locked: false,
            },
        ];

        assert_eq!(
            render_lock_summary(&collections),
            "collections: 2 total, 1 locked\n  login  locked\n  work   unlocked\n"
        );
    }

    #[test]
    fn status_rendering_handles_the_empty_service() {
        assert_eq!(render_lock_summary(&[]), "collections: 0 total, 0 locked\n");
    }

    #[test]
    fn private_interface_probe_wording_is_stable() {
        assert_eq!(
            private_interface_wording(InterfaceProbe::Available),
            "available"
        );
        assert_eq!(
            private_interface_wording(InterfaceProbe::Unavailable),
            "unavailable"
        );
        assert_eq!(
            private_interface_wording(InterfaceProbe::Unknown),
            "unknown (introspection failed)"
        );
    }

    #[test]
    fn unlock_defaults_to_login() {
        let cli = Cli::try_parse_from(["gmellon", "unlock"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Unlock {
                collection,
                stdin: false
            } if collection == "login"
        ));
    }

    #[test]
    fn unlock_accepts_an_explicit_collection_and_stdin() {
        let cli = Cli::try_parse_from(["gmellon", "unlock", "work", "--stdin"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Unlock {
                collection,
                stdin: true
            } if collection == "work"
        ));
    }

    #[test]
    fn lock_defaults_to_login() {
        let cli = Cli::try_parse_from(["gmellon", "lock"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Lock { collection } if collection == "login"
        ));
    }

    #[test]
    fn lock_accepts_an_explicit_collection() {
        let cli = Cli::try_parse_from(["gmellon", "lock", "work"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Lock { collection } if collection == "work"
        ));
    }

    #[test]
    fn change_defaults_to_login() {
        let cli = Cli::try_parse_from(["gmellon", "change"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Change {
                collection,
                stdin: false
            } if collection == "login"
        ));
    }

    #[test]
    fn change_accepts_an_explicit_collection_and_stdin() {
        let cli = Cli::try_parse_from(["gmellon", "change", "work", "--stdin"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Change {
                collection,
                stdin: true
            } if collection == "work"
        ));
    }

    #[test]
    fn change_stdin_reads_current_new_and_confirmation_lines() {
        let mut input = io::Cursor::new(b"old\nnew\nnew\n".to_vec());
        let result = read_change_stdin(&mut input);
        let (original, new) = match result {
            Ok(secrets) => secrets,
            Err(error) => panic!("three valid lines should parse: {error}"),
        };

        assert_eq!(original.as_bytes(), b"old");
        assert_eq!(new.as_bytes(), b"new");
    }

    #[test]
    fn change_stdin_rejects_confirmation_mismatch() {
        let mut input = io::Cursor::new(b"old\nnew\ndifferent\n".to_vec());

        assert!(matches!(
            read_change_stdin(&mut input),
            Err(SecretError::ConfirmationMismatch)
        ));
    }

    #[test]
    fn service_errors_map_to_stable_exit_codes() {
        assert_eq!(service_error_exit(&ServiceError::PasswordDenied), 2);
        assert_eq!(
            service_error_exit(&ServiceError::PrivateInterfaceUnavailable),
            3
        );
        assert_eq!(service_error_exit(&ServiceError::ServiceUnavailable), 4);
        assert_eq!(service_error_exit(&ServiceError::InvalidCollectionId), 1);
        assert_eq!(
            service_error_exit(&ServiceError::CollectionNotFound {
                id: CollectionId::new("missing").unwrap()
            }),
            1
        );
        // The encrypted-session failures stay in the unexpected-local-error
        // family: the documented 0-4 exit table gains no new code.
        assert_eq!(
            service_error_exit(&ServiceError::EncryptedSessionUnsupported),
            1
        );
        assert_eq!(
            service_error_exit(&ServiceError::Session(CryptoError::Randomness)),
            1
        );
        // Lock stays in the unexpected-error family too: a demanded prompt
        // object or an incomplete lock is a clear stderr message, never a
        // new exit code.
        assert_eq!(service_error_exit(&ServiceError::LockPromptRequired), 1);
        assert_eq!(
            service_error_exit(&ServiceError::LockIncomplete {
                id: CollectionId::new("work").unwrap()
            }),
            1
        );
    }

    #[test]
    fn collection_rendering_is_deterministic_and_escapes_controls() {
        let collections = [
            Collection {
                id: CollectionId::new("login").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login")
                    .unwrap(),
                label: "Login".to_owned(),
                locked: true,
            },
            Collection {
                id: CollectionId::new("work").unwrap(),
                path: OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work")
                    .unwrap(),
                label: "Work\nSecrets".to_owned(),
                locked: false,
            },
        ];

        assert_eq!(
            render_collections(&collections),
            "ID\tLOCKED\tLABEL\nlogin\tyes\tLogin\nwork\tno\tWork\\nSecrets\n"
        );
    }
}
