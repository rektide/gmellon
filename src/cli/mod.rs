use std::io;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use gmellon::secret_input::{self, Secret, SecretError};
use gmellon::secret_service::session;
use gmellon::secret_service::{
    BlockingClient, Collection, CollectionId, Error as ServiceError, InterfaceProbe,
    UnlockOutcome,
};

const EXIT_ERROR: u8 = 1;
const EXIT_DENIED: u8 = 2;
const EXIT_FAILED: u8 = 3;
const EXIT_NO_DAEMON: u8 = 4;
const DEFAULT_COLLECTION: &str = "login";

/// List, unlock, and re-key GNOME keyring collections without a GUI or PAM.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List collection IDs, labels, and lock state.
    List,

    /// Report service capabilities and collection lock state.
    ///
    /// A prompt-free health report, distinct from `list`'s deterministic
    /// column output: it never prompts, never unlocks or locks anything,
    /// and never calls a password method. Per-collection lines carry the
    /// stable ID and lock state only; labels belong to `list`.
    Status,

    /// Unlock an existing collection.
    Unlock {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,

        /// Read one password line from stdin instead of prompting on the TTY.
        #[arg(long)]
        stdin: bool,
    },

    /// Change an existing collection's password.
    Change {
        /// Stable collection ID; defaults to login.
        #[arg(value_name = "COLLECTION", default_value = DEFAULT_COLLECTION)]
        collection: String,

        /// Read old, new, and confirmation lines from stdin.
        #[arg(long)]
        stdin: bool,
    },
}

pub fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Command::List => list(),
        Command::Status => status(),
        Command::Unlock { collection, stdin } => unlock(&collection, stdin),
        Command::Change { collection, stdin } => change(&collection, stdin),
    }
}

fn list() -> ExitCode {
    let client = match BlockingClient::session() {
        Ok(client) => client,
        Err(error) => return report_service_error(error),
    };
    match client.collections() {
        Ok(collections) => {
            print!("{}", render_collections(&collections));
            ExitCode::SUCCESS
        }
        Err(error) => report_service_error(error),
    }
}

fn status() -> ExitCode {
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
    println!(
        "private password interface: {}",
        private_interface_wording(client.private_interface_probe())
    );
    match client.collections() {
        Ok(collections) => {
            print!("{}", render_lock_summary(&collections));
            ExitCode::SUCCESS
        }
        Err(error) => report_service_error(error),
    }
}

fn private_interface_wording(probe: InterfaceProbe) -> &'static str {
    match probe {
        InterfaceProbe::Available => "available",
        InterfaceProbe::Unavailable => "unavailable",
        InterfaceProbe::Unknown => "unknown (introspection failed)",
    }
}

fn unlock(collection: &str, stdin: bool) -> ExitCode {
    let id = match CollectionId::new(collection) {
        Ok(id) => id,
        Err(error) => return report_service_error(error),
    };
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
        return ExitCode::SUCCESS;
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
            return ExitCode::from(EXIT_ERROR);
        }
    };

    match client.unlock(&id, secret.as_bytes()) {
        Ok(UnlockOutcome::Unlocked) => {
            println!("unlocked collection {id}");
            ExitCode::SUCCESS
        }
        Ok(UnlockOutcome::AlreadyUnlocked) => {
            println!("collection {id} is already unlocked; password was not checked");
            ExitCode::SUCCESS
        }
        Err(error) => report_service_error(error),
    }
}

fn change(collection: &str, stdin: bool) -> ExitCode {
    let id = match CollectionId::new(collection) {
        Ok(id) => id,
        Err(error) => return report_service_error(error),
    };
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
            ExitCode::SUCCESS
        }
        Err(error) => report_service_error(error),
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

fn report_input_error(error: SecretError) -> ExitCode {
    eprintln!("gmellon: {error}");
    ExitCode::from(EXIT_ERROR)
}

fn report_service_error(error: ServiceError) -> ExitCode {
    let exit = service_error_exit(&error);
    eprintln!("gmellon: {error}");
    ExitCode::from(exit)
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
    use clap::{CommandFactory, Parser};
    use gmellon::secret_service::session::CryptoError;
    use zbus::zvariant::OwnedObjectPath;

    use super::*;

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_exposes_collection_commands() {
        let help = Cli::command().render_long_help().to_string();

        for command in ["list", "status", "unlock", "change"] {
            assert!(help.contains(command), "help omitted {command}");
        }
        assert!(!help.contains("control-dir"));
        assert!(!help.contains("allow-create"));
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
        assert_eq!(private_interface_wording(InterfaceProbe::Available), "available");
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
