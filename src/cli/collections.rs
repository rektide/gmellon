//! Collection command handlers: list, status, unlock, lock, change, and
//! items. The unlock and change paths speak GNOME Keyring's private
//! password interface through the client; the rest are read-only.

use std::io;

use gmellon::secret_input::{self, Secret, SecretError};
use gmellon::secret_service::{
    ALGORITHM, BlockingClient, CollectionId, Error as ServiceError, LockOutcome, UnlockOutcome,
};

use super::render::{
    private_interface_wording, render_collections, render_items, render_lock_summary,
};
use super::report::{
    EXIT_ERROR, EXIT_OK, denied_wording, report_input_error, report_service_error,
};

pub(crate) fn list() -> u8 {
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

pub(crate) fn status() -> u8 {
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
        println!("encrypted session: negotiated ({})", ALGORITHM);
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

pub(crate) fn unlock(collection: &str, stdin: bool) -> u8 {
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
pub(crate) fn lock(collection: &str) -> u8 {
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

pub(crate) fn change(collection: &str, stdin: bool) -> u8 {
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

/// List a collection's items: metadata only, no secret is read.
pub(crate) fn items(collection: &str) -> u8 {
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

#[cfg(test)]
mod tests {
    use std::io;

    use gmellon::secret_input::SecretError;

    use super::*;

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
}
