//! Stable exit codes and the stderr diagnostics that report failures.
//!
//! The 0–4 table documented in `doc/status.md` is output contract:
//! `service_error_exit` matches every [`ServiceError`] variant, so adding
//! one forces an exit-code decision, and
//! `service_errors_map_to_stable_exit_codes` pins the mapping.

use gmellon::secret_input::SecretError;
use gmellon::secret_service::Error as ServiceError;

pub(crate) const EXIT_OK: u8 = 0;
pub(crate) const EXIT_ERROR: u8 = 1;
pub(crate) const EXIT_DENIED: u8 = 2;
pub(crate) const EXIT_FAILED: u8 = 3;
pub(crate) const EXIT_NO_DAEMON: u8 = 4;

/// Outcome word for a failed password exchange: `Denied` only for a
/// password denial, `Failed` for everything else. The distinction is
/// metadata; the error detail stays on the ordinary stderr line.
pub(crate) fn denied_wording(error: &ServiceError) -> &'static str {
    match error {
        ServiceError::PasswordDenied => "Denied",
        _ => "Failed",
    }
}

pub(crate) fn report_input_error(error: SecretError) -> u8 {
    eprintln!("gmellon: {error}");
    EXIT_ERROR
}

pub(crate) fn report_service_error(error: ServiceError) -> u8 {
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
        | ServiceError::SshKeyItemLocked { .. }
        | ServiceError::SecretSessionMismatch
        | ServiceError::Bus(_) => EXIT_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use gmellon::secret_service::CollectionId;
    use gmellon::secret_service::session::CryptoError;

    use super::*;

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
}
