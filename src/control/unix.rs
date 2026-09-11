use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::Metadata;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use rustix::process::RawUid;

/// A control socket failed a local ownership or type check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityError {
    SymbolicLink {
        path: PathBuf,
    },
    NotSocket {
        path: PathBuf,
    },
    SocketOwnerMismatch {
        path: PathBuf,
        expected: RawUid,
        actual: RawUid,
    },
    PeerOwnerMismatch {
        path: PathBuf,
        expected: RawUid,
        actual: RawUid,
    },
}

impl Display for SecurityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymbolicLink { path } => {
                write!(
                    formatter,
                    "control socket is a symbolic link: {}",
                    path.display()
                )
            }
            Self::NotSocket { path } => {
                write!(
                    formatter,
                    "control path is not a socket: {}",
                    path.display()
                )
            }
            Self::SocketOwnerMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "control socket {} belongs to uid {actual}, expected {expected}",
                path.display()
            ),
            Self::PeerOwnerMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "control socket peer at {} runs as uid {actual}, expected {expected}",
                path.display()
            ),
        }
    }
}

impl Error for SecurityError {}

pub(super) fn effective_uid() -> RawUid {
    rustix::process::geteuid().as_raw()
}

pub(super) fn validate_socket_metadata(
    path: &Path,
    metadata: &Metadata,
    expected_uid: RawUid,
) -> Result<(), SecurityError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(SecurityError::SymbolicLink {
            path: path.to_owned(),
        });
    }
    if !file_type.is_socket() {
        return Err(SecurityError::NotSocket {
            path: path.to_owned(),
        });
    }

    validate_socket_owner(path, expected_uid, metadata.uid())
}

fn validate_socket_owner(
    path: &Path,
    expected_uid: RawUid,
    actual_uid: RawUid,
) -> Result<(), SecurityError> {
    if actual_uid != expected_uid {
        return Err(SecurityError::SocketOwnerMismatch {
            path: path.to_owned(),
            expected: expected_uid,
            actual: actual_uid,
        });
    }

    Ok(())
}

pub(super) fn validate_peer_owner(
    path: &Path,
    expected_uid: RawUid,
    actual_uid: RawUid,
) -> Result<(), SecurityError> {
    if actual_uid != expected_uid {
        return Err(SecurityError::PeerOwnerMismatch {
            path: path.to_owned(),
            expected: expected_uid,
            actual: actual_uid,
        });
    }

    Ok(())
}

pub(super) fn peer_uid(socket: impl AsFd) -> io::Result<RawUid> {
    rustix::net::sockopt::socket_peercred(socket)
        .map(|credentials| credentials.uid.as_raw())
        .map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_checks_distinguish_socket_and_peer_mismatches() {
        let path = Path::new("control");

        assert_eq!(
            validate_socket_owner(path, 1000, 1001),
            Err(SecurityError::SocketOwnerMismatch {
                path: path.to_owned(),
                expected: 1000,
                actual: 1001,
            })
        );
        assert_eq!(
            validate_peer_owner(path, 1000, 1001),
            Err(SecurityError::PeerOwnerMismatch {
                path: path.to_owned(),
                expected: 1000,
                actual: 1001,
            })
        );
    }
}
