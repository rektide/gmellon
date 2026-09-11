use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::protocol::{
    DaemonResult, DecodeError, EncodeError, Request, decode_response, encode_request,
};
use super::unix::{
    SecurityError, effective_uid, peer_uid, validate_peer_owner, validate_socket_metadata,
};

const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_LENGTH: usize = 8;
const CREDENTIAL_BYTE: [u8; 1] = [0];

/// The synchronous I/O step that failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoStage {
    InspectSocket,
    Connect,
    ConfigureSocket,
    InspectPeer,
    SendCredentials,
    SendRequest,
    ReceiveResponse,
}

impl Display for IoStage {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InspectSocket => "inspect control socket",
            Self::Connect => "connect to control socket",
            Self::ConfigureSocket => "configure control socket",
            Self::InspectPeer => "inspect control socket peer",
            Self::SendCredentials => "send control credentials",
            Self::SendRequest => "send control request",
            Self::ReceiveResponse => "receive control response",
        })
    }
}

/// A local failure while exchanging a request with the daemon.
#[derive(Debug)]
pub enum ControlError {
    NoDaemon { path: PathBuf },
    Security(SecurityError),
    Encode(EncodeError),
    Decode(DecodeError),
    Io { stage: IoStage, source: io::Error },
}

impl Display for ControlError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDaemon { path } => {
                write!(formatter, "no daemon is listening at {}", path.display())
            }
            Self::Security(error) => Display::fmt(error, formatter),
            Self::Encode(error) => write!(formatter, "could not encode control request: {error}"),
            Self::Decode(error) => write!(formatter, "invalid control response: {error}"),
            Self::Io { stage, source } => write!(formatter, "failed to {stage}: {source}"),
        }
    }
}

impl Error for ControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Security(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::NoDaemon { .. } => None,
        }
    }
}

/// Blocking adapter for GNOME Keyring's one-request-per-connection protocol.
///
/// Framing is provided by [`super::sans_io`]. A future asynchronous adapter can
/// reuse that codec and the Unix ownership checks without wrapping this type.
#[derive(Clone, Debug)]
pub struct SyncClient {
    socket_path: PathBuf,
    io_timeout: Duration,
}

impl SyncClient {
    /// Address the `control` socket inside `control_directory`.
    pub fn new(control_directory: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: control_directory.into().join("control"),
            io_timeout: DEFAULT_IO_TIMEOUT,
        }
    }

    /// Override the read and write timeout used for each exchange.
    #[must_use]
    pub fn with_io_timeout(mut self, io_timeout: Duration) -> Self {
        self.io_timeout = io_timeout;
        self
    }

    /// Return the socket path selected by this client.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Unlock or create the login keyring with `password`.
    pub fn unlock(&self, password: &[u8]) -> Result<DaemonResult, ControlError> {
        self.exchange(Request::Unlock { password })
    }

    /// Change the login keyring password.
    pub fn change(
        &self,
        original_password: &[u8],
        new_password: &[u8],
    ) -> Result<DaemonResult, ControlError> {
        self.exchange(Request::Change {
            original_password,
            new_password,
        })
    }

    fn exchange(&self, request: Request<'_>) -> Result<DaemonResult, ControlError> {
        let frame = encode_request(request).map_err(ControlError::Encode)?;
        let expected_uid = effective_uid();
        let metadata = match fs::symlink_metadata(&self.socket_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ControlError::NoDaemon {
                    path: self.socket_path.clone(),
                });
            }
            Err(source) => {
                return Err(ControlError::Io {
                    stage: IoStage::InspectSocket,
                    source,
                });
            }
        };
        validate_socket_metadata(&self.socket_path, &metadata, expected_uid)
            .map_err(ControlError::Security)?;

        let mut stream = UnixStream::connect(&self.socket_path).map_err(|source| {
            if matches!(
                source.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) {
                ControlError::NoDaemon {
                    path: self.socket_path.clone(),
                }
            } else {
                ControlError::Io {
                    stage: IoStage::Connect,
                    source,
                }
            }
        })?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(|source| ControlError::Io {
                stage: IoStage::ConfigureSocket,
                source,
            })?;

        let actual_uid = peer_uid(&stream).map_err(|source| ControlError::Io {
            stage: IoStage::InspectPeer,
            source,
        })?;
        validate_peer_owner(&self.socket_path, expected_uid, actual_uid)
            .map_err(ControlError::Security)?;

        stream
            .write_all(&CREDENTIAL_BYTE)
            .map_err(|source| ControlError::Io {
                stage: IoStage::SendCredentials,
                source,
            })?;
        stream
            .write_all(frame.as_ref())
            .map_err(|source| ControlError::Io {
                stage: IoStage::SendRequest,
                source,
            })?;

        let mut response = [0_u8; RESPONSE_LENGTH];
        stream
            .read_exact(&mut response)
            .map_err(|source| ControlError::Io {
                stage: IoStage::ReceiveResponse,
                source,
            })?;
        decode_response(&response).map_err(ControlError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::thread::{self, JoinHandle};

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::control::sans_io::decode_request;

    struct ReceivedRequest {
        credential: u8,
        frame: Zeroizing<Vec<u8>>,
    }

    #[test]
    fn unlock_sends_credentials_then_the_request() {
        let (directory, listener) = listening_control_socket();
        let server = serve_once(listener, vec![response(DaemonResult::Ok)], Duration::ZERO);
        let client = SyncClient::new(directory.path());

        assert_eq!(client.unlock(b"mellon").unwrap(), DaemonResult::Ok);
        let received = server.join().unwrap();
        assert_eq!(received.credential, 0);
        match decode_request(received.frame.as_slice()).unwrap() {
            Request::Unlock { password } => assert_eq!(password, b"mellon"),
            Request::Change { .. } => panic!("received change instead of unlock"),
        }
    }

    #[test]
    fn change_sends_both_passwords() {
        let (directory, listener) = listening_control_socket();
        let server = serve_once(
            listener,
            vec![response(DaemonResult::Denied)],
            Duration::ZERO,
        );
        let client = SyncClient::new(directory.path());

        assert_eq!(client.change(b"old", b"new").unwrap(), DaemonResult::Denied);
        let received = server.join().unwrap();
        match decode_request(received.frame.as_slice()).unwrap() {
            Request::Change {
                original_password,
                new_password,
            } => {
                assert_eq!(original_password, b"old");
                assert_eq!(new_password, b"new");
            }
            Request::Unlock { .. } => panic!("received unlock instead of change"),
        }
    }

    #[test]
    fn partial_response_delivery_is_reassembled() {
        let (directory, listener) = listening_control_socket();
        let response = response(DaemonResult::Ok);
        let server = serve_once(
            listener,
            vec![response[..3].to_vec(), response[3..].to_vec()],
            Duration::from_millis(10),
        );

        assert_eq!(
            SyncClient::new(directory.path()).unlock(b"friend").unwrap(),
            DaemonResult::Ok
        );
        server.join().unwrap();
    }

    #[test]
    fn missing_and_refused_sockets_are_no_daemon() {
        let directory = TempDir::new().unwrap();
        let client = SyncClient::new(directory.path());
        assert!(matches!(
            client.unlock(b"friend"),
            Err(ControlError::NoDaemon { .. })
        ));

        let socket_path = directory.path().join("control");
        let listener = UnixListener::bind(&socket_path).unwrap();
        drop(listener);
        assert!(matches!(
            client.unlock(b"friend"),
            Err(ControlError::NoDaemon { .. })
        ));
    }

    #[test]
    fn non_socket_and_symbolic_link_paths_are_rejected() {
        let directory = TempDir::new().unwrap();
        let socket_path = directory.path().join("control");
        File::create(&socket_path).unwrap();
        assert!(matches!(
            SyncClient::new(directory.path()).unlock(b"friend"),
            Err(ControlError::Security(SecurityError::NotSocket { .. }))
        ));

        fs::remove_file(&socket_path).unwrap();
        let target_path = directory.path().join("actual-control");
        let _listener = UnixListener::bind(&target_path).unwrap();
        symlink(&target_path, &socket_path).unwrap();
        assert!(matches!(
            SyncClient::new(directory.path()).unlock(b"friend"),
            Err(ControlError::Security(SecurityError::SymbolicLink { .. }))
        ));
    }

    #[test]
    fn malformed_and_truncated_responses_are_distinct() {
        let (directory, listener) = listening_control_socket();
        let server = serve_once(listener, vec![vec![0, 0, 0, 9, 0, 0, 0, 0]], Duration::ZERO);
        assert!(matches!(
            SyncClient::new(directory.path()).unlock(b"friend"),
            Err(ControlError::Decode(DecodeError::InvalidDeclaredLength {
                declared: 9
            }))
        ));
        server.join().unwrap();

        let (directory, listener) = listening_control_socket();
        let server = serve_once(listener, vec![vec![0, 0, 0, 8]], Duration::ZERO);
        assert!(matches!(
            SyncClient::new(directory.path()).unlock(b"friend"),
            Err(ControlError::Io {
                stage: IoStage::ReceiveResponse,
                ..
            })
        ));
        server.join().unwrap();
    }

    #[test]
    fn response_read_is_bounded_by_the_configured_timeout() {
        let (directory, listener) = listening_control_socket();
        let server = serve_once(listener, Vec::new(), Duration::from_millis(150));
        let client = SyncClient::new(directory.path()).with_io_timeout(Duration::from_millis(25));

        let error = client.unlock(b"friend").unwrap_err();
        assert!(matches!(
            error,
            ControlError::Io {
                stage: IoStage::ReceiveResponse,
                ..
            }
        ));
        server.join().unwrap();
    }

    fn listening_control_socket() -> (TempDir, UnixListener) {
        let directory = TempDir::new().unwrap();
        let listener = UnixListener::bind(directory.path().join("control")).unwrap();
        (directory, listener)
    }

    fn serve_once(
        listener: UnixListener,
        response_chunks: Vec<Vec<u8>>,
        delay: Duration,
    ) -> JoinHandle<ReceivedRequest> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut credential = [0_u8; 1];
            stream.read_exact(&mut credential).unwrap();

            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let frame_length = u32::from_be_bytes(length) as usize;
            let mut frame = Zeroizing::new(vec![0_u8; frame_length]);
            frame[..4].copy_from_slice(&length);
            stream.read_exact(&mut frame[4..]).unwrap();

            let has_response = !response_chunks.is_empty();
            for chunk in response_chunks {
                if !delay.is_zero() {
                    thread::sleep(delay);
                }
                stream.write_all(&chunk).unwrap();
            }
            if !has_response && !delay.is_zero() {
                thread::sleep(delay);
            }

            ReceivedRequest {
                credential: credential[0],
                frame,
            }
        })
    }

    fn response(result: DaemonResult) -> Vec<u8> {
        let mut response = 8_u32.to_be_bytes().to_vec();
        response.extend_from_slice(&(result as u32).to_be_bytes());
        response
    }
}
