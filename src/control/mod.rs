//! GNOME Keyring's private control interface.

mod protocol;
#[cfg(unix)]
mod sync;
#[cfg(unix)]
mod unix;

pub use protocol::DaemonResult;
#[cfg(unix)]
pub use sync::{ControlError, IoStage, SyncClient};
#[cfg(unix)]
pub use unix::SecurityError;

/// Pure protocol machinery for alternate I/O adapters and deterministic tests.
pub mod sans_io {
    pub use super::protocol::{
        DaemonResult, DecodeError, EncodeError, Operation, Request, RequestFrame, decode_request,
        decode_response, encode_request,
    };
}
