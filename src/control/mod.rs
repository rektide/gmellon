//! GNOME Keyring's private login control interface.
//!
//! This module is available only with the `login-control` Cargo feature
//! (disabled by default) and is a library: no CLI command selects it and
//! there is no fallback path from the default zbus collection backend.
//!
//! Its semantics are narrower than the collection backend's and are stated
//! honestly rather than hidden:
//!
//! - only the special `login` keyring is addressable;
//! - UNLOCK and CHANGE can *create* a missing login keyring, encrypted with
//!   whatever password is sent; and
//! - an OK response cannot distinguish an already-unlocked keyring from a
//!   newly unlocked one.

mod protocol;
#[cfg(target_os = "linux")]
mod sync;
#[cfg(target_os = "linux")]
mod unix;

pub use protocol::DaemonResult;
#[cfg(target_os = "linux")]
pub use sync::{IoStage, LoginControlClient, LoginControlError};
#[cfg(target_os = "linux")]
pub use unix::SecurityError;

/// Pure protocol machinery for alternate I/O adapters and deterministic tests.
pub mod sans_io {
    pub use super::protocol::{
        DaemonResult, DecodeError, EncodeError, Operation, Request, RequestFrame, decode_request,
        decode_response, encode_request,
    };
}
