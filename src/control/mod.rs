//! GNOME Keyring's private control protocol.
//!
//! Socket discovery, peer validation, and I/O will live behind this module's
//! client interface. The codec is exposed temporarily while that interface is
//! built.

mod protocol;

pub use protocol::{
    DaemonResult, DecodeError, EncodeError, Operation, Request, RequestFrame, decode_response,
    encode_request,
};
