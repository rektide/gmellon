//! Collection-oriented access to GNOME Keyring's Secret Service.
//!
//! Collection discovery uses the standard Secret Service API. Headless
//! password operations use GNOME Keyring's private
//! `InternalUnsupportedGuiltRiddenInterface`; capability errors are explicit.

pub mod session;

mod blocking;
mod proxies;

pub use blocking::{
    BlockingClient, Collection, CollectionId, Error, InterfaceProbe, Item, LockOutcome,
    UnlockOutcome, decode_open_session_output,
};
// The negotiated session's algorithm is client capability surface: the CLI
// reports it through this re-export rather than reaching into the sans-I/O
// crypto module below the client.
pub use session::ALGORITHM;
