//! Collection-oriented access to GNOME Keyring's Secret Service.
//!
//! Collection discovery uses the standard Secret Service API. Headless
//! password operations use GNOME Keyring's private
//! `InternalUnsupportedGuiltRiddenInterface`; capability errors are explicit.

pub mod session;

mod blocking;
mod proxies;

pub use blocking::{BlockingClient, Collection, CollectionId, Error, UnlockOutcome};
