use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::proxies::{
    COLLECTION_PATH_PREFIX, GnomeInternalProxyBlocking, INTERNAL_INTERFACE_NAME, SERVICE_NAME,
    SERVICE_OBJECT_PATH, SecretCollectionProxyBlocking, SecretServiceProxyBlocking,
};
use super::session::{self, ClientKeypair, CryptoError, SessionKey};

const DENIED_ERROR: &str = "org.gnome.keyring.Error.Denied";
const NO_SUCH_OBJECT_ERROR: &str = "org.freedesktop.Secret.Error.NoSuchObject";
const NAME_HAS_NO_OWNER_ERROR: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
const SERVICE_UNKNOWN_ERROR: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const UNKNOWN_INTERFACE_ERROR: &str = "org.freedesktop.DBus.Error.UnknownInterface";
const UNKNOWN_METHOD_ERROR: &str = "org.freedesktop.DBus.Error.UnknownMethod";
const NOT_SUPPORTED_ERROR: &str = "org.freedesktop.DBus.Error.NotSupported";

/// Stable identifier derived from a Secret Service collection object path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CollectionId(String);

impl CollectionId {
    /// Parse a non-empty collection ID. IDs are compared with object-path
    /// segments returned by the service; they are never interpolated into a
    /// D-Bus path.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.is_empty() {
            return Err(Error::InvalidCollectionId);
        }
        Ok(Self(value))
    }

    /// Borrow the collection ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_path(path: &OwnedObjectPath) -> Result<Self, Error> {
        let id = path
            .as_str()
            .strip_prefix(COLLECTION_PATH_PREFIX)
            .filter(|id| !id.is_empty() && !id.contains('/'))
            .ok_or_else(|| Error::InvalidCollectionPath { path: path.clone() })?;
        Self::new(id)
    }
}

impl Display for CollectionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Public metadata for one collection exposed by Secret Service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Collection {
    pub id: CollectionId,
    pub path: OwnedObjectPath,
    pub label: String,
    pub locked: bool,
}

/// Result of an ordinary unlock request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlockOutcome {
    /// The selected collection was locked and accepted the supplied password.
    Unlocked,
    /// The collection was already unlocked; the password was not checked.
    AlreadyUnlocked,
}

/// Result of an explicit lock request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockOutcome {
    /// The selected collection was locked by this request.
    Locked,
    /// The collection was already locked; no Lock call was made.
    AlreadyLocked,
}

/// Outcome of the read-only probe for GNOME Keyring's private password
/// interface.
///
/// The probe never calls a password method: it issues one standard
/// `org.freedesktop.DBus.Introspectable.Introspect` request on the service
/// object — read-only and side-effect-free, answered automatically by GDBus
/// objects — and searches the returned XML for the interface name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceProbe {
    /// The service object's introspection XML names the private interface.
    Available,
    /// The service answered introspection without naming the interface.
    Unavailable,
    /// Introspection itself failed; presence is unknown, not an error.
    Unknown,
}

/// A collection discovery or password-operation failure.
#[derive(Debug)]
pub enum Error {
    InvalidCollectionId,
    InvalidCollectionPath {
        path: OwnedObjectPath,
    },
    CollectionNotFound {
        id: CollectionId,
    },
    ServiceUnavailable,
    PasswordDenied,
    PrivateInterfaceUnavailable,
    /// The service rejected the encrypted-session algorithm. There is
    /// deliberately no plain-session fallback.
    EncryptedSessionUnsupported,
    /// The encrypted session's cryptography failed (randomness, peer key,
    /// key derivation, or sealing).
    Session(CryptoError),
    /// The service demanded an interactive prompt object to lock; gmellon
    /// does not perform prompt objects.
    LockPromptRequired,
    /// The service answered the Lock call without reporting the collection
    /// locked.
    LockIncomplete {
        id: CollectionId,
    },
    Bus(zbus::Error),
}

impl Display for Error {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCollectionId => formatter.write_str("collection ID cannot be empty"),
            Self::InvalidCollectionPath { path } => {
                write!(formatter, "unexpected collection object path: {path}")
            }
            Self::CollectionNotFound { id } => {
                write!(formatter, "collection ID does not exist: {id}")
            }
            Self::ServiceUnavailable => {
                formatter.write_str("GNOME Keyring's Secret Service is unavailable")
            }
            Self::PasswordDenied => formatter.write_str("collection password was denied"),
            Self::PrivateInterfaceUnavailable => formatter.write_str(
                "the Secret Service does not provide GNOME Keyring's private password interface",
            ),
            Self::EncryptedSessionUnsupported => formatter.write_str(
                "the Secret Service does not support encrypted sessions \
                 (dh-ietf1024-sha256-aes128-cbc-pkcs7); refusing to fall back to a plain session",
            ),
            Self::Session(error) => {
                write!(
                    formatter,
                    "encrypted Secret Service session failed: {error}"
                )
            }
            Self::LockPromptRequired => formatter.write_str(
                "the Secret Service demands an interactive prompt object to lock; \
                 gmellon does not perform prompt objects",
            ),
            Self::LockIncomplete { id } => {
                write!(
                    formatter,
                    "the service did not report collection {id} locked"
                )
            }
            Self::Bus(error) => write!(formatter, "Secret Service D-Bus error: {error}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Bus(error) => Some(error),
            _ => None,
        }
    }
}

/// Blocking collection-oriented GNOME Keyring client.
///
/// Every instance negotiates the encrypted Secret Service session
/// (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) on construction; there is no
/// plain-session fallback. Passwords are sealed per call with a fresh IV.
///
/// The zbus proxy declarations also generate asynchronous proxies. A future
/// Tokio adapter can reuse those declarations, the collection model, and the
/// sans-I/O [`session`] core rather than wrapping this blocking client.
pub struct BlockingClient {
    connection: Connection,
    session_path: OwnedObjectPath,
    session_key: SessionKey,
}

impl BlockingClient {
    /// Connect to the caller's D-Bus session and negotiate the encrypted
    /// Secret Service session.
    pub fn session() -> Result<Self, Error> {
        let span = tracing::info_span!("connection");
        let connection = span.in_scope(|| {
            let connection = Connection::session().map_err(|_| Error::ServiceUnavailable)?;
            tracing::info!("connected to the session bus");
            Ok(connection)
        })?;
        Self::new(connection)
    }

    /// Use an existing connection, such as an isolated test-bus connection,
    /// and negotiate the encrypted Secret Service session over it.
    pub fn new(connection: Connection) -> Result<Self, Error> {
        // The span name and every event in this client are diagnostics
        // surface: fields are scalars (algorithm names, IDs, lengths,
        // outcomes) — never password bytes, key material, IVs, ciphertext,
        // or secret-bearing structs.
        let _negotiation = tracing::info_span!("session-negotiation").entered();
        let service = SecretServiceProxyBlocking::new(&connection).map_err(Error::Bus)?;
        let keypair = ClientKeypair::generate().map_err(Error::Session)?;
        // The daemon unwraps the outer variant itself and requires the inner
        // type to be `ay` (G_VARIANT_TYPE_BYTESTRING in
        // gkd_secret_session_handle_open), so the public key travels as a
        // byte-array variant.
        let input = Value::from(keypair.public_key());
        let (output, session_path) = service
            .open_session(session::ALGORITHM, &input)
            .map_err(classify_session_error)?;
        let server_public = decode_open_session_output(&output)?;
        let session_key = keypair
            .derive_aes_key(&server_public)
            .map_err(Error::Session)?;
        tracing::info!(algorithm = session::ALGORITHM, "session negotiated");
        Ok(Self {
            connection,
            session_path,
            session_key,
        })
    }

    /// List all collections with stable IDs, mutable labels, and lock state.
    pub fn collections(&self) -> Result<Vec<Collection>, Error> {
        let _resolution = tracing::info_span!("collection-resolution").entered();
        let service = SecretServiceProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let mut collections = service
            .collections()
            .map_err(classify_service_error)?
            .into_iter()
            .map(|path| self.inspect_collection(path))
            .collect::<Result<Vec<_>, _>>()?;
        collections.sort_by(|left, right| left.id.cmp(&right.id));
        tracing::info!(collections = collections.len(), "collections resolved");
        Ok(collections)
    }

    /// Resolve one collection by its stable ID.
    pub fn collection(&self, id: &CollectionId) -> Result<Collection, Error> {
        let _resolution = tracing::info_span!("collection-resolution", collection = %id).entered();
        let collection = self.inspect_collection(self.find_path(id)?)?;
        tracing::info!(locked = collection.locked, "collection resolved");
        Ok(collection)
    }

    /// Probe whether the service exposes GNOME Keyring's private password
    /// interface, without ever calling a password method.
    ///
    /// One standard `Introspect` request on `/org/freedesktop/secrets`
    /// decides it: GDBus daemons answer with the XML of every interface
    /// registered on the object, so the interface name is either present
    /// ([`InterfaceProbe::Available`]) or absent
    /// ([`InterfaceProbe::Unavailable`]). A service that does not answer
    /// introspection — or any transport failure — reports
    /// [`InterfaceProbe::Unknown`] rather than an error: `status` may still
    /// report everything else.
    pub fn private_interface_probe(&self) -> InterfaceProbe {
        use zbus::blocking::fdo::IntrospectableProxy;

        let builder = IntrospectableProxy::builder(&self.connection);
        let Ok(builder) = builder.destination(SERVICE_NAME) else {
            return InterfaceProbe::Unknown;
        };
        let Ok(builder) = builder.path(SERVICE_OBJECT_PATH) else {
            return InterfaceProbe::Unknown;
        };
        let Ok(proxy) = builder.build() else {
            return InterfaceProbe::Unknown;
        };
        match proxy.introspect() {
            Ok(xml) if xml.contains(INTERNAL_INTERFACE_NAME) => InterfaceProbe::Available,
            Ok(_) => InterfaceProbe::Unavailable,
            Err(_) => InterfaceProbe::Unknown,
        }
    }

    /// Unlock a selected collection. Already-unlocked collections are never
    /// relocked and the supplied password is not verified in that state.
    pub fn unlock(&self, id: &CollectionId, password: &[u8]) -> Result<UnlockOutcome, Error> {
        let collection = self.collection(id)?;
        if !collection.locked {
            return Ok(UnlockOutcome::AlreadyUnlocked);
        }

        let internal = GnomeInternalProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let sealed = session::seal(&self.session_key, password).map_err(Error::Session)?;
        // Lengths only: the plaintext and ciphertext bytes never enter an
        // event, and the IV is never logged.
        tracing::info!(
            input = "password",
            plaintext_length = password.len(),
            ciphertext_length = sealed.ciphertext.len(),
            "seal performed"
        );
        let content_type = "text/plain";
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let path: ObjectPath<'_> = collection.path.as_ref();
        internal
            .unlock_with_master_password(
                &path,
                (
                    &session,
                    sealed.iv.as_slice(),
                    sealed.ciphertext.as_slice(),
                    content_type,
                ),
            )
            .map_err(|error| classify_password_error(error, id))?;
        Ok(UnlockOutcome::Unlocked)
    }

    /// Change the password protecting a selected collection.
    pub fn change_password(
        &self,
        id: &CollectionId,
        original_password: &[u8],
        new_password: &[u8],
    ) -> Result<(), Error> {
        let collection = self.collection(id)?;
        let internal = GnomeInternalProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let sealed_original =
            session::seal(&self.session_key, original_password).map_err(Error::Session)?;
        // Lengths only, one event per sealed input: no bytes, no IVs.
        tracing::info!(
            input = "original",
            plaintext_length = original_password.len(),
            ciphertext_length = sealed_original.ciphertext.len(),
            "seal performed"
        );
        let sealed_new = session::seal(&self.session_key, new_password).map_err(Error::Session)?;
        tracing::info!(
            input = "new",
            plaintext_length = new_password.len(),
            ciphertext_length = sealed_new.ciphertext.len(),
            "seal performed"
        );
        let content_type = "text/plain";
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let path: ObjectPath<'_> = collection.path.as_ref();
        internal
            .change_with_master_password(
                &path,
                (
                    &session,
                    sealed_original.iv.as_slice(),
                    sealed_original.ciphertext.as_slice(),
                    content_type,
                ),
                (
                    &session,
                    sealed_new.iv.as_slice(),
                    sealed_new.ciphertext.as_slice(),
                    content_type,
                ),
            )
            .map_err(|error| classify_password_error(error, id))
    }

    /// Lock a selected collection through the standard Secret Service API.
    ///
    /// Locking is an explicit state change; no other client method ever
    /// calls it (the never-relock discipline runs both directions). An
    /// already-locked collection is a successful no-op that makes no Lock
    /// call. The service is not expected to prompt for a lock, but if it
    /// demands an interactive prompt object the request fails closed rather
    /// than performing it.
    pub fn lock(&self, id: &CollectionId) -> Result<LockOutcome, Error> {
        let collection = self.collection(id)?;
        if collection.locked {
            return Ok(LockOutcome::AlreadyLocked);
        }

        let service = SecretServiceProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let path: ObjectPath<'_> = collection.path.as_ref();
        let (locked, prompt) = service.lock(&[path]).map_err(classify_service_error)?;
        // An empty path or "/" means no prompt was necessary. Anything else
        // is a prompt object gmellon refuses to perform.
        if !prompt.as_str().is_empty() && prompt.as_str() != "/" {
            return Err(Error::LockPromptRequired);
        }
        if !locked
            .iter()
            .any(|locked_path| locked_path == &collection.path)
        {
            return Err(Error::LockIncomplete { id: id.clone() });
        }
        Ok(LockOutcome::Locked)
    }

    fn find_path(&self, id: &CollectionId) -> Result<OwnedObjectPath, Error> {
        let service = SecretServiceProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        service
            .collections()
            .map_err(classify_service_error)?
            .into_iter()
            .find_map(|path| match CollectionId::from_path(&path) {
                Ok(found) if found == *id => Some(Ok(path)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .transpose()?
            .ok_or_else(|| Error::CollectionNotFound { id: id.clone() })
    }

    fn inspect_collection(&self, path: OwnedObjectPath) -> Result<Collection, Error> {
        let id = CollectionId::from_path(&path)?;
        let proxy = SecretCollectionProxyBlocking::builder(&self.connection)
            .destination(SERVICE_NAME)
            .map_err(Error::Bus)?
            .path(path.clone())
            .map_err(Error::Bus)?
            .build()
            .map_err(Error::Bus)?;
        let label = proxy.label().map_err(classify_service_error)?;
        let locked = proxy.locked().map_err(classify_service_error)?;
        Ok(Collection {
            id,
            path,
            label,
            locked,
        })
    }
}

fn classify_session_error(error: zbus::Error) -> Error {
    let zbus::Error::MethodError(name, _, _) = &error else {
        return Error::Bus(error);
    };
    match classify_error_name(name.as_str()) {
        RemoteError::ServiceUnavailable => Error::ServiceUnavailable,
        // gkd_secret_session_handle_open raises G_DBUS_ERROR_NOT_SUPPORTED
        // for an unknown algorithm. An algorithm-rejecting service gets a
        // distinct failure; there is deliberately no plain-session fallback
        // (libsecret falls back here; gmellon does not).
        RemoteError::EncryptedSessionUnsupported => Error::EncryptedSessionUnsupported,
        _ => Error::Bus(error),
    }
}

/// Decode a peer's OpenSession reply into its Diffie-Hellman public key
/// bytes. The reply payload is the `ay` variant the daemon builds for this
/// algorithm (g_variant_new_fixed_array in gkd-secret-session.c); a
/// byte-array answer arrives as a u8 array, and anything else is treated as
/// an unreadable peer key, failing closed. Public so test fixtures and a
/// future async adapter share one decode step for the same wire shape.
pub fn decode_open_session_output(output: &OwnedValue) -> Result<Vec<u8>, Error> {
    let bytes = match &**output {
        Value::Array(array) => {
            let mut bytes = Vec::with_capacity(array.len());
            for element in array.iter() {
                match element {
                    Value::U8(byte) => bytes.push(*byte),
                    _ => return Err(unreadable_peer_key()),
                }
            }
            bytes
        }
        _ => return Err(unreadable_peer_key()),
    };
    Ok(bytes)
}

fn unreadable_peer_key() -> Error {
    Error::Session(CryptoError::PeerPublicKeyLength { length: 0 })
}

fn classify_password_error(error: zbus::Error, id: &CollectionId) -> Error {
    let zbus::Error::MethodError(name, _, _) = &error else {
        return Error::Bus(error);
    };

    match classify_error_name(name.as_str()) {
        RemoteError::Denied => Error::PasswordDenied,
        RemoteError::NoSuchObject => Error::CollectionNotFound { id: id.clone() },
        RemoteError::PrivateInterfaceUnavailable => Error::PrivateInterfaceUnavailable,
        RemoteError::ServiceUnavailable => Error::ServiceUnavailable,
        RemoteError::EncryptedSessionUnsupported | RemoteError::Other => Error::Bus(error),
    }
}

fn classify_service_error(error: zbus::Error) -> Error {
    let zbus::Error::MethodError(name, _, _) = &error else {
        return Error::Bus(error);
    };
    if classify_error_name(name.as_str()) == RemoteError::ServiceUnavailable {
        Error::ServiceUnavailable
    } else {
        Error::Bus(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteError {
    Denied,
    NoSuchObject,
    PrivateInterfaceUnavailable,
    ServiceUnavailable,
    EncryptedSessionUnsupported,
    Other,
}

fn classify_error_name(name: &str) -> RemoteError {
    match name {
        DENIED_ERROR => RemoteError::Denied,
        NO_SUCH_OBJECT_ERROR => RemoteError::NoSuchObject,
        UNKNOWN_INTERFACE_ERROR | UNKNOWN_METHOD_ERROR => RemoteError::PrivateInterfaceUnavailable,
        NAME_HAS_NO_OWNER_ERROR | SERVICE_UNKNOWN_ERROR => RemoteError::ServiceUnavailable,
        NOT_SUPPORTED_ERROR => RemoteError::EncryptedSessionUnsupported,
        _ => RemoteError::Other,
    }
}

#[cfg(test)]
mod tests {
    use zbus::zvariant::ObjectPath;

    use super::*;

    #[test]
    fn collection_id_is_extracted_without_rebuilding_a_path() {
        let path = OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/work").unwrap();
        let id = CollectionId::from_path(&path).unwrap();

        assert_eq!(id.as_str(), "work");
    }

    #[test]
    fn malformed_collection_paths_are_rejected() {
        for path in [
            "/org/example/work",
            "/org/freedesktop/secrets/collection/work/nested",
        ] {
            let path = OwnedObjectPath::try_from(path).unwrap();
            assert!(matches!(
                CollectionId::from_path(&path),
                Err(Error::InvalidCollectionPath { .. })
            ));
        }
    }

    #[test]
    fn empty_collection_id_is_rejected() {
        assert!(matches!(
            CollectionId::new(""),
            Err(Error::InvalidCollectionId)
        ));
    }

    #[test]
    fn private_interface_error_names_are_recognized() {
        assert_eq!(
            classify_error_name(UNKNOWN_INTERFACE_ERROR),
            RemoteError::PrivateInterfaceUnavailable
        );
        assert_eq!(
            classify_error_name(UNKNOWN_METHOD_ERROR),
            RemoteError::PrivateInterfaceUnavailable
        );
        assert_eq!(classify_error_name(DENIED_ERROR), RemoteError::Denied);
        assert_eq!(
            classify_error_name(NO_SUCH_OBJECT_ERROR),
            RemoteError::NoSuchObject
        );
        assert_eq!(
            classify_error_name(SERVICE_UNKNOWN_ERROR),
            RemoteError::ServiceUnavailable
        );
        assert_eq!(
            classify_error_name(NAME_HAS_NO_OWNER_ERROR),
            RemoteError::ServiceUnavailable
        );
        assert_eq!(
            classify_error_name(NOT_SUPPORTED_ERROR),
            RemoteError::EncryptedSessionUnsupported
        );
        assert_eq!(classify_error_name("org.example.Other"), RemoteError::Other);
    }

    #[test]
    fn open_session_output_decodes_only_byte_arrays() {
        let bytes = Value::from(vec![0x01u8, 0x02, 0x7f]);
        let owned = OwnedValue::try_from(bytes).expect("byte array converts");
        assert_eq!(
            decode_open_session_output(&owned).expect("byte array decodes"),
            vec![0x01, 0x02, 0x7f]
        );

        for other in [Value::from("not a key"), Value::from(128u32)] {
            let owned = OwnedValue::try_from(other).expect("value converts");
            assert!(
                matches!(
                    decode_open_session_output(&owned),
                    Err(Error::Session(CryptoError::PeerPublicKeyLength {
                        length: 0
                    }))
                ),
                "non-array OpenSession replies must fail closed"
            );
        }
    }

    #[test]
    fn session_error_display_names_the_algorithm_and_refuses_fallback() {
        let message = Error::EncryptedSessionUnsupported.to_string();
        assert!(message.contains("does not support encrypted sessions"));
        assert!(message.contains("dh-ietf1024-sha256-aes128-cbc-pkcs7"));
        assert!(message.contains("refusing to fall back"));

        let wrapped = Error::Session(CryptoError::Randomness).to_string();
        assert!(wrapped.starts_with("encrypted Secret Service session failed:"));
    }

    #[test]
    fn service_constants_match_the_upstream_object() {
        assert_eq!(SERVICE_NAME, "org.freedesktop.secrets");
        assert!(ObjectPath::try_from("/org/freedesktop/secrets").is_ok());
        assert_eq!(
            SERVICE_OBJECT_PATH, "/org/freedesktop/secrets",
            "the probe must introspect the object the private interface lives on"
        );
        assert_eq!(
            INTERNAL_INTERFACE_NAME,
            "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"
        );
    }
}
