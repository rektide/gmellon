use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};

use super::proxies::{
    COLLECTION_PATH_PREFIX, GnomeInternalProxyBlocking, SERVICE_NAME,
    SecretCollectionProxyBlocking, SecretServiceProxyBlocking,
};

const DENIED_ERROR: &str = "org.gnome.keyring.Error.Denied";
const NO_SUCH_OBJECT_ERROR: &str = "org.freedesktop.Secret.Error.NoSuchObject";
const NAME_HAS_NO_OWNER_ERROR: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
const SERVICE_UNKNOWN_ERROR: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const UNKNOWN_INTERFACE_ERROR: &str = "org.freedesktop.DBus.Error.UnknownInterface";
const UNKNOWN_METHOD_ERROR: &str = "org.freedesktop.DBus.Error.UnknownMethod";

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

/// A collection discovery or password-operation failure.
#[derive(Debug)]
pub enum Error {
    InvalidCollectionId,
    InvalidCollectionPath { path: OwnedObjectPath },
    CollectionNotFound { id: CollectionId },
    ServiceUnavailable,
    PasswordDenied,
    PrivateInterfaceUnavailable,
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
            Self::Bus(error) => write!(formatter, "Secret Service D-Bus error: {error}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Bus(error) => Some(error),
            _ => None,
        }
    }
}

/// Blocking collection-oriented GNOME Keyring client.
///
/// The zbus proxy declarations also generate asynchronous proxies. A future
/// Tokio adapter can reuse those declarations and the collection model rather
/// than wrapping this blocking client.
pub struct BlockingClient {
    connection: Connection,
    session_path: OwnedObjectPath,
}

impl BlockingClient {
    /// Connect to the caller's D-Bus session and open a plain Secret Service
    /// session.
    pub fn session() -> Result<Self, Error> {
        Self::new(Connection::session().map_err(|_| Error::ServiceUnavailable)?)
    }

    /// Use an existing connection, such as an isolated test-bus connection.
    pub fn new(connection: Connection) -> Result<Self, Error> {
        let service = SecretServiceProxyBlocking::new(&connection).map_err(Error::Bus)?;
        let input = Value::from("");
        let (_output, session_path) = service
            .open_session("plain", &input)
            .map_err(classify_service_error)?;
        Ok(Self {
            connection,
            session_path,
        })
    }

    /// List all collections with stable IDs, mutable labels, and lock state.
    pub fn collections(&self) -> Result<Vec<Collection>, Error> {
        let service = SecretServiceProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let mut collections = service
            .collections()
            .map_err(classify_service_error)?
            .into_iter()
            .map(|path| self.inspect_collection(path))
            .collect::<Result<Vec<_>, _>>()?;
        collections.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(collections)
    }

    /// Resolve one collection by its stable ID.
    pub fn collection(&self, id: &CollectionId) -> Result<Collection, Error> {
        self.inspect_collection(self.find_path(id)?)
    }

    /// Unlock a selected collection. Already-unlocked collections are never
    /// relocked and the supplied password is not verified in that state.
    pub fn unlock(&self, id: &CollectionId, password: &[u8]) -> Result<UnlockOutcome, Error> {
        let collection = self.collection(id)?;
        if !collection.locked {
            return Ok(UnlockOutcome::AlreadyUnlocked);
        }

        let internal = GnomeInternalProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let empty_parameters: &[u8] = &[];
        let content_type = "text/plain";
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let path: ObjectPath<'_> = collection.path.as_ref();
        internal
            .unlock_with_master_password(
                &path,
                (&session, empty_parameters, password, content_type),
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
        let empty_parameters: &[u8] = &[];
        let content_type = "text/plain";
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let path: ObjectPath<'_> = collection.path.as_ref();
        internal
            .change_with_master_password(
                &path,
                (&session, empty_parameters, original_password, content_type),
                (&session, empty_parameters, new_password, content_type),
            )
            .map_err(|error| classify_password_error(error, id))
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

fn classify_password_error(error: zbus::Error, id: &CollectionId) -> Error {
    let zbus::Error::MethodError(name, _, _) = &error else {
        return Error::Bus(error);
    };

    match classify_error_name(name.as_str()) {
        RemoteError::Denied => Error::PasswordDenied,
        RemoteError::NoSuchObject => Error::CollectionNotFound { id: id.clone() },
        RemoteError::PrivateInterfaceUnavailable => Error::PrivateInterfaceUnavailable,
        RemoteError::ServiceUnavailable => Error::ServiceUnavailable,
        RemoteError::Other => Error::Bus(error),
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
    Other,
}

fn classify_error_name(name: &str) -> RemoteError {
    match name {
        DENIED_ERROR => RemoteError::Denied,
        NO_SUCH_OBJECT_ERROR => RemoteError::NoSuchObject,
        UNKNOWN_INTERFACE_ERROR | UNKNOWN_METHOD_ERROR => RemoteError::PrivateInterfaceUnavailable,
        NAME_HAS_NO_OWNER_ERROR | SERVICE_UNKNOWN_ERROR => RemoteError::ServiceUnavailable,
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
        assert_eq!(classify_error_name("org.example.Other"), RemoteError::Other);
    }

    #[test]
    fn service_constants_match_the_upstream_object() {
        assert_eq!(SERVICE_NAME, "org.freedesktop.secrets");
        assert!(ObjectPath::try_from("/org/freedesktop/secrets").is_ok());
    }
}
