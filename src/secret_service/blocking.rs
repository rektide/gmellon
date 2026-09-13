use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use super::proxies::{
    COLLECTION_PATH_PREFIX, GnomeInternalProxyBlocking, INTERNAL_INTERFACE_NAME, SERVICE_NAME,
    SERVICE_OBJECT_PATH, SecretCollectionProxyBlocking, SecretItemProxyBlocking,
    SecretServiceProxyBlocking,
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

/// The attribute gcr-ssh-agent matches key passphrases by (verified against
/// gcr-ssh-agent-interaction.c: the generic schema with one `unique` field).
pub const UNIQUE_ATTRIBUTE: &str = "unique";
/// Prefix of the `unique` attribute value for stored SSH key passphrases.
pub const SSH_STORE_PREFIX: &str = "ssh-store:";
/// The schema attribute libsecret records on items stored under a dotted
/// schema name; gcr's lookup includes it, so stored items must carry it.
pub const GENERIC_SCHEMA_ATTRIBUTE: (&str, &str) = ("xdg:schema", "org.freedesktop.Secret.Generic");

/// Public metadata for one item inside a collection. Metadata only —
/// item secrets are never read by gmellon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Item {
    pub label: String,
    pub locked: bool,
    /// Deterministically sorted attribute pairs.
    pub attributes: BTreeMap<String, String>,
    pub path: OwnedObjectPath,
}

impl Item {
    /// The SSH key path this item stores a passphrase for, when it carries
    /// the gcr `ssh-store:` unique attribute.
    pub fn ssh_key_path(&self) -> Option<&str> {
        self.attributes
            .get(UNIQUE_ATTRIBUTE)?
            .strip_prefix(SSH_STORE_PREFIX)
    }
}

/// The final path component of a key path, used for the human label.
fn ssh_key_basename(key_path: &str) -> &str {
    key_path.rsplit('/').next().unwrap_or(key_path)
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
    /// No stored passphrase item exists for the SSH key.
    SshKeyItemNotFound {
        key: String,
    },
    /// Multiple passphrase items claim the same key; nothing was changed.
    SshKeyItemsAmbiguous {
        key: String,
        count: usize,
    },
    /// The target collection is locked; storing requires unlocking first.
    CollectionLocked {
        id: CollectionId,
    },
    /// The service has no `default` alias; gcr-ssh-agent's lookup goes
    /// there, so stored keys would be unreachable.
    NoDefaultCollection,
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
            Self::CollectionLocked { id } => {
                write!(
                    formatter,
                    "collection {id} is locked; run gmellon unlock {id} first"
                )
            }
            Self::NoDefaultCollection => formatter.write_str(
                "the Secret Service has no default collection alias; gcr-ssh-agent \
                 looks there for stored key passphrases, so gmellon refuses to \
                 store where it could not be found",
            ),
            Self::SshKeyItemNotFound { key } => {
                write!(formatter, "no stored passphrase for SSH key {key}")
            }
            Self::SshKeyItemsAmbiguous { key, count } => {
                write!(
                    formatter,
                    "{count} stored passphrase items claim SSH key {key}; \
                     gmellon ssh-list shows them; nothing was changed"
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

    /// List the metadata of every item in a collection. Metadata only:
    /// labels, lock state, and attributes — no secret is read.
    pub fn items(&self, id: &CollectionId) -> Result<Vec<Item>, Error> {
        let proxy = self.collection_proxy(&self.find_path(id)?)?;
        let mut items = proxy
            .items()
            .map_err(classify_service_error)?
            .into_iter()
            .map(|path| self.inspect_item(path))
            .collect::<Result<Vec<_>, _>>()?;
        items.sort_by(|left, right| {
            (&left.label, &left.attributes).cmp(&(&right.label, &right.attributes))
        });
        Ok(items)
    }

    /// Every stored SSH key passphrase item across all collections: items
    /// whose `unique` attribute carries the gcr-ssh-agent `ssh-store:`
    /// prefix, paired with the owning collection's ID.
    pub fn ssh_key_items(&self) -> Result<Vec<(CollectionId, Item)>, Error> {
        let mut found = Vec::new();
        for collection in self.collections()? {
            let proxy = self.collection_proxy(&collection.path)?;
            for path in proxy.items().map_err(classify_service_error)? {
                let item = self.inspect_item(path)?;
                if item
                    .attributes
                    .get(UNIQUE_ATTRIBUTE)
                    .is_some_and(|value| value.starts_with(SSH_STORE_PREFIX))
                {
                    found.push((collection.id.clone(), item));
                }
            }
        }
        found.sort_by(|left, right| {
            let left_key = left.1.ssh_key_path().unwrap_or_default();
            let right_key = right.1.ssh_key_path().unwrap_or_default();
            (&left_key, &left.0, &left.1.label).cmp(&(&right_key, &right.0, &right.1.label))
        });
        Ok(found)
    }

    /// Resolve the service's `default` alias — where libsecret-based
    /// consumers such as gcr-ssh-agent look first — to its collection.
    pub fn default_collection(&self) -> Result<Collection, Error> {
        let service = SecretServiceProxyBlocking::new(&self.connection).map_err(Error::Bus)?;
        let path = service
            .read_alias("default")
            .map_err(classify_service_error)?;
        if path.as_str().is_empty() || path.as_str() == "/" {
            return Err(Error::NoDefaultCollection);
        }
        self.inspect_collection(path)
    }

    /// Store (or replace, by unique attribute) the passphrase item for an
    /// SSH key exactly as gcr-ssh-agent expects to find it: the
    /// `unique=ssh-store:<path>` attribute, the generic schema attribute
    /// libsecret records for dotted schemas, and a human label.
    ///
    /// The caller is responsible for having verified the passphrase against
    /// the key; this method only stores.
    pub fn create_ssh_key_item(
        &self,
        collection_id: &CollectionId,
        key_path: &str,
        passphrase: &[u8],
    ) -> Result<(), Error> {
        let collection = self.collection(collection_id)?;
        if collection.locked {
            return Err(Error::CollectionLocked {
                id: collection_id.clone(),
            });
        }
        let proxy = self.collection_proxy(&collection.path)?;

        let label = format!("Unlock password for: {}", ssh_key_basename(key_path));
        let mut attributes = std::collections::HashMap::new();
        attributes.insert(
            UNIQUE_ATTRIBUTE.to_owned(),
            format!("{SSH_STORE_PREFIX}{key_path}"),
        );
        attributes.insert(
            GENERIC_SCHEMA_ATTRIBUTE.0.to_owned(),
            GENERIC_SCHEMA_ATTRIBUTE.1.to_owned(),
        );
        let mut properties: std::collections::HashMap<&str, Value<'_>> =
            std::collections::HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::Dict(zbus::zvariant::Dict::from(attributes)),
        );

        let sealed = session::seal(&self.session_key, passphrase).map_err(Error::Session)?;
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let content_type = "text/plain";
        let (item, prompt) = proxy
            .create_item(
                &properties,
                (
                    &session,
                    sealed.iv.as_slice(),
                    sealed.ciphertext.as_slice(),
                    content_type,
                ),
                true,
            )
            .map_err(|error| classify_password_error(error, collection_id))?;
        // An empty path or "/" means no prompt was necessary; gmellon does
        // not perform prompt objects.
        if !prompt.as_str().is_empty() && prompt.as_str() != "/" {
            let _ = item;
            return Err(Error::LockPromptRequired);
        }
        Ok(())
    }

    fn inspect_item(&self, path: OwnedObjectPath) -> Result<Item, Error> {
        let proxy = self.item_proxy(path.clone())?;
        let label = proxy.label().map_err(classify_service_error)?;
        let locked = proxy.locked().map_err(classify_service_error)?;
        let attributes: BTreeMap<String, String> = proxy
            .attributes()
            .map_err(classify_service_error)?
            .into_iter()
            .collect();
        Ok(Item {
            label,
            locked,
            attributes,
            path,
        })
    }

    /// Delete the stored passphrase item for an SSH key, selected by exact
    /// `unique` attribute match. Exactly one match must exist: none is an
    /// error, and duplicates (which gcr cannot disambiguate either) are
    /// reported without changing anything.
    pub fn remove_ssh_key_item(&self, key_path: &str) -> Result<CollectionId, Error> {
        let wanted = format!("{SSH_STORE_PREFIX}{key_path}");
        let mut matches: Vec<(CollectionId, Item)> = Vec::new();
        for collection in self.collections()? {
            let proxy = self.collection_proxy(&collection.path)?;
            for path in proxy.items().map_err(classify_service_error)? {
                let item = self.inspect_item(path)?;
                if item.attributes.get(UNIQUE_ATTRIBUTE) == Some(&wanted) {
                    matches.push((collection.id.clone(), item));
                }
            }
        }
        match matches.len() {
            0 => Err(Error::SshKeyItemNotFound {
                key: key_path.to_owned(),
            }),
            1 => {
                let (collection_id, item) = matches.pop().expect("one match");
                let proxy = self.item_proxy(item.path)?;
                let prompt = proxy.delete().map_err(classify_service_error)?;
                // An empty path or "/" means no prompt was necessary;
                // gmellon does not perform prompt objects.
                if !prompt.as_str().is_empty() && prompt.as_str() != "/" {
                    return Err(Error::LockPromptRequired);
                }
                Ok(collection_id)
            }
            count => Err(Error::SshKeyItemsAmbiguous {
                key: key_path.to_owned(),
                count,
            }),
        }
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
        let proxy = self.collection_proxy(&path)?;
        let label = proxy.label().map_err(classify_service_error)?;
        let locked = proxy.locked().map_err(classify_service_error)?;
        Ok(Collection {
            id,
            path,
            label,
            locked,
        })
    }

    fn collection_proxy(
        &self,
        path: &OwnedObjectPath,
    ) -> Result<SecretCollectionProxyBlocking<'_>, Error> {
        SecretCollectionProxyBlocking::builder(&self.connection)
            .destination(SERVICE_NAME)
            .map_err(Error::Bus)?
            .path(path.clone())
            .map_err(Error::Bus)?
            .build()
            .map_err(Error::Bus)
    }

    fn item_proxy(&self, path: OwnedObjectPath) -> Result<SecretItemProxyBlocking<'_>, Error> {
        SecretItemProxyBlocking::builder(&self.connection)
            .destination(SERVICE_NAME)
            .map_err(Error::Bus)?
            .path(path)
            .map_err(Error::Bus)?
            .build()
            .map_err(Error::Bus)
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
