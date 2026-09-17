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
/// The per-key opt-in marking an SSH passphrase item answerable by the
/// gmellon askpass helper (design/askpass/askpass.glm53.md). Superset
/// attribute matching keeps gcr's lookup unaffected by its presence.
pub const ASKPASS_ATTRIBUTE: (&str, &str) = ("gmellon:askpass", "allow");

/// Public metadata for one item inside a collection. Metadata only —
/// item secrets are read solely by the askpass answer path
/// ([`BlockingClient::ssh_key_secret`]).
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

    /// Whether the gmellon askpass helper may answer for this item's key
    /// (the per-key opt-in; default-deny).
    pub fn askpass_allowed(&self) -> bool {
        self.attributes.get(ASKPASS_ATTRIBUTE.0) == Some(&ASKPASS_ATTRIBUTE.1.to_owned())
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
    /// The stored passphrase item for the key is locked; the askpass
    /// helper refuses rather than prompt.
    SshKeyItemLocked {
        key: String,
    },
    /// The service returned a secret sealed for a session other than the
    /// caller's; a protocol violation, treated as an unreadable secret.
    SecretSessionMismatch,
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
            Self::SshKeyItemLocked { key } => {
                write!(
                    formatter,
                    "the stored passphrase for SSH key {key} is locked; \
                     the askpass helper refuses rather than prompt"
                )
            }
            Self::SecretSessionMismatch => formatter.write_str(
                "the Secret Service returned a secret sealed for a different session",
            ),
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
    /// libsecret records for dotted schemas, and a human label. With
    /// `askpass_allowed` the item also ends up carrying the per-key
    /// opt-in that makes the gmellon askpass helper answer for it.
    ///
    /// gnome-keyring's CreateItem-replace match is subset-on-the-new-fields
    /// (gkd-secret-objects.c collection_find_matching_item →
    /// gkm_secret_fields_match): an existing item matches only when it
    /// already carries every attribute of the incoming properties, and a
    /// match has its attributes set wholesale. So a CreateItem carrying
    /// the grant would *duplicate* an existing un-granted item instead of
    /// replacing it. The store therefore always replaces with the plain
    /// gcr attribute set (which subset-matches granted and un-granted
    /// items alike, and replaces their attributes wholesale), and the
    /// grant is merged afterwards through the writable attributes
    /// property — two calls, but exactly one item, always.
    ///
    /// The caller is responsible for having verified the passphrase against
    /// the key; this method only stores.
    pub fn create_ssh_key_item(
        &self,
        collection_id: &CollectionId,
        key_path: &str,
        passphrase: &[u8],
        askpass_allowed: bool,
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
        // The merge step below re-sends the stored set plus the grant;
        // keep a copy before the properties map takes ownership.
        let mut merge_attributes = attributes.clone();
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
        // Second half of the no-duplicates sequence above: merge the grant
        // into the (now exactly one) item through the writable attributes
        // property. A plain re-store without the flag deliberately leaves
        // the grant off — the flags passed are the state stored.
        if askpass_allowed {
            merge_attributes.insert(
                ASKPASS_ATTRIBUTE.0.to_owned(),
                ASKPASS_ATTRIBUTE.1.to_owned(),
            );
            let proxy = self.item_proxy(item)?;
            proxy
                .set_attributes(merge_attributes)
                .map_err(classify_service_error)?;
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

    /// Every stored passphrase item across all collections whose `unique`
    /// attribute is exactly `ssh-store:<key_path>`, paired with the owning
    /// collection's ID. gcr-ssh-agent cannot disambiguate duplicates
    /// either, so callers require exactly one match.
    fn find_exact_ssh_key_items(&self, key_path: &str) -> Result<Vec<(CollectionId, Item)>, Error> {
        let wanted = format!("{SSH_STORE_PREFIX}{key_path}");
        let mut matches = Vec::new();
        for collection in self.collections()? {
            let proxy = self.collection_proxy(&collection.path)?;
            for path in proxy.items().map_err(classify_service_error)? {
                let item = self.inspect_item(path)?;
                if item.attributes.get(UNIQUE_ATTRIBUTE) == Some(&wanted) {
                    matches.push((collection.id.clone(), item));
                }
            }
        }
        Ok(matches)
    }

    /// The exactly-one match for a key's stored passphrase item with its
    /// owning collection: none is [`Error::SshKeyItemNotFound`], duplicates
    /// are [`Error::SshKeyItemsAmbiguous`] with nothing changed. Metadata
    /// only — the askpass path checks the grant before reading any secret.
    pub fn ssh_key_item(&self, key_path: &str) -> Result<(CollectionId, Item), Error> {
        let mut matches = self.find_exact_ssh_key_items(key_path)?;
        match matches.len() {
            1 => Ok(matches.pop().expect("one match")),
            0 => Err(Error::SshKeyItemNotFound {
                key: key_path.to_owned(),
            }),
            count => Err(Error::SshKeyItemsAmbiguous {
                key: key_path.to_owned(),
                count,
            }),
        }
    }

    /// Read back the stored passphrase for an SSH key — the one place
    /// gmellon decrypts a secret (the askpass answer path; see
    /// design/askpass/askpass.glm53.md). The secret crosses the bus only
    /// as ciphertext under this client's encrypted session and is
    /// returned zeroized-on-drop.
    ///
    /// The opt-in askpass grant is *not* consulted here; callers enforce
    /// their own policy before reading.
    pub fn ssh_key_secret(&self, key_path: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let (_collection_id, item) = self.ssh_key_item(key_path)?;
        if item.locked {
            return Err(Error::SshKeyItemLocked {
                key: key_path.to_owned(),
            });
        }
        let proxy = self.item_proxy(item.path)?;
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let (answered_session, iv, value, _content_type) = proxy
            .get_secret(&session)
            .map_err(classify_service_error)?;
        if answered_session.as_str() != session.as_str() {
            return Err(Error::SecretSessionMismatch);
        }
        let iv = zeroize::Zeroizing::new(iv);
        let value = zeroize::Zeroizing::new(value);
        let secret = session::open(&self.session_key, &iv, &value).map_err(Error::Session)?;
        tracing::info!(
            plaintext_length = secret.len(),
            "stored passphrase read back under the encrypted session"
        );
        Ok(secret)
    }

    /// Grant or revoke the askpass opt-in attribute on the stored
    /// passphrase item for a key, leaving the item (and its secret)
    /// untouched for gcr-ssh-agent. Returns the owning collection's ID.
    pub fn set_ssh_key_askpass(
        &self,
        key_path: &str,
        allowed: bool,
    ) -> Result<CollectionId, Error> {
        let (collection_id, item) = self.ssh_key_item(key_path)?;
        if item.locked {
            return Err(Error::SshKeyItemLocked {
                key: key_path.to_owned(),
            });
        }
        // The writable attributes property replaces the dictionary
        // wholesale, so start from the item's current attributes and
        // merge the one change.
        let mut attributes: std::collections::HashMap<String, String> = item
            .attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if allowed {
            attributes.insert(
                ASKPASS_ATTRIBUTE.0.to_owned(),
                ASKPASS_ATTRIBUTE.1.to_owned(),
            );
        } else {
            attributes.remove(ASKPASS_ATTRIBUTE.0);
        }
        let proxy = self.item_proxy(item.path)?;
        proxy
            .set_attributes(attributes)
            .map_err(classify_service_error)?;
        tracing::info!(allowed, "ssh key askpass grant updated");
        Ok(collection_id)
    }

    /// Delete the stored passphrase item for an SSH key, selected by exact
    /// `unique` attribute match. Exactly one match must exist: none is an
    /// error, and duplicates (which gcr cannot disambiguate either) are
    /// reported without changing anything.
    pub fn remove_ssh_key_item(&self, key_path: &str) -> Result<CollectionId, Error> {
        let (collection_id, item) = self.ssh_key_item(key_path)?;
        let proxy = self.item_proxy(item.path)?;
        let prompt = proxy.delete().map_err(classify_service_error)?;
        // An empty path or "/" means no prompt was necessary;
        // gmellon does not perform prompt objects.
        if !prompt.as_str().is_empty() && prompt.as_str() != "/" {
            return Err(Error::LockPromptRequired);
        }
        Ok(collection_id)
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
