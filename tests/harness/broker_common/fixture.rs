//! Harness environment contract and the fixture connection: the only
//! facility permitted to create collections and to call the standard `Lock`
//! method, plus the private-interface proxies and the secret decryption the
//! fixture setup needs.

use std::collections::HashMap;
use std::env;
use std::error::Error as StdError;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs;
use std::path::{Path, PathBuf};

use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};
use zeroize::Zeroizing;

use gmellon::secret_service::decode_open_session_output;
use gmellon::secret_service::session::{self, ClientKeypair};

use super::required_env;
use crate::common;

pub const BROKER_MODE: &str = "private-broker";
/// One persistent fixture collection is labeled exactly `login`, because the
/// parent acceptance requires listing `login` plus a second collection by
/// stable ID. On the observed daemon 48.0 the token collection persists as
/// `login.keyring` and its D-Bus object-path ID is exactly `login` (the label
/// needs no escaping), so the proofs assert the exact ID rather than a
/// login-shaped approximation.
pub const LOGIN_LABEL: &str = "login";
/// Harness environment contract: proofs run inside `broker.py`, never on a
/// host bus.
pub struct BusEnvironment {
    pub address: String,
    pub root: PathBuf,
}

pub fn validated_harness_environment() -> BusEnvironment {
    assert_eq!(
        env::var("GMELL_HARNESS_MODE").ok().as_deref(),
        Some(BROKER_MODE),
        "the broker proof must run inside the private-broker harness"
    );

    let root = common::required_path("GMELL_HARNESS_ROOT");
    common::assert_beneath(&root, Path::new(common::APPROVED_TEMP_ROOT));
    let metadata = fs::metadata(&root).expect("harness root should exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    let socket = common::required_path("GMELL_HARNESS_BUS_SOCKET");
    common::assert_beneath(&socket, &root);
    let socket_metadata = fs::metadata(&socket).expect("private bus socket should exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        assert!(
            socket_metadata.file_type().is_socket(),
            "private bus path is not a socket: {}",
            socket.display()
        );
    }
    let address = format!("unix:path={}", socket.display());
    assert_eq!(
        env::var_os("DBUS_SESSION_BUS_ADDRESS").as_deref(),
        Some(OsStr::new(&address)),
        "session bus address must be the harness listener"
    );

    let system_address = required_env("DBUS_SYSTEM_BUS_ADDRESS");
    let unreachable = format!("unix:path={}", root.join("missing-system-bus").display());
    assert_eq!(
        system_address, unreachable,
        "system bus address must remain an unreachable scratch path"
    );
    assert!(
        !root.join("missing-system-bus").exists(),
        "unreachable system-bus scratch path must not exist"
    );

    for name in [
        "GMELL_HARNESS_DAEMON_PID",
        "GMELL_HARNESS_BROKER_LAUNCHER_PID",
        "GMELL_HARNESS_BROKER_PID",
    ] {
        assert!(env::var_os(name).is_some(), "harness did not export {name}");
    }
    for name in [
        "HOME",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_HOME",
        "GMELL_HARNESS_CONTROL_SOCKET",
    ] {
        common::assert_beneath(&common::required_path(name), &root);
    }

    BusEnvironment { address, root }
}

/// Fixture setup failure: transport or encrypted-session negotiation. The
/// fixture is test scaffolding, so any failure aborts the proof.
#[derive(Debug)]
pub enum FixtureError {
    Transport(zbus::Error),
    Session(gmellon::secret_service::Error),
}

impl Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "fixture D-Bus failure: {error}"),
            Self::Session(error) => write!(formatter, "fixture session failure: {error}"),
        }
    }
}

impl StdError for FixtureError {}

/// Disposable fixture: the only facility permitted to create collections and
/// to call the standard `Lock` method. It owns a separate D-Bus connection so
/// monitor evidence can attribute every Lock call to it alone. Product code
/// must never lock or relock a collection as part of ordinary unlock.
///
/// The fixture negotiates the same encrypted session the product client uses
/// (via the shared sans-I/O [`session`] core), so fixture-created collections
/// are also protected by sealed passwords and no password-method body on the
/// proof bus ever carries plaintext.
pub struct Fixture {
    connection: zbus::blocking::Connection,
    session_path: OwnedObjectPath,
    session_key: session::SessionKey,
    lock_calls: usize,
}

/// Secret Service `(oayays)` tuple, matching the product proxy declaration.
type FixtureSecret<'a> = (&'a ObjectPath<'a>, &'a [u8], &'a [u8], &'a str);

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
trait FixtureService {
    fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> zbus::Result<(zbus::zvariant::OwnedValue, OwnedObjectPath)>;

    /// TEST-FIXTURE ONLY: returns a disposable collection to the locked
    /// state. Counted and attributed so the proof can show product unlock
    /// never calls it.
    fn lock(
        &self,
        objects: &[ObjectPath<'_>],
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;

    /// TEST-FIXTURE ONLY: point an alias such as "default" at a collection,
    /// mirroring the state a real desktop session has (a real system's
    /// default alias resolves to its login keyring; the private fixture
    /// creation path does not establish one by itself).
    fn set_alias(&self, name: &str, collection: &ObjectPath<'_>) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
trait FixtureGnomeInternal {
    /// TEST-FIXTURE ONLY: create one persistent disposable collection
    /// protected by a generated password.
    fn create_with_master_password(
        &self,
        properties: &HashMap<&str, Value<'_>>,
        master: FixtureSecret<'_>,
    ) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets"
)]
trait FixtureCollection {
    #[zbus(property)]
    fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// TEST-FIXTURE ONLY: stage one standard-API item in this collection.
    /// Returns the item path and the prompt path (which must stay "/").
    fn create_item(
        &self,
        properties: &HashMap<&str, Value<'_>>,
        secret: FixtureSecret<'_>,
        replace: bool,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
}

#[zbus::proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets"
)]
trait FixtureItem {
    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<HashMap<String, String>>;

    /// TEST-FIXTURE ONLY: delete a fixture-staged item so a proof segment
    /// leaves no state behind. Returns the prompt path (which must stay "/").
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    /// TEST-FIXTURE ONLY: read one item's secret under the caller's
    /// encrypted session; the returned tuple is the wire Secret.
    fn get_secret(
        &self,
        session: &ObjectPath<'_>,
    ) -> zbus::Result<(OwnedObjectPath, Vec<u8>, Vec<u8>, String)>;
}

/// TEST-FIXTURE ONLY: decrypt one wire Secret under the fixture's session
/// key, mirroring what gcr-ssh-agent would obtain from the item. Lives in
/// the test harness: the product never decrypts.
pub fn fixture_open(
    key: &session::SessionKey,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    use aes::cipher::BlockModeDecrypt;
    use aes::cipher::{InnerIvInit, Key, KeyInit};
    use cbc::Decryptor;

    type Aes128 = aes::Aes128;
    let cipher = Aes128::new(&Key::<Aes128>::from(
        <[u8; 16]>::try_from(key.as_slice()).map_err(|_| "session key is not 16 bytes")?,
    ));
    let decryptor = Decryptor::<Aes128>::inner_iv_slice_init(cipher, iv)
        .map_err(|_| "item secret IV is not 16 bytes")?;
    let mut buffer = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded::<aes::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| "item secret failed to decrypt under the fixture session")?;
    Ok(Zeroizing::new(plaintext.to_vec()))
}

impl Fixture {
    pub fn connect(address: &str) -> Result<Self, FixtureError> {
        let connection = zbus::blocking::connection::Builder::address(address)
            .and_then(|builder| builder.build())
            .map_err(FixtureError::Transport)?;
        let service =
            FixtureServiceProxyBlocking::new(&connection).map_err(FixtureError::Transport)?;
        // Same negotiation the product client performs, reusing the shared
        // crypto core and decode step so the fixture's session is exactly as
        // encrypted as the product's.
        let keypair = ClientKeypair::generate().map_err(|error| {
            FixtureError::Session(gmellon::secret_service::Error::Session(error))
        })?;
        let input = Value::from(keypair.public_key());
        let (output, session_path) = service
            .open_session(session::ALGORITHM, &input)
            .map_err(FixtureError::Transport)?;
        let server_public = decode_open_session_output(&output).map_err(FixtureError::Session)?;
        let session_key = keypair.derive_aes_key(&server_public).map_err(|error| {
            FixtureError::Session(gmellon::secret_service::Error::Session(error))
        })?;
        Ok(Self {
            connection,
            session_path,
            session_key,
            lock_calls: 0,
        })
    }

    pub fn unique_name(&self) -> String {
        self.connection
            .unique_name()
            .expect("fixture connection owns a unique name")
            .to_string()
    }

    /// TEST-FIXTURE ONLY: read one item's secret back by its exact `unique`
    /// attribute, decrypting under the fixture's encrypted session — the
    /// same read gcr-ssh-agent performs. Proves the stored value equals the
    /// passphrase the proof fed to `ssh-add`.
    pub fn read_item_secret_by_unique(
        &self,
        collection: &OwnedObjectPath,
        unique_value: &str,
    ) -> Result<Zeroizing<Vec<u8>>, FixtureError> {
        let collection_proxy = FixtureCollectionProxyBlocking::builder(&self.connection)
            .destination("org.freedesktop.secrets")
            .map_err(FixtureError::Transport)?
            .path(collection.clone())
            .map_err(FixtureError::Transport)?
            .build()
            .map_err(FixtureError::Transport)?;
        for item_path in collection_proxy.items().map_err(FixtureError::Transport)? {
            let item_proxy = FixtureItemProxyBlocking::builder(&self.connection)
                .destination("org.freedesktop.secrets")
                .map_err(FixtureError::Transport)?
                .path(item_path)
                .map_err(FixtureError::Transport)?
                .build()
                .map_err(FixtureError::Transport)?;
            let attributes = item_proxy.attributes().map_err(FixtureError::Transport)?;
            if attributes.get("unique").map(String::as_str) == Some(unique_value) {
                let session: ObjectPath<'_> = self.session_path.as_ref();
                let (_session, iv, value, _content_type) = item_proxy
                    .get_secret(&session)
                    .map_err(FixtureError::Transport)?;
                return Ok(fixture_open(&self.session_key, &iv, &value)
                    .unwrap_or_else(|reason| panic!("fixture secret readback failed: {reason}")));
            }
        }
        Err(FixtureError::Session(
            gmellon::secret_service::Error::SshKeyItemNotFound {
                key: unique_value.to_owned(),
            },
        ))
    }

    pub fn lock_calls(&self) -> usize {
        self.lock_calls
    }

    /// Test-fixture setup only: point an alias such as "default" at a
    /// collection, mirroring a real desktop session (whose default alias
    /// resolves to the login keyring). The private fixture creation path
    /// does not establish aliases.
    pub fn set_alias(&self, name: &str, collection: &OwnedObjectPath) -> Result<(), FixtureError> {
        let service =
            FixtureServiceProxyBlocking::new(&self.connection).map_err(FixtureError::Transport)?;
        let path: ObjectPath<'_> = collection.as_ref();
        service
            .set_alias(name, &path)
            .map_err(FixtureError::Transport)
    }

    /// Test-fixture setup only: standard Lock on one disposable collection.
    pub fn lock(&mut self, collection: &OwnedObjectPath) -> Result<(), FixtureError> {
        let service =
            FixtureServiceProxyBlocking::new(&self.connection).map_err(FixtureError::Transport)?;
        let path: ObjectPath<'_> = collection.as_ref();
        let (locked, prompt) = service
            .lock(std::slice::from_ref(&path))
            .map_err(FixtureError::Transport)?;
        assert_eq!(
            prompt.as_str(),
            "/",
            "fixture Lock of a lockable collection must not return a prompt"
        );
        assert_eq!(
            locked.as_slice(),
            std::slice::from_ref(collection),
            "fixture Lock must report exactly the requested collection"
        );
        self.lock_calls += 1;
        Ok(())
    }

    /// Test-fixture setup only: private CreateWithMasterPassword. The label
    /// property key is interface-qualified because the daemon parses the
    /// dictionary against `org.freedesktop.Secret.Collection`. The master
    /// password is sealed under the fixture's encrypted session, exactly as
    /// the product seals its passwords.
    pub fn create(&self, label: &str, password: &[u8]) -> Result<OwnedObjectPath, FixtureError> {
        let sealed = session::seal(&self.session_key, password).map_err(|error| {
            FixtureError::Session(gmellon::secret_service::Error::Session(error))
        })?;
        let internal = FixtureGnomeInternalProxyBlocking::new(&self.connection)
            .map_err(FixtureError::Transport)?;
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert(
            "org.freedesktop.Secret.Collection.Label",
            Value::from(label),
        );
        let session: ObjectPath<'_> = self.session_path.as_ref();
        internal
            .create_with_master_password(
                &properties,
                (
                    &session,
                    sealed.iv.as_slice(),
                    sealed.ciphertext.as_slice(),
                    "text/plain",
                ),
            )
            .map_err(FixtureError::Transport)
    }

    /// TEST-FIXTURE ONLY: stage one standard-API ssh-store item — the same
    /// item shape the product's `ssh-add` stores, created through the plain
    /// `org.freedesktop.Secret.Collection.CreateItem` path so a proof can
    /// arrange states the product itself refuses to produce (such as two
    /// items claiming one key). With `extra_attribute` the staged item
    /// carries one attribute beyond the gcr set, which defeats
    /// gnome-keyring's subset-match replace and makes genuine duplicates
    /// possible. The passphrase is sealed under the fixture's encrypted
    /// session exactly as the product seals its stores.
    pub fn create_ssh_store_item(
        &self,
        collection: &OwnedObjectPath,
        unique_value: &str,
        label: &str,
        passphrase: &[u8],
        extra_attribute: Option<(&str, &str)>,
    ) -> Result<OwnedObjectPath, FixtureError> {
        let collection_proxy = FixtureCollectionProxyBlocking::builder(&self.connection)
            .destination("org.freedesktop.secrets")
            .map_err(FixtureError::Transport)?
            .path(collection.clone())
            .map_err(FixtureError::Transport)?
            .build()
            .map_err(FixtureError::Transport)?;
        let sealed = session::seal(&self.session_key, passphrase).map_err(|error| {
            FixtureError::Session(gmellon::secret_service::Error::Session(error))
        })?;
        let mut attributes: HashMap<String, String> = HashMap::new();
        attributes.insert("unique".to_owned(), unique_value.to_owned());
        attributes.insert(
            "xdg:schema".to_owned(),
            "org.freedesktop.Secret.Generic".to_owned(),
        );
        if let Some((key, value)) = extra_attribute {
            attributes.insert(key.to_owned(), value.to_owned());
        }
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::Dict(zbus::zvariant::Dict::from(attributes)),
        );
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let (item, prompt) = collection_proxy
            .create_item(
                &properties,
                (
                    &session,
                    sealed.iv.as_slice(),
                    sealed.ciphertext.as_slice(),
                    "text/plain",
                ),
                false,
            )
            .map_err(FixtureError::Transport)?;
        assert_eq!(
            prompt.as_str(),
            "/",
            "staging an ssh-store item must not demand a prompt"
        );
        Ok(item)
    }

    /// TEST-FIXTURE ONLY: delete a fixture-staged item, restoring the store
    /// state a proof segment found. The returned prompt path must stay "/".
    pub fn delete_item(&self, item: &OwnedObjectPath) -> Result<(), FixtureError> {
        let item_proxy = FixtureItemProxyBlocking::builder(&self.connection)
            .destination("org.freedesktop.secrets")
            .map_err(FixtureError::Transport)?
            .path(item.clone())
            .map_err(FixtureError::Transport)?
            .build()
            .map_err(FixtureError::Transport)?;
        let prompt = item_proxy.delete().map_err(FixtureError::Transport)?;
        assert_eq!(
            prompt.as_str(),
            "/",
            "deleting a fixture-staged item must not demand a prompt"
        );
        Ok(())
    }
}
/// The stable ID the installed daemon derives from a token-collection label:
/// the label with each `-` escaped as `_2d` (observed `gmellon_2dproof_2dalpha`
/// for `gmellon-proof-alpha`). `login` contains no escapable characters, so
/// its exact ID is `login` — the parent acceptance's literal requirement.
pub fn expected_collection_id(label: &str) -> String {
    label.replace('-', "_2d")
}
