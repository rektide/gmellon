//! Shared machinery for the private-broker Rust proofs.
//!
//! Both the collection-client proof
//! ([`tests/harness/broker_collections.rs`](../broker_collections.rs)) and the
//! CLI binary proof ([`tests/harness/broker_cli.rs`](../broker_cli.rs))
//! run inside [`broker.py`](../../../dev/harness/broker.py) against one
//! isolated private bus and daemon. They share this module for the validated
//! environment contract, the fixture connection that performs the only
//! permitted mutation setup (private `CreateWithMasterPassword` plus counted
//! standard `Lock` calls), the match-filtered method-call monitors (standard
//! `Service.Lock` for fixture-attributed locking, plus the password-bearing
//! private `ChangeWithMasterPassword` rule whose stdout is consumed by a
//! streaming reader that retains only header-derived facts and never writes
//! a raw log to disk), disposable proof secrets, and the outer isolated
//! runner. Include `mod common;` and
//! `mod broker_common;` together: this module builds on [`common`].
//!
//! The streaming header parser [`HeaderCallParser`] is pinned against the
//! installed busctl monitor shape by the ordinary positive-control tests in
//! [`tests/harness/redaction_scan.rs`](../redaction_scan.rs).
//!
//! This file is compiled only as a module of the declared `[[test]]`
//! targets; Cargo does not discover it as a separate test.

use std::collections::HashMap;
use std::env;
use std::error::Error as StdError;
use std::ffi::OsStr;
use std::fmt::Display;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};
use zeroize::Zeroizing;

use gmellon::secret_service::decode_open_session_output;
use gmellon::secret_service::session::{self, ClientKeypair};

use super::common;

pub const BROKER_MODE: &str = "private-broker";
pub const BUSCTL: &str = "/usr/bin/busctl";
pub const STDBUF: &str = "/usr/bin/stdbuf";
/// One persistent fixture collection is labeled exactly `login`, because the
/// parent acceptance requires listing `login` plus a second collection by
/// stable ID. On the observed daemon 48.0 the token collection persists as
/// `login.keyring` and its D-Bus object-path ID is exactly `login` (the label
/// needs no escaping), so the proofs assert the exact ID rather than a
/// login-shaped approximation.
pub const LOGIN_LABEL: &str = "login";
/// The monitor sees only this traffic: standard Service.Lock method calls.
/// Passwords travel exclusively in private-interface method bodies, which the
/// match rule excludes, so retained monitor output cannot carry secret bytes.
pub const LOCK_MATCH: &str = "interface='org.freedesktop.Secret.Service',member='Lock'";
/// The change monitor sees only this traffic: private
/// `ChangeWithMasterPassword` method calls. Unlike the Lock rule this one
/// selects password-bearing bodies by design — counting method-call headers
/// is the only wire evidence that a confirmation mismatch never reached the
/// daemon — so its stdout is consumed by an owned streaming reader that
/// records only header-derived facts (count and sender unique names) and
/// discards every other line, including bodies, as it is read. Decoded
/// password bytes therefore transit the pipe and the reader's single reused
/// line buffer only: no raw change-monitor output ever exists on disk, in
/// any form, on success, failure, or abrupt teardown.
pub const CHANGE_MATCH: &str = "interface='org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',member='ChangeWithMasterPassword'";
/// The body monitor sees every member of GNOME's private password
/// interface. Its bodies are password-bearing by design, so like the change
/// rule its stdout is a pipe streamed through an owned reader that never
/// writes bodies to disk; the reader additionally reconstructs each `ay`
/// array in memory to prove the passwords travel only as ciphertext.
pub const PASSWORD_INTERFACE_MATCH: &str =
    "interface='org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface'";
/// The negotiation monitor sees Secret Service OpenSession method calls.
/// Bodies carry the algorithm string and DH public keys only — never
/// passwords — but the monitor streams through a pipe and retains only
/// header- and algorithm-derived facts all the same.
pub const OPEN_SESSION_MATCH: &str =
    "interface='org.freedesktop.Secret.Service',member='OpenSession'";
/// The item-creation monitor sees CreateItem calls on Secret Service
/// collections: the only standard-API path a passphrase can travel. Bodies
/// are secret-bearing by design, so the pipe/reader discipline of the
/// password monitor applies unchanged.
pub const CREATE_ITEM_MATCH: &str =
    "interface='org.freedesktop.Secret.Collection',member='CreateItem'";
/// The exact body line the installed busctl renders for the encrypted
/// session algorithm string inside an OpenSession call.
pub const DH_ALGORITHM_LINE: &str = "STRING \"dh-ietf1024-sha256-aes128-cbc-pkcs7\";";
pub const MONITOR_BANNER: &str = "Monitoring bus message stream.";

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

/// Match-filtered bus monitor counting method calls of one member.
///
/// The monitor connects only to the harness's private bus. Its match rule
/// selects exactly one member's method calls; the summary retains only
/// header-derived facts (count and sender unique names), never message
/// bodies. Two policies cover the proof's two rules:
///
/// - the standard `Service.Lock` rule excludes every password-bearing body,
///   so its raw log is a file that is asserted secret-free (in bytes and
///   reversible encodings) after the run and deleted once the summary is
///   extracted; on failure paths it is retained for the artifact walk;
/// - the private `ChangeWithMasterPassword` rule selects password-bearing
///   bodies by design, so its stdout is never a file: it is a pipe drained
///   by an owned reader thread ([`HeaderCallParser`]) that records only
///   header-derived facts and drops every other line immediately. No raw
///   output exists on disk in any form, so no failure path — panic unwind,
///   reader error, malformed header, shutdown failure, abrupt signal — can
///   retain a password-bearing file either.
pub struct MethodMonitor {
    child: Child,
    /// Raw stdout log, present only for body-excluding rules. Always `None`
    /// for password-bearing rules, whose output never touches the
    /// filesystem.
    log_path: Option<PathBuf>,
    ready_path: PathBuf,
    summary_path: PathBuf,
    /// Owned streaming header reader, present only for password-bearing
    /// rules. Finish and Drop kill and reap the child first, so joining
    /// always observes the pipe's end-of-file and the thread never
    /// outlives the monitor (including through a panic unwind).
    reader: Option<JoinHandle<ReaderOutcome>>,
    spec: MonitorSpec,
}

/// What one monitor instance counts and how its artifacts are treated.
pub struct MonitorSpec {
    /// File stem for the raw log, readiness log, and redacted summary.
    pub stem: &'static str,
    /// The exclusive busctl match rule selecting the counted traffic.
    pub match_rule: &'static str,
    /// The member whose method-call headers are counted.
    pub member: &'static str,
    /// Whether the match rule selects password-bearing bodies.
    pub password_bearing: bool,
}

/// Final header-derived facts from the streaming reader thread. `failure`
/// carries the first reader I/O error or malformed/ambiguous header reason;
/// the proof turns any failure into a hard panic (fail closed) rather than
/// trusting a partial count.
pub struct ReaderOutcome {
    pub calls: usize,
    pub senders: Vec<String>,
    pub failure: Option<String>,
}

/// Incremental one-line-at-a-time parser for the password-bearing monitor's
/// stdout, pinned against the installed busctl 261 monitor rendering. Each
/// matched message prints one block:
///
/// ```text
/// ‣ Type=method_call  Endian=l  Flags=0  Version=1 Cookie=1  Timestamp="Sat 2026-09-12 07:49:30.942831 UTC"
///   Sender=:1.7  Destination=:1.3  Path=/org/freedesktop/DBus  Interface=org.freedesktop.DBus  Member=Hello
///   UniqueName=:1.7
///   MESSAGE "(…)" {
///           …body lines: quoted strings and one `BYTE <decimal>;` per
///           `ay` element…
///   };
///
/// ```
///
/// (captured under the private broker with a benign rule;
/// `.test-agent/change-monitor-hardening/probe.sh`). The target header is
/// exactly the line whose whitespace-delimited tokens include both
/// `Sender=<unique bus name>` and `Member=<member>`; the `Timestamp` value
/// contains spaces, so parsing is token-based, never substring-based. A line
/// that carries one of those key shapes without the other is malformed or
/// ambiguous for attribution and fails the proof closed instead of being
/// counted or guessed. Everything else — type lines, `UniqueName=` lines,
/// quoted body text, `BYTE` dumps, blank separators — is discarded
/// immediately and can never contribute to the count.
pub struct HeaderCallParser {
    member_token: String,
    pub calls: usize,
    pub senders: Vec<String>,
    pub failure: Option<String>,
}

impl HeaderCallParser {
    pub fn new(member: &'static str) -> Self {
        Self {
            member_token: format!("Member={member}"),
            calls: 0,
            senders: Vec::new(),
            failure: None,
        }
    }

    /// Examine one raw stdout line, record header-derived facts if it is a
    /// target header line, and drop its content. The first failure is
    /// sticky; later lines are still drained so the reader can reach
    /// end-of-file and be joined.
    pub fn absorb_line(&mut self, line: &str) {
        if self.failure.is_some() {
            return;
        }
        let mut sender: Option<&str> = None;
        let mut member_seen = false;
        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("Sender=") {
                if sender.is_some() {
                    self.fail_closed(format!(
                        "header line carries more than one Sender token: {line:?}"
                    ));
                    return;
                }
                sender = Some(value);
            } else if token == self.member_token {
                member_seen = true;
            }
        }
        match sender {
            Some(value) if member_seen => {
                if !is_unique_bus_name(value) {
                    self.fail_closed(format!(
                        "target header Sender value is not a unique bus name: {value:?}"
                    ));
                    return;
                }
                self.calls += 1;
                self.senders.push(value.to_owned());
            }
            Some(_) => self.fail_closed(format!(
                "header-shaped line without the target Member token; the \
                 installed busctl shape cannot be attributed: {line:?}"
            )),
            None if member_seen => self.fail_closed(format!(
                "target header line without a Sender token; the call cannot \
                 be attributed: {line:?}"
            )),
            None => {}
        }
    }

    fn fail_closed(&mut self, reason: String) {
        self.failure = Some(reason);
    }

    /// The header-derived facts, consuming the parser.
    pub fn into_outcome(self) -> ReaderOutcome {
        ReaderOutcome {
            calls: self.calls,
            senders: self.senders,
            failure: self.failure,
        }
    }
}

/// The D-Bus unique-name grammar the parser pins senders to: a leading `:`
/// followed by non-empty dot-separated elements of the bus-name alphabet.
/// Method-call senders on a bus are always unique names (the bus rewrites
/// the field when forwarding), so anything else is malformed output.
fn is_unique_bus_name(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(':') else {
        return false;
    };
    !rest.is_empty()
        && rest.split('.').all(|element| {
            !element.is_empty()
                && element.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
}

/// Spawn the owned reader thread that drains the password-bearing monitor's
/// piped stdout. One line buffer is reused: each line is parsed for
/// header-derived facts and its bytes dropped before the next line is read,
/// so no accumulation of raw stdout — in a String, Vec, or file — ever
/// exists, and decoded bodies live only transiently in the pipe and this
/// one buffer.
fn spawn_header_reader(stdout: ChildStdout, member: &'static str) -> JoinHandle<ReaderOutcome> {
    thread::Builder::new()
        .name(format!("{member}-monitor-headers"))
        .spawn(move || {
            let mut parser = HeaderCallParser::new(member);
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => parser.absorb_line(&line),
                    Err(error) => {
                        let mut outcome = parser.into_outcome();
                        outcome.failure =
                            Some(format!("reading {member} monitor stdout failed: {error}"));
                        return outcome;
                    }
                }
            }
            parser.into_outcome()
        })
        .unwrap_or_else(|error| panic!("spawn the {member} monitor reader thread: {error}"))
}

/// Build the line-buffered `busctl monitor` command for one match rule with
/// stdin detached. Callers decide where stdout and stderr go.
fn busctl_monitor_command(address: &str, match_rule: &str) -> Command {
    let mut command = Command::new(STDBUF);
    command
        .arg("-oL")
        .arg(BUSCTL)
        .arg(format!("--address={address}"))
        .arg("monitor")
        .arg(format!("--match={match_rule}"))
        .stdin(Stdio::null());
    command
}

/// Wait until the monitor's readiness log carries its banner. BecomeMonitor
/// applies only after the bus replies; the tool prints its banner then, so
/// waiting for the banner closes the startup race without guessing a delay.
fn wait_for_monitor_ready(ready_path: &Path, stem: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if fs::read_to_string(ready_path)
            .map(|log| log.contains(MONITOR_BANNER))
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("{stem} monitor did not reach monitoring state before the deadline");
}

/// Give the line-buffered monitor a moment to flush any in-flight line, then
/// stop it. `Child::kill` sends SIGKILL immediately on Unix — there is
/// deliberately no TERM-first grace period — and the pipe lives in the
/// kernel, so every line the monitor already wrote survives for its reader;
/// the settle delay plus the proofs' closed-count assertions guard against a
/// truncated last line. The deadline only bounds reaping.
fn stop_monitor_child(child: &mut Child, stem: &str) {
    thread::sleep(Duration::from_millis(200));
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => panic!("{stem} monitor did not exit after SIGKILL"),
            Err(error) => panic!("{stem} monitor wait failed: {error}"),
        }
    }
}

pub struct MonitorSummary {
    /// Observed method calls of [`MonitorSpec::member`].
    pub calls: usize,
    /// Every sender unique name, in arrival order.
    pub senders: Vec<String>,
    /// Observed calls whose sender is the fixture connection.
    pub fixture_calls: usize,
    /// Whether every observed call came from the fixture connection.
    pub senders_match_fixture: bool,
}

impl MethodMonitor {
    /// Standard `Service.Lock` monitor: fixture-attribution evidence for the
    /// no-relock guarantee. Password bodies are excluded by the match rule.
    pub fn lock(address: &str, root: &Path) -> Self {
        Self::start(
            MonitorSpec {
                stem: "lock-monitor",
                match_rule: LOCK_MATCH,
                member: "Lock",
                password_bearing: false,
            },
            address,
            root,
        )
    }

    /// Private `ChangeWithMasterPassword` call monitor: counts the method
    /// calls whose absence proves an input-rejected `gmellon change` never
    /// reached the daemon. Its match rule selects password-bearing bodies,
    /// so its stdout is streamed through a pipe and parsed incrementally:
    /// no raw output ever exists on disk.
    pub fn change_calls(address: &str, root: &Path) -> Self {
        Self::start(
            MonitorSpec {
                stem: "change-monitor",
                match_rule: CHANGE_MATCH,
                member: "ChangeWithMasterPassword",
                password_bearing: true,
            },
            address,
            root,
        )
    }

    pub fn start(spec: MonitorSpec, address: &str, root: &Path) -> Self {
        let ready_path = root.join(format!("{}.ready.log", spec.stem));
        let summary_path = root.join(format!("{}.txt", spec.stem));
        // busctl prints its readiness banner on stderr and all message
        // traffic — headers and bodies — on stdout, so the banner gets its
        // own file and stdout stays parseable. The readiness file cannot
        // carry bodies; finish still secret-scans it as proof.
        let ready = File::create(&ready_path)
            .unwrap_or_else(|error| panic!("create {} log: {error}", spec.stem));
        let mut command = busctl_monitor_command(address, spec.match_rule);
        command.stderr(ready);
        let monitor = if spec.password_bearing {
            // Password-bearing bodies must never exist on disk in any form,
            // not even transiently: stdout is a pipe drained by the owned
            // reader thread, which records only header-derived facts and
            // discards every other line as it is read.
            let mut child = command
                .stdout(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("spawn {BUSCTL} monitor: {error}"));
            let stdout = child
                .stdout
                .take()
                .expect("piped monitor stdout must be takeable right after spawn");
            let reader = Some(spawn_header_reader(stdout, spec.member));
            Self {
                child,
                log_path: None,
                ready_path,
                summary_path,
                reader,
                spec,
            }
        } else {
            let log_path = root.join(format!("{}.log", spec.stem));
            let output = File::create(&log_path)
                .unwrap_or_else(|error| panic!("create {} log: {error}", spec.stem));
            let child = command
                .stdout(output)
                .spawn()
                .unwrap_or_else(|error| panic!("spawn {BUSCTL} monitor: {error}"));
            Self {
                child,
                log_path: Some(log_path),
                ready_path,
                summary_path,
                reader: None,
                spec,
            }
        };
        wait_for_monitor_ready(&monitor.ready_path, monitor.spec.stem);
        monitor
    }

    /// Stop the monitor, extract the header-derived evidence, retain a
    /// redacted summary, and delete the raw logs.
    pub fn finish(
        self,
        fixture_sender: &str,
        fixture_calls: usize,
        secrets: &ProofSecrets,
    ) -> MonitorSummary {
        if self.reader.is_some() {
            self.finish_streaming(fixture_sender, fixture_calls, secrets)
        } else {
            self.finish_from_raw_log(fixture_sender, fixture_calls, secrets)
        }
    }

    /// Success path for the password-bearing streaming monitor: stop the
    /// monitor, join the reader, fail closed on any reader or parser
    /// failure, retain only the header-derived summary, and delete the
    /// banner-only readiness log. There is no raw log to delete because
    /// none was ever created.
    fn finish_streaming(
        mut self,
        fixture_sender: &str,
        fixture_calls: usize,
        secrets: &ProofSecrets,
    ) -> MonitorSummary {
        let handle = self
            .reader
            .take()
            .expect("streaming monitor owns its reader");
        let outcome = self.stop_and_join(handle);
        self.assert_ready_and_scan(secrets);
        if let Some(reason) = outcome.failure {
            panic!(
                "the streaming {} monitor failed closed: {reason}",
                self.spec.stem
            );
        }
        self.write_summary(
            fixture_sender,
            fixture_calls,
            outcome.calls,
            &outcome.senders,
            Some("streamed-headers-never-on-disk"),
        )
    }

    /// Success path for the body-excluding file monitor, unchanged in
    /// policy: read the raw log after shutdown, prove it and the readiness
    /// log secret-free, extract the header-derived count and senders,
    /// retain the redacted summary, and delete both raw logs.
    fn finish_from_raw_log(
        mut self,
        fixture_sender: &str,
        fixture_calls: usize,
        secrets: &ProofSecrets,
    ) -> MonitorSummary {
        let bytes = self.shutdown_and_read();
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        self.assert_ready_and_scan(secrets);
        for (_name, secret) in secrets.named() {
            // The match rule excludes password bodies entirely, so any
            // occurrence — literal or encoded — is a rule regression.
            common::assert_secret_absent(
                raw.as_bytes(),
                secret,
                &format!("the raw {} log", self.spec.stem),
            );
        }

        let member_token = format!("Member={}", self.spec.member);
        let senders: Vec<String> = raw
            .lines()
            .filter(|line| line.contains("Sender=") && line.contains(&member_token))
            .filter_map(|line| {
                line.split_whitespace()
                    .find(|token| token.starts_with("Sender="))
            })
            .map(|token| token.trim_start_matches("Sender=").to_string())
            .collect();
        let calls = senders.len();
        let summary = self.write_summary(fixture_sender, fixture_calls, calls, &senders, None);
        let log_path = self
            .log_path
            .clone()
            .expect("file monitor owns its raw log");
        fs::remove_file(&log_path)
            .unwrap_or_else(|error| panic!("delete raw {} log: {error}", self.spec.stem));
        fs::remove_file(&self.ready_path)
            .unwrap_or_else(|error| panic!("delete {} readiness log: {error}", self.spec.stem));
        summary
    }

    /// Require the readiness banner and prove the banner-only readiness log
    /// secret-free, whatever the rule.
    fn assert_ready_and_scan(&self, secrets: &ProofSecrets) {
        let ready = fs::read_to_string(&self.ready_path)
            .unwrap_or_else(|error| panic!("read {} readiness log: {error}", self.spec.stem));
        assert!(
            ready.contains(MONITOR_BANNER),
            "{} monitor log lost its readiness banner",
            self.spec.stem
        );
        let subject = format!("the {} monitor readiness log", self.spec.stem);
        for (_name, secret) in secrets.named() {
            common::assert_secret_absent(ready.as_bytes(), secret, &subject);
        }
    }

    /// Retain the redacted, header-derived summary and report it.
    fn write_summary(
        &self,
        fixture_sender: &str,
        fixture_calls: usize,
        calls: usize,
        senders: &[String],
        output: Option<&str>,
    ) -> MonitorSummary {
        let fixture_calls_observed = senders
            .iter()
            .filter(|sender| sender.as_str() == fixture_sender)
            .count();
        let senders_match_fixture = senders
            .iter()
            .all(|sender| sender.as_str() == fixture_sender);
        let output_line = match output {
            Some(output) => format!("output={output}\n"),
            None => String::new(),
        };
        let summary = format!(
            "tool={BUSCTL} monitor\nmatch={}\nmember={}\n{output_line}\
             fixture_sender={fixture_sender}\nfixture_calls_stated={fixture_calls}\n\
             observed_calls={calls}\nobserved_fixture_calls={fixture_calls_observed}\n\
             senders_match_fixture={senders_match_fixture}\nsenders={}\n",
            self.spec.match_rule,
            self.spec.member,
            senders.join(","),
        );
        fs::write(&self.summary_path, summary)
            .unwrap_or_else(|error| panic!("write redacted {} summary: {error}", self.spec.stem));
        MonitorSummary {
            calls,
            senders: senders.to_vec(),
            fixture_calls: fixture_calls_observed,
            senders_match_fixture,
        }
    }

    /// Stop the streaming monitor and collect the reader's final facts. The
    /// child is killed and reaped first, so its pipe write end is closed,
    /// the reader observes end-of-file (or has already exited on its own
    /// error), and the join cannot hang or outlive the process.
    fn stop_and_join(&mut self, handle: JoinHandle<ReaderOutcome>) -> ReaderOutcome {
        self.stop();
        handle
            .join()
            .unwrap_or_else(|_| panic!("the {} monitor reader thread panicked", self.spec.stem))
    }

    /// Give the line-buffered monitor a moment to flush any in-flight line,
    /// then stop it with the shared child-stop semantics.
    fn stop(&mut self) {
        stop_monitor_child(&mut self.child, self.spec.stem);
    }

    /// Body-excluding monitor shutdown: stop the process and read its raw
    /// log. Same stop semantics as [`MethodMonitor::stop`] — one immediate
    /// SIGKILL, not a TERM-then-KILL sequence.
    fn shutdown_and_read(&mut self) -> Vec<u8> {
        self.stop();
        let log_path = self
            .log_path
            .clone()
            .expect("file monitor owns its raw log");
        fs::read(&log_path).unwrap_or_else(|error| panic!("read {} log: {error}", self.spec.stem))
    }
}

impl Drop for MethodMonitor {
    fn drop(&mut self) {
        // Never leak the process or the reader thread, including through a
        // panic unwind: kill and reap the child first, which closes the
        // pipe, then join the reader (which at worst drains and drops the
        // remaining body lines). The password-bearing monitor has no raw
        // log on disk at any point, so failure paths only remove its
        // banner-only readiness log; body-excluding raw logs stay in place
        // for the artifact scan, as before.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
        if self.spec.password_bearing {
            let _ = fs::remove_file(&self.ready_path);
        }
    }
}

/// What one [`BodyMonitor`] instance watches and how it verdicts bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyMode {
    /// Every member of GNOME's private password interface. Verdicts assert
    /// that each Secret in each call traveled encrypted: a 16-byte IV array
    /// plus a non-empty 16-multiple ciphertext array, per member arity.
    PasswordMethods,
    /// Secret Service OpenSession calls. Verdicts assert the negotiated
    /// algorithm is the encrypted-session one and that a 1..=128-byte DH
    /// public key array traveled.
    OpenSessions,
    /// Secret Service CreateItem calls on collections. Verdicts assert each
    /// created item's Secret traveled encrypted: a 16-byte IV array plus a
    /// non-empty 16-multiple ciphertext array as the trailing pair.
    CreateItems,
}

/// Header- and length-derived facts for one captured method call. Never
/// carries body bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct CapturedBodyMessage {
    pub member: String,
    pub sender: String,
    /// Lengths of every `ay` array in the body, in capture order.
    pub array_lengths: Vec<usize>,
    /// Password-method verdict: every Secret in the call had a 16-byte IV
    /// array and a non-empty 16-multiple ciphertext array.
    pub encrypted_secrets: bool,
    /// OpenSession verdict: the body carried the encrypted-session
    /// algorithm string.
    pub dh_algorithm: bool,
}

/// Final facts from the streaming body reader thread.
pub struct BodyScanOutcome {
    pub messages: Vec<CapturedBodyMessage>,
    /// Leak descriptions naming the member, field kind, and the generated
    /// secret's proof name — never the bytes.
    pub leaks: Vec<String>,
    /// Fail-closed parser failures; any entry fails the proof.
    pub failures: Vec<String>,
}

/// Incremental one-line-at-a-time scanner for the body monitor's stdout,
/// pinned against the installed busctl 261 monitor rendering captured under
/// the private broker (`.test-agent/session-monitor-probe/`):
///
/// ```text
/// ‣ Type=method_call  Endian=l  Flags=4  Version=1  Cookie=2  Timestamp="..."
///   Sender=:1.7  Destination=...  Interface=...  Member=UnlockWithMasterPassword
///   UniqueName=:1.7
///   MESSAGE "o(oayays)" {
///           OBJECT_PATH "/org/freedesktop/secrets/collection/x";
///           STRUCT "oayays" {
///                   OBJECT_PATH "/org/freedesktop/secrets/session/1";
///                   ARRAY "y" {
///                           BYTE 65;
///                   };
///                   ARRAY "y" {
///                           BYTE 68;
///                           BYTE 69;
///                   };
///                   STRING "text/plain";
///           };
///   };
/// ```
///
/// An empty `ay` renders as an `ARRAY "y" {` line with no `BYTE` lines (a
/// plain-session secret's empty parameters), so run lengths distinguish
/// encrypted from plain secrets. Each line is scanned against every
/// generated secret (literal and hex) before it is dropped, and every
/// reconstructed `ay` run is scanned before it is dropped: decoded bodies
/// transit the pipe, one line buffer, and one zeroized run buffer only, and
/// are never accumulated or written to disk.
pub struct BodyScanner {
    mode: BodyMode,
    secrets: Vec<(&'static str, Zeroizing<Vec<u8>>)>,
    current: Option<CapturedBodyMessage>,
    current_array: Option<Zeroizing<Vec<u8>>>,
    pub messages: Vec<CapturedBodyMessage>,
    pub leaks: Vec<String>,
    pub failures: Vec<String>,
}

impl BodyScanner {
    pub fn new(mode: BodyMode, secrets: Vec<(&'static str, Zeroizing<Vec<u8>>)>) -> Self {
        Self {
            mode,
            secrets,
            current: None,
            current_array: None,
            messages: Vec::new(),
            leaks: Vec::new(),
            failures: Vec::new(),
        }
    }

    /// Examine one raw stdout line, record facts, and drop its content.
    /// Failures and leaks are sticky and merely accumulate; the proof fails
    /// closed on them at finish.
    pub fn absorb_line(&mut self, line: &str) {
        for (name, secret) in &self.secrets {
            if common::contains(line.as_bytes(), secret) {
                self.leaks.push(format!(
                    "field=raw-line member={} secret={name}",
                    self.member()
                ));
            } else if common::contains_encoded(line.as_bytes(), secret) {
                self.leaks.push(format!(
                    "field=raw-line-hex member={} secret={name}",
                    self.member()
                ));
            }
        }

        let mut tokens = line.split_whitespace();
        match tokens.next() {
            Some(token) if token.starts_with("Sender=") => self.absorb_header_line(line),
            Some("ARRAY") if tokens.next().is_some_and(|token| token == "\"y\"") => {
                self.open_array();
            }
            Some("BYTE") => {
                let value = tokens
                    .next()
                    .and_then(|token| token.strip_suffix(';'))
                    .and_then(|digits| digits.parse::<u8>().ok());
                match (value, self.current_array.as_mut()) {
                    (Some(byte), Some(run)) => run.push(byte),
                    (Some(_), None) => self
                        .failures
                        .push(format!("BYTE outside an ARRAY \"y\" block: {line:?}")),
                    (None, _) => self.failures.push(format!("malformed BYTE line: {line:?}")),
                }
            }
            _ => self.absorb_other_line(line),
        }
    }

    /// The target header line: it must carry both the `Sender` and `Member`
    /// tokens, and the sender must be a unique bus name, or the output
    /// cannot be attributed and the proof fails closed.
    fn absorb_header_line(&mut self, line: &str) {
        let mut sender: Option<&str> = None;
        let mut member: Option<&str> = None;
        for token in line.split_whitespace() {
            if let Some(value) = token.strip_prefix("Sender=") {
                if sender.is_some() {
                    self.failures.push(format!(
                        "header line carries more than one Sender token: {line:?}"
                    ));
                    return;
                }
                sender = Some(value);
            } else if let Some(value) = token.strip_prefix("Member=") {
                member = Some(value);
            }
        }
        let (Some(sender), Some(member)) = (sender, member) else {
            self.failures.push(format!(
                "header-shaped line lacks Sender or Member; the installed busctl \
                 shape cannot be attributed: {line:?}"
            ));
            return;
        };
        if !is_unique_bus_name(sender) {
            self.failures.push(format!(
                "target header Sender value is not a unique bus name: {sender:?}"
            ));
            return;
        }
        if matches!(self.mode, BodyMode::OpenSessions) && member != "OpenSession" {
            self.failures.push(format!(
                "OpenSession monitor captured unexpected member {member:?}"
            ));
            return;
        }
        self.finalize_message();
        self.current = Some(CapturedBodyMessage {
            member: member.to_owned(),
            sender: sender.to_owned(),
            array_lengths: Vec::new(),
            encrypted_secrets: false,
            dh_algorithm: false,
        });
    }

    /// Lines that are not headers, array opens, or BYTE dumps: the algorithm
    /// string is a fact for the OpenSession verdict; a Member-bearing line
    /// without a Sender is an unattributable header shape and fails closed;
    /// everything else is ignored and dropped.
    fn absorb_other_line(&mut self, line: &str) {
        let mut member_token = false;
        for token in line.split_whitespace() {
            if token.starts_with("Member=") {
                member_token = true;
            }
        }
        if member_token {
            self.failures.push(format!(
                "header-shaped line without a Sender token; the call cannot \
                 be attributed: {line:?}"
            ));
            return;
        }
        if matches!(self.mode, BodyMode::OpenSessions) {
            let trimmed = line.trim();
            // The pinned rendering of the encrypted algorithm line drives
            // the verdict, so the scanner cannot drift from the installed
            // busctl shape.
            if trimmed == DH_ALGORITHM_LINE {
                if let Some(message) = &mut self.current {
                    message.dh_algorithm = true;
                }
                return;
            }
            if let Some(rest) = trimmed.strip_prefix("STRING \"") {
                let Some(name) = rest.strip_suffix("\";") else {
                    return;
                };
                if let Some(message) = &mut self.current {
                    message.dh_algorithm |= name == session::ALGORITHM;
                    if name == "plain" {
                        self.failures.push(
                            "plain-session OpenSession negotiation captured; the product \
                             must never negotiate plain"
                                .to_owned(),
                        );
                    }
                }
            }
        }
    }

    fn member(&self) -> &str {
        self.current
            .as_ref()
            .map(|message| message.member.as_str())
            .unwrap_or("<no-message>")
    }

    fn open_array(&mut self) {
        self.close_array();
        if self.current.is_none() {
            self.failures
                .push("ARRAY \"y\" block before any captured header line".to_owned());
            return;
        }
        self.current_array = Some(Zeroizing::new(Vec::new()));
    }

    fn close_array(&mut self) {
        if let Some(run) = self.current_array.take() {
            // The core absence check: a password traveling in the clear
            // inside an `ay` body renders as one `BYTE <decimal>;` line per
            // element, so only the reconstructed run can contain it. The
            // run is zeroized on drop; only the leak description (member
            // and proof-secret name) is retained.
            for (name, secret) in &self.secrets {
                if common::contains(run.as_slice(), secret) {
                    self.leaks.push(format!(
                        "field=ay-run member={} secret={name}",
                        self.member()
                    ));
                }
            }
            if let Some(message) = &mut self.current {
                message.array_lengths.push(run.len());
            }
        }
    }

    /// Evaluate the completed message's verdicts and retain only facts.
    fn finalize_message(&mut self) {
        self.close_array();
        let Some(mut message) = self.current.take() else {
            return;
        };
        match self.mode {
            BodyMode::PasswordMethods | BodyMode::CreateItems => {
                match encrypted_secret_shape(&message.member, &message.array_lengths) {
                    Ok(shape) => message.encrypted_secrets = shape,
                    Err(reason) => self.failures.push(reason),
                }
            }
            BodyMode::OpenSessions => {
                if let Err(reason) = open_session_shape(&message.array_lengths) {
                    self.failures.push(reason);
                }
            }
        }
        self.messages.push(message);
    }

    /// The retained facts, consuming the scanner and finalizing any
    /// in-flight message.
    pub fn into_outcome(mut self) -> BodyScanOutcome {
        self.finalize_message();
        BodyScanOutcome {
            messages: self.messages,
            leaks: self.leaks,
            failures: self.failures,
        }
    }
}

/// Whether every Secret in one captured password-method call traveled in
/// the encrypted shape: per member arity, each Secret's `parameters` array
/// is exactly the 16-byte IV and its `value` array is a non-empty 16
/// multiple (PKCS#7 ciphertext). A plain-session secret (empty parameters)
/// or an absent body therefore fails instead of passing vacuously.
fn encrypted_secret_shape(member: &str, array_lengths: &[usize]) -> Result<bool, String> {
    let one_secret = |pair: &[usize]| -> bool {
        pair.len() == 2 && pair[0] == 16 && pair[1] >= 16 && pair[1].is_multiple_of(16)
    };
    let shape = match member {
        "UnlockWithMasterPassword" => one_secret(array_lengths),
        "ChangeWithMasterPassword" => {
            array_lengths.len() == 4
                && one_secret(&array_lengths[..2])
                && one_secret(&array_lengths[2..])
        }
        "CreateWithMasterPassword" => {
            // The properties dictionary precedes the master Secret; only the
            // trailing pair is the Secret.
            array_lengths.len() >= 2 && one_secret(&array_lengths[array_lengths.len() - 2..])
        }
        // The a{sv} properties render as strings; the Secret's IV and
        // ciphertext arrays are the only `ay` bodies, so the trailing pair
        // is the encrypted Secret.
        "CreateItem" => {
            array_lengths.len() >= 2 && one_secret(&array_lengths[array_lengths.len() - 2..])
        }
        other => {
            return Err(format!(
                "password-interface monitor captured unexpected member {other:?}"
            ));
        }
    };
    Ok(shape)
}

/// Whether one captured OpenSession call carried a plausible DH public key:
/// at least one `ay` array of 1..=128 bytes.
fn open_session_shape(array_lengths: &[usize]) -> Result<bool, String> {
    Ok(array_lengths
        .iter()
        .any(|length| (1..=128).contains(length)))
}

/// Spawn the owned reader thread that drains the body monitor's piped
/// stdout. One line buffer is reused and one zeroized run buffer exists at
/// a time; each is scanned and dropped before the next, so no accumulation
/// of raw stdout — in a String, Vec, or file — ever exists.
fn spawn_body_reader(
    stdout: ChildStdout,
    mode: BodyMode,
    secrets: Vec<(&'static str, Zeroizing<Vec<u8>>)>,
) -> JoinHandle<BodyScanOutcome> {
    thread::Builder::new()
        .name("body-monitor-scanner".to_owned())
        .spawn(move || {
            let mut scanner = BodyScanner::new(mode, secrets);
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => scanner.absorb_line(&line),
                    Err(error) => {
                        let mut outcome = scanner.into_outcome();
                        outcome
                            .failures
                            .push(format!("reading body monitor stdout failed: {error}"));
                        return outcome;
                    }
                }
            }
            scanner.into_outcome()
        })
        .unwrap_or_else(|error| panic!("spawn the body monitor reader thread: {error}"))
}

/// Match-filtered streaming bus monitor that verdicts message *bodies* for
/// the encrypted-session proofs.
///
/// Unlike [`MethodMonitor`], which retains only header-derived facts, this
/// monitor reconstructs each captured body's `ay` arrays in memory — through
/// a pipe, one line and one zeroized run at a time — to prove two things at
/// once:
///
/// - absence: no generated password appears in any password-method body,
///   neither as literal or hex-encoded line bytes (string fields) nor inside
///   a decoded `ay` run;
/// - presence: every captured password-method call carries well-formed
///   encrypted Secrets (16-byte IV, non-empty 16-multiple ciphertext), and
///   every captured OpenSession negotiated the encrypted algorithm, so a
///   plain secret or negotiation fails the proof instead of passing
///   vacuously from a blind monitor.
///
/// Nothing body-shaped is ever written to disk. Finish retains only the
/// header-, length-, and verdict-derived summary.
pub struct BodyMonitor {
    child: Child,
    ready_path: PathBuf,
    summary_path: PathBuf,
    /// Owned streaming reader; Finish and Drop kill and reap the child
    /// first, so joining always observes the pipe's end-of-file and the
    /// thread never outlives the monitor (including through a panic
    /// unwind).
    reader: Option<JoinHandle<BodyScanOutcome>>,
    mode: BodyMode,
    stem: &'static str,
}

impl BodyMonitor {
    /// Monitor every member of GNOME's private password interface, scanning
    /// bodies against the generated proof secrets.
    pub fn password_methods(address: &str, root: &Path, secrets: &ProofSecrets) -> Self {
        Self::start(
            BodyMode::PasswordMethods,
            PASSWORD_INTERFACE_MATCH,
            "password-body-monitor",
            address,
            root,
            secrets.named().to_vec(),
        )
    }

    /// Monitor Secret Service OpenSession negotiations. Bodies carry the
    /// algorithm string and public keys only, but the same streaming and
    /// scanning discipline applies.
    pub fn open_sessions(address: &str, root: &Path, secrets: &ProofSecrets) -> Self {
        Self::start(
            BodyMode::OpenSessions,
            OPEN_SESSION_MATCH,
            "open-session-monitor",
            address,
            root,
            secrets.named().to_vec(),
        )
    }

    pub fn create_items(address: &str, root: &Path, secrets: &ProofSecrets) -> Self {
        Self::start(
            BodyMode::CreateItems,
            CREATE_ITEM_MATCH,
            "create-item-monitor",
            address,
            root,
            secrets.named().to_vec(),
        )
    }

    fn start(
        mode: BodyMode,
        match_rule: &str,
        stem: &'static str,
        address: &str,
        root: &Path,
        secrets: Vec<(&'static str, &[u8])>,
    ) -> Self {
        let ready_path = root.join(format!("{stem}.ready.log"));
        let summary_path = root.join(format!("{stem}.txt"));
        let ready =
            File::create(&ready_path).unwrap_or_else(|error| panic!("create {stem} log: {error}"));
        let mut command = busctl_monitor_command(address, match_rule);
        command.stderr(ready);
        let mut child = command
            .stdout(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {BUSCTL} monitor: {error}"));
        let stdout = child
            .stdout
            .take()
            .expect("piped monitor stdout must be takeable right after spawn");
        let owned_secrets: Vec<(&'static str, Zeroizing<Vec<u8>>)> = secrets
            .iter()
            .map(|(name, secret)| (*name, Zeroizing::new(secret.to_vec())))
            .collect();
        let reader = Some(spawn_body_reader(stdout, mode, owned_secrets));
        let monitor = Self {
            child,
            ready_path,
            summary_path,
            reader,
            mode,
            stem,
        };
        wait_for_monitor_ready(&monitor.ready_path, stem);
        monitor
    }

    /// Stop the monitor, join the reader, fail closed on any parser failure
    /// or leaked secret, retain the redacted fact summary, and delete the
    /// banner-only readiness log. There is no raw log to delete because none
    /// was ever created.
    pub fn finish(mut self, secrets: &ProofSecrets) -> BodyMonitorSummary {
        let handle = self.reader.take().expect("body monitor owns its reader");
        stop_monitor_child(&mut self.child, self.stem);
        let outcome = handle
            .join()
            .unwrap_or_else(|_| panic!("the {} reader thread panicked", self.stem));

        let ready = fs::read_to_string(&self.ready_path)
            .unwrap_or_else(|error| panic!("read {} readiness log: {error}", self.stem));
        assert!(
            ready.contains(MONITOR_BANNER),
            "{} monitor log lost its readiness banner",
            self.stem
        );
        for (name, secret) in secrets.named() {
            common::assert_secret_absent(
                ready.as_bytes(),
                secret,
                &format!(
                    "the {} monitor readiness log (generated {name} password)",
                    self.stem
                ),
            );
        }

        if !outcome.failures.is_empty() {
            panic!(
                "the {} body monitor failed closed: {}",
                self.stem,
                outcome.failures.join("; ")
            );
        }
        if !outcome.leaks.is_empty() {
            panic!(
                "the {} body monitor observed generated passwords in captured bodies: {}",
                self.stem,
                outcome.leaks.join("; ")
            );
        }

        let mut summary = format!(
            "tool={BUSCTL} monitor\nmatch-mode={:?}\nmessages={}\n",
            self.mode,
            outcome.messages.len()
        );
        for message in &outcome.messages {
            summary.push_str(&format!(
                "message member={} sender={} arrays={:?} encrypted_secrets={} dh_algorithm={}\n",
                message.member,
                message.sender,
                message.array_lengths,
                message.encrypted_secrets,
                message.dh_algorithm
            ));
        }
        summary.push_str("leaks=0\n");
        fs::write(&self.summary_path, summary)
            .unwrap_or_else(|error| panic!("write redacted {} summary: {error}", self.stem));
        fs::remove_file(&self.ready_path)
            .unwrap_or_else(|error| panic!("delete {} readiness log: {error}", self.stem));

        BodyMonitorSummary {
            messages: outcome.messages,
        }
    }
}

impl Drop for BodyMonitor {
    fn drop(&mut self) {
        // Same never-leak semantics as MethodMonitor: kill and reap the
        // child (closing the pipe), then join the reader, which at worst
        // drains and drops the remaining body lines. No raw output ever
        // exists on disk; failure paths remove the banner-only readiness
        // log.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.reader.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&self.ready_path);
    }
}

/// Retained facts from one body monitor run.
pub struct BodyMonitorSummary {
    pub messages: Vec<CapturedBodyMessage>,
}

impl BodyMonitorSummary {
    /// Captured calls of one member, in arrival order.
    pub fn messages_of(&self, member: &str) -> Vec<&CapturedBodyMessage> {
        self.messages
            .iter()
            .filter(|message| message.member == member)
            .collect()
    }

    /// Whether every captured message of one member passed the mode's
    /// encrypted verdict.
    pub fn all_encrypted(&self, member: &str) -> bool {
        let messages = self.messages_of(member);
        !messages.is_empty() && messages.iter().all(|message| message.encrypted_secrets)
    }
}

/// Generated, zeroized-on-drop proof secrets and the non-secret run tag used
/// to make the second fixture label distinguishable per run. The `login`
/// collection deliberately carries no run tag: its stable ID must be exactly
/// `login`.
pub struct ProofSecrets {
    pub run_tag: String,
    pub login: Zeroizing<Vec<u8>>,
    pub second: Zeroizing<Vec<u8>>,
    pub wrong: Zeroizing<Vec<u8>>,
    pub login_two: Zeroizing<Vec<u8>>,
    /// The rotated password for the second collection: `second` becomes
    /// invalid and `second_two` unlocks after a proven `gmellon change`.
    pub second_two: Zeroizing<Vec<u8>>,
    /// The passphrase of the proof's generated SSH key; it must appear in
    /// no stream, artifact, or bus body in the clear.
    pub key_pass: Zeroizing<Vec<u8>>,
    /// The rotation passphrase: the proof's SSH key is regenerated at the
    /// same path under it, making the stored `key_pass` item stale for the
    /// `ssh-verify` proof. Held under the same redaction discipline as
    /// every other generated secret.
    pub key_pass_two: Zeroizing<Vec<u8>>,
}

impl ProofSecrets {
    pub fn generate() -> Self {
        let login = common::random_password();
        let second = common::distinct_password(&[&login]);
        let login_two = common::distinct_password(&[&login, &second]);
        let second_two = common::distinct_password(&[&login, &second, &login_two]);
        let wrong = common::distinct_password(&[&login, &second, &login_two, &second_two]);
        let key_pass =
            common::distinct_password(&[&login, &second, &login_two, &second_two, &wrong]);
        let key_pass_two = common::distinct_password(&[
            &login,
            &second,
            &login_two,
            &second_two,
            &wrong,
            &key_pass,
        ]);

        // Not a secret: a printable tag identifying this run's second fixture.
        let mut random = [0_u8; 4];
        common::read_urandom(&mut random);
        let run_tag = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        Self {
            run_tag,
            login,
            second,
            wrong,
            login_two,
            second_two,
            key_pass,
            key_pass_two,
        }
    }

    pub fn all_slices(&self) -> Vec<&[u8]> {
        vec![
            self.login.as_slice(),
            self.second.as_slice(),
            self.wrong.as_slice(),
            self.login_two.as_slice(),
            self.second_two.as_slice(),
            self.key_pass.as_slice(),
            self.key_pass_two.as_slice(),
        ]
    }

    pub fn named(&self) -> [(&'static str, &[u8]); 7] {
        [
            ("login", self.login.as_slice()),
            ("second", self.second.as_slice()),
            ("wrong", self.wrong.as_slice()),
            ("login_two", self.login_two.as_slice()),
            ("second_two", self.second_two.as_slice()),
            ("key_pass", self.key_pass.as_slice()),
            ("key_pass_two", self.key_pass_two.as_slice()),
        ]
    }
}

/// The stable ID the installed daemon derives from a token-collection label:
/// the label with each `-` escaped as `_2d` (observed `gmellon_2dproof_2dalpha`
/// for `gmellon-proof-alpha`). `login` contains no escapable characters, so
/// its exact ID is `login` — the parent acceptance's literal requirement.
pub fn expected_collection_id(label: &str) -> String {
    label.replace('-', "_2d")
}

/// Outer-mode prerequisite preflight shared by every private-broker Rust
/// proof. Mirrors `broker.py`'s host-dependency probe plus the monitor tools.
pub fn require_outer_prerequisites() {
    #[cfg(not(target_os = "linux"))]
    panic!("private-broker proofs require Linux Unix-socket peer credentials");

    let broker = common::repository_root().join("dev/harness/broker.py");
    let metadata = fs::metadata(&broker).unwrap_or_else(|error| {
        panic!(
            "private-broker proof requires executable {}: {error}",
            broker.display()
        )
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            metadata.permissions().mode() & 0o111 != 0,
            "private-broker proof requires executable {}; restore its executable mode",
            broker.display()
        );
    }

    common::require_command("python3", ["--version"], "install Python 3");
    let daemon = ["/usr/bin/gnome-keyring-daemon", "/bin/gnome-keyring-daemon"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or_else(|| {
            panic!("private-broker proof requires gnome-keyring-daemon in /usr/bin or /bin")
        });
    common::require_command(
        daemon,
        ["--version"],
        "install a runnable system GNOME Keyring daemon package",
    );
    for tool in ["systemd-socket-activate", "dbus-broker-launch", "gdbus"] {
        require_fixed_tool(tool, "install the private-broker host dependencies");
    }
    common::require_command(
        BUSCTL,
        ["--version"],
        "install systemd's busctl for the lock-call monitor",
    );
    assert!(
        Path::new(STDBUF).is_file(),
        "private-broker proof requires {STDBUF} for line-buffered monitor output"
    );

    for socket in ["/run/systemd/journal/socket", "/run/dbus/system_bus_socket"] {
        let path = Path::new(socket);
        let metadata = fs::metadata(path)
            .unwrap_or_else(|error| panic!("private-broker proof requires {socket}: {error}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            assert!(
                metadata.file_type().is_socket(),
                "private-broker host dependency is not a socket: {socket}"
            );
        }
    }
    assert!(
        Path::new("/run/systemd/system").is_dir(),
        "private-broker proof requires a running host systemd runtime"
    );
    File::open("/dev/urandom").unwrap_or_else(|error| {
        panic!("private-broker proof requires readable /dev/urandom: {error}")
    });
}

pub fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("the harness did not export {name}"))
}

/// Mirror broker.py's host-dependency probe: presence and executability in
/// the fixed /usr/bin:/bin set, without executing the tool (gdbus and the
/// launcher have no safe --version probe).
fn require_fixed_tool(name: &str, remedy: &str) {
    let found = ["/usr/bin", "/bin"].into_iter().any(|directory| {
        let path = Path::new(directory).join(name);
        fs::metadata(path)
            .map(|metadata| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    metadata.is_file()
                }
            })
            .unwrap_or(false)
    });
    assert!(
        found,
        "private-broker proof requires {name} in /usr/bin or /bin; {remedy}"
    );
}

/// Outer-mode runner: re-run exactly `test_name` inside `broker.py`, honoring
/// the caller's `--keep-success` opt-in, and require a clean harness exit.
pub fn run_broker_isolated(test_name: &str, context: &str) {
    require_outer_prerequisites();
    let broker = common::repository_root().join("dev/harness/broker.py");
    let current_test = env::current_exe()
        .unwrap_or_else(|error| panic!("{context} could not locate its test executable: {error}"));
    let mut command = Command::new(&broker);
    if env::var_os(common::KEEP_SUCCESS_MARKER).as_deref() == Some(OsStr::new("1")) {
        command.arg("--keep-success");
    }
    let output = command
        .arg("--")
        .arg(current_test)
        .args(["--ignored", "--exact", test_name, "--nocapture"])
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "explicit {context} run could not execute {}: {error}; ensure python3 is installed and the broker script is executable",
                broker.display()
            )
        });
    common::relay(&output);
    assert!(
        output.status.success(),
        "executable {context} failed with {}; diagnostics are printed above and any allocated failure scratch was retained",
        output.status
    );
}
