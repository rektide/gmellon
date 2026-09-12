//! Opt-in proof of the committed Rust Secret Service client against an
//! isolated private dbus-broker daemon.
//!
//! The ignored outer test invokes the executable broker harness contract,
//! which starts a private bus, manually launches `gnome-keyring-daemon`, and
//! re-runs only this test inside the isolated command environment. The inner
//! proof is maintained Rust: a zbus test fixture performs the *only* permitted
//! mutation setup — creating disposable collections through GNOME's private
//! `CreateWithMasterPassword` (one labeled exactly `login`, satisfying the
//! parent acceptance's literal login-plus-second requirement, plus a second
//! distinguishable collection) and returning them to the locked state with the
//! standard `Lock` method — and every observed behavior is asserted through
//! the public `gmellon::secret_service::BlockingClient`.
//!
//! Ordinary `cargo test` and `cargo nextest run` visibly skip this proof. The
//! maintained explicit entry point is `dev/harness/check rust-broker`.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use gmellon::secret_service::{BlockingClient, CollectionId, Error, UnlockOutcome};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};
use zeroize::Zeroizing;

use std::collections::HashMap;

const ACTIVE_MARKER: &str = "GMELL_HARNESS_ACTIVE";
const BROKER_MODE: &str = "private-broker";
const KEEP_SUCCESS_MARKER: &str = "GMELL_HARNESS_KEEP_SUCCESS";
const PROOF_TEST: &str = "private_broker_collections_client_proof";
const APPROVED_TEMP_ROOT: &str = "/home/rektide/tmp-opencode";
const BUSCTL: &str = "/usr/bin/busctl";
const STDBUF: &str = "/usr/bin/stdbuf";
/// One persistent fixture collection is labeled exactly `login`, because the
/// parent acceptance requires listing `login` plus a second collection by
/// stable ID. On the observed daemon 48.0 the token collection persists as
/// `login.keyring` and its D-Bus object-path ID is exactly `login` (the label
/// needs no escaping), so the proof asserts the exact ID rather than a
/// login-shaped approximation.
const LOGIN_LABEL: &str = "login";
/// The monitor sees only this traffic: standard Service.Lock method calls.
/// Passwords travel exclusively in private-interface method bodies, which the
/// match rule excludes, so retained monitor output cannot carry secret bytes.
const LOCK_MATCH: &str = "interface='org.freedesktop.Secret.Service',member='Lock'";
const MONITOR_BANNER: &str = "Monitoring bus message stream.";

#[test]
#[ignore = "requires explicit private-broker harness run; see doc/harness/README.md"]
fn private_broker_collections_client_proof() {
    if env::var_os(ACTIVE_MARKER).is_some() {
        #[cfg(not(target_os = "linux"))]
        panic!("private-broker collection proof requires Linux Unix-socket peer credentials");

        let secrets = ProofSecrets::generate();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_proof(&secrets);
        }));
        finish_case("private_broker_collections", &secrets.all_slices(), outcome);
        return;
    }

    run_isolated();
}

/// Everything the inner proof asserts, in one command inside `broker.py`.
fn run_proof(secrets: &ProofSecrets) {
    let bus = validated_harness_environment();

    // The lock-call monitor must be armed before any fixture traffic so the
    // count is exhaustive; readiness is proven by its banner, not a sleep.
    let monitor = LockMonitor::start(&bus.address, &bus.root);

    // Fixture connection: separate D-Bus unique name from the product client,
    // so every observed Lock call can be attributed to a sender.
    let mut fixture = Fixture::connect(&bus.address).expect("fixture plain session");
    let fixture_sender = fixture.unique_name();

    let label_second = format!("gmellon-proof-second-{}", secrets.run_tag);

    // Fixture setup: persistent disposable collections with distinct
    // passwords. This is the only code permitted to create or lock. One
    // collection is labeled exactly `login`; the second carries a per-run tag
    // so its escaped-label ID is distinguishable from any other run's.
    let login_path = fixture
        .create(LOGIN_LABEL, &secrets.login)
        .expect("fixture CreateWithMasterPassword login");
    let second_path = fixture
        .create(&label_second, &secrets.second)
        .expect("fixture CreateWithMasterPassword second");
    assert_ne!(login_path, second_path);

    // One product client, as a CLI process would own it. It resolves its own
    // connection from the exported DBUS_SESSION_BUS_ADDRESS.
    let client = BlockingClient::session().expect("BlockingClient::session");

    // Discovery is by label only to learn the stable IDs; every later
    // operation addresses the returned CollectionId values, never a hardcoded
    // object path or label.
    let login_id = collection_id_by_label(&client, LOGIN_LABEL);
    let second_id = collection_id_by_label(&client, &label_second);
    assert_ne!(login_id, second_id);

    // The parent acceptance literally requires the `login` collection: the
    // discovered stable ID must be exactly `login` (observed daemon 48.0
    // behavior — the label needs no escaping), not a login-shaped run-tagged
    // approximation.
    assert_eq!(
        login_id.as_str(),
        LOGIN_LABEL,
        "the collection labeled {LOGIN_LABEL} must expose the exact stable ID `{LOGIN_LABEL}`"
    );

    // A just-created collection holds its master-password credential, so it
    // starts unlocked; the daemon persists token collections immediately.
    assert_lock_state(&client, &login_id, false, "login after fixture create");
    assert_lock_state(&client, &second_id, false, "second after fixture create");
    assert_persisted(&bus, LOGIN_LABEL, &login_id);
    assert_persisted(&bus, &label_second, &second_id);

    // Fixture-only locking: standard Lock, counted and attributed.
    fixture.lock(&login_path).expect("fixture Lock login");
    fixture.lock(&second_path).expect("fixture Lock second");
    assert_lock_state(&client, &login_id, true, "login after fixture lock");
    assert_lock_state(&client, &second_id, true, "second after fixture lock");

    // Wrong password while genuinely locked: denied, and the denial must not
    // change lock state.
    assert!(
        matches!(
            client.unlock(&login_id, &secrets.wrong),
            Err(Error::PasswordDenied)
        ),
        "wrong password while login locked must be PasswordDenied"
    );
    assert_lock_state(&client, &login_id, true, "login after denied attempt");

    // Cross password: login's password is wrong for second.
    assert!(
        matches!(
            client.unlock(&second_id, &secrets.login),
            Err(Error::PasswordDenied)
        ),
        "login's password on locked second must be PasswordDenied"
    );

    // Each correct password unlocks only its own collection.
    assert_eq!(
        client
            .unlock(&login_id, &secrets.login)
            .expect("unlock login with its password"),
        UnlockOutcome::Unlocked
    );
    assert_lock_state(&client, &login_id, false, "login after unlock");
    assert_lock_state(
        &client,
        &second_id,
        true,
        "second untouched by login unlock",
    );

    assert_eq!(
        client
            .unlock(&second_id, &secrets.second)
            .expect("unlock second with its password"),
        UnlockOutcome::Unlocked
    );
    assert_lock_state(
        &client,
        &login_id,
        false,
        "login untouched by second unlock",
    );

    // Already-unlocked: the committed client returns AlreadyUnlocked from its
    // lock-state guard in `blocking.rs` before any password method is sent,
    // so no password method is invoked on this path (established by the
    // committed early return plus this outcome — the monitor's match rule is
    // deliberately password-excluding and proves only the no-Lock claim).
    // Upstream's private method would short-circuit anyway, which is exactly
    // why the client's guard, not the daemon, carries the no-verification
    // behavior. Both a wrong and the correct password return AlreadyUnlocked
    // and the collection stays unlocked.
    assert_eq!(
        client
            .unlock(&login_id, &secrets.wrong)
            .expect("already-unlocked login with wrong password"),
        UnlockOutcome::AlreadyUnlocked
    );
    assert_lock_state(
        &client,
        &login_id,
        false,
        "login after already-unlocked path",
    );
    assert_eq!(
        client
            .unlock(&login_id, &secrets.login)
            .expect("already-unlocked login with its password"),
        UnlockOutcome::AlreadyUnlocked
    );

    // Missing collection: discovery reports it before any password method.
    let missing = CollectionId::new("gmellon-proof-missing").expect("nonempty id");
    assert!(
        matches!(
            client.unlock(&missing, &secrets.login),
            Err(Error::CollectionNotFound { .. })
        ),
        "unlock of a missing collection must be CollectionNotFound"
    );
    assert!(
        matches!(
            client.change_password(&missing, &secrets.login, &secrets.login_two),
            Err(Error::CollectionNotFound { .. })
        ),
        "change_password of a missing collection must be CollectionNotFound"
    );

    // Password change on the unlocked login, then fixture-only relock: the
    // former password is denied while locked, the new one unlocks.
    client
        .change_password(&login_id, &secrets.login, &secrets.login_two)
        .expect("change_password login L to L2");
    assert_lock_state(&client, &login_id, false, "login after change_password");

    fixture
        .lock(&login_path)
        .expect("fixture Lock login after change");
    assert_lock_state(&client, &login_id, true, "login after fixture relock");

    assert!(
        matches!(
            client.unlock(&login_id, &secrets.login),
            Err(Error::PasswordDenied)
        ),
        "former password while login relocked must be PasswordDenied"
    );
    assert_eq!(
        client
            .unlock(&login_id, &secrets.login_two)
            .expect("unlock login with the changed password"),
        UnlockOutcome::Unlocked
    );

    // Wire evidence: ordinary product unlock/change never emitted a standard
    // Lock method call. Every observed Lock belongs to the fixture sender,
    // and the total equals only the fixture's deliberate calls. The count is
    // positive, so a silently broken monitor cannot pass vacuously.
    let observed = monitor.finish(&fixture_sender, fixture.lock_calls(), secrets);
    assert!(
        observed.lock_calls >= 1,
        "the monitor observed no Lock traffic although the fixture locked collections"
    );
    assert_eq!(
        observed.lock_calls,
        fixture.lock_calls(),
        "observed Service.Lock calls must equal the fixture's deliberate calls"
    );
    assert!(
        observed.senders_match_fixture,
        "every observed Service.Lock call must come from the fixture connection"
    );
}

/// Harness environment contract: the proof runs inside `broker.py`, never on
/// a host bus.
struct BusEnvironment {
    address: String,
    root: PathBuf,
}

fn validated_harness_environment() -> BusEnvironment {
    assert_eq!(
        env::var("GMELL_HARNESS_MODE").ok().as_deref(),
        Some(BROKER_MODE),
        "collection proof must run inside the private-broker harness"
    );

    let root = required_path("GMELL_HARNESS_ROOT");
    assert_beneath(&root, Path::new(APPROVED_TEMP_ROOT));
    let metadata = fs::metadata(&root).expect("harness root should exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    let socket = required_path("GMELL_HARNESS_BUS_SOCKET");
    assert_beneath(&socket, &root);
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
        assert_beneath(&required_path(name), &root);
    }

    BusEnvironment { address, root }
}

/// Disposable fixture: the only facility permitted to create collections and
/// to call the standard `Lock` method. It owns a separate D-Bus connection so
/// monitor evidence can attribute every Lock call to it alone. Product code
/// must never lock or relock a collection as part of ordinary unlock.
struct Fixture {
    connection: zbus::blocking::Connection,
    session_path: OwnedObjectPath,
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

impl Fixture {
    fn connect(address: &str) -> zbus::Result<Self> {
        let connection = zbus::blocking::connection::Builder::address(address)?.build()?;
        let service = FixtureServiceProxyBlocking::new(&connection)?;
        let input = Value::from("");
        let (_output, session_path) = service.open_session("plain", &input)?;
        Ok(Self {
            connection,
            session_path,
            lock_calls: 0,
        })
    }

    fn unique_name(&self) -> String {
        self.connection
            .unique_name()
            .expect("fixture connection owns a unique name")
            .to_string()
    }

    fn lock_calls(&self) -> usize {
        self.lock_calls
    }

    /// Test-fixture setup only: standard Lock on one disposable collection.
    fn lock(&mut self, collection: &OwnedObjectPath) -> zbus::Result<()> {
        let service = FixtureServiceProxyBlocking::new(&self.connection)?;
        let path: ObjectPath<'_> = collection.as_ref();
        let (locked, prompt) = service.lock(std::slice::from_ref(&path))?;
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
    /// dictionary against `org.freedesktop.Secret.Collection`.
    fn create(&self, label: &str, password: &[u8]) -> zbus::Result<OwnedObjectPath> {
        let internal = FixtureGnomeInternalProxyBlocking::new(&self.connection)?;
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert(
            "org.freedesktop.Secret.Collection.Label",
            Value::from(label),
        );
        let session: ObjectPath<'_> = self.session_path.as_ref();
        let empty_parameters: &[u8] = &[];
        internal.create_with_master_password(
            &properties,
            (&session, empty_parameters, password, "text/plain"),
        )
    }
}

/// Match-filtered bus monitor counting standard `Service.Lock` method calls.
///
/// The monitor connects only to the harness's private bus and its match rule
/// excludes every password-bearing private-interface message body, so its log
/// cannot contain secret bytes; the proof still scans it before deleting it.
struct LockMonitor {
    child: Child,
    log_path: PathBuf,
    ready_path: PathBuf,
}

struct MonitorSummary {
    lock_calls: usize,
    senders_match_fixture: bool,
}

impl LockMonitor {
    fn start(address: &str, root: &Path) -> Self {
        let log_path = root.join("lock-monitor.log");
        let ready_path = root.join("lock-monitor.ready.log");
        let output = File::create(&log_path).expect("create lock monitor log");
        // busctl prints its readiness banner on stderr and message traffic on
        // stdout, so the banner gets its own file and stdout stays parseable.
        let ready = File::create(&ready_path).expect("create lock monitor readiness log");
        let child = Command::new(STDBUF)
            .arg("-oL")
            .arg(BUSCTL)
            .arg(format!("--address={address}"))
            .arg("monitor")
            .arg(format!("--match={LOCK_MATCH}"))
            .stdin(Stdio::null())
            .stdout(output)
            .stderr(ready)
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {BUSCTL} monitor: {error}"));

        let monitor = Self {
            child,
            log_path,
            ready_path,
        };
        // BecomeMonitor applies only after the bus replies; the tool prints
        // its banner then, so waiting for the banner closes the startup race
        // without guessing a delay.
        let deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < deadline {
            if fs::read_to_string(&monitor.ready_path)
                .map(|log| log.contains(MONITOR_BANNER))
                .unwrap_or(false)
            {
                return monitor;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("lock monitor did not reach monitoring state before the deadline");
    }

    /// Stop the monitor, verify its log carries no secret bytes, extract the
    /// Lock-call evidence, retain a redacted summary, and delete the raw log.
    fn finish(
        mut self,
        fixture_sender: &str,
        fixture_calls: usize,
        secrets: &ProofSecrets,
    ) -> MonitorSummary {
        let bytes = self.shutdown_and_read();
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let ready = fs::read_to_string(&self.ready_path).expect("read lock monitor readiness log");
        assert!(
            ready.contains(MONITOR_BANNER),
            "lock monitor log lost its readiness banner"
        );

        for (name, secret) in secrets.named() {
            assert!(
                !contains(raw.as_bytes(), secret),
                "generated password {name} appeared in the raw monitor log"
            );
            assert!(
                !contains(ready.as_bytes(), secret),
                "generated password {name} appeared in the monitor readiness log"
            );
        }

        let senders: Vec<String> = raw
            .lines()
            .filter(|line| line.contains("Sender=") && line.contains("Member=Lock"))
            .filter_map(|line| {
                line.split_whitespace()
                    .find(|token| token.starts_with("Sender="))
            })
            .map(|token| token.trim_start_matches("Sender=").to_string())
            .collect();
        let senders_match_fixture = senders.iter().all(|sender| sender == fixture_sender);

        let summary = format!(
            "tool={BUSCTL} monitor\nmatch={LOCK_MATCH}\nfixture_sender={fixture_sender}\n\
             fixture_lock_calls={fixture_calls}\nobserved_lock_calls={}\n\
             senders_match_fixture={senders_match_fixture}\n",
            senders.len()
        );
        fs::write(self.log_path.with_file_name("lock-monitor.txt"), summary)
            .expect("write redacted lock monitor summary");
        fs::remove_file(&self.log_path).expect("delete raw lock monitor log");
        fs::remove_file(&self.ready_path).expect("delete monitor readiness log");

        MonitorSummary {
            lock_calls: senders.len(),
            senders_match_fixture,
        }
    }

    fn shutdown_and_read(&mut self) -> Vec<u8> {
        // Give the line-buffered monitor a moment to flush the last message,
        // then TERM; a monitor that ignores TERM within the bound is KILLed.
        thread::sleep(Duration::from_millis(200));
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Ok(None) => panic!("lock monitor did not exit after KILL"),
                Err(error) => panic!("lock monitor wait failed: {error}"),
            }
        }
        fs::read(&self.log_path).expect("read lock monitor log")
    }
}

impl Drop for LockMonitor {
    fn drop(&mut self) {
        // Failure path: never leak the process; the raw log stays for the
        // artifact scan, and the match rule kept password bodies out of it.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Generated, zeroized-on-drop proof secrets and the non-secret run tag used
/// to make the second fixture label distinguishable per run. The `login`
/// collection deliberately carries no run tag: its stable ID must be exactly
/// `login`.
struct ProofSecrets {
    run_tag: String,
    login: Zeroizing<Vec<u8>>,
    second: Zeroizing<Vec<u8>>,
    wrong: Zeroizing<Vec<u8>>,
    login_two: Zeroizing<Vec<u8>>,
}

impl ProofSecrets {
    fn generate() -> Self {
        let login = random_password();
        let second = distinct_password(&[&login]);
        let login_two = distinct_password(&[&login, &second]);
        let wrong = distinct_password(&[&login, &second, &login_two]);

        // Not a secret: a printable tag identifying this run's second fixture.
        let mut random = [0_u8; 4];
        read_urandom(&mut random);
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
        }
    }

    fn all_slices(&self) -> Vec<&[u8]> {
        vec![
            self.login.as_slice(),
            self.second.as_slice(),
            self.wrong.as_slice(),
            self.login_two.as_slice(),
        ]
    }

    fn named(&self) -> [(&'static str, &[u8]); 4] {
        [
            ("login", self.login.as_slice()),
            ("second", self.second.as_slice()),
            ("wrong", self.wrong.as_slice()),
            ("login_two", self.login_two.as_slice()),
        ]
    }
}

fn collection_id_by_label(client: &BlockingClient, label: &str) -> CollectionId {
    let collections = client.collections().expect("BlockingClient::collections");
    let found = collections
        .iter()
        .find(|collection| collection.label == label)
        .unwrap_or_else(|| panic!("collection labeled {label} was not listed"));
    assert_eq!(found.label, label);
    found.id.clone()
}

fn assert_lock_state(client: &BlockingClient, id: &CollectionId, locked: bool, stage: &str) {
    let collections = client
        .collections()
        .expect("list collections for lock state");
    let found = collections
        .iter()
        .find(|collection| &collection.id == id)
        .unwrap_or_else(|| panic!("collection {id} missing at stage {stage}"));
    assert_eq!(found.locked, locked, "unexpected lock state at {stage}");
}

/// Observed daemon-48.0 persistence contract for token collections, asserted
/// per fixture: the store file stem is the raw label, and the D-Bus ID is the
/// escaped-label form. The escaped form is asserted, not guessed: the exact
/// `login` ID for the untagged label, and the deterministic `-` to `_2d`
/// escaping for the tagged second label.
fn assert_persisted(bus: &BusEnvironment, label: &str, id: &CollectionId) {
    let keyrings = required_path("XDG_DATA_HOME").join("keyrings");
    let file = keyrings.join(format!("{label}.keyring"));
    assert!(
        file.is_file(),
        "token collection {id} was not persisted at {}",
        file.display()
    );
    assert_beneath(&file, &bus.root);
    let expected_id = expected_collection_id(label);
    assert_eq!(
        id.as_str(),
        expected_id,
        "collection ID for label {label} is not the observed escaped-label form"
    );
}

/// The stable ID the installed daemon derives from a token-collection label:
/// the label with each `-` escaped as `_2d` (observed `gmellon_2dproof_2dalpha`
/// for `gmellon-proof-alpha`). `login` contains no escapable characters, so
/// its exact ID is `login` — the parent acceptance's literal requirement.
fn expected_collection_id(label: &str) -> String {
    label.replace('-', "_2d")
}

// --- outer runner and shared helpers ---------------------------------------

fn run_isolated() {
    require_outer_prerequisites();
    let broker = repository_root().join("dev/harness/broker.py");
    let current_test = env::current_exe().unwrap_or_else(|error| {
        panic!("private-broker proof could not locate its test executable: {error}")
    });
    let mut command = Command::new(&broker);
    if env::var_os(KEEP_SUCCESS_MARKER).as_deref() == Some(OsStr::new("1")) {
        command.arg("--keep-success");
    }
    let output = command
        .arg("--")
        .arg(current_test)
        .args(["--ignored", "--exact", PROOF_TEST, "--nocapture"])
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "explicit private-broker run could not execute {}: {error}; ensure python3 is installed and the broker script is executable",
                broker.display()
            )
        });
    relay(&output);
    assert!(
        output.status.success(),
        "executable private-broker proof failed with {}; diagnostics are printed above and any allocated failure scratch was retained",
        output.status
    );
}

fn require_outer_prerequisites() {
    #[cfg(not(target_os = "linux"))]
    panic!("private-broker collection proof requires Linux Unix-socket peer credentials");

    let broker = repository_root().join("dev/harness/broker.py");
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

    require_command("python3", ["--version"], "install Python 3");
    let daemon = ["/usr/bin/gnome-keyring-daemon", "/bin/gnome-keyring-daemon"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or_else(|| {
            panic!("private-broker proof requires gnome-keyring-daemon in /usr/bin or /bin")
        });
    require_command(
        daemon,
        ["--version"],
        "install a runnable system GNOME Keyring daemon package",
    );
    for tool in ["systemd-socket-activate", "dbus-broker-launch", "gdbus"] {
        require_fixed_tool(tool, "install the private-broker host dependencies");
    }
    require_command(
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

fn require_command<I, S>(program: impl AsRef<OsStr>, arguments: I, remedy: &str)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let display = program.as_ref().to_string_lossy();
    let result = Command::new(program.as_ref()).args(arguments).output();
    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "private-broker prerequisite `{display}` failed with {}; {remedy}",
            output.status
        ),
        Err(error) => {
            panic!("private-broker prerequisite `{display}` is unavailable: {error}; {remedy}")
        }
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn relay(output: &Output) {
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
}

fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("broker harness did not export {name}"))
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("broker harness did not export {name}"))
}

fn assert_beneath(path: &Path, root: &Path) {
    assert!(
        path.starts_with(root),
        "harness path {} escaped expected root {}",
        path.display(),
        root.display()
    );
}

fn read_urandom(buffer: &mut [u8]) {
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(buffer))
        .expect("preflighted /dev/urandom should remain readable");
}

fn random_password() -> Zeroizing<Vec<u8>> {
    let mut random = [0_u8; 32];
    read_urandom(&mut random);
    Zeroizing::new(random.into_iter().map(|byte| byte % 94 + 33).collect())
}

fn distinct_password(others: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    loop {
        let candidate = random_password();
        if others.iter().all(|other| candidate.as_slice() != *other) {
            return candidate;
        }
    }
}

/// Record the redacted observation, then scan the retained harness artifacts
/// for every generated secret before reporting success (or re-raising an
/// earlier assertion failure). The scan covers exactly what exists beneath the
/// harness root at scan time: every regular file is read and checked, and any
/// symlink fails the proof instead of being skipped, so no unscanned path can
/// point outside the scratch root. `cleanup.json` is outside this scope by
/// construction: the supervisor writes it after the command exits, and it
/// records metadata only (command status, handled signal, per-child teardown),
/// never command data.
fn finish_case(path_name: &str, secrets: &[&[u8]], outcome: std::thread::Result<()>) {
    let root = required_path("GMELL_HARNESS_ROOT");
    let observation = root.join("rust-broker-proof.txt");
    let record = |scan: &str| {
        fs::write(
            &observation,
            format!(
                "path={path_name}\nclient=gmellon::secret_service::BlockingClient\n\
                 secret_values={}\nartifact_scan={scan}\n",
                secrets.len()
            ),
        )
        .expect("write redacted Rust proof evidence")
    };

    record("pending");
    scan_directory(&root, secrets);
    record("passed");

    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

fn scan_directory(directory: &Path, secrets: &[&[u8]]) {
    for entry in fs::read_dir(directory).expect("scan harness artifacts") {
        let entry = entry.expect("read harness artifact entry");
        let file_type = entry.file_type().expect("inspect harness artifact type");
        // Fail closed: a symlink skipped by a regular-file scan would be an
        // unscanned gap that could point outside the scratch root, so its
        // presence is proof failure. The scan never follows links.
        assert!(
            !file_type.is_symlink(),
            "symlink {} inside the retained harness root; the artifact scan refuses to skip it",
            entry.path().display()
        );
        if file_type.is_dir() {
            scan_directory(&entry.path(), secrets);
        } else if file_type.is_file() {
            let contents =
                fs::read(entry.path()).expect("read harness artifact for redaction scan");
            assert!(secrets.iter().all(|secret| !secret.is_empty()));
            assert!(
                secrets.iter().all(|secret| !contains(&contents, secret)),
                "generated password appeared in retained harness artifact {}",
                entry.path().display()
            );
        }
        // Live Unix sockets (the private bus and control sockets) are the only
        // other entries the retained root holds while the command runs; they
        // carry no readable retained bytes and are deliberately outside the
        // scan scope.
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
