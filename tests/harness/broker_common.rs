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
//! private `ChangeWithMasterPassword` rule whose raw output is deleted after
//! header-derived counting), disposable proof secrets, and the outer isolated
//! runner. Include `mod common;` and
//! `mod broker_common;` together: this module builds on [`common`].
//!
//! This file is compiled only as a module of the declared `[[test]]`
//! targets; Cargo does not discover it as a separate test.

use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use zbus::zvariant::{ObjectPath, OwnedObjectPath, Value};
use zeroize::Zeroizing;

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
/// daemon — so its raw log carries secrets in busctl's decoded forms, is
/// always deleted after the header-derived summary is extracted, and is
/// deleted (not retained) on failure paths too.
pub const CHANGE_MATCH: &str = "interface='org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface',member='ChangeWithMasterPassword'";
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

/// Disposable fixture: the only facility permitted to create collections and
/// to call the standard `Lock` method. It owns a separate D-Bus connection so
/// monitor evidence can attribute every Lock call to it alone. Product code
/// must never lock or relock a collection as part of ordinary unlock.
pub struct Fixture {
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
    pub fn connect(address: &str) -> zbus::Result<Self> {
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

    pub fn unique_name(&self) -> String {
        self.connection
            .unique_name()
            .expect("fixture connection owns a unique name")
            .to_string()
    }

    pub fn lock_calls(&self) -> usize {
        self.lock_calls
    }

    /// Test-fixture setup only: standard Lock on one disposable collection.
    pub fn lock(&mut self, collection: &OwnedObjectPath) -> zbus::Result<()> {
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
    pub fn create(&self, label: &str, password: &[u8]) -> zbus::Result<OwnedObjectPath> {
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

/// Match-filtered bus monitor counting method calls of one member.
///
/// The monitor connects only to the harness's private bus. Its match rule
/// selects exactly one member's method calls; the summary retains only
/// header-derived facts (count and sender unique names), never message
/// bodies. Two policies cover the proof's two rules:
///
/// - the standard `Service.Lock` rule excludes every password-bearing body,
///   so its raw log is asserted secret-free (in bytes and reversible
///   encodings) before deletion, and is left in place on failure paths;
/// - the private `ChangeWithMasterPassword` rule selects password-bearing
///   bodies by design, so its raw log is never asserted secret-free: it is
///   deleted on both success and failure paths, and the fail-closed walk
///   over retained artifacts proves no encoding survived anywhere.
pub struct MethodMonitor {
    child: Child,
    log_path: PathBuf,
    ready_path: PathBuf,
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
    /// reached the daemon. The raw log is password-bearing and is always
    /// deleted.
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
        let log_path = root.join(format!("{}.log", spec.stem));
        let ready_path = root.join(format!("{}.ready.log", spec.stem));
        let output = File::create(&log_path)
            .unwrap_or_else(|error| panic!("create {} log: {error}", spec.stem));
        // busctl prints its readiness banner on stderr and message traffic on
        // stdout, so the banner gets its own file and stdout stays parseable.
        let ready = File::create(&ready_path)
            .unwrap_or_else(|error| panic!("create {} readiness log: {error}", spec.stem));
        let child = Command::new(STDBUF)
            .arg("-oL")
            .arg(BUSCTL)
            .arg(format!("--address={address}"))
            .arg("monitor")
            .arg(format!("--match={}", spec.match_rule))
            .stdin(Stdio::null())
            .stdout(output)
            .stderr(ready)
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {BUSCTL} monitor: {error}"));

        let monitor = Self {
            child,
            log_path,
            ready_path,
            spec,
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
        panic!(
            "{} monitor did not reach monitoring state before the deadline",
            monitor.spec.stem
        );
    }

    /// Stop the monitor, extract the header-derived evidence, retain a
    /// redacted summary, and delete the raw logs.
    pub fn finish(
        mut self,
        fixture_sender: &str,
        fixture_calls: usize,
        secrets: &ProofSecrets,
    ) -> MonitorSummary {
        let bytes = self.shutdown_and_read();
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let ready = fs::read_to_string(&self.ready_path)
            .unwrap_or_else(|error| panic!("read {} readiness log: {error}", self.spec.stem));
        assert!(
            ready.contains(MONITOR_BANNER),
            "{} monitor log lost its readiness banner",
            self.spec.stem
        );

        let summary_path = self
            .log_path
            .with_file_name(format!("{}.txt", self.spec.stem));
        let subject = format!("the {} monitor readiness log", self.spec.stem);
        for (_name, secret) in secrets.named() {
            // The readiness log is banner text only, whatever the rule.
            common::assert_secret_absent(ready.as_bytes(), secret, &subject);
            if !self.spec.password_bearing {
                // The match rule excludes password bodies entirely, so any
                // occurrence — literal or encoded — is a rule regression.
                common::assert_secret_absent(
                    raw.as_bytes(),
                    secret,
                    &format!("the raw {} log", self.spec.stem),
                );
            }
            // Password-bearing raw logs legitimately carry decoded bodies of
            // the counted calls; they are deleted below and the
            // retained-artifact walk proves nothing survived.
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
        let fixture_calls_observed = senders
            .iter()
            .filter(|sender| sender.as_str() == fixture_sender)
            .count();
        let senders_match_fixture = senders
            .iter()
            .all(|sender| sender.as_str() == fixture_sender);

        let summary = format!(
            "tool={BUSCTL} monitor\nmatch={}\nmember={}\nfixture_sender={fixture_sender}\n\
             fixture_calls_stated={fixture_calls}\nobserved_calls={}\n\
             observed_fixture_calls={fixture_calls_observed}\n\
             senders_match_fixture={senders_match_fixture}\nsenders={}\n",
            self.spec.match_rule,
            self.spec.member,
            senders.len(),
            senders.join(","),
        );
        fs::write(&summary_path, summary)
            .unwrap_or_else(|error| panic!("write redacted {} summary: {error}", self.spec.stem));
        fs::remove_file(&self.log_path)
            .unwrap_or_else(|error| panic!("delete raw {} log: {error}", self.spec.stem));
        fs::remove_file(&self.ready_path)
            .unwrap_or_else(|error| panic!("delete {} readiness log: {error}", self.spec.stem));

        MonitorSummary {
            calls: senders.len(),
            senders,
            fixture_calls: fixture_calls_observed,
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
                Ok(None) => panic!("{} monitor did not exit after KILL", self.spec.stem),
                Err(error) => panic!("{} monitor wait failed: {error}", self.spec.stem),
            }
        }
        fs::read(&self.log_path)
            .unwrap_or_else(|error| panic!("read {} log: {error}", self.spec.stem))
    }
}

impl Drop for MethodMonitor {
    fn drop(&mut self) {
        // Never leak the process. Password-bearing raw logs are deleted even
        // on failure paths, so retained failure scratch cannot carry
        // recoverable password dumps; body-excluding raw logs stay for the
        // artifact scan, as before.
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.spec.password_bearing {
            let _ = fs::remove_file(&self.log_path);
            let _ = fs::remove_file(&self.ready_path);
        }
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
}

impl ProofSecrets {
    pub fn generate() -> Self {
        let login = common::random_password();
        let second = common::distinct_password(&[&login]);
        let login_two = common::distinct_password(&[&login, &second]);
        let second_two = common::distinct_password(&[&login, &second, &login_two]);
        let wrong = common::distinct_password(&[&login, &second, &login_two, &second_two]);

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
        }
    }

    pub fn all_slices(&self) -> Vec<&[u8]> {
        vec![
            self.login.as_slice(),
            self.second.as_slice(),
            self.wrong.as_slice(),
            self.login_two.as_slice(),
            self.second_two.as_slice(),
        ]
    }

    pub fn named(&self) -> [(&'static str, &[u8]); 5] {
        [
            ("login", self.login.as_slice()),
            ("second", self.second.as_slice()),
            ("wrong", self.wrong.as_slice()),
            ("login_two", self.login_two.as_slice()),
            ("second_two", self.second_two.as_slice()),
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
