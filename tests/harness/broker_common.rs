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
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread::{self, JoinHandle};
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
/// daemon — so its stdout is consumed by an owned streaming reader that
/// records only header-derived facts (count and sender unique names) and
/// discards every other line, including bodies, as it is read. Decoded
/// password bytes therefore transit the pipe and the reader's single reused
/// line buffer only: no raw change-monitor output ever exists on disk, in
/// any form, on success, failure, or abrupt teardown.
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
        let mut command = Command::new(STDBUF);
        command
            .arg("-oL")
            .arg(BUSCTL)
            .arg(format!("--address={address}"))
            .arg("monitor")
            .arg(format!("--match={}", spec.match_rule))
            .stdin(Stdio::null())
            .stderr(ready);
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
    /// then stop it. `Child::kill` sends SIGKILL immediately on Unix — there
    /// is deliberately no TERM-first grace period, and the old TERM-then-
    /// KILL comment was wrong — and the pipe lives in the kernel, so every
    /// line the monitor already wrote survives for its reader; the settle
    /// delay plus the proof's closed-count assertions guard against a
    /// truncated last line. The deadline only bounds reaping.
    fn stop(&mut self) {
        thread::sleep(Duration::from_millis(200));
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Ok(None) => panic!("{} monitor did not exit after SIGKILL", self.spec.stem),
                Err(error) => panic!("{} monitor wait failed: {error}", self.spec.stem),
            }
        }
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
