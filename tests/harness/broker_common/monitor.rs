//! Match-filtered method-call monitors: the busctl monitor spawn/stop
//! plumbing and the header-counting monitor whose password-bearing rules
//! stream through an owned reader and never touch the disk.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::scanner::{ReaderOutcome, spawn_header_reader};
use super::secrets::ProofSecrets;
use crate::common;

pub const BUSCTL: &str = "/usr/bin/busctl";
pub const STDBUF: &str = "/usr/bin/stdbuf";
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
///   by an owned reader thread ([`super::scanner::HeaderCallParser`]) that records only
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
/// Build the line-buffered `busctl monitor` command for one match rule with
/// stdin detached. Callers decide where stdout and stderr go.
pub(super) fn busctl_monitor_command(address: &str, match_rule: &str) -> Command {
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
pub(super) fn wait_for_monitor_ready(ready_path: &Path, stem: &str) {
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
pub(super) fn stop_monitor_child(child: &mut Child, stem: &str) {
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
