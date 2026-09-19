//! The body-verdict monitor: streams captured method-call bodies through the
//! scanner machinery to prove secret absence and encrypted shape without
//! anything body-shaped ever reaching the disk.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread::JoinHandle;

use zeroize::Zeroizing;

use super::monitor::{
    BUSCTL, MONITOR_BANNER, busctl_monitor_command, stop_monitor_child, wait_for_monitor_ready,
};
use super::scanner::{BodyMode, BodyScanOutcome, CapturedBodyMessage, spawn_body_reader};
use super::secrets::ProofSecrets;
use crate::common;

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
/// Match-filtered streaming bus monitor that verdicts message *bodies* for
/// the encrypted-session proofs.
///
/// Unlike [`super::monitor::MethodMonitor`], which retains only header-derived facts, this
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
