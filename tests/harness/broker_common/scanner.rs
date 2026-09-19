//! Streaming stdout scanners: incremental one-line-at-a-time parsers for the
//! installed busctl monitor renderings, plus the owned reader threads that
//! drain the piped monitors so raw output never accumulates or touches the
//! disk.

use std::io::{BufRead, BufReader};
use std::process::ChildStdout;
use std::thread::{self, JoinHandle};

use zeroize::Zeroizing;

use gmellon::secret_service::session;

use crate::common;

/// The exact body line the installed busctl renders for the encrypted
/// session algorithm string inside an OpenSession call.
pub const DH_ALGORITHM_LINE: &str = "STRING \"dh-ietf1024-sha256-aes128-cbc-pkcs7\";";
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
pub(super) fn spawn_header_reader(
    stdout: ChildStdout,
    member: &'static str,
) -> JoinHandle<ReaderOutcome> {
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
pub(super) fn spawn_body_reader(
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
