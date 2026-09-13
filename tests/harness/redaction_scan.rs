//! Ordinary positive-control unit tests for the shared redaction scanner and
//! the streaming monitor header parser.
//!
//! The harness proofs exercise
//! [`common::assert_secret_absent`](common::fn.assert_secret_absent) only on
//! the absence side: a leak fails a proof, but nothing demonstrated that the
//! scanner actually *detects* each reversible encoding. These tests are the
//! positive controls: synthetic haystacks carrying a known value as literal
//! bytes, contiguous lowercase and uppercase hex, and the exact
//! `BYTE <decimal>;` line form installed `busctl monitor` prints for decoded
//! `ay` bodies must be detected — by the boolean scanners directly and by
//! `assert_secret_absent` raising a panic — while benign text and partial
//! encodings stay silent.
//!
//! The same target pins [`broker_common::HeaderCallParser`] against the
//! installed busctl 261 monitor block shape captured with a benign rule
//! under the private broker (`.test-agent/change-monitor-hardening/`), so
//! the streaming password-bearing monitor cannot drift into counting loose
//! text from bodies.
//!
//! These tests are ordinary — never ignored — and need no daemon, bus, or
//! harness environment. This file is a declared `[[test]]` target
//! (`redaction_scan`); `common` and `broker_common` are compiled into it as
//! modules, exactly as the proof targets include them, so the controls run
//! exactly once per suite instead of duplicating across the three ignored
//! proof binaries.

// Both shared modules compile into this ordinary target, but this target
// exercises only the scanner helpers and the header parser; the rest is
// harness machinery owned by the proof targets. Silence dead-code analysis
// exactly as broker_collections.rs does for the same reason.
#[allow(dead_code)]
mod broker_common;
#[allow(dead_code)]
mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use broker_common::HeaderCallParser;
use common::{assert_secret_absent, contains, contains_byte_dump, contains_encoded};

/// One synthetic secret with varied byte values: printable, mixed-case, and
/// a punctuation byte, so the hex and decimal dump encodings are unambiguous.
const SECRET: &[u8] = b"Zx9Q!";

fn lowercase_hex(secret: &[u8]) -> String {
    secret.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn uppercase_hex(secret: &[u8]) -> String {
    secret.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn exact_byte_dump(secret: &[u8]) -> String {
    secret
        .iter()
        .map(|byte| format!("BYTE {byte};\n"))
        .collect()
}

// --- literal bytes ---------------------------------------------------------

#[test]
fn contains_matches_literal_bytes_only() {
    let haystack = b"leading Zx9Q! trailing";
    assert!(
        contains(haystack, SECRET),
        "literal secret bytes must be detected"
    );
    assert!(!contains(b"leading Zx9 trailing", SECRET));
    assert!(!contains(b"", SECRET));
    // A haystack holding only a prefix of the secret is not a match.
    assert!(!contains(b"leading Zx9Q trailing", SECRET));
}

// --- reversible hex encodings ----------------------------------------------

#[test]
fn contains_encoded_matches_both_hex_cases() {
    assert!(contains_encoded(
        format!("log line {} log line", lowercase_hex(SECRET)).as_bytes(),
        SECRET,
    ));
    assert!(contains_encoded(
        format!("log line {} log line", uppercase_hex(SECRET)).as_bytes(),
        SECRET,
    ));
}

#[test]
fn contains_encoded_stays_silent_on_partial_or_benign_input() {
    let lower = lowercase_hex(SECRET);
    // Every encoding but the last byte is not the secret.
    assert!(!contains_encoded(
        format!("prefix {} suffix", &lower[..lower.len() - 2]).as_bytes(),
        SECRET,
    ));
    assert!(!contains_encoded(b"ordinary diagnostic text", SECRET));
    // Documented scanner semantics: an empty secret never matches.
    assert!(!contains_encoded(b"anything", b""));
}

// --- exact `BYTE <decimal>;` busctl dumps ----------------------------------

#[test]
fn contains_byte_dump_matches_the_exact_busctl_dump_form() {
    let mut text = String::from("‣ Type=method_call  Endian=l\n");
    text.push_str(&exact_byte_dump(SECRET));
    text.push_str("  };\n");
    assert!(contains_byte_dump(text.as_bytes(), SECRET));

    // Unrelated lines between the tokens do not break in-order
    // reconstruction of the dump stream.
    let scattered = [
        "BYTE 90;",
        "noise line",
        "BYTE 120;",
        "",
        "BYTE 57;",
        "BYTE 81;",
        "more noise",
        "BYTE 33;",
    ]
    .join("\n");
    assert!(contains_byte_dump(scattered.as_bytes(), SECRET));
}

#[test]
fn contains_byte_dump_stays_silent_on_partial_scrambled_or_other_input() {
    // Out-of-order dump values are not the secret.
    let scrambled = ["BYTE 90;", "BYTE 120;", "BYTE 81;", "BYTE 57;", "BYTE 33;"].join("\n");
    assert!(!contains_byte_dump(scrambled.as_bytes(), SECRET));

    // A dump missing the last byte is not the secret.
    let truncated = SECRET[..SECRET.len() - 1]
        .iter()
        .map(|byte| format!("BYTE {byte};\n"))
        .collect::<String>();
    assert!(!contains_byte_dump(truncated.as_bytes(), SECRET));

    // An unrelated dump and plain text are benign.
    assert!(!contains_byte_dump(
        "BYTE 1;\nBYTE 2;\nBYTE 3;\n".as_bytes(),
        SECRET
    ));
    assert!(!contains_byte_dump(b"no dump here", SECRET));
    // Documented scanner semantics: an empty secret never matches.
    assert!(!contains_byte_dump(b"anything", b""));
}

#[test]
fn contains_byte_dump_requires_the_exact_busctl_token_form() {
    let exact = exact_byte_dump(SECRET);
    assert!(contains_byte_dump(exact.as_bytes(), SECRET), "control");

    // Lowercase keyword, comma terminator, and a missing semicolon are not
    // the exact `BYTE <decimal>;` token form and must not count.
    let lowercase = SECRET
        .iter()
        .map(|byte| format!("byte {byte};\n"))
        .collect::<String>();
    assert!(!contains_byte_dump(lowercase.as_bytes(), SECRET));

    let comma = SECRET
        .iter()
        .map(|byte| format!("BYTE {byte},\n"))
        .collect::<String>();
    assert!(!contains_byte_dump(comma.as_bytes(), SECRET));

    let unterminated = SECRET
        .iter()
        .map(|byte| format!("BYTE {byte}\n"))
        .collect::<String>();
    assert!(!contains_byte_dump(unterminated.as_bytes(), SECRET));
}

// --- assert_secret_absent: detection actually panics -----------------------

/// Run `assert_secret_absent` on a haystack that must be detected, require
/// the panic, and pin its diagnostic phrase.
fn require_detection(haystack: &[u8], expected_fragment: &str) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        assert_secret_absent(haystack, SECRET, "synthetic subject");
    }));
    let panic = result.expect_err("assert_secret_absent must detect the encoding");
    let message = panic
        .downcast_ref::<&str>()
        .map(|payload| (*payload).to_owned())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic payload>".to_owned());
    assert!(
        message.contains(expected_fragment),
        "panic message {message:?} must explain the {expected_fragment:?} detection"
    );
}

#[test]
fn assert_secret_absent_panics_on_literal_bytes() {
    require_detection(b"prefix Zx9Q! suffix", "literally");
}

#[test]
fn assert_secret_absent_panics_on_lowercase_hex() {
    require_detection(
        format!("hex {} hex", lowercase_hex(SECRET)).as_bytes(),
        "hex-encoded",
    );
}

#[test]
fn assert_secret_absent_panics_on_uppercase_hex() {
    require_detection(
        format!("HEX {} HEX", uppercase_hex(SECRET)).as_bytes(),
        "hex-encoded",
    );
}

#[test]
fn assert_secret_absent_panics_on_a_decoded_byte_dump() {
    require_detection(exact_byte_dump(SECRET).as_bytes(), "decoded byte dump");
}

#[test]
fn assert_secret_absent_accepts_benign_text() {
    let haystack = b"ID\tLOCKED\tLABEL\nlogin\tyes\tlogin\nordinary rows only";
    assert_secret_absent(haystack, SECRET, "benign subject");
}

// --- streaming header parser pinned to installed busctl output -------------

/// The exact matched-message block shape the installed busctl 261 prints,
/// captured under the private broker with a benign `Hello` rule
/// (`.test-agent/change-monitor-hardening/probe.sh`) and adapted only in the
/// member and paths. Note the header line carries `Sender=` and `Member=`
/// together and the `Timestamp` value contains spaces, which is why the
/// parser is token-based.
const BUSCTL_TYPE_LINE: &str = "‣ Type=method_call  Endian=l  Flags=0  Version=1 Cookie=4  Timestamp=\"Sat 2026-09-12 07:49:30.942831 UTC\"";
fn busctl_header_line(sender: &str) -> String {
    let line = "  Sender=%s  Destination=:1.3  Path=/org/freedesktop/secrets  \
                Interface=org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface  \
                Member=ChangeWithMasterPassword";
    line.replace("%s", sender)
}

/// Feed one full installed-shape message block through the parser.
fn feed_installed_block(parser: &mut HeaderCallParser, sender: &str) {
    parser.absorb_line(BUSCTL_TYPE_LINE);
    parser.absorb_line(&busctl_header_line(sender));
    parser.absorb_line(&format!("  UniqueName={sender}"));
    parser.absorb_line("  MESSAGE \"(a{sv}(oayays))\" {");
    parser.absorb_line("          \"org.freedesktop.Secret.Collection.Label\" = \"login\";");
    parser.absorb_line("          BYTE 108;");
    parser.absorb_line("  };");
    parser.absorb_line("");
}

#[test]
fn header_parser_counts_installed_shape_messages_with_senders() {
    let mut parser = HeaderCallParser::new("ChangeWithMasterPassword");
    for sender in [":1.5", ":1.6", ":1.7"] {
        feed_installed_block(&mut parser, sender);
    }
    assert_eq!(parser.calls, 3, "exactly the three header lines count");
    assert_eq!(parser.senders, [":1.5", ":1.6", ":1.7"]);
    assert_eq!(parser.failure, None);
}

#[test]
fn header_parser_discards_bodies_and_counts_nothing() {
    let mut parser = HeaderCallParser::new("ChangeWithMasterPassword");
    parser.absorb_line(BUSCTL_TYPE_LINE);
    parser.absorb_line("  MESSAGE \"(a{sv}(oayays))\" {");
    parser.absorb_line("          \"org.freedesktop.Secret.Collection.Label\" = \"login\";");
    parser.absorb_line("          BYTE 90;");
    parser.absorb_line("          BYTE 120;");
    parser.absorb_line("  };");
    parser.absorb_line("");
    // Even quoted body text that embeds header-shaped keys stays body text.
    parser.absorb_line("          \"Member=ChangeWithMasterPassword\" = \"Sender=:1.9\";");
    assert_eq!(parser.calls, 0, "no loose body text may count");
    assert!(parser.senders.is_empty());
    assert_eq!(parser.failure, None);
}

#[test]
fn header_parser_fails_closed_on_a_member_line_without_sender() {
    let mut parser = HeaderCallParser::new("ChangeWithMasterPassword");
    parser.absorb_line(
        "  Destination=:1.3  Path=/x  Interface=org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface  Member=ChangeWithMasterPassword",
    );
    let failure = parser
        .failure
        .as_deref()
        .expect("an unattributable header line must fail closed");
    assert!(
        failure.contains("Sender"),
        "failure must name the missing Sender token: {failure}"
    );
    assert_eq!(parser.calls, 0);
}

#[test]
fn header_parser_fails_closed_on_a_sender_line_without_the_member() {
    let mut parser = HeaderCallParser::new("ChangeWithMasterPassword");
    parser.absorb_line("  Sender=:1.2  Destination=:1.3  Path=/x  Interface=other");
    let failure = parser
        .failure
        .as_deref()
        .expect("an ambiguous Sender line must fail closed");
    assert!(
        failure.contains("Member"),
        "failure must name the missing Member token: {failure}"
    );
    assert_eq!(parser.calls, 0);
}

#[test]
fn header_parser_fails_closed_on_malformed_sender_values() {
    for malformed in [
        "Sender=  Member=ChangeWithMasterPassword",
        "Sender=not-a-bus-name!!  Member=ChangeWithMasterPassword",
        "Sender=:1.  Member=ChangeWithMasterPassword",
        "Sender=org.freedesktop.DBus  Member=ChangeWithMasterPassword",
        "Sender=:1.2  Sender=:1.3  Member=ChangeWithMasterPassword",
    ] {
        let mut parser = HeaderCallParser::new("ChangeWithMasterPassword");
        parser.absorb_line(&format!("  {malformed}"));
        assert!(
            parser.failure.is_some(),
            "malformed sender line must fail closed: {malformed}"
        );
        assert_eq!(parser.calls, 0, "nothing malformed may count: {malformed}");
    }
}

#[test]
fn header_parser_accepts_only_unique_bus_name_senders_by_shape() {
    let mut parser = HeaderCallParser::new("ChangeWithMasterPassword");
    parser.absorb_line(&busctl_header_line(":1.12"));
    assert_eq!(parser.calls, 1);
    assert_eq!(parser.senders, [":1.12"]);
    assert_eq!(parser.failure, None);
}

// --- streaming body scanner pinned to installed busctl output ---------------

use broker_common::{BodyMode, BodyScanner, DH_ALGORITHM_LINE};
use zeroize::Zeroizing;

/// One busctl password-method block in the exact installed shape captured
/// under the private broker (`.test-agent/session-monitor-probe/probe4.sh`),
/// with the two `ay` arrays sized by the caller: the Secret's `parameters`
/// (the IV) and `value` (the ciphertext).
fn busctl_secret_block(member: &str, sender: &str, iv_bytes: &[u8], value_bytes: &[u8]) -> String {
    let array = |bytes: &[u8]| -> String {
        let mut block = String::from("                  ARRAY \"y\" {\n");
        for byte in bytes {
            block.push_str(&format!("                          BYTE {byte};\n"));
        }
        block.push_str("                  };\n");
        block
    };
    format!(
        "‣ Type=method_call  Endian=l  Flags=4  Version=1 Cookie=2  Timestamp=\"Sun 2026-09-13 09:24:12.765793 UTC\"\n\
         \x20 Sender={sender}  Destination=org.freedesktop.secrets  Path=/org/freedesktop/secrets  \
         Interface=org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface  Member={member}\n\
         \x20 UniqueName={sender}\n\
         \x20 MESSAGE \"o(oayays)\" {{\n\
         \x20         OBJECT_PATH \"/org/freedesktop/secrets/collection/login\";\n\
         \x20         STRUCT \"oayays\" {{\n\
         \x20                 OBJECT_PATH \"/org/freedesktop/secrets/session/1\";\n{}{}\
         \x20                 STRING \"text/plain\";\n\
         \x20         }};\n\
         \x20 }};\n\
         \n",
        array(iv_bytes),
        array(value_bytes),
    )
}

/// One busctl OpenSession block in the exact installed shape captured under
/// the private broker (`.test-agent/session-monitor-probe/probe6.sh`).
fn busctl_open_session_block(sender: &str, algorithm: &str, public_key: &[u8]) -> String {
    let mut key_block = String::from("                  ARRAY \"y\" {\n");
    for byte in public_key {
        key_block.push_str(&format!("                          BYTE {byte};\n"));
    }
    key_block.push_str("                  };\n");
    format!(
        "‣ Type=method_call  Endian=l  Flags=0  Version=1 Cookie=3  Timestamp=\"Sun 2026-09-13 09:30:16.170165 UTC\"\n\
         \x20 Sender={sender}  Destination=org.freedesktop.secrets  Path=/org/freedesktop/secrets  \
         Interface=org.freedesktop.Secret.Service  Member=OpenSession\n\
         \x20 UniqueName={sender}\n\
         \x20 MESSAGE \"sv\" {{\n\
         \x20         STRING \"{algorithm}\";\n\
         \x20         VARIANT \"ay\" {{\n{key_block}\
         \x20         }};\n\
         \x20 }};\n\
         \n"
    )
}

fn owned_secrets() -> Vec<(&'static str, Zeroizing<Vec<u8>>)> {
    vec![("probe", Zeroizing::new(SECRET.to_vec()))]
}

#[test]
fn body_scanner_verdicts_encrypted_secret_shapes() {
    let iv: Vec<u8> = (0..16).collect();
    let ciphertext: Vec<u8> = (0..32).map(|byte| 255 - byte as u8).collect();

    let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
    for line in busctl_secret_block("UnlockWithMasterPassword", ":1.9", &iv, &ciphertext).lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert_eq!(outcome.leaks, Vec::<String>::new());
    assert_eq!(outcome.failures, Vec::<String>::new());
    let message = &outcome.messages[0];
    assert_eq!(message.member, "UnlockWithMasterPassword");
    assert_eq!(message.sender, ":1.9");
    assert_eq!(message.array_lengths, [16, 32]);
    assert!(
        message.encrypted_secrets,
        "IV(16) + ciphertext(32) is the encrypted shape"
    );
}

#[test]
fn body_scanner_rejects_plain_session_secret_shapes() {
    // A plain-session Secret has an empty parameters array; it must not be
    // verdicted encrypted even though the value carries bytes.
    let iv = Vec::new();
    let value = vec![0x41u8, 0x42, 0x43];

    let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
    for line in busctl_secret_block("UnlockWithMasterPassword", ":1.9", &iv, &value).lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert_eq!(outcome.failures, Vec::<String>::new());
    assert!(
        !outcome.messages[0].encrypted_secrets,
        "an empty IV array is the plain-session shape and must fail the verdict"
    );
    assert_eq!(outcome.messages[0].array_lengths, [0, 3]);
}

#[test]
fn body_scanner_detects_a_password_inside_a_decoded_ay_run() {
    // The core absence check: the password bytes travel as one `BYTE
    // <decimal>;` line per element, so only the reconstructed run can
    // contain them.
    let iv: Vec<u8> = (0..16).collect();

    let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
    for line in busctl_secret_block("UnlockWithMasterPassword", ":1.9", &iv, SECRET).lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert_eq!(outcome.leaks.len(), 1, "the decoded run must be caught");
    assert!(
        outcome.leaks[0].contains("field=ay-run"),
        "the leak description must name the ay run: {}",
        outcome.leaks[0]
    );
    assert!(
        outcome.leaks[0].contains("secret=probe"),
        "the leak description must name the secret, never its bytes"
    );
}

#[test]
fn body_scanner_detects_a_password_in_raw_line_bytes() {
    let iv: Vec<u8> = (0..16).collect();
    let ciphertext: Vec<u8> = (0..32).map(|byte| byte as u8).collect();
    let mut block = busctl_secret_block("UnlockWithMasterPassword", ":1.9", &iv, &ciphertext);
    // A string field carrying the literal secret, as a diagnostic dump could.
    block.push_str("          STRING \"prefix Zx9Q! suffix\";\n");

    let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
    for line in block.lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert!(
        outcome
            .leaks
            .iter()
            .any(|leak| leak.contains("field=raw-line")),
        "the literal line bytes must be caught"
    );
}

#[test]
fn body_scanner_fails_closed_on_bodies_without_headers() {
    let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
    scanner.absorb_line("  MESSAGE \"o(oayays)\" {");
    scanner.absorb_line("          BYTE 65;");
    let outcome = scanner.into_outcome();
    assert!(
        !outcome.failures.is_empty(),
        "a BYTE outside an ARRAY block and before any header must fail closed"
    );
    assert_eq!(outcome.messages.len(), 0);
}

#[test]
fn body_scanner_fails_closed_on_unattributable_headers() {
    for malformed in [
        "Sender=:1.2  Path=/x  Interface=other",
        "Destination=:1.3  Member=UnlockWithMasterPassword",
        "Sender=not-a-bus-name!!  Member=UnlockWithMasterPassword",
    ] {
        let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
        scanner.absorb_line(&format!("  {malformed}"));
        let outcome = scanner.into_outcome();
        assert!(
            !outcome.failures.is_empty(),
            "unattributable header must fail closed: {malformed}"
        );
    }
}

#[test]
fn body_scanner_verdicts_open_session_negotiations() {
    let public_key = [0xdeu8, 0xad, 0xef];
    let block =
        busctl_open_session_block(":1.7", "dh-ietf1024-sha256-aes128-cbc-pkcs7", &public_key);
    // The rendered algorithm line must match the pinned const exactly, tying
    // the scanner's verdict input to the installed rendering.
    assert!(block.contains(DH_ALGORITHM_LINE));
    let mut scanner = BodyScanner::new(BodyMode::OpenSessions, owned_secrets());
    for line in block.lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert_eq!(outcome.failures, Vec::<String>::new());
    let message = &outcome.messages[0];
    assert!(message.dh_algorithm);
    assert_eq!(message.array_lengths, [3]);

    // A plain negotiation must be recorded as a failure, never verdicted.
    let mut scanner = BodyScanner::new(BodyMode::OpenSessions, owned_secrets());
    for line in busctl_open_session_block(":1.8", "plain", &[]).lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert!(
        outcome
            .failures
            .iter()
            .any(|failure| failure.contains("plain-session")),
        "a plain OpenSession must fail closed: {:?}",
        outcome.failures
    );
    assert!(!outcome.messages[0].dh_algorithm);
}

#[test]
fn body_scanner_change_calls_require_two_encrypted_secrets() {
    // A change call carries two Secrets: four `ay` arrays in body order
    // (IV, ciphertext, IV, ciphertext).
    let iv: Vec<u8> = (0..16).collect();
    let ciphertext: Vec<u8> = (0..48).map(|byte| byte as u8).collect();
    let second_iv: Vec<u8> = (16..32).collect();
    let second_ciphertext: Vec<u8> = (0..16).map(|byte| byte + 200).collect();

    let mut block = busctl_secret_block("ChangeWithMasterPassword", ":1.9", &iv, &ciphertext);
    // The helper emits one Secret; splice in the second Secret's arrays
    // before the closing content-type line of the first.
    let mut second = String::new();
    for array in [&second_iv, &second_ciphertext] {
        second.push_str("                  ARRAY \"y\" {\n");
        for byte in array {
            second.push_str(&format!("                          BYTE {byte};\n"));
        }
        second.push_str("                  };\n");
    }
    let content_type_line = "                  STRING \"text/plain\";\n";
    let splice_point = block.rfind(content_type_line).expect("content type line");
    block.insert_str(splice_point, &second);

    let mut scanner = BodyScanner::new(BodyMode::PasswordMethods, owned_secrets());
    for line in block.lines() {
        scanner.absorb_line(line);
    }
    let outcome = scanner.into_outcome();
    assert_eq!(outcome.failures, Vec::<String>::new());
    assert_eq!(outcome.messages[0].array_lengths, [16, 48, 16, 16]);
    assert!(
        outcome.messages[0].encrypted_secrets,
        "two IV/ciphertext pairs must verdict encrypted"
    );
}
