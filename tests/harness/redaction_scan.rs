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
