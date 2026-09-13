//! Secret (password) acquisition for the control protocol.
//!
//! Two input paths share one output type, [`Secret`]:
//!
//! - [`prompt`] and [`prompt_confirmed`] ask a human on the controlling
//!   terminal (`/dev/tty`) with echo disabled, via `rpassword`. `rpassword`
//!   restores terminal state even when an error unwinds through it and raises
//!   `SIGINT` for Ctrl-C, and is the established local choice for password
//!   prompts.
//! - [`read_stdin_line`] implements the explicit `--stdin` path as an
//!   ordinary line-record reader over any [`BufRead`].
//!
//! # Why `--stdin` does not use `rpassword`
//!
//! `rpassword` runs an interactive line editor over whatever source it reads:
//! DEL and Backspace delete characters, Ctrl-U and Ctrl-W clear the line,
//! escape sequences are consumed, and other control bytes are silently
//! dropped. Those semantics are right for a human at a keyboard and wrong for
//! a pipe, where those bytes are password bytes. (`rpassword` deprecated
//! `read_password_from_bufread` and points at its config-driven reader, but
//! that path still runs the same editor over piped input.) The `--stdin` path
//! therefore reads plain bytes: every byte before the terminator is content.
//!
//! # Input contract
//!
//! - Input is UTF-8. Invalid UTF-8 on the stdin path is an error, never a
//!   lossy replacement. The control protocol itself stays raw-byte capable:
//!   [`Secret::as_bytes`] feeds `control::sans_io` request encoding directly.
//! - A line is terminated by LF; a CR immediately before it (CRLF) is
//!   stripped. A lone CR is content.
//! - End of input before a newline is an error, an empty pipe included. An
//!   empty line is a valid empty secret.
//! - Secrets are at most [`MAX_SECRET_BYTES`] bytes, bounding allocation from
//!   untrusted pipes.
//!
//! # Hygiene
//!
//! [`Secret`] owns a best-effort zeroized-on-drop string, implements none of
//! `Debug`, `Clone`, or `Display`, and never yields owned content. The stdin
//! buffer is allocated once at its maximum capacity so reallocation cannot
//! leave secret prefixes behind. Confirmation temporaries are cleared on drop.
//! Error values carry redacted metadata only — never reader-provided text.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead, Read as _};
use std::str;

use zeroize::Zeroizing;

/// Maximum accepted secret length, in bytes.
///
/// Generous for any legitimate passphrase or generated token, while an
/// untrusted pipe cannot drive unbounded allocation.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Longest line the stdin reader will buffer: the maximum content plus the
/// two-byte CRLF terminator.
const MAX_LINE_BYTES: usize = MAX_SECRET_BYTES + 2;

/// A secret value whose allocation is cleared when dropped.
///
/// This type deliberately implements none of [`Debug`], [`Clone`], or
/// [`Display`], and exposes content only as borrowed bytes so it cannot
/// escape the zeroizing guard.
pub struct Secret {
    value: Zeroizing<String>,
}

impl Secret {
    /// Adopt and validate a `String` already decoded by the terminal reader.
    fn from_string(value: String) -> Result<Self, SecretError> {
        let value = Zeroizing::new(value);
        if value.len() > MAX_SECRET_BYTES {
            return Err(SecretError::TooLong {
                maximum: MAX_SECRET_BYTES,
            });
        }
        Ok(Self { value })
    }

    /// Validate accumulated line bytes as UTF-8.
    fn from_utf8(bytes: Zeroizing<Vec<u8>>) -> Result<Self, SecretError> {
        // `str::from_utf8` borrows, so no error value can retain the bytes;
        // `bytes` is zeroized when dropped either way.
        let value = match str::from_utf8(&bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => return Err(SecretError::InvalidUtf8),
        };
        Self::from_string(value)
    }

    /// The secret as raw bytes for request encoding.
    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }
}

/// A failure while acquiring a secret.
///
/// Variants carry metadata (lengths, limits) only; none ever contains secret
/// content, which is why deriving `Debug` is safe here.
#[derive(Debug)]
pub enum SecretError {
    /// The controlling terminal could not be opened for a no-echo prompt.
    NoControllingTerminal,
    /// The two confirmation entries differed.
    ConfirmationMismatch,
    /// Input ended before a terminating newline.
    UnterminatedInput { length: usize },
    /// Input exceeded [`MAX_SECRET_BYTES`].
    TooLong { maximum: usize },
    /// Input was not valid UTF-8.
    InvalidUtf8,
    /// Reading failed. Reader-provided error text is deliberately discarded.
    Io {
        kind: io::ErrorKind,
        raw_os_error: Option<i32>,
    },
}

impl Display for SecretError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoControllingTerminal => formatter.write_str(
                "no controlling terminal to prompt on; run from a terminal or pass --stdin to read the secret from standard input",
            ),
            Self::ConfirmationMismatch => {
                formatter.write_str("the two entered secrets do not match")
            }
            Self::UnterminatedInput { length } => write!(
                formatter,
                "secret input ended after {length} bytes without a newline"
            ),
            Self::TooLong { maximum } => write!(
                formatter,
                "secret input exceeds the {maximum}-byte maximum length"
            ),
            Self::InvalidUtf8 => formatter.write_str("secret input is not valid UTF-8"),
            Self::Io {
                kind,
                raw_os_error,
            } => match raw_os_error {
                Some(code) => write!(
                    formatter,
                    "failed to read secret input ({kind:?}, operating system error {code})"
                ),
                None => write!(formatter, "failed to read secret input ({kind:?})"),
            },
        }
    }
}

impl Error for SecretError {}

/// Prompt once on the controlling terminal with echo disabled.
///
/// The prompt is written to and read from `/dev/tty`, so redirected stdin
/// does not disturb the interactive path. Opening `/dev/tty` without a
/// controlling terminal fails with `ENXIO`, which maps to
/// [`SecretError::NoControllingTerminal`] with an actionable message.
pub fn prompt(prompt: &str) -> Result<Secret, SecretError> {
    prompt_once(prompt)
}

/// One controlling-terminal prompt; also the per-entry reader used by
/// [`prompt_confirmed`].
fn prompt_once(prompt: &str) -> Result<Secret, SecretError> {
    prompt_via_rpassword(prompt, rpassword::ConfigBuilder::new().build())
}

/// Prompt twice on the controlling terminal and require both entries to match.
///
/// A single mismatch is an error; there is no retry loop. Both intermediate
/// values are zeroized on drop, and only the confirmed first entry is
/// returned.
pub fn prompt_confirmed(prompt: &str, confirmation_prompt: &str) -> Result<Secret, SecretError> {
    let first = prompt_once(prompt)?;
    let second = prompt_once(confirmation_prompt)?;
    confirm(first, second)
}

/// Read two consecutive `--stdin` lines and require them to match.
///
/// ```
/// use std::io::Cursor;
///
/// use gmellon::secret_input::{self, SecretError};
///
/// let mut input = Cursor::new(b"mellon\nmellon\n".to_vec());
/// let secret = secret_input::read_stdin_confirmed(&mut input).unwrap();
///
/// assert_eq!(secret.as_bytes(), b"mellon");
///
/// let mismatch = &mut Cursor::new(b"mellon\nfriend\n".to_vec());
/// assert!(matches!(
///     secret_input::read_stdin_confirmed(mismatch),
///     Err(SecretError::ConfirmationMismatch)
/// ));
/// ```
pub fn read_stdin_confirmed(reader: &mut impl BufRead) -> Result<Secret, SecretError> {
    let first = read_stdin_line(reader)?;
    let second = read_stdin_line(reader)?;
    confirm(first, second)
}

fn confirm(first: Secret, second: Secret) -> Result<Secret, SecretError> {
    if first.as_bytes() != second.as_bytes() {
        // Both values are zeroized as they drop out of scope.
        return Err(SecretError::ConfirmationMismatch);
    }
    Ok(first)
}

/// Read one `--stdin` secret line from `reader`.
///
/// Line-record semantics: LF terminates the line, a CR immediately before it
/// is stripped, every other byte (including control bytes) is literal
/// content, and end of input before a newline is an error. The reader is left
/// positioned after the newline so a following line can be read next.
///
/// ```
/// use std::io::Cursor;
///
/// use gmellon::secret_input;
///
/// let mut stdin = Cursor::new(b"mellon\n".to_vec());
/// let secret = secret_input::read_stdin_line(&mut stdin).unwrap();
///
/// assert_eq!(secret.as_bytes(), b"mellon");
/// ```
pub fn read_stdin_line(reader: &mut impl BufRead) -> Result<Secret, SecretError> {
    // Exact preallocation prevents secret prefixes being abandoned by a Vec
    // reallocation before the final allocation can be zeroized.
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE_BYTES));
    // `take` bounds the buffer: `read_until` can consume at most one full
    // line even from a pipe that never sends a newline.
    reader
        .take(MAX_LINE_BYTES as u64)
        .read_until(b'\n', &mut line)
        .map_err(redact_io_error)?;

    match line.last() {
        Some(b'\n') => {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.len() > MAX_SECRET_BYTES {
                return Err(SecretError::TooLong {
                    maximum: MAX_SECRET_BYTES,
                });
            }
            Secret::from_utf8(line)
        }
        _ => {
            if line.len() > MAX_SECRET_BYTES {
                return Err(SecretError::TooLong {
                    maximum: MAX_SECRET_BYTES,
                });
            }
            Err(SecretError::UnterminatedInput { length: line.len() })
        }
    }
}

/// Run one `rpassword` prompt under `config` and wrap the answer.
///
/// The production [`prompt`] and the injected-reader tests share this path.
fn prompt_via_rpassword(prompt: &str, config: rpassword::Config) -> Result<Secret, SecretError> {
    let answer =
        rpassword::prompt_password_with_config(prompt, config).map_err(classify_terminal_error)?;
    Secret::from_string(answer)
}

/// Map terminal-open failures to actionable errors.
///
/// Opening `/dev/tty` without a controlling terminal fails with `ENXIO`
/// (Linux errno 6), which otherwise surfaces as an opaque uncategorized I/O
/// error. Other errors retain only their kind and numeric operating-system
/// code; reader-provided text is discarded.
fn classify_terminal_error(error: io::Error) -> SecretError {
    if error.raw_os_error() == Some(rustix::io::Errno::NXIO.raw_os_error()) {
        return SecretError::NoControllingTerminal;
    }
    redact_io_error(error)
}

fn redact_io_error(error: io::Error) -> SecretError {
    SecretError::Io {
        kind: error.kind(),
        raw_os_error: error.raw_os_error(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    #[cfg(feature = "login-control")]
    use crate::control::sans_io::{Request, decode_request, encode_request};

    /// A cursor over borrowed bytes, so byte literals work uniformly.
    fn line_input(bytes: &[u8]) -> Cursor<&[u8]> {
        Cursor::new(bytes)
    }

    #[test]
    fn lf_terminates_and_excludes_the_newline() {
        let secret = read_stdin_line(&mut line_input(b"mellon\n")).unwrap();

        assert_eq!(secret.as_bytes(), b"mellon");
    }

    #[test]
    fn crlf_terminates_and_strips_only_the_final_cr() {
        let secret = read_stdin_line(&mut line_input(b"mellon\r\n")).unwrap();

        assert_eq!(secret.as_bytes(), b"mellon");
    }

    #[test]
    fn lone_cr_is_content_not_a_terminator() {
        let secret = read_stdin_line(&mut line_input(b"mel\rLon\n")).unwrap();

        assert_eq!(secret.as_bytes(), b"mel\rLon");
    }

    #[test]
    fn empty_line_is_an_empty_secret() {
        let secret = read_stdin_line(&mut line_input(b"\n")).unwrap();

        assert_eq!(secret.as_bytes(), b"");
    }

    #[test]
    fn empty_input_is_unterminated() {
        let result = read_stdin_line(&mut line_input(b""));

        assert!(matches!(
            result,
            Err(SecretError::UnterminatedInput { length: 0 })
        ));
    }

    #[test]
    fn eof_before_newline_is_an_error() {
        let result = read_stdin_line(&mut line_input(b"mellon"));

        assert!(matches!(
            result,
            Err(SecretError::UnterminatedInput { length }) if length == "mellon".len()
        ));
    }

    #[test]
    fn each_read_consumes_exactly_one_line() {
        let mut stdin = Cursor::new(b"old\nnew\nremaining\n".to_vec());

        assert_eq!(read_stdin_line(&mut stdin).unwrap().as_bytes(), b"old");
        assert_eq!(read_stdin_line(&mut stdin).unwrap().as_bytes(), b"new");
        assert_eq!(
            read_stdin_line(&mut stdin).unwrap().as_bytes(),
            b"remaining"
        );
    }

    #[test]
    fn invalid_utf8_is_rejected_not_replaced() {
        let result = read_stdin_line(&mut line_input(b"\xff\xfe\xfd\n"));

        assert!(matches!(result, Err(SecretError::InvalidUtf8)));
    }

    #[test]
    fn multibyte_utf8_survives_intact() {
        let secret = read_stdin_line(&mut line_input("mellón\n".as_bytes())).unwrap();

        assert_eq!(secret.as_bytes(), "mellón".as_bytes());
    }

    #[test]
    fn at_limit_lines_are_accepted_with_either_terminator() {
        let lf = read_stdin_line(&mut Cursor::new(
            [vec![b'a'; MAX_SECRET_BYTES], b"\n".to_vec()].concat(),
        ))
        .unwrap();
        let crlf = read_stdin_line(&mut Cursor::new(
            [vec![b'a'; MAX_SECRET_BYTES], b"\r\n".to_vec()].concat(),
        ))
        .unwrap();

        assert_eq!(lf.as_bytes().len(), MAX_SECRET_BYTES);
        assert_eq!(crlf.as_bytes().len(), MAX_SECRET_BYTES);
    }

    #[test]
    fn over_limit_lines_are_rejected() {
        let result = read_stdin_line(&mut Cursor::new(
            [vec![b'a'; MAX_SECRET_BYTES + 1], b"\n".to_vec()].concat(),
        ));

        assert!(matches!(
            result,
            Err(SecretError::TooLong {
                maximum: MAX_SECRET_BYTES
            })
        ));
    }

    #[test]
    fn over_limit_input_without_a_newline_is_rejected_without_unbounded_reads() {
        // No newline and no end of input: the bounded reader must stop and
        // error rather than buffering a growing line.
        let mut input = Cursor::new(vec![b'a'; MAX_SECRET_BYTES + 5]);
        let result = read_stdin_line(&mut input);

        assert!(matches!(
            result,
            Err(SecretError::TooLong {
                maximum: MAX_SECRET_BYTES
            })
        ));
        assert_eq!(input.position(), MAX_LINE_BYTES as u64);
    }

    #[test]
    fn unterminated_at_limit_reports_unterminated() {
        let result = read_stdin_line(&mut Cursor::new(vec![b'a'; MAX_SECRET_BYTES]));

        assert!(matches!(
            result,
            Err(SecretError::UnterminatedInput {
                length: MAX_SECRET_BYTES
            })
        ));
    }

    #[test]
    fn control_bytes_are_literal_content_on_stdin() {
        // DEL, Backspace, Ctrl-C, Ctrl-D, and an escape sequence: editing
        // commands for a terminal editor, plain password bytes here.
        let secret = read_stdin_line(&mut line_input(b"pass\x7f\x08\x03\x04\x1b[Aword\n")).unwrap();

        assert_eq!(secret.as_bytes(), b"pass\x7f\x08\x03\x04\x1b[Aword");
    }

    #[test]
    fn rpassword_would_edit_those_same_bytes() {
        // The contrast that justifies a separate stdin reader: rpassword's
        // configured reader still runs its interactive editor over piped
        // input, so the same bytes yield a different (edited) value.
        let literal = b"mellon\x7f\x7fn";
        let config = rpassword::ConfigBuilder::new()
            .input_reader(Cursor::new(literal.to_vec()))
            .output_discard()
            .build();

        let edited = rpassword::read_password_with_config(config).unwrap();

        assert_ne!(edited.as_bytes(), literal);
    }

    #[test]
    fn prompt_via_rpassword_reads_the_configured_source() {
        let config = rpassword::ConfigBuilder::new()
            .input_reader(Cursor::new(b"mellon\n".to_vec()))
            .output_discard()
            .build();

        let secret = prompt_via_rpassword("Password: ", config).unwrap();

        assert_eq!(secret.as_bytes(), b"mellon");
    }

    #[test]
    fn tty_answers_share_the_secret_length_limit() {
        let config = rpassword::ConfigBuilder::new()
            .input_reader(Cursor::new(
                [vec![b'a'; MAX_SECRET_BYTES + 1], b"\n".to_vec()].concat(),
            ))
            .output_discard()
            .build();

        assert!(matches!(
            prompt_via_rpassword("Password: ", config),
            Err(SecretError::TooLong {
                maximum: MAX_SECRET_BYTES
            })
        ));
    }

    #[test]
    fn prompt_via_rpassword_maps_reader_failures_to_io_errors() {
        let config = rpassword::ConfigBuilder::new()
            .input_file_path("/nonexistent/gmellon-test-tty")
            .output_discard()
            .build();

        assert!(matches!(
            prompt_via_rpassword("Password: ", config),
            Err(SecretError::Io { .. })
        ));
    }

    #[test]
    fn enxio_maps_to_an_actionable_error() {
        let error = classify_terminal_error(io::Error::from_raw_os_error(
            rustix::io::Errno::NXIO.raw_os_error(),
        ));

        assert!(matches!(error, SecretError::NoControllingTerminal));
        assert!(error.to_string().contains("--stdin"));
    }

    #[test]
    fn other_terminal_failures_stay_io_errors() {
        let error = classify_terminal_error(io::Error::from_raw_os_error(13)); // EACCES

        assert!(matches!(error, SecretError::Io { .. }));
    }

    #[test]
    fn reader_error_text_is_redacted() {
        struct LeakyReader;

        impl io::Read for LeakyReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("mellon must not escape"))
            }
        }

        let mut input = io::BufReader::new(LeakyReader);
        let error = read_stdin_line(&mut input)
            .err()
            .expect("the injected reader should fail");

        assert!(matches!(error, SecretError::Io { .. }));
        assert!(!error.to_string().contains("mellon"));
        assert!(!format!("{error:?}").contains("mellon"));
    }

    #[test]
    fn stdin_confirmation_returns_the_matched_value() {
        let mut input = Cursor::new(b"mellon\nmellon\n".to_vec());

        let secret = read_stdin_confirmed(&mut input).unwrap();

        assert_eq!(secret.as_bytes(), b"mellon");
    }

    #[test]
    fn confirmation_mismatch_is_a_single_error_without_secret_content() {
        let mut input = Cursor::new(b"mellon\nfriend\n".to_vec());

        let error = read_stdin_confirmed(&mut input)
            .err()
            .expect("mismatching entries should fail");

        let message = error.to_string();
        assert!(matches!(error, SecretError::ConfirmationMismatch));
        assert!(!message.contains("mellon"));
        assert!(!message.contains("friend"));
    }

    #[test]
    fn confirmation_propagates_read_errors() {
        let mut input = Cursor::new(b"mellon\n".to_vec());

        let error = read_stdin_confirmed(&mut input)
            .err()
            .expect("an unterminated second entry should fail");

        assert!(matches!(
            error,
            SecretError::UnterminatedInput { length: 0 }
        ));
    }

    #[test]
    #[cfg(feature = "login-control")]
    fn secrets_feed_the_control_codec_and_round_trip() {
        let secret = read_stdin_line(&mut line_input(b"mellon\n")).unwrap();
        let frame = encode_request(Request::Unlock {
            password: secret.as_bytes(),
        })
        .unwrap();

        match decode_request(frame.as_ref()).unwrap() {
            Request::Unlock { password } => assert_eq!(password, b"mellon"),
            Request::Change { .. } => panic!("decoded unlock as change"),
        }
    }

    #[test]
    #[cfg(feature = "login-control")]
    fn multibyte_secrets_round_trip_through_the_wire_shape() {
        let text = "mellón-🔑";
        let mut input = Cursor::new(format!("{text}\n").into_bytes());
        let secret = read_stdin_line(&mut input).unwrap();
        let frame = encode_request(Request::Unlock {
            password: secret.as_bytes(),
        })
        .unwrap();

        match decode_request(frame.as_ref()).unwrap() {
            Request::Unlock { password } => assert_eq!(password, text.as_bytes()),
            Request::Change { .. } => panic!("decoded unlock as change"),
        }
    }
}
