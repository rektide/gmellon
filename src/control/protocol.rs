use std::error::Error;
use std::fmt::{self, Display, Formatter};

use zeroize::Zeroizing;

const HEADER_LENGTH: usize = 8;
const MAX_STRING_LENGTH: usize = 0x7fff_ffff;
const RESPONSE_LENGTH: usize = 8;

/// Operation codes accepted by the GNOME Keyring control socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Operation {
    Initialize = 0,
    Unlock = 1,
    Change = 2,
    Quit = 3,
}

/// Result codes used by the GNOME Keyring control protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DaemonResult {
    Ok = 0,
    Denied = 1,
    Failed = 2,
    NoDaemon = 3,
}

/// A password-bearing request supported by `gmellon`.
///
/// This type deliberately does not implement [`Debug`].
pub enum Request<'a> {
    Unlock {
        password: &'a str,
    },
    Change {
        original_password: &'a str,
        new_password: &'a str,
    },
}

/// An encoded request whose allocation is cleared when dropped.
///
/// This type deliberately does not implement [`Debug`] or expose its inner
/// `Vec`, preventing callers from accidentally taking ownership without the
/// zeroization guard.
#[must_use = "the encoded request must be sent or explicitly dropped"]
pub struct RequestFrame {
    bytes: Zeroizing<Vec<u8>>,
}

impl AsRef<[u8]> for RequestFrame {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

/// A request could not be represented in the daemon's wire format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    InteriorNul,
    StringTooLong { length: usize },
    FrameTooLong,
}

impl Display for EncodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul => formatter.write_str("a control string contains a NUL byte"),
            Self::StringTooLong { length } => {
                write!(
                    formatter,
                    "control string length {length} exceeds the protocol limit"
                )
            }
            Self::FrameTooLong => formatter.write_str("control request exceeds the frame limit"),
        }
    }
}

impl Error for EncodeError {}

/// A daemon response was not a valid result frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    UnexpectedResponseLength { actual: usize },
    InvalidDeclaredLength { declared: u32 },
    UnknownResult { value: u32 },
}

impl Display for DecodeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedResponseLength { actual } => {
                write!(
                    formatter,
                    "expected an 8-byte response, received {actual} bytes"
                )
            }
            Self::InvalidDeclaredLength { declared } => {
                write!(formatter, "response declares invalid length {declared}")
            }
            Self::UnknownResult { value } => {
                write!(formatter, "response contains unknown result code {value}")
            }
        }
    }
}

impl Error for DecodeError {}

/// Encode one password-bearing request, excluding the transport's credential
/// NUL byte.
pub fn encode_request(request: Request<'_>) -> Result<RequestFrame, EncodeError> {
    match request {
        Request::Unlock { password } => encode_fields(Operation::Unlock, &[password]),
        Request::Change {
            original_password,
            new_password,
        } => encode_fields(Operation::Change, &[original_password, new_password]),
    }
}

/// Decode the exact eight-byte response used by UNLOCK and CHANGE.
pub fn decode_response(response: &[u8]) -> Result<DaemonResult, DecodeError> {
    if response.len() != RESPONSE_LENGTH {
        return Err(DecodeError::UnexpectedResponseLength {
            actual: response.len(),
        });
    }

    let declared = read_u32(&response[..4]);
    if declared != RESPONSE_LENGTH as u32 {
        return Err(DecodeError::InvalidDeclaredLength { declared });
    }

    match read_u32(&response[4..]) {
        0 => Ok(DaemonResult::Ok),
        1 => Ok(DaemonResult::Denied),
        2 => Ok(DaemonResult::Failed),
        3 => Ok(DaemonResult::NoDaemon),
        value => Err(DecodeError::UnknownResult { value }),
    }
}

fn encode_fields(operation: Operation, fields: &[&str]) -> Result<RequestFrame, EncodeError> {
    for field in fields {
        if field.as_bytes().contains(&0) {
            return Err(EncodeError::InteriorNul);
        }
    }

    let field_lengths: Vec<_> = fields.iter().map(|field| field.len()).collect();
    let frame_length = encoded_request_length(&field_lengths)?;
    let mut bytes = Vec::with_capacity(frame_length as usize);

    push_u32(&mut bytes, frame_length);
    push_u32(&mut bytes, operation as u32);
    for field in fields {
        push_u32(&mut bytes, field.len() as u32);
        bytes.extend_from_slice(field.as_bytes());
    }

    Ok(RequestFrame {
        bytes: Zeroizing::new(bytes),
    })
}

fn encoded_request_length(field_lengths: &[usize]) -> Result<u32, EncodeError> {
    let mut length = HEADER_LENGTH;

    for &field_length in field_lengths {
        if field_length >= MAX_STRING_LENGTH {
            return Err(EncodeError::StringTooLong {
                length: field_length,
            });
        }

        length = length
            .checked_add(4)
            .and_then(|length| length.checked_add(field_length))
            .ok_or(EncodeError::FrameTooLong)?;
    }

    u32::try_from(length).map_err(|_| EncodeError::FrameTooLong)
}

fn push_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_be_bytes());
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("codec supplied exactly four bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_codes_match_upstream() {
        assert_eq!(Operation::Initialize as u32, 0);
        assert_eq!(Operation::Unlock as u32, 1);
        assert_eq!(Operation::Change as u32, 2);
        assert_eq!(Operation::Quit as u32, 3);
    }

    #[test]
    fn result_codes_match_upstream() {
        assert_eq!(DaemonResult::Ok as u32, 0);
        assert_eq!(DaemonResult::Denied as u32, 1);
        assert_eq!(DaemonResult::Failed as u32, 2);
        assert_eq!(DaemonResult::NoDaemon as u32, 3);
    }

    #[test]
    fn unlock_mellon_matches_the_golden_frame() {
        let frame = encode_request(Request::Unlock { password: "mellon" })
            .expect("the golden request should encode");

        assert_eq!(
            frame.as_ref(),
            [
                0x00, 0x00, 0x00, 0x12, // total length: 18
                0x00, 0x00, 0x00, 0x01, // UNLOCK
                0x00, 0x00, 0x00, 0x06, // password length: 6
                b'm', b'e', b'l', b'l', b'o', b'n',
            ]
        );
    }

    #[test]
    fn change_matches_a_golden_frame() {
        let frame = encode_request(Request::Change {
            original_password: "old",
            new_password: "new",
        })
        .expect("the change request should encode");

        assert_eq!(
            frame.as_ref(),
            [
                0x00, 0x00, 0x00, 0x16, // total length: 22
                0x00, 0x00, 0x00, 0x02, // CHANGE
                0x00, 0x00, 0x00, 0x03, b'o', b'l', b'd', 0x00, 0x00, 0x00, 0x03, b'n', b'e', b'w',
            ]
        );
    }

    #[test]
    fn encoded_requests_round_trip_through_the_wire_shape() {
        let unlock = encode_request(Request::Unlock { password: "friend" }).unwrap();
        let change = encode_request(Request::Change {
            original_password: "friend",
            new_password: "mellon",
        })
        .unwrap();

        let (operation, fields) = decode_request_for_test(unlock.as_ref());
        assert_eq!(operation, Operation::Unlock);
        assert_eq!(fields, [b"friend".as_slice()]);

        let (operation, fields) = decode_request_for_test(change.as_ref());
        assert_eq!(operation, Operation::Change);
        assert_eq!(fields, [b"friend".as_slice(), b"mellon".as_slice()]);
    }

    #[test]
    fn empty_unlock_password_is_representable() {
        let frame = encode_request(Request::Unlock { password: "" }).unwrap();

        assert_eq!(frame.as_ref().len(), 12);
        assert_eq!(&frame.as_ref()[8..], &[0, 0, 0, 0]);
    }

    #[test]
    fn interior_nul_is_rejected() {
        let result = encode_request(Request::Unlock {
            password: "not\0a-c-string",
        });

        assert!(matches!(result, Err(EncodeError::InteriorNul)));
    }

    #[test]
    fn protocol_length_limits_are_checked_before_allocation() {
        assert_eq!(
            encoded_request_length(&[MAX_STRING_LENGTH]),
            Err(EncodeError::StringTooLong {
                length: MAX_STRING_LENGTH
            })
        );
        assert_eq!(
            encoded_request_length(&[MAX_STRING_LENGTH - 1, MAX_STRING_LENGTH - 1]),
            Err(EncodeError::FrameTooLong)
        );
        assert_eq!(
            encoded_request_length(&[usize::MAX - HEADER_LENGTH]),
            Err(EncodeError::StringTooLong {
                length: usize::MAX - HEADER_LENGTH
            })
        );
    }

    #[test]
    fn all_known_results_decode() {
        for (value, expected) in [
            (0_u32, DaemonResult::Ok),
            (1, DaemonResult::Denied),
            (2, DaemonResult::Failed),
            (3, DaemonResult::NoDaemon),
        ] {
            let mut response = 8_u32.to_be_bytes().to_vec();
            response.extend_from_slice(&value.to_be_bytes());

            assert_eq!(decode_response(&response), Ok(expected));
        }
    }

    #[test]
    fn response_must_be_exactly_eight_bytes() {
        assert_eq!(
            decode_response(&[0; 7]),
            Err(DecodeError::UnexpectedResponseLength { actual: 7 })
        );
        assert_eq!(
            decode_response(&[0; 9]),
            Err(DecodeError::UnexpectedResponseLength { actual: 9 })
        );
    }

    #[test]
    fn response_declared_length_must_be_eight() {
        let response = [0, 0, 0, 9, 0, 0, 0, 0];

        assert_eq!(
            decode_response(&response),
            Err(DecodeError::InvalidDeclaredLength { declared: 9 })
        );
    }

    #[test]
    fn unknown_result_is_rejected() {
        let response = [0, 0, 0, 8, 0, 0, 0, 4];

        assert_eq!(
            decode_response(&response),
            Err(DecodeError::UnknownResult { value: 4 })
        );
    }

    fn decode_request_for_test(frame: &[u8]) -> (Operation, Vec<&[u8]>) {
        assert!(frame.len() >= HEADER_LENGTH);
        assert_eq!(read_u32(&frame[..4]) as usize, frame.len());

        let operation = match read_u32(&frame[4..8]) {
            1 => Operation::Unlock,
            2 => Operation::Change,
            value => panic!("unexpected operation {value}"),
        };
        let field_count = match operation {
            Operation::Unlock => 1,
            Operation::Change => 2,
            Operation::Initialize | Operation::Quit => unreachable!(),
        };
        let mut fields = Vec::with_capacity(field_count);
        let mut offset = HEADER_LENGTH;

        for _ in 0..field_count {
            let length = read_u32(&frame[offset..offset + 4]) as usize;
            offset += 4;
            fields.push(&frame[offset..offset + length]);
            offset += length;
        }

        assert_eq!(offset, frame.len());
        (operation, fields)
    }
}
