//! Sans-I/O cryptography for the encrypted Secret Service session.
//!
//! This module implements the `dh-ietf1024-sha256-aes128-cbc-pkcs7` session
//! that `gnome-keyring-daemon` negotiates through
//! `org.freedesktop.Secret.Service.OpenSession`. It is pure computation over
//! byte slices and owns no I/O or zbus types, so the blocking client and a
//! future Tokio adapter can share it verbatim:
//!
//! 1. The client generates a fresh Diffie-Hellman keypair in the RFC 2409
//!    1024-bit MODP group ("ietf-ike-grp-modp-1024", generator 2) and sends
//!    its public key as the `ay` OpenSession input variant, minimal unsigned
//!    big-endian.
//! 2. The daemon replies with its own public key. [`ClientKeypair`]
//!    validates it and computes the shared secret `y^x mod p`.
//! 3. The shared secret is left-padded with zero bytes to the prime length
//!    (128 bytes) before key derivation. A minimal-length encoding derives a
//!    wrong key with no visible error; this normalization is required by both
//!    peers (`egg_dh_gen_secret` in gnome-keyring's `egg/egg-dh.c`, which
//!    memmove+memsets the pad, and the PKCS#11 derive on the daemon side).
//! 4. AES-128 key = HKDF-SHA256(ikm, salt empty, info empty, L=16). Not
//!    `sha256(ikm)[..16]`: libsecret calls
//!    `egg_hkdf_perform("sha256", ikm, NULL, 0, NULL, 0, out, 16)` and the
//!    daemon uses `CKM_G_HKDF_SHA256_DERIVE` with a NULL parameter
//!    (`daemon/dbus/gkd-secret-session.c`). An empty salt per RFC 5869 is
//!    HashLen zero bytes.
//! 5. Each Secret seals with a fresh random IV and PKCS#7 padding: the
//!    Secret tuple's `parameters` field carries the IV and `value` carries
//!    the ciphertext. gmellon only ever encrypts.
//!
//! Hygiene follows `crate::secret_input`: the private exponent, shared
//! secret, derived key, IV, and padded plaintext live in zeroizing
//! allocations, and secret-bearing types implement none of `Debug`, `Clone`,
//! or `Display`.

use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::sync::LazyLock;

use aes::Aes128Enc;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeEncrypt, InnerIvInit, Key, KeyInit};
use cbc::Encryptor;
use crypto_bigint::{BoxedUint, Odd};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

#[cfg(test)]
use aes::Aes128Dec;
#[cfg(test)]
use aes::cipher::BlockModeDecrypt;
#[cfg(test)]
use cbc::Decryptor;

/// Secret Service OpenSession algorithm this module implements.
pub const ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 1024-bit MODP group prime, byte-for-byte from
/// `dh_group_1024_prime` in gnome-keyring's `egg/egg-dh.c` (lines 47-54).
const PRIME_BYTES: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Group bit length, and byte length of the prime and of every padded
/// group element.
const DH_BITS: u32 = 1024;
const PRIME_LEN: usize = 128;

/// Group generator g = 2 (`{ 0x02 }` in `egg_dh_default_params`).
const GENERATOR: u8 = 0x02;

/// AES-128 key, IV, and cipher block length in bytes.
const AES_KEY_LEN: usize = 16;

static PRIME: LazyLock<Odd<BoxedUint>> = LazyLock::new(|| {
    let prime = BoxedUint::from_be_slice_truncated(&PRIME_BYTES, DH_BITS);
    // PRIME_BYTES is a byte-for-byte copy of an odd prime; the conversion
    // cannot fail.
    Odd::new(prime).expect("RFC 2409 1024-bit MODP prime is odd")
});

static PRIME_MINUS_ONE: LazyLock<BoxedUint> = LazyLock::new(|| {
    let one = BoxedUint::from_be_slice_truncated(&[1], DH_BITS);
    // The subtraction cannot underflow: the prime is at least two.
    PRIME.wrapping_sub(&one)
});

/// A failure inside the session crypto core.
#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// The operating-system randomness source failed while generating a
    /// private exponent or IV.
    Randomness,
    /// The peer public key was empty or longer than the 128-byte prime.
    /// The length is metadata, never key material.
    PeerPublicKeyLength { length: usize },
    /// The peer public key failed the `1 < y < p - 1` range check.
    PeerPublicKeyOutOfRange,
    /// HKDF could not produce the requested output length. Unreachable at
    /// 16 bytes; kept so no code path needs `unwrap`.
    KeyDerivation,
    /// The AES-CBC encryption reported a padding error. Unreachable with
    /// internally sized buffers; kept so no code path needs `unwrap`.
    Cipher,
}

impl Display for CryptoError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Randomness => formatter.write_str("operating-system randomness source failed"),
            Self::PeerPublicKeyLength { length } => write!(
                formatter,
                "peer DH public key has invalid length {length} (expected 1 to {PRIME_LEN} bytes)"
            ),
            Self::PeerPublicKeyOutOfRange => {
                formatter.write_str("peer DH public key is outside the valid range")
            }
            Self::KeyDerivation => formatter.write_str("HKDF key derivation failed"),
            Self::Cipher => formatter.write_str("AES-CBC encryption failed"),
        }
    }
}

impl StdError for CryptoError {}

/// A freshly generated client Diffie-Hellman keypair for one session.
///
/// The private exponent is a fresh random value below `p / 2`, mirroring
/// gnome-keyring's `egg_dh_gen_pair` (randomize, then
/// `gcry_mpi_clear_highbit(priv, pbits - 1)`), and is zeroized on drop.
/// Keypairs are never reused across sessions.
///
/// This type deliberately implements none of [`Debug`], [`Clone`], or
/// [`Display`] because the private exponent is secret.
pub struct ClientKeypair {
    private: Zeroizing<BoxedUint>,
    public: BoxedUint,
}

impl ClientKeypair {
    /// Generate a fresh keypair from operating-system randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut exponent = Zeroizing::new([0u8; PRIME_LEN]);
        getrandom::fill(exponent.as_mut()).map_err(|_| CryptoError::Randomness)?;
        // Keep the exponent below 2^1023, hence below p/2, matching
        // egg_dh_gen_pair's clear_highbit(pbits - 1).
        exponent[0] &= 0x7F;
        if exponent.iter().all(|byte| *byte == 0) {
            // Probability ~2^-1023; report rather than retry.
            return Err(CryptoError::Randomness);
        }
        Ok(Self::from_private_exponent(&exponent[..]))
    }

    /// The public key `g^x mod p` in minimal unsigned big-endian encoding,
    /// ready to send as the OpenSession `ay` input variant.
    pub fn public_key(&self) -> Vec<u8> {
        // Variable-time trimming is acceptable: the value is public.
        self.public.to_be_bytes_trimmed_vartime().into_vec()
    }

    /// Validate the server's public key and derive the session AES key.
    ///
    /// `server_public` is the byte array returned by `OpenSession` for the
    /// `dh-ietf1024-sha256-aes128-cbc-pkcs7` algorithm. The key must decode
    /// to an integer satisfying `1 < y < p - 1` within at most the prime's
    /// byte length; anything else fails closed.
    pub fn derive_aes_key(&self, server_public: &[u8]) -> Result<SessionKey, CryptoError> {
        let length = server_public.len();
        if length == 0 || length > PRIME_LEN {
            return Err(CryptoError::PeerPublicKeyLength { length });
        }
        let peer = BoxedUint::from_be_slice(server_public, DH_BITS)
            .map_err(|_| CryptoError::PeerPublicKeyLength { length })?;

        // Fail closed unless 1 < y < p - 1. The comparisons are
        // variable-time, which is safe: y is peer-controlled public data and
        // the verdict is reported to the caller either way. This rejects
        // 0, 1, p - 1, p, and any value above p that fits the encoding.
        let one = BoxedUint::from_be_slice_truncated(&[1], DH_BITS);
        if peer.cmp_vartime(&one) != std::cmp::Ordering::Greater
            || peer.cmp_vartime(&*PRIME_MINUS_ONE) != std::cmp::Ordering::Less
        {
            return Err(CryptoError::PeerPublicKeyOutOfRange);
        }

        // Montgomery-ladder modular exponentiation: constant-time with
        // respect to the exponent. The base is peer-influenced, but the
        // exponent is fresh per-session random and never reused, which is
        // the primary mitigation for DH timing attacks.
        let shared = Zeroizing::new(peer.pow_mod(&self.private, &PRIME));

        // Normalize the shared secret to exactly the prime length before
        // the KDF. egg_dh_gen_secret in egg/egg-dh.c left-pads with zeros
        // the same way; a minimal-length encoding derives a wrong key with
        // no visible error.
        let mut ikm = Zeroizing::new([0u8; PRIME_LEN]);
        let raw = shared.to_be_bytes();
        ikm[PRIME_LEN - raw.len()..].copy_from_slice(&raw);

        let mut key = Zeroizing::new([0u8; AES_KEY_LEN]);
        hkdf_sha256(None, &ikm[..], &[], key.as_mut())?;
        Ok(SessionKey { bytes: key })
    }

    /// Build a keypair from a fixed private exponent.
    fn from_private_exponent(exponent: &[u8]) -> Self {
        let private = Zeroizing::new(BoxedUint::from_be_slice_truncated(exponent, DH_BITS));
        let generator = BoxedUint::from_be_slice_truncated(&[GENERATOR], DH_BITS);
        let public = generator.pow_mod(&private, &PRIME);
        Self { private, public }
    }
}

/// The negotiated AES-128 session key.
///
/// This type deliberately implements none of [`Debug`], [`Clone`], or
/// [`Display`] and never yields owned key material.
pub struct SessionKey {
    bytes: Zeroizing<[u8; AES_KEY_LEN]>,
}

impl SessionKey {
    /// Borrow the key bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..]
    }
}

/// One sealed Secret value: the fresh random IV that traveled in the Secret
/// tuple's `parameters` field and the PKCS#7-padded AES-128-CBC ciphertext
/// that traveled in `value`.
///
/// Both parts cross the wire in the clear, but the IV is still zeroized on
/// drop to keep buffers hygienic.
pub struct SealedSecret {
    pub iv: Zeroizing<Vec<u8>>,
    pub ciphertext: Vec<u8>,
}

/// Seal one plaintext for the daemon under the session key.
///
/// PKCS#7 pads the plaintext to a 16-byte multiple — a full extra block
/// when the plaintext already is one — and a fresh random IV is generated
/// per Secret. The padded buffer and IV live in zeroizing allocations; the
/// in-place encryption leaves only ciphertext behind.
pub fn seal(key: &SessionKey, plaintext: &[u8]) -> Result<SealedSecret, CryptoError> {
    let mut iv = Zeroizing::new([0u8; AES_KEY_LEN]);
    getrandom::fill(iv.as_mut()).map_err(|_| CryptoError::Randomness)?;

    // PKCS#7 always appends 1..=16 bytes.
    let padding = AES_KEY_LEN - (plaintext.len() % AES_KEY_LEN);
    let mut padded = Zeroizing::new(vec![0u8; plaintext.len() + padding]);
    padded[..plaintext.len()].copy_from_slice(plaintext);

    let cipher = Aes128Enc::new(&Key::<Aes128Enc>::from(*key.bytes));
    let encryptor = Encryptor::<Aes128Enc>::inner_iv_slice_init(cipher, &iv[..])
        .map_err(|_| CryptoError::Cipher)?;
    encryptor
        .encrypt_padded::<Pkcs7>(&mut padded, plaintext.len())
        .map_err(|_| CryptoError::Cipher)?;

    // After in-place encryption the buffer holds only ciphertext; take it
    // out without copying so nothing padded-plaintext-shaped lingers.
    Ok(SealedSecret {
        iv: Zeroizing::new(iv.to_vec()),
        ciphertext: std::mem::take(&mut padded),
    })
}

/// HKDF-SHA256 with explicit salt and info.
///
/// `None` salt is RFC 5869's HashLen zero bytes, matching egg-hkdf's
/// `g_malloc0(hash_len)` default. Kept as one place so the RFC 5869 test
/// vectors exercise the exact code path used for session keys.
fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, okm)
        .map_err(|_| CryptoError::KeyDerivation)
}

/// Decrypt helper for tests only. The product never decrypts.
#[cfg(test)]
fn open(key: &SessionKey, iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes128Dec::new(&Key::<Aes128Dec>::from(*key.bytes));
    let decryptor =
        Decryptor::<Aes128Dec>::inner_iv_slice_init(cipher, iv).map_err(|_| CryptoError::Cipher)?;
    let mut buffer = ciphertext.to_vec();
    decryptor
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map(|plaintext| plaintext.to_vec())
        .map_err(|_| CryptoError::Cipher)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hex of `dh_group_1024_prime`, transcribed from gnome-keyring's
    /// `egg/egg-dh.c` lines 47-54.
    const PRIME_HEX: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1\
                             29024e088a67cc74020bbea63b139b22514a08798e3404dd\
                             ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245\
                             e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
                             ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381\
                             ffffffffffffffff";

    /// Fixed negotiation vector, computed independently with Python
    /// (int modpow + hashlib.hmac implementing RFC 5869 directly, no Rust
    /// crypto crates involved) on 2026-09-13. x and y are random 1023-bit
    /// exponents; X = 2^x, Y = 2^y, ikm = Y^x = X^y mod p (no leading zero
    /// bytes), key = HKDF-SHA256(ikm, salt empty, info empty, 16).
    const KAT_X: &str = "7f734c4f9283dd747064299f36f72de1b38a368c082d86c0860477a2b04ef243\
                         616e24236c7a5a04fbe9b3bdcfcfd11cfb88358ba37a800971378bf9d02caf6c\
                         08b35941721f8158978094e52f2689618041023fc397dfa2cfff184023fb4e69a\
                         6bb9ca3391de35bccddef2c05c8e74007ec8ebb58b57048d6c7b287edfa5017";
    const KAT_Y: &str = "5a7eac66f76a6e481efb4e546a76b380091c518d84c213a53e657e9ec1b40ac8\
                         1af5369cf20baaaa7aa27961f18d97533bde7e2b3dd7ddd32aba02221e00e9327\
                         6fc0b01b0a07ebafe213cd4bdd5e612f809e927ea5849407226372be8d3966885\
                         7ce48337445d6b141c3c557502a9b378cad0fdbe1dd6ae1542183315e7d83a";
    const KAT_PUBLIC_X: &str = "1b27c464ec336a9d30c64a6f5940886b699b0572bb42d8918b6ab7233d99b61c\
                                0d27b944b6cdb82c2ebef22341325db85389f16ac76d85042bd74d01ddd5e95\
                                fc19db8bb8e8749c6bb76b1248ac3d81e537ec9760c7e3071f277c299580074\
                                2f4b0ca096ab231782004a4835548b834d05ed0c9720ccf3f5645b30ffa9e9f\
                                5b5";
    const KAT_PUBLIC_Y: &str = "b215e010fd75eba0ad7ffc08574a8f107c9c5c22a4bb2efbc1ed69f939f7d7e8\
                                ebd00a90eb8101f5b737d273a80bf69e1842389e9894a44c7eb96da8bf493197\
                                3bee00782e99a1aed8b94150745e058e3fb32689f5f77463b2fbcf7cafb8d080\
                                5ce6b515d4a0b960983b077be96f14e47da2b8a76374bbbd079f3a204a182383";
    const KAT_IKM: &str = "b491b5751560c8b2de3be99b392ff20d1016d311bbf9587b0e2da42b11882729\
                           51d00b3e10c8577986a523e74fbbea4d1c7c71a3c434ad62ca698fc8031cb1d48\
                           b4f3aa174df4b199c21edf42ef62271d69f1c2c8c637d0e69849be3ab1ccb47db\
                           db52f0cde2ea7a3fef5019f2765bf947cbbf41b0986d08c4a85d3ec18f2e37";
    const KAT_KEY: &str = "f9845bc679edbac3de23bae88faf9208";

    /// Left-pad KAT: with peer public key 3 and private exponent 1 the
    /// shared secret is 3, whose minimal encoding is the single byte 0x03
    /// while the KDF input must be that byte left-padded to 128 bytes.
    /// Key values computed independently with Python as above.
    const SMALL_KEY_PADDED: &str = "4ef3e644a4c232ab12248a367b3aefed";
    const SMALL_KEY_UNPADDED: &str = "04c336e979b4fcd372cf6ef0ce0669e5";
    /// Second left-pad KAT: 5^4 = 625 = 0x271.
    const SMALL_KEY_625: &str = "b5606a7ee85d6f29e1224e900b43587c";

    fn unhex(value: &str) -> Vec<u8> {
        assert!(
            value.len().is_multiple_of(2),
            "hex literal must have even length"
        );
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("valid hex");
                let low = (pair[1] as char).to_digit(16).expect("valid hex");
                (high * 16 + low) as u8
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn keypair_from_hex(exponent: &str) -> ClientKeypair {
        ClientKeypair::from_private_exponent(&unhex(exponent))
    }

    fn session_key_from_bytes(bytes: [u8; AES_KEY_LEN]) -> SessionKey {
        SessionKey {
            bytes: Zeroizing::new(bytes),
        }
    }

    #[test]
    fn algorithm_string_matches_the_secret_service_protocol() {
        assert_eq!(ALGORITHM, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
    }

    /// Pins the group parameters byte-for-byte to gnome-keyring's egg-dh.c
    /// (adapted from the `/dh/default_1024` check in egg/test-dh.c) and to
    /// the structural shape of the RFC 2409 group 2 prime.
    #[test]
    fn prime_and_generator_match_gnome_keyring_egg_dh() {
        assert_eq!(hex(&PRIME_BYTES), PRIME_HEX);
        assert_eq!(PRIME_BYTES.len(), PRIME_LEN);
        // 2^1024 - 2^960 - 1 + 2^64 * floor(2^894 * pi + 129093): the top
        // and bottom 64 bits are all ones and the value is 1024 bits.
        assert_eq!(PRIME_BYTES[0], 0xFF);
        assert_eq!(PRIME_BYTES[..8], [0xFF; 8]);
        assert_eq!(PRIME_BYTES[120..], [0xFF; 8]);
        assert!(PRIME_BYTES[127] & 1 == 1, "prime must be odd");
        assert_eq!(GENERATOR, 0x02);
        assert_eq!(
            BoxedUint::from_be_slice_truncated(&PRIME_BYTES, DH_BITS).bits_vartime(),
            DH_BITS
        );
    }

    /// RFC 5869 test cases 1-3, adapted from gnome-keyring's
    /// egg/test-hkdf.c (which transcribes the RFC appendix). Case 3's
    /// empty salt and empty info is exactly the session-key configuration.
    #[test]
    fn hkdf_sha256_matches_rfc5869_vectors() {
        let ikm_1 = [0x0b; 22];
        let salt_1: [u8; 13] = core::array::from_fn(|index| index as u8);
        let info_1: [u8; 10] = core::array::from_fn(|index| 0xf0 + index as u8);
        let mut okm = [0u8; 42];
        hkdf_sha256(Some(&salt_1), &ikm_1, &info_1, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // RFC 5869 A.2 uses 80-byte inputs and an 82-byte output.
        let ikm_2: Vec<u8> = (0x00..=0x4f).collect();
        let salt_2: Vec<u8> = (0x60..=0xaf).collect();
        let info_2: Vec<u8> = (0xb0..=0xff).collect();
        let mut okm_2 = [0u8; 82];
        hkdf_sha256(Some(&salt_2), &ikm_2, &info_2, &mut okm_2).unwrap();
        assert_eq!(
            hex(&okm_2),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db\
             71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );

        // A.3 is the session-key configuration: empty salt, empty info.
        hkdf_sha256(None, &ikm_1, &[], &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn fixed_vector_negotiation_matches_independent_computation() {
        let client = keypair_from_hex(KAT_X);
        let server = keypair_from_hex(KAT_Y);

        // The public keys must reproduce the independently computed values.
        assert_eq!(hex(&client.public_key()), KAT_PUBLIC_X);
        assert_eq!(hex(&server.public_key()), KAT_PUBLIC_Y);

        // Both sides must arrive at the same AES key, and it must equal
        // HKDF over the independently computed shared secret.
        let client_key = client.derive_aes_key(&unhex(KAT_PUBLIC_Y)).unwrap();
        let server_key = server.derive_aes_key(&unhex(KAT_PUBLIC_X)).unwrap();
        let mut expected = [0u8; AES_KEY_LEN];
        hkdf_sha256(None, &unhex(KAT_IKM), &[], &mut expected).unwrap();
        assert_eq!(hex(expected.as_slice()), KAT_KEY);
        assert_eq!(client_key.as_slice(), expected.as_slice());
        assert_eq!(server_key.as_slice(), client_key.as_slice());
    }

    #[test]
    fn small_shared_secret_is_left_padded_to_prime_length() {
        // Peer public key 3, private exponent 1: shared secret 3.
        let client = keypair_from_hex("01");
        let key = client.derive_aes_key(&[0x03]).unwrap();

        let mut padded = vec![0u8; PRIME_LEN - 1];
        padded.push(0x03);
        let mut expected = [0u8; AES_KEY_LEN];
        hkdf_sha256(None, &padded, &[], &mut expected).unwrap();
        assert_eq!(key.as_slice(), expected.as_slice());
        assert_eq!(hex(key.as_slice()), SMALL_KEY_PADDED);

        // Deriving over the unpadded minimal encoding must yield a
        // different key: proves the normalization is load-bearing.
        let mut wrong = [0u8; AES_KEY_LEN];
        hkdf_sha256(None, &[0x03], &[], &mut wrong).unwrap();
        assert_eq!(hex(wrong.as_slice()), SMALL_KEY_UNPADDED);
        assert_ne!(key.as_slice(), wrong.as_slice());

        // 5^4 = 625 = 0x271 with 125 leading zero bytes.
        let client = keypair_from_hex("04");
        let key = client.derive_aes_key(&[0x05]).unwrap();
        assert_eq!(hex(key.as_slice()), SMALL_KEY_625);
    }

    /// Adapted from the `/dh/perform` agreement test in egg/test-dh.c: two
    /// fresh keypairs in the 1024-bit group must derive one shared key.
    #[test]
    fn two_fresh_keypairs_derive_the_same_key() {
        let client = ClientKeypair::generate().unwrap();
        let server = ClientKeypair::generate().unwrap();

        let client_key = client.derive_aes_key(&server.public_key()).unwrap();
        let server_key = server.derive_aes_key(&client.public_key()).unwrap();
        assert_eq!(client_key.as_slice(), server_key.as_slice());
    }

    #[test]
    fn generated_public_keys_use_minimal_big_endian_encoding() {
        for _ in 0..8 {
            let keypair = ClientKeypair::generate().unwrap();
            let public = keypair.public_key();
            assert!(!public.is_empty());
            assert!(public.len() <= PRIME_LEN);
            assert_ne!(public[0], 0, "encoding must be minimal");
            // A zero-padded 128-byte form of the same key must also be
            // accepted from a peer.
            let mut padded = vec![0u8; PRIME_LEN - public.len()];
            padded.extend_from_slice(&public);
            let peer = ClientKeypair::generate().unwrap();
            assert!(peer.derive_aes_key(&padded).is_ok());
        }
    }

    #[test]
    fn peer_public_keys_are_validated_before_derivation() {
        let client = ClientKeypair::generate().unwrap();
        let prime_minus_one_bytes = {
            let mut bytes = PRIME_BYTES;
            let mut carry = 1u16;
            for byte in bytes.iter_mut().rev() {
                let value = *byte as u16;
                let difference = value.wrapping_sub(carry);
                *byte = difference as u8;
                carry = difference >> 8;
            }
            bytes
        };

        // Empty, single zero byte, and a 128-byte zero encoding all decode
        // to 0 or nothing.
        assert!(matches!(
            client.derive_aes_key(&[]),
            Err(CryptoError::PeerPublicKeyLength { length: 0 })
        ));
        assert!(matches!(
            client.derive_aes_key(&[0x00]),
            Err(CryptoError::PeerPublicKeyOutOfRange)
        ));
        assert!(matches!(
            client.derive_aes_key(&[0u8; PRIME_LEN]),
            Err(CryptoError::PeerPublicKeyOutOfRange)
        ));
        // y = 1.
        assert!(matches!(
            client.derive_aes_key(&[0x01]),
            Err(CryptoError::PeerPublicKeyOutOfRange)
        ));
        // y = p - 1 and y = p.
        assert!(matches!(
            client.derive_aes_key(&prime_minus_one_bytes),
            Err(CryptoError::PeerPublicKeyOutOfRange)
        ));
        assert!(matches!(
            client.derive_aes_key(&PRIME_BYTES),
            Err(CryptoError::PeerPublicKeyOutOfRange)
        ));
        // Encodings longer than the prime are rejected by length before
        // any range reasoning.
        assert!(matches!(
            client.derive_aes_key(&[0x01; PRIME_LEN + 1]),
            Err(CryptoError::PeerPublicKeyLength { .. })
        ));
        // 0xff..ff is above p.
        assert!(matches!(
            client.derive_aes_key(&[0xFF; PRIME_LEN]),
            Err(CryptoError::PeerPublicKeyOutOfRange)
        ));
        // Valid values derive, including the smallest legal key.
        assert!(client.derive_aes_key(&[0x02]).is_ok());
    }

    #[test]
    fn sealed_secrets_have_pkcs7_shape_and_fresh_ivs() {
        let key = session_key_from_bytes([0x42; AES_KEY_LEN]);
        let plaintext = b"collection password";

        let sealed = seal(&key, plaintext).unwrap();
        assert_eq!(sealed.iv.len(), AES_KEY_LEN);
        assert_eq!(sealed.ciphertext.len() % AES_KEY_LEN, 0);
        assert!(sealed.ciphertext.len() > plaintext.len());
        assert_ne!(sealed.ciphertext, plaintext);

        // A second seal of the same plaintext must differ: fresh IV.
        let again = seal(&key, plaintext).unwrap();
        assert_ne!(sealed.iv.as_slice(), again.iv.as_slice());
        assert_ne!(sealed.ciphertext, again.ciphertext);

        // A 16-byte plaintext is exactly one block, so PKCS#7 must append
        // a full second block; an empty plaintext still pads one block.
        assert_eq!(seal(&key, &[0xAB; 16]).unwrap().ciphertext.len(), 32);
        assert_eq!(seal(&key, b"").unwrap().ciphertext.len(), 16);
        assert_eq!(seal(&key, &[0xCD; 17]).unwrap().ciphertext.len(), 32);
    }

    #[test]
    fn sealed_secrets_round_trip_through_the_test_decryptor() {
        for plaintext in [
            &b""[..],
            b"a",
            b"exactly-16-bytes!!",
            b"seventeen bytes ok!",
            &[0u8; 64][..],
            &[0xFF; 100][..],
        ] {
            let key = session_key_from_bytes(core::array::from_fn(|index| index as u8));
            let sealed = seal(&key, plaintext).unwrap();
            let recovered = open(&key, sealed.iv.as_slice(), &sealed.ciphertext).unwrap();
            assert_eq!(recovered.as_slice(), plaintext);
        }
    }

    #[test]
    fn sealed_secrets_do_not_decrypt_under_a_different_key() {
        let key = session_key_from_bytes([0x11; AES_KEY_LEN]);
        let other = session_key_from_bytes([0x22; AES_KEY_LEN]);
        let sealed = seal(&key, b"shared secret body").unwrap();
        assert!(open(&other, sealed.iv.as_slice(), &sealed.ciphertext).is_err());
    }
}
