//! Deterministic Carrack epoch and pack key derivation.

use std::{error::Error, fmt};

use hkdf::Hkdf;
use sha2::Sha256;

const ROOT_KEY_BYTES: usize = 32;
const EPOCH_KEY_BYTES: usize = 32;
const PACK_KEY_BYTES: usize = 16;
const IDENTIFIER_BYTES: usize = 16;
const EPOCH_KEY_INFO: &[u8] = b"carrack/epoch-key/v1";
const PACK_KEY_INFO: &[u8] = b"carrack/pack-key/v1";

/// Reports a missing key context or impossible HKDF output length.
#[derive(Debug, Eq, PartialEq)]
pub enum KeyDerivationError {
    /// A secret key or identifier was entirely zero.
    ZeroContext(&'static str),
    /// The selected HKDF could not produce the fixed V1 output length.
    InvalidOutputLength,
}

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroContext(name) => write!(formatter, "{name} must not be zero"),
            Self::InvalidOutputLength => formatter.write_str("HKDF output length is invalid"),
        }
    }
}

impl Error for KeyDerivationError {}

/// Derives one namespace epoch key from a versioned root seed.
///
/// # Errors
///
/// Returns [`KeyDerivationError`] when the root key or namespace identifier is
/// zero, or when HKDF rejects the fixed V1 output length.
pub fn derive_epoch_key(
    root_key: &[u8; ROOT_KEY_BYTES],
    namespace_id: &[u8; IDENTIFIER_BYTES],
    epoch_id: u64,
) -> Result<[u8; EPOCH_KEY_BYTES], KeyDerivationError> {
    reject_zero(root_key, "root key")?;
    reject_zero(namespace_id, "namespace ID")?;

    let mut salt = [0_u8; IDENTIFIER_BYTES + size_of::<u64>()];
    salt[..IDENTIFIER_BYTES].copy_from_slice(namespace_id);
    salt[IDENTIFIER_BYTES..].copy_from_slice(&epoch_id.to_be_bytes());

    expand(root_key, &salt, EPOCH_KEY_INFO)
}

/// Derives one AES-128 pack key from an authorized epoch key.
///
/// # Errors
///
/// Returns [`KeyDerivationError`] when the epoch key or pack identifier is
/// zero, or when HKDF rejects the fixed V1 output length.
pub fn derive_pack_key(
    epoch_key: &[u8; EPOCH_KEY_BYTES],
    pack_id: &[u8; IDENTIFIER_BYTES],
) -> Result<[u8; PACK_KEY_BYTES], KeyDerivationError> {
    reject_zero(epoch_key, "epoch key")?;
    reject_zero(pack_id, "pack ID")?;

    expand(epoch_key, pack_id, PACK_KEY_INFO)
}

fn expand<const OUTPUT_BYTES: usize>(
    input_key: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; OUTPUT_BYTES], KeyDerivationError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key);
    let mut output = [0_u8; OUTPUT_BYTES];
    hkdf.expand(info, &mut output)
        .map_err(|_| KeyDerivationError::InvalidOutputLength)?;

    Ok(output)
}

fn reject_zero(value: &[u8], name: &'static str) -> Result<(), KeyDerivationError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(KeyDerivationError::ZeroContext(name));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::Deserialize;

    use super::{derive_epoch_key, derive_pack_key};

    #[derive(Deserialize)]
    struct CryptoVector {
        suite: String,
        root_seed_base64: String,
        namespace_id_base64: String,
        epoch_id: u64,
        pack_id_base64: String,
        epoch_key_base64: String,
        pack_key_base64: String,
    }

    #[test]
    fn matches_shared_go_vector() {
        let vector: CryptoVector =
            serde_json::from_str(include_str!("../../schemas/crypto-v1-vectors.json"))
                .expect("shared crypto vector must be valid JSON");
        assert_eq!(vector.suite, "carrack-aes128gcm-hkdfsha256-v1");

        let root_key = decode_array(&vector.root_seed_base64);
        let namespace_id = decode_array(&vector.namespace_id_base64);
        let pack_id = decode_array(&vector.pack_id_base64);

        let epoch_key = derive_epoch_key(&root_key, &namespace_id, vector.epoch_id)
            .expect("epoch derivation must succeed");
        let pack_key = derive_pack_key(&epoch_key, &pack_id).expect("pack derivation must succeed");

        assert_eq!(STANDARD.encode(epoch_key), vector.epoch_key_base64);
        assert_eq!(STANDARD.encode(pack_key), vector.pack_key_base64);
    }

    #[test]
    fn rejects_zero_contexts() {
        let nonzero_root = [1_u8; 32];
        let nonzero_id = [1_u8; 16];

        assert!(derive_epoch_key(&[0_u8; 32], &nonzero_id, 0).is_err());
        assert!(derive_epoch_key(&nonzero_root, &[0_u8; 16], 0).is_err());
        assert!(derive_pack_key(&[0_u8; 32], &nonzero_id).is_err());
        assert!(derive_pack_key(&nonzero_root, &[0_u8; 16]).is_err());
    }

    fn decode_array<const BYTES: usize>(encoded: &str) -> [u8; BYTES] {
        STANDARD
            .decode(encoded)
            .expect("vector value must be base64")
            .try_into()
            .expect("vector value must have fixed length")
    }
}
