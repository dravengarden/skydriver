//! Authenticated encryption for disposable local metadata caches.
//!
//! This crate owns only a stable, token-scoped sealed-record primitive. It has
//! no VFS, Merkle, catalog, filesystem, async-runtime, database, network, or
//! provider knowledge. Cache policy and recovery belong to its caller.

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{AeadInPlace as _, generic_array::GenericArray},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const RECORD_PREFIX: &[u8] = b"skydriver.metadata-cache.v1\0";
const KEY_INFO: &[u8] = b"skydriver.metadata-cache-key.v1";
const AAD_DOMAIN: &[u8] = b"skydriver.metadata-cache-record.v1\0";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAXIMUM_CONTEXT_BYTES: usize = 4 * 1024;

/// Metadata-cache codec failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A context, bound, or record layout is invalid.
    #[error("invalid metadata cache record: {0}")]
    InvalidInput(&'static str),
    /// Key derivation or authenticated decryption failed.
    #[error("metadata cache authentication failed")]
    Authentication,
}

/// One authority-scoped metadata-cache record codec.
///
/// The key is derived from caller-provided secret and non-secret scope
/// identities. Neither input is serialized. Callers must supply a fresh random
/// nonce for every call to [`Self::seal`].
#[derive(Clone)]
pub struct MetadataCacheCipher {
    cipher: Aes256Gcm,
}

impl MetadataCacheCipher {
    /// Derives a cache-only key for one exact authority scope.
    ///
    /// # Errors
    ///
    /// Returns an error only when portable key derivation fails.
    pub fn new(secret: &[u8; 32], scope: &[u8; 16]) -> Result<Self, Error> {
        let hkdf = Hkdf::<Sha256>::new(Some(scope), secret);
        let mut key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(KEY_INFO, key.as_mut())
            .map_err(|_| Error::Authentication)?;
        Ok(Self {
            cipher: Aes256Gcm::new(GenericArray::from_slice(key.as_ref())),
        })
    }

    /// Seals one cache value and authenticates its logical context.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized context and authenticated-encryption
    /// failure. Nonce uniqueness is the caller's responsibility.
    pub fn seal(
        &self,
        context: &str,
        nonce: [u8; NONCE_BYTES],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let aad = record_aad(context)?;
        let mut ciphertext = plaintext.to_vec();
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ciphertext)
            .map_err(|_| Error::Authentication)?;
        let capacity = RECORD_PREFIX
            .len()
            .checked_add(NONCE_BYTES)
            .and_then(|length| length.checked_add(ciphertext.len()))
            .and_then(|length| length.checked_add(TAG_BYTES))
            .ok_or(Error::InvalidInput("record length overflows"))?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(RECORD_PREFIX);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        encoded.extend_from_slice(&tag);
        Ok(encoded)
    }

    /// Authenticates and opens one exact bounded cache value.
    ///
    /// # Errors
    ///
    /// Rejects another format version, wrong authority/context, truncation,
    /// oversized input, or any ciphertext modification.
    pub fn open(
        &self,
        context: &str,
        encoded: &[u8],
        maximum_plaintext_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        let aad = record_aad(context)?;
        let overhead = RECORD_PREFIX.len() + NONCE_BYTES + TAG_BYTES;
        if encoded.len() < overhead
            || encoded.len() > maximum_plaintext_bytes.saturating_add(overhead)
            || !encoded.starts_with(RECORD_PREFIX)
        {
            return Err(Error::InvalidInput("record layout is invalid"));
        }
        let nonce_start = RECORD_PREFIX.len();
        let ciphertext_start = nonce_start + NONCE_BYTES;
        let tag_start = encoded.len() - TAG_BYTES;
        let nonce = &encoded[nonce_start..ciphertext_start];
        let mut plaintext = encoded[ciphertext_start..tag_start].to_vec();
        let tag = GenericArray::from_slice(&encoded[tag_start..]);
        self.cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce), &aad, &mut plaintext, tag)
            .map_err(|_| Error::Authentication)?;
        Ok(plaintext)
    }

    /// Maximum encoded bytes for a bounded plaintext value.
    #[must_use]
    pub const fn maximum_encoded_bytes(maximum_plaintext_bytes: usize) -> usize {
        maximum_plaintext_bytes.saturating_add(RECORD_PREFIX.len() + NONCE_BYTES + TAG_BYTES)
    }
}

fn record_aad(context: &str) -> Result<Vec<u8>, Error> {
    if context.is_empty() || context.len() > MAXIMUM_CONTEXT_BYTES {
        return Err(Error::InvalidInput("context is invalid"));
    }
    let context_bytes = u32::try_from(context.len())
        .map_err(|_| Error::InvalidInput("context length overflows"))?;
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 4 + context.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(&context_bytes.to_be_bytes());
    aad.extend_from_slice(context.as_bytes());
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_and_binds_authority_context_and_bound() {
        let cipher = MetadataCacheCipher::new(&[1; 32], &[2; 16]).expect("cache cipher");
        let encoded = cipher
            .seal("node/abc", [3; 12], b"private metadata")
            .expect("seal cache record");
        assert_eq!(
            cipher
                .open("node/abc", &encoded, 16)
                .expect("open cache record"),
            b"private metadata"
        );
        assert!(cipher.open("node/other", &encoded, 16).is_err());
        assert!(cipher.open("node/abc", &encoded, 15).is_err());
        let other = MetadataCacheCipher::new(&[4; 32], &[2; 16]).expect("other cache cipher");
        assert!(other.open("node/abc", &encoded, 16).is_err());
    }

    #[test]
    fn record_rejects_tampering_and_unknown_versions() {
        let cipher = MetadataCacheCipher::new(&[1; 32], &[2; 16]).expect("cache cipher");
        let mut encoded = cipher
            .seal("head", [3; 12], b"metadata")
            .expect("seal cache record");
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(cipher.open("head", &encoded, 8).is_err());
        encoded[0] ^= 1;
        assert!(cipher.open("head", &encoded, 8).is_err());
    }
}
