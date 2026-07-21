//! Version-scoped key derivation and independently authenticated frames.

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{AeadInPlace as _, generic_array::GenericArray},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::Error;

const FILE_KEY_INFO: &[u8] = b"skydriver.vfs.file-key.v1";
const FRAME_AAD_DOMAIN: &[u8] = b"skydriver.vfs.file-frame.v1\0";

/// Descriptor for one immutable encrypted file version.
#[derive(Clone, Copy, Debug)]
pub struct EncryptionDescriptor {
    /// Stable opaque directory identity.
    pub directory_id: [u8; 16],
    /// Immutable opaque file-version identity.
    pub version_id: [u8; 16],
    /// Non-zero directory-key epoch.
    pub key_epoch: u64,
    /// Independently authenticated frame size.
    pub frame_bytes: u64,
}

/// Version-scoped authenticated frame codec.
///
/// The codec owns the only product implementation of file-key derivation,
/// nonce construction, frame layout, and AAD construction. I/O layers may
/// stream frames through it without learning those protocol rules.
pub struct FrameCipher {
    descriptor: EncryptionDescriptor,
    cipher: Aes256Gcm,
    next_seal_ordinal: u64,
}

impl FrameCipher {
    /// Derives one immutable version-scoped frame codec.
    ///
    /// # Errors
    ///
    /// Rejects an invalid descriptor or failed key derivation.
    pub fn new(descriptor: EncryptionDescriptor, directory_key: &[u8; 32]) -> Result<Self, Error> {
        validate_descriptor(descriptor)?;
        let mut salt = [0_u8; 32];
        salt[..16].copy_from_slice(&descriptor.directory_id);
        salt[16..].copy_from_slice(&descriptor.version_id);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), directory_key);
        let mut file_key = Zeroizing::new([0_u8; 32]);
        hkdf.expand(FILE_KEY_INFO, file_key.as_mut())
            .map_err(|_| Error::Crypto)?;
        Ok(Self {
            descriptor,
            cipher: Aes256Gcm::new(GenericArray::from_slice(file_key.as_ref())),
            next_seal_ordinal: 0,
        })
    }

    /// Encrypts one exact canonical plaintext frame in place.
    ///
    /// # Errors
    ///
    /// Rejects an ordinal or frame length inconsistent with the complete
    /// plaintext length.
    pub fn seal_frame(
        &mut self,
        ordinal: u64,
        total_plaintext_bytes: u64,
        frame: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        if ordinal != self.next_seal_ordinal {
            return Err(Error::InvalidInput(
                "encryption frames are not strictly ordered",
            ));
        }
        let frame_plaintext_bytes = self.validate_frame(
            ordinal,
            total_plaintext_bytes,
            u64::try_from(frame.len())
                .map_err(|_| Error::InvalidInput("frame length exceeds u64"))?,
        )?;
        let nonce = nonce(ordinal);
        let aad = frame_aad(
            self.descriptor,
            ordinal,
            frame_plaintext_bytes,
            total_plaintext_bytes,
        );
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, frame)
            .map(Into::into)
            .map_err(|_| Error::Crypto)?;
        self.next_seal_ordinal = self
            .next_seal_ordinal
            .checked_add(1)
            .ok_or(Error::InvalidInput("encryption frame ordinal overflows"))?;
        Ok(tag)
    }

    /// Authenticates and decrypts one exact canonical frame in place.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical layout or failed authentication.
    pub fn open_frame(
        &self,
        ordinal: u64,
        total_plaintext_bytes: u64,
        frame: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        let frame_plaintext_bytes = self.validate_frame(
            ordinal,
            total_plaintext_bytes,
            u64::try_from(frame.len())
                .map_err(|_| Error::InvalidInput("frame length exceeds u64"))?,
        )?;
        let nonce = nonce(ordinal);
        let aad = frame_aad(
            self.descriptor,
            ordinal,
            frame_plaintext_bytes,
            total_plaintext_bytes,
        );
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                frame,
                GenericArray::from_slice(tag),
            )
            .map_err(|_| Error::Crypto)
    }

    fn validate_frame(
        &self,
        ordinal: u64,
        total_plaintext_bytes: u64,
        actual_frame_bytes: u64,
    ) -> Result<u64, Error> {
        let offset = ordinal
            .checked_mul(self.descriptor.frame_bytes)
            .ok_or(Error::InvalidInput("frame offset overflows"))?;
        if offset >= total_plaintext_bytes {
            return Err(Error::InvalidInput("frame ordinal exceeds object"));
        }
        let expected = self
            .descriptor
            .frame_bytes
            .min(total_plaintext_bytes - offset);
        if actual_frame_bytes != expected {
            return Err(Error::InvalidInput("frame length differs"));
        }
        Ok(expected)
    }
}

/// Encrypts a complete in-memory object into independently authenticated frames.
///
/// # Errors
///
/// Returns an error for an invalid descriptor or failed key derivation.
pub fn seal(
    plaintext: &[u8],
    descriptor: EncryptionDescriptor,
    directory_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    validate_descriptor(descriptor)?;
    let mut cipher = FrameCipher::new(descriptor, directory_key)?;
    let frame_bytes = usize::try_from(descriptor.frame_bytes)
        .map_err(|_| Error::InvalidInput("frame size exceeds platform"))?;
    let mut encoded =
        Vec::with_capacity(plaintext.len() + plaintext.len().div_ceil(frame_bytes) * 16);
    for (ordinal, source) in plaintext.chunks(frame_bytes).enumerate() {
        let mut frame = Zeroizing::new(source.to_vec());
        let tag = cipher.seal_frame(ordinal as u64, plaintext.len() as u64, frame.as_mut())?;
        encoded.extend_from_slice(frame.as_ref());
        encoded.extend_from_slice(&tag);
    }
    Ok(encoded)
}

/// Authenticates and decrypts one complete in-memory encoded object.
///
/// # Errors
///
/// Returns an error for an invalid layout, key, tag, or trailing bytes.
pub fn open(
    encoded: &[u8],
    plaintext_bytes: u64,
    descriptor: EncryptionDescriptor,
    directory_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    validate_descriptor(descriptor)?;
    let plaintext_bytes = usize::try_from(plaintext_bytes)
        .map_err(|_| Error::InvalidInput("plaintext size exceeds platform"))?;
    let frame_bytes = usize::try_from(descriptor.frame_bytes)
        .map_err(|_| Error::InvalidInput("frame size exceeds platform"))?;
    let frame_count = plaintext_bytes.div_ceil(frame_bytes);
    let expected = plaintext_bytes
        .checked_add(
            frame_count
                .checked_mul(16)
                .ok_or(Error::InvalidInput("encoded size overflow"))?,
        )
        .ok_or(Error::InvalidInput("encoded size overflow"))?;
    if encoded.len() != expected {
        return Err(Error::InvalidInput("encoded object length mismatch"));
    }
    let cipher = FrameCipher::new(descriptor, directory_key)?;
    let mut decoded = Vec::with_capacity(plaintext_bytes);
    let mut offset = 0;
    for ordinal in 0..frame_count {
        let length = frame_bytes.min(plaintext_bytes - decoded.len());
        let mut frame = Zeroizing::new(encoded[offset..offset + length].to_vec());
        let tag = &encoded[offset + length..offset + length + 16];
        let tag: &[u8; 16] = tag
            .try_into()
            .map_err(|_| Error::InvalidInput("frame tag width differs"))?;
        cipher.open_frame(ordinal as u64, plaintext_bytes as u64, frame.as_mut(), tag)?;
        decoded.extend_from_slice(frame.as_ref());
        offset += length + 16;
    }
    Ok(decoded)
}

fn validate_descriptor(descriptor: EncryptionDescriptor) -> Result<(), Error> {
    if descriptor.key_epoch == 0 || descriptor.frame_bytes == 0 {
        return Err(Error::InvalidInput("invalid encryption descriptor"));
    }
    Ok(())
}

fn nonce(ordinal: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&ordinal.to_be_bytes());
    nonce
}

fn frame_aad(
    descriptor: EncryptionDescriptor,
    ordinal: u64,
    frame_plaintext_bytes: u64,
    total_plaintext_bytes: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_AAD_DOMAIN.len() + 64);
    aad.extend_from_slice(FRAME_AAD_DOMAIN);
    aad.extend_from_slice(&descriptor.directory_id);
    aad.extend_from_slice(&descriptor.version_id);
    aad.extend_from_slice(&descriptor.key_epoch.to_be_bytes());
    aad.extend_from_slice(&descriptor.frame_bytes.to_be_bytes());
    aad.extend_from_slice(&total_plaintext_bytes.to_be_bytes());
    aad.extend_from_slice(&ordinal.to_be_bytes());
    aad.extend_from_slice(&frame_plaintext_bytes.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::{EncryptionDescriptor, FrameCipher, open, seal};
    use crate::Error;

    #[test]
    fn round_trips_and_rejects_tampered_ciphertext() {
        let descriptor = EncryptionDescriptor {
            directory_id: [1; 16],
            version_id: [2; 16],
            key_epoch: 1,
            frame_bytes: 4,
        };
        let key = [3; 32];
        let mut encoded = seal(b"payload", descriptor, &key).expect("seal");
        assert_eq!(
            open(&encoded, 7, descriptor, &key).expect("open"),
            b"payload"
        );
        encoded[0] ^= 1;
        assert!(matches!(
            open(&encoded, 7, descriptor, &key),
            Err(Error::Crypto)
        ));
    }

    #[test]
    fn version_identity_separates_ciphertext_domains() {
        let key = [3; 32];
        let first = EncryptionDescriptor {
            directory_id: [1; 16],
            version_id: [2; 16],
            key_epoch: 1,
            frame_bytes: 4,
        };
        let second = EncryptionDescriptor {
            version_id: [4; 16],
            ..first
        };
        assert_ne!(
            seal(b"payload", first, &key).unwrap(),
            seal(b"payload", second, &key).unwrap()
        );
    }

    #[test]
    fn frame_codec_rejects_noncanonical_ordinal_and_length() {
        let descriptor = EncryptionDescriptor {
            directory_id: [1; 16],
            version_id: [2; 16],
            key_epoch: 1,
            frame_bytes: 4,
        };
        let mut cipher = FrameCipher::new(descriptor, &[3; 32]).expect("derive frame codec");
        let mut short_nonfinal = [0_u8; 3];
        assert!(cipher.seal_frame(0, 7, &mut short_nonfinal).is_err());
        let mut first = [0_u8; 4];
        cipher
            .seal_frame(0, 7, &mut first)
            .expect("seal first canonical frame");
        assert!(cipher.seal_frame(0, 7, &mut first).is_err());

        let mut cipher = FrameCipher::new(descriptor, &[3; 32]).expect("derive another codec");
        let mut past_end = [0_u8; 3];
        assert!(cipher.seal_frame(2, 7, &mut past_end).is_err());
    }
}
