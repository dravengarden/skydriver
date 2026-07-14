//! Portable Carrack integrity and cryptographic primitives.
//!
//! This crate has no filesystem, socket, runtime, or provider dependency. It
//! is the SDK layer shared by native clients and Cloudflare Worker WASM.

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{AeadInPlace as _, generic_array::GenericArray},
};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

const FILE_LEAF_DOMAIN: &[u8] = b"carrack.vfs.file.leaf.v1\0";
const FILE_EMPTY_DOMAIN: &[u8] = b"carrack.vfs.file.empty.v1\0";
const FILE_NODE_DOMAIN: &[u8] = b"carrack.vfs.file.node.v1\0";
const FILE_ROOT_DOMAIN: &[u8] = b"carrack.vfs.file.root.v1\0";
const FILE_KEY_INFO: &[u8] = b"carrack.vfs.file-key.v1";
const FRAME_AAD_DOMAIN: &[u8] = b"carrack.vfs.file-frame.v1\0";
const MAXIMUM_BLOCK_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_BLOCKS: usize = 1_000_000;

/// Portable SDK validation failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An input or derived layout violates a protocol bound.
    #[error("invalid Carrack SDK input: {0}")]
    InvalidInput(&'static str),
    /// Key derivation or authenticated encryption failed.
    #[error("Carrack SDK cryptographic verification failed")]
    Crypto,
}

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

/// Deterministic proof that the portable SDK executed inside its caller.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WasmAcceptanceProof {
    /// Stable response schema.
    pub schema: &'static str,
    /// Portable SDK implementation version.
    pub sdk_version: &'static str,
    /// Input byte length.
    pub plaintext_bytes: u64,
    /// Canonical Carrack file Merkle root.
    pub plaintext_merkle_root: String,
    /// SHA-256 of the encoded complete object.
    pub encoded_sha256: String,
    /// SHA-256 after authenticated decryption.
    pub decoded_sha256: String,
    /// True only when authenticated round-trip bytes are exact.
    pub round_trip_verified: bool,
}

/// Computes the canonical complete-file Merkle root for in-memory bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when block sizing exceeds protocol bounds.
pub fn file_merkle_root(payload: &[u8], block_bytes: u64) -> Result<[u8; 32], Error> {
    if block_bytes == 0 || block_bytes > MAXIMUM_BLOCK_BYTES {
        return Err(Error::InvalidInput("unsafe verification block size"));
    }
    let block_bytes = usize::try_from(block_bytes)
        .map_err(|_| Error::InvalidInput("block size exceeds platform"))?;
    let block_count = payload.len().div_ceil(block_bytes);
    if block_count > MAXIMUM_BLOCKS {
        return Err(Error::InvalidInput("verification block limit exceeded"));
    }
    let leaves = payload
        .chunks(block_bytes)
        .enumerate()
        .map(|(index, block)| hash_leaf(index as u64, block))
        .collect::<Vec<_>>();
    file_merkle_root_from_block_digests(payload.len() as u64, block_bytes as u64, &leaves)
}

/// Computes a file root from already verified ordered block digests.
///
/// Native streaming clients use this entry point so they do not buffer the
/// complete file, while WASM byte clients use [`file_merkle_root`].
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when sizing and digest count disagree.
pub fn file_merkle_root_from_block_digests(
    size_bytes: u64,
    block_bytes: u64,
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], Error> {
    if block_bytes == 0 || block_bytes > MAXIMUM_BLOCK_BYTES {
        return Err(Error::InvalidInput("unsafe verification block size"));
    }
    let expected_blocks = if size_bytes == 0 {
        0
    } else {
        1 + (size_bytes - 1) / block_bytes
    };
    if leaves.len() > MAXIMUM_BLOCKS || expected_blocks != leaves.len() as u64 {
        return Err(Error::InvalidInput("verification block count mismatch"));
    }
    let tree = if leaves.is_empty() {
        Sha256::digest(FILE_EMPTY_DOMAIN).into()
    } else {
        canonical_tree(leaves, 0)
    };
    let mut root = Sha256::new();
    root.update(FILE_ROOT_DOMAIN);
    root.update(block_bytes.to_be_bytes());
    root.update(size_bytes.to_be_bytes());
    root.update((leaves.len() as u64).to_be_bytes());
    root.update(tree);
    Ok(root.finalize().into())
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
    let cipher = cipher(descriptor, directory_key)?;
    let frame_bytes = usize::try_from(descriptor.frame_bytes)
        .map_err(|_| Error::InvalidInput("frame size exceeds platform"))?;
    let mut encoded =
        Vec::with_capacity(plaintext.len() + plaintext.len().div_ceil(frame_bytes) * 16);
    for (ordinal, source) in plaintext.chunks(frame_bytes).enumerate() {
        let mut frame = Zeroizing::new(source.to_vec());
        let nonce = nonce(ordinal as u64);
        let aad = frame_aad(
            descriptor,
            ordinal as u64,
            source.len() as u64,
            plaintext.len() as u64,
        );
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, frame.as_mut())
            .map_err(|_| Error::Crypto)?;
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
    let cipher = cipher(descriptor, directory_key)?;
    let mut decoded = Vec::with_capacity(plaintext_bytes);
    let mut offset = 0;
    for ordinal in 0..frame_count {
        let length = frame_bytes.min(plaintext_bytes - decoded.len());
        let mut frame = Zeroizing::new(encoded[offset..offset + length].to_vec());
        let tag = &encoded[offset + length..offset + length + 16];
        let nonce = nonce(ordinal as u64);
        let aad = frame_aad(
            descriptor,
            ordinal as u64,
            length as u64,
            plaintext_bytes as u64,
        );
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                &aad,
                frame.as_mut(),
                GenericArray::from_slice(tag),
            )
            .map_err(|_| Error::Crypto)?;
        decoded.extend_from_slice(frame.as_ref());
        offset += length + 16;
    }
    Ok(decoded)
}

/// Runs a deterministic Merkle and authenticated-encryption round trip.
///
/// This is intentionally provider- and credential-free so a deployed Worker
/// can prove that the same SDK core used by native clients executes as WASM.
///
/// # Errors
///
/// Returns an error if any integrity or authenticated-encryption step fails.
pub fn wasm_acceptance_proof(payload: &[u8]) -> Result<WasmAcceptanceProof, Error> {
    let descriptor = EncryptionDescriptor {
        directory_id: [0x11; 16],
        version_id: [0x22; 16],
        key_epoch: 1,
        frame_bytes: 4,
    };
    let mut key = Zeroizing::new([0x33_u8; 32]);
    let root = file_merkle_root(payload, 4)?;
    let encoded = seal(payload, descriptor, &key)?;
    let decoded = open(&encoded, payload.len() as u64, descriptor, &key)?;
    key.zeroize();
    let decoded_sha256 = Sha256::digest(&decoded);
    let proof = WasmAcceptanceProof {
        schema: "carrack.sdk.wasm-acceptance.v1",
        sdk_version: env!("CARGO_PKG_VERSION"),
        plaintext_bytes: payload.len() as u64,
        plaintext_merkle_root: hex::encode(root),
        encoded_sha256: hex::encode(Sha256::digest(&encoded)),
        decoded_sha256: hex::encode(decoded_sha256),
        round_trip_verified: decoded == payload,
    };
    if !proof.round_trip_verified {
        return Err(Error::Crypto);
    }
    Ok(proof)
}

fn validate_descriptor(descriptor: EncryptionDescriptor) -> Result<(), Error> {
    if descriptor.key_epoch == 0 || descriptor.frame_bytes == 0 {
        return Err(Error::InvalidInput("invalid encryption descriptor"));
    }
    Ok(())
}

fn cipher(descriptor: EncryptionDescriptor, directory_key: &[u8; 32]) -> Result<Aes256Gcm, Error> {
    let mut salt = [0_u8; 32];
    salt[..16].copy_from_slice(&descriptor.directory_id);
    salt[16..].copy_from_slice(&descriptor.version_id);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), directory_key);
    let mut file_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(FILE_KEY_INFO, file_key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(Aes256Gcm::new(GenericArray::from_slice(file_key.as_ref())))
}

fn hash_leaf(index: u64, payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FILE_LEAF_DOMAIN);
    hash.update(index.to_be_bytes());
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}

fn canonical_tree(leaves: &[[u8; 32]], first: u64) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut left_count = 1;
    while left_count <= (leaves.len() - 1) / 2 {
        left_count *= 2;
    }
    let left = canonical_tree(&leaves[..left_count], first);
    let right = canonical_tree(&leaves[left_count..], first + left_count as u64);
    let mut hash = Sha256::new();
    hash.update(FILE_NODE_DOMAIN);
    hash.update(first.to_be_bytes());
    hash.update((leaves.len() as u64).to_be_bytes());
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
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
    use super::*;

    #[test]
    fn matches_shared_abc_merkle_vector_and_round_trips() {
        let proof = wasm_acceptance_proof(b"abc").expect("portable proof");
        assert_eq!(
            proof.plaintext_merkle_root,
            "d60042cf44d28c3a12f278cffde67620f94f1a3e4c82208102da97b96cd5b4d9"
        );
        assert_eq!(
            proof.decoded_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(proof.round_trip_verified);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let descriptor = EncryptionDescriptor {
            directory_id: [1; 16],
            version_id: [2; 16],
            key_epoch: 1,
            frame_bytes: 4,
        };
        let key = [3; 32];
        let mut encoded = seal(b"payload", descriptor, &key).expect("seal");
        encoded[0] ^= 1;
        assert!(matches!(
            open(&encoded, 7, descriptor, &key),
            Err(Error::Crypto)
        ));
    }
}
