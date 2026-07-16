//! Cross-module native/WASM acceptance proof.

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::{
    crypto::{EncryptionDescriptor, open, seal},
    error::Error,
    integrity::file_merkle_root,
};

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

/// Runs a deterministic Merkle and authenticated-encryption round trip.
///
/// This intentionally composes public module APIs rather than owning any
/// integrity or cryptographic rule itself.
///
/// # Errors
///
/// Returns an error if any module rejects the input or authenticated round trip.
pub fn wasm_acceptance_proof(payload: &[u8]) -> Result<WasmAcceptanceProof, Error> {
    let descriptor = EncryptionDescriptor {
        directory_id: [0x11; 16],
        version_id: [0x22; 16],
        key_epoch: 1,
        frame_bytes: 4,
    };
    let mut key = [0x33_u8; 32];
    let root = file_merkle_root(payload, 4)?;
    let encoded = seal(payload, descriptor, &key)?;
    let decoded = open(&encoded, payload.len() as u64, descriptor, &key)?;
    key.zeroize();
    let proof = WasmAcceptanceProof {
        schema: "carrack.sdk.wasm-acceptance.v1",
        sdk_version: env!("CARGO_PKG_VERSION"),
        plaintext_bytes: payload.len() as u64,
        plaintext_merkle_root: hex::encode(root),
        encoded_sha256: hex::encode(Sha256::digest(&encoded)),
        decoded_sha256: hex::encode(Sha256::digest(&decoded)),
        round_trip_verified: decoded == payload,
    };
    if !proof.round_trip_verified {
        return Err(Error::Crypto);
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::wasm_acceptance_proof;

    #[test]
    fn composes_exact_integrity_and_crypto_results() {
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
}
