//! Portable Carrack protocol core.
//!
//! Modules are intentionally orthogonal and contain no filesystem, socket,
//! runtime, provider, CLI, UI, or database dependency:
//! - [`integrity`] owns file, directory, metadata, and manifest identity.
//! - [`crypto`] owns key derivation and authenticated frame encoding.
//! - [`catalog`] owns complete checkpoint and delta closure verification.
//! - [`canonical`] owns context-free canonical wire-value parsing.
//! - [`acceptance`] composes public APIs only to prove native/WASM parity.

pub mod acceptance;
pub mod canonical;
pub mod catalog;
pub mod crypto;
pub mod error;
pub mod integrity;

pub use acceptance::{WasmAcceptanceProof, wasm_acceptance_proof};
pub use canonical::decode_lower_hex;
pub use catalog::{
    CATALOG_CHECKPOINT_SCHEMA, CATALOG_DELTA_SCHEMA, CatalogCheckpoint, CatalogCheckpointDirectory,
    CatalogCheckpointEntry, CatalogCheckpointEntryKind, CatalogDelta,
    MAXIMUM_CATALOG_CHECKPOINT_BYTES, MAXIMUM_CATALOG_DELTA_BYTES, MAXIMUM_CATALOG_DIRECTORIES,
    MAXIMUM_CATALOG_ENTRIES, apply_catalog_delta, build_catalog_delta, catalog_checkpoint_etag,
    catalog_checkpoint_view_etag, project_catalog_checkpoint, validate_catalog_checkpoint,
    validate_catalog_checkpoint_etag, validate_catalog_delta,
};
pub use crypto::{EncryptionDescriptor, FrameCipher, open, seal};
pub use error::Error;
pub use integrity::{
    BlockManifestExpectation, DirectoryMerkleAccumulator, DirectoryMerkleEntry,
    FileMerkleAccumulator, directory_merkle_root, empty_metadata_root, encode_block_manifest,
    file_block_digest, file_merkle_root, file_merkle_root_from_block_digests,
    validate_block_manifest,
};
