//! Worker adapter for the portable Carrack integrity core.
//!
//! This module owns only the database-friendly, owned directory-entry shape.
//! Canonical parsing, validation, sorting, and Merkle computation belong to
//! `carrack-sdk-core`, which is shared with native clients and Worker WASM.

use carrack_sdk_core::{
    BlockManifestExpectation, DirectoryMerkleEntry, Error, decode_lower_hex, directory_merkle_root,
};

pub(crate) type Hash = [u8; 32];
pub(crate) type Identifier = [u8; 16];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryEntry {
    File {
        name: String,
        stable_id: Identifier,
        version_id: Identifier,
        size_bytes: u64,
        data_root: Hash,
        metadata_root: Hash,
    },
    Directory {
        name: String,
        stable_id: Identifier,
        data_root: Hash,
    },
}

pub(crate) fn directory_root(entries: &[DirectoryEntry]) -> Result<Hash, Error> {
    let portable = entries
        .iter()
        .map(|entry| match entry {
            DirectoryEntry::File {
                name,
                stable_id,
                version_id,
                size_bytes,
                data_root,
                metadata_root,
            } => DirectoryMerkleEntry::File {
                name,
                stable_id: *stable_id,
                version_id: *version_id,
                size_bytes: *size_bytes,
                data_root: *data_root,
                metadata_root: *metadata_root,
            },
            DirectoryEntry::Directory {
                name,
                stable_id,
                data_root,
            } => DirectoryMerkleEntry::Directory {
                name,
                stable_id: *stable_id,
                data_root: *data_root,
            },
        })
        .collect::<Vec<_>>();
    directory_merkle_root(&portable)
}

pub(crate) fn validate_block_manifest(
    encoded: &[u8],
    expected_size_bytes: u64,
    expected_block_bytes: u64,
    expected_blocks: u64,
    expected_root: Hash,
) -> Result<(), Error> {
    carrack_sdk_core::validate_block_manifest(
        encoded,
        BlockManifestExpectation {
            size_bytes: expected_size_bytes,
            block_bytes: expected_block_bytes,
            block_count: expected_blocks,
            file_root: expected_root,
        },
    )
}

pub(crate) fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], Error> {
    decode_lower_hex(encoded)
}
