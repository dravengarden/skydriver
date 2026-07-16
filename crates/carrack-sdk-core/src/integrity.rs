//! Canonical file, directory, metadata, and block-manifest identities.

use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;

use crate::error::Error;

const FILE_LEAF_DOMAIN: &[u8] = b"carrack.vfs.file.leaf.v1\0";
const FILE_EMPTY_DOMAIN: &[u8] = b"carrack.vfs.file.empty.v1\0";
const FILE_NODE_DOMAIN: &[u8] = b"carrack.vfs.file.node.v1\0";
const FILE_ROOT_DOMAIN: &[u8] = b"carrack.vfs.file.root.v1\0";
const DIRECTORY_FILE_ENTRY_DOMAIN: &[u8] = b"carrack.vfs.directory.file-entry.v1\0";
const DIRECTORY_CHILD_ENTRY_DOMAIN: &[u8] = b"carrack.vfs.directory.child-entry.v1\0";
const DIRECTORY_EMPTY_DOMAIN: &[u8] = b"carrack.vfs.directory.empty.v1\0";
const DIRECTORY_NODE_DOMAIN: &[u8] = b"carrack.vfs.directory.node.v1\0";
const DIRECTORY_ROOT_DOMAIN: &[u8] = b"carrack.vfs.directory.root.v1\0";
const BLOCK_MANIFEST_DOMAIN: &[u8] = b"carrack.vfs.block-manifest.v1\0";
const EMPTY_METADATA_DOMAIN: &[u8] = b"carrack.vfs.metadata.empty.v1\0";
const MAXIMUM_BLOCK_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_BLOCKS: usize = 1_000_000;
const MAXIMUM_DIRECTORY_ENTRIES: usize = 1_000_000;
const MAXIMUM_NAME_BYTES: usize = 255;

#[derive(Clone, Copy)]
struct FileSubtree {
    first: u64,
    leaves: u64,
    digest: [u8; 32],
}

/// Incrementally computes one canonical Carrack file Merkle root.
///
/// The accumulator retains only completed power-of-two subtree digests, so
/// memory is logarithmic in the number of verification blocks. Every block
/// except the final block must have exactly the configured size.
pub struct FileMerkleAccumulator {
    block_bytes: u64,
    size_bytes: u64,
    block_count: u64,
    final_block_seen: bool,
    subtrees: Vec<FileSubtree>,
}

impl FileMerkleAccumulator {
    /// Creates an empty accumulator for one positive bounded block size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for an unsafe block size.
    pub fn new(block_bytes: u64) -> Result<Self, Error> {
        if block_bytes == 0 || block_bytes > MAXIMUM_BLOCK_BYTES {
            return Err(Error::InvalidInput("unsafe verification block size"));
        }
        Ok(Self {
            block_bytes,
            size_bytes: 0,
            block_count: 0,
            final_block_seen: false,
            subtrees: Vec::new(),
        })
    }

    /// Adds the next exact plaintext verification block.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, out-of-order-after-final, or excessive
    /// blocks and arithmetic overflow.
    pub fn push_block(&mut self, payload: &[u8]) -> Result<(), Error> {
        let payload_bytes = payload.len() as u64;
        if payload_bytes == 0 || payload_bytes > self.block_bytes {
            return Err(Error::InvalidInput("invalid verification block length"));
        }
        if self.final_block_seen {
            return Err(Error::InvalidInput(
                "verification block follows final block",
            ));
        }
        if self.block_count >= MAXIMUM_BLOCKS as u64 {
            return Err(Error::InvalidInput("verification block limit exceeded"));
        }
        if payload_bytes < self.block_bytes {
            self.final_block_seen = true;
        }
        let index = self.block_count;
        self.block_count += 1;
        self.size_bytes = self
            .size_bytes
            .checked_add(payload_bytes)
            .ok_or(Error::InvalidInput("file size overflow"))?;
        let mut node = FileSubtree {
            first: index,
            leaves: 1,
            digest: hash_leaf(index, payload),
        };
        while self
            .subtrees
            .last()
            .is_some_and(|left| left.leaves == node.leaves)
        {
            let Some(left) = self.subtrees.pop() else {
                return Err(Error::InvalidInput("file Merkle subtree stack is empty"));
            };
            node = merge_file_subtrees(left, node)?;
        }
        self.subtrees.push(node);
        Ok(())
    }

    /// Finishes the exact file identity, including the empty-file root.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical block sequence or arithmetic overflow.
    pub fn finish(mut self) -> Result<[u8; 32], Error> {
        let expected_blocks = expected_block_count(self.size_bytes, self.block_bytes);
        if expected_blocks != self.block_count {
            return Err(Error::InvalidInput("verification block count mismatch"));
        }
        let tree = if let Some(mut right) = self.subtrees.pop() {
            while let Some(left) = self.subtrees.pop() {
                right = merge_file_subtrees(left, right)?;
            }
            right.digest
        } else {
            Sha256::digest(FILE_EMPTY_DOMAIN).into()
        };
        Ok(file_root(
            self.block_bytes,
            self.size_bytes,
            self.block_count,
            tree,
        ))
    }
}

/// Exact immutable identity proved by one canonical block manifest.
#[derive(Clone, Copy, Debug)]
pub struct BlockManifestExpectation {
    /// Complete plaintext byte length.
    pub size_bytes: u64,
    /// Canonical plaintext verification-block size.
    pub block_bytes: u64,
    /// Exact number of ordered verification blocks.
    pub block_count: u64,
    /// Expected complete plaintext Merkle root.
    pub file_root: [u8; 32],
}

/// One immutable entry committed by a canonical directory Merkle root.
#[derive(Clone, Copy, Debug)]
pub enum DirectoryMerkleEntry<'a> {
    /// One complete immutable file version.
    File {
        /// NFC entry name.
        name: &'a str,
        /// Stable file identity.
        stable_id: [u8; 16],
        /// Immutable file-version identity.
        version_id: [u8; 16],
        /// Plaintext file length.
        size_bytes: u64,
        /// Plaintext file Merkle root.
        data_root: [u8; 32],
        /// Portable metadata root.
        metadata_root: [u8; 32],
    },
    /// One child directory and its committed content root.
    Directory {
        /// NFC entry name.
        name: &'a str,
        /// Stable child-directory identity.
        stable_id: [u8; 16],
        /// Child directory Merkle root.
        data_root: [u8; 32],
    },
}

/// Incrementally authenticates one already name-ordered directory.
///
/// This permits revision-pinned pages to be verified without retaining an
/// entire wide directory in memory. The accumulator owns only the previous
/// bounded name and logarithmically many subtree digests.
pub struct DirectoryMerkleAccumulator {
    entry_count: u64,
    previous_name: Option<String>,
    subtrees: Vec<FileSubtree>,
}

impl DirectoryMerkleAccumulator {
    /// Creates an empty ordered-directory accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entry_count: 0,
            previous_name: None,
            subtrees: Vec::new(),
        }
    }

    /// Adds the next canonical entry in strictly increasing UTF-8 name order.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, duplicate/out-of-order names, excessive
    /// entries, and arithmetic overflow.
    pub fn push(&mut self, entry: &DirectoryMerkleEntry<'_>) -> Result<(), Error> {
        validate_directory_entry(entry)?;
        let name = entry_name(entry);
        if self
            .previous_name
            .as_deref()
            .is_some_and(|previous| previous.as_bytes() >= name.as_bytes())
        {
            return Err(Error::InvalidInput(
                "directory entries are not strictly ordered",
            ));
        }
        if self.entry_count >= MAXIMUM_DIRECTORY_ENTRIES as u64 {
            return Err(Error::InvalidInput("directory entry limit exceeded"));
        }
        let mut node = FileSubtree {
            first: self.entry_count,
            leaves: 1,
            digest: hash_directory_entry(entry)?,
        };
        self.entry_count += 1;
        while self
            .subtrees
            .last()
            .is_some_and(|left| left.leaves == node.leaves)
        {
            let Some(left) = self.subtrees.pop() else {
                return Err(Error::InvalidInput(
                    "directory Merkle subtree stack is empty",
                ));
            };
            node = merge_subtrees(DIRECTORY_NODE_DOMAIN, left, node)?;
        }
        self.subtrees.push(node);
        self.previous_name = Some(name.to_owned());
        Ok(())
    }

    /// Finishes the exact root for the complete ordered directory.
    ///
    /// # Errors
    ///
    /// Rejects arithmetic or internal adjacency inconsistencies.
    pub fn finish(mut self) -> Result<[u8; 32], Error> {
        let tree = if let Some(mut right) = self.subtrees.pop() {
            while let Some(left) = self.subtrees.pop() {
                right = merge_subtrees(DIRECTORY_NODE_DOMAIN, left, right)?;
            }
            right.digest
        } else {
            Sha256::digest(DIRECTORY_EMPTY_DOMAIN).into()
        };
        let mut root = Sha256::new();
        root.update(DIRECTORY_ROOT_DOMAIN);
        root.update(self.entry_count.to_be_bytes());
        root.update(tree);
        Ok(root.finalize().into())
    }
}

impl Default for DirectoryMerkleAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the canonical complete-file Merkle root for in-memory bytes.
///
/// # Errors
///
/// Rejects unsafe block sizing or an excessive number of blocks.
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
/// # Errors
///
/// Rejects unsafe sizing or a digest count inconsistent with the file length.
pub fn file_merkle_root_from_block_digests(
    size_bytes: u64,
    block_bytes: u64,
    leaves: &[[u8; 32]],
) -> Result<[u8; 32], Error> {
    if block_bytes == 0 || block_bytes > MAXIMUM_BLOCK_BYTES {
        return Err(Error::InvalidInput("unsafe verification block size"));
    }
    let expected_blocks = expected_block_count(size_bytes, block_bytes);
    if leaves.len() > MAXIMUM_BLOCKS || expected_blocks != leaves.len() as u64 {
        return Err(Error::InvalidInput("verification block count mismatch"));
    }
    let tree = if leaves.is_empty() {
        Sha256::digest(FILE_EMPTY_DOMAIN).into()
    } else {
        canonical_tree_with_domain(FILE_NODE_DOMAIN, leaves, 0)
    };
    Ok(file_root(
        block_bytes,
        size_bytes,
        leaves.len() as u64,
        tree,
    ))
}

/// Computes one canonical ordered plaintext block digest.
#[must_use]
pub fn file_block_digest(index: u64, payload: &[u8]) -> [u8; 32] {
    hash_leaf(index, payload)
}

/// Encodes one canonical block manifest and its independently derived root.
///
/// # Errors
///
/// Rejects unsafe sizing, inconsistent or zero digests, and length overflow.
pub fn encode_block_manifest(
    size_bytes: u64,
    block_bytes: u64,
    leaves: &[[u8; 32]],
) -> Result<Vec<u8>, Error> {
    if leaves.contains(&[0; 32]) {
        return Err(Error::InvalidInput("block manifest digest is zero"));
    }
    let root = file_merkle_root_from_block_digests(size_bytes, block_bytes, leaves)?;
    let capacity = BLOCK_MANIFEST_DOMAIN
        .len()
        .checked_add(3 * 8 + 32)
        .and_then(|fixed| fixed.checked_add(leaves.len().checked_mul(32)?))
        .ok_or(Error::InvalidInput("block manifest length overflows"))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(BLOCK_MANIFEST_DOMAIN);
    encoded.extend_from_slice(&size_bytes.to_be_bytes());
    encoded.extend_from_slice(&block_bytes.to_be_bytes());
    encoded.extend_from_slice(&(leaves.len() as u64).to_be_bytes());
    for digest in leaves {
        encoded.extend_from_slice(digest);
    }
    encoded.extend_from_slice(&root);
    Ok(encoded)
}

/// Validates one complete canonical block manifest against an exact version.
///
/// # Errors
///
/// Rejects malformed, noncanonical, oversized, inconsistent, or mismatched input.
pub fn validate_block_manifest(
    encoded: &[u8],
    expected: BlockManifestExpectation,
) -> Result<(), Error> {
    let fixed_bytes = BLOCK_MANIFEST_DOMAIN
        .len()
        .checked_add(3 * 8 + 32)
        .ok_or(Error::InvalidInput("block manifest length overflow"))?;
    if encoded.len() < fixed_bytes || !encoded.starts_with(BLOCK_MANIFEST_DOMAIN) {
        return Err(Error::InvalidInput(
            "block manifest domain or length differs",
        ));
    }
    let mut offset = BLOCK_MANIFEST_DOMAIN.len();
    let size_bytes = read_u64(encoded, &mut offset)?;
    let block_bytes = read_u64(encoded, &mut offset)?;
    let block_count = read_u64(encoded, &mut offset)?;
    let digest_bytes = usize::try_from(block_count)
        .ok()
        .and_then(|count| count.checked_mul(32))
        .ok_or(Error::InvalidInput(
            "block manifest digest length overflows",
        ))?;
    if block_count > MAXIMUM_BLOCKS as u64
        || fixed_bytes.checked_add(digest_bytes) != Some(encoded.len())
        || size_bytes != expected.size_bytes
        || block_bytes != expected.block_bytes
        || block_count != expected.block_count
    {
        return Err(Error::InvalidInput("block manifest layout differs"));
    }
    let mut leaves = Vec::with_capacity(digest_bytes / 32);
    for _ in 0..block_count {
        let end = offset.checked_add(32).ok_or(Error::InvalidInput(
            "block manifest digest offset overflows",
        ))?;
        let digest: [u8; 32] = encoded
            .get(offset..end)
            .ok_or(Error::InvalidInput("block manifest digest is short"))?
            .try_into()
            .map_err(|_| Error::InvalidInput("block manifest digest width differs"))?;
        if digest == [0; 32] {
            return Err(Error::InvalidInput("block manifest digest is zero"));
        }
        leaves.push(digest);
        offset = end;
    }
    let embedded_root: [u8; 32] = encoded
        .get(offset..)
        .ok_or(Error::InvalidInput("block manifest root is missing"))?
        .try_into()
        .map_err(|_| Error::InvalidInput("block manifest root width differs"))?;
    let root = file_merkle_root_from_block_digests(size_bytes, block_bytes, &leaves)?;
    if embedded_root != root || root != expected.file_root {
        return Err(Error::InvalidInput("block manifest root differs"));
    }
    Ok(())
}

/// Computes the canonical Merkle root for a complete directory node.
///
/// # Errors
///
/// Rejects malformed names, zero identities, duplicates, and excessive entries.
pub fn directory_merkle_root(entries: &[DirectoryMerkleEntry<'_>]) -> Result<[u8; 32], Error> {
    if entries.len() > MAXIMUM_DIRECTORY_ENTRIES {
        return Err(Error::InvalidInput("directory entry limit exceeded"));
    }
    let mut canonical = entries.to_vec();
    canonical.sort_by(|left, right| {
        entry_name(left)
            .as_bytes()
            .cmp(entry_name(right).as_bytes())
    });
    let mut accumulator = DirectoryMerkleAccumulator::new();
    for entry in &canonical {
        accumulator.push(entry)?;
    }
    accumulator.finish()
}

/// Returns the canonical metadata root for an entry with no portable metadata.
#[must_use]
pub fn empty_metadata_root() -> [u8; 32] {
    Sha256::digest(EMPTY_METADATA_DOMAIN).into()
}

fn file_root(block_bytes: u64, size_bytes: u64, block_count: u64, tree: [u8; 32]) -> [u8; 32] {
    let mut root = Sha256::new();
    root.update(FILE_ROOT_DOMAIN);
    root.update(block_bytes.to_be_bytes());
    root.update(size_bytes.to_be_bytes());
    root.update(block_count.to_be_bytes());
    root.update(tree);
    root.finalize().into()
}

fn hash_leaf(index: u64, payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FILE_LEAF_DOMAIN);
    hash.update(index.to_be_bytes());
    hash.update((payload.len() as u64).to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}

fn expected_block_count(size_bytes: u64, block_bytes: u64) -> u64 {
    if size_bytes == 0 {
        0
    } else {
        1 + (size_bytes - 1) / block_bytes
    }
}

fn read_u64(encoded: &[u8], offset: &mut usize) -> Result<u64, Error> {
    let end = offset
        .checked_add(8)
        .ok_or(Error::InvalidInput("encoded integer offset overflows"))?;
    let value = u64::from_be_bytes(
        encoded
            .get(*offset..end)
            .ok_or(Error::InvalidInput("encoded integer is short"))?
            .try_into()
            .map_err(|_| Error::InvalidInput("encoded integer width differs"))?,
    );
    *offset = end;
    Ok(value)
}

fn merge_file_subtrees(left: FileSubtree, right: FileSubtree) -> Result<FileSubtree, Error> {
    merge_subtrees(FILE_NODE_DOMAIN, left, right)
}

fn merge_subtrees(
    domain: &[u8],
    left: FileSubtree,
    right: FileSubtree,
) -> Result<FileSubtree, Error> {
    if left.first.checked_add(left.leaves) != Some(right.first) {
        return Err(Error::InvalidInput("file Merkle subtrees are not adjacent"));
    }
    let leaves = left
        .leaves
        .checked_add(right.leaves)
        .ok_or(Error::InvalidInput("verification block count overflow"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(left.first.to_be_bytes());
    hash.update(leaves.to_be_bytes());
    hash.update(left.digest);
    hash.update(right.digest);
    Ok(FileSubtree {
        first: left.first,
        leaves,
        digest: hash.finalize().into(),
    })
}

fn canonical_tree_with_domain(domain: &[u8], leaves: &[[u8; 32]], first: u64) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut left_count = 1;
    while left_count <= (leaves.len() - 1) / 2 {
        left_count *= 2;
    }
    let left = canonical_tree_with_domain(domain, &leaves[..left_count], first);
    let right =
        canonical_tree_with_domain(domain, &leaves[left_count..], first + left_count as u64);
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(first.to_be_bytes());
    hash.update((leaves.len() as u64).to_be_bytes());
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

fn validate_directory_entry(entry: &DirectoryMerkleEntry<'_>) -> Result<(), Error> {
    let name = entry_name(entry);
    if name.is_empty()
        || name.len() > MAXIMUM_NAME_BYTES
        || name == "."
        || name == ".."
        || name.contains(['/', '\0'])
        || !name.nfc().eq(name.chars())
    {
        return Err(Error::InvalidInput("directory entry name is not canonical"));
    }
    match entry {
        DirectoryMerkleEntry::File {
            stable_id,
            version_id,
            data_root,
            metadata_root,
            ..
        } => {
            if *stable_id == [0; 16]
                || *version_id == [0; 16]
                || *data_root == [0; 32]
                || *metadata_root == [0; 32]
            {
                return Err(Error::InvalidInput("file directory entry identity is zero"));
            }
        }
        DirectoryMerkleEntry::Directory {
            stable_id,
            data_root,
            ..
        } => {
            if *stable_id == [0; 16] || *data_root == [0; 32] {
                return Err(Error::InvalidInput(
                    "child directory entry identity is zero",
                ));
            }
        }
    }
    Ok(())
}

fn entry_name<'a>(entry: &'a DirectoryMerkleEntry<'a>) -> &'a str {
    match entry {
        DirectoryMerkleEntry::File { name, .. } | DirectoryMerkleEntry::Directory { name, .. } => {
            name
        }
    }
}

fn hash_directory_entry(entry: &DirectoryMerkleEntry<'_>) -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    match entry {
        DirectoryMerkleEntry::File { .. } => hash.update(DIRECTORY_FILE_ENTRY_DOMAIN),
        DirectoryMerkleEntry::Directory { .. } => hash.update(DIRECTORY_CHILD_ENTRY_DOMAIN),
    }
    let name = entry_name(entry);
    hash.update(
        u32::try_from(name.len())
            .map_err(|_| Error::InvalidInput("directory entry name exceeds u32"))?
            .to_be_bytes(),
    );
    hash.update(name.as_bytes());
    match entry {
        DirectoryMerkleEntry::File {
            stable_id,
            version_id,
            size_bytes,
            data_root,
            metadata_root,
            ..
        } => {
            hash.update(stable_id);
            hash.update(version_id);
            hash.update(size_bytes.to_be_bytes());
            hash.update(data_root);
            hash.update(metadata_root);
        }
        DirectoryMerkleEntry::Directory {
            stable_id,
            data_root,
            ..
        } => {
            hash.update(stable_id);
            hash.update(data_root);
        }
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_lower_hex;
    use serde::Deserialize;

    const MANIFEST_GOLDEN: &str = include_str!("../../../testdata/vfs-block-manifest-v1.json");

    #[derive(Deserialize)]
    struct GoldenManifests {
        schema: String,
        manifests: Vec<GoldenManifest>,
    }
    #[derive(Deserialize)]
    struct GoldenManifest {
        name: String,
        manifest_hex: String,
        sha256: String,
        size_bytes: u64,
        block_bytes: u64,
        block_count: u64,
        file_root: String,
    }

    #[test]
    fn incremental_matches_batch_for_every_tree_shape() {
        for length in 0_u8..64 {
            let payload = (0..length).collect::<Vec<_>>();
            let mut accumulator = FileMerkleAccumulator::new(4).expect("accumulator");
            for block in payload.chunks(4) {
                accumulator.push_block(block).expect("block");
            }
            assert_eq!(
                accumulator.finish().unwrap(),
                file_merkle_root(&payload, 4).unwrap()
            );
        }
    }

    #[test]
    fn manifest_vectors_are_exact_and_tampering_fails() {
        let vectors: GoldenManifests = serde_json::from_str(MANIFEST_GOLDEN).unwrap();
        assert_eq!(vectors.schema, "carrack.vfs-block-manifest.golden.v1");
        for vector in vectors.manifests {
            let encoded = hex::decode(&vector.manifest_hex).unwrap();
            assert_eq!(hex::encode(Sha256::digest(&encoded)), vector.sha256);
            let expected = BlockManifestExpectation {
                size_bytes: vector.size_bytes,
                block_bytes: vector.block_bytes,
                block_count: vector.block_count,
                file_root: decode_lower_hex(&vector.file_root).unwrap(),
            };
            validate_block_manifest(&encoded, expected)
                .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
            let mut tampered = encoded;
            tampered[0] ^= 1;
            assert!(validate_block_manifest(&tampered, expected).is_err());
        }
    }

    #[test]
    fn directory_identity_rejects_noncanonical_and_duplicate_names() {
        let decomposed = DirectoryMerkleEntry::Directory {
            name: "e\u{301}",
            stable_id: [1; 16],
            data_root: [2; 32],
        };
        assert!(directory_merkle_root(&[decomposed]).is_err());
        let duplicate = DirectoryMerkleEntry::Directory {
            name: "docs",
            stable_id: [1; 16],
            data_root: [2; 32],
        };
        assert!(directory_merkle_root(&[duplicate, duplicate]).is_err());
    }

    #[test]
    fn streaming_directory_matches_batch_and_rejects_page_reordering() {
        let first = DirectoryMerkleEntry::Directory {
            name: "a",
            stable_id: [1; 16],
            data_root: [2; 32],
        };
        let second = DirectoryMerkleEntry::Directory {
            name: "b",
            stable_id: [3; 16],
            data_root: [4; 32],
        };
        let mut streaming = DirectoryMerkleAccumulator::new();
        streaming.push(&first).unwrap();
        streaming.push(&second).unwrap();
        assert_eq!(
            streaming.finish().unwrap(),
            directory_merkle_root(&[second, first]).unwrap()
        );

        let mut reordered = DirectoryMerkleAccumulator::new();
        reordered.push(&second).unwrap();
        assert!(reordered.push(&first).is_err());
    }

    #[test]
    fn streaming_directory_keeps_logarithmic_state_at_one_hundred_thousand_entries() {
        let mut streaming = DirectoryMerkleAccumulator::new();
        for index in 0..100_000_u64 {
            let name = format!("entry-{index:06}");
            streaming
                .push(&DirectoryMerkleEntry::Directory {
                    name: &name,
                    stable_id: index
                        .saturating_add(1)
                        .to_be_bytes()
                        .repeat(2)
                        .try_into()
                        .unwrap(),
                    data_root: Sha256::digest(index.to_be_bytes()).into(),
                })
                .expect("append ordered wide-directory entry");
            assert!(streaming.subtrees.len() <= 17);
        }
        assert_ne!(streaming.finish().expect("finish wide directory"), [0; 32]);
    }

    #[test]
    #[ignore = "explicit million-entry scale acceptance"]
    fn streaming_directory_accepts_one_million_entries_with_logarithmic_state() {
        let mut streaming = DirectoryMerkleAccumulator::new();
        for index in 0..1_000_000_u64 {
            let name = format!("entry-{index:06}");
            streaming
                .push(&DirectoryMerkleEntry::Directory {
                    name: &name,
                    stable_id: index
                        .saturating_add(1)
                        .to_be_bytes()
                        .repeat(2)
                        .try_into()
                        .unwrap(),
                    data_root: Sha256::digest(index.to_be_bytes()).into(),
                })
                .expect("append million-entry directory");
            assert!(streaming.subtrees.len() <= 20);
        }
        assert_ne!(streaming.finish().expect("finish million entries"), [0; 32]);
    }
}
