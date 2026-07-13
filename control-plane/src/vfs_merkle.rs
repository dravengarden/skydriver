#![allow(
    dead_code,
    reason = "V2 handlers will consume this canonical integrity format incrementally"
)]

use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;

const FILE_EMPTY_DOMAIN: &str = "carrack.vfs.file.empty.v1";
const FILE_NODE_DOMAIN: &str = "carrack.vfs.file.node.v1";
const FILE_ROOT_DOMAIN: &str = "carrack.vfs.file.root.v1";
const DIRECTORY_FILE_ENTRY_DOMAIN: &str = "carrack.vfs.directory.file-entry.v1";
const DIRECTORY_CHILD_ENTRY_DOMAIN: &str = "carrack.vfs.directory.child-entry.v1";
const DIRECTORY_EMPTY_DOMAIN: &str = "carrack.vfs.directory.empty.v1";
const DIRECTORY_NODE_DOMAIN: &str = "carrack.vfs.directory.node.v1";
const DIRECTORY_ROOT_DOMAIN: &str = "carrack.vfs.directory.root.v1";
const EMPTY_METADATA_DOMAIN: &str = "carrack.vfs.metadata.empty.v1";
const BLOCK_MANIFEST_DOMAIN: &str = "carrack.vfs.block-manifest.v1";
const MAXIMUM_FILE_BLOCKS: u64 = 1_000_000;
const MAXIMUM_DIRECTORY_ENTRIES: usize = 1_000_000;
const MAXIMUM_NAME_BYTES: usize = 255;

pub(crate) type Hash = [u8; 32];
pub(crate) type Identifier = [u8; 16];

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileBlock {
    index: u64,
    offset: u64,
    size_bytes: u64,
    digest: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileTree {
    size_bytes: u64,
    block_bytes: u64,
    blocks: Vec<FileBlock>,
    tree_digest: Hash,
    root: Hash,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct HashedDirectoryEntry {
    entry: DirectoryEntry,
    digest: Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryTree {
    entries: Vec<HashedDirectoryEntry>,
    tree_digest: Hash,
    root: Hash,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MerkleError {
    File(&'static str),
    Directory(&'static str),
    Manifest(&'static str),
    Hex(&'static str),
}

fn file_root_from_blocks(
    size_bytes: u64,
    block_bytes: u64,
    blocks: &[FileBlock],
) -> Result<FileTree, MerkleError> {
    if block_bytes == 0 {
        return Err(MerkleError::File("block size must be positive"));
    }

    let expected_count = expected_block_count(size_bytes, block_bytes);
    if expected_count > MAXIMUM_FILE_BLOCKS
        || usize::try_from(expected_count).ok() != Some(blocks.len())
    {
        return Err(MerkleError::File("block count differs"));
    }

    let mut leaves = Vec::with_capacity(blocks.len());
    for (position, block) in blocks.iter().enumerate() {
        let index =
            u64::try_from(position).map_err(|_| MerkleError::File("block index exceeds u64"))?;
        let expected_offset = index
            .checked_mul(block_bytes)
            .ok_or(MerkleError::File("block offset overflows"))?;
        let expected_length = block_bytes.min(size_bytes - expected_offset);

        if block.index != index
            || block.offset != expected_offset
            || block.size_bytes != expected_length
            || block.digest == [0; 32]
        {
            return Err(MerkleError::File("block layout is not canonical"));
        }

        leaves.push(block.digest);
    }

    let tree_digest = if leaves.is_empty() {
        hash_empty(FILE_EMPTY_DOMAIN)
    } else {
        build_canonical_tree(FILE_NODE_DOMAIN, &leaves, 0)?
    };

    let mut root_hasher = domain_hasher(FILE_ROOT_DOMAIN);
    update_u64(&mut root_hasher, block_bytes);
    update_u64(&mut root_hasher, size_bytes);
    update_u64(
        &mut root_hasher,
        u64::try_from(blocks.len()).map_err(|_| MerkleError::File("block count exceeds u64"))?,
    );
    root_hasher.update(tree_digest);

    Ok(FileTree {
        size_bytes,
        block_bytes,
        blocks: blocks.to_vec(),
        tree_digest,
        root: finish(root_hasher),
    })
}

fn build_directory(entries: &[DirectoryEntry]) -> Result<DirectoryTree, MerkleError> {
    if entries.len() > MAXIMUM_DIRECTORY_ENTRIES {
        return Err(MerkleError::Directory("entry count exceeds limit"));
    }

    let mut canonical = entries.to_vec();
    canonical.sort_by(|left, right| {
        entry_name(left)
            .as_bytes()
            .cmp(entry_name(right).as_bytes())
    });

    let mut hashed: Vec<HashedDirectoryEntry> = Vec::with_capacity(canonical.len());
    let mut leaves = Vec::with_capacity(canonical.len());

    for (index, entry) in canonical.into_iter().enumerate() {
        validate_directory_entry(&entry)?;
        if index != 0 && entry_name(&hashed[index - 1].entry) == entry_name(&entry) {
            return Err(MerkleError::Directory("duplicate entry name"));
        }

        let digest = hash_directory_entry(&entry)?;
        leaves.push(digest);
        hashed.push(HashedDirectoryEntry { entry, digest });
    }

    let tree_digest = if leaves.is_empty() {
        hash_empty(DIRECTORY_EMPTY_DOMAIN)
    } else {
        build_canonical_tree(DIRECTORY_NODE_DOMAIN, &leaves, 0)?
    };

    let mut root_hasher = domain_hasher(DIRECTORY_ROOT_DOMAIN);
    update_u64(
        &mut root_hasher,
        u64::try_from(leaves.len())
            .map_err(|_| MerkleError::Directory("entry count exceeds u64"))?,
    );
    root_hasher.update(tree_digest);

    Ok(DirectoryTree {
        entries: hashed,
        tree_digest,
        root: finish(root_hasher),
    })
}

pub(crate) fn directory_root(entries: &[DirectoryEntry]) -> Result<Hash, MerkleError> {
    Ok(build_directory(entries)?.root)
}

pub(crate) fn validate_block_manifest(
    encoded: &[u8],
    expected_size_bytes: u64,
    expected_block_bytes: u64,
    expected_blocks: u64,
    expected_root: Hash,
) -> Result<(), MerkleError> {
    let prefix_bytes = BLOCK_MANIFEST_DOMAIN.len() + 1;
    let fixed_bytes = prefix_bytes + 3 * 8 + 32;
    if encoded.len() < fixed_bytes
        || encoded.get(..BLOCK_MANIFEST_DOMAIN.len()) != Some(BLOCK_MANIFEST_DOMAIN.as_bytes())
        || encoded.get(BLOCK_MANIFEST_DOMAIN.len()) != Some(&0)
    {
        return Err(MerkleError::Manifest("domain or minimum length differs"));
    }

    let mut offset = prefix_bytes;
    let size_bytes = read_manifest_u64(encoded, &mut offset)?;
    let block_bytes = read_manifest_u64(encoded, &mut offset)?;
    let block_count = read_manifest_u64(encoded, &mut offset)?;
    if block_count > MAXIMUM_FILE_BLOCKS
        || usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_mul(32))
            .and_then(|digests| fixed_bytes.checked_add(digests))
            != Some(encoded.len())
        || block_bytes == 0
        || block_count != expected_block_count(size_bytes, block_bytes)
    {
        return Err(MerkleError::Manifest("layout or exact length differs"));
    }

    let mut blocks = Vec::with_capacity(
        usize::try_from(block_count)
            .map_err(|_| MerkleError::Manifest("block count exceeds usize"))?,
    );
    for index in 0..block_count {
        let end = offset
            .checked_add(32)
            .ok_or(MerkleError::Manifest("digest offset overflows"))?;
        let digest: Hash = encoded[offset..end]
            .try_into()
            .map_err(|_| MerkleError::Manifest("leaf digest is short"))?;
        if digest == [0; 32] {
            return Err(MerkleError::Manifest("leaf digest is zero"));
        }
        let block_offset = index
            .checked_mul(block_bytes)
            .ok_or(MerkleError::Manifest("block offset overflows"))?;
        blocks.push(FileBlock {
            index,
            offset: block_offset,
            size_bytes: block_bytes.min(size_bytes - block_offset),
            digest,
        });
        offset = end;
    }

    let embedded_root: Hash = encoded[offset..]
        .try_into()
        .map_err(|_| MerkleError::Manifest("embedded root length differs"))?;
    let tree = file_root_from_blocks(size_bytes, block_bytes, &blocks)?;
    if embedded_root != tree.root
        || size_bytes != expected_size_bytes
        || block_bytes != expected_block_bytes
        || block_count != expected_blocks
        || tree.root != expected_root
    {
        return Err(MerkleError::Manifest("declared file identity differs"));
    }

    Ok(())
}

fn read_manifest_u64(encoded: &[u8], offset: &mut usize) -> Result<u64, MerkleError> {
    let end = offset
        .checked_add(8)
        .ok_or(MerkleError::Manifest("integer offset overflows"))?;
    let value = u64::from_be_bytes(
        encoded
            .get(*offset..end)
            .ok_or(MerkleError::Manifest("integer is short"))?
            .try_into()
            .map_err(|_| MerkleError::Manifest("integer width differs"))?,
    );
    *offset = end;
    Ok(value)
}

fn validate_directory_entry(entry: &DirectoryEntry) -> Result<(), MerkleError> {
    let name = entry_name(entry);
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAXIMUM_NAME_BYTES
        || name.contains('/')
        || name.contains('\0')
        || !name.nfc().eq(name.chars())
    {
        return Err(MerkleError::Directory("name is not canonical NFC"));
    }

    match entry {
        DirectoryEntry::File {
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
                return Err(MerkleError::Directory("file entry omits identity"));
            }
        }
        DirectoryEntry::Directory {
            stable_id,
            data_root,
            ..
        } => {
            if *stable_id == [0; 16] || *data_root == [0; 32] {
                return Err(MerkleError::Directory("directory entry omits identity"));
            }
        }
    }

    Ok(())
}

fn hash_directory_entry(entry: &DirectoryEntry) -> Result<Hash, MerkleError> {
    let domain = match entry {
        DirectoryEntry::File { .. } => DIRECTORY_FILE_ENTRY_DOMAIN,
        DirectoryEntry::Directory { .. } => DIRECTORY_CHILD_ENTRY_DOMAIN,
    };
    let name = entry_name(entry);
    let mut hasher = domain_hasher(domain);
    update_u32(
        &mut hasher,
        u32::try_from(name.len()).map_err(|_| MerkleError::Directory("name exceeds u32"))?,
    );
    hasher.update(name.as_bytes());

    match entry {
        DirectoryEntry::File {
            stable_id,
            version_id,
            size_bytes,
            data_root,
            metadata_root,
            ..
        } => {
            hasher.update(stable_id);
            hasher.update(version_id);
            update_u64(&mut hasher, *size_bytes);
            hasher.update(data_root);
            hasher.update(metadata_root);
        }
        DirectoryEntry::Directory {
            stable_id,
            data_root,
            ..
        } => {
            hasher.update(stable_id);
            hasher.update(data_root);
        }
    }

    Ok(finish(hasher))
}

fn entry_name(entry: &DirectoryEntry) -> &str {
    match entry {
        DirectoryEntry::File { name, .. } | DirectoryEntry::Directory { name, .. } => name,
    }
}

fn build_canonical_tree(
    domain: &str,
    leaves: &[Hash],
    first_leaf: u64,
) -> Result<Hash, MerkleError> {
    if leaves.len() == 1 {
        return Ok(leaves[0]);
    }

    let left_count = largest_power_of_two_prefix(leaves.len());
    let left = build_canonical_tree(domain, &leaves[..left_count], first_leaf)?;
    let right_first = first_leaf
        .checked_add(
            u64::try_from(left_count)
                .map_err(|_| MerkleError::File("tree position exceeds u64"))?,
        )
        .ok_or(MerkleError::File("tree position overflows"))?;
    let right = build_canonical_tree(domain, &leaves[left_count..], right_first)?;

    let mut hasher = domain_hasher(domain);
    update_u64(&mut hasher, first_leaf);
    update_u64(
        &mut hasher,
        u64::try_from(leaves.len()).map_err(|_| MerkleError::File("tree count exceeds u64"))?,
    );
    hasher.update(left);
    hasher.update(right);

    Ok(finish(hasher))
}

fn largest_power_of_two_prefix(count: usize) -> usize {
    let mut prefix = 1;
    while prefix <= (count - 1) / 2 {
        prefix *= 2;
    }
    prefix
}

fn expected_block_count(size_bytes: u64, block_bytes: u64) -> u64 {
    if size_bytes == 0 {
        0
    } else {
        1 + (size_bytes - 1) / block_bytes
    }
}

fn empty_metadata_root() -> Hash {
    hash_empty(EMPTY_METADATA_DOMAIN)
}

fn hash_empty(domain: &str) -> Hash {
    finish(domain_hasher(domain))
}

fn domain_hasher(domain: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher
}

fn update_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_be_bytes());
}

fn update_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn finish(hasher: Sha256) -> Hash {
    hasher.finalize().into()
}

pub(crate) fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], MerkleError> {
    if encoded.len() != N * 2 {
        return Err(MerkleError::Hex("hex length differs"));
    }

    let mut decoded = [0_u8; N];
    for (index, destination) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        let pair = &encoded.as_bytes()[offset..offset + 2];
        *destination = decode_nibble(pair[0])?
            .checked_mul(16)
            .and_then(|high| high.checked_add(decode_nibble(pair[1]).ok()?))
            .ok_or(MerkleError::Hex("hex byte overflows"))?;
    }

    Ok(decoded)
}

fn decode_nibble(value: u8) -> Result<u8, MerkleError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(MerkleError::Hex("hex must be lowercase")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const GOLDEN: &str = include_str!("../../testdata/vfs-merkle-v1.json");
    const MANIFEST_GOLDEN: &str = include_str!("../../testdata/vfs-block-manifest-v1.json");
    const GOLDEN_SCHEMA: &str = "carrack.vfs-merkle.golden.v1";
    const FILE_LEAF_DOMAIN: &str = "carrack.vfs.file.leaf.v1";

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenVectors {
        schema: String,
        files: Vec<GoldenFileVector>,
        directories: Vec<GoldenDirectoryVector>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenFileVector {
        name: String,
        payload_hex: String,
        expected: GoldenFileTree,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenFileTree {
        size_bytes: u64,
        block_bytes: u64,
        blocks: Option<Vec<GoldenFileBlock>>,
        tree_digest: String,
        root: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenFileBlock {
        index: u64,
        offset: u64,
        size_bytes: u64,
        digest: String,
    }

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenEntry {
        name: String,
        kind: String,
        stable_id: String,
        version_id: Option<String>,
        #[serde(default)]
        size_bytes: u64,
        data_root: String,
        metadata_root: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenDirectoryVector {
        name: String,
        entries: Vec<GoldenEntry>,
        expected: GoldenDirectoryTree,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenDirectoryTree {
        entries: Vec<GoldenHashedEntry>,
        tree_digest: String,
        root: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenHashedEntry {
        entry: GoldenEntry,
        digest: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GoldenManifests {
        schema: String,
        manifests: Vec<GoldenManifest>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
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
    fn matches_shared_go_file_and_directory_vectors() {
        let vectors: GoldenVectors = serde_json::from_str(GOLDEN).expect("decode golden vectors");
        assert_eq!(vectors.schema, GOLDEN_SCHEMA);

        for vector in vectors.files {
            verify_file_vector(&vector)
                .unwrap_or_else(|error| panic!("file vector {} failed: {error:?}", vector.name));
        }

        for vector in vectors.directories {
            verify_directory_vector(&vector).unwrap_or_else(|error| {
                panic!("directory vector {} failed: {error:?}", vector.name)
            });
        }
    }

    #[test]
    fn matches_shared_go_block_manifest_vectors() {
        let vectors: GoldenManifests =
            serde_json::from_str(MANIFEST_GOLDEN).expect("decode manifest vectors");
        assert_eq!(vectors.schema, "carrack.vfs-block-manifest.golden.v1");

        for vector in vectors.manifests {
            let encoded = decode_variable_hex(&vector.manifest_hex)
                .unwrap_or_else(|error| panic!("manifest {} hex: {error:?}", vector.name));
            assert_eq!(
                lowercase_test_hex(&Sha256::digest(&encoded)),
                vector.sha256,
                "manifest {} SHA-256",
                vector.name
            );
            validate_block_manifest(
                &encoded,
                vector.size_bytes,
                vector.block_bytes,
                vector.block_count,
                decode_hex(&vector.file_root).expect("decode manifest root"),
            )
            .unwrap_or_else(|error| panic!("manifest {} failed: {error:?}", vector.name));
        }
    }

    #[test]
    fn rejects_decomposed_directory_name() {
        let entry = DirectoryEntry::Directory {
            name: "e\u{301}".to_owned(),
            stable_id: [1; 16],
            data_root: [2; 32],
        };
        assert!(matches!(
            build_directory(&[entry]),
            Err(MerkleError::Directory(_))
        ));
    }

    fn verify_file_vector(vector: &GoldenFileVector) -> Result<(), MerkleError> {
        let payload = decode_variable_hex(&vector.payload_hex)?;
        if u64::try_from(payload.len()).ok() != Some(vector.expected.size_bytes) {
            return Err(MerkleError::File("payload length differs"));
        }

        let expected_blocks = vector.expected.blocks.as_deref().unwrap_or_default();
        let mut blocks = Vec::with_capacity(expected_blocks.len());
        for expected in expected_blocks {
            let start = usize::try_from(expected.offset)
                .map_err(|_| MerkleError::File("offset exceeds usize"))?;
            let length = usize::try_from(expected.size_bytes)
                .map_err(|_| MerkleError::File("length exceeds usize"))?;
            let end = start
                .checked_add(length)
                .ok_or(MerkleError::File("payload range overflows"))?;
            let digest = hash_file_block(expected.index, &payload[start..end]);
            if digest != decode_hex::<32>(&expected.digest)? {
                return Err(MerkleError::File("leaf digest differs"));
            }

            blocks.push(FileBlock {
                index: expected.index,
                offset: expected.offset,
                size_bytes: expected.size_bytes,
                digest,
            });
        }

        let tree = file_root_from_blocks(
            vector.expected.size_bytes,
            vector.expected.block_bytes,
            &blocks,
        )?;
        if tree.tree_digest != decode_hex::<32>(&vector.expected.tree_digest)?
            || tree.root != decode_hex::<32>(&vector.expected.root)?
        {
            return Err(MerkleError::File("file root differs"));
        }

        Ok(())
    }

    fn verify_directory_vector(vector: &GoldenDirectoryVector) -> Result<(), MerkleError> {
        let entries = vector
            .entries
            .iter()
            .map(convert_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let tree = build_directory(&entries)?;
        if tree.tree_digest != decode_hex::<32>(&vector.expected.tree_digest)?
            || tree.root != decode_hex::<32>(&vector.expected.root)?
            || tree.entries.len() != vector.expected.entries.len()
        {
            return Err(MerkleError::Directory("directory root differs"));
        }

        for (actual, expected) in tree.entries.iter().zip(&vector.expected.entries) {
            if actual.entry != convert_entry(&expected.entry)?
                || actual.digest != decode_hex::<32>(&expected.digest)?
            {
                return Err(MerkleError::Directory("entry digest differs"));
            }
        }

        Ok(())
    }

    fn convert_entry(entry: &GoldenEntry) -> Result<DirectoryEntry, MerkleError> {
        let stable_id = decode_hex::<16>(&entry.stable_id)?;
        let data_root = decode_hex::<32>(&entry.data_root)?;
        match entry.kind.as_str() {
            "file" => Ok(DirectoryEntry::File {
                name: entry.name.clone(),
                stable_id,
                version_id: decode_hex::<16>(
                    entry
                        .version_id
                        .as_deref()
                        .ok_or(MerkleError::Directory("file version is missing"))?,
                )?,
                size_bytes: entry.size_bytes,
                data_root,
                metadata_root: decode_hex::<32>(
                    entry
                        .metadata_root
                        .as_deref()
                        .ok_or(MerkleError::Directory("file metadata is missing"))?,
                )?,
            }),
            "directory"
                if entry.version_id.is_none()
                    && entry.metadata_root.is_none()
                    && entry.size_bytes == 0 =>
            {
                Ok(DirectoryEntry::Directory {
                    name: entry.name.clone(),
                    stable_id,
                    data_root,
                })
            }
            _ => Err(MerkleError::Directory("entry kind is invalid")),
        }
    }

    fn hash_file_block(index: u64, payload: &[u8]) -> Hash {
        let mut hasher = domain_hasher(FILE_LEAF_DOMAIN);
        update_u64(&mut hasher, index);
        update_u64(
            &mut hasher,
            u64::try_from(payload.len()).expect("test payload length fits u64"),
        );
        hasher.update(payload);
        finish(hasher)
    }

    fn decode_variable_hex(encoded: &str) -> Result<Vec<u8>, MerkleError> {
        if !encoded.len().is_multiple_of(2) {
            return Err(MerkleError::Hex("hex length is odd"));
        }

        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                decode_nibble(pair[0])?
                    .checked_mul(16)
                    .and_then(|high| high.checked_add(decode_nibble(pair[1]).ok()?))
                    .ok_or(MerkleError::Hex("hex byte overflows"))
            })
            .collect()
    }

    fn lowercase_test_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[test]
    fn empty_metadata_domain_matches_shared_vector() {
        assert_eq!(
            empty_metadata_root(),
            decode_hex::<32>("7f8375a6dbb0bbb8aa2a4c5893444ec014588c02e59841088b1064646663bfc7")
                .expect("decode expected metadata root")
        );
    }
}
