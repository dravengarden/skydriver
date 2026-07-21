//! Canonical Skydriver file Merkle and block-manifest implementation.

use std::io::{Read as _, Seek as _};
use std::path::Path;

const MAXIMUM_BLOCKS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileBlock {
    pub index: u64,
    pub offset: u64,
    pub size_bytes: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FileTree {
    pub size_bytes: u64,
    pub block_bytes: u64,
    pub blocks: Vec<FileBlock>,
    pub root: [u8; 32],
}

pub(crate) fn build_file(path: &Path, block_bytes: u64) -> Result<FileTree, crate::Error> {
    if block_bytes == 0 || block_bytes > 256 * 1024 * 1024 {
        return Err(crate::Error::InvalidResponse(
            "unsafe verification block size".to_owned(),
        ));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| crate::Error::InvalidResponse(format!("open source: {error}")))?;
    let before = file
        .metadata()
        .map_err(|error| crate::Error::InvalidResponse(format!("inspect source: {error}")))?;
    if !before.is_file() {
        return Err(crate::Error::InvalidResponse(
            "source is not a regular file".to_owned(),
        ));
    }
    let size_bytes = before.len();
    let block_count = if size_bytes == 0 {
        0
    } else {
        1 + (size_bytes - 1) / block_bytes
    };
    if block_count > MAXIMUM_BLOCKS as u64 {
        return Err(crate::Error::InvalidResponse(
            "source exceeds verification block limit".to_owned(),
        ));
    }
    let capacity = usize::try_from(block_bytes).map_err(|_| {
        crate::Error::InvalidResponse("block size exceeds this platform".to_owned())
    })?;
    let mut buffer = vec![0_u8; capacity];
    let block_capacity = usize::try_from(block_count).map_err(|_| {
        crate::Error::InvalidResponse("block count exceeds this platform".to_owned())
    })?;
    let mut blocks = Vec::with_capacity(block_capacity);
    let mut offset = 0_u64;
    for index in 0..block_count {
        let length = block_bytes.min(size_bytes - offset);
        let length_usize = usize::try_from(length)
            .map_err(|_| crate::Error::InvalidResponse("block exceeds this platform".to_owned()))?;
        file.read_exact(&mut buffer[..length_usize])
            .map_err(|error| {
                crate::Error::InvalidResponse(format!("hash source block: {error}"))
            })?;
        blocks.push(FileBlock {
            index,
            offset,
            size_bytes: length,
            digest: skydriver_sdk_core::file_block_digest(index, &buffer[..length_usize]),
        });
        offset += length;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| crate::Error::InvalidResponse(format!("check source EOF: {error}")))?
        != 0
    {
        return Err(crate::Error::InvalidResponse(
            "source grew while hashing".to_owned(),
        ));
    }
    let after = file
        .metadata()
        .map_err(|error| crate::Error::InvalidResponse(format!("reinspect source: {error}")))?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(crate::Error::InvalidResponse(
            "source changed while hashing".to_owned(),
        ));
    }
    root_from_blocks(size_bytes, block_bytes, blocks)
}

pub(crate) fn matches_file(
    path: &Path,
    block_bytes: u64,
    expected_size_bytes: u64,
    expected_root: &str,
) -> Result<bool, crate::Error> {
    let path_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(crate::Error::InvalidResponse(format!(
                "inspect local file: {error}"
            )));
        }
    };
    if !path_metadata.file_type().is_file() || path_metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| crate::Error::InvalidResponse(format!("open local file: {error}")))?;
    let before = file
        .metadata()
        .map_err(|error| crate::Error::InvalidResponse(format!("inspect local file: {error}")))?;
    if !matches_open_file(&mut file, block_bytes, expected_size_bytes, expected_root)? {
        return Ok(false);
    }
    let after = file
        .metadata()
        .map_err(|error| crate::Error::InvalidResponse(format!("reinspect local file: {error}")))?;
    let current_path = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(crate::Error::InvalidResponse(format!(
                "reinspect local file path: {error}"
            )));
        }
    };
    Ok(before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && same_file_identity(&before, &current_path))
}

pub(crate) fn matches_open_file(
    file: &mut std::fs::File,
    block_bytes: u64,
    expected_size_bytes: u64,
    expected_root: &str,
) -> Result<bool, crate::Error> {
    let before = file.metadata().map_err(|error| {
        crate::Error::InvalidResponse(format!("inspect open local file: {error}"))
    })?;
    if !before.is_file() || before.len() != expected_size_bytes {
        return Ok(false);
    }
    file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
        crate::Error::InvalidResponse(format!("rewind open local file: {error}"))
    })?;
    let capacity = usize::try_from(block_bytes.min(expected_size_bytes)).map_err(|_| {
        crate::Error::InvalidResponse("verification block size exceeds this platform".to_owned())
    })?;
    let mut buffer = vec![0_u8; capacity];
    let mut accumulator = skydriver_sdk_core::FileMerkleAccumulator::new(block_bytes)
        .map_err(|error| crate::Error::InvalidResponse(error.to_string()))?;
    let mut offset = 0_u64;
    while offset < expected_size_bytes {
        let length = block_bytes.min(expected_size_bytes - offset);
        let length = usize::try_from(length).map_err(|_| {
            crate::Error::InvalidResponse("verification block exceeds this platform".to_owned())
        })?;
        file.read_exact(&mut buffer[..length]).map_err(|error| {
            crate::Error::InvalidResponse(format!("hash local file block: {error}"))
        })?;
        accumulator
            .push_block(&buffer[..length])
            .map_err(|error| crate::Error::InvalidResponse(error.to_string()))?;
        offset = offset
            .checked_add(length as u64)
            .ok_or_else(|| crate::Error::InvalidResponse("local file size overflow".to_owned()))?;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| crate::Error::InvalidResponse(format!("check local file EOF: {error}")))?
        != 0
    {
        return Ok(false);
    }
    let after = file.metadata().map_err(|error| {
        crate::Error::InvalidResponse(format!("reinspect open local file: {error}"))
    })?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Ok(false);
    }
    let root = accumulator
        .finish()
        .map_err(|error| crate::Error::InvalidResponse(error.to_string()))?;
    Ok(hex::encode(root) == expected_root)
}

#[cfg(unix)]
fn same_file_identity(opened: &std::fs::Metadata, current: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    current.file_type().is_file()
        && !current.file_type().is_symlink()
        && opened.dev() == current.dev()
        && opened.ino() == current.ino()
}

#[cfg(not(unix))]
fn same_file_identity(opened: &std::fs::Metadata, current: &std::fs::Metadata) -> bool {
    current.file_type().is_file()
        && !current.file_type().is_symlink()
        && opened.len() == current.len()
        && opened.modified().ok() == current.modified().ok()
}

pub(crate) fn manifest(tree: &FileTree) -> Result<Vec<u8>, crate::Error> {
    let leaves = tree
        .blocks
        .iter()
        .map(|block| block.digest)
        .collect::<Vec<_>>();
    skydriver_sdk_core::encode_block_manifest(tree.size_bytes, tree.block_bytes, &leaves)
        .map_err(|error| crate::Error::InvalidResponse(error.to_string()))
}

pub(crate) fn empty_metadata_root() -> [u8; 32] {
    skydriver_sdk_core::empty_metadata_root()
}

fn root_from_blocks(
    size_bytes: u64,
    block_bytes: u64,
    blocks: Vec<FileBlock>,
) -> Result<FileTree, crate::Error> {
    let leaves = blocks.iter().map(|block| block.digest).collect::<Vec<_>>();
    let root =
        skydriver_sdk_core::file_merkle_root_from_block_digests(size_bytes, block_bytes, &leaves)
            .map_err(|error| crate::Error::InvalidResponse(error.to_string()))?;
    Ok(FileTree {
        size_bytes,
        block_bytes,
        blocks,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::{build_file, empty_metadata_root, manifest, matches_file};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vectors {
        files: Vec<Vector>,
    }
    #[derive(Deserialize)]
    struct Vector {
        payload_hex: String,
        expected: Expected,
    }
    #[derive(Deserialize)]
    struct Expected {
        block_bytes: u64,
        root: String,
    }

    #[test]
    fn matches_shared_go_golden_vectors() {
        let vectors: Vectors =
            serde_json::from_str(include_str!("../../../testdata/vfs-merkle-v1.json")).unwrap();
        for vector in vectors.files {
            let directory = std::env::temp_dir();
            let path = directory.join(format!("carrack-rust-merkle-{}", vector.expected.root));
            std::fs::write(&path, hex::decode(vector.payload_hex).unwrap()).unwrap();
            let tree = build_file(&path, vector.expected.block_bytes).unwrap();
            std::fs::remove_file(path).unwrap();
            assert_eq!(hex::encode(tree.root), vector.expected.root);
            assert!(!manifest(&tree).expect("encode manifest").is_empty());
        }
        assert_eq!(hex::encode(empty_metadata_root()).len(), 64);
    }

    #[test]
    fn streaming_local_verification_matches_root_and_rejects_symlink() {
        let directory = tempfile::tempdir().expect("local verification directory");
        let path = directory.path().join("payload");
        std::fs::write(&path, b"abcdefghijk").expect("write local payload");
        let expected = build_file(&path, 4).expect("build expected file root");
        assert!(
            matches_file(&path, 4, 11, &hex::encode(expected.root))
                .expect("stream local verification")
        );
        assert!(!matches_file(&path, 4, 11, &"00".repeat(32)).expect("reject wrong root"));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&path, directory.path().join("payload-link"))
                .expect("create payload symlink");
            assert!(
                !matches_file(
                    &directory.path().join("payload-link"),
                    4,
                    11,
                    &hex::encode(expected.root),
                )
                .expect("reject symlink reuse")
            );
        }
    }
}
