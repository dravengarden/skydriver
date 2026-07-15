//! Private content-addressed directory catalog used by incremental sync.

use carrack_sdk_core::{DirectoryMerkleEntry, directory_merkle_root};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{DirectoryEntry, EntryKind, Error};

const NODE_SCHEMA: &str = "carrack.vfs.catalog-node.v1";
const ENVELOPE_SCHEMA: &str = "carrack.vfs.catalog-node-envelope.v1";
const MAXIMUM_NODE_BYTES: u64 = 512 * 1024 * 1024;
static TEMPORARY_ORDINAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogNode {
    schema: String,
    pub(crate) directory_id: String,
    pub(crate) data_root: String,
    pub(crate) entries: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogEntry {
    pub(crate) name: String,
    pub(crate) kind: EntryKind,
    pub(crate) file_id: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) child_directory_id: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) data_root: String,
    pub(crate) metadata_root: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogEnvelope {
    schema: String,
    sha256: String,
    node: CatalogNode,
}

pub(crate) struct CatalogStore {
    nodes: PathBuf,
}

impl CatalogStore {
    pub(crate) fn new(state_directory: &Path, token_id: &str) -> Result<Self, Error> {
        validate_hex::<16>(token_id, "catalog token identity")?;
        let nodes = state_directory
            .join("catalog/tokens")
            .join(token_id)
            .join("nodes");
        ensure_private_directory(&nodes)?;
        Ok(Self { nodes })
    }

    pub(crate) fn load(
        &self,
        directory_id: &str,
        data_root: &str,
    ) -> Result<Option<CatalogNode>, Error> {
        validate_hex::<16>(directory_id, "catalog directory identity")?;
        validate_hex::<32>(data_root, "catalog directory root")?;
        let path = self.node_path(directory_id, data_root)?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(local_error("inspect catalog node", error)),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAXIMUM_NODE_BYTES
        {
            return Err(Error::InvalidResponse(
                "catalog node is not a bounded regular file".to_owned(),
            ));
        }
        let encoded =
            std::fs::read(&path).map_err(|error| local_error("read catalog node", error))?;
        let envelope: CatalogEnvelope = serde_json::from_slice(&encoded)
            .map_err(|error| Error::InvalidResponse(format!("decode catalog node: {error}")))?;
        if serde_json::to_vec(&envelope)
            .map_err(|error| Error::InvalidResponse(format!("encode catalog node: {error}")))?
            != encoded
            || envelope.schema != ENVELOPE_SCHEMA
        {
            return Err(Error::InvalidResponse(
                "catalog node envelope is not canonical".to_owned(),
            ));
        }
        let node_bytes = canonical_node_bytes(&envelope.node)?;
        if envelope.sha256 != hex::encode(Sha256::digest(&node_bytes)) {
            return Err(Error::InvalidResponse(
                "catalog node envelope checksum differs".to_owned(),
            ));
        }
        validate_node(&envelope.node, directory_id, data_root)?;
        Ok(Some(envelope.node))
    }

    pub(crate) fn publish(
        &self,
        directory_id: &str,
        data_root: &str,
        entries: &[DirectoryEntry],
    ) -> Result<CatalogNode, Error> {
        let node = CatalogNode {
            schema: NODE_SCHEMA.to_owned(),
            directory_id: directory_id.to_owned(),
            data_root: data_root.to_owned(),
            entries: entries.iter().map(CatalogEntry::from).collect(),
        };
        validate_node(&node, directory_id, data_root)?;
        if let Some(existing) = self.load(directory_id, data_root)? {
            if canonical_node_bytes(&existing)? != canonical_node_bytes(&node)? {
                return Err(Error::InvalidResponse(
                    "existing catalog node differs at one content address".to_owned(),
                ));
            }
            return Ok(existing);
        }
        let node_bytes = canonical_node_bytes(&node)?;
        let envelope = CatalogEnvelope {
            schema: ENVELOPE_SCHEMA.to_owned(),
            sha256: hex::encode(Sha256::digest(&node_bytes)),
            node: node.clone(),
        };
        let encoded = serde_json::to_vec(&envelope)
            .map_err(|error| Error::InvalidResponse(format!("encode catalog envelope: {error}")))?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAXIMUM_NODE_BYTES {
            return Err(Error::InvalidResponse(
                "catalog node exceeds the local size bound".to_owned(),
            ));
        }
        let final_path = self.node_path(directory_id, data_root)?;
        let parent = final_path
            .parent()
            .ok_or_else(|| Error::InvalidResponse("catalog node path has no parent".to_owned()))?;
        ensure_private_directory(parent)?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            std::process::id(),
            TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed)
        ));
        write_private_file(&temporary, &encoded)?;
        match std::fs::hard_link(&temporary, &final_path) {
            Ok(()) => {
                sync_directory(parent)?;
                std::fs::remove_file(&temporary)
                    .map_err(|error| local_error("remove catalog temporary", error))?;
                sync_directory(parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&temporary)
                    .map_err(|remove| local_error("remove raced catalog temporary", remove))?;
                let existing = self.load(directory_id, data_root)?.ok_or_else(|| {
                    Error::InvalidResponse("raced catalog node disappeared".to_owned())
                })?;
                if canonical_node_bytes(&existing)? != node_bytes {
                    return Err(Error::InvalidResponse(
                        "raced catalog node differs at one content address".to_owned(),
                    ));
                }
                return Ok(existing);
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(local_error("publish catalog node", error));
            }
        }
        Ok(node)
    }

    fn node_path(&self, directory_id: &str, data_root: &str) -> Result<PathBuf, Error> {
        let shard = data_root
            .get(..2)
            .ok_or_else(|| Error::InvalidResponse("catalog root cannot be sharded".to_owned()))?;
        Ok(self
            .nodes
            .join(shard)
            .join(format!("{directory_id}-{data_root}.json")))
    }
}

impl From<&DirectoryEntry> for CatalogEntry {
    fn from(entry: &DirectoryEntry) -> Self {
        Self {
            name: entry.name.clone(),
            kind: entry.kind,
            file_id: entry.file_id.clone(),
            version_id: entry.version_id.clone(),
            child_directory_id: entry.child_directory_id.clone(),
            size_bytes: entry.size_bytes,
            data_root: entry.data_root.clone(),
            metadata_root: entry.metadata_root.clone(),
        }
    }
}

fn validate_node(node: &CatalogNode, directory_id: &str, data_root: &str) -> Result<(), Error> {
    if node.schema != NODE_SCHEMA
        || node.directory_id != directory_id
        || node.data_root != data_root
    {
        return Err(Error::InvalidResponse(
            "catalog node identity differs".to_owned(),
        ));
    }
    validate_hex::<16>(&node.directory_id, "catalog directory identity")?;
    let expected_root = decode_hex::<32>(&node.data_root, "catalog directory root")?;
    for pair in node.entries.windows(2) {
        if pair[0].name.as_bytes() >= pair[1].name.as_bytes() {
            return Err(Error::InvalidResponse(
                "catalog entries are not canonically ordered".to_owned(),
            ));
        }
    }
    let entries = node
        .entries
        .iter()
        .map(merkle_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let actual_root = directory_merkle_root(&entries)
        .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    if actual_root != expected_root {
        return Err(Error::InvalidResponse(
            "catalog directory Merkle root differs".to_owned(),
        ));
    }
    Ok(())
}

fn merkle_entry(entry: &CatalogEntry) -> Result<DirectoryMerkleEntry<'_>, Error> {
    let data_root = decode_hex::<32>(&entry.data_root, "catalog entry data root")?;
    match entry.kind {
        EntryKind::File => {
            if entry.child_directory_id.is_some() || entry.metadata_root.is_none() {
                return Err(Error::InvalidResponse(
                    "catalog file entry union is invalid".to_owned(),
                ));
            }
            Ok(DirectoryMerkleEntry::File {
                name: &entry.name,
                stable_id: decode_hex::<16>(
                    entry.file_id.as_deref().unwrap_or_default(),
                    "catalog file identity",
                )?,
                version_id: decode_hex::<16>(
                    entry.version_id.as_deref().unwrap_or_default(),
                    "catalog version identity",
                )?,
                size_bytes: entry.size_bytes,
                data_root,
                metadata_root: decode_hex::<32>(
                    entry.metadata_root.as_deref().unwrap_or_default(),
                    "catalog metadata root",
                )?,
            })
        }
        EntryKind::Directory => {
            if entry.file_id.is_some()
                || entry.version_id.is_some()
                || entry.metadata_root.is_some()
                || entry.size_bytes != 0
            {
                return Err(Error::InvalidResponse(
                    "catalog directory entry union is invalid".to_owned(),
                ));
            }
            Ok(DirectoryMerkleEntry::Directory {
                name: &entry.name,
                stable_id: decode_hex::<16>(
                    entry.child_directory_id.as_deref().unwrap_or_default(),
                    "catalog child identity",
                )?,
                data_root,
            })
        }
    }
}

fn canonical_node_bytes(node: &CatalogNode) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(node)
        .map_err(|error| Error::InvalidResponse(format!("encode catalog node: {error}")))
}

fn validate_hex<const N: usize>(value: &str, context: &str) -> Result<(), Error> {
    let _ = decode_hex::<N>(value, context)?;
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, context: &str) -> Result<[u8; N], Error> {
    if value.len() != N * 2
        || value == "0".repeat(N * 2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidResponse(format!("{context} is invalid")));
    }
    let decoded = hex::decode(value)
        .map_err(|error| Error::InvalidResponse(format!("decode {context}: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| Error::InvalidResponse(format!("{context} length differs")))
}

fn ensure_private_directory(path: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(path)
        .map_err(|error| local_error("create catalog directory", error))?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| local_error("inspect catalog directory", error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidResponse(
            "catalog path is not a real directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| local_error("protect catalog directory", error))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, encoded: &[u8]) -> Result<(), Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| local_error("create catalog temporary", error))?;
    file.write_all(encoded)
        .map_err(|error| local_error("write catalog temporary", error))?;
    file.sync_all()
        .map_err(|error| local_error("sync catalog temporary", error))
}

fn sync_directory(path: &Path) -> Result<(), Error> {
    std::fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| local_error("sync catalog directory", error))
}

fn local_error(context: &str, error: impl std::fmt::Display) -> Error {
    Error::InvalidResponse(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_loads_and_rejects_corrupt_nodes() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let store = CatalogStore::new(temporary.path(), "101112131415161718191a1b1c1d1e1f")
            .expect("catalog store");
        let directory_id = "2031425364758697a8b9cadbecfd0e1f";
        let data_root = "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254";
        let node = store
            .publish(directory_id, data_root, &[])
            .expect("publish catalog node");
        assert_eq!(node.directory_id, directory_id);
        assert_eq!(
            store
                .load(directory_id, data_root)
                .expect("load catalog node")
                .expect("stored node")
                .data_root,
            data_root
        );
        let path = store
            .node_path(directory_id, data_root)
            .expect("catalog path");
        let mut bytes = std::fs::read(&path).expect("read stored node");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(path, bytes).expect("corrupt stored node");
        assert!(store.load(directory_id, data_root).is_err());
    }

    #[test]
    fn isolates_nodes_between_vfs_tokens() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let first = CatalogStore::new(temporary.path(), "101112131415161718191a1b1c1d1e1f")
            .expect("first token catalog");
        let second = CatalogStore::new(temporary.path(), "202122232425262728292a2b2c2d2e2f")
            .expect("second token catalog");
        let directory_id = "303132333435363738393a3b3c3d3e3f";
        let data_root = "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254";

        first
            .publish(directory_id, data_root, &[])
            .expect("publish first token node");

        assert!(
            second
                .load(directory_id, data_root)
                .expect("load second token node")
                .is_none()
        );
    }
}
