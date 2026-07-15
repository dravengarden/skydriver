//! Private content-addressed directory catalog used by incremental sync.

use carrack_sdk_core::{
    CatalogCheckpoint, CatalogCheckpointEntryKind, DirectoryMerkleEntry, catalog_checkpoint_etag,
    directory_merkle_root, validate_catalog_checkpoint,
};
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
const HEAD_SCHEMA: &str = "carrack.vfs.catalog-head.v1";
const HEAD_ENVELOPE_SCHEMA: &str = "carrack.vfs.catalog-head-envelope.v1";
const MAXIMUM_NODE_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_HEAD_BYTES: u64 = 64 * 1024;
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogHead {
    schema: String,
    filesystem_id: String,
    revision_id: u64,
    root_directory_id: String,
    root_data_root: String,
    checkpoint_sha256: String,
    etag: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogHeadEnvelope {
    schema: String,
    sha256: String,
    head: CatalogHead,
}

pub(crate) struct CatalogStore {
    root: PathBuf,
    nodes: PathBuf,
}

impl CatalogStore {
    pub(crate) fn new(state_directory: &Path, token_id: &str) -> Result<Self, Error> {
        validate_hex::<16>(token_id, "catalog token identity")?;
        let root = state_directory.join("catalog/tokens").join(token_id);
        let nodes = root.join("nodes");
        ensure_private_directory(&root)?;
        ensure_private_directory(&nodes)?;
        Ok(Self { root, nodes })
    }

    pub(crate) fn checkpoint_etag(&self) -> Result<Option<String>, Error> {
        let Some(head) = self.load_head()? else {
            return Ok(None);
        };
        if self
            .load(&head.root_directory_id, &head.root_data_root)?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(head.etag))
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
        self.publish_node(node)
    }

    pub(crate) fn publish_checkpoint(&self, checkpoint: &CatalogCheckpoint) -> Result<(), Error> {
        validate_catalog_checkpoint(checkpoint)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        for directory in &checkpoint.directories {
            self.publish_node(CatalogNode {
                schema: NODE_SCHEMA.to_owned(),
                directory_id: directory.directory_id.clone(),
                data_root: directory.data_root.clone(),
                entries: directory
                    .entries
                    .iter()
                    .map(|entry| CatalogEntry {
                        name: entry.name.clone(),
                        kind: match entry.kind {
                            CatalogCheckpointEntryKind::File => EntryKind::File,
                            CatalogCheckpointEntryKind::Directory => EntryKind::Directory,
                        },
                        file_id: entry.file_id.clone(),
                        version_id: entry.version_id.clone(),
                        child_directory_id: entry.child_directory_id.clone(),
                        size_bytes: entry.size_bytes,
                        data_root: entry.data_root.clone(),
                        metadata_root: entry.metadata_root.clone(),
                    })
                    .collect(),
            })?;
        }
        let checkpoint_bytes = serde_json::to_vec(checkpoint).map_err(|error| {
            Error::InvalidResponse(format!("encode catalog checkpoint receipt: {error}"))
        })?;
        let checkpoint_sha256 = hex::encode(Sha256::digest(&checkpoint_bytes));
        self.publish_head(CatalogHead {
            schema: HEAD_SCHEMA.to_owned(),
            filesystem_id: checkpoint.filesystem_id.clone(),
            revision_id: checkpoint.revision_id,
            root_directory_id: checkpoint.root_directory_id.clone(),
            root_data_root: checkpoint.root_data_root.clone(),
            etag: catalog_checkpoint_etag(&checkpoint_sha256)
                .map_err(|error| Error::InvalidResponse(error.to_string()))?,
            checkpoint_sha256,
        })?;
        Ok(())
    }

    fn load_head(&self) -> Result<Option<CatalogHead>, Error> {
        let path = self.root.join("head.json");
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(local_error("inspect catalog head", error)),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAXIMUM_HEAD_BYTES
        {
            return Err(Error::InvalidResponse(
                "catalog head is not a bounded regular file".to_owned(),
            ));
        }
        let encoded =
            std::fs::read(path).map_err(|error| local_error("read catalog head", error))?;
        let envelope: CatalogHeadEnvelope = serde_json::from_slice(&encoded)
            .map_err(|error| Error::InvalidResponse(format!("decode catalog head: {error}")))?;
        if serde_json::to_vec(&envelope)
            .map_err(|error| Error::InvalidResponse(format!("encode catalog head: {error}")))?
            != encoded
            || envelope.schema != HEAD_ENVELOPE_SCHEMA
        {
            return Err(Error::InvalidResponse(
                "catalog head envelope is not canonical".to_owned(),
            ));
        }
        let head_bytes = canonical_head_bytes(&envelope.head)?;
        if envelope.sha256 != hex::encode(Sha256::digest(&head_bytes)) {
            return Err(Error::InvalidResponse(
                "catalog head envelope checksum differs".to_owned(),
            ));
        }
        validate_head(&envelope.head)?;
        Ok(Some(envelope.head))
    }

    fn publish_head(&self, head: CatalogHead) -> Result<(), Error> {
        validate_head(&head)?;
        if let Some(existing) = self.load_head()? {
            if existing.revision_id > head.revision_id {
                return Ok(());
            }
            if existing.revision_id == head.revision_id {
                if canonical_head_bytes(&existing)? != canonical_head_bytes(&head)? {
                    return Err(Error::InvalidResponse(
                        "catalog head differs at one revision".to_owned(),
                    ));
                }
                return Ok(());
            }
        }
        let head_bytes = canonical_head_bytes(&head)?;
        let envelope = CatalogHeadEnvelope {
            schema: HEAD_ENVELOPE_SCHEMA.to_owned(),
            sha256: hex::encode(Sha256::digest(&head_bytes)),
            head,
        };
        let encoded = serde_json::to_vec(&envelope)
            .map_err(|error| Error::InvalidResponse(format!("encode catalog head: {error}")))?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > MAXIMUM_HEAD_BYTES {
            return Err(Error::InvalidResponse(
                "catalog head exceeds the local size bound".to_owned(),
            ));
        }
        let temporary = self.root.join(format!(
            ".head.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed)
        ));
        write_private_file(&temporary, &encoded)?;
        std::fs::rename(&temporary, self.root.join("head.json"))
            .map_err(|error| local_error("publish catalog head", error))?;
        sync_directory(&self.root)
    }

    fn publish_node(&self, node: CatalogNode) -> Result<CatalogNode, Error> {
        let directory_id = node.directory_id.clone();
        let data_root = node.data_root.clone();
        validate_node(&node, &directory_id, &data_root)?;
        if let Some(existing) = self.load(&directory_id, &data_root)? {
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
        let final_path = self.node_path(&directory_id, &data_root)?;
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
                let existing = self.load(&directory_id, &data_root)?.ok_or_else(|| {
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

fn validate_head(head: &CatalogHead) -> Result<(), Error> {
    validate_hex::<16>(&head.filesystem_id, "catalog head filesystem identity")?;
    validate_hex::<16>(
        &head.root_directory_id,
        "catalog head root directory identity",
    )?;
    validate_hex::<32>(&head.root_data_root, "catalog head root")?;
    validate_hex::<32>(&head.checkpoint_sha256, "catalog head checkpoint SHA-256")?;
    if head.schema != HEAD_SCHEMA
        || head.revision_id == 0
        || catalog_checkpoint_etag(&head.checkpoint_sha256)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?
            != head.etag
    {
        return Err(Error::InvalidResponse(
            "catalog head identity differs".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_head_bytes(head: &CatalogHead) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(head)
        .map_err(|error| Error::InvalidResponse(format!("encode catalog head: {error}")))
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

    fn empty_checkpoint() -> CatalogCheckpoint {
        let root = hex::encode(directory_merkle_root(&[]).expect("empty directory root"));
        CatalogCheckpoint {
            schema: carrack_sdk_core::CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            parent_revision_id: None,
            root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            root_data_root: root.clone(),
            created_at: 1_700_000_000,
            directories: vec![carrack_sdk_core::CatalogCheckpointDirectory {
                directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
                parent_directory_id: None,
                name: String::new(),
                data_root: root,
                entries: Vec::new(),
            }],
        }
    }

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

    #[test]
    fn persists_only_a_verified_checkpoint_head() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let store = CatalogStore::new(temporary.path(), "303132333435363738393a3b3c3d3e3f")
            .expect("catalog store");
        let checkpoint = empty_checkpoint();
        let checkpoint_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&checkpoint).expect("encode checkpoint"),
        ));
        let expected = catalog_checkpoint_etag(&checkpoint_sha256).expect("checkpoint entity tag");

        store
            .publish_checkpoint(&checkpoint)
            .expect("publish checkpoint");
        assert_eq!(
            store.checkpoint_etag().expect("read checkpoint head"),
            Some(expected)
        );

        let head_path = store.root.join("head.json");
        let mut bytes = std::fs::read(&head_path).expect("read checkpoint head");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(head_path, bytes).expect("corrupt checkpoint head");
        assert!(store.checkpoint_etag().is_err());
    }
}
