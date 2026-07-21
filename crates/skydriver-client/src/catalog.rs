//! Private content-addressed directory catalog used by incremental sync.

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use skydriver_metadata_cache::MetadataCacheCipher;
use skydriver_sdk_core::{
    CATALOG_CHECKPOINT_SCHEMA, CatalogCheckpoint, CatalogCheckpointDirectory,
    CatalogCheckpointEntry, CatalogCheckpointEntryKind, CatalogDelta, DirectoryMerkleEntry,
    apply_catalog_delta, directory_merkle_root, validate_catalog_checkpoint,
    validate_catalog_checkpoint_etag,
};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{DirectoryEntry, EntryKind, Error, VfsToken, private_fs::ensure_private_directory};

const NODE_SCHEMA: &str = "skydriver.vfs.catalog-node.v1";
const ENVELOPE_SCHEMA: &str = "skydriver.vfs.catalog-node-envelope.v1";
const HEAD_SCHEMA: &str = "skydriver.vfs.catalog-head.v1";
const HEAD_ENVELOPE_SCHEMA: &str = "skydriver.vfs.catalog-head-envelope.v1";
const MAXIMUM_NODE_BYTES: usize = 512 * 1024 * 1024;
const MAXIMUM_HEAD_BYTES: usize = 64 * 1024;
const MAXIMUM_GC_CURSOR_BYTES: usize = 1;
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

#[derive(Clone, Debug)]
pub(crate) struct CatalogCheckpointCondition {
    pub(crate) filesystem_id: String,
    pub(crate) revision_id: u64,
    pub(crate) root_directory_id: String,
    pub(crate) root_data_root: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) etag: String,
}

#[derive(Clone)]
pub(crate) struct CatalogStore {
    root: PathBuf,
    nodes: PathBuf,
    cipher: MetadataCacheCipher,
    enabled: bool,
}

impl CatalogStore {
    pub(crate) fn new(
        state_directory: &Path,
        token_id: &str,
        token: &VfsToken,
        enabled: bool,
    ) -> Result<Self, Error> {
        let token_identity = decode_hex::<16>(token_id, "catalog token identity")?;
        let root = state_directory.join("catalog/tokens").join(token_id);
        let nodes = root.join("nodes");
        if enabled {
            ensure_private_directory(&root, "catalog root")?;
            ensure_private_directory(&nodes, "catalog node directory")?;
        }
        Ok(Self {
            root,
            nodes,
            cipher: token.metadata_cache_cipher(&token_identity)?,
            enabled,
        })
    }

    pub(crate) fn checkpoint_condition(&self) -> Result<Option<CatalogCheckpointCondition>, Error> {
        if !self.enabled {
            return Ok(None);
        }
        let head = if let Ok(head) = self.load_head() {
            head
        } else {
            self.discard_head()?;
            None
        };
        let Some(head) = head else {
            return Ok(None);
        };
        let root = if let Ok(root) = self.load(&head.root_directory_id, &head.root_data_root) {
            root
        } else {
            self.discard_node(&head.root_directory_id, &head.root_data_root)?;
            None
        };
        if root.is_none() {
            return Ok(None);
        }
        Ok(Some(CatalogCheckpointCondition {
            filesystem_id: head.filesystem_id,
            revision_id: head.revision_id,
            root_directory_id: head.root_directory_id,
            root_data_root: head.root_data_root,
            checkpoint_sha256: head.checkpoint_sha256,
            etag: head.etag,
        }))
    }

    pub(crate) fn load(
        &self,
        directory_id: &str,
        data_root: &str,
    ) -> Result<Option<CatalogNode>, Error> {
        if !self.enabled {
            return Ok(None);
        }
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
            || metadata.len()
                > u64::try_from(MetadataCacheCipher::maximum_encoded_bytes(
                    MAXIMUM_NODE_BYTES,
                ))
                .unwrap_or(u64::MAX)
        {
            return Err(Error::InvalidResponse(
                "catalog node is not a bounded regular file".to_owned(),
            ));
        }
        let sealed =
            std::fs::read(&path).map_err(|error| local_error("read catalog node", error))?;
        let encoded = self
            .cipher
            .open(
                &node_context(directory_id, data_root),
                &sealed,
                MAXIMUM_NODE_BYTES,
            )
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
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
        if self.enabled {
            self.publish_node(node)
        } else {
            validate_node(&node, directory_id, data_root)?;
            Ok(node)
        }
    }

    pub(crate) fn publish_checkpoint(
        &self,
        checkpoint: &CatalogCheckpoint,
        etag: &str,
    ) -> Result<(), Error> {
        validate_catalog_checkpoint(checkpoint)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        validate_catalog_checkpoint_etag(etag)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        if !self.enabled {
            return Ok(());
        }
        let _lock = self.acquire_head_lock()?;
        for directory in &checkpoint.directories {
            self.publish_node(checkpoint_node(directory))?;
        }
        if self.publish_checkpoint_head_locked(checkpoint, etag)? {
            let _ = self.prune_one_shard(checkpoint);
        }
        Ok(())
    }

    fn publish_checkpoint_head_locked(
        &self,
        checkpoint: &CatalogCheckpoint,
        etag: &str,
    ) -> Result<bool, Error> {
        let checkpoint_bytes = serde_json::to_vec(checkpoint).map_err(|error| {
            Error::InvalidResponse(format!("encode catalog checkpoint receipt: {error}"))
        })?;
        let checkpoint_sha256 = hex::encode(Sha256::digest(&checkpoint_bytes));
        self.publish_head_locked(CatalogHead {
            schema: HEAD_SCHEMA.to_owned(),
            filesystem_id: checkpoint.filesystem_id.clone(),
            revision_id: checkpoint.revision_id,
            root_directory_id: checkpoint.root_directory_id.clone(),
            root_data_root: checkpoint.root_data_root.clone(),
            etag: etag.to_owned(),
            checkpoint_sha256,
        })
    }

    pub(crate) fn apply_delta(&self, delta: &CatalogDelta, etag: &str) -> Result<(), Error> {
        let _lock = self.acquire_head_lock()?;
        let head = self.load_head()?.ok_or_else(|| {
            Error::InvalidResponse("catalog delta has no local base head".to_owned())
        })?;
        let base = self.reconstruct_checkpoint(&head)?;
        let checkpoint = apply_catalog_delta(&base, &head.checkpoint_sha256, delta)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        // The portable core has reconstructed and verified the complete target
        // checkpoint, including its target SHA-256. Unchanged content-addressed
        // nodes already belong to the verified base, so only delta-carried nodes
        // need publication before the new head becomes visible.
        for directory in &delta.directories {
            self.publish_node(checkpoint_node(directory))?;
        }
        if self.publish_checkpoint_head_locked(&checkpoint, etag)? {
            let _ = self.prune_one_shard(&checkpoint);
        }
        Ok(())
    }

    fn reconstruct_checkpoint(&self, head: &CatalogHead) -> Result<CatalogCheckpoint, Error> {
        let mut visited = HashSet::new();
        let mut pending = vec![(
            head.root_directory_id.clone(),
            head.root_data_root.clone(),
            None,
            String::new(),
        )];
        let mut directories = Vec::new();
        while let Some((directory_id, data_root, parent_directory_id, name)) = pending.pop() {
            if !visited.insert(directory_id.clone()) {
                return Err(Error::InvalidResponse(
                    "local catalog base is not a tree".to_owned(),
                ));
            }
            let node = self.load(&directory_id, &data_root)?.ok_or_else(|| {
                Error::InvalidResponse("local catalog base node is missing".to_owned())
            })?;
            let entries = node
                .entries
                .iter()
                .map(checkpoint_entry)
                .collect::<Vec<_>>();
            for entry in entries.iter().rev() {
                if entry.kind == CatalogCheckpointEntryKind::Directory {
                    pending.push((
                        entry.child_directory_id.clone().ok_or_else(|| {
                            Error::InvalidResponse(
                                "local catalog child identity is missing".to_owned(),
                            )
                        })?,
                        entry.data_root.clone(),
                        Some(directory_id.clone()),
                        entry.name.clone(),
                    ));
                }
            }
            directories.push(CatalogCheckpointDirectory {
                directory_id,
                parent_directory_id,
                name,
                data_root,
                entries,
            });
        }
        directories.sort_unstable_by(|left, right| left.directory_id.cmp(&right.directory_id));
        let checkpoint = CatalogCheckpoint {
            schema: CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: head.filesystem_id.clone(),
            revision_id: head.revision_id,
            parent_revision_id: None,
            root_directory_id: head.root_directory_id.clone(),
            root_data_root: head.root_data_root.clone(),
            created_at: 1,
            directories,
        };
        validate_catalog_checkpoint(&checkpoint)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        Ok(checkpoint)
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
            || metadata.len()
                > u64::try_from(MetadataCacheCipher::maximum_encoded_bytes(
                    MAXIMUM_HEAD_BYTES,
                ))
                .unwrap_or(u64::MAX)
        {
            return Err(Error::InvalidResponse(
                "catalog head is not a bounded regular file".to_owned(),
            ));
        }
        let sealed =
            std::fs::read(path).map_err(|error| local_error("read catalog head", error))?;
        let encoded = self
            .cipher
            .open("head", &sealed, MAXIMUM_HEAD_BYTES)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
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

    fn publish_head_locked(&self, head: CatalogHead) -> Result<bool, Error> {
        validate_head(&head)?;
        let existing = if let Ok(existing) = self.load_head() {
            existing
        } else {
            self.discard_head()?;
            None
        };
        if let Some(existing) = existing {
            if existing.revision_id > head.revision_id {
                return Ok(false);
            }
            if existing.revision_id == head.revision_id {
                if canonical_head_bytes(&existing)? != canonical_head_bytes(&head)? {
                    return Err(Error::InvalidResponse(
                        "catalog head differs at one revision".to_owned(),
                    ));
                }
                return Ok(true);
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
        if encoded.len() > MAXIMUM_HEAD_BYTES {
            return Err(Error::InvalidResponse(
                "catalog head exceeds the local size bound".to_owned(),
            ));
        }
        let temporary = self.root.join(format!(
            ".head.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed)
        ));
        let sealed = self.seal("head", &encoded)?;
        write_private_file(&temporary, &sealed)?;
        std::fs::rename(&temporary, self.root.join("head.json"))
            .map_err(|error| local_error("publish catalog head", error))?;
        sync_directory(&self.root)?;
        Ok(true)
    }

    fn publish_node(&self, node: CatalogNode) -> Result<CatalogNode, Error> {
        let directory_id = node.directory_id.clone();
        let data_root = node.data_root.clone();
        validate_node(&node, &directory_id, &data_root)?;
        let existing = if let Ok(existing) = self.load(&directory_id, &data_root) {
            existing
        } else {
            self.discard_node(&directory_id, &data_root)?;
            None
        };
        if let Some(existing) = existing {
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
        if encoded.len() > MAXIMUM_NODE_BYTES {
            return Err(Error::InvalidResponse(
                "catalog node exceeds the local size bound".to_owned(),
            ));
        }
        let final_path = self.node_path(&directory_id, &data_root)?;
        let parent = final_path
            .parent()
            .ok_or_else(|| Error::InvalidResponse("catalog node path has no parent".to_owned()))?;
        ensure_private_directory(parent, "catalog node directory")?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            std::process::id(),
            TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed)
        ));
        let sealed = self.seal(&node_context(&directory_id, &data_root), &encoded)?;
        write_private_file(&temporary, &sealed)?;
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

    pub(crate) fn discard_node(&self, directory_id: &str, data_root: &str) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        let path = self.node_path(directory_id, data_root)?;
        remove_cache_file(&path, "discard invalid catalog node")
    }

    pub(crate) fn discard_head(&self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        remove_cache_file(&self.root.join("head.json"), "discard invalid catalog head")
    }

    fn seal(&self, context: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|error| Error::InvalidResponse(format!("generate cache nonce: {error}")))?;
        self.cipher
            .seal(context, nonce, plaintext)
            .map_err(|error| Error::InvalidResponse(error.to_string()))
    }

    fn acquire_head_lock(&self) -> Result<std::fs::File, Error> {
        let path = self.root.join("head.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|error| local_error("open catalog head lock", error))?;
        let metadata = file
            .metadata()
            .map_err(|error| local_error("inspect catalog head lock", error))?;
        if !metadata.is_file() {
            return Err(Error::InvalidResponse(
                "catalog head lock is not a regular file".to_owned(),
            ));
        }
        file.lock_exclusive()
            .map_err(|error| local_error("lock catalog head", error))?;
        Ok(file)
    }

    fn prune_one_shard(&self, checkpoint: &CatalogCheckpoint) -> Result<(), Error> {
        let shard = self.load_gc_shard();
        let shard_name = format!("{shard:02x}");
        let directory = self.nodes.join(&shard_name);
        let reachable = checkpoint
            .directories
            .iter()
            .filter(|node| node.data_root.starts_with(&shard_name))
            .map(|node| self.node_path(&node.directory_id, &node.data_root))
            .collect::<Result<HashSet<_>, _>>()?;
        match std::fs::read_dir(&directory) {
            Ok(entries) => {
                for entry in entries {
                    let entry =
                        entry.map_err(|error| local_error("read catalog GC entry", error))?;
                    let path = entry.path();
                    let metadata = std::fs::symlink_metadata(&path)
                        .map_err(|error| local_error("inspect catalog GC entry", error))?;
                    if metadata.file_type().is_file()
                        && !metadata.file_type().is_symlink()
                        && path
                            .extension()
                            .is_some_and(|extension| extension == "json")
                        && !reachable.contains(&path)
                    {
                        match std::fs::remove_file(&path) {
                            Ok(()) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(local_error("remove stale catalog node", error));
                            }
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(local_error("open catalog GC shard", error)),
        }
        self.publish_gc_shard(shard.wrapping_add(1))
    }

    fn load_gc_shard(&self) -> u8 {
        let path = self.root.join("gc.cursor");
        let Ok(sealed) = std::fs::read(&path) else {
            return 0;
        };
        match self
            .cipher
            .open("gc-cursor", &sealed, MAXIMUM_GC_CURSOR_BYTES)
        {
            Ok(plaintext) if plaintext.len() == 1 => plaintext[0],
            _ => {
                let _ = std::fs::remove_file(path);
                0
            }
        }
    }

    fn publish_gc_shard(&self, shard: u8) -> Result<(), Error> {
        let temporary = self.root.join(format!(
            ".gc.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed)
        ));
        let sealed = self.seal("gc-cursor", &[shard])?;
        write_private_file(&temporary, &sealed)?;
        std::fs::rename(&temporary, self.root.join("gc.cursor"))
            .map_err(|error| local_error("publish catalog GC cursor", error))?;
        sync_directory(&self.root)
    }
}

fn node_context(directory_id: &str, data_root: &str) -> String {
    format!("node/{directory_id}/{data_root}")
}

fn remove_cache_file(path: &Path, context: &'static str) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(local_error(context, error)),
    }
}

fn checkpoint_node(directory: &CatalogCheckpointDirectory) -> CatalogNode {
    CatalogNode {
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

fn checkpoint_entry(entry: &CatalogEntry) -> CatalogCheckpointEntry {
    CatalogCheckpointEntry {
        name: entry.name.clone(),
        kind: match entry.kind {
            EntryKind::File => CatalogCheckpointEntryKind::File,
            EntryKind::Directory => CatalogCheckpointEntryKind::Directory,
        },
        file_id: entry.file_id.clone(),
        version_id: entry.version_id.clone(),
        child_directory_id: entry.child_directory_id.clone(),
        size_bytes: entry.size_bytes,
        data_root: entry.data_root.clone(),
        metadata_root: entry.metadata_root.clone(),
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

pub(crate) fn merkle_entry(entry: &CatalogEntry) -> Result<DirectoryMerkleEntry<'_>, Error> {
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
    validate_catalog_checkpoint_etag(&head.etag)
        .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    if head.schema != HEAD_SCHEMA || head.revision_id == 0 {
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use skydriver_sdk_core::build_catalog_delta;

    fn cache_token(byte: u8) -> VfsToken {
        VfsToken::parse(&URL_SAFE_NO_PAD.encode([byte; 32])).expect("cache token")
    }

    fn empty_directory_root() -> String {
        hex::encode(directory_merkle_root(&[]).expect("empty directory root"))
    }

    fn empty_checkpoint() -> CatalogCheckpoint {
        let root = hex::encode(directory_merkle_root(&[]).expect("empty directory root"));
        CatalogCheckpoint {
            schema: skydriver_sdk_core::CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            parent_revision_id: None,
            root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            root_data_root: root.clone(),
            created_at: 1_700_000_000,
            directories: vec![skydriver_sdk_core::CatalogCheckpointDirectory {
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
        let store = CatalogStore::new(
            temporary.path(),
            "101112131415161718191a1b1c1d1e1f",
            &cache_token(1),
            true,
        )
        .expect("catalog store");
        let directory_id = "2031425364758697a8b9cadbecfd0e1f";
        let data_root = empty_directory_root();
        let node = store
            .publish(directory_id, &data_root, &[])
            .expect("publish catalog node");
        assert_eq!(node.directory_id, directory_id);
        assert_eq!(
            store
                .load(directory_id, &data_root)
                .expect("load catalog node")
                .expect("stored node")
                .data_root,
            data_root
        );
        let path = store
            .node_path(directory_id, &data_root)
            .expect("catalog path");
        let mut bytes = std::fs::read(&path).expect("read stored node");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(path, bytes).expect("corrupt stored node");
        assert!(store.load(directory_id, &data_root).is_err());
        store
            .publish(directory_id, &data_root, &[])
            .expect("verified publication replaces invalid cache node");
        assert!(
            store
                .load(directory_id, &data_root)
                .expect("load repaired catalog node")
                .is_some()
        );
    }

    #[test]
    fn isolates_nodes_between_vfs_tokens() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let first = CatalogStore::new(
            temporary.path(),
            "101112131415161718191a1b1c1d1e1f",
            &cache_token(1),
            true,
        )
        .expect("first token catalog");
        let second = CatalogStore::new(
            temporary.path(),
            "202122232425262728292a2b2c2d2e2f",
            &cache_token(2),
            true,
        )
        .expect("second token catalog");
        let directory_id = "303132333435363738393a3b3c3d3e3f";
        let data_root = empty_directory_root();

        first
            .publish(directory_id, &data_root, &[])
            .expect("publish first token node");

        assert!(
            second
                .load(directory_id, &data_root)
                .expect("load second token node")
                .is_none()
        );
    }

    #[test]
    fn encrypts_metadata_at_rest_and_reopens_only_with_the_same_token() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let token_id = "101112131415161718191a1b1c1d1e1f";
        let token = cache_token(1);
        let store =
            CatalogStore::new(temporary.path(), token_id, &token, true).expect("catalog store");
        let directory_id = "2031425364758697a8b9cadbecfd0e1f";
        let data_root = empty_directory_root();
        store
            .publish(directory_id, &data_root, &[])
            .expect("publish encrypted node");
        let path = store
            .node_path(directory_id, &data_root)
            .expect("catalog node path");
        let sealed = std::fs::read(path).expect("read sealed node");
        assert!(!String::from_utf8_lossy(&sealed).contains(NODE_SCHEMA));

        let reopened = CatalogStore::new(temporary.path(), token_id, &token, true)
            .expect("reopen catalog store");
        assert!(
            reopened
                .load(directory_id, &data_root)
                .expect("open same-token node")
                .is_some()
        );
        let wrong_token = CatalogStore::new(temporary.path(), token_id, &cache_token(2), true)
            .expect("wrong-token store");
        assert!(wrong_token.load(directory_id, &data_root).is_err());
    }

    #[test]
    fn disabled_catalog_cache_keeps_metadata_ephemeral() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let token_id = "101112131415161718191a1b1c1d1e1f";
        let store = CatalogStore::new(temporary.path(), token_id, &cache_token(1), false)
            .expect("disabled catalog store");
        let directory_id = "2031425364758697a8b9cadbecfd0e1f";
        let data_root = empty_directory_root();
        store
            .publish(directory_id, &data_root, &[])
            .expect("validate ephemeral node");

        assert!(
            store
                .load(directory_id, &data_root)
                .expect("disabled cache miss")
                .is_none()
        );
        assert!(store.checkpoint_condition().expect("no head").is_none());
        assert!(!temporary.path().join("catalog").exists());
    }

    #[test]
    fn persists_only_a_verified_checkpoint_head() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let store = CatalogStore::new(
            temporary.path(),
            "303132333435363738393a3b3c3d3e3f",
            &cache_token(3),
            true,
        )
        .expect("catalog store");
        let checkpoint = empty_checkpoint();
        let checkpoint_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&checkpoint).expect("encode checkpoint"),
        ));
        let expected = format!("\"sha256:{checkpoint_sha256}\"");

        store
            .publish_checkpoint(&checkpoint, &expected)
            .expect("publish checkpoint");
        assert_eq!(
            store
                .checkpoint_condition()
                .expect("read checkpoint head")
                .map(|condition| condition.etag),
            Some(expected)
        );

        let head_path = store.root.join("head.json");
        let mut bytes = std::fs::read(&head_path).expect("read checkpoint head");
        let middle = bytes.len() / 2;
        bytes[middle] ^= 1;
        std::fs::write(head_path, bytes).expect("corrupt checkpoint head");
        assert!(
            store
                .checkpoint_condition()
                .expect("invalid cache head is discarded")
                .is_none()
        );
    }

    #[test]
    fn catalog_head_never_regresses_when_clients_share_one_cache() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let token = cache_token(3);
        let store = CatalogStore::new(
            temporary.path(),
            "303132333435363738393a3b3c3d3e3f",
            &token,
            true,
        )
        .expect("catalog store");
        let newer = checkpoint_with_child(2, Some(1), "newer");
        let older = checkpoint_with_child(1, None, "older");
        store
            .publish_checkpoint(&newer, &format!("\"sha256:{}\"", checkpoint_sha256(&newer)))
            .expect("publish newer head");
        store
            .publish_checkpoint(&older, &format!("\"sha256:{}\"", checkpoint_sha256(&older)))
            .expect("ignore older head");

        assert_eq!(
            store
                .checkpoint_condition()
                .expect("load monotonic head")
                .expect("catalog head")
                .revision_id,
            2
        );
    }

    #[test]
    fn catalog_gc_removes_only_nodes_outside_the_published_closure() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let store = CatalogStore::new(
            temporary.path(),
            "303132333435363738393a3b3c3d3e3f",
            &cache_token(3),
            true,
        )
        .expect("catalog store");
        let old = checkpoint_with_child(1, None, "old");
        let current = checkpoint_with_child(2, Some(1), "current");
        store
            .publish_checkpoint(&old, &format!("\"sha256:{}\"", checkpoint_sha256(&old)))
            .expect("publish old checkpoint");
        let old_root = store
            .node_path(&old.root_directory_id, &old.root_data_root)
            .expect("old root path");
        let current_root = store
            .node_path(&current.root_directory_id, &current.root_data_root)
            .expect("current root path");
        let shard = u8::from_str_radix(&old.root_data_root[..2], 16).expect("old root shard");
        store.publish_gc_shard(shard).expect("select GC shard");

        store
            .publish_checkpoint(
                &current,
                &format!("\"sha256:{}\"", checkpoint_sha256(&current)),
            )
            .expect("publish current checkpoint");

        assert!(!old_root.exists());
        assert!(current_root.exists());
        assert_eq!(
            store
                .checkpoint_condition()
                .expect("current condition")
                .expect("current head")
                .revision_id,
            2
        );
    }

    #[test]
    fn corrupt_catalog_gc_cursor_falls_back_without_affecting_publication() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let store = CatalogStore::new(
            temporary.path(),
            "303132333435363738393a3b3c3d3e3f",
            &cache_token(3),
            true,
        )
        .expect("catalog store");
        std::fs::write(store.root.join("gc.cursor"), b"not a sealed cursor")
            .expect("write corrupt cursor");
        let checkpoint = empty_checkpoint();
        store
            .publish_checkpoint(
                &checkpoint,
                &format!("\"sha256:{}\"", checkpoint_sha256(&checkpoint)),
            )
            .expect("publish despite corrupt GC hint");

        assert_eq!(store.load_gc_shard(), 1);
        assert!(store.checkpoint_condition().expect("head").is_some());
    }

    #[test]
    fn applies_minimal_delta_over_verified_content_addressed_base() {
        let temporary = tempfile::tempdir().expect("temporary catalog");
        let store = CatalogStore::new(
            temporary.path(),
            "303132333435363738393a3b3c3d3e3f",
            &cache_token(3),
            true,
        )
        .expect("catalog store");
        let base = checkpoint_with_child(1, None, "docs");
        let target = checkpoint_with_child(2, Some(1), "archive");
        let base_sha256 = checkpoint_sha256(&base);
        let target_sha256 = checkpoint_sha256(&target);
        let base_etag = format!("\"sha256:{base_sha256}\"");
        let target_etag = format!("\"sha256:{target_sha256}\"");
        let delta = build_catalog_delta(&base, &base_sha256, &target, &target_sha256)
            .expect("build minimal catalog delta");
        assert_eq!(delta.directories.len(), 1);

        store
            .publish_checkpoint(&base, &base_etag)
            .expect("publish base checkpoint");
        store
            .apply_delta(&delta, &target_etag)
            .expect("apply verified minimal delta");

        let condition = store
            .checkpoint_condition()
            .expect("load target condition")
            .expect("target condition");
        assert_eq!(condition.revision_id, 2);
        assert_eq!(condition.root_data_root, target.root_data_root);
        assert_eq!(condition.checkpoint_sha256, target_sha256);
    }

    fn checkpoint_with_child(
        revision_id: u64,
        parent_revision_id: Option<u64>,
        child_name: &str,
    ) -> CatalogCheckpoint {
        let root_directory_id = "202122232425262728292a2b2c2d2e2f";
        let child_directory_id = "404142434445464748494a4b4c4d4e4f";
        let child_root = hex::encode(directory_merkle_root(&[]).expect("empty child root"));
        let child_root_bytes = decode_hex::<32>(&child_root, "child root").expect("child root hex");
        let root = hex::encode(
            directory_merkle_root(&[DirectoryMerkleEntry::Directory {
                name: child_name,
                stable_id: decode_hex::<16>(child_directory_id, "child identity")
                    .expect("child identity hex"),
                data_root: child_root_bytes,
            }])
            .expect("parent root"),
        );
        CatalogCheckpoint {
            schema: CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id,
            parent_revision_id,
            root_directory_id: root_directory_id.to_owned(),
            root_data_root: root.clone(),
            created_at: 1_700_000_000 + revision_id,
            directories: vec![
                CatalogCheckpointDirectory {
                    directory_id: root_directory_id.to_owned(),
                    parent_directory_id: None,
                    name: String::new(),
                    data_root: root,
                    entries: vec![CatalogCheckpointEntry {
                        name: child_name.to_owned(),
                        kind: CatalogCheckpointEntryKind::Directory,
                        file_id: None,
                        version_id: None,
                        child_directory_id: Some(child_directory_id.to_owned()),
                        size_bytes: 0,
                        data_root: child_root.clone(),
                        metadata_root: None,
                    }],
                },
                CatalogCheckpointDirectory {
                    directory_id: child_directory_id.to_owned(),
                    parent_directory_id: Some(root_directory_id.to_owned()),
                    name: child_name.to_owned(),
                    data_root: child_root,
                    entries: Vec::new(),
                },
            ],
        }
    }

    fn checkpoint_sha256(checkpoint: &CatalogCheckpoint) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(checkpoint).expect("encode checkpoint"),
        ))
    }
}
