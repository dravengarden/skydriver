//! Portable VFS catalog checkpoint schema and verification.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{DirectoryMerkleEntry, Error, directory_merkle_root};

/// Stable complete VFS catalog checkpoint schema.
pub const CATALOG_CHECKPOINT_SCHEMA: &str = "carrack.vfs.catalog-checkpoint.v1";
/// Maximum directories accepted in one complete checkpoint.
pub const MAXIMUM_CATALOG_DIRECTORIES: usize = 5_000;
/// Maximum entries accepted across one complete checkpoint.
pub const MAXIMUM_CATALOG_ENTRIES: usize = 20_000;
/// Maximum encoded bytes accepted for one complete checkpoint.
pub const MAXIMUM_CATALOG_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;

/// Constructs the exact strong HTTP entity tag for one canonical checkpoint
/// SHA-256.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] for anything other than lowercase SHA-256
/// hexadecimal.
pub fn catalog_checkpoint_etag(sha256: &str) -> Result<String, Error> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidInput("catalog checkpoint SHA-256 is invalid"));
    }
    Ok(format!("\"sha256:{sha256}\""))
}

/// Constructs the strong entity tag for one deterministic authorized subtree
/// view of an immutable complete checkpoint.
///
/// The returned tag intentionally differs from the encoded subtree SHA-256:
/// a Worker can reauthorize an unchanged view and answer HTTP 304 without
/// reading and projecting the complete checkpoint from object storage.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when either identity is malformed.
pub fn catalog_checkpoint_view_etag(
    checkpoint_sha256: &str,
    root_directory_id: &str,
) -> Result<String, Error> {
    let checkpoint_digest =
        decode_hex::<32>(checkpoint_sha256, "catalog checkpoint SHA-256 is invalid")?;
    let root = decode_hex::<16>(
        root_directory_id,
        "catalog root directory identity is invalid",
    )?;
    let mut digest = Sha256::new();
    digest.update(b"carrack.vfs.catalog-checkpoint-view-etag.v1\0");
    digest.update(checkpoint_digest);
    digest.update(root);
    catalog_checkpoint_etag(&hex::encode(digest.finalize()))
}

/// Validates the exact strong entity-tag syntax accepted for catalog
/// checkpoint receipts.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] for a weak, unquoted, or noncanonical tag.
pub fn validate_catalog_checkpoint_etag(etag: &str) -> Result<(), Error> {
    let Some(digest) = etag
        .strip_prefix("\"sha256:")
        .and_then(|value| value.strip_suffix('"'))
    else {
        return Err(Error::InvalidInput(
            "catalog checkpoint entity tag is invalid",
        ));
    };
    if catalog_checkpoint_etag(digest)? != etag {
        return Err(Error::InvalidInput(
            "catalog checkpoint entity tag is invalid",
        ));
    }
    Ok(())
}

/// One complete immutable filesystem catalog checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCheckpoint {
    /// Stable schema identity.
    pub schema: String,
    /// Stable filesystem identity.
    pub filesystem_id: String,
    /// Monotonic catalog publication identity.
    pub revision_id: u64,
    /// Previous catalog revision, when one exists.
    pub parent_revision_id: Option<u64>,
    /// Stable filesystem-root directory identity.
    pub root_directory_id: String,
    /// Merkle root committed by the filesystem root.
    pub root_data_root: String,
    /// Server-clock creation time.
    pub created_at: u64,
    /// Canonically ordered complete directory nodes.
    pub directories: Vec<CatalogCheckpointDirectory>,
}

/// One complete directory node inside a catalog checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCheckpointDirectory {
    /// Stable directory identity.
    pub directory_id: String,
    /// Parent directory identity, absent only for the filesystem root.
    pub parent_directory_id: Option<String>,
    /// Canonical name within the parent, empty only for the root.
    pub name: String,
    /// Merkle root over the complete ordered entries.
    pub data_root: String,
    /// Canonically ordered complete directory entries.
    pub entries: Vec<CatalogCheckpointEntry>,
}

/// One immutable file or child-directory entry in a checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCheckpointEntry {
    /// Canonical NFC entry name.
    pub name: String,
    /// Disjoint entry union arm.
    pub kind: CatalogCheckpointEntryKind,
    /// Stable file identity for file entries.
    pub file_id: Option<String>,
    /// Immutable file-version identity for file entries.
    pub version_id: Option<String>,
    /// Stable child identity for directory entries.
    pub child_directory_id: Option<String>,
    /// Plaintext bytes for file entries; zero for directories.
    pub size_bytes: u64,
    /// File or child-directory Merkle root.
    pub data_root: String,
    /// Portable file metadata root for file entries.
    pub metadata_root: Option<String>,
}

/// Checkpoint entry union discriminator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogCheckpointEntryKind {
    /// Complete immutable file version.
    File,
    /// Child directory node.
    Directory,
}

/// Produces the complete Merkle closure rooted at one directory from an
/// already verified immutable checkpoint.
///
/// The selected directory becomes the logical root without changing its
/// content root; its original parent and name are authorization-external
/// navigation metadata and are removed from the projected view.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when the source checkpoint is invalid or
/// the requested directory is absent from its authenticated tree.
pub fn project_catalog_checkpoint(
    checkpoint: &CatalogCheckpoint,
    root_directory_id: &str,
) -> Result<CatalogCheckpoint, Error> {
    validate_catalog_checkpoint(checkpoint)?;
    decode_hex::<16>(
        root_directory_id,
        "catalog projection root identity is invalid",
    )?;

    let by_id = checkpoint
        .directories
        .iter()
        .map(|directory| (directory.directory_id.as_str(), directory))
        .collect::<HashMap<_, _>>();
    let root = by_id
        .get(root_directory_id)
        .copied()
        .ok_or(Error::InvalidInput("catalog projection root is missing"))?;
    let mut selected = HashSet::new();
    let mut pending = vec![root_directory_id];
    while let Some(directory_id) = pending.pop() {
        if !selected.insert(directory_id) {
            return Err(Error::InvalidInput("catalog projection is not a tree"));
        }
        let directory = by_id
            .get(directory_id)
            .copied()
            .ok_or(Error::InvalidInput("catalog projection child is missing"))?;
        for entry in &directory.entries {
            if entry.kind == CatalogCheckpointEntryKind::Directory {
                pending.push(
                    entry
                        .child_directory_id
                        .as_deref()
                        .ok_or(Error::InvalidInput(
                            "catalog projection child identity is missing",
                        ))?,
                );
            }
        }
    }

    let mut directories = checkpoint
        .directories
        .iter()
        .filter(|directory| selected.contains(directory.directory_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let projected_root = directories
        .iter_mut()
        .find(|directory| directory.directory_id == root_directory_id)
        .ok_or(Error::InvalidInput("catalog projection root is missing"))?;
    projected_root.parent_directory_id = None;
    projected_root.name.clear();

    let projected = CatalogCheckpoint {
        schema: checkpoint.schema.clone(),
        filesystem_id: checkpoint.filesystem_id.clone(),
        revision_id: checkpoint.revision_id,
        parent_revision_id: checkpoint.parent_revision_id,
        root_directory_id: root_directory_id.to_owned(),
        root_data_root: root.data_root.clone(),
        created_at: checkpoint.created_at,
        directories,
    };
    validate_catalog_checkpoint(&projected)?;
    Ok(projected)
}

/// Verifies every identity, bound, directory Merkle root, and tree edge in a
/// complete checkpoint.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when the checkpoint is malformed,
/// incomplete, noncanonical, or internally contradictory.
#[allow(
    clippy::too_many_lines,
    reason = "one verifier keeps bounds, Merkle roots, and complete tree reachability in one fail-closed boundary"
)]
pub fn validate_catalog_checkpoint(checkpoint: &CatalogCheckpoint) -> Result<(), Error> {
    if checkpoint.schema != CATALOG_CHECKPOINT_SCHEMA
        || checkpoint.revision_id == 0
        || checkpoint.created_at == 0
        || checkpoint
            .parent_revision_id
            .is_some_and(|parent| parent >= checkpoint.revision_id)
    {
        return Err(Error::InvalidInput(
            "catalog checkpoint identity is invalid",
        ));
    }
    decode_hex::<16>(&checkpoint.filesystem_id, "catalog filesystem identity")?;
    decode_hex::<16>(
        &checkpoint.root_directory_id,
        "catalog root directory identity",
    )?;
    decode_hex::<32>(&checkpoint.root_data_root, "catalog root data root")?;
    if checkpoint.directories.is_empty()
        || checkpoint.directories.len() > MAXIMUM_CATALOG_DIRECTORIES
    {
        return Err(Error::InvalidInput("catalog directory bound exceeded"));
    }
    for pair in checkpoint.directories.windows(2) {
        if pair[0].directory_id.as_bytes() >= pair[1].directory_id.as_bytes() {
            return Err(Error::InvalidInput(
                "catalog directories are not canonically ordered",
            ));
        }
    }

    let mut entry_count = 0_usize;
    let mut by_id = HashMap::with_capacity(checkpoint.directories.len());
    for (index, directory) in checkpoint.directories.iter().enumerate() {
        decode_hex::<16>(&directory.directory_id, "catalog directory identity")?;
        if let Some(parent) = &directory.parent_directory_id {
            decode_hex::<16>(parent, "catalog parent directory identity")?;
            if parent == &directory.directory_id {
                return Err(Error::InvalidInput("catalog directory is self-parented"));
            }
        }
        let expected_root = decode_hex::<32>(&directory.data_root, "catalog directory root")?;
        if by_id
            .insert(directory.directory_id.as_str(), index)
            .is_some()
        {
            return Err(Error::InvalidInput(
                "catalog directory identity is duplicated",
            ));
        }
        entry_count = entry_count
            .checked_add(directory.entries.len())
            .ok_or(Error::InvalidInput("catalog entry bound exceeded"))?;
        if entry_count > MAXIMUM_CATALOG_ENTRIES {
            return Err(Error::InvalidInput("catalog entry bound exceeded"));
        }
        for pair in directory.entries.windows(2) {
            if pair[0].name.as_bytes() >= pair[1].name.as_bytes() {
                return Err(Error::InvalidInput(
                    "catalog entries are not canonically ordered",
                ));
            }
        }
        let merkle_entries = directory
            .entries
            .iter()
            .map(merkle_entry)
            .collect::<Result<Vec<_>, _>>()?;
        if directory_merkle_root(&merkle_entries)? != expected_root {
            return Err(Error::InvalidInput("catalog directory root differs"));
        }
    }

    let root_index = by_id
        .get(checkpoint.root_directory_id.as_str())
        .copied()
        .ok_or(Error::InvalidInput("catalog root directory is missing"))?;
    let root = &checkpoint.directories[root_index];
    if root.parent_directory_id.is_some()
        || !root.name.is_empty()
        || root.data_root != checkpoint.root_data_root
    {
        return Err(Error::InvalidInput("catalog root identity differs"));
    }

    let mut visited = HashSet::with_capacity(checkpoint.directories.len());
    let mut pending = vec![checkpoint.root_directory_id.as_str()];
    while let Some(directory_id) = pending.pop() {
        if !visited.insert(directory_id) {
            return Err(Error::InvalidInput("catalog directory graph is not a tree"));
        }
        let index = by_id
            .get(directory_id)
            .copied()
            .ok_or(Error::InvalidInput("catalog child directory is missing"))?;
        let directory = &checkpoint.directories[index];
        for entry in &directory.entries {
            if entry.kind != CatalogCheckpointEntryKind::Directory {
                continue;
            }
            let child_id = entry
                .child_directory_id
                .as_deref()
                .ok_or(Error::InvalidInput("catalog child identity is missing"))?;
            let child_index = by_id
                .get(child_id)
                .copied()
                .ok_or(Error::InvalidInput("catalog child directory is missing"))?;
            let child = &checkpoint.directories[child_index];
            if child.parent_directory_id.as_deref() != Some(directory.directory_id.as_str())
                || child.name != entry.name
                || child.data_root != entry.data_root
            {
                return Err(Error::InvalidInput("catalog child link differs"));
            }
            pending.push(child_id);
        }
    }
    if visited.len() != checkpoint.directories.len() {
        return Err(Error::InvalidInput(
            "catalog contains an unreachable directory",
        ));
    }
    Ok(())
}

fn merkle_entry(entry: &CatalogCheckpointEntry) -> Result<DirectoryMerkleEntry<'_>, Error> {
    let data_root = decode_hex::<32>(&entry.data_root, "catalog entry data root")?;
    match entry.kind {
        CatalogCheckpointEntryKind::File
            if entry.child_directory_id.is_none()
                && entry.file_id.is_some()
                && entry.version_id.is_some()
                && entry.metadata_root.is_some() =>
        {
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
        CatalogCheckpointEntryKind::Directory
            if entry.file_id.is_none()
                && entry.version_id.is_none()
                && entry.child_directory_id.is_some()
                && entry.metadata_root.is_none()
                && entry.size_bytes == 0 =>
        {
            Ok(DirectoryMerkleEntry::Directory {
                name: &entry.name,
                stable_id: decode_hex::<16>(
                    entry.child_directory_id.as_deref().unwrap_or_default(),
                    "catalog child identity",
                )?,
                data_root,
            })
        }
        _ => Err(Error::InvalidInput("catalog entry union is invalid")),
    }
}

fn decode_hex<const N: usize>(value: &str, error: &'static str) -> Result<[u8; N], Error> {
    if value.len() != N * 2
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidInput(error));
    }
    hex::decode(value)
        .map_err(|_| Error::InvalidInput(error))?
        .try_into()
        .map_err(|_| Error::InvalidInput(error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_checkpoint() -> CatalogCheckpoint {
        let root = hex::encode(directory_merkle_root(&[]).expect("empty directory root"));
        CatalogCheckpoint {
            schema: CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            parent_revision_id: None,
            root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            root_data_root: root.clone(),
            created_at: 1_700_000_000,
            directories: vec![CatalogCheckpointDirectory {
                directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
                parent_directory_id: None,
                name: String::new(),
                data_root: root,
                entries: Vec::new(),
            }],
        }
    }

    #[test]
    fn accepts_complete_empty_checkpoint() {
        validate_catalog_checkpoint(&empty_checkpoint()).expect("valid empty checkpoint");
    }

    #[test]
    fn constructs_strong_checkpoint_etag() {
        assert_eq!(
            catalog_checkpoint_etag(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .expect("checkpoint entity tag"),
            "\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""
        );
        assert!(catalog_checkpoint_etag("AA").is_err());
        validate_catalog_checkpoint_etag(
            "\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
        )
        .expect("valid checkpoint entity tag");
        assert!(validate_catalog_checkpoint_etag("W/\"sha256:aa\"").is_err());
    }

    #[test]
    fn constructs_stable_authorized_view_etag() {
        let tag = catalog_checkpoint_view_etag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "202122232425262728292a2b2c2d2e2f",
        )
        .expect("checkpoint view entity tag");
        assert_eq!(
            tag,
            "\"sha256:c512d6569dbc3c3393c8c12c6c25fff666eae28a91c25ce2b12b353ec601d3cd\""
        );
        validate_catalog_checkpoint_etag(&tag).expect("valid view entity tag");
        assert_ne!(
            tag,
            catalog_checkpoint_etag(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .expect("artifact entity tag")
        );
    }

    #[test]
    fn projects_one_authenticated_subtree() {
        let mut checkpoint = empty_checkpoint();
        let child_id = "303132333435363738393a3b3c3d3e3f";
        let grandchild_id = "404142434445464748494a4b4c4d4e4f";
        let empty_root = hex::encode(directory_merkle_root(&[]).expect("empty directory root"));
        let child_entries = vec![CatalogCheckpointEntry {
            name: "nested".to_owned(),
            kind: CatalogCheckpointEntryKind::Directory,
            file_id: None,
            version_id: None,
            child_directory_id: Some(grandchild_id.to_owned()),
            size_bytes: 0,
            data_root: empty_root.clone(),
            metadata_root: None,
        }];
        let child_root = hex::encode(
            directory_merkle_root(
                &child_entries
                    .iter()
                    .map(merkle_entry)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("child Merkle entries"),
            )
            .expect("child directory root"),
        );
        checkpoint.directories[0].entries = vec![CatalogCheckpointEntry {
            name: "allowed".to_owned(),
            kind: CatalogCheckpointEntryKind::Directory,
            file_id: None,
            version_id: None,
            child_directory_id: Some(child_id.to_owned()),
            size_bytes: 0,
            data_root: child_root.clone(),
            metadata_root: None,
        }];
        checkpoint.directories[0].data_root = hex::encode(
            directory_merkle_root(
                &checkpoint.directories[0]
                    .entries
                    .iter()
                    .map(merkle_entry)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("root Merkle entries"),
            )
            .expect("root directory root"),
        );
        checkpoint.root_data_root = checkpoint.directories[0].data_root.clone();
        checkpoint.directories.push(CatalogCheckpointDirectory {
            directory_id: child_id.to_owned(),
            parent_directory_id: Some(checkpoint.root_directory_id.clone()),
            name: "allowed".to_owned(),
            data_root: child_root.clone(),
            entries: child_entries,
        });
        checkpoint.directories.push(CatalogCheckpointDirectory {
            directory_id: grandchild_id.to_owned(),
            parent_directory_id: Some(child_id.to_owned()),
            name: "nested".to_owned(),
            data_root: empty_root,
            entries: Vec::new(),
        });
        validate_catalog_checkpoint(&checkpoint).expect("source checkpoint");

        let projected =
            project_catalog_checkpoint(&checkpoint, child_id).expect("projected checkpoint");
        assert_eq!(projected.root_directory_id, child_id);
        assert_eq!(projected.root_data_root, child_root);
        assert_eq!(projected.directories.len(), 2);
        assert!(projected.directories[0].parent_directory_id.is_none());
        assert!(projected.directories[0].name.is_empty());
        validate_catalog_checkpoint(&projected).expect("valid projected checkpoint");
    }

    #[test]
    fn rejects_unreachable_directory() {
        let mut checkpoint = empty_checkpoint();
        checkpoint.directories.push(CatalogCheckpointDirectory {
            directory_id: "303132333435363738393a3b3c3d3e3f".to_owned(),
            parent_directory_id: Some(checkpoint.root_directory_id.clone()),
            name: "orphan".to_owned(),
            data_root: hex::encode(directory_merkle_root(&[]).expect("empty directory root")),
            entries: Vec::new(),
        });
        assert!(matches!(
            validate_catalog_checkpoint(&checkpoint),
            Err(Error::InvalidInput(
                "catalog contains an unreachable directory"
            ))
        ));
    }
}
