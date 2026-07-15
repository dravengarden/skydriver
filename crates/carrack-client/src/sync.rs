//! Incremental, verified VFS-directory synchronization to a local tree.

use futures_util::{StreamExt as _, stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

use crate::{
    DirectoryPage, EntryKind, Error, GetOptions, VfsClient,
    catalog::{CatalogNode, CatalogStore},
    download::DownloadExpectation,
    integrity,
    vfs::{CatalogCheckpointOutcome, canonical_components},
};

const STATE_SCHEMA: &str = "carrack.local-sync-state.v1";
const CATALOG_PAGE_SIZE: u32 = 1_000;

/// Bounded incremental directory synchronization settings.
pub struct SyncOptions {
    /// Private state and provider-download journal directory.
    pub state_directory: PathBuf,
    /// Provider range segment bytes for each changed file.
    pub transfer_part_bytes: u64,
    /// Maximum files downloaded concurrently.
    pub maximum_concurrency: usize,
    /// Maximum provider range operations within each file.
    pub maximum_file_concurrency: usize,
}

/// Verified incremental directory synchronization result.
#[derive(Clone, Debug, Serialize)]
pub struct SyncResult {
    /// Stable output schema.
    pub schema: &'static str,
    /// Canonical VFS source directory.
    pub source: String,
    /// Local destination root.
    pub destination: PathBuf,
    /// Directory nodes prefetched from the control plane.
    pub directories: u64,
    /// Complete file entries in the synchronized tree.
    pub files: u64,
    /// Files whose prior local Merkle proof remained valid.
    pub reused_files: u64,
    /// Files downloaded, decrypted, and verified in this run.
    pub downloaded_files: u64,
    /// Plaintext bytes downloaded in this run.
    pub downloaded_bytes: u64,
    /// Correctness-preserving provider degradations.
    pub warnings: Vec<String>,
}

#[derive(Clone)]
struct PlannedFile {
    vfs_path: String,
    relative_path: PathBuf,
    file_id: String,
    version_id: String,
    size_bytes: u64,
    file_root: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateRecord {
    relative_path: PathBuf,
    version_id: String,
    size_bytes: u64,
    file_root: String,
    verification_block_bytes: u64,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyncState {
    schema: String,
    source: String,
    records: Vec<StateRecord>,
}

struct Downloaded {
    record: StateRecord,
    warnings: Vec<String>,
}

struct CatalogFence {
    filesystem_id: String,
    directory_id: String,
    revision: u64,
    data_root: String,
}

struct PendingDirectory {
    vfs_path: String,
    relative_path: PathBuf,
    directory_id: String,
    data_root: String,
    node: Option<CatalogNode>,
}

impl VfsClient {
    /// Incrementally synchronizes one VFS directory into a local directory.
    ///
    /// The complete remote catalog is fetched before provider reads begin.
    /// Unchanged local files are reused only after recomputing their exact
    /// plaintext Merkle root with the previously authenticated block size.
    /// Changed files download concurrently and each file retains its own
    /// resumable exact-range pipeline. Untracked local files are preserved.
    ///
    /// # Errors
    ///
    /// Fails without publishing sync state when catalog traversal, local path
    /// safety, provider reads, decryption, or any Merkle verification fails.
    #[allow(
        clippy::too_many_lines,
        reason = "catalog planning, verified reuse, bounded downloads, and atomic state publication share one sync boundary"
    )]
    pub async fn sync_to_local(
        &self,
        source: &str,
        destination: &Path,
        options: &SyncOptions,
    ) -> Result<SyncResult, Error> {
        validate_options(options)?;
        ensure_directory(destination)?;
        protect_directory(&options.state_directory)?;
        let session = self.session().await?;
        let catalog = CatalogStore::new(&options.state_directory, &session.token_id)?;
        let checkpoint_etag = catalog.checkpoint_etag()?;
        let bulk_catalog_authorized = match self
            .catalog_checkpoint(&session, checkpoint_etag.as_deref())
            .await?
        {
            CatalogCheckpointOutcome::Delivered(delivery) => {
                catalog.publish_checkpoint(&delivery.checkpoint, &delivery.etag)?;
                true
            }
            CatalogCheckpointOutcome::Unchanged => true,
            CatalogCheckpointOutcome::Unavailable => false,
        };
        let state_path = state_path(&options.state_directory, &session.token_id, source);
        let previous = read_state(&state_path, source)?;
        let (directories, files) = self
            .plan_tree(
                source,
                destination,
                &catalog,
                &session,
                options.maximum_concurrency,
                bulk_catalog_authorized,
            )
            .await?;
        let mut records = Vec::with_capacity(files.len());
        let mut downloads = Vec::new();
        let mut reused_files = 0_u64;
        for file in files {
            let local_path = destination.join(&file.relative_path);
            let reusable = previous.records.iter().find(|record| {
                record.relative_path == file.relative_path
                    && record.version_id == file.version_id
                    && record.size_bytes == file.size_bytes
                    && record.file_root == file.file_root
            });
            if let Some(record) = reusable
                && local_matches(&local_path, record)?
            {
                records.push(record.clone());
                reused_files += 1;
            } else {
                downloads.push(file);
            }
        }

        let client = self.clone();
        let destination = destination.to_owned();
        let result_destination = destination.clone();
        let state_directory = options.state_directory.clone();
        let transfer_part_bytes = options.transfer_part_bytes;
        let file_concurrency = options.maximum_file_concurrency;
        let maximum_concurrency = options.maximum_concurrency;
        let mut pending = stream::iter(downloads.into_iter().map(move |file| {
            let client = client.clone();
            let destination = destination.clone();
            let state_directory = state_directory.clone();
            async move {
                download_one(
                    &client,
                    &file,
                    &destination,
                    &state_directory,
                    transfer_part_bytes,
                    file_concurrency,
                )
                .await
            }
        }))
        .buffer_unordered(maximum_concurrency);
        let mut warnings = Vec::new();
        let mut downloaded_bytes = 0_u64;
        let mut downloaded_files = 0_u64;
        while let Some(downloaded) = pending.next().await {
            let downloaded = downloaded?;
            downloaded_bytes = downloaded_bytes.saturating_add(downloaded.record.size_bytes);
            downloaded_files += 1;
            warnings.extend(downloaded.warnings);
            records.push(downloaded.record);
        }
        records.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        warnings.sort();
        warnings.dedup();
        write_state(
            &state_path,
            &SyncState {
                schema: STATE_SCHEMA.to_owned(),
                source: source.to_owned(),
                records,
            },
        )?;
        Ok(SyncResult {
            schema: "carrack.fs-sync.v1",
            source: source.to_owned(),
            destination: result_destination,
            directories,
            files: reused_files + downloaded_files,
            reused_files,
            downloaded_files,
            downloaded_bytes,
            warnings,
        })
    }

    async fn plan_tree(
        &self,
        source: &str,
        destination: &Path,
        catalog: &CatalogStore,
        session: &crate::VfsSession,
        maximum_concurrency: usize,
        bulk_catalog_authorized: bool,
    ) -> Result<(u64, Vec<PlannedFile>), Error> {
        let (fence, root) = self
            .source_catalog(source, catalog, session, bulk_catalog_authorized)
            .await?;
        let canonical_source = if source == "/" {
            String::new()
        } else {
            source.trim_end_matches('/').to_owned()
        };
        let mut pending = VecDeque::from([PendingDirectory {
            vfs_path: canonical_source,
            relative_path: PathBuf::new(),
            directory_id: root.directory_id.clone(),
            data_root: root.data_root.clone(),
            node: Some(root),
        }]);
        let mut directories = 0_u64;
        let mut files = Vec::new();
        while !pending.is_empty() {
            let batch = (0..maximum_concurrency)
                .filter_map(|_| pending.pop_front())
                .collect::<Vec<_>>();
            let mut loaded = stream::iter(batch.into_iter().map(|mut task| async move {
                let node = match task.node.take() {
                    Some(node) => node,
                    None => {
                        self.load_catalog_node(
                            catalog,
                            &task.directory_id,
                            &task.data_root,
                            bulk_catalog_authorized,
                        )
                        .await?
                    }
                };
                Ok::<_, Error>((task, node))
            }))
            .buffer_unordered(maximum_concurrency);
            while let Some(result) = loaded.next().await {
                let (task, node) = result?;
                ensure_directory(&destination.join(&task.relative_path))?;
                directories += 1;
                for entry in node.entries {
                    let child_relative = task.relative_path.join(&entry.name);
                    let child_vfs = if task.vfs_path.is_empty() {
                        format!("/{}", entry.name)
                    } else {
                        format!("{}/{}", task.vfs_path, entry.name)
                    };
                    match entry.kind {
                        EntryKind::Directory => pending.push_back(PendingDirectory {
                            vfs_path: child_vfs,
                            relative_path: child_relative,
                            directory_id: required(
                                entry.child_directory_id,
                                "catalog directory entry omitted child identity",
                            )?,
                            data_root: entry.data_root,
                            node: None,
                        }),
                        EntryKind::File => files.push(PlannedFile {
                            vfs_path: child_vfs,
                            relative_path: child_relative,
                            file_id: required(
                                entry.file_id,
                                "catalog file entry omitted file identity",
                            )?,
                            version_id: required(
                                entry.version_id,
                                "catalog file entry omitted version identity",
                            )?,
                            size_bytes: entry.size_bytes,
                            file_root: entry.data_root,
                        }),
                    }
                }
            }
        }
        let final_page = self.list_directory(&fence.directory_id, None, 1).await?;
        validate_page_identity(
            &final_page,
            &fence.directory_id,
            &fence.data_root,
            Some((&fence.filesystem_id, fence.revision)),
        )?;
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok((directories, files))
    }

    async fn source_catalog(
        &self,
        source: &str,
        catalog: &CatalogStore,
        session: &crate::VfsSession,
        bulk_catalog_authorized: bool,
    ) -> Result<(CatalogFence, CatalogNode), Error> {
        let components = canonical_components(source)?;
        let root_page = self
            .list_directory(&session.root_directory_id, None, CATALOG_PAGE_SIZE)
            .await?;
        validate_page_identity(
            &root_page,
            &session.root_directory_id,
            &root_page.directory.data_root,
            None,
        )?;
        let mut current = self
            .load_catalog_from_first(catalog, root_page.clone())
            .await?;
        let mut source_id = current.directory_id.clone();
        let mut source_root = current.data_root.clone();
        for (index, component) in components.iter().enumerate() {
            let entry = current
                .entries
                .iter()
                .find(|entry| entry.name == *component)
                .ok_or_else(|| Error::Rejected {
                    status: 404,
                    message: format!("VFS path not found: {source}"),
                })?;
            if entry.kind != EntryKind::Directory {
                return Err(Error::Rejected {
                    status: 400,
                    message: format!("VFS path is not a directory: {source}"),
                });
            }
            source_id = required(
                entry.child_directory_id.clone(),
                "catalog directory entry omitted child identity",
            )?;
            source_root = entry.data_root.clone();
            if index + 1 != components.len() {
                current = self
                    .load_catalog_node(catalog, &source_id, &source_root, bulk_catalog_authorized)
                    .await?;
            }
        }
        let source_page = if components.is_empty() {
            root_page
        } else {
            self.list_directory(&source_id, None, CATALOG_PAGE_SIZE)
                .await?
        };
        validate_page_identity(&source_page, &source_id, &source_root, None)?;
        let fence = CatalogFence {
            filesystem_id: source_page.directory.filesystem_id.clone(),
            directory_id: source_id,
            revision: source_page.directory.revision,
            data_root: source_root,
        };
        let node = self.load_catalog_from_first(catalog, source_page).await?;
        Ok((fence, node))
    }

    async fn load_catalog_node(
        &self,
        catalog: &CatalogStore,
        directory_id: &str,
        data_root: &str,
        bulk_catalog_authorized: bool,
    ) -> Result<CatalogNode, Error> {
        if bulk_catalog_authorized && let Some(node) = catalog.load(directory_id, data_root)? {
            return Ok(node);
        }
        let first = self
            .list_directory(directory_id, None, CATALOG_PAGE_SIZE)
            .await?;
        validate_page_identity(&first, directory_id, data_root, None)?;
        self.load_catalog_from_first(catalog, first).await
    }

    async fn load_catalog_from_first(
        &self,
        catalog: &CatalogStore,
        mut page: DirectoryPage,
    ) -> Result<CatalogNode, Error> {
        let directory_id = page.directory.id.clone();
        let data_root = page.directory.data_root.clone();
        if let Some(node) = catalog.load(&directory_id, &data_root)? {
            return Ok(node);
        }
        let filesystem_id = page.directory.filesystem_id.clone();
        let revision = page.directory.revision;
        let mut cursor = page.next_cursor.take();
        while let Some(next) = cursor {
            let mut continuation = self
                .list_directory(&directory_id, Some(&next), CATALOG_PAGE_SIZE)
                .await?;
            validate_page_identity(
                &continuation,
                &directory_id,
                &data_root,
                Some((&filesystem_id, revision)),
            )?;
            page.entries.append(&mut continuation.entries);
            cursor = continuation.next_cursor.take();
        }
        catalog.publish(&directory_id, &data_root, &page.entries)
    }
}

fn validate_page_identity(
    page: &DirectoryPage,
    directory_id: &str,
    data_root: &str,
    fence: Option<(&str, u64)>,
) -> Result<(), Error> {
    if page.schema != "carrack.vfs.directory-list.v1"
        || page.directory.id != directory_id
        || page.directory.data_root != data_root
        || page.directory.revision == 0
        || fence.is_some_and(|(filesystem_id, revision)| {
            page.directory.filesystem_id != filesystem_id || page.directory.revision != revision
        })
    {
        return Err(Error::InvalidResponse(
            "directory page differs from the catalog fence".to_owned(),
        ));
    }
    Ok(())
}

fn required(value: Option<String>, message: &'static str) -> Result<String, Error> {
    value.ok_or_else(|| Error::InvalidResponse(message.to_owned()))
}

async fn download_one(
    client: &VfsClient,
    file: &PlannedFile,
    destination: &Path,
    state_directory: &Path,
    transfer_part_bytes: u64,
    maximum_file_concurrency: usize,
) -> Result<Downloaded, Error> {
    let target = destination.join(&file.relative_path);
    let parent = target
        .parent()
        .ok_or_else(|| Error::InvalidResponse("sync target has no parent".to_owned()))?;
    ensure_directory(parent)?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::InvalidResponse("sync target filename is not UTF-8".to_owned()))?;
    let temporary = parent.join(format!(".{file_name}.carrack-{}.tmp", file.version_id));
    if temporary.exists() {
        std::fs::remove_file(&temporary).map_err(local_error("remove stale sync temporary"))?;
    }
    let result = client
        .get_file_version(
            &file.vfs_path,
            DownloadExpectation::new(
                &file.file_id,
                &file.version_id,
                file.size_bytes,
                &file.file_root,
            ),
            &temporary,
            &GetOptions {
                staging_directory: state_directory.join("downloads").join(&file.version_id),
                transfer_part_bytes,
                maximum_concurrency: maximum_file_concurrency,
            },
        )
        .await?;
    if result.version_id != file.version_id || result.file_root != file.file_root {
        let _ = std::fs::remove_file(&temporary);
        return Err(Error::InvalidResponse(
            "sync download identity changed".to_owned(),
        ));
    }
    std::fs::rename(&temporary, &target).map_err(local_error("publish synchronized file"))?;
    Ok(Downloaded {
        record: StateRecord {
            relative_path: file.relative_path.clone(),
            version_id: file.version_id.clone(),
            size_bytes: file.size_bytes,
            file_root: file.file_root.clone(),
            verification_block_bytes: result.verification_block_bytes,
        },
        warnings: result.warnings,
    })
}

fn local_matches(path: &Path, record: &StateRecord) -> Result<bool, Error> {
    if !path
        .metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.len() == record.size_bytes)
    {
        return Ok(false);
    }
    let tree = integrity::build_file(path, record.verification_block_bytes)?;
    Ok(tree.size_bytes == record.size_bytes && hex::encode(tree.root) == record.file_root)
}

fn validate_options(options: &SyncOptions) -> Result<(), Error> {
    if options.transfer_part_bytes == 0
        || options.maximum_concurrency == 0
        || options.maximum_file_concurrency == 0
    {
        return Err(Error::InvalidResponse(
            "sync pipeline bounds must be nonzero".to_owned(),
        ));
    }
    Ok(())
}

fn state_path(root: &Path, token_id: &str, source: &str) -> PathBuf {
    root.join("sync/tokens").join(token_id).join(format!(
        "{}.json",
        hex::encode(Sha256::digest(source.as_bytes()))
    ))
}

fn read_state(path: &Path, source: &str) -> Result<SyncState, Error> {
    let Ok(bytes) = std::fs::read(path) else {
        return Ok(SyncState::default());
    };
    let state: SyncState = serde_json::from_slice(&bytes)
        .map_err(|error| Error::InvalidResponse(format!("decode local sync state: {error}")))?;
    if state.schema != STATE_SCHEMA || state.source != source {
        return Err(Error::InvalidResponse(
            "local sync state identity differs".to_owned(),
        ));
    }
    Ok(state)
}

fn write_state(path: &Path, state: &SyncState) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidResponse("local sync state has no parent".to_owned()))?;
    protect_directory(parent)?;
    let bytes = serde_json::to_vec(state)
        .map_err(|error| Error::InvalidResponse(format!("encode local sync state: {error}")))?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, bytes).map_err(local_error("write local sync state"))?;
    std::fs::rename(&temporary, path).map_err(local_error("publish local sync state"))
}

fn ensure_directory(path: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(path).map_err(local_error("create local sync directory"))?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(local_error("inspect local sync directory"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidResponse(
            "local sync directory is not a real directory".to_owned(),
        ));
    }
    Ok(())
}

fn protect_directory(path: &Path) -> Result<(), Error> {
    ensure_directory(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(local_error("protect local sync state"))?;
    }
    Ok(())
}

fn local_error(context: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |error| Error::InvalidResponse(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use carrack_sdk_core::{
        CATALOG_CHECKPOINT_SCHEMA, CatalogCheckpoint, CatalogCheckpointDirectory,
        CatalogCheckpointEntry, CatalogCheckpointEntryKind, DirectoryMerkleEntry,
        catalog_checkpoint_view_etag, directory_merkle_root,
    };
    use httpmock::{Method::GET, MockServer};
    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::{SyncOptions, VfsClient};
    use crate::VfsToken;

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end checkpoint test keeps every authenticated page and expected hit count visible"
    )]
    async fn hydrates_checkpoint_and_revalidates_only_the_root() {
        let server = MockServer::start_async().await;
        let filesystem_id = "101112131415161718191a1b1c1d1e1f";
        let root_id = "202122232425262728292a2b2c2d2e2f";
        let child_id = "303132333435363738393a3b3c3d3e3f";
        let empty_root = "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254";
        let child_root: [u8; 32] = hex::decode(empty_root)
            .expect("empty directory root hex")
            .try_into()
            .expect("empty directory root length");
        let root_data_root = hex::encode(
            directory_merkle_root(&[DirectoryMerkleEntry::Directory {
                name: "docs",
                stable_id: hex::decode(child_id)
                    .expect("child identity hex")
                    .try_into()
                    .expect("child identity length"),
                data_root: child_root,
            }])
            .expect("root directory Merkle root"),
        );
        let root_page = json!({
            "schema": "carrack.vfs.directory-list.v1",
            "directory": {
                "id": root_id,
                "filesystem_id": filesystem_id,
                "parent_id": null,
                "name": "",
                "data_root": root_data_root,
                "crypto_suite": "aes-256-gcm-hkdf-sha256-v1",
                "active_key_epoch": 1,
                "acl_inherits": false,
                "revision": 7,
                "acl_revision": 1,
                "placement_revision": 1
            },
            "entries": [{
                "name": "docs",
                "kind": "directory",
                "file_id": null,
                "version_id": null,
                "child_directory_id": child_id,
                "size_bytes": 0,
                "data_root": empty_root,
                "metadata_root": null,
                "revision": 1,
                "updated_at": 1_700_000_000
            }],
            "next_cursor": null
        });
        let child_page = json!({
            "schema": "carrack.vfs.directory-list.v1",
            "directory": {
                "id": child_id,
                "filesystem_id": filesystem_id,
                "parent_id": root_id,
                "name": "docs",
                "data_root": empty_root,
                "crypto_suite": "aes-256-gcm-hkdf-sha256-v1",
                "active_key_epoch": 1,
                "acl_inherits": true,
                "revision": 3,
                "acl_revision": 1,
                "placement_revision": 1
            },
            "entries": [],
            "next_cursor": null
        });
        let checkpoint = CatalogCheckpoint {
            schema: CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: filesystem_id.to_owned(),
            revision_id: 11,
            parent_revision_id: Some(10),
            root_directory_id: root_id.to_owned(),
            root_data_root: root_data_root.clone(),
            created_at: 1_700_000_000,
            directories: vec![
                CatalogCheckpointDirectory {
                    directory_id: root_id.to_owned(),
                    parent_directory_id: None,
                    name: String::new(),
                    data_root: root_data_root.clone(),
                    entries: vec![CatalogCheckpointEntry {
                        name: "docs".to_owned(),
                        kind: CatalogCheckpointEntryKind::Directory,
                        file_id: None,
                        version_id: None,
                        child_directory_id: Some(child_id.to_owned()),
                        size_bytes: 0,
                        data_root: empty_root.to_owned(),
                        metadata_root: None,
                    }],
                },
                CatalogCheckpointDirectory {
                    directory_id: child_id.to_owned(),
                    parent_directory_id: Some(root_id.to_owned()),
                    name: "docs".to_owned(),
                    data_root: empty_root.to_owned(),
                    entries: Vec::new(),
                },
            ],
        };
        let checkpoint_body = serde_json::to_vec(&checkpoint).expect("encode checkpoint");
        let checkpoint_sha256 = hex::encode(Sha256::digest(&checkpoint_body));
        let checkpoint_etag = catalog_checkpoint_view_etag(&checkpoint_sha256, root_id)
            .expect("checkpoint view entity tag");
        let session = server
            .mock_async(|when, then| {
                when.method(GET).path("/api/v2/session");
                then.status(200).json_body(json!({
                    "schema": "carrack.vfs.session.v1",
                    "token_id": "404142434445464748494a4b4c4d4e4f",
                    "principal_id": "505152535455565758595a5b5c5d5e5f",
                    "root_directory_id": root_id,
                    "expires_at": 2_000_000_000
                }));
            })
            .await;
        let checkpoint_delivery = server
            .mock_async(|when, then| {
                when.method(GET).path("/api/v2/catalog/checkpoint");
                then.status(200)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", checkpoint_body.len().to_string())
                    .header("ETag", checkpoint_etag)
                    .header("Carrack-Catalog-SHA256", checkpoint_sha256)
                    .header("Carrack-Catalog-Revision", "11")
                    .header("Carrack-Catalog-Root", root_data_root.clone())
                    .body(checkpoint_body);
            })
            .await;
        let root_catalog = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/api/v2/directories/{root_id}/entries"))
                    .query_param("limit", "1000");
                then.status(200).json_body(root_page.clone());
            })
            .await;
        let root_fence = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/api/v2/directories/{root_id}/entries"))
                    .query_param("limit", "1");
                then.status(200).json_body(root_page.clone());
            })
            .await;
        let child_catalog = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path(format!("/api/v2/directories/{child_id}/entries"))
                    .query_param("limit", "1000");
                then.status(200).json_body(child_page);
            })
            .await;
        let encoded_token = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let client = VfsClient::new(
            &format!("{}/", server.base_url()),
            VfsToken::parse(&encoded_token).expect("VFS token"),
        )
        .expect("VFS client");
        let temporary = tempfile::tempdir().expect("sync temporary directory");
        let destination = temporary.path().join("destination");
        let options = SyncOptions {
            state_directory: temporary.path().join("state"),
            transfer_part_bytes: 1024,
            maximum_concurrency: 2,
            maximum_file_concurrency: 2,
        };

        for _ in 0..2 {
            let result = client
                .sync_to_local("/", &destination, &options)
                .await
                .expect("synchronize empty child tree");
            assert_eq!(result.directories, 2);
            assert_eq!(result.files, 0);
            assert!(destination.join("docs").is_dir());
        }

        session.assert_hits_async(2).await;
        checkpoint_delivery.assert_hits_async(2).await;
        root_catalog.assert_hits_async(2).await;
        root_fence.assert_hits_async(2).await;
        child_catalog.assert_hits_async(0).await;
    }
}
