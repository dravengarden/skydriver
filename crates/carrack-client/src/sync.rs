//! Incremental, verified VFS-directory synchronization to a local tree.

use futures_util::{StreamExt as _, stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

use crate::{EntryKind, Error, GetOptions, VfsClient, integrity};

const STATE_SCHEMA: &str = "carrack.local-sync-state.v1";

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
        let state_path = state_path(&options.state_directory, source);
        let previous = read_state(&state_path, source)?;
        let (directories, files) = self.plan_tree(source, destination).await?;
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
    ) -> Result<(u64, Vec<PlannedFile>), Error> {
        let mut stack = vec![(source.trim_end_matches('/').to_owned(), PathBuf::new())];
        let mut directories = 0_u64;
        let mut files = Vec::new();
        while let Some((vfs_path, relative)) = stack.pop() {
            ensure_directory(&destination.join(&relative))?;
            let page = self
                .list_path(if vfs_path.is_empty() { "/" } else { &vfs_path })
                .await?;
            directories += 1;
            for entry in page.entries.into_iter().rev() {
                let child_relative = relative.join(&entry.name);
                let child_vfs = if vfs_path.is_empty() || vfs_path == "/" {
                    format!("/{}", entry.name)
                } else {
                    format!("{vfs_path}/{}", entry.name)
                };
                match entry.kind {
                    EntryKind::Directory => stack.push((child_vfs, child_relative)),
                    EntryKind::File => files.push(PlannedFile {
                        vfs_path: child_vfs,
                        relative_path: child_relative,
                        version_id: entry.version_id.ok_or_else(|| {
                            Error::InvalidResponse("file entry omitted version identity".to_owned())
                        })?,
                        size_bytes: entry.size_bytes,
                        file_root: entry.data_root,
                    }),
                }
            }
        }
        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok((directories, files))
    }
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
        .get_file(
            &file.vfs_path,
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

fn state_path(root: &Path, source: &str) -> PathBuf {
    root.join(format!(
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
