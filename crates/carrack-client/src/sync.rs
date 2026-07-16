//! Incremental, verified VFS-directory synchronization to a local tree.

use futures_util::{StreamExt as _, stream};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{
    cell::Cell,
    collections::VecDeque,
    io::{BufReader, BufWriter, Read as _, Write as _},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    DirectoryPage, EntryKind, Error, GetOptions, VfsClient,
    catalog::{CatalogEntry, CatalogNode, CatalogStore, merkle_entry},
    download::DownloadExpectation,
    integrity,
    vfs::{CatalogCheckpointOutcome, canonical_components},
};

const LEGACY_STATE_SCHEMA: &str = "carrack.local-sync-state.v1";
const STATE_SCHEMA: &str = "carrack.local-sync-state.v2";
const CATALOG_PAGE_SIZE: u32 = 1_000;
const MAXIMUM_MEMORY_DIRECTORY_ENTRIES: usize = 20_000;
const MAXIMUM_SPOOL_RECORD_BYTES: usize = 1024 * 1024;
static PLAN_SPOOL_ORDINAL: AtomicU64 = AtomicU64::new(0);
static STATE_TEMPORARY_ORDINAL: AtomicU64 = AtomicU64::new(0);

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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySyncState {
    schema: String,
    source: String,
    records: Vec<StateRecord>,
}

struct StateIndex {
    connection: rusqlite::Connection,
    healthy: Cell<bool>,
}

impl StateIndex {
    fn open(path: &Path, source: &str) -> Result<Self, Error> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(local_error("inspect indexed local sync state"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(Error::InvalidResponse(
                "indexed local sync state is not a regular file".to_owned(),
            ));
        }
        let connection = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(state_database_error("open indexed local sync state"))?;
        connection
            .execute_batch("PRAGMA trusted_schema = OFF; PRAGMA query_only = ON;")
            .map_err(state_database_error("harden indexed local sync state"))?;
        // This index is only a hint: every reused file is still hashed against the
        // server-pinned root. Avoid an O(N) quick_check on every warm sync; SQLite
        // read errors and malformed rows instead disable or miss the hint safely.
        let identity = connection
            .query_row("SELECT schema, source FROM state_identity", [], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .optional()
            .map_err(state_database_error("read indexed local sync identity"))?;
        if identity
            .as_ref()
            .map(|(schema, source)| (schema.as_str(), source.as_str()))
            != Some((STATE_SCHEMA, source))
        {
            return Err(Error::InvalidResponse(
                "indexed local sync state identity differs".to_owned(),
            ));
        }
        Ok(Self {
            connection,
            healthy: Cell::new(true),
        })
    }

    fn lookup(&self, relative_path: &Path) -> Option<StateRecord> {
        if !self.healthy.get() {
            return None;
        }
        let path = relative_path.to_str()?;
        let result = self
            .connection
            .query_row(
                "SELECT version_id, size_bytes, file_root, verification_block_bytes FROM state_records WHERE relative_path = ?1",
                [path],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional();
        let row = if let Ok(row) = result {
            row
        } else {
            self.healthy.set(false);
            return None;
        }?;
        let size_bytes = canonical_u64(&row.1)?;
        let verification_block_bytes = canonical_u64(&row.3)?;
        if row.0.is_empty()
            || row.2.len() != 64
            || hex::decode(&row.2).is_err()
            || verification_block_bytes == 0
            || verification_block_bytes > 256 * 1024 * 1024
        {
            return None;
        }
        Some(StateRecord {
            relative_path: relative_path.to_owned(),
            version_id: row.0,
            size_bytes,
            file_root: row.2,
            verification_block_bytes,
        })
    }
}

struct Downloaded {
    record: StateRecord,
    warnings: Vec<String>,
}

struct RecordSpool<T> {
    path: Option<PathBuf>,
    writer: Option<BufWriter<std::fs::File>>,
    record: PhantomData<T>,
}

struct RecordSpoolReader<T> {
    path: Option<PathBuf>,
    file: std::fs::File,
    record: PhantomData<T>,
}

struct LoadedDirectory {
    directory_id: String,
    data_root: String,
    entries: LoadedEntries,
}

enum LoadedEntries {
    Memory(std::vec::IntoIter<CatalogEntry>),
    Spool(RecordSpoolReader<CatalogEntry>),
}

impl Iterator for LoadedEntries {
    type Item = Result<CatalogEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Memory(entries) => entries.next().map(Ok),
            Self::Spool(entries) => entries.next(),
        }
    }
}

impl From<CatalogNode> for LoadedDirectory {
    fn from(node: CatalogNode) -> Self {
        Self {
            directory_id: node.directory_id,
            data_root: node.data_root,
            entries: LoadedEntries::Memory(node.entries.into_iter()),
        }
    }
}

fn retain_bounded<T>(retained: &mut Option<Vec<T>>, value: T, maximum: usize) {
    if let Some(values) = retained {
        if values.len() < maximum {
            values.push(value);
        } else {
            *retained = None;
        }
    }
}

#[derive(Debug)]
struct DestinationLock {
    _ancestors: Vec<std::fs::File>,
    _destination: std::fs::File,
}

impl<T> RecordSpool<T> {
    fn create(state_directory: &Path) -> Result<Self, Error> {
        let directory = state_directory.join("sync/plans");
        protect_directory(&directory)?;
        loop {
            let ordinal = PLAN_SPOOL_ORDINAL.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(".plan-{}-{ordinal:016x}.spool", std::process::id()));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        if let Err(error) =
                            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                        {
                            drop(file);
                            let _ = std::fs::remove_file(&path);
                            return Err(local_error("protect sync record spool")(error));
                        }
                    }
                    return Ok(Self {
                        path: Some(path),
                        writer: Some(BufWriter::new(file)),
                        record: PhantomData,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(local_error("create sync record spool")(error)),
            }
        }
    }

    fn append(&mut self, record: &T) -> Result<(), Error>
    where
        T: Serialize,
    {
        let encoded = serde_json::to_vec(record).map_err(|error| {
            Error::InvalidResponse(format!("encode sync spool record: {error}"))
        })?;
        if encoded.is_empty() || encoded.len() > MAXIMUM_SPOOL_RECORD_BYTES {
            return Err(Error::InvalidResponse(
                "sync spool record exceeds its local bound".to_owned(),
            ));
        }
        let length = u32::try_from(encoded.len()).map_err(|_| {
            Error::InvalidResponse("sync spool record length exceeds u32".to_owned())
        })?;
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| Error::InvalidResponse("sync record spool is sealed".to_owned()))?;
        writer
            .write_all(&length.to_be_bytes())
            .and_then(|()| writer.write_all(&encoded))
            .map_err(local_error("write sync record spool"))?;
        Ok(())
    }

    fn finish(mut self) -> Result<RecordSpoolReader<T>, Error> {
        let mut writer = self
            .writer
            .take()
            .ok_or_else(|| Error::InvalidResponse("sync record spool is sealed".to_owned()))?;
        writer
            .flush()
            .map_err(local_error("flush sync record spool"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(local_error("sync record spool"))?;
        drop(writer);
        let path = self.path.take().ok_or_else(|| {
            Error::InvalidResponse("sync record spool path is missing".to_owned())
        })?;
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(local_error("open sync record spool")(error));
            }
        };
        Ok(RecordSpoolReader {
            path: Some(path),
            file,
            record: PhantomData,
        })
    }
}

impl<T> Drop for RecordSpool<T> {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl<T> Iterator for RecordSpoolReader<T>
where
    T: DeserializeOwned,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut encoded_length = [0_u8; 4];
        match self.file.read(&mut encoded_length[..1]) {
            Ok(0) => return None,
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read returned more than one byte"),
            Err(error) => return Some(Err(local_error("read sync record spool")(error))),
        }
        if let Err(error) = self.file.read_exact(&mut encoded_length[1..]) {
            return Some(Err(local_error("read sync spool record length")(error)));
        }
        let length = u32::from_be_bytes(encoded_length) as usize;
        if length == 0 || length > MAXIMUM_SPOOL_RECORD_BYTES {
            return Some(Err(Error::InvalidResponse(
                "sync spool record length is invalid".to_owned(),
            )));
        }
        let mut encoded = vec![0_u8; length];
        if let Err(error) = self.file.read_exact(&mut encoded) {
            return Some(Err(local_error("read sync spool record")(error)));
        }
        Some(
            serde_json::from_slice(&encoded).map_err(|error| {
                Error::InvalidResponse(format!("decode sync spool record: {error}"))
            }),
        )
    }
}

impl<T> Drop for RecordSpoolReader<T> {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
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
    node: Option<LoadedDirectory>,
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
        let _destination_lock = acquire_sync_lock(destination)?;
        let session = self.session().await?;
        let catalog = CatalogStore::new(&options.state_directory, &session.token_id)?;
        let checkpoint_condition = catalog.checkpoint_condition()?;
        let bulk_catalog_authorized = match self
            .catalog_checkpoint(&session, checkpoint_condition.as_ref())
            .await?
        {
            CatalogCheckpointOutcome::Delivered(delivery) => {
                catalog.publish_checkpoint(&delivery.checkpoint, &delivery.etag)?;
                true
            }
            CatalogCheckpointOutcome::Delta(delivery) => {
                catalog.apply_delta(&delivery.delta, &delivery.etag)?;
                true
            }
            CatalogCheckpointOutcome::Unchanged => true,
            CatalogCheckpointOutcome::Unavailable => false,
        };
        let state_path = state_path(&options.state_directory, &session.token_id, source);
        let legacy_state_path =
            legacy_state_path(&options.state_directory, &session.token_id, source);
        let (previous, mut warnings) = open_state_index(
            &options.state_directory,
            &state_path,
            &legacy_state_path,
            source,
        )?;
        let plan_spool = RecordSpool::<PlannedFile>::create(&options.state_directory)?;
        let (fence, directories, files) = self
            .plan_tree(
                source,
                destination,
                &catalog,
                &session,
                &options.state_directory,
                options.maximum_concurrency,
                bulk_catalog_authorized,
                plan_spool,
            )
            .await?;
        let mut records = RecordSpool::<StateRecord>::create(&options.state_directory)?;
        let mut downloads = RecordSpool::<PlannedFile>::create(&options.state_directory)?;
        let mut reused_files = 0_u64;
        for file in files.finish()? {
            let file = file?;
            let local_path = destination.join(&file.relative_path);
            let reusable = match &previous {
                Some(index) => index.lookup(&file.relative_path),
                None => None,
            }
            .filter(|record| {
                record.relative_path == file.relative_path
                    && record.version_id == file.version_id
                    && record.size_bytes == file.size_bytes
                    && record.file_root == file.file_root
            });
            if let Some(record) = reusable
                && local_matches(&local_path, &record)?
            {
                records.append(&record)?;
                reused_files += 1;
            } else {
                downloads.append(&file)?;
            }
        }

        let client = self.clone();
        let destination = destination.to_owned();
        let result_destination = destination.clone();
        let state_directory = options.state_directory.clone();
        let transfer_part_bytes = options.transfer_part_bytes;
        let file_concurrency = options.maximum_file_concurrency;
        let maximum_concurrency = options.maximum_concurrency;
        let mut pending = stream::iter(downloads.finish()?.map(move |file| {
            let client = client.clone();
            let destination = destination.clone();
            let state_directory = state_directory.clone();
            async move {
                let file = file?;
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
        let mut downloaded_bytes = 0_u64;
        let mut downloaded_files = 0_u64;
        while let Some(downloaded) = pending.next().await {
            let downloaded = downloaded?;
            downloaded_bytes = downloaded_bytes.saturating_add(downloaded.record.size_bytes);
            downloaded_files += 1;
            warnings.extend(downloaded.warnings);
            records.append(&downloaded.record)?;
        }
        let final_page = self.list_directory(&fence.directory_id, None, 1).await?;
        validate_page_identity(
            &final_page,
            &fence.directory_id,
            &fence.data_root,
            Some((&fence.filesystem_id, fence.revision)),
        )?;
        drop(previous);
        warnings.extend(write_state(&state_path, source, records.finish()?)?);
        if let Err(error) = std::fs::remove_file(&legacy_state_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warnings.push(format!(
                "The indexed sync state was published, but legacy state cleanup was deferred: {error}"
            ));
        }
        warnings.sort();
        warnings.dedup();
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

    #[allow(
        clippy::too_many_arguments,
        reason = "the authenticated traversal carries explicit catalog, fence, concurrency, and private spool boundaries"
    )]
    async fn plan_tree(
        &self,
        source: &str,
        destination: &Path,
        catalog: &CatalogStore,
        session: &crate::VfsSession,
        state_directory: &Path,
        maximum_concurrency: usize,
        bulk_catalog_authorized: bool,
        mut files: RecordSpool<PlannedFile>,
    ) -> Result<(CatalogFence, u64, RecordSpool<PlannedFile>), Error> {
        let (fence, root) = self
            .source_catalog(
                source,
                catalog,
                session,
                state_directory,
                bulk_catalog_authorized,
            )
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
                            state_directory,
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
                    let entry = entry?;
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
                        EntryKind::File => files.append(&PlannedFile {
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
                        })?,
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
        Ok((fence, directories, files))
    }

    async fn source_catalog(
        &self,
        source: &str,
        catalog: &CatalogStore,
        session: &crate::VfsSession,
        state_directory: &Path,
        bulk_catalog_authorized: bool,
    ) -> Result<(CatalogFence, LoadedDirectory), Error> {
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
            .load_catalog_from_first(catalog, root_page.clone(), state_directory)
            .await?;
        let mut source_id = current.directory_id.clone();
        let mut source_root = current.data_root.clone();
        for (index, component) in components.iter().enumerate() {
            let mut found = None;
            for entry in current.entries.by_ref() {
                let entry = entry?;
                if entry.name == *component {
                    found = Some(entry);
                    break;
                }
            }
            let entry = found.ok_or_else(|| Error::Rejected {
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
                    .load_catalog_node(
                        catalog,
                        &source_id,
                        &source_root,
                        state_directory,
                        bulk_catalog_authorized,
                    )
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
        let node = if components.is_empty() {
            current
        } else {
            self.load_catalog_from_first(catalog, source_page, state_directory)
                .await?
        };
        Ok((fence, node))
    }

    async fn load_catalog_node(
        &self,
        catalog: &CatalogStore,
        directory_id: &str,
        data_root: &str,
        state_directory: &Path,
        bulk_catalog_authorized: bool,
    ) -> Result<LoadedDirectory, Error> {
        if bulk_catalog_authorized && let Some(node) = catalog.load(directory_id, data_root)? {
            return Ok(node.into());
        }
        let first = self
            .list_directory(directory_id, None, CATALOG_PAGE_SIZE)
            .await?;
        validate_page_identity(&first, directory_id, data_root, None)?;
        self.load_catalog_from_first(catalog, first, state_directory)
            .await
    }

    async fn load_catalog_from_first(
        &self,
        catalog: &CatalogStore,
        mut page: DirectoryPage,
        state_directory: &Path,
    ) -> Result<LoadedDirectory, Error> {
        let directory_id = page.directory.id.clone();
        let data_root = page.directory.data_root.clone();
        if let Some(node) = catalog.load(&directory_id, &data_root)? {
            return Ok(node.into());
        }
        let filesystem_id = page.directory.filesystem_id.clone();
        let revision = page.directory.revision;
        let expected_root = carrack_sdk_core::decode_lower_hex::<32>(&data_root)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        let mut accumulator = carrack_sdk_core::DirectoryMerkleAccumulator::new();
        let mut spool = RecordSpool::<CatalogEntry>::create(state_directory)?;
        let mut cache_entries = Some(Vec::new());
        loop {
            for entry in page.entries.drain(..) {
                let catalog_entry = CatalogEntry::from(&entry);
                accumulator
                    .push(&merkle_entry(&catalog_entry)?)
                    .map_err(|error| Error::InvalidResponse(error.to_string()))?;
                spool.append(&catalog_entry)?;
                retain_bounded(&mut cache_entries, entry, MAXIMUM_MEMORY_DIRECTORY_ENTRIES);
            }
            let Some(next) = page.next_cursor.take() else {
                break;
            };
            page = self
                .list_directory(&directory_id, Some(&next), CATALOG_PAGE_SIZE)
                .await?;
            validate_page_identity(
                &page,
                &directory_id,
                &data_root,
                Some((&filesystem_id, revision)),
            )?;
        }
        let actual_root = accumulator
            .finish()
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        if actual_root != expected_root {
            return Err(Error::InvalidResponse(
                "paged catalog directory Merkle root differs".to_owned(),
            ));
        }
        if let Some(entries) = cache_entries {
            return catalog
                .publish(&directory_id, &data_root, &entries)
                .map(Into::into);
        }
        Ok(LoadedDirectory {
            directory_id,
            data_root,
            entries: LoadedEntries::Spool(spool.finish()?),
        })
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
    integrity::matches_file(
        path,
        record.verification_block_bytes,
        record.size_bytes,
        &record.file_root,
    )
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

fn acquire_sync_lock(destination: &Path) -> Result<DestinationLock, Error> {
    let canonical_destination = std::fs::canonicalize(destination)
        .map_err(local_error("canonicalize local sync destination"))?;
    let mut ancestors = canonical_destination
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>();
    ancestors.reverse();
    let mut ancestor_locks = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let file = std::fs::File::open(ancestor)
            .map_err(local_error("open local sync ancestor for locking"))?;
        fs2::FileExt::try_lock_shared(&file).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                Error::InvalidResponse(format!(
                    "another sync is already publishing an overlapping destination of {}",
                    canonical_destination.display()
                ))
            } else {
                local_error("lock local sync ancestor")(error)
            }
        })?;
        ancestor_locks.push(file);
    }
    let destination_lock = std::fs::File::open(&canonical_destination)
        .map_err(local_error("open local sync destination for locking"))?;
    fs2::FileExt::try_lock_exclusive(&destination_lock).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Error::InvalidResponse(format!(
                "another sync is already publishing an overlapping destination of {}",
                canonical_destination.display()
            ))
        } else {
            local_error("lock local sync destination")(error)
        }
    })?;
    Ok(DestinationLock {
        _ancestors: ancestor_locks,
        _destination: destination_lock,
    })
}

fn state_path(root: &Path, token_id: &str, source: &str) -> PathBuf {
    root.join("sync/tokens").join(token_id).join(format!(
        "{}.sqlite3",
        hex::encode(Sha256::digest(source.as_bytes()))
    ))
}

fn legacy_state_path(root: &Path, token_id: &str, source: &str) -> PathBuf {
    root.join("sync/tokens").join(token_id).join(format!(
        "{}.json",
        hex::encode(Sha256::digest(source.as_bytes()))
    ))
}

fn open_state_index(
    state_directory: &Path,
    path: &Path,
    legacy_path: &Path,
    source: &str,
) -> Result<(Option<StateIndex>, Vec<String>), Error> {
    let mut warnings = Vec::new();
    if path.exists() {
        return match StateIndex::open(path, source) {
            Ok(index) => Ok((Some(index), warnings)),
            Err(error) => {
                warnings.push(format!(
                    "The local sync index is invalid and will be rebuilt without trusting it: {error}"
                ));
                Ok((None, warnings))
            }
        };
    }
    if !legacy_path.exists() {
        return Ok((None, warnings));
    }
    let legacy = match read_legacy_state(legacy_path, source) {
        Ok(legacy) => legacy,
        Err(error) => {
            warnings.push(format!(
                "The legacy local sync state is invalid and will be rebuilt without trusting it: {error}"
            ));
            return Ok((None, warnings));
        }
    };
    let mut records = RecordSpool::<StateRecord>::create(state_directory)?;
    for record in legacy.records {
        records.append(&record)?;
    }
    if let Err(error) = write_state(path, source, records.finish()?) {
        warnings.push(format!(
            "The legacy local sync state could not be indexed and will be rebuilt: {error}"
        ));
        return Ok((None, warnings));
    }
    match StateIndex::open(path, source) {
        Ok(index) => {
            if let Err(error) = std::fs::remove_file(legacy_path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                warnings.push(format!(
                    "The indexed sync state is ready, but legacy state cleanup was deferred: {error}"
                ));
            }
            Ok((Some(index), warnings))
        }
        Err(error) => {
            warnings.push(format!(
                "The migrated local sync index failed validation and will not be trusted: {error}"
            ));
            Ok((None, warnings))
        }
    }
}

fn read_legacy_state(path: &Path, source: &str) -> Result<LegacySyncState, Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LegacySyncState::default());
        }
        Err(error) => return Err(local_error("inspect local sync state")(error)),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(Error::InvalidResponse(
            "local sync state is not a regular file".to_owned(),
        ));
    }
    let file = std::fs::File::open(path).map_err(local_error("open local sync state"))?;
    let state: LegacySyncState = serde_json::from_reader(BufReader::new(file))
        .map_err(|error| Error::InvalidResponse(format!("decode local sync state: {error}")))?;
    if state.schema != LEGACY_STATE_SCHEMA || state.source != source {
        return Err(Error::InvalidResponse(
            "local sync state identity differs".to_owned(),
        ));
    }
    Ok(state)
}

fn write_state(
    path: &Path,
    source: &str,
    records: RecordSpoolReader<StateRecord>,
) -> Result<Vec<String>, Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::InvalidResponse("local sync state has no parent".to_owned()))?;
    protect_directory(parent)?;
    let (temporary, file) = create_state_temporary(parent)?;
    drop(file);
    let built = build_state_database(&temporary, source, records);
    if let Err(error) = built {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(local_error("publish local sync state")(error));
    }
    let mut warnings = Vec::new();
    if let Err(error) = sync_state_directory(parent) {
        warnings.push(format!(
            "The verified sync state was published, but its directory sync failed: {error}"
        ));
    }
    Ok(warnings)
}

fn build_state_database(
    path: &Path,
    source: &str,
    records: RecordSpoolReader<StateRecord>,
) -> Result<(), Error> {
    let mut connection = rusqlite::Connection::open(path)
        .map_err(state_database_error("create indexed local sync state"))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA trusted_schema = OFF;
             PRAGMA user_version = 2;
             CREATE TABLE state_identity (
                 schema TEXT NOT NULL,
                 source TEXT NOT NULL
             ) STRICT;
             CREATE TABLE state_records (
                 relative_path TEXT PRIMARY KEY,
                 version_id TEXT NOT NULL,
                 size_bytes TEXT NOT NULL,
                 file_root TEXT NOT NULL,
                 verification_block_bytes TEXT NOT NULL
             ) STRICT, WITHOUT ROWID;",
        )
        .map_err(state_database_error("initialize indexed local sync state"))?;
    let transaction = connection
        .transaction()
        .map_err(state_database_error("begin indexed local sync state"))?;
    transaction
        .execute(
            "INSERT INTO state_identity (schema, source) VALUES (?1, ?2)",
            (STATE_SCHEMA, source),
        )
        .map_err(state_database_error("write indexed local sync identity"))?;
    {
        let mut insert = transaction
            .prepare_cached(
                "INSERT INTO state_records (
                    relative_path,
                    version_id,
                    size_bytes,
                    file_root,
                    verification_block_bytes
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .map_err(state_database_error("prepare indexed local sync record"))?;
        for record in records {
            let record = record?;
            let relative_path = validate_state_record(&record)?;
            insert
                .execute((
                    relative_path,
                    record.version_id.as_str(),
                    record.size_bytes.to_string(),
                    record.file_root.as_str(),
                    record.verification_block_bytes.to_string(),
                ))
                .map_err(state_database_error("write indexed local sync record"))?;
        }
    }
    transaction
        .commit()
        .map_err(state_database_error("commit indexed local sync state"))?;
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(state_database_error("verify indexed local sync state"))?;
    if integrity != "ok" {
        return Err(Error::InvalidResponse(
            "new indexed local sync state failed its integrity check".to_owned(),
        ));
    }
    connection
        .close()
        .map_err(|(_, error)| state_database_error("close indexed local sync state")(error))?;
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(local_error("sync indexed local sync state"))
}

fn validate_state_record(record: &StateRecord) -> Result<&str, Error> {
    let path = record
        .relative_path
        .to_str()
        .ok_or_else(|| Error::InvalidResponse("local sync state path is not UTF-8".to_owned()))?;
    if path.is_empty()
        || record.relative_path.is_absolute()
        || record
            .relative_path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || record.version_id.is_empty()
        || record.file_root.len() != 64
        || hex::decode(&record.file_root)
            .ok()
            .is_none_or(|decoded| hex::encode(decoded) != record.file_root)
        || record.verification_block_bytes == 0
        || record.verification_block_bytes > 256 * 1024 * 1024
    {
        return Err(Error::InvalidResponse(
            "local sync state record is not canonical".to_owned(),
        ));
    }
    Ok(path)
}

fn canonical_u64(value: &str) -> Option<u64> {
    let decoded = value.parse::<u64>().ok()?;
    (decoded.to_string() == value).then_some(decoded)
}

fn state_database_error(context: &'static str) -> impl FnOnce(rusqlite::Error) -> Error {
    move |error| Error::InvalidResponse(format!("{context}: {error}"))
}

fn create_state_temporary(parent: &Path) -> Result<(PathBuf, std::fs::File), Error> {
    loop {
        let ordinal = STATE_TEMPORARY_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".state-{}-{ordinal:016x}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    {
                        drop(file);
                        let _ = std::fs::remove_file(&path);
                        return Err(local_error("protect local sync state")(error));
                    }
                }
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(local_error("create local sync state")(error)),
        }
    }
}

fn sync_state_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(local_error("sync local state directory"))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
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

    use super::{
        LEGACY_STATE_SCHEMA, PlannedFile, RecordSpool, StateIndex, StateRecord, SyncOptions,
        VfsClient, acquire_sync_lock, open_state_index, retain_bounded, write_state,
    };
    use crate::VfsToken;

    #[test]
    fn bounded_directory_cache_drops_all_entries_at_its_limit() {
        let mut retained = Some(Vec::new());
        retain_bounded(&mut retained, 1_u8, 2);
        retain_bounded(&mut retained, 2_u8, 2);
        assert_eq!(retained, Some(vec![1, 2]));

        retain_bounded(&mut retained, 3_u8, 2);
        assert!(retained.is_none());
        retain_bounded(&mut retained, 4_u8, 2);
        assert!(retained.is_none());
    }

    #[test]
    fn plan_spool_streams_records_and_removes_private_file() {
        let temporary = tempfile::tempdir().expect("sync plan temporary directory");
        let mut spool =
            RecordSpool::<PlannedFile>::create(temporary.path()).expect("create sync plan spool");
        let first = PlannedFile {
            vfs_path: "/first.parquet".to_owned(),
            relative_path: "first.parquet".into(),
            file_id: "first-file".to_owned(),
            version_id: "first-version".to_owned(),
            size_bytes: 11,
            file_root: "11".repeat(32),
        };
        let second = PlannedFile {
            vfs_path: "/second.parquet".to_owned(),
            relative_path: "second.parquet".into(),
            file_id: "second-file".to_owned(),
            version_id: "second-version".to_owned(),
            size_bytes: 22,
            file_root: "22".repeat(32),
        };
        spool.append(&first).expect("append first plan record");
        spool.append(&second).expect("append second plan record");

        let mut reader = spool.finish().expect("seal sync plan spool");
        let spool_path = reader.path.clone().expect("reader spool path");
        assert!(spool_path.is_file());
        let decoded_first = reader.next().expect("first record").expect("decode first");
        let decoded_second = reader
            .next()
            .expect("second record")
            .expect("decode second");
        assert_eq!(decoded_first.relative_path, first.relative_path);
        assert_eq!(decoded_first.version_id, first.version_id);
        assert_eq!(decoded_second.relative_path, second.relative_path);
        assert_eq!(decoded_second.version_id, second.version_id);
        assert!(reader.next().is_none());
        drop(reader);
        assert!(!spool_path.exists());
    }

    #[test]
    fn plan_spools_are_unique_within_one_process() {
        let temporary = tempfile::tempdir().expect("sync plan temporary directory");
        let first =
            RecordSpool::<PlannedFile>::create(temporary.path()).expect("first sync plan spool");
        let second =
            RecordSpool::<PlannedFile>::create(temporary.path()).expect("second sync plan spool");
        assert_ne!(first.path, second.path);
    }

    #[test]
    fn sync_state_publication_is_atomic_and_ignores_legacy_temporary_name() {
        let temporary = tempfile::tempdir().expect("sync state temporary directory");
        let path = temporary.path().join("tokens/token/source.sqlite3");
        let parent = path.parent().expect("sync state parent");
        std::fs::create_dir_all(parent).expect("create sync state parent");
        let legacy_temporary = path.with_extension("sqlite3.tmp");
        std::fs::write(&legacy_temporary, b"other concurrent writer")
            .expect("write legacy temporary collision");
        let source = "/docs/\"quoted\"";
        let first = StateRecord {
            relative_path: "first.parquet".into(),
            version_id: "first-version".to_owned(),
            size_bytes: 11,
            file_root: "11".repeat(32),
            verification_block_bytes: 4,
        };
        let mut first_records =
            RecordSpool::<StateRecord>::create(temporary.path()).expect("first state spool");
        first_records.append(&first).expect("append first state");
        write_state(
            &path,
            source,
            first_records.finish().expect("seal first state spool"),
        )
        .expect("publish first sync state");
        let second = StateRecord {
            relative_path: "second.parquet".into(),
            version_id: "second-version".to_owned(),
            size_bytes: 22,
            file_root: "22".repeat(32),
            verification_block_bytes: 8,
        };
        let mut second_records =
            RecordSpool::<StateRecord>::create(temporary.path()).expect("second state spool");
        second_records.append(&second).expect("append second state");
        second_records
            .append(&first)
            .expect("append another streamed state");
        write_state(
            &path,
            source,
            second_records.finish().expect("seal second state spool"),
        )
        .expect("replace sync state atomically");

        let loaded = StateIndex::open(&path, source).expect("open latest sync state");
        assert_eq!(
            loaded
                .lookup(std::path::Path::new("second.parquet"))
                .expect("second indexed record")
                .version_id,
            "second-version"
        );
        assert!(
            loaded
                .lookup(std::path::Path::new("first.parquet"))
                .is_some()
        );
        assert_eq!(
            std::fs::read(&legacy_temporary).expect("read legacy temporary"),
            b"other concurrent writer"
        );
    }

    #[test]
    fn legacy_sync_state_migrates_to_the_indexed_format() {
        let temporary = tempfile::tempdir().expect("sync state temporary directory");
        let state_directory = temporary.path().join("state");
        let path = state_directory.join("tokens/token/source.sqlite3");
        let legacy_path = state_directory.join("tokens/token/source.json");
        std::fs::create_dir_all(legacy_path.parent().expect("legacy state parent"))
            .expect("create legacy state parent");
        let source = "/archive";
        std::fs::write(
            &legacy_path,
            serde_json::to_vec(&json!({
                "schema": LEGACY_STATE_SCHEMA,
                "source": source,
                "records": [{
                    "relative_path": "partition/file.parquet",
                    "version_id": "version-1",
                    "size_bytes": 42,
                    "file_root": "ab".repeat(32),
                    "verification_block_bytes": 4_194_304
                }]
            }))
            .expect("encode legacy state"),
        )
        .expect("write legacy state");

        let (index, warnings) = open_state_index(&state_directory, &path, &legacy_path, source)
            .expect("migrate legacy state");

        assert!(warnings.is_empty());
        let record = index
            .expect("indexed state")
            .lookup(std::path::Path::new("partition/file.parquet"))
            .expect("migrated record");
        assert_eq!(record.version_id, "version-1");
        assert_eq!(record.size_bytes, 42);
        assert!(path.is_file());
        assert!(!legacy_path.exists());
    }

    #[test]
    fn corrupt_sync_index_is_ignored_for_a_safe_rebuild() {
        let temporary = tempfile::tempdir().expect("sync state temporary directory");
        let state_directory = temporary.path().join("state");
        let path = state_directory.join("tokens/token/source.sqlite3");
        let legacy_path = state_directory.join("tokens/token/source.json");
        std::fs::create_dir_all(path.parent().expect("indexed state parent"))
            .expect("create indexed state parent");
        std::fs::write(&path, b"not a sqlite database").expect("write corrupt index");

        let (index, warnings) = open_state_index(&state_directory, &path, &legacy_path, "/archive")
            .expect("fall back from corrupt index");

        assert!(index.is_none());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("will be rebuilt without trusting it"));
    }

    #[test]
    fn destination_lock_rejects_overlapping_sync_and_allows_siblings() {
        let temporary = tempfile::tempdir().expect("sync lock temporary directory");
        let destination = temporary.path().join("destination");
        std::fs::create_dir(&destination).expect("create sync destination");
        let child = destination.join("child");
        std::fs::create_dir(&child).expect("create nested sync destination");
        let sibling = temporary.path().join("sibling");
        std::fs::create_dir(&sibling).expect("create sibling sync destination");
        let first = acquire_sync_lock(&destination).expect("acquire first sync lock");
        acquire_sync_lock(&destination).expect_err("reject concurrent sync destination");
        acquire_sync_lock(&child).expect_err("reject nested sync destination");
        let sibling_lock = acquire_sync_lock(&sibling).expect("allow sibling sync destination");
        drop(sibling_lock);
        drop(first);
        acquire_sync_lock(&child).expect("acquire nested destination after release");
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end checkpoint test keeps every authenticated page and expected hit count visible"
    )]
    async fn hydrates_checkpoint_and_fences_root_before_and_after_payload_phase() {
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
        root_fence.assert_hits_async(4).await;
        child_catalog.assert_hits_async(0).await;
    }
}
