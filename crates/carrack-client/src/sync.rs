//! Incremental, verified VFS-directory synchronization to a local tree.

use futures_util::{StreamExt as _, stream};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{
    cell::Cell,
    io::{BufReader, BufWriter, Read as _, Write as _},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    CatalogWatchEvent, DirectoryPage, EntryKind, Error, GetOptions, VfsClient,
    catalog::{CatalogEntry, CatalogNode, CatalogStore, merkle_entry},
    download::{DownloadExpectation, PreparedDownload, ReadLeaseCompletion},
    integrity,
    private_fs::ensure_private_directory,
    vfs::{CatalogCheckpointOutcome, canonical_components},
};

const LEGACY_STATE_SCHEMA: &str = "carrack.local-sync-state.v1";
const STATE_SCHEMA: &str = "carrack.local-sync-state.v2";
const CATALOG_PAGE_SIZE: u32 = 1_000;
const MAXIMUM_TRANSFER_PART_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_PIPELINE_CONCURRENCY: usize = 64;
const MAXIMUM_MEMORY_DIRECTORY_ENTRIES: usize = 20_000;
const MAXIMUM_SPOOL_RECORD_BYTES: usize = 1024 * 1024;
const READ_LEASE_COMPLETION_BATCH_ITEMS: usize = 64;
static PLAN_SPOOL_ORDINAL: AtomicU64 = AtomicU64::new(0);
static STATE_TEMPORARY_ORDINAL: AtomicU64 = AtomicU64::new(0);
static LOCAL_REUSE_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// Bounded incremental directory synchronization settings.
pub struct SyncOptions {
    /// Private state and provider-download journal directory.
    pub state_directory: PathBuf,
    /// Persist authenticated metadata/Merkle catalog acceleration locally.
    pub use_catalog_cache: bool,
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
    version_lookup_indexed: bool,
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
        let user_version = connection
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .map_err(state_database_error("read indexed local sync version"))?;
        Ok(Self {
            connection,
            healthy: Cell::new(true),
            version_lookup_indexed: user_version >= 3,
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
        decode_state_row(relative_path.to_owned(), row)
    }

    fn lookup_version(&self, version_id: &str) -> Vec<StateRecord> {
        if !self.healthy.get() || !self.version_lookup_indexed || version_id.is_empty() {
            return Vec::new();
        }
        let Ok(mut statement) = self.connection.prepare_cached(
            "SELECT relative_path, version_id, size_bytes, file_root, verification_block_bytes
             FROM state_records
             WHERE version_id = ?1
             ORDER BY relative_path
             LIMIT 16",
        ) else {
            self.healthy.set(false);
            return Vec::new();
        };
        let Ok(rows) = statement.query_map([version_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }) else {
            self.healthy.set(false);
            return Vec::new();
        };
        rows.filter_map(|row| {
            let (relative_path, version_id, size_bytes, file_root, verification_block_bytes) =
                row.ok()?;
            decode_state_row(
                PathBuf::from(relative_path),
                (version_id, size_bytes, file_root, verification_block_bytes),
            )
        })
        .collect()
    }
}

fn decode_state_row(
    relative_path: PathBuf,
    row: (String, String, String, String),
) -> Option<StateRecord> {
    let size_bytes = canonical_u64(&row.1)?;
    let verification_block_bytes = canonical_u64(&row.3)?;
    let record = StateRecord {
        relative_path,
        version_id: row.0,
        size_bytes,
        file_root: row.2,
        verification_block_bytes,
    };
    validate_state_record(&record).ok()?;
    Some(record)
}

struct Downloaded {
    record: StateRecord,
    warnings: Vec<String>,
    completion: ReadLeaseCompletion,
}

struct PreparedPlannedFile {
    file: PlannedFile,
    download: PreparedDownload,
}

enum PlanMessage {
    File(Box<Result<PreparedPlannedFile, Error>>),
    Finished,
}

struct PlanProducerGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl PlanProducerGuard {
    async fn finish(mut self) -> Result<(), Error> {
        let handle = self.handle.take().ok_or_else(|| {
            Error::InvalidResponse("download plan producer handle is missing".to_owned())
        })?;
        handle.await.map_err(|error| {
            Error::InvalidResponse(format!("download plan producer failed: {error}"))
        })
    }
}

impl Drop for PlanProducerGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

struct LocalReusePlan {
    file: PlannedFile,
    exact: Option<StateRecord>,
    relocated: Vec<StateRecord>,
}

enum LocalDisposition {
    Reused(StateRecord),
    Staged(StagedLocalReuse),
    Download(PlannedFile),
}

struct LocalEvaluation {
    disposition: LocalDisposition,
    warnings: Vec<String>,
}

struct StagedLocalReuse {
    temporary: Option<PathBuf>,
    target: PathBuf,
    record: StateRecord,
}

impl StagedLocalReuse {
    fn publish(mut self) -> Result<StateRecord, Error> {
        let temporary = self.temporary.as_ref().ok_or_else(|| {
            Error::InvalidResponse("local reuse staging identity is missing".to_owned())
        })?;
        std::fs::rename(temporary, &self.target)
            .map_err(local_error("publish immutable local reuse"))?;
        let parent = self
            .target
            .parent()
            .ok_or_else(|| Error::InvalidResponse("local reuse target has no parent".to_owned()))?;
        sync_publication_directory(parent)?;
        self.temporary = None;
        Ok(self.record.clone())
    }
}

impl Drop for StagedLocalReuse {
    fn drop(&mut self) {
        if let Some(temporary) = self.temporary.take() {
            let _ = std::fs::remove_file(temporary);
        }
    }
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
        ensure_private_directory(&directory, "sync plan spool directory")?;
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

async fn validate_watch_fence(
    client: &VfsClient,
    fence: &CatalogFence,
    event: &CatalogWatchEvent,
) -> Result<(), Error> {
    if event.filesystem_id != fence.filesystem_id {
        return Err(Error::InvalidResponse(
            "catalog watch filesystem differs from the sync fence".to_owned(),
        ));
    }
    if event.root_directory_id == fence.directory_id {
        if event.root_data_root != fence.data_root {
            return Err(Error::InvalidResponse(
                "namespace changed during synchronization".to_owned(),
            ));
        }
        return Ok(());
    }
    let page = client.list_directory(&fence.directory_id, None, 1).await?;
    validate_page_identity(
        &page,
        &fence.directory_id,
        &fence.data_root,
        Some((&fence.filesystem_id, fence.revision)),
    )
}

#[derive(Deserialize, Serialize)]
struct PendingDirectory {
    vfs_path: String,
    relative_path: PathBuf,
    directory_id: String,
    data_root: String,
    #[serde(skip)]
    node: Option<LoadedDirectory>,
}

impl VfsClient {
    /// Incrementally synchronizes one VFS directory into a local directory.
    ///
    /// The complete remote catalog is fetched before provider reads begin.
    /// Unchanged local files are reused only after recomputing their exact
    /// plaintext Merkle root with the previously authenticated block size.
    /// Local verification and changed-file downloads use bounded concurrency;
    /// each changed file retains its own resumable exact-range pipeline.
    /// Untracked local files are preserved.
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
        ensure_private_directory(&options.state_directory, "sync state directory")?;
        let _destination_lock = acquire_sync_lock(destination)?;
        let session = self.session().await?;
        let catalog = CatalogStore::new(
            &options.state_directory,
            &session.token_id,
            &self.token,
            options.use_catalog_cache,
        )?;
        let checkpoint_condition = catalog.checkpoint_condition()?;
        let checkpoint = match self
            .catalog_checkpoint(&session, checkpoint_condition.as_ref())
            .await
        {
            Ok(outcome) => outcome,
            Err(Error::InvalidResponse(_) | Error::Transport(_)) => {
                CatalogCheckpointOutcome::Unavailable
            }
            Err(error) => return Err(error),
        };
        let bulk_catalog_authorized = match checkpoint {
            CatalogCheckpointOutcome::Delivered(delivery) => {
                if options.use_catalog_cache
                    && catalog
                        .publish_checkpoint(&delivery.checkpoint, &delivery.etag)
                        .is_ok()
                {
                    true
                } else {
                    catalog.discard_head()?;
                    false
                }
            }
            CatalogCheckpointOutcome::Delta(delivery) => {
                if options.use_catalog_cache
                    && catalog.apply_delta(&delivery.delta, &delivery.etag).is_ok()
                {
                    true
                } else {
                    catalog.discard_head()?;
                    false
                }
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
        let mut download_candidates = 0_u64;
        let mut reused_files = 0_u64;
        let maximum_concurrency = options.maximum_concurrency;
        let local_destination = destination.to_owned();
        let mut local_pending = stream::iter(files.finish()?.map(|file| {
            let plan = file.map(|file| build_local_reuse_plan(previous.as_ref(), file));
            let destination = local_destination.clone();
            async move {
                let plan = plan?;
                tokio::task::spawn_blocking(move || evaluate_local_file(&destination, plan))
                    .await
                    .map_err(|error| {
                        Error::InvalidResponse(format!("local verification worker failed: {error}"))
                    })?
            }
        }))
        .buffer_unordered(maximum_concurrency);
        let mut local_error = None;
        while let Some(evaluated) = local_pending.next().await {
            match evaluated {
                Ok(evaluated) => {
                    warnings.extend(evaluated.warnings);
                    match evaluated.disposition {
                        LocalDisposition::Reused(record) => {
                            records.append(&record)?;
                            reused_files += 1;
                        }
                        LocalDisposition::Staged(staged) => match staged.publish() {
                            Ok(record) => {
                                records.append(&record)?;
                                reused_files += 1;
                            }
                            Err(error) => {
                                if local_error.is_none() {
                                    local_error = Some(error);
                                }
                            }
                        },
                        LocalDisposition::Download(file) => {
                            downloads.append(&file)?;
                            download_candidates += 1;
                        }
                    }
                }
                Err(error) => {
                    // Blocking verification workers cannot be cancelled safely.
                    // Drain the bounded pool before returning so no local file
                    // publication can occur after the sync call has completed.
                    if local_error.is_none() {
                        local_error = Some(error);
                    }
                }
            }
        }
        drop(local_pending);
        if let Some(error) = local_error {
            return Err(error);
        }

        let mut catalog_watch = if download_candidates == 0 {
            None
        } else {
            self.watch_catalog_for_session(&session).await.ok()
        };
        if let Some(watch) = catalog_watch.as_ref() {
            validate_watch_fence(self, &fence, watch.current()).await?;
        }

        let (plans, plan_producer) =
            start_plan_producer(self.clone(), downloads.finish()?, maximum_concurrency);
        let plans = stream::unfold((plans, false), |(mut plans, terminated)| async move {
            if terminated {
                return None;
            }
            match plans.recv().await {
                Some(PlanMessage::File(file)) => Some((*file, (plans, false))),
                Some(PlanMessage::Finished) => None,
                None => Some((
                    Err(Error::InvalidResponse(
                        "download plan producer stopped before completion".to_owned(),
                    )),
                    (plans, true),
                )),
            }
        });
        let client = self.clone();
        let destination = destination.to_owned();
        let result_destination = destination.clone();
        let state_directory = options.state_directory.clone();
        let transfer_part_bytes = options.transfer_part_bytes;
        let file_concurrency = options.maximum_file_concurrency;
        let pending = plans
            .map(move |prepared| {
                let client = client.clone();
                let destination = destination.clone();
                let state_directory = state_directory.clone();
                async move {
                    download_one(
                        &client,
                        prepared?,
                        &destination,
                        &state_directory,
                        transfer_part_bytes,
                        file_concurrency,
                    )
                    .await
                }
            })
            .buffer_unordered(maximum_concurrency);
        futures_util::pin_mut!(pending);
        let mut downloaded_bytes = 0_u64;
        let mut downloaded_files = 0_u64;
        let mut completions = RecordSpool::<ReadLeaseCompletion>::create(&options.state_directory)?;
        loop {
            let downloaded = if let Some(watch) = catalog_watch.as_mut() {
                tokio::select! {
                    downloaded = pending.next() => downloaded,
                    event = watch.next_event() => {
                        match event {
                            Ok(event) => validate_watch_fence(self, &fence, &event).await?,
                            Err(_) => catalog_watch = None,
                        }
                        continue;
                    }
                }
            } else {
                pending.next().await
            };
            let Some(downloaded) = downloaded else {
                break;
            };
            let downloaded = downloaded?;
            downloaded_bytes = downloaded_bytes.saturating_add(downloaded.record.size_bytes);
            downloaded_files += 1;
            warnings.extend(downloaded.warnings);
            records.append(&downloaded.record)?;
            completions.append(&downloaded.completion)?;
        }
        plan_producer.finish().await?;
        warnings.extend(complete_read_lease_spool(self, completions.finish()?).await);
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
        clippy::too_many_lines,
        reason = "the authenticated traversal keeps its catalog fence, bounded disk queue, and planning publication in one reviewable boundary"
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
        let root = PendingDirectory {
            vfs_path: canonical_source,
            relative_path: PathBuf::new(),
            directory_id: root.directory_id.clone(),
            data_root: root.data_root.clone(),
            node: Some(root),
        };
        let mut pending: Box<dyn Iterator<Item = Result<PendingDirectory, Error>>> =
            Box::new(std::iter::once(Ok(root)));
        let mut directories = 0_u64;
        loop {
            let mut next = RecordSpool::<PendingDirectory>::create(state_directory)?;
            let mut next_directories = 0_u64;
            loop {
                let batch = pending
                    .by_ref()
                    .take(maximum_concurrency)
                    .collect::<Result<Vec<_>, _>>()?;
                if batch.is_empty() {
                    break;
                }
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
                            EntryKind::Directory => {
                                next.append(&PendingDirectory {
                                    vfs_path: child_vfs,
                                    relative_path: child_relative,
                                    directory_id: required(
                                        entry.child_directory_id,
                                        "catalog directory entry omitted child identity",
                                    )?,
                                    data_root: entry.data_root,
                                    node: None,
                                })?;
                                next_directories += 1;
                            }
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
            if next_directories == 0 {
                break;
            }
            pending = Box::new(next.finish()?);
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
        // A delivered checkpoint, delta, or reauthorized 304 proves that the
        // token-scoped local DAG may supply directory contents. The live page is
        // then needed only for identity/revision fencing, not bulk entries.
        let identity_page_size = if bulk_catalog_authorized {
            1
        } else {
            CATALOG_PAGE_SIZE
        };
        let root_page = self
            .list_directory(&session.root_directory_id, None, identity_page_size)
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
            self.list_directory(&source_id, None, identity_page_size)
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
        if bulk_catalog_authorized
            && let Some(node) = load_cached_catalog_node(catalog, directory_id, data_root).await?
        {
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
        if let Some(node) = load_cached_catalog_node(catalog, &directory_id, &data_root).await? {
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

async fn load_cached_catalog_node(
    catalog: &CatalogStore,
    directory_id: &str,
    data_root: &str,
) -> Result<Option<CatalogNode>, Error> {
    let catalog = catalog.clone();
    let directory_id = directory_id.to_owned();
    let data_root = data_root.to_owned();
    tokio::task::spawn_blocking(move || {
        if let Ok(node) = catalog.load(&directory_id, &data_root) {
            Ok(node)
        } else {
            catalog.discard_node(&directory_id, &data_root)?;
            Ok(None)
        }
    })
    .await
    .map_err(|error| {
        Error::InvalidResponse(format!("local catalog verification worker failed: {error}"))
    })?
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
    prepared: PreparedPlannedFile,
    destination: &Path,
    state_directory: &Path,
    transfer_part_bytes: u64,
    maximum_file_concurrency: usize,
) -> Result<Downloaded, Error> {
    let PreparedPlannedFile { file, download } = prepared;
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
    let (result, completion) = client
        .finish_prepared_file(
            &file.vfs_path,
            download,
            &temporary,
            &GetOptions {
                staging_directory: state_directory.join("downloads").join(&file.version_id),
                transfer_part_bytes,
                maximum_concurrency: maximum_file_concurrency,
            },
            true,
        )
        .await?;
    let completion = completion.ok_or_else(|| {
        Error::InvalidResponse("sync download omitted deferred completion".to_owned())
    })?;
    if result.version_id != file.version_id || result.file_root != file.file_root {
        let _ = std::fs::remove_file(&temporary);
        return Err(Error::InvalidResponse(
            "sync download identity changed".to_owned(),
        ));
    }
    std::fs::rename(&temporary, &target).map_err(local_error("publish synchronized file"))?;
    sync_publication_directory(parent)?;
    Ok(Downloaded {
        record: StateRecord {
            relative_path: file.relative_path.clone(),
            version_id: file.version_id.clone(),
            size_bytes: file.size_bytes,
            file_root: file.file_root.clone(),
            verification_block_bytes: result.verification_block_bytes,
        },
        warnings: result.warnings,
        completion,
    })
}

fn start_plan_producer(
    client: VfsClient,
    files: RecordSpoolReader<PlannedFile>,
    maximum_concurrency: usize,
) -> (tokio::sync::mpsc::Receiver<PlanMessage>, PlanProducerGuard) {
    let (sender, receiver) = tokio::sync::mpsc::channel(maximum_concurrency);
    let handle = tokio::spawn(async move {
        let mut pending = stream::iter(files.map(move |file| {
            let client = client.clone();
            async move {
                let file = file?;
                let download = client
                    .prepare_file_version(DownloadExpectation::new(
                        &file.file_id,
                        &file.version_id,
                        file.size_bytes,
                        &file.file_root,
                    ))
                    .await?;
                Ok(PreparedPlannedFile { file, download })
            }
        }))
        .buffer_unordered(maximum_concurrency);
        while let Some(file) = pending.next().await {
            let failed = file.is_err();
            if sender
                .send(PlanMessage::File(Box::new(file)))
                .await
                .is_err()
            {
                return;
            }
            if failed {
                return;
            }
        }
        let _ = sender.send(PlanMessage::Finished).await;
    });
    (
        receiver,
        PlanProducerGuard {
            handle: Some(handle),
        },
    )
}

async fn complete_read_lease_spool(
    client: &VfsClient,
    mut completions: RecordSpoolReader<ReadLeaseCompletion>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    loop {
        let mut batch = Vec::with_capacity(READ_LEASE_COMPLETION_BATCH_ITEMS);
        while batch.len() < READ_LEASE_COMPLETION_BATCH_ITEMS {
            match completions.next() {
                Some(Ok(completion)) => batch.push(completion),
                Some(Err(error)) => {
                    warnings.push(format!(
                        "The verified files were published, but their read-lease completion spool could not be read and remaining leases will rely on expiry: {error}"
                    ));
                    return warnings;
                }
                None => break,
            }
        }
        if batch.is_empty() {
            break;
        }
        if let Err(error) = client.complete_read_leases(&batch).await {
            warnings.push(format!(
                "The verified files were published, but a read-lease completion batch will rely on expiry: {error}"
            ));
        }
    }
    warnings
}

fn local_matches(path: &Path, record: &StateRecord) -> Result<bool, Error> {
    integrity::matches_file(
        path,
        record.verification_block_bytes,
        record.size_bytes,
        &record.file_root,
    )
}

fn build_local_reuse_plan(previous: Option<&StateIndex>, file: PlannedFile) -> LocalReusePlan {
    let exact = previous
        .and_then(|index| index.lookup(&file.relative_path))
        .filter(|record| {
            record.relative_path == file.relative_path
                && record.version_id == file.version_id
                && record.size_bytes == file.size_bytes
                && record.file_root == file.file_root
        });
    let relocated = previous.map_or_else(Vec::new, |index| {
        index
            .lookup_version(&file.version_id)
            .into_iter()
            .filter(|candidate| {
                candidate.relative_path != file.relative_path
                    && candidate.size_bytes == file.size_bytes
                    && candidate.file_root == file.file_root
            })
            .collect()
    });
    LocalReusePlan {
        file,
        exact,
        relocated,
    }
}

fn evaluate_local_file(destination: &Path, plan: LocalReusePlan) -> Result<LocalEvaluation, Error> {
    if let Some(record) = plan.exact
        && local_matches(&destination.join(&record.relative_path), &record)?
    {
        return Ok(LocalEvaluation {
            disposition: LocalDisposition::Reused(record),
            warnings: Vec::new(),
        });
    }
    let mut warnings = Vec::new();
    for candidate in plan.relocated {
        match stage_local_version(destination, &plan.file, &candidate) {
            Ok(Some(staged)) => {
                return Ok(LocalEvaluation {
                    disposition: LocalDisposition::Staged(staged),
                    warnings,
                });
            }
            Ok(None) => {}
            Err(error) => warnings.push(format!(
                "Local immutable-version reuse for {} failed and provider download was retained: {error}",
                plan.file.relative_path.display()
            )),
        }
    }
    Ok(LocalEvaluation {
        disposition: LocalDisposition::Download(plan.file),
        warnings,
    })
}

fn stage_local_version(
    destination: &Path,
    file: &PlannedFile,
    candidate: &StateRecord,
) -> Result<Option<StagedLocalReuse>, Error> {
    let source = destination.join(&candidate.relative_path);
    if !local_matches(&source, candidate)? {
        return Ok(None);
    }
    let target = destination.join(&file.relative_path);
    let parent = target
        .parent()
        .ok_or_else(|| Error::InvalidResponse("sync reuse target has no parent".to_owned()))?;
    ensure_directory(parent)?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::InvalidResponse("sync reuse filename is not UTF-8".to_owned()))?;
    let (temporary, mut output) = loop {
        let ordinal = LOCAL_REUSE_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{file_name}.carrack-reuse-{}-{ordinal:016x}.tmp",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(output) => break (temporary, output),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(local_error("create local reuse temporary")(error)),
        }
    };
    let copied = (|| -> Result<(), Error> {
        let input = std::fs::File::open(&source)
            .map_err(local_error("open immutable local reuse source"))?;
        let metadata = input
            .metadata()
            .map_err(local_error("inspect immutable local reuse source"))?;
        if !metadata.is_file() || metadata.len() != candidate.size_bytes {
            return Err(Error::InvalidResponse(
                "local immutable-version source changed before copy".to_owned(),
            ));
        }
        let maximum_copy_bytes = candidate
            .size_bytes
            .checked_add(1)
            .ok_or_else(|| Error::InvalidResponse("local reuse size overflow".to_owned()))?;
        let copied_bytes = std::io::copy(&mut input.take(maximum_copy_bytes), &mut output)
            .map_err(local_error("copy immutable local reuse source"))?;
        if copied_bytes != candidate.size_bytes {
            return Err(Error::InvalidResponse(
                "local immutable-version source changed during copy".to_owned(),
            ));
        }
        output
            .sync_all()
            .map_err(local_error("sync immutable local reuse temporary"))?;
        drop(output);
        if !local_matches(&temporary, candidate)? {
            return Err(Error::InvalidResponse(
                "local immutable-version copy changed during verification".to_owned(),
            ));
        }
        Ok(())
    })();
    if let Err(error) = copied {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(Some(StagedLocalReuse {
        temporary: Some(temporary),
        target,
        record: StateRecord {
            relative_path: file.relative_path.clone(),
            version_id: file.version_id.clone(),
            size_bytes: file.size_bytes,
            file_root: file.file_root.clone(),
            verification_block_bytes: candidate.verification_block_bytes,
        },
    }))
}

fn validate_options(options: &SyncOptions) -> Result<(), Error> {
    if !options.state_directory.is_absolute()
        || options.transfer_part_bytes == 0
        || options.transfer_part_bytes > MAXIMUM_TRANSFER_PART_BYTES
        || options.maximum_concurrency == 0
        || options.maximum_concurrency > MAXIMUM_PIPELINE_CONCURRENCY
        || options.maximum_file_concurrency == 0
        || options.maximum_file_concurrency > MAXIMUM_PIPELINE_CONCURRENCY
    {
        return Err(Error::InvalidResponse(
            "invalid sync pipeline options".to_owned(),
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
    ensure_private_directory(parent, "sync state database directory")?;
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
             PRAGMA user_version = 3;
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
             ) STRICT, WITHOUT ROWID;
             CREATE INDEX state_records_version_id
                 ON state_records (version_id, relative_path);",
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

fn sync_publication_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(local_error("sync local file publication directory"))
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
    use std::path::PathBuf;
    use std::time::Instant;

    use super::{
        CatalogFence, LEGACY_STATE_SCHEMA, LocalDisposition, LocalReusePlan, PlanMessage,
        PlannedFile, RecordSpool, StateIndex, StateRecord, SyncOptions, VfsClient,
        acquire_sync_lock, evaluate_local_file, open_state_index, retain_bounded,
        stage_local_version, start_plan_producer, validate_options, validate_watch_fence,
        write_state,
    };
    use crate::{CatalogWatchEvent, VfsToken};

    fn watch_event(
        filesystem_id: &str,
        root_directory_id: &str,
        root_data_root: &str,
    ) -> CatalogWatchEvent {
        CatalogWatchEvent {
            schema: "carrack.vfs.catalog-watch.v1".to_owned(),
            kind: "catalog_head".to_owned(),
            filesystem_id: filesystem_id.to_owned(),
            revision_id: 7,
            root_directory_id: root_directory_id.to_owned(),
            root_data_root: root_data_root.to_owned(),
            etag: carrack_sdk_core::catalog_checkpoint_etag(&"22".repeat(32))
                .expect("valid catalog watch ETag"),
        }
    }

    fn download_plan(file_id: &str, version_id: &str, lease_id: &str) -> serde_json::Value {
        json!({
            "schema": "carrack.vfs.download-plan.v1",
            "filesystem_id": "11111111111111111111111111111111",
            "directory_id": "22222222222222222222222222222222",
            "file_id": file_id,
            "version_id": version_id,
            "plaintext_bytes": 0,
            "verification_block_bytes": 4,
            "verification_block_count": 0,
            "file_root": "11".repeat(32),
            "metadata_root": "22".repeat(32),
            "block_manifest_sha256": "33".repeat(32),
            "block_manifest_bytes": 1,
            "block_manifest_r2_key": "manifest-key",
            "block_manifest_r2_version": "manifest-version",
            "crypto_suite": "plaintext/v1",
            "key_epoch": 1,
            "encryption_frame_bytes": 4,
            "encoded_bytes": 0,
            "encoded_sha256": "44".repeat(32),
            "location_id": "55555555555555555555555555555555",
            "driver_id": "local-test",
            "storage_key": "opaque-key",
            "native_id": null,
            "provider_version": null,
            "etag": null,
            "driver_kind": carrack_driver_contract::DriverKind::LocalFilesystemV2.as_str(),
            "driver_revision": 1,
            "config": {},
            "credential": null,
            "directory_key": null,
            "read_lease_id": lease_id,
            "expires_at": 2_000_000_000_u64
        })
    }

    #[tokio::test]
    async fn plan_producer_prefetches_beyond_the_payload_window_and_terminates() {
        let server = MockServer::start_async().await;
        let temporary = tempfile::tempdir().expect("temporary directory");
        let ids = [
            (
                "33333333333333333333333333333331",
                "44444444444444444444444444444441",
                "66666666666666666666666666666661",
            ),
            (
                "33333333333333333333333333333332",
                "44444444444444444444444444444442",
                "66666666666666666666666666666662",
            ),
            (
                "33333333333333333333333333333333",
                "44444444444444444444444444444443",
                "66666666666666666666666666666663",
            ),
        ];
        let mut mocks = Vec::new();
        let mut spool = RecordSpool::<PlannedFile>::create(temporary.path()).expect("plan spool");
        for (ordinal, (file_id, version_id, lease_id)) in ids.iter().enumerate() {
            mocks.push(
                server
                    .mock_async(|when, then| {
                        when.method(GET)
                            .path(format!("/api/v2/versions/{version_id}/download"));
                        then.status(200)
                            .json_body(download_plan(file_id, version_id, lease_id));
                    })
                    .await,
            );
            spool
                .append(&PlannedFile {
                    vfs_path: format!("/file-{ordinal}"),
                    relative_path: PathBuf::from(format!("file-{ordinal}")),
                    file_id: (*file_id).to_owned(),
                    version_id: (*version_id).to_owned(),
                    size_bytes: 0,
                    file_root: "11".repeat(32),
                })
                .expect("append plan");
        }
        let token = VfsToken::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32])).expect("VFS token");
        let client = VfsClient::new(&format!("{}/", server.base_url()), token).expect("client");
        let (mut plans, producer) =
            start_plan_producer(client, spool.finish().expect("finish spool"), 2);

        assert!(matches!(
            plans.recv().await,
            Some(PlanMessage::File(file)) if file.is_ok()
        ));
        for _ in 0..100 {
            if mocks[2].hits_async().await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            mocks[2].hits_async().await,
            1,
            "the next plan was not prefetched while an earlier payload could be active"
        );
        for _ in 0..2 {
            assert!(matches!(
                plans.recv().await,
                Some(PlanMessage::File(file)) if file.is_ok()
            ));
        }
        assert!(matches!(plans.recv().await, Some(PlanMessage::Finished)));
        producer.finish().await.expect("plan producer completed");
    }

    #[tokio::test]
    async fn direct_catalog_watch_fence_accepts_only_the_pinned_view() {
        let filesystem_id = "019f0000000000000000000000000001";
        let directory_id = "019f0000000000000000000000000002";
        let data_root = "11".repeat(32);
        let fence = CatalogFence {
            filesystem_id: filesystem_id.to_owned(),
            directory_id: directory_id.to_owned(),
            revision: 5,
            data_root: data_root.clone(),
        };
        let client = VfsClient::new(
            "http://127.0.0.1:9",
            VfsToken::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32])).expect("valid VFS token"),
        )
        .expect("VFS client");

        validate_watch_fence(
            &client,
            &fence,
            &watch_event(filesystem_id, directory_id, &data_root),
        )
        .await
        .expect("identical pinned view");

        assert!(
            validate_watch_fence(
                &client,
                &fence,
                &watch_event(filesystem_id, directory_id, &"33".repeat(32)),
            )
            .await
            .is_err()
        );
        assert!(
            validate_watch_fence(
                &client,
                &fence,
                &watch_event("019f0000000000000000000000000003", directory_id, &data_root,),
            )
            .await
            .is_err()
        );
    }

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
    fn rejects_unbounded_sync_pipeline_options() {
        let temporary = tempfile::tempdir().expect("sync options temporary directory");
        let options =
            |transfer_part_bytes, maximum_concurrency, maximum_file_concurrency| SyncOptions {
                state_directory: temporary.path().join("state"),
                use_catalog_cache: true,
                transfer_part_bytes,
                maximum_concurrency,
                maximum_file_concurrency,
            };
        let valid = options(256 * 1024 * 1024, 64, 64);
        validate_options(&valid).expect("maximum bounded options");

        for invalid in [
            SyncOptions {
                state_directory: "relative/state".into(),
                use_catalog_cache: true,
                transfer_part_bytes: 1024,
                maximum_concurrency: 1,
                maximum_file_concurrency: 1,
            },
            options(valid.transfer_part_bytes + 1, 64, 64),
            options(256 * 1024 * 1024, valid.maximum_concurrency + 1, 64),
            options(256 * 1024 * 1024, 64, valid.maximum_file_concurrency + 1),
        ] {
            validate_options(&invalid).expect_err("unbounded sync option must fail closed");
        }
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
            loaded
                .lookup_version("first-version")
                .into_iter()
                .map(|record| record.relative_path)
                .collect::<Vec<_>>(),
            vec![std::path::PathBuf::from("first.parquet")]
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
    fn immutable_version_reuse_copies_and_reverifies_before_publication() {
        let temporary = tempfile::tempdir().expect("local reuse temporary directory");
        let destination = temporary.path().join("destination");
        let old_path = destination.join("old/data.parquet");
        std::fs::create_dir_all(old_path.parent().expect("old path parent"))
            .expect("create old path parent");
        std::fs::write(&old_path, b"verified immutable payload").expect("write immutable payload");
        let tree = super::integrity::build_file(&old_path, 4).expect("hash immutable payload");
        let candidate = StateRecord {
            relative_path: "old/data.parquet".into(),
            version_id: "immutable-version".to_owned(),
            size_bytes: tree.size_bytes,
            file_root: hex::encode(tree.root),
            verification_block_bytes: tree.block_bytes,
        };
        let planned = PlannedFile {
            vfs_path: "/new/data.parquet".to_owned(),
            relative_path: "new/data.parquet".into(),
            file_id: "file-id".to_owned(),
            version_id: candidate.version_id.clone(),
            size_bytes: candidate.size_bytes,
            file_root: candidate.file_root.clone(),
        };

        let staged = stage_local_version(&destination, &planned, &candidate)
            .expect("stage immutable local version")
            .expect("matching immutable version");
        assert!(!destination.join(&planned.relative_path).exists());
        let record = staged.publish().expect("publish immutable local version");

        assert_eq!(record.relative_path, planned.relative_path);
        assert_eq!(
            std::fs::read(&old_path).expect("read old path"),
            b"verified immutable payload"
        );
        assert_eq!(
            std::fs::read(destination.join(&planned.relative_path)).expect("read reused path"),
            b"verified immutable payload"
        );
        assert!(
            std::fs::read_dir(destination.join("new"))
                .expect("read target parent")
                .all(|entry| !entry
                    .expect("target entry")
                    .file_name()
                    .to_string_lossy()
                    .contains("carrack-reuse"))
        );

        let cancelled = PlannedFile {
            relative_path: "cancelled/data.parquet".into(),
            vfs_path: "/cancelled/data.parquet".to_owned(),
            ..planned.clone()
        };
        let staged = stage_local_version(&destination, &cancelled, &candidate)
            .expect("stage cancelled local version")
            .expect("matching cancelled version");
        let staged_path = staged
            .temporary
            .clone()
            .expect("cancelled staging identity");
        assert!(staged_path.is_file());
        drop(staged);
        assert!(!staged_path.exists());
        assert!(!destination.join(cancelled.relative_path).exists());

        std::fs::write(&old_path, b"corrupt immutable payload").expect("corrupt old path");
        let rejected = PlannedFile {
            relative_path: "rejected/data.parquet".into(),
            vfs_path: "/rejected/data.parquet".to_owned(),
            ..planned
        };
        assert!(
            stage_local_version(&destination, &rejected, &candidate)
                .expect("reject corrupt local candidate")
                .is_none()
        );
        assert!(!destination.join(rejected.relative_path).exists());
    }

    #[test]
    fn unchanged_file_uses_no_download_and_local_corruption_forces_download() {
        let temporary = tempfile::tempdir().expect("local reuse temporary directory");
        let destination = temporary.path().join("destination");
        std::fs::create_dir(&destination).expect("create destination");
        let path = destination.join("unchanged.parquet");
        std::fs::write(&path, b"authenticated payload").expect("write authenticated payload");
        let tree = super::integrity::build_file(&path, 4).expect("hash authenticated payload");
        let record = StateRecord {
            relative_path: "unchanged.parquet".into(),
            version_id: "immutable-version".to_owned(),
            size_bytes: tree.size_bytes,
            file_root: hex::encode(tree.root),
            verification_block_bytes: tree.block_bytes,
        };
        let file = PlannedFile {
            vfs_path: "/unchanged.parquet".to_owned(),
            relative_path: record.relative_path.clone(),
            file_id: "file-id".to_owned(),
            version_id: record.version_id.clone(),
            size_bytes: record.size_bytes,
            file_root: record.file_root.clone(),
        };
        let unchanged = evaluate_local_file(
            &destination,
            LocalReusePlan {
                file: file.clone(),
                exact: Some(record.clone()),
                relocated: Vec::new(),
            },
        )
        .expect("evaluate unchanged file");
        assert!(matches!(unchanged.disposition, LocalDisposition::Reused(_)));

        let corrupt_bytes = usize::try_from(record.size_bytes).expect("test payload length");
        std::fs::write(&path, vec![b'x'; corrupt_bytes])
            .expect("corrupt local payload without changing its length");
        let corrupt = evaluate_local_file(
            &destination,
            LocalReusePlan {
                file,
                exact: Some(record),
                relocated: Vec::new(),
            },
        )
        .expect("evaluate corrupt local file");
        assert!(matches!(corrupt.disposition, LocalDisposition::Download(_)));
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
                "crypto_suite": "carrack-vfs-aes256gcm-hkdfsha256-v1",
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
                "crypto_suite": "carrack-vfs-aes256gcm-hkdfsha256-v1",
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
            use_catalog_cache: true,
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
        root_fence.assert_hits_async(6).await;
        child_catalog.assert_hits_async(0).await;
    }

    #[test]
    #[ignore = "release-only scaling acceptance"]
    fn indexed_state_accepts_one_hundred_thousand_records_without_linear_lookup() {
        const RECORDS: usize = 100_000;
        let temporary = tempfile::tempdir().expect("state scaling temporary directory");
        let state_root = temporary.path().join("state");
        let mut spool =
            RecordSpool::<StateRecord>::create(&state_root).expect("create state scaling spool");
        let root = "42".repeat(32);
        let started = Instant::now();
        for index in 0..RECORDS {
            spool
                .append(&StateRecord {
                    relative_path: format!("partition-{index:06}.parquet").into(),
                    version_id: format!("version-{index:06}"),
                    size_bytes: 4096,
                    file_root: root.clone(),
                    verification_block_bytes: 1024,
                })
                .expect("append state scaling record");
        }
        let spool_elapsed = started.elapsed();
        let path = state_root.join("state.sqlite3");
        let build_started = Instant::now();
        write_state(
            &path,
            "/benchmark",
            spool.finish().expect("seal state scaling spool"),
        )
        .expect("publish indexed scaling state");
        let build_elapsed = build_started.elapsed();
        let state = StateIndex::open(&path, "/benchmark").expect("open indexed scaling state");
        let lookup_started = Instant::now();
        for index in 0..RECORDS {
            let relative_path = PathBuf::from(format!("partition-{index:06}.parquet"));
            let record = state.lookup(&relative_path).expect("indexed state record");
            assert_eq!(record.relative_path, relative_path);
        }
        let lookup_elapsed = lookup_started.elapsed();
        eprintln!(
            "carrack_sync_state_benchmark records={RECORDS} spool_ms={} build_ms={} lookup_ms={} database_bytes={}",
            spool_elapsed.as_millis(),
            build_elapsed.as_millis(),
            lookup_elapsed.as_millis(),
            std::fs::metadata(path)
                .expect("state database metadata")
                .len()
        );
    }

    #[test]
    #[ignore = "release-only scaling acceptance"]
    fn warm_sync_rehashes_ten_thousand_files_without_provider_payload() {
        const FILES: usize = 10_000;
        const FILE_BYTES: usize = 4096;
        const BLOCK_BYTES: u64 = 1024;
        let temporary = tempfile::tempdir().expect("warm scaling temporary directory");
        let destination = temporary.path().join("destination");
        std::fs::create_dir(&destination).expect("create warm scaling destination");
        let payload = vec![0x5a; FILE_BYTES];
        let mut accumulator = carrack_sdk_core::FileMerkleAccumulator::new(BLOCK_BYTES)
            .expect("create warm scaling accumulator");
        let block_bytes = usize::try_from(BLOCK_BYTES).expect("benchmark block size fits usize");
        for block in payload.chunks(block_bytes) {
            accumulator
                .push_block(block)
                .expect("hash warm scaling payload block");
        }
        let root = hex::encode(accumulator.finish().expect("finish warm scaling payload"));
        for index in 0..FILES {
            std::fs::write(
                destination.join(format!("partition-{index:05}.parquet")),
                &payload,
            )
            .expect("write warm scaling file");
        }
        let started = Instant::now();
        for index in 0..FILES {
            let relative_path = PathBuf::from(format!("partition-{index:05}.parquet"));
            let record = StateRecord {
                relative_path: relative_path.clone(),
                version_id: format!("version-{index:05}"),
                size_bytes: FILE_BYTES as u64,
                file_root: root.clone(),
                verification_block_bytes: BLOCK_BYTES,
            };
            let evaluation = evaluate_local_file(
                &destination,
                LocalReusePlan {
                    file: PlannedFile {
                        vfs_path: format!(
                            "/{relative_path}",
                            relative_path = relative_path.display()
                        ),
                        relative_path,
                        file_id: format!("file-{index:05}"),
                        version_id: record.version_id.clone(),
                        size_bytes: record.size_bytes,
                        file_root: record.file_root.clone(),
                    },
                    exact: Some(record),
                    relocated: Vec::new(),
                },
            )
            .expect("verify warm scaling file");
            assert!(matches!(
                evaluation.disposition,
                LocalDisposition::Reused(_)
            ));
        }
        let elapsed = started.elapsed();
        eprintln!(
            "carrack_warm_sync_benchmark files={FILES} local_bytes={} provider_bytes=0 elapsed_ms={}",
            FILES * FILE_BYTES,
            elapsed.as_millis()
        );
    }
}
