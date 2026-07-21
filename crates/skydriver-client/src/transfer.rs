//! Complete-object Put orchestration and rooted local-driver transport.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use zeroize::Zeroize;

use crate::{
    Error, VfsClient,
    crypto::{Descriptor, stage},
    driver::{DriverRegistry, UploadRequest},
    integrity,
    private_fs::ensure_private_directory,
    vfs::{canonical_components, canonical_path},
};

const SOURCE_COPY_BUFFER_BYTES: usize = 1024 * 1024;
const MAXIMUM_RANGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_PUT_CONTROL_BODY_BYTES: usize = 256 * 1024;
static PLAINTEXT_SPOOL_ORDINAL: AtomicU64 = AtomicU64::new(0);

/// High-level immutable Put requirements.
pub struct PutOptions {
    /// Exact destination entry revision, or zero for creation.
    pub expected_entry_revision: u64,
    /// Optional preferred placement selected by policy.
    pub preferred_driver_id: Option<String>,
    /// Stable identity for retries of this exact content publication.
    pub idempotency_key: String,
    /// Plaintext integrity block size.
    pub verification_block_bytes: u64,
    /// Independently authenticated encryption frame size.
    pub encryption_frame_bytes: u64,
    /// Private absolute encoded-staging directory.
    pub staging_directory: PathBuf,
    /// Provider transfer part size used by the hidden resumable pipeline.
    pub transfer_part_bytes: u64,
    /// Maximum concurrent provider part operations.
    pub maximum_concurrency: usize,
}

/// A source that can open the same complete byte sequence again.
///
/// Skydriver normalizes the first opened reader into a private durable spool so
/// provider retry and recovery never depend on the caller remaining alive.
pub trait ReplayableUploadSource: Send + Sync {
    /// Exact number of bytes returned by every opened reader.
    fn size_bytes(&self) -> u64;

    /// Opens the complete byte sequence at offset zero.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the source cannot open a fresh reader.
    fn open(&self) -> std::io::Result<Box<dyn Read + Send>>;
}

/// A complete source that can open independently bounded exact ranges.
pub trait BoundedRangeUploadSource: Send + Sync {
    /// Exact complete source length.
    fn size_bytes(&self) -> u64;

    /// Opens exactly `length` bytes beginning at `offset`.
    ///
    /// Returning fewer or additional bytes fails closed.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the exact requested range cannot be opened.
    fn open_range(&self, offset: u64, length: u64) -> std::io::Result<Box<dyn Read + Send>>;
}

struct PlaintextSpool {
    path: Option<PathBuf>,
}

struct CancelSafeStage {
    staged: Option<crate::crypto::StagedObject>,
}

impl CancelSafeStage {
    fn into_inner(mut self) -> Result<crate::crypto::StagedObject, Error> {
        self.staged.take().ok_or_else(|| {
            Error::InvalidResponse("encoded staging worker omitted its result".to_owned())
        })
    }
}

impl Drop for CancelSafeStage {
    fn drop(&mut self) {
        if let Some(staged) = self.staged.take() {
            let _ = std::fs::remove_file(staged.path);
        }
    }
}

impl PlaintextSpool {
    fn path(&self) -> Result<&Path, Error> {
        self.path.as_deref().ok_or_else(|| {
            Error::InvalidResponse("plaintext source spool identity is missing".to_owned())
        })
    }

    fn remove(mut self) -> Result<(), Error> {
        let path = self.path.take().ok_or_else(|| {
            Error::InvalidResponse("plaintext source spool identity is missing".to_owned())
        })?;
        std::fs::remove_file(path)
            .map_err(|error| Error::InvalidResponse(format!("remove plaintext spool: {error}")))
    }
}

impl Drop for PlaintextSpool {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Durable Put publication receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    missing_docs,
    reason = "wire fields retain the documented server schema names"
)]
pub struct PutReceipt {
    pub schema: String,
    pub intent_id: String,
    pub file_id: String,
    pub version_id: String,
    pub location_id: String,
    pub driver_id: String,
    pub storage_key: String,
    pub block_manifest_r2_version: String,
    pub encoded_bytes: u64,
    pub encoded_sha256: String,
    pub verification_method: String,
    pub native_id: Option<String>,
    pub provider_version: Option<String>,
    pub etag: Option<String>,
    pub entry_revision: u64,
    pub catalog_revision_id: u64,
    pub committed_at: u64,
    pub state: String,
}

/// Verified native Put result.
#[derive(Clone, Debug, Serialize)]
pub struct PutResult {
    /// Stable output schema.
    pub schema: &'static str,
    /// Durable publication receipt.
    pub receipt: PutReceipt,
    /// Plaintext bytes read and verified.
    pub plaintext_bytes: u64,
    /// Plaintext file Merkle root.
    pub file_root: String,
    /// Portable metadata root.
    pub metadata_root: String,
    /// Effective storage crypto suite.
    pub crypto_suite: String,
    /// Effective authenticated frame size.
    pub encryption_frame_bytes: u64,
    /// Correctness-preserving capability degradations.
    pub warnings: Vec<String>,
}

#[derive(Serialize)]
struct PrepareRequest<'a> {
    directory_id: &'a str,
    entry_name: &'a str,
    expected_entry_revision: u64,
    plaintext_bytes: u64,
    verification_block_bytes: u64,
    verification_block_count: u64,
    file_root: &'a str,
    metadata_root: &'a str,
    block_manifest_sha256: &'a str,
    block_manifest_bytes: u64,
    encryption_frame_bytes: u64,
    preferred_driver_id: Option<&'a str>,
    idempotency_key: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema: String,
    intent_id: String,
    filesystem_id: String,
    directory_id: String,
    entry_name: String,
    expected_entry_revision: u64,
    file_id: String,
    version_id: String,
    location_id: String,
    driver_id: String,
    storage_key: String,
    block_manifest_r2_key: String,
    crypto_suite: String,
    key_epoch: u64,
    encryption_frame_bytes: u64,
    requires_encryption_key: bool,
    state: String,
    expires_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyGrant {
    schema: String,
    intent_id: String,
    directory_id: String,
    version_id: String,
    crypto_suite: String,
    key_epoch: u64,
    directory_key: Option<String>,
    expires_at: u64,
}

impl Drop for KeyGrant {
    fn drop(&mut self) {
        if let Some(directory_key) = self.directory_key.as_mut() {
            directory_key.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DriverGrant {
    schema: String,
    intent_id: String,
    driver_id: String,
    driver_kind: String,
    driver_revision: u64,
    config: Value,
    credential: Option<Value>,
    expires_at: u64,
}

impl Drop for DriverGrant {
    fn drop(&mut self) {
        if let Some(credential) = self.credential.as_mut() {
            zeroize_json_value(credential);
        }
    }
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_value),
        Value::Object(values) => values.values_mut().for_each(zeroize_json_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestStage {
    schema: String,
    intent_id: String,
    sha256: String,
    bytes: u64,
    r2_key: String,
    r2_version: String,
}

#[derive(Serialize)]
struct CommitRequest<'a> {
    block_manifest_r2_version: &'a str,
    encoded_bytes: u64,
    encoded_sha256: &'a str,
    verification_method: &'static str,
    native_id: Option<&'a str>,
    provider_version: Option<&'a str>,
    etag: Option<&'a str>,
    telemetry: TransferTelemetry,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct TransferTelemetry {
    schema: String,
    provider_ms: u64,
    total_ms: u64,
    retries: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_provider_ms: Option<u64>,
}

impl TransferTelemetry {
    pub(crate) fn measured(provider: std::time::Duration, total: std::time::Duration) -> Self {
        Self {
            schema: "skydriver.transfer-telemetry.v1".to_owned(),
            provider_ms: duration_ms(provider),
            total_ms: duration_ms(total).max(duration_ms(provider)),
            retries: 0,
            plan_ms: None,
            queue_ms: None,
            post_provider_ms: None,
        }
    }

    pub(crate) fn measured_download(
        plan: std::time::Duration,
        queue: std::time::Duration,
        provider: std::time::Duration,
        post_provider: std::time::Duration,
        total: std::time::Duration,
    ) -> Self {
        let plan_ms = duration_ms(plan);
        let queue_ms = duration_ms(queue);
        let provider_ms = duration_ms(provider);
        let post_provider_ms = duration_ms(post_provider);
        let phase_total = plan_ms
            .saturating_add(queue_ms)
            .saturating_add(provider_ms)
            .saturating_add(post_provider_ms);
        Self {
            schema: "skydriver.transfer-telemetry.v2".to_owned(),
            provider_ms,
            total_ms: duration_ms(total).max(phase_total),
            retries: 0,
            plan_ms: Some(plan_ms),
            queue_ms: Some(queue_ms),
            post_provider_ms: Some(post_provider_ms),
        }
    }

    pub(crate) fn add_post_provider(&mut self, elapsed: std::time::Duration) {
        let elapsed_ms = duration_ms(elapsed);
        if let Some(post_provider_ms) = self.post_provider_ms.as_mut() {
            *post_provider_ms = post_provider_ms.saturating_add(elapsed_ms);
            self.total_ms = self.total_ms.saturating_add(elapsed_ms);
        }
    }
}

impl VfsClient {
    /// Uploads an in-memory byte slice through the same complete-object,
    /// resumable, encrypted, and verified pipeline as [`Self::put_file`].
    ///
    /// Bytes are first spooled into an owner-private file because provider
    /// retries and full readback must survive bounded-memory scheduling.
    ///
    /// # Errors
    ///
    /// Returns an error when private spooling, upload, verification, or
    /// optimistic publication fails.
    pub async fn put_bytes(
        &self,
        bytes: &[u8],
        vfs_path: &str,
        options: &PutOptions,
    ) -> Result<PutResult, Error> {
        validate_options(options)?;
        let (spool, mut output) = create_plaintext_spool(&options.staging_directory)?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| Error::InvalidResponse(format!("write plaintext spool: {error}")))?;
        drop(output);
        self.put_spooled_source(spool, vfs_path, options).await
    }

    /// Uploads a one-shot reader after privately spooling at most `maximum_bytes`.
    ///
    /// The reader is consumed on a blocking worker. Reading one byte beyond the
    /// explicit bound fails before control-plane or provider I/O.
    ///
    /// # Errors
    ///
    /// Returns an error when the bound is zero or exceeded, private spooling
    /// fails, or the ordinary complete-object Put pipeline rejects the object.
    pub async fn put_reader<R>(
        &self,
        reader: R,
        maximum_bytes: u64,
        vfs_path: &str,
        options: &PutOptions,
    ) -> Result<PutResult, Error>
    where
        R: Read + Send + 'static,
    {
        validate_options(options)?;
        if maximum_bytes == 0 {
            return Err(Error::InvalidResponse(
                "one-shot upload maximum bytes must be nonzero".to_owned(),
            ));
        }
        let staging_directory = options.staging_directory.clone();
        let spool = run_source_worker(move || {
            spool_bounded_reader(&staging_directory, reader, maximum_bytes)
        })
        .await?;
        self.put_spooled_source(spool, vfs_path, options).await
    }

    /// Uploads one replayable complete source through a private durable spool.
    ///
    /// # Errors
    ///
    /// Returns an error when the declared length differs from the opened
    /// reader, private spooling fails, or complete-object Put fails.
    pub async fn put_replayable_source<S>(
        &self,
        source: S,
        vfs_path: &str,
        options: &PutOptions,
    ) -> Result<PutResult, Error>
    where
        S: ReplayableUploadSource + 'static,
    {
        validate_options(options)?;
        let staging_directory = options.staging_directory.clone();
        let spool = run_source_worker(move || {
            let size_bytes = source.size_bytes();
            let reader = source
                .open()
                .map_err(source_io_error("open replayable source"))?;
            spool_exact_reader(&staging_directory, reader, size_bytes)
        })
        .await?;
        self.put_spooled_source(spool, vfs_path, options).await
    }

    /// Uploads one complete range source through bounded exact range readers.
    ///
    /// # Errors
    ///
    /// Returns an error when the range bound is unsafe, any reader is short or
    /// overlong, private spooling fails, or complete-object Put fails.
    pub async fn put_range_source<S>(
        &self,
        source: S,
        range_bytes: u64,
        vfs_path: &str,
        options: &PutOptions,
    ) -> Result<PutResult, Error>
    where
        S: BoundedRangeUploadSource + 'static,
    {
        validate_options(options)?;
        if range_bytes == 0 || range_bytes > MAXIMUM_RANGE_BYTES {
            return Err(Error::InvalidResponse(
                "upload source range bytes are outside the safe bound".to_owned(),
            ));
        }
        let staging_directory = options.staging_directory.clone();
        let spool =
            run_source_worker(move || spool_range_source(&staging_directory, &source, range_bytes))
                .await?;
        self.put_spooled_source(spool, vfs_path, options).await
    }

    async fn put_spooled_source(
        &self,
        spool: PlaintextSpool,
        vfs_path: &str,
        options: &PutOptions,
    ) -> Result<PutResult, Error> {
        let result = self.put_file(spool.path()?, vfs_path, options).await;
        let cleanup = spool.remove();
        let mut value = result?;
        if let Err(error) = cleanup {
            value.warnings.push(format!(
                "The verified file was published, but plaintext source spool cleanup was deferred: {error}"
            ));
        }
        Ok(value)
    }

    /// Uploads one unchanged local regular file as a complete provider object.
    ///
    /// # Errors
    ///
    /// Fails before publication on source races, crypto/Merkle divergence,
    /// unsupported drivers, provider readback mismatch, or optimistic conflict.
    #[allow(
        clippy::too_many_lines,
        reason = "Put keeps immutable identities and fail-closed publication together"
    )]
    pub async fn put_file(
        &self,
        source: &Path,
        vfs_path: &str,
        options: &PutOptions,
    ) -> Result<PutResult, Error> {
        let transfer_started = Instant::now();
        validate_options(options)?;
        let components = canonical_components(vfs_path)?;
        let (entry_name, parent_components) = components.split_last().ok_or_else(|| {
            Error::InvalidResponse("Put target must not be the VFS root".to_owned())
        })?;
        let resolved = self.resolve(&canonical_path(parent_components)).await?;
        let parent_directory_id = match resolved.entry {
            Some(entry) if entry.kind == crate::EntryKind::Directory => entry.child_directory_id,
            None => Some(resolved.parent.id),
            _ => None,
        }
        .ok_or_else(|| Error::InvalidResponse("Put parent is not a directory".to_owned()))?;
        if entry_name.is_empty() {
            return Err(Error::InvalidResponse(
                "Put target is not a file path".to_owned(),
            ));
        }
        let source_path = source.to_owned();
        let verification_block_bytes = options.verification_block_bytes;
        let tree = tokio::task::spawn_blocking(move || {
            integrity::build_file(&source_path, verification_block_bytes)
        })
        .await
        .map_err(|error| {
            Error::InvalidResponse(format!("source integrity worker failed: {error}"))
        })??;
        let manifest = integrity::manifest(&tree)?;
        let manifest_sha256 = hex::encode(Sha256::digest(&manifest));
        let file_root = hex::encode(tree.root);
        let metadata_root = hex::encode(integrity::empty_metadata_root());
        let token = self.token.encode();
        let preparation: Preparation = self
            .control
            .send_json_bounded(
                Method::POST,
                "api/v2/puts/prepare",
                Some(&token),
                &[],
                Some(&PrepareRequest {
                    directory_id: &parent_directory_id,
                    entry_name,
                    expected_entry_revision: options.expected_entry_revision,
                    plaintext_bytes: tree.size_bytes,
                    verification_block_bytes: tree.block_bytes,
                    verification_block_count: tree.blocks.len() as u64,
                    file_root: &file_root,
                    metadata_root: &metadata_root,
                    block_manifest_sha256: &manifest_sha256,
                    block_manifest_bytes: manifest.len() as u64,
                    encryption_frame_bytes: options.encryption_frame_bytes,
                    preferred_driver_id: options.preferred_driver_id.as_deref(),
                    idempotency_key: &options.idempotency_key,
                }),
                MAXIMUM_PUT_CONTROL_BODY_BYTES,
            )
            .await?;
        validate_preparation(&preparation, &parent_directory_id, entry_name, options)?;
        let key_grant_path = format!("api/v2/puts/{}/key-grant", preparation.intent_id);
        let driver_grant_path = format!("api/v2/puts/{}/driver-grant", preparation.intent_id);
        let key_request = self.control.send_json_bounded::<KeyGrant, ()>(
            Method::POST,
            &key_grant_path,
            Some(&token),
            &[],
            None,
            MAXIMUM_PUT_CONTROL_BODY_BYTES,
        );
        let driver_request = self.control.send_json_bounded::<DriverGrant, ()>(
            Method::POST,
            &driver_grant_path,
            Some(&token),
            &[],
            None,
            MAXIMUM_PUT_CONTROL_BODY_BYTES,
        );
        let (key, mut driver) = tokio::try_join!(key_request, driver_request)?;
        validate_key_grant(&key, &preparation)?;
        validate_driver_grant(&driver, &preparation)?;
        let directory_key = decode_directory_key(&key)?;
        let descriptor = Descriptor {
            directory_id: parse_identifier(&preparation.directory_id)?,
            version_id: parse_identifier(&preparation.version_id)?,
            key_epoch: preparation.key_epoch,
            frame_bytes: preparation.encryption_frame_bytes,
            plaintext_bytes: tree.size_bytes,
        };
        let stage_source = source.to_owned();
        let stage_root = options.staging_directory.clone();
        let stage_intent_id = preparation.intent_id.clone();
        let stage_suite = preparation.crypto_suite.clone();
        let expected_tree = tree.clone();
        let stage_work = run_stage_worker(move || {
            let mut directory_key = directory_key;
            let staged = stage(
                &stage_source,
                &stage_root,
                &stage_intent_id,
                &stage_suite,
                &descriptor,
                directory_key.as_ref(),
            );
            if let Some(key) = directory_key.as_mut() {
                key.zeroize();
            }
            let staged = staged?;
            let observed = integrity::build_file(&stage_source, verification_block_bytes);
            match observed {
                Ok(observed) if observed == expected_tree => Ok(CancelSafeStage {
                    staged: Some(staged),
                }),
                Ok(_) => {
                    let _ = std::fs::remove_file(&staged.path);
                    Err(Error::InvalidResponse(
                        "source changed during encoding".to_owned(),
                    ))
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&staged.path);
                    Err(error)
                }
            }
        });
        let manifest_work = self.stage_manifest(&token, &preparation, &manifest);
        let (staged, manifest_stage) = tokio::try_join!(stage_work, manifest_work)?;
        let staged = staged.into_inner()?;
        let provider_started = Instant::now();
        let mut opened_driver = DriverRegistry::open(
            &driver.driver_kind,
            std::mem::take(&mut driver.config),
            driver.credential.take(),
        )?;
        let object = opened_driver
            .upload(UploadRequest {
                control: &self.control,
                token: &token,
                intent_id: &preparation.intent_id,
                storage_key: &preparation.storage_key,
                staged: &staged,
                part_bytes: options.transfer_part_bytes,
                maximum_concurrency: options.maximum_concurrency,
            })
            .await?;
        let provider_elapsed = provider_started.elapsed();
        let warnings = opened_driver.upload_warnings(options.maximum_concurrency);
        let commit: PutReceipt = self
            .control
            .send_json_bounded(
                Method::POST,
                &format!("api/v2/puts/{}/commit", preparation.intent_id),
                Some(&token),
                &[],
                Some(&CommitRequest {
                    block_manifest_r2_version: &manifest_stage.r2_version,
                    encoded_bytes: staged.encoded_bytes,
                    encoded_sha256: &staged.encoded_sha256,
                    verification_method: "complete_readback",
                    native_id: Some(&object.native_id),
                    provider_version: Some(&object.provider_version),
                    etag: Some(&object.etag),
                    telemetry: TransferTelemetry::measured(
                        provider_elapsed,
                        transfer_started.elapsed(),
                    ),
                }),
                MAXIMUM_PUT_CONTROL_BODY_BYTES,
            )
            .await?;
        validate_receipt(&commit, &preparation, &manifest_stage, &staged)?;
        std::fs::remove_file(&staged.path).map_err(|error| {
            Error::InvalidResponse(format!("remove committed staging: {error}"))
        })?;
        Ok(PutResult {
            schema: "skydriver.fs-put.v1",
            receipt: commit,
            plaintext_bytes: tree.size_bytes,
            file_root,
            metadata_root,
            crypto_suite: preparation.crypto_suite,
            encryption_frame_bytes: preparation.encryption_frame_bytes,
            warnings,
        })
    }

    async fn stage_manifest(
        &self,
        token: &str,
        preparation: &Preparation,
        manifest: &[u8],
    ) -> Result<ManifestStage, Error> {
        let endpoint = self
            .control
            .endpoint
            .join(&format!(
                "api/v2/puts/{}/block-manifest",
                preparation.intent_id
            ))
            .map_err(|error| Error::InvalidEndpoint(error.to_string()))?;
        let response = self
            .control
            .http
            .post(endpoint)
            .header("Accept", "application/json")
            .header("Content-Type", "application/octet-stream")
            .header("Skydriver-Protocol-Epoch", crate::PROTOCOL_EPOCH)
            .header("Skydriver-SDK-Version", crate::SDK_VERSION)
            .bearer_auth(token)
            .body(manifest.to_vec())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(Error::Rejected {
                status: response.status().as_u16(),
                message: "block-manifest stage rejected".to_owned(),
            });
        }
        let staged: ManifestStage = crate::decode_json(response, 64 * 1024, false).await?;
        if staged.schema != "skydriver.vfs.block-manifest-stage.v1"
            || staged.intent_id != preparation.intent_id
            || staged.sha256 != hex::encode(Sha256::digest(manifest))
            || staged.bytes != manifest.len() as u64
            || staged.r2_key != preparation.block_manifest_r2_key
            || staged.r2_version.is_empty()
        {
            return Err(Error::InvalidResponse(
                "invalid block-manifest stage".to_owned(),
            ));
        }
        Ok(staged)
    }
}

async fn run_source_worker<F>(work: F) -> Result<PlaintextSpool, Error>
where
    F: FnOnce() -> Result<PlaintextSpool, Error> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|error| {
        Error::InvalidResponse(format!("plaintext source spool worker failed: {error}"))
    })?
}

async fn run_stage_worker<F>(work: F) -> Result<CancelSafeStage, Error>
where
    F: FnOnce() -> Result<CancelSafeStage, Error> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|error| {
        Error::InvalidResponse(format!("encoded staging worker failed: {error}"))
    })?
}

fn spool_bounded_reader<R: Read>(
    staging_root: &Path,
    reader: R,
    maximum_bytes: u64,
) -> Result<PlaintextSpool, Error> {
    let (spool, mut output) = create_plaintext_spool(staging_root)?;
    copy_reader(reader, &mut output, maximum_bytes, false)?;
    finish_plaintext_spool(&output)?;
    Ok(spool)
}

fn spool_exact_reader<R: Read>(
    staging_root: &Path,
    reader: R,
    size_bytes: u64,
) -> Result<PlaintextSpool, Error> {
    let (spool, mut output) = create_plaintext_spool(staging_root)?;
    copy_reader(reader, &mut output, size_bytes, true)?;
    finish_plaintext_spool(&output)?;
    Ok(spool)
}

fn spool_range_source<S: BoundedRangeUploadSource>(
    staging_root: &Path,
    source: &S,
    range_bytes: u64,
) -> Result<PlaintextSpool, Error> {
    let (spool, mut output) = create_plaintext_spool(staging_root)?;
    let size_bytes = source.size_bytes();
    let mut offset = 0_u64;
    while offset < size_bytes {
        let length = range_bytes.min(size_bytes - offset);
        let reader = source
            .open_range(offset, length)
            .map_err(source_io_error("open bounded upload range"))?;
        copy_reader(reader, &mut output, length, true)?;
        offset = offset
            .checked_add(length)
            .ok_or_else(|| Error::InvalidResponse("upload source offset overflow".to_owned()))?;
    }
    finish_plaintext_spool(&output)?;
    Ok(spool)
}

fn create_plaintext_spool(staging_root: &Path) -> Result<(PlaintextSpool, std::fs::File), Error> {
    let directory = staging_root.join("plaintext-sources");
    ensure_private_directory(&directory, "plaintext spool directory")?;
    loop {
        let ordinal = PLAINTEXT_SPOOL_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            ".source-{}-{ordinal:016x}.spool",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                return Ok((PlaintextSpool { path: Some(path) }, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(Error::InvalidResponse(format!(
                    "create plaintext source spool: {error}"
                )));
            }
        }
    }
}

fn copy_reader<R: Read>(
    mut reader: R,
    output: &mut std::fs::File,
    bound_bytes: u64,
    exact: bool,
) -> Result<(), Error> {
    let mut buffer = vec![0_u8; SOURCE_COPY_BUFFER_BYTES];
    let mut copied = 0_u64;
    while copied < bound_bytes {
        let remaining = bound_bytes - copied;
        let length =
            usize::try_from(remaining.min(SOURCE_COPY_BUFFER_BYTES as u64)).map_err(|_| {
                Error::InvalidResponse("upload source range exceeds platform".to_owned())
            })?;
        let read = reader
            .read(&mut buffer[..length])
            .map_err(source_io_error("read upload source"))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(source_io_error("write plaintext source spool"))?;
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| Error::InvalidResponse("upload source size overflow".to_owned()))?;
    }
    let mut extra = [0_u8; 1];
    let has_extra = reader
        .read(&mut extra)
        .map_err(source_io_error("check upload source bound"))?
        != 0;
    if has_extra || (exact && copied != bound_bytes) {
        return Err(Error::InvalidResponse(if has_extra {
            "upload source exceeded its declared byte bound".to_owned()
        } else {
            "upload source ended before its declared length".to_owned()
        }));
    }
    Ok(())
}

fn finish_plaintext_spool(file: &std::fs::File) -> Result<(), Error> {
    file.sync_all()
        .map_err(source_io_error("sync plaintext source spool"))
}

fn source_io_error(context: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |error| Error::InvalidResponse(format!("{context}: {error}"))
}

fn duration_ms(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn validate_options(options: &PutOptions) -> Result<(), Error> {
    if !options.staging_directory.is_absolute()
        || options.idempotency_key.is_empty()
        || options.idempotency_key.len() > 256
        || options.verification_block_bytes == 0
        || options.verification_block_bytes > 256 * 1024 * 1024
        || options.encryption_frame_bytes == 0
        || options.encryption_frame_bytes > options.verification_block_bytes
        || !options
            .verification_block_bytes
            .is_multiple_of(options.encryption_frame_bytes)
        || options.transfer_part_bytes == 0
        || options.transfer_part_bytes > 256 * 1024 * 1024
        || options.maximum_concurrency == 0
        || options.maximum_concurrency > 64
    {
        return Err(Error::InvalidResponse("invalid Put options".to_owned()));
    }
    Ok(())
}

fn validate_preparation(
    value: &Preparation,
    directory_id: &str,
    entry_name: &str,
    options: &PutOptions,
) -> Result<(), Error> {
    for identifier in [
        value.intent_id.as_str(),
        value.filesystem_id.as_str(),
        value.directory_id.as_str(),
        value.file_id.as_str(),
        value.version_id.as_str(),
        value.location_id.as_str(),
    ] {
        parse_identifier(identifier)
            .map_err(|_| Error::InvalidResponse("invalid Put preparation identity".to_owned()))?;
    }
    if !matches!(
        value.crypto_suite.as_str(),
        "plaintext/v1" | "skydriver-vfs-aes256gcm-hkdfsha256-v1"
    ) {
        return Err(Error::failure(
            crate::FailureKind::UnsupportedSuite,
            format!("unsupported crypto suite {}", value.crypto_suite),
        ));
    }
    if value.schema != "skydriver.vfs.put-preparation.v1"
        || value.directory_id != directory_id
        || value.entry_name != entry_name
        || value.expected_entry_revision != options.expected_entry_revision
        || value.driver_id.is_empty()
        || value.storage_key.is_empty()
        || value.block_manifest_r2_key.is_empty()
        || value.key_epoch == 0
        || value.encryption_frame_bytes != options.encryption_frame_bytes
        || value.requires_encryption_key != (value.crypto_suite != "plaintext/v1")
        || !matches!(value.state.as_str(), "prepared" | "committed")
        || value.expires_at == 0
    {
        return Err(Error::InvalidResponse(
            "invalid Put preparation identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_key_grant(value: &KeyGrant, preparation: &Preparation) -> Result<(), Error> {
    if value.schema != "skydriver.vfs.directory-key-grant.v1"
        || value.intent_id != preparation.intent_id
        || value.directory_id != preparation.directory_id
        || value.version_id != preparation.version_id
        || value.crypto_suite != preparation.crypto_suite
        || value.key_epoch != preparation.key_epoch
        || value.expires_at == 0
    {
        return Err(Error::InvalidResponse(
            "invalid directory-key grant".to_owned(),
        ));
    }
    Ok(())
}

fn validate_driver_grant(value: &DriverGrant, preparation: &Preparation) -> Result<(), Error> {
    if value.schema != "skydriver.vfs.driver-grant.v1"
        || value.intent_id != preparation.intent_id
        || value.driver_id != preparation.driver_id
        || value.driver_revision == 0
        || value.expires_at == 0
        || !value.config.is_object()
        || value
            .credential
            .as_ref()
            .is_some_and(|credential| !credential.is_object())
    {
        return Err(Error::InvalidResponse("invalid driver grant".to_owned()));
    }
    Ok(())
}

fn decode_directory_key(grant: &KeyGrant) -> Result<Option<[u8; 32]>, Error> {
    let Some(encoded) = grant.directory_key.as_deref() else {
        if grant.crypto_suite == "plaintext/v1" {
            return Ok(None);
        }
        return Err(Error::InvalidResponse(
            "encrypted key grant omitted key".to_owned(),
        ));
    };
    if grant.crypto_suite == "plaintext/v1" {
        return Err(Error::InvalidResponse(
            "plaintext grant exposed key".to_owned(),
        ));
    }
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidResponse("invalid directory key".to_owned()))?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        decoded.zeroize();
        return Err(Error::InvalidResponse("invalid directory key".to_owned()));
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(Some(key))
}

fn parse_identifier(value: &str) -> Result<[u8; 16], Error> {
    let decoded = skydriver_sdk_core::decode_lower_hex::<16>(value)
        .map_err(|_| Error::InvalidResponse("invalid VFS identifier".to_owned()))?;
    if decoded == [0; 16] {
        return Err(Error::InvalidResponse("invalid VFS identifier".to_owned()));
    }
    Ok(decoded)
}

fn validate_receipt(
    value: &PutReceipt,
    preparation: &Preparation,
    manifest: &ManifestStage,
    staged: &crate::crypto::StagedObject,
) -> Result<(), Error> {
    if value.schema != "skydriver.vfs.put-receipt.v1"
        || value.intent_id != preparation.intent_id
        || value.file_id != preparation.file_id
        || value.version_id != preparation.version_id
        || value.location_id != preparation.location_id
        || value.driver_id != preparation.driver_id
        || value.storage_key != preparation.storage_key
        || value.block_manifest_r2_version != manifest.r2_version
        || value.encoded_bytes != staged.encoded_bytes
        || value.encoded_sha256 != staged.encoded_sha256
        || value.verification_method != "complete_readback"
        || value.entry_revision == 0
        || value.catalog_revision_id == 0
        || value.committed_at == 0
        || value.state != "committed"
    {
        return Err(Error::InvalidResponse(
            "invalid Put receipt identity".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, time::Duration};

    use super::{
        BoundedRangeUploadSource, CancelSafeStage, Preparation, PutOptions, TransferTelemetry,
        run_source_worker, run_stage_worker, spool_bounded_reader, spool_exact_reader,
        spool_range_source, validate_preparation,
    };

    fn put_options(staging_directory: &std::path::Path) -> PutOptions {
        PutOptions {
            expected_entry_revision: 0,
            preferred_driver_id: None,
            idempotency_key: "test-put".to_owned(),
            verification_block_bytes: 4,
            encryption_frame_bytes: 4,
            staging_directory: staging_directory.to_owned(),
            transfer_part_bytes: 4,
            maximum_concurrency: 1,
        }
    }

    #[test]
    fn download_telemetry_is_a_complete_bounded_phase_partition() {
        let telemetry = TransferTelemetry::measured_download(
            Duration::from_millis(2),
            Duration::from_millis(3),
            Duration::from_millis(5),
            Duration::from_millis(7),
            Duration::from_millis(18),
        );
        let value = serde_json::to_value(telemetry).expect("serialize telemetry");
        assert_eq!(value["schema"], "skydriver.transfer-telemetry.v2");
        assert_eq!(value["plan_ms"], 2);
        assert_eq!(value["queue_ms"], 3);
        assert_eq!(value["provider_ms"], 5);
        assert_eq!(value["post_provider_ms"], 7);
        assert_eq!(value["total_ms"], 18);

        let legacy = serde_json::to_value(TransferTelemetry::measured(
            Duration::from_millis(5),
            Duration::from_millis(8),
        ))
        .expect("serialize legacy telemetry");
        assert_eq!(legacy["schema"], "skydriver.transfer-telemetry.v1");
        assert!(legacy.get("plan_ms").is_none());
        assert!(legacy.get("queue_ms").is_none());
        assert!(legacy.get("post_provider_ms").is_none());
    }

    fn valid_preparation() -> Preparation {
        Preparation {
            schema: "skydriver.vfs.put-preparation.v1".to_owned(),
            intent_id: "11111111111111111111111111111111".to_owned(),
            filesystem_id: "22222222222222222222222222222222".to_owned(),
            directory_id: "33333333333333333333333333333333".to_owned(),
            entry_name: "file".to_owned(),
            expected_entry_revision: 0,
            file_id: "44444444444444444444444444444444".to_owned(),
            version_id: "55555555555555555555555555555555".to_owned(),
            location_id: "66666666666666666666666666666666".to_owned(),
            driver_id: "r2-default".to_owned(),
            storage_key: "opaque-key".to_owned(),
            block_manifest_r2_key: "manifest-key".to_owned(),
            crypto_suite: "skydriver-vfs-aes256gcm-hkdfsha256-v1".to_owned(),
            key_epoch: 1,
            encryption_frame_bytes: 4,
            requires_encryption_key: true,
            state: "prepared".to_owned(),
            expires_at: 1,
        }
    }

    struct MemoryRanges {
        bytes: Vec<u8>,
        append_extra: bool,
    }

    impl BoundedRangeUploadSource for MemoryRanges {
        fn size_bytes(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn open_range(
            &self,
            offset: u64,
            length: u64,
        ) -> std::io::Result<Box<dyn std::io::Read + Send>> {
            let start = usize::try_from(offset).expect("range offset");
            let end = start + usize::try_from(length).expect("range length");
            let mut range = self.bytes[start..end].to_vec();
            if self.append_extra {
                range.push(0xff);
            }
            Ok(Box::new(Cursor::new(range)))
        }
    }

    #[test]
    fn put_preparation_requires_canonical_identifiers_and_suite() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let options = put_options(temporary.path());
        let preparation = valid_preparation();
        validate_preparation(
            &preparation,
            &preparation.directory_id,
            &preparation.entry_name,
            &options,
        )
        .expect("valid Put preparation");

        let mut traversal = valid_preparation();
        traversal.intent_id = "../intent/../../outside...........".to_owned();
        validate_preparation(
            &traversal,
            &traversal.directory_id,
            &traversal.entry_name,
            &options,
        )
        .expect_err("reject Put URL and staging path injection");

        let mut uppercase = valid_preparation();
        uppercase.version_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        validate_preparation(
            &uppercase,
            &uppercase.directory_id,
            &uppercase.entry_name,
            &options,
        )
        .expect_err("reject noncanonical Put identity");

        let mut unsupported = valid_preparation();
        unsupported.crypto_suite = "future/unknown".to_owned();
        let error = validate_preparation(
            &unsupported,
            &unsupported.directory_id,
            &unsupported.entry_name,
            &options,
        )
        .expect_err("reject unsupported Put suite");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::UnsupportedSuite)
        );
    }

    #[test]
    fn one_shot_spool_is_bounded_private_and_raii_cleaned() {
        let temporary = tempfile::tempdir().expect("source spool temporary directory");
        let spool = spool_bounded_reader(temporary.path(), Cursor::new(b"payload"), 7)
            .expect("spool bounded reader");
        let path = spool.path().expect("source spool path").to_owned();
        assert_eq!(std::fs::read(&path).expect("read source spool"), b"payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("source spool metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(spool);
        assert!(!path.exists());

        assert!(spool_bounded_reader(temporary.path(), Cursor::new(b"too long"), 3).is_err());
        assert_no_spool_files(temporary.path());
    }

    #[test]
    fn exact_and_range_sources_reject_short_or_additional_bytes() {
        let temporary = tempfile::tempdir().expect("source spool temporary directory");
        assert!(spool_exact_reader(temporary.path(), Cursor::new(b"short"), 6).is_err());
        assert!(spool_exact_reader(temporary.path(), Cursor::new(b"extra"), 4).is_err());

        let source = MemoryRanges {
            bytes: b"range-source".to_vec(),
            append_extra: false,
        };
        let spool = spool_range_source(temporary.path(), &source, 3).expect("spool range source");
        assert_eq!(
            std::fs::read(spool.path().expect("range spool path")).expect("read range spool"),
            b"range-source"
        );
        drop(spool);

        let overlong = MemoryRanges {
            bytes: b"range-source".to_vec(),
            append_extra: true,
        };
        assert!(spool_range_source(temporary.path(), &overlong, 3).is_err());
        assert_no_spool_files(temporary.path());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_source_worker_cleans_a_late_result() {
        let temporary = tempfile::tempdir().expect("source spool temporary directory");
        let staging = temporary.path().to_owned();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (spooled_tx, spooled_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            run_source_worker(move || {
                started_tx.send(()).expect("announce source worker");
                release_rx.recv().expect("release source worker");
                let spool = spool_bounded_reader(&staging, Cursor::new(b"late payload"), 12)?;
                spooled_tx.send(()).expect("announce completed spool");
                Ok(spool)
            })
            .await
        });
        started_rx.recv().expect("source worker started");
        task.abort();
        release_tx.send(()).expect("release cancelled worker");
        spooled_rx.recv().expect("cancelled worker completed spool");
        let joined = task.await;
        assert!(matches!(joined, Err(error) if error.is_cancelled()));

        for _ in 0..100 {
            if no_spool_files(temporary.path()) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_no_spool_files(temporary.path());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_stage_worker_removes_a_late_encoded_object() {
        let temporary = tempfile::tempdir().expect("encoded stage temporary directory");
        let path = temporary.path().join("late.encoded");
        let worker_path = path.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (staged_tx, staged_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            run_stage_worker(move || {
                started_tx.send(()).expect("announce stage worker");
                release_rx.recv().expect("release stage worker");
                std::fs::write(&worker_path, b"encoded").expect("write encoded stage");
                staged_tx.send(()).expect("announce completed stage");
                Ok(CancelSafeStage {
                    staged: Some(crate::crypto::StagedObject {
                        path: worker_path,
                        encoded_bytes: 7,
                        encoded_sha256: "11".repeat(32),
                    }),
                })
            })
            .await
        });
        started_rx.recv().expect("stage worker started");
        task.abort();
        release_tx.send(()).expect("release cancelled stage worker");
        staged_rx.recv().expect("cancelled worker completed stage");
        let joined = task.await;
        assert!(matches!(joined, Err(error) if error.is_cancelled()));

        for _ in 0..100 {
            if !path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!path.exists(), "late encoded stage was not removed");
    }

    fn assert_no_spool_files(root: &std::path::Path) {
        assert!(no_spool_files(root));
    }

    fn no_spool_files(root: &std::path::Path) -> bool {
        let directory = root.join("plaintext-sources");
        if !directory.exists() {
            return true;
        }
        std::fs::read_dir(directory)
            .expect("read plaintext source directory")
            .next()
            .is_none()
    }
}
