//! Immutable download planning, provider readback, decryption, and verification.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

use crate::{
    Error, VfsClient,
    crypto::{Descriptor, restore_to_staging},
    driver::{DownloadRequest, DriverRegistry},
    private_fs::ensure_private_directory,
    publication::VerifiedPublication,
    transfer::TransferTelemetry,
};

const VERIFIED_OUTPUT_COPY_BUFFER_BYTES: usize = 1024 * 1024;
const MAXIMUM_DOWNLOAD_PLAN_BODY_BYTES: usize = 256 * 1024;
static VERIFIED_OUTPUT_ORDINAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadLeaseCompletion {
    read_lease_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    telemetry: Option<TransferTelemetry>,
}

impl ReadLeaseCompletion {
    pub(crate) fn include_publication(&mut self, elapsed: Duration) {
        if let Some(telemetry) = self.telemetry.as_mut() {
            telemetry.add_post_provider(elapsed);
        }
    }
}

#[derive(Serialize)]
struct CompletionRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    telemetry: Option<&'a TransferTelemetry>,
}

#[derive(Serialize)]
struct CompletionBatchRequest<'a> {
    schema: &'static str,
    completions: &'a [ReadLeaseCompletion],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionBatchResponse {
    schema: String,
    completed_at: u64,
    results: Vec<CompletionBatchResult>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionBatchResult {
    read_lease_id: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadPlan {
    schema: String,
    filesystem_id: String,
    directory_id: String,
    file_id: String,
    version_id: String,
    plaintext_bytes: u64,
    verification_block_bytes: u64,
    verification_block_count: u64,
    file_root: String,
    metadata_root: String,
    block_manifest_sha256: String,
    block_manifest_bytes: u64,
    block_manifest_r2_key: String,
    block_manifest_r2_version: String,
    crypto_suite: String,
    key_epoch: u64,
    encryption_frame_bytes: u64,
    encoded_bytes: u64,
    encoded_sha256: String,
    location_id: String,
    driver_id: String,
    storage_key: String,
    native_id: Option<String>,
    provider_version: Option<String>,
    etag: Option<String>,
    driver_kind: String,
    driver_revision: u64,
    config: Value,
    credential: Option<Value>,
    directory_key: Option<String>,
    read_lease_id: String,
    expires_at: u64,
}

impl Drop for DownloadPlan {
    fn drop(&mut self) {
        if let Some(directory_key) = self.directory_key.as_mut() {
            directory_key.zeroize();
        }
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

pub(crate) struct PreparedDownload {
    plan: DownloadPlan,
    transfer_started: Instant,
    plan_elapsed: Duration,
    plan_completed_at: Instant,
}

#[derive(Clone, Copy)]
struct DownloadPhases {
    queue: Duration,
    provider: Duration,
    post_provider: Duration,
}

/// Verified native file download result.
#[derive(Clone, Debug, Serialize)]
pub struct GetResult {
    /// Stable output schema.
    pub schema: &'static str,
    /// Requested absolute VFS path.
    pub path: String,
    /// Immutable version downloaded.
    pub version_id: String,
    /// Plaintext bytes written.
    pub plaintext_bytes: u64,
    /// Verified plaintext Merkle root.
    pub file_root: String,
    /// Plaintext Merkle verification block size.
    pub verification_block_bytes: u64,
    /// Driver that served the complete encoded object.
    pub driver_id: String,
    /// Correctness-preserving capability degradations.
    pub warnings: Vec<String>,
}

/// Verified in-memory complete-file download.
pub struct GetBytesResult {
    /// Transfer and integrity receipt.
    pub transfer: GetResult,
    /// Complete verified plaintext bytes.
    pub bytes: Vec<u8>,
}

/// Hidden resumable provider pipeline settings for one file download.
pub struct GetOptions {
    /// Private absolute encoded-download staging directory.
    pub staging_directory: PathBuf,
    /// Provider range segment bytes.
    pub transfer_part_bytes: u64,
    /// Maximum provider range operations in flight.
    pub maximum_concurrency: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct DownloadExpectation<'a> {
    file_id: &'a str,
    version_id: &'a str,
    plaintext_bytes: u64,
    file_root: &'a str,
}

impl<'a> DownloadExpectation<'a> {
    pub(crate) fn new(
        file_id: &'a str,
        version_id: &'a str,
        plaintext_bytes: u64,
        file_root: &'a str,
    ) -> Self {
        Self {
            file_id,
            version_id,
            plaintext_bytes,
            file_root,
        }
    }
}

impl VfsClient {
    /// Downloads, decrypts, and verifies one complete immutable file.
    ///
    /// # Errors
    ///
    /// Fails without publishing the destination on authorization, provider,
    /// encoded checksum, AEAD authentication, or plaintext Merkle divergence.
    pub async fn get_file(
        &self,
        vfs_path: &str,
        destination: &Path,
        options: &GetOptions,
    ) -> Result<GetResult, Error> {
        validate_options(options)?;
        let resolved = resolve_file_download(self, vfs_path).await?;
        self.get_file_version(vfs_path, resolved.expectation(), destination, options)
            .await
    }

    /// Downloads and verifies one complete file before returning its bytes.
    ///
    /// The declared maximum is checked before provider I/O and bounds the
    /// returned allocation. Plaintext is never returned before its Merkle root
    /// and exact length have been verified.
    ///
    /// # Errors
    ///
    /// Fails when the immutable file exceeds `maximum_bytes`, download or
    /// verification fails, or the private verified-output spool cannot be read.
    pub async fn get_bytes(
        &self,
        vfs_path: &str,
        maximum_bytes: u64,
        options: &GetOptions,
    ) -> Result<GetBytesResult, Error> {
        validate_options(options)?;
        validate_output_maximum(maximum_bytes)?;
        let resolved = resolve_file_download(self, vfs_path).await?;
        validate_output_bound(resolved.plaintext_bytes, maximum_bytes)?;
        let spool = VerifiedOutputSpool::new(&options.staging_directory)?;
        let transfer = self
            .get_file_version(vfs_path, resolved.expectation(), spool.path(), options)
            .await?;
        let mut bytes =
            Vec::with_capacity(usize::try_from(transfer.plaintext_bytes).map_err(|_| {
                Error::InvalidResponse("verified output exceeds this platform".to_owned())
            })?);
        copy_verified_output(&spool, &mut bytes, transfer.plaintext_bytes, maximum_bytes)?;
        Ok(GetBytesResult { transfer, bytes })
    }

    /// Downloads and verifies one complete file before writing it to `writer`.
    ///
    /// No bytes are emitted until the private plaintext spool has passed exact
    /// length and Merkle-root verification. The synchronous writer is consumed
    /// inline after verification so cancellation cannot leave a detached worker
    /// mutating it after this future returns.
    ///
    /// # Errors
    ///
    /// Fails before provider I/O when the immutable file exceeds
    /// `maximum_bytes`, or when download, verification, or writer I/O fails.
    pub async fn get_writer<W: Write>(
        &self,
        vfs_path: &str,
        mut writer: W,
        maximum_bytes: u64,
        options: &GetOptions,
    ) -> Result<(GetResult, W), Error> {
        validate_options(options)?;
        validate_output_maximum(maximum_bytes)?;
        let resolved = resolve_file_download(self, vfs_path).await?;
        validate_output_bound(resolved.plaintext_bytes, maximum_bytes)?;
        let spool = VerifiedOutputSpool::new(&options.staging_directory)?;
        let transfer = self
            .get_file_version(vfs_path, resolved.expectation(), spool.path(), options)
            .await?;
        copy_verified_output(&spool, &mut writer, transfer.plaintext_bytes, maximum_bytes)?;
        Ok((transfer, writer))
    }

    pub(crate) async fn get_file_version(
        &self,
        vfs_path: &str,
        expected: DownloadExpectation<'_>,
        destination: &Path,
        options: &GetOptions,
    ) -> Result<GetResult, Error> {
        let prepared = self.prepare_file_version(expected).await?;
        self.finish_prepared_file(vfs_path, prepared, destination, options, false)
            .await
            .map(|(result, _, _)| result)
    }

    pub(crate) async fn prepare_file_version(
        &self,
        expected: DownloadExpectation<'_>,
    ) -> Result<PreparedDownload, Error> {
        let transfer_started = Instant::now();
        let token = self.token.encode();
        let plan: DownloadPlan = self
            .control
            .send_json_bounded::<DownloadPlan, ()>(
                Method::GET,
                &format!("api/v2/versions/{}/download", expected.version_id),
                Some(&token),
                &[],
                None,
                MAXIMUM_DOWNLOAD_PLAN_BODY_BYTES,
            )
            .await?;
        validate_plan(&plan, expected)?;
        let plan_completed_at = Instant::now();
        Ok(PreparedDownload {
            plan,
            transfer_started,
            plan_elapsed: plan_completed_at.duration_since(transfer_started),
            plan_completed_at,
        })
    }

    pub(crate) async fn finish_prepared_file(
        &self,
        vfs_path: &str,
        mut prepared: PreparedDownload,
        destination: &Path,
        options: &GetOptions,
        defer_successful_completion: bool,
    ) -> Result<
        (
            GetResult,
            Option<ReadLeaseCompletion>,
            Option<VerifiedPublication>,
        ),
        Error,
    > {
        validate_options(options)?;
        let _staging_lock =
            acquire_download_staging_lock(&options.staging_directory, &prepared.plan.version_id)
                .await?;
        let token = self.token.encode();
        let outcome = self
            .finish_download(
                vfs_path,
                destination,
                options,
                &mut prepared.plan,
                prepared.plan_completed_at,
                defer_successful_completion,
            )
            .await;
        let completion = ReadLeaseCompletion {
            read_lease_id: prepared.plan.read_lease_id.clone(),
            telemetry: outcome.as_ref().ok().map(|(_, phases, _)| {
                TransferTelemetry::measured_download(
                    prepared.plan_elapsed,
                    phases.queue,
                    phases.provider,
                    phases.post_provider,
                    prepared.transfer_started.elapsed(),
                )
            }),
        };
        match outcome {
            Ok((result, _, publication)) if defer_successful_completion => {
                Ok((result, Some(completion), publication))
            }
            Ok((mut result, _, publication)) => {
                debug_assert!(publication.is_none());
                if let Err(error) = self.complete_read_lease(&token, &completion).await {
                    result.warnings.push(format!(
                        "The verified file was published, but read-lease completion will rely on expiry: {error}"
                    ));
                }
                Ok((result, None, None))
            }
            Err(error) => {
                let _ = self.complete_read_lease(&token, &completion).await;
                Err(error)
            }
        }
    }

    async fn complete_read_lease(
        &self,
        token: &str,
        completion: &ReadLeaseCompletion,
    ) -> Result<(), Error> {
        self.control
            .send_json::<Value, CompletionRequest<'_>>(
                Method::POST,
                &format!("api/v2/read-leases/{}/complete", completion.read_lease_id),
                Some(token),
                &[],
                Some(&CompletionRequest {
                    telemetry: completion.telemetry.as_ref(),
                }),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn complete_read_leases(
        &self,
        completions: &[ReadLeaseCompletion],
    ) -> Result<(), Error> {
        let token = self.token.encode();
        let batched = self
            .control
            .send_json::<CompletionBatchResponse, CompletionBatchRequest<'_>>(
                Method::POST,
                "api/v2/read-leases/complete-batch",
                Some(&token),
                &[],
                Some(&CompletionBatchRequest {
                    schema: "carrack.vfs.read-lease-completion-batch.v1",
                    completions,
                }),
            )
            .await;
        if let Ok(response) = batched {
            let valid = response.schema == "carrack.vfs.read-lease-completion-batch.v1"
                && response.completed_at != 0
                && response.results.len() == completions.len()
                && response
                    .results
                    .iter()
                    .zip(completions)
                    .all(|(result, expected)| {
                        result.read_lease_id == expected.read_lease_id
                            && result.status == "completed"
                    });
            if valid {
                return Ok(());
            }
        }
        // Rolling upgrades and transient batch failures retain the original
        // idempotent endpoint as a correctness-neutral fallback.
        let mut failed = 0_usize;
        for completion in completions {
            if self.complete_read_lease(&token, completion).await.is_err() {
                failed += 1;
            }
        }
        if failed == 0 {
            Ok(())
        } else {
            Err(Error::InvalidResponse(format!(
                "{failed} read leases could not be completed and will rely on expiry"
            )))
        }
    }

    async fn finish_download(
        &self,
        vfs_path: &str,
        destination: &Path,
        options: &GetOptions,
        plan: &mut DownloadPlan,
        plan_completed_at: Instant,
        defer_publication: bool,
    ) -> Result<(GetResult, DownloadPhases, Option<VerifiedPublication>), Error> {
        let provider_started = Instant::now();
        let queue = provider_started.duration_since(plan_completed_at);
        let mut opened_driver = DriverRegistry::open(
            &plan.driver_kind,
            std::mem::take(&mut plan.config),
            plan.credential.take(),
        )?;
        let encoded = opened_driver
            .download(DownloadRequest {
                http: &self.control.http,
                storage_key: &plan.storage_key,
                native_id: plan.native_id.as_deref(),
                staging_directory: &options.staging_directory,
                version_id: &plan.version_id,
                encoded_bytes: plan.encoded_bytes,
                encoded_sha256: &plan.encoded_sha256,
                part_bytes: options.transfer_part_bytes,
                maximum_concurrency: options.maximum_concurrency,
            })
            .await?;
        let provider_elapsed = provider_started.elapsed();
        let post_provider_started = Instant::now();
        let mut directory_key = decode_directory_key(plan)?;
        let descriptor = Descriptor {
            directory_id: parse_identifier(&plan.directory_id)?,
            version_id: parse_identifier(&plan.version_id)?,
            key_epoch: plan.key_epoch,
            frame_bytes: plan.encryption_frame_bytes,
            plaintext_bytes: plan.plaintext_bytes,
        };
        let parent = destination.parent().ok_or_else(|| {
            Error::InvalidResponse("download destination has no parent".to_owned())
        })?;
        let plaintext_staging = restore_to_staging(
            &encoded,
            parent,
            &plan.crypto_suite,
            &descriptor,
            directory_key.as_ref(),
        );
        if let Some(key) = directory_key.as_mut() {
            key.zeroize();
        }
        let plaintext_staging = plaintext_staging?;
        let publication = VerifiedPublication::open(
            &plaintext_staging,
            plan.verification_block_bytes,
            plan.plaintext_bytes,
            &plan.file_root,
        )?;
        let (mut warnings, publication) = if defer_publication {
            (Vec::new(), Some(publication))
        } else {
            (publication.publish_no_replace(destination)?, None)
        };
        warnings.extend(opened_driver.download_warnings(options.maximum_concurrency));
        if let Err(error) = std::fs::remove_file(&encoded) {
            warnings.push(format!(
                "The verified file was published, but encoded staging cleanup was deferred: {error}"
            ));
        }
        Ok((
            GetResult {
                schema: "carrack.fs-get.v1",
                path: vfs_path.to_owned(),
                version_id: plan.version_id.clone(),
                plaintext_bytes: plan.plaintext_bytes,
                file_root: plan.file_root.clone(),
                verification_block_bytes: plan.verification_block_bytes,
                driver_id: plan.driver_id.clone(),
                warnings,
            },
            DownloadPhases {
                queue,
                provider: provider_elapsed,
                post_provider: post_provider_started.elapsed(),
            },
            publication,
        ))
    }
}

struct DownloadStagingLock {
    _file: File,
}

async fn acquire_download_staging_lock(
    staging_root: &Path,
    version_id: &str,
) -> Result<DownloadStagingLock, Error> {
    let staging_root = staging_root.to_owned();
    let version_id = version_id.to_owned();
    tokio::task::spawn_blocking(move || {
        acquire_download_staging_lock_blocking(&staging_root, &version_id)
    })
    .await
    .map_err(|error| {
        Error::InvalidResponse(format!("download staging lock worker failed: {error}"))
    })?
}

fn acquire_download_staging_lock_blocking(
    staging_root: &Path,
    version_id: &str,
) -> Result<DownloadStagingLock, Error> {
    let _ = parse_identifier(version_id)?;
    ensure_private_directory(staging_root, "download staging root")?;
    let file = File::open(staging_root)
        .map_err(|error| Error::InvalidResponse(format!("open download staging lock: {error}")))?;
    fs2::FileExt::lock_exclusive(&file)
        .map_err(|error| Error::InvalidResponse(format!("lock download staging: {error}")))?;
    Ok(DownloadStagingLock { _file: file })
}

struct ResolvedFileDownload {
    file_id: String,
    version_id: String,
    plaintext_bytes: u64,
    file_root: String,
}

impl ResolvedFileDownload {
    fn expectation(&self) -> DownloadExpectation<'_> {
        DownloadExpectation::new(
            &self.file_id,
            &self.version_id,
            self.plaintext_bytes,
            &self.file_root,
        )
    }
}

async fn resolve_file_download(
    client: &VfsClient,
    vfs_path: &str,
) -> Result<ResolvedFileDownload, Error> {
    let resolved = client.resolve(vfs_path).await?;
    let entry = resolved
        .entry
        .ok_or_else(|| Error::InvalidResponse("cannot download the VFS root".to_owned()))?;
    if entry.kind != crate::EntryKind::File {
        return Err(Error::InvalidResponse(
            "download target is not a file".to_owned(),
        ));
    }
    Ok(ResolvedFileDownload {
        file_id: entry
            .file_id
            .ok_or_else(|| Error::InvalidResponse("file entry omitted file identity".to_owned()))?,
        version_id: entry.version_id.ok_or_else(|| {
            Error::InvalidResponse("file entry omitted version identity".to_owned())
        })?,
        plaintext_bytes: entry.size_bytes,
        file_root: entry.data_root,
    })
}

struct VerifiedOutputSpool {
    directory: PathBuf,
    path: PathBuf,
}

impl VerifiedOutputSpool {
    fn new(staging_root: &Path) -> Result<Self, Error> {
        let root = staging_root.join("verified-outputs");
        ensure_private_directory(&root, "verified output root")?;
        loop {
            let ordinal = VERIFIED_OUTPUT_ORDINAL.fetch_add(1, Ordering::Relaxed);
            let directory = root.join(format!(".output-{}-{ordinal:016x}", std::process::id()));
            match std::fs::create_dir(&directory) {
                Ok(()) => {
                    let spool = Self {
                        path: directory.join("plaintext"),
                        directory,
                    };
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(
                            &spool.directory,
                            std::fs::Permissions::from_mode(0o700),
                        )
                        .map_err(|error| {
                            Error::InvalidResponse(format!(
                                "protect verified output directory: {error}"
                            ))
                        })?;
                    }
                    return Ok(spool);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(Error::InvalidResponse(format!(
                        "create verified output directory: {error}"
                    )));
                }
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VerifiedOutputSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn validate_output_bound(plaintext_bytes: u64, maximum_bytes: u64) -> Result<(), Error> {
    validate_output_maximum(maximum_bytes)?;
    if plaintext_bytes > maximum_bytes {
        return Err(Error::InvalidResponse(
            "download exceeds the declared output byte bound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_output_maximum(maximum_bytes: u64) -> Result<(), Error> {
    if maximum_bytes == 0 {
        return Err(Error::InvalidResponse(
            "download output maximum bytes must be nonzero".to_owned(),
        ));
    }
    Ok(())
}

fn copy_verified_output<W: Write>(
    spool: &VerifiedOutputSpool,
    writer: &mut W,
    expected_bytes: u64,
    maximum_bytes: u64,
) -> Result<(), Error> {
    validate_output_bound(expected_bytes, maximum_bytes)?;
    let mut input = std::fs::File::open(spool.path())
        .map_err(|error| Error::InvalidResponse(format!("open verified output: {error}")))?;
    let observed_bytes = input
        .metadata()
        .map_err(|error| Error::InvalidResponse(format!("inspect verified output: {error}")))?
        .len();
    if observed_bytes != expected_bytes {
        return Err(Error::failure(
            crate::FailureKind::CorruptPlaintext,
            "verified output length changed before emission",
        ));
    }
    let mut buffer = vec![0_u8; VERIFIED_OUTPUT_COPY_BUFFER_BYTES];
    let mut copied = 0_u64;
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| Error::InvalidResponse(format!("read verified output: {error}")))?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| Error::InvalidResponse("verified output size overflow".to_owned()))?;
        if copied > expected_bytes {
            return Err(Error::failure(
                crate::FailureKind::CorruptPlaintext,
                "verified output grew before emission completed",
            ));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| Error::InvalidResponse(format!("write verified output: {error}")))?;
    }
    if copied != expected_bytes {
        return Err(Error::failure(
            crate::FailureKind::CorruptPlaintext,
            "verified output changed before emission completed",
        ));
    }
    writer
        .flush()
        .map_err(|error| Error::InvalidResponse(format!("flush verified output: {error}")))
}

#[cfg(test)]
fn verify_and_publish_plaintext(
    staging: &Path,
    destination: &Path,
    verification_block_bytes: u64,
    plaintext_bytes: u64,
    file_root: &str,
) -> Result<Vec<String>, Error> {
    VerifiedPublication::open(
        staging,
        verification_block_bytes,
        plaintext_bytes,
        file_root,
    )?
    .publish_no_replace(destination)
}

fn validate_plan(plan: &DownloadPlan, expected: DownloadExpectation<'_>) -> Result<(), Error> {
    for identifier in [
        plan.filesystem_id.as_str(),
        plan.directory_id.as_str(),
        plan.file_id.as_str(),
        plan.version_id.as_str(),
        plan.location_id.as_str(),
        plan.read_lease_id.as_str(),
    ] {
        parse_identifier(identifier)
            .map_err(|_| Error::InvalidResponse("invalid download plan identity".to_owned()))?;
    }
    for digest in [
        plan.file_root.as_str(),
        plan.metadata_root.as_str(),
        plan.block_manifest_sha256.as_str(),
        plan.encoded_sha256.as_str(),
    ] {
        parse_digest(digest)
            .map_err(|_| Error::InvalidResponse("invalid download plan digest".to_owned()))?;
    }
    if !matches!(
        plan.crypto_suite.as_str(),
        "plaintext/v1" | "carrack-vfs-aes256gcm-hkdfsha256-v1"
    ) {
        return Err(Error::failure(
            crate::FailureKind::UnsupportedSuite,
            format!("unsupported download crypto suite {}", plan.crypto_suite),
        ));
    }
    let mut validated_key = decode_directory_key(plan)?;
    if let Some(key) = validated_key.as_mut() {
        key.zeroize();
    }
    let _ = (
        plan.block_manifest_bytes,
        &plan.native_id,
        &plan.provider_version,
        &plan.etag,
    );
    if plan.schema != "carrack.vfs.download-plan.v1"
        || expected.version_id != plan.version_id
        || expected.file_id != plan.file_id
        || expected.plaintext_bytes != plan.plaintext_bytes
        || expected.file_root != plan.file_root
        || plan.verification_block_bytes == 0
        || plan.verification_block_bytes > 256 * 1024 * 1024
        || plan.verification_block_count
            != if plan.plaintext_bytes == 0 {
                0
            } else {
                1 + (plan.plaintext_bytes - 1) / plan.verification_block_bytes
            }
        || plan.key_epoch == 0
        || plan.encryption_frame_bytes == 0
        || plan.encryption_frame_bytes > plan.verification_block_bytes
        || !plan
            .verification_block_bytes
            .is_multiple_of(plan.encryption_frame_bytes)
        || plan.block_manifest_bytes == 0
        || plan.driver_id.is_empty()
        || plan.driver_kind.is_empty()
        || plan.driver_revision == 0
        || plan.storage_key.is_empty()
        || plan.block_manifest_r2_key.is_empty()
        || plan.block_manifest_r2_version.is_empty()
        || plan.expires_at == 0
        || !plan.config.is_object()
        || plan
            .credential
            .as_ref()
            .is_some_and(|value| !value.is_object())
    {
        return Err(Error::InvalidResponse(
            "invalid download plan identity".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn verify_plaintext_identity(
    observed_bytes: u64,
    observed_root: &str,
    expected_bytes: u64,
    expected_root: &str,
) -> Result<(), Error> {
    if observed_bytes != expected_bytes || observed_root != expected_root {
        return Err(Error::failure(
            crate::FailureKind::CorruptPlaintext,
            "downloaded plaintext Merkle root differs",
        ));
    }
    Ok(())
}

fn validate_options(options: &GetOptions) -> Result<(), Error> {
    if !options.staging_directory.is_absolute()
        || options.transfer_part_bytes == 0
        || options.transfer_part_bytes > 256 * 1024 * 1024
        || options.maximum_concurrency == 0
        || options.maximum_concurrency > 64
    {
        return Err(Error::InvalidResponse(
            "invalid download pipeline options".to_owned(),
        ));
    }
    Ok(())
}

fn decode_directory_key(plan: &DownloadPlan) -> Result<Option<[u8; 32]>, Error> {
    let Some(encoded) = plan.directory_key.as_deref() else {
        if plan.crypto_suite == "plaintext/v1" {
            return Ok(None);
        }
        return Err(Error::InvalidResponse(
            "encrypted download omitted key".to_owned(),
        ));
    };
    if plan.crypto_suite == "plaintext/v1" {
        return Err(Error::InvalidResponse(
            "plaintext download exposed key".to_owned(),
        ));
    }
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::InvalidResponse("invalid download key".to_owned()))?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        decoded.zeroize();
        return Err(Error::InvalidResponse("invalid download key".to_owned()));
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

fn parse_digest(value: &str) -> Result<[u8; 32], Error> {
    skydriver_sdk_core::decode_lower_hex::<32>(value)
        .map_err(|_| Error::InvalidResponse("invalid SHA-256 digest".to_owned()))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use httpmock::{Method::POST, MockServer};
    use serde_json::json;
    use skydriver_driver_contract::DriverKind;

    use super::{
        DownloadExpectation, DownloadPlan, ReadLeaseCompletion, VerifiedOutputSpool,
        acquire_download_staging_lock_blocking, copy_verified_output, validate_plan,
        verify_and_publish_plaintext, verify_plaintext_identity,
    };
    use crate::{VfsClient, VfsToken, publication::VerifiedPublication};

    fn verified(path: &std::path::Path, payload: &[u8]) -> VerifiedPublication {
        let root =
            hex::encode(skydriver_sdk_core::file_merkle_root(payload, 4).expect("plaintext root"));
        VerifiedPublication::open(path, 4, payload.len() as u64, &root)
            .expect("verified publication")
    }

    fn client(server: &MockServer) -> VfsClient {
        VfsClient::new(
            &format!("{}/", server.base_url()),
            VfsToken::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32])).expect("VFS token"),
        )
        .expect("VFS client")
    }

    fn completion(id: &str) -> ReadLeaseCompletion {
        ReadLeaseCompletion {
            read_lease_id: id.to_owned(),
            telemetry: None,
        }
    }

    fn valid_plan() -> DownloadPlan {
        DownloadPlan {
            schema: "carrack.vfs.download-plan.v1".to_owned(),
            filesystem_id: "11111111111111111111111111111111".to_owned(),
            directory_id: "22222222222222222222222222222222".to_owned(),
            file_id: "33333333333333333333333333333333".to_owned(),
            version_id: "44444444444444444444444444444444".to_owned(),
            plaintext_bytes: 0,
            verification_block_bytes: 4,
            verification_block_count: 0,
            file_root: "11".repeat(32),
            metadata_root: "22".repeat(32),
            block_manifest_sha256: "33".repeat(32),
            block_manifest_bytes: 1,
            block_manifest_r2_key: "manifest-key".to_owned(),
            block_manifest_r2_version: "manifest-version".to_owned(),
            crypto_suite: "carrack-vfs-aes256gcm-hkdfsha256-v1".to_owned(),
            key_epoch: 1,
            encryption_frame_bytes: 4,
            encoded_bytes: 0,
            encoded_sha256: "44".repeat(32),
            location_id: "55555555555555555555555555555555".to_owned(),
            driver_id: "r2-default".to_owned(),
            storage_key: "opaque-key".to_owned(),
            native_id: Some("native".to_owned()),
            provider_version: Some("provider-version".to_owned()),
            etag: Some("etag".to_owned()),
            driver_kind: DriverKind::R2V1.as_str().to_owned(),
            driver_revision: 1,
            config: json!({}),
            credential: Some(json!({})),
            directory_key: Some(URL_SAFE_NO_PAD.encode([7_u8; 32])),
            read_lease_id: "66666666666666666666666666666666".to_owned(),
            expires_at: 1,
        }
    }

    fn expectation(plan: &DownloadPlan) -> DownloadExpectation<'_> {
        DownloadExpectation::new(
            &plan.file_id,
            &plan.version_id,
            plan.plaintext_bytes,
            &plan.file_root,
        )
    }

    #[test]
    fn distinguishes_plaintext_merkle_divergence() {
        let error = verify_plaintext_identity(3, "observed", 3, "expected")
            .expect_err("reject plaintext divergence");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::CorruptPlaintext)
        );
        assert!(verify_plaintext_identity(3, "expected", 3, "expected").is_ok());
    }

    #[tokio::test]
    async fn read_lease_completion_uses_one_bounded_batch() {
        let server = MockServer::start_async().await;
        let first = "11111111111111111111111111111111";
        let second = "22222222222222222222222222222222";
        let batch = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/api/v2/read-leases/complete-batch")
                    .json_body(json!({
                        "schema": "carrack.vfs.read-lease-completion-batch.v1",
                        "completions": [
                            {"read_lease_id": first},
                            {"read_lease_id": second}
                        ]
                    }));
                then.status(200).json_body(json!({
                    "schema": "carrack.vfs.read-lease-completion-batch.v1",
                    "completed_at": 1,
                    "results": [
                        {"read_lease_id": first, "status": "completed"},
                        {"read_lease_id": second, "status": "completed"}
                    ]
                }));
            })
            .await;
        client(&server)
            .complete_read_leases(&[completion(first), completion(second)])
            .await
            .expect("complete batch");
        batch.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn read_lease_completion_falls_back_to_individual_endpoint() {
        let server = MockServer::start_async().await;
        let first = "11111111111111111111111111111111";
        let second = "22222222222222222222222222222222";
        let batch = server
            .mock_async(|when, then| {
                when.method(POST).path("/api/v2/read-leases/complete-batch");
                then.status(404).body("not deployed");
            })
            .await;
        let first_release = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/api/v2/read-leases/{first}/complete"))
                    .json_body(json!({}));
                then.status(200).json_body(json!({"completed": true}));
            })
            .await;
        let second_release = server
            .mock_async(|when, then| {
                when.method(POST)
                    .path(format!("/api/v2/read-leases/{second}/complete"))
                    .json_body(json!({}));
                then.status(200).json_body(json!({"completed": true}));
            })
            .await;
        client(&server)
            .complete_read_leases(&[completion(first), completion(second)])
            .await
            .expect("single-endpoint fallback");
        batch.assert_calls_async(1).await;
        first_release.assert_calls_async(1).await;
        second_release.assert_calls_async(1).await;
    }

    #[test]
    fn download_plan_rejects_noncanonical_identity_before_transfer() {
        let plan = valid_plan();
        validate_plan(&plan, expectation(&plan)).expect("valid download plan");

        let mut traversal = valid_plan();
        traversal.read_lease_id = "../lease/../../outside............".to_owned();
        validate_plan(&traversal, expectation(&traversal)).expect_err("reject URL path injection");

        let mut uppercase = valid_plan();
        uppercase.location_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        validate_plan(&uppercase, expectation(&uppercase))
            .expect_err("reject noncanonical uppercase identity");

        let mut malformed_digest = valid_plan();
        malformed_digest.encoded_sha256 = "z".repeat(64);
        validate_plan(&malformed_digest, expectation(&malformed_digest))
            .expect_err("reject malformed encoded digest");

        let mut oversized_block = valid_plan();
        oversized_block.verification_block_bytes = 256 * 1024 * 1024 + 1;
        validate_plan(&oversized_block, expectation(&oversized_block))
            .expect_err("reject oversized verification allocation");
    }

    #[test]
    fn download_plan_rejects_crypto_mismatch_before_transfer() {
        let mut unsupported = valid_plan();
        unsupported.crypto_suite = "future/unknown".to_owned();
        let error = validate_plan(&unsupported, expectation(&unsupported))
            .expect_err("reject unsupported suite");
        assert_eq!(
            error.failure_kind(),
            Some(crate::FailureKind::UnsupportedSuite)
        );

        let mut plaintext_with_key = valid_plan();
        plaintext_with_key.crypto_suite = "plaintext/v1".to_owned();
        validate_plan(&plaintext_with_key, expectation(&plaintext_with_key))
            .expect_err("reject plaintext key exposure");

        let mut encrypted_without_key = valid_plan();
        encrypted_without_key.directory_key = None;
        validate_plan(&encrypted_without_key, expectation(&encrypted_without_key))
            .expect_err("reject missing encrypted key");
    }

    #[test]
    fn shared_download_staging_root_is_serialized_without_residue() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let version_id = "44444444444444444444444444444444";
        let first = acquire_download_staging_lock_blocking(temporary.path(), version_id)
            .expect("first staging lock");
        let root = temporary.path().to_owned();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).expect("announce lock waiter");
            let lock = acquire_download_staging_lock_blocking(&root, version_id)
                .expect("second staging lock");
            acquired_tx.send(lock).expect("announce acquired lock");
        });
        started_rx.recv().expect("lock waiter started");
        assert!(
            acquired_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "same-version staging lock did not serialize"
        );
        drop(first);
        let second = acquired_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("second staging lock acquired after release");
        drop(second);
        waiter.join().expect("lock waiter");

        assert!(
            std::fs::read_dir(temporary.path())
                .expect("read staging root")
                .next()
                .is_none(),
            "staging fence left local metadata"
        );
    }

    #[test]
    fn merkle_failure_never_publishes_plaintext() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let staging = directory.path().join("staging");
        let destination = directory.path().join("destination");
        std::fs::write(&staging, b"untrusted").expect("write plaintext staging");

        verify_and_publish_plaintext(&staging, &destination, 4, 9, &"00".repeat(32))
            .expect_err("reject plaintext Merkle divergence");

        assert!(!staging.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn no_replace_publication_preserves_existing_destination() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let staging = directory.path().join("staging");
        let destination = directory.path().join("destination");
        std::fs::write(&staging, b"new").expect("write plaintext staging");
        std::fs::write(&destination, b"old").expect("write existing destination");

        verified(&staging, b"new")
            .publish_no_replace(&destination)
            .expect_err("reject replacement");

        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"old"
        );
    }

    #[test]
    fn no_replace_publication_has_one_atomic_winner_under_race() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = directory.path().join("first-staging");
        let second = directory.path().join("second-staging");
        let destination = directory.path().join("destination");
        std::fs::write(&first, b"first").expect("write first staging");
        std::fs::write(&second, b"second").expect("write second staging");
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let first_publish = scope.spawn(|| {
                barrier.wait();
                verified(&first, b"first").publish_no_replace(&destination)
            });
            let second_publish = scope.spawn(|| {
                barrier.wait();
                verified(&second, b"second").publish_no_replace(&destination)
            });
            [
                first_publish.join().expect("first publisher"),
                second_publish.join().expect("second publisher"),
            ]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(matches!(
            std::fs::read(destination)
                .expect("read atomic winner")
                .as_slice(),
            b"first" | b"second"
        ));
    }

    #[test]
    fn verified_output_is_private_bounded_and_raii_cleaned() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let spool = VerifiedOutputSpool::new(temporary.path()).expect("verified output spool");
        let directory = spool.directory.clone();
        std::fs::write(spool.path(), b"verified").expect("write verified output");
        let mut writer = Cursor::new(Vec::new());
        copy_verified_output(&spool, &mut writer, 8, 8).expect("copy verified output");
        assert_eq!(writer.into_inner(), b"verified");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&directory)
                    .expect("verified output directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        drop(spool);
        assert!(!directory.exists());
    }

    #[test]
    fn verified_output_bound_fails_before_writer_emission() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let spool = VerifiedOutputSpool::new(temporary.path()).expect("verified output spool");
        std::fs::write(spool.path(), b"verified").expect("write verified output");
        let mut writer = Cursor::new(Vec::new());
        copy_verified_output(&spool, &mut writer, 8, 7).expect_err("reject output above bound");
        assert!(writer.into_inner().is_empty());
    }
}
