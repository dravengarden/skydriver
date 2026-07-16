//! Immutable download planning, provider readback, decryption, and verification.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroize;

use crate::{
    Error, VfsClient,
    crypto::{Descriptor, restore_to_staging},
    driver::{DownloadRequest, DriverRegistry},
    integrity,
    transfer::TransferTelemetry,
};

#[derive(Serialize)]
struct CompletionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    telemetry: Option<TransferTelemetry>,
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
        let resolved = self.resolve(vfs_path).await?;
        let entry = resolved
            .entry
            .ok_or_else(|| Error::InvalidResponse("cannot download the VFS root".to_owned()))?;
        if entry.kind != crate::EntryKind::File {
            return Err(Error::InvalidResponse(
                "download target is not a file".to_owned(),
            ));
        }
        let file_id = entry
            .file_id
            .as_deref()
            .ok_or_else(|| Error::InvalidResponse("file entry omitted file identity".to_owned()))?;
        let version_id = entry.version_id.as_deref().ok_or_else(|| {
            Error::InvalidResponse("file entry omitted version identity".to_owned())
        })?;
        self.get_expected_file(
            vfs_path,
            DownloadExpectation::new(file_id, version_id, entry.size_bytes, &entry.data_root),
            destination,
            options,
        )
        .await
    }

    pub(crate) async fn get_file_version(
        &self,
        vfs_path: &str,
        expected: DownloadExpectation<'_>,
        destination: &Path,
        options: &GetOptions,
    ) -> Result<GetResult, Error> {
        self.get_expected_file(vfs_path, expected, destination, options)
            .await
    }

    async fn get_expected_file(
        &self,
        vfs_path: &str,
        expected: DownloadExpectation<'_>,
        destination: &Path,
        options: &GetOptions,
    ) -> Result<GetResult, Error> {
        validate_options(options)?;
        let transfer_started = Instant::now();
        let token = self.token.encode();
        let mut plan: DownloadPlan = self
            .control
            .send_json::<DownloadPlan, ()>(
                Method::GET,
                &format!("api/v2/versions/{}/download", expected.version_id),
                Some(&token),
                &[],
                None,
            )
            .await?;
        validate_plan(&plan, expected)?;
        let outcome = self
            .finish_download(vfs_path, destination, options, &mut plan)
            .await;
        let completion = CompletionRequest {
            telemetry: outcome.as_ref().ok().map(|(_, provider_elapsed)| {
                TransferTelemetry::measured(*provider_elapsed, transfer_started.elapsed())
            }),
        };
        let release = self
            .control
            .send_json::<Value, CompletionRequest>(
                Method::POST,
                &format!("api/v2/read-leases/{}/complete", plan.read_lease_id),
                Some(&token),
                &[],
                Some(&completion),
            )
            .await;
        match outcome {
            Ok((mut result, _)) => {
                if let Err(error) = release {
                    result.warnings.push(format!(
                        "The verified file was published, but read-lease completion will rely on expiry: {error}"
                    ));
                }
                Ok(result)
            }
            Err(error) => {
                let _ = release;
                Err(error)
            }
        }
    }

    async fn finish_download(
        &self,
        vfs_path: &str,
        destination: &Path,
        options: &GetOptions,
        plan: &mut DownloadPlan,
    ) -> Result<(GetResult, Duration), Error> {
        let provider_started = Instant::now();
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
        let mut warnings = verify_and_publish_plaintext(
            &plaintext_staging,
            destination,
            plan.verification_block_bytes,
            plan.plaintext_bytes,
            &plan.file_root,
        )?;
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
            provider_elapsed,
        ))
    }
}

fn verify_and_publish_plaintext(
    staging: &Path,
    destination: &Path,
    verification_block_bytes: u64,
    plaintext_bytes: u64,
    file_root: &str,
) -> Result<Vec<String>, Error> {
    let tree = match integrity::build_file(staging, verification_block_bytes) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = std::fs::remove_file(staging);
            return Err(error);
        }
    };
    if let Err(error) = verify_plaintext_identity(
        tree.size_bytes,
        &hex::encode(tree.root),
        plaintext_bytes,
        file_root,
    ) {
        let _ = std::fs::remove_file(staging);
        return Err(error);
    }
    match publish_no_replace(staging, destination) {
        Ok(warnings) => Ok(warnings),
        Err(error) => {
            let _ = std::fs::remove_file(staging);
            Err(error)
        }
    }
}

fn publish_no_replace(staging: &Path, destination: &Path) -> Result<Vec<String>, Error> {
    let parent = destination
        .parent()
        .ok_or_else(|| Error::InvalidResponse("download destination has no parent".to_owned()))?;
    std::fs::hard_link(staging, destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::InvalidResponse("download destination already exists".to_owned())
        } else {
            Error::InvalidResponse(format!(
                "publish downloaded file without replacement: {error}"
            ))
        }
    })?;
    let mut warnings = Vec::new();
    if let Err(error) = sync_directory(parent) {
        warnings.push(format!(
            "The verified file was published, but its directory sync failed: {error}"
        ));
    }
    if let Err(error) = std::fs::remove_file(staging) {
        warnings.push(format!(
            "The verified file was published, but plaintext staging cleanup was deferred: {error}"
        ));
    } else if let Err(error) = sync_directory(parent) {
        warnings.push(format!(
            "The verified file was published, but staging cleanup directory sync failed: {error}"
        ));
    }
    Ok(warnings)
}

fn sync_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| Error::InvalidResponse(format!("sync download directory: {error}")))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn validate_plan(plan: &DownloadPlan, expected: DownloadExpectation<'_>) -> Result<(), Error> {
    let _ = (
        &plan.filesystem_id,
        &plan.file_id,
        &plan.metadata_root,
        &plan.block_manifest_sha256,
        plan.block_manifest_bytes,
        &plan.block_manifest_r2_key,
        &plan.block_manifest_r2_version,
        &plan.location_id,
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
        || plan.verification_block_count
            != if plan.plaintext_bytes == 0 {
                0
            } else {
                1 + (plan.plaintext_bytes - 1) / plan.verification_block_bytes
            }
        || plan.key_epoch == 0
        || plan.encryption_frame_bytes == 0
        || plan.encoded_sha256.len() != 64
        || plan.driver_revision == 0
        || plan.storage_key.is_empty()
        || plan.read_lease_id.len() != 32
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
    if options.transfer_part_bytes == 0
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
    let decoded = hex::decode(value)
        .map_err(|_| Error::InvalidResponse("invalid VFS identifier".to_owned()))?;
    if decoded.len() != 16 || decoded.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidResponse("invalid VFS identifier".to_owned()));
    }
    let mut result = [0_u8; 16];
    result.copy_from_slice(&decoded);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{publish_no_replace, verify_and_publish_plaintext, verify_plaintext_identity};

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

        publish_no_replace(&staging, &destination).expect_err("reject replacement");

        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"old"
        );
    }
}
