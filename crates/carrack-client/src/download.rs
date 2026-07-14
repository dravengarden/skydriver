//! Immutable download planning, provider readback, decryption, and verification.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cap_std::{ambient_authority, fs::Dir};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    io::Seek as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroize;

use crate::{
    Error, VfsClient,
    crypto::{Descriptor, restore},
    integrity,
};

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
        let version_id = entry.version_id.as_deref().ok_or_else(|| {
            Error::InvalidResponse("file entry omitted version identity".to_owned())
        })?;
        let token = self.token.encode();
        let mut plan: DownloadPlan = self
            .control
            .send_json::<DownloadPlan, ()>(
                Method::GET,
                &format!("api/v2/versions/{version_id}/download"),
                Some(&token),
                &[],
                None,
            )
            .await?;
        validate_plan(&plan, &entry)?;
        let outcome = self
            .finish_download(vfs_path, destination, options, &mut plan)
            .await;
        let release = self
            .control
            .send_json::<Value, ()>(
                Method::POST,
                &format!("api/v2/read-leases/{}/complete", plan.read_lease_id),
                Some(&token),
                &[],
                None,
            )
            .await;
        let result = outcome?;
        release?;
        Ok(result)
    }

    async fn finish_download(
        &self,
        vfs_path: &str,
        destination: &Path,
        options: &GetOptions,
        plan: &mut DownloadPlan,
    ) -> Result<GetResult, Error> {
        let encoded = fetch_provider(&self.control.http, plan, options).await?;
        let mut directory_key = decode_directory_key(plan)?;
        let descriptor = Descriptor {
            directory_id: parse_identifier(&plan.directory_id)?,
            version_id: parse_identifier(&plan.version_id)?,
            key_epoch: plan.key_epoch,
            frame_bytes: plan.encryption_frame_bytes,
            plaintext_bytes: plan.plaintext_bytes,
        };
        let restored = restore(
            &encoded,
            destination,
            &plan.crypto_suite,
            &descriptor,
            directory_key.as_ref(),
        );
        if let Some(key) = directory_key.as_mut() {
            key.zeroize();
        }
        restored?;
        let tree = integrity::build_file(destination, plan.verification_block_bytes)?;
        if tree.size_bytes != plan.plaintext_bytes || hex::encode(tree.root) != plan.file_root {
            let _ = std::fs::remove_file(destination);
            return Err(Error::InvalidResponse(
                "downloaded plaintext Merkle root differs".to_owned(),
            ));
        }
        std::fs::remove_file(&encoded)
            .map_err(|error| Error::InvalidResponse(format!("remove download staging: {error}")))?;
        Ok(GetResult {
            schema: "carrack.fs-get.v1",
            path: vfs_path.to_owned(),
            version_id: plan.version_id.clone(),
            plaintext_bytes: plan.plaintext_bytes,
            file_root: plan.file_root.clone(),
            verification_block_bytes: plan.verification_block_bytes,
            driver_id: plan.driver_id.clone(),
            warnings: if plan.driver_kind == "aliyundrive-open/v2"
                && options.maximum_concurrency > 1
            {
                vec![
                    "Aliyun exact-range download is safely degraded to sequential requests; use an S3 or R2 driver when parallel ranges are required."
                        .to_owned(),
                ]
            } else {
                Vec::new()
            },
        })
    }
}

fn validate_plan(plan: &DownloadPlan, entry: &crate::DirectoryEntry) -> Result<(), Error> {
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
        || entry.version_id.as_deref() != Some(&plan.version_id)
        || entry.file_id.as_deref() != Some(&plan.file_id)
        || entry.size_bytes != plan.plaintext_bytes
        || entry.data_root != plan.file_root
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

#[allow(
    clippy::too_many_lines,
    reason = "provider dispatch and resumable local assembly share one checksum boundary"
)]
async fn fetch_provider(
    http: &reqwest::Client,
    plan: &mut DownloadPlan,
    options: &GetOptions,
) -> Result<PathBuf, Error> {
    if plan.driver_kind == "aliyundrive-open/v2" {
        let credential = plan.credential.take().ok_or_else(|| {
            Error::InvalidResponse("Aliyun download omitted credentials".to_owned())
        })?;
        return crate::aliyun::download(
            http,
            &plan.driver_kind,
            &plan.config,
            credential,
            &plan.storage_key,
            plan.native_id.as_deref(),
            &options.staging_directory,
            &plan.version_id,
            plan.encoded_bytes,
            &plan.encoded_sha256,
        )
        .await;
    }
    if plan.driver_kind != "local-filesystem/v2" {
        return Err(Error::InvalidResponse(format!(
            "native Rust download does not yet support driver kind {}",
            plan.driver_kind
        )));
    }
    if plan.credential.is_some() {
        return Err(Error::InvalidResponse(
            "local driver unexpectedly received credentials".to_owned(),
        ));
    }
    let root = plan
        .config
        .get("root")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidResponse("local driver root is missing".to_owned()))?;
    let staging_root = &options.staging_directory;
    std::fs::create_dir_all(staging_root)
        .map_err(|error| Error::InvalidResponse(format!("create download staging: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(staging_root, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| Error::InvalidResponse(format!("protect download staging: {error}")),
        )?;
    }
    let relative = super::transfer::safe_storage_key(&plan.storage_key)?;
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| Error::InvalidResponse(format!("open local driver root: {error}")))?;
    let path = staging_root.join(format!("{}.download", plan.version_id));
    if path
        .metadata()
        .is_ok_and(|metadata| metadata.len() == plan.encoded_bytes)
        && hash_local_file(&path)? == plan.encoded_sha256
    {
        return Ok(path);
    }
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|error| Error::InvalidResponse(format!("reset download assembly: {error}")))?;
    }
    let part_root = staging_root.join("parts").join(&plan.version_id);
    std::fs::create_dir_all(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("create download journal: {error}")))?;
    download_parts(
        &directory,
        &relative,
        &part_root,
        plan.encoded_bytes,
        options.transfer_part_bytes,
        options.maximum_concurrency,
    )?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| Error::InvalidResponse(format!("create download staging: {error}")))?;
    let part_count = plan.encoded_bytes.div_ceil(options.transfer_part_bytes);
    for ordinal in 0..part_count {
        let mut part = std::fs::File::open(part_root.join(part_name(ordinal)))
            .map_err(|error| Error::InvalidResponse(format!("open download part: {error}")))?;
        std::io::copy(&mut part, &mut output).map_err(|error| {
            Error::InvalidResponse(format!("assemble download staging: {error}"))
        })?;
    }
    output
        .sync_all()
        .map_err(|error| Error::InvalidResponse(format!("sync download staging: {error}")))?;
    if path.metadata().map_or(0, |metadata| metadata.len()) != plan.encoded_bytes
        || hash_local_file(&path)? != plan.encoded_sha256
    {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&part_root);
        return Err(Error::InvalidResponse(
            "provider object checksum differs".to_owned(),
        ));
    }
    std::fs::remove_dir_all(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("remove download journal: {error}")))?;
    let _ = std::fs::remove_dir(staging_root.join("parts"));
    Ok(path)
}

fn download_parts(
    directory: &Dir,
    source: &Path,
    part_root: &Path,
    total_bytes: u64,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<(), Error> {
    let part_count = total_bytes.div_ceil(part_bytes);
    let next = AtomicU64::new(0);
    let worker_count =
        maximum_concurrency.min(usize::try_from(part_count.max(1)).unwrap_or(usize::MAX));
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..worker_count {
            let next = &next;
            let worker_directory = directory.try_clone().map_err(|error| {
                Error::InvalidResponse(format!("clone local driver root: {error}"))
            })?;
            workers.push(scope.spawn(move || -> Result<(), Error> {
                loop {
                    let ordinal = next.fetch_add(1, Ordering::Relaxed);
                    if ordinal >= part_count {
                        return Ok(());
                    }
                    let offset = ordinal * part_bytes;
                    let length = part_bytes.min(total_bytes - offset);
                    let part_path = part_root.join(part_name(ordinal));
                    if part_path
                        .metadata()
                        .is_ok_and(|metadata| metadata.len() == length)
                    {
                        continue;
                    }
                    if part_path.exists() {
                        std::fs::remove_file(&part_path).map_err(|error| {
                            Error::InvalidResponse(format!("reset download part: {error}"))
                        })?;
                    }
                    let mut input = worker_directory.open(source).map_err(|error| {
                        Error::InvalidResponse(format!("open provider object: {error}"))
                    })?;
                    input
                        .seek(std::io::SeekFrom::Start(offset))
                        .map_err(|error| {
                            Error::InvalidResponse(format!("seek provider object: {error}"))
                        })?;
                    let mut output = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&part_path)
                        .map_err(|error| {
                            Error::InvalidResponse(format!("create download part: {error}"))
                        })?;
                    copy_exact_bytes(&mut input, &mut output, length)?;
                    output.sync_all().map_err(|error| {
                        Error::InvalidResponse(format!("sync download part: {error}"))
                    })?;
                }
            }));
        }
        for worker in workers {
            worker.join().map_err(|_| {
                Error::InvalidResponse("local download worker panicked".to_owned())
            })??;
        }
        Ok(())
    })
}

fn copy_exact_bytes(
    input: &mut impl std::io::Read,
    output: &mut impl std::io::Write,
    bytes: u64,
) -> Result<(), Error> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        input
            .read_exact(&mut buffer[..wanted])
            .map_err(|error| Error::InvalidResponse(format!("read download part: {error}")))?;
        output
            .write_all(&buffer[..wanted])
            .map_err(|error| Error::InvalidResponse(format!("write download part: {error}")))?;
        remaining -= wanted as u64;
    }
    Ok(())
}

fn hash_local_file(path: &Path) -> Result<String, Error> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::InvalidResponse(format!("open download assembly: {error}")))?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)
        .map_err(|error| Error::InvalidResponse(format!("hash download assembly: {error}")))?;
    Ok(hex::encode(hash.finalize()))
}

fn part_name(ordinal: u64) -> String {
    format!("{ordinal:016x}.part")
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
