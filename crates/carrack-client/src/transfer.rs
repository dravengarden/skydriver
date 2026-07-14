//! Complete-object Put orchestration and rooted local-driver transport.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::io::{Read, Seek as _, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

use crate::{
    Error, VfsClient,
    crypto::{Descriptor, stage},
    integrity,
    vfs::{canonical_components, canonical_path},
};

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
        let spool_directory = options.staging_directory.join("plaintext");
        std::fs::create_dir_all(&spool_directory).map_err(|error| {
            Error::InvalidResponse(format!("create private plaintext spool: {error}"))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&spool_directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| {
                    Error::InvalidResponse(format!("protect private plaintext spool: {error}"))
                })?;
        }
        let identity = hex::encode(Sha256::digest(
            [options.idempotency_key.as_bytes(), bytes].concat(),
        ));
        let spool = spool_directory.join(identity);
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&spool)
            .map_err(|error| Error::InvalidResponse(format!("create plaintext spool: {error}")))?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| Error::InvalidResponse(format!("write plaintext spool: {error}")))?;
        drop(output);
        let result = self.put_file(&spool, vfs_path, options).await;
        let cleanup = std::fs::remove_file(&spool)
            .map_err(|error| Error::InvalidResponse(format!("remove plaintext spool: {error}")));
        let _ = std::fs::remove_dir(&spool_directory);
        let value = result?;
        cleanup?;
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
        let tree = integrity::build_file(source, options.verification_block_bytes)?;
        let manifest = integrity::manifest(&tree);
        let manifest_sha256 = hex::encode(Sha256::digest(&manifest));
        let file_root = hex::encode(tree.root);
        let metadata_root = hex::encode(integrity::empty_metadata_root());
        let token = self.token.encode();
        let preparation: Preparation = self
            .control
            .send_json(
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
            )
            .await?;
        validate_preparation(&preparation, &parent_directory_id, entry_name, options)?;
        let key: KeyGrant = self
            .control
            .send_json::<KeyGrant, ()>(
                Method::POST,
                &format!("api/v2/puts/{}/key-grant", preparation.intent_id),
                Some(&token),
                &[],
                None,
            )
            .await?;
        validate_key_grant(&key, &preparation)?;
        let mut driver: DriverGrant = self
            .control
            .send_json::<DriverGrant, ()>(
                Method::POST,
                &format!("api/v2/puts/{}/driver-grant", preparation.intent_id),
                Some(&token),
                &[],
                None,
            )
            .await?;
        validate_driver_grant(&driver, &preparation)?;
        let mut directory_key = decode_directory_key(&key)?;
        let descriptor = Descriptor {
            directory_id: parse_identifier(&preparation.directory_id)?,
            version_id: parse_identifier(&preparation.version_id)?,
            key_epoch: preparation.key_epoch,
            frame_bytes: preparation.encryption_frame_bytes,
            plaintext_bytes: tree.size_bytes,
        };
        let staged = stage(
            source,
            &options.staging_directory,
            &preparation.intent_id,
            &preparation.crypto_suite,
            &descriptor,
            directory_key.as_ref(),
        )?;
        if let Some(key) = directory_key.as_mut() {
            key.zeroize();
        }
        if integrity::build_file(source, options.verification_block_bytes)? != tree {
            return Err(Error::InvalidResponse(
                "source changed during encoding".to_owned(),
            ));
        }
        let manifest_stage = self.stage_manifest(&token, &preparation, &manifest).await?;
        let object = upload_driver(
            &self.control.http,
            &mut driver,
            &preparation.intent_id,
            &preparation.storage_key,
            &staged,
            options.transfer_part_bytes,
            options.maximum_concurrency,
        )
        .await?;
        let warnings = if driver.driver_kind == "aliyundrive-open/v2"
            && options.maximum_concurrency > 1
        {
            vec![
                "Aliyun upload concurrency is safely degraded to one; use an S3 or R2 driver when parallel multipart upload is required."
                    .to_owned(),
            ]
        } else {
            Vec::new()
        };
        let commit: PutReceipt = self
            .control
            .send_json(
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
                }),
            )
            .await?;
        validate_receipt(&commit, &preparation, &manifest_stage, &staged)?;
        std::fs::remove_file(&staged.path).map_err(|error| {
            Error::InvalidResponse(format!("remove committed staging: {error}"))
        })?;
        Ok(PutResult {
            schema: "carrack.fs-put.v1",
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
            .header("Carrack-Protocol-Epoch", crate::PROTOCOL_EPOCH)
            .header("Carrack-SDK-Version", crate::SDK_VERSION)
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
        if staged.schema != "carrack.vfs.block-manifest-stage.v1"
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

struct ProviderObject {
    native_id: String,
    provider_version: String,
    etag: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "provider dispatch and resumable local publication share one readback boundary"
)]
async fn upload_driver(
    http: &reqwest::Client,
    driver: &mut DriverGrant,
    intent_id: &str,
    storage_key: &str,
    staged: &crate::crypto::StagedObject,
    part_bytes: u64,
    maximum_concurrency: usize,
) -> Result<ProviderObject, Error> {
    if driver.driver_kind == "aliyundrive-open/v2" {
        let credential = driver.credential.take().ok_or_else(|| {
            Error::InvalidResponse("Aliyun driver omitted its credential".to_owned())
        })?;
        let object = crate::aliyun::upload(
            http,
            &driver.driver_kind,
            &driver.config,
            credential,
            storage_key,
            &staged.path,
            staged.encoded_bytes,
            &staged.encoded_sha256,
        )
        .await?;
        return Ok(ProviderObject {
            native_id: object.native_id,
            provider_version: object.provider_version,
            etag: object.etag,
        });
    }
    if driver.driver_kind != "local-filesystem/v2" {
        return Err(Error::InvalidResponse(format!(
            "unsupported native driver kind {}",
            driver.driver_kind
        )));
    }
    if driver.credential.is_some() {
        return Err(Error::InvalidResponse(
            "local driver unexpectedly received credentials".to_owned(),
        ));
    }
    let root = driver
        .config
        .get("root")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidResponse("local driver root is missing".to_owned()))?;
    let relative = safe_storage_key(storage_key)?;
    let directory = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| Error::InvalidResponse(format!("open local driver root: {error}")))?;
    if let Some(parent) = relative.parent() {
        directory
            .create_dir_all(parent)
            .map_err(|error| Error::InvalidResponse(format!("create object parent: {error}")))?;
    }
    let part_count = staged.encoded_bytes.div_ceil(part_bytes);
    let part_root = PathBuf::from(format!(".carrack/uploads/{intent_id}"));
    directory
        .create_dir_all(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("create upload journal: {error}")))?;
    upload_parts(
        &directory,
        &staged.path,
        &part_root,
        staged.encoded_bytes,
        part_bytes,
        part_count,
        maximum_concurrency,
    )?;
    let temporary = PathBuf::from(format!("{}.carrack-upload-{intent_id}", relative.display()));
    if directory.metadata(&temporary).is_ok() {
        directory
            .remove_file(&temporary)
            .map_err(|error| Error::InvalidResponse(format!("reset upload assembly: {error}")))?;
    }
    let mut output = directory
        .open_with(&temporary, OpenOptions::new().write(true).create_new(true))
        .map_err(|error| Error::InvalidResponse(format!("create local upload: {error}")))?;
    for ordinal in 0..part_count {
        let mut part = directory
            .open(part_root.join(part_name(ordinal)))
            .map_err(|error| Error::InvalidResponse(format!("open upload part: {error}")))?;
        std::io::copy(&mut part, &mut output)
            .map_err(|error| Error::InvalidResponse(format!("assemble local upload: {error}")))?;
    }
    output
        .sync_all()
        .map_err(|error| Error::InvalidResponse(format!("sync local upload: {error}")))?;
    drop(output);
    if directory.metadata(&relative).is_ok() {
        directory
            .remove_file(&temporary)
            .map_err(|error| Error::InvalidResponse(format!("remove replay temporary: {error}")))?;
    } else {
        directory
            .rename(&temporary, &directory, &relative)
            .map_err(|error| Error::InvalidResponse(format!("publish local object: {error}")))?;
    }
    let mut file = directory
        .open(&relative)
        .map_err(|error| Error::InvalidResponse(format!("read back local object: {error}")))?;
    let mut hash = Sha256::new();
    let bytes = std::io::copy(&mut file, &mut hash)
        .map_err(|error| Error::InvalidResponse(format!("verify local object: {error}")))?;
    if bytes != staged.encoded_bytes || hex::encode(hash.finalize()) != staged.encoded_sha256 {
        let _ = directory.remove_file(&relative);
        return Err(Error::InvalidResponse(
            "local provider readback differs".to_owned(),
        ));
    }
    for ordinal in 0..part_count {
        directory
            .remove_file(part_root.join(part_name(ordinal)))
            .map_err(|error| Error::InvalidResponse(format!("remove upload part: {error}")))?;
    }
    directory
        .remove_dir(&part_root)
        .map_err(|error| Error::InvalidResponse(format!("remove upload journal: {error}")))?;
    Ok(ProviderObject {
        native_id: format!("sha256:{}", staged.encoded_sha256),
        provider_version: format!("sha256:{}", staged.encoded_sha256),
        etag: staged.encoded_sha256.clone(),
    })
}

fn upload_parts(
    directory: &Dir,
    source: &Path,
    part_root: &Path,
    total_bytes: u64,
    part_bytes: u64,
    part_count: u64,
    maximum_concurrency: usize,
) -> Result<(), Error> {
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
                    if worker_directory
                        .metadata(&part_path)
                        .is_ok_and(|metadata| metadata.len() == length)
                    {
                        continue;
                    }
                    if worker_directory.metadata(&part_path).is_ok() {
                        worker_directory.remove_file(&part_path).map_err(|error| {
                            Error::InvalidResponse(format!("reset upload part: {error}"))
                        })?;
                    }
                    let mut input = std::fs::File::open(source).map_err(|error| {
                        Error::InvalidResponse(format!("open encoded staging: {error}"))
                    })?;
                    input
                        .seek(std::io::SeekFrom::Start(offset))
                        .map_err(|error| {
                            Error::InvalidResponse(format!("seek encoded staging: {error}"))
                        })?;
                    let mut output = worker_directory
                        .open_with(&part_path, OpenOptions::new().write(true).create_new(true))
                        .map_err(|error| {
                            Error::InvalidResponse(format!("create upload part: {error}"))
                        })?;
                    copy_exact_bytes(&mut input, &mut output, length)?;
                    output.sync_all().map_err(|error| {
                        Error::InvalidResponse(format!("sync upload part: {error}"))
                    })?;
                }
            }));
        }
        for worker in workers {
            worker
                .join()
                .map_err(|_| Error::InvalidResponse("local upload worker panicked".to_owned()))??;
        }
        Ok(())
    })
}

fn copy_exact_bytes(
    input: &mut impl Read,
    output: &mut impl Write,
    bytes: u64,
) -> Result<(), Error> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        input
            .read_exact(&mut buffer[..wanted])
            .map_err(|error| Error::InvalidResponse(format!("read transfer part: {error}")))?;
        output
            .write_all(&buffer[..wanted])
            .map_err(|error| Error::InvalidResponse(format!("write transfer part: {error}")))?;
        remaining -= wanted as u64;
    }
    Ok(())
}

fn part_name(ordinal: u64) -> String {
    format!("{ordinal:016x}.part")
}

pub(crate) fn safe_storage_key(value: &str) -> Result<PathBuf, Error> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Error::InvalidResponse(
            "unsafe provider storage key".to_owned(),
        ));
    }
    Ok(path.to_owned())
}

fn validate_options(options: &PutOptions) -> Result<(), Error> {
    if options.idempotency_key.is_empty()
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
    if value.schema != "carrack.vfs.put-preparation.v1"
        || value.directory_id != directory_id
        || value.entry_name != entry_name
        || value.expected_entry_revision != options.expected_entry_revision
        || value.intent_id.len() != 32
        || value.version_id.len() != 32
        || value.file_id.len() != 32
        || value.location_id.len() != 32
        || value.filesystem_id.len() != 32
        || value.driver_id.is_empty()
        || value.storage_key.is_empty()
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
    if value.schema != "carrack.vfs.directory-key-grant.v1"
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
    if value.schema != "carrack.vfs.driver-grant.v1"
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
    let decoded = hex::decode(value)
        .map_err(|_| Error::InvalidResponse("invalid VFS identifier".to_owned()))?;
    if decoded.len() != 16 || decoded.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidResponse("invalid VFS identifier".to_owned()));
    }
    let mut result = [0_u8; 16];
    result.copy_from_slice(&decoded);
    Ok(result)
}

fn validate_receipt(
    value: &PutReceipt,
    preparation: &Preparation,
    manifest: &ManifestStage,
    staged: &crate::crypto::StagedObject,
) -> Result<(), Error> {
    if value.schema != "carrack.vfs.put-receipt.v1"
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
