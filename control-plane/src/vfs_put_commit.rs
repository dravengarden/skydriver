use std::{collections::BTreeSet, fmt::Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{
    Bucket, Conditional, D1Database, D1PreparedStatement, Date, Env, Request, Response, Result,
    wasm_bindgen::JsValue,
};

use crate::{
    transfer_metrics::{self, OwnedTransferIdentity, TransferTelemetry},
    vfs_envelopes::{ENCRYPTED_SUITE, PLAINTEXT_SUITE},
    vfs_merkle::{DirectoryEntry, decode_hex, directory_root, validate_block_manifest},
    vfs_put,
    vfs_tokens::AuthenticatedVfsToken,
};

const PUT_RECEIPT_SCHEMA: &str = "carrack.vfs.put-receipt.v1";
const BLOCK_MANIFEST_SCHEMA: &str = "carrack.vfs.block-manifest-stage.v1";
const MAXIMUM_COMMIT_REBASE_ATTEMPTS: usize = 4;
const MAXIMUM_DIRECTORY_DEPTH: usize = 32;
const MAXIMUM_PROVIDER_IDENTITY_BYTES: usize = 1_024;
const AES_GCM_FRAME_TAG_BYTES: u64 = 16;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerificationMethod {
    ProviderChecksum,
    CompleteReadback,
}

impl VerificationMethod {
    const fn name(self) -> &'static str {
        match self {
            Self::ProviderChecksum => "provider_checksum",
            Self::CompleteReadback => "complete_readback",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitRequest {
    block_manifest_r2_version: String,
    encoded_bytes: u64,
    encoded_sha256: String,
    verification_method: VerificationMethod,
    native_id: Option<String>,
    provider_version: Option<String>,
    etag: Option<String>,
    #[serde(default, skip_serializing)]
    telemetry: Option<TransferTelemetry>,
}

#[derive(Deserialize)]
struct PutIntentRow {
    id: String,
    filesystem_id: String,
    directory_id: String,
    entry_name: String,
    expected_entry_revision: u64,
    expected_file_revision: u64,
    expected_current_version_id: Option<String>,
    file_id: String,
    version_id: String,
    location_id: String,
    driver_id: String,
    storage_key: String,
    plaintext_bytes: u64,
    verification_block_bytes: u64,
    verification_block_count: u64,
    file_root: String,
    metadata_root: String,
    block_manifest_sha256: String,
    block_manifest_bytes: u64,
    block_manifest_r2_key: String,
    crypto_suite: String,
    key_epoch: u64,
    encryption_frame_bytes: u64,
    state: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct ReceiptRow {
    intent_id: String,
    file_id: String,
    version_id: String,
    location_id: String,
    driver_id: String,
    storage_key: String,
    commit_sha256: String,
    block_manifest_r2_version: String,
    encoded_bytes: u64,
    encoded_sha256: String,
    verification_method: String,
    native_id: Option<String>,
    provider_version: Option<String>,
    etag: Option<String>,
    entry_revision: u64,
    catalog_revision_id: u64,
    committed_at: u64,
}

#[derive(Deserialize)]
struct UploadEvidenceRow {
    commit_sha256: String,
}

#[derive(Serialize)]
struct CommitResponse {
    schema: &'static str,
    intent_id: String,
    file_id: String,
    version_id: String,
    location_id: String,
    driver_id: String,
    storage_key: String,
    block_manifest_r2_version: String,
    encoded_bytes: u64,
    encoded_sha256: String,
    verification_method: String,
    native_id: Option<String>,
    provider_version: Option<String>,
    etag: Option<String>,
    entry_revision: u64,
    catalog_revision_id: u64,
    committed_at: u64,
    state: &'static str,
}

#[derive(Serialize)]
struct BlockManifestResponse {
    schema: &'static str,
    intent_id: String,
    sha256: String,
    bytes: u64,
    r2_key: String,
    r2_version: String,
}

#[derive(Deserialize)]
struct FileStateRow {
    current_version_id: Option<String>,
    revision: u64,
    state: String,
}

#[derive(Clone, Deserialize)]
struct DirectoryRow {
    id: String,
    filesystem_id: String,
    parent_id: Option<String>,
    name: String,
    data_root: String,
    revision: u64,
    state: String,
}

#[derive(Deserialize)]
struct StoredEntryRow {
    name: String,
    kind: String,
    file_id: Option<String>,
    version_id: Option<String>,
    child_directory_id: Option<String>,
    size_bytes: u64,
    data_root: String,
    metadata_root: Option<String>,
    revision: u64,
}

struct StoredEntry {
    entry: DirectoryEntry,
    revision: u64,
}

pub(crate) struct DirectoryUpdate {
    pub(crate) directory_id: String,
    pub(crate) expected_revision: u64,
    pub(crate) expected_root: String,
    pub(crate) new_root: String,
}

pub(crate) struct LinkUpdate {
    pub(crate) parent_directory_id: String,
    pub(crate) child_directory_id: String,
    pub(crate) name: String,
    pub(crate) expected_revision: u64,
    pub(crate) new_child_root: String,
}

pub(crate) struct RootPlan {
    pub(crate) directories: Vec<DirectoryUpdate>,
    pub(crate) links: Vec<LinkUpdate>,
    pub(crate) root: String,
}

enum Replacement {
    File,
    Child {
        id: String,
        name: String,
        data_root: String,
    },
}

/// Stores one protected integrity block manifest in control-plane R2.
///
/// Block manifests contain hashes and canonical layout only, never payload
/// bytes, file keys, virtual paths, or provider credentials. The write is
/// content-addressed and conditional; an existing key is accepted only after
/// exact length, bytes, and SHA-256 comparison.
pub(crate) async fn stage_block_manifest(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    intent_id: &str,
) -> Result<Response> {
    let database = env.d1("CARRACK_INDEX")?;
    let Some(intent) = load_intent(&database, intent_id, &token.principal_id).await? else {
        return Response::error("VFS put intent was not found", 404);
    };
    if !matches!(intent.state.as_str(), "prepared" | "committed")
        || (intent.state == "prepared" && intent.expires_at <= current_unix_seconds())
    {
        return Response::error("VFS put intent is no longer resumable", 409);
    }
    if !vfs_put::authorized(&database, token, &intent.directory_id, &intent.driver_id).await? {
        return Response::error("VFS block-manifest staging is not authorized", 403);
    }

    let encoded = request.bytes().await?;
    let encoded_bytes = u64::try_from(encoded.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let digest = Sha256::digest(&encoded);
    let sha256 = lowercase_hex(&digest)?;
    if encoded_bytes != intent.block_manifest_bytes || sha256 != intent.block_manifest_sha256 {
        return Response::error("VFS block manifest differs from its preparation", 409);
    }
    if validate_block_manifest(
        &encoded,
        intent.plaintext_bytes,
        intent.verification_block_bytes,
        intent.verification_block_count,
        decode_digest(&intent.file_root)?,
    )
    .is_err()
    {
        return Response::error("VFS block manifest does not prove its file root", 409);
    }

    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let stored = store_immutable_manifest(
        &bucket,
        &intent.block_manifest_r2_key,
        &encoded,
        digest.as_slice(),
    )
    .await?;

    Response::from_json(&BlockManifestResponse {
        schema: BLOCK_MANIFEST_SCHEMA,
        intent_id: intent.id,
        sha256,
        bytes: encoded_bytes,
        r2_key: intent.block_manifest_r2_key,
        r2_version: stored,
    })
}

/// Commits one already transferred and independently verified complete object.
///
/// The control plane verifies the immutable R2 block manifest, recomputes every
/// affected directory root, and publishes the version, location, entry,
/// ancestor roots, catalog outbox item, and durable receipt in one short D1
/// batch. Root-only races are rebased and retried; a changed target entry is an
/// explicit conflict. The current VFS token and ACL are checked again by the
/// final database transition.
#[allow(
    clippy::too_many_lines,
    reason = "publication keeps evidence, optimistic rebase, and receipt replay in one visible protocol"
)]
pub(crate) async fn commit(
    request: &mut Request,
    env: &Env,
    context: &worker::Context,
    token: &AuthenticatedVfsToken,
    intent_id: &str,
) -> Result<Response> {
    let requested = request.json::<CommitRequest>().await?;
    if !valid_commit_request(&requested) {
        return Response::error("invalid VFS put commit", 400);
    }
    let commit_sha256 = commit_identity(&requested)?;
    let database = env.d1("CARRACK_INDEX")?;
    let Some(intent) = load_intent(&database, intent_id, &token.principal_id).await? else {
        return Response::error("VFS put intent was not found", 404);
    };

    if let Some(receipt) = load_receipt(&database, intent_id).await? {
        return receipt_response_with_metric(
            receipt,
            &commit_sha256,
            context,
            env,
            &intent,
            token,
            &requested,
            current_unix_seconds(),
        );
    }
    if intent.state != "prepared" || intent.expires_at <= current_unix_seconds() {
        return Response::error("VFS put intent is no longer committable", 409);
    }
    let Some(expected_encoded_bytes) = expected_encoded_bytes(
        &intent.crypto_suite,
        intent.plaintext_bytes,
        intent.encryption_frame_bytes,
    ) else {
        return Response::error("VFS object encoding is unsupported", 409);
    };
    if requested.encoded_bytes != expected_encoded_bytes {
        return Response::error("VFS object encoded length differs", 409);
    }
    if !vfs_put::authorized(&database, token, &intent.directory_id, &intent.driver_id).await? {
        return Response::error("VFS put commit is not authorized", 403);
    }

    validate_staged_manifest(env, &intent, &requested.block_manifest_r2_version).await?;

    let evidence_time = current_unix_seconds();
    let record_error = record_upload_evidence(
        &database,
        &intent,
        token,
        &requested,
        &commit_sha256,
        evidence_time,
    )
    .await
    .err();
    let evidence = load_upload_evidence(&database, intent_id).await?;
    if evidence.is_none() {
        if let Some(error) = record_error {
            let current = load_intent(&database, intent_id, &token.principal_id).await?;
            if current.is_none_or(|value| {
                value.state != "prepared" || value.expires_at <= current_unix_seconds()
            }) {
                return Response::error("VFS put intent expired before evidence was recorded", 409);
            }
            return Err(error);
        }
        return Response::error("VFS upload evidence was not recorded", 409);
    }
    let evidence = evidence.expect("checked upload evidence");
    if evidence.commit_sha256 != commit_sha256 {
        return Response::error(
            "VFS put commit identity conflicts with upload evidence",
            409,
        );
    }

    for _ in 0..MAXIMUM_COMMIT_REBASE_ATTEMPTS {
        let Some(plan) = plan_directory_roots(&database, &intent).await? else {
            return Response::error("VFS entry precondition changed", 409);
        };
        let now = current_unix_seconds();
        let statements = commit_statements(
            &database,
            &intent,
            token,
            &requested,
            &commit_sha256,
            &plan,
            now,
        )?;
        if database.batch(statements).await.is_ok() {
            let Some(receipt) = load_receipt(&database, intent_id).await? else {
                return Response::error("VFS put commit did not publish a receipt", 409);
            };
            return receipt_response_with_metric(
                receipt,
                &commit_sha256,
                context,
                env,
                &intent,
                token,
                &requested,
                now,
            );
        }

        if let Some(receipt) = load_receipt(&database, intent_id).await? {
            return receipt_response_with_metric(
                receipt,
                &commit_sha256,
                context,
                env,
                &intent,
                token,
                &requested,
                current_unix_seconds(),
            );
        }
        let Some(current) = load_intent(&database, intent_id, &token.principal_id).await? else {
            return Response::error("VFS put intent disappeared", 409);
        };
        if current.state != "prepared" {
            return Response::error("VFS put commit lost its intent state", 409);
        }
    }

    Response::error("VFS directory roots remained contended", 409)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the metric identity must match the exact committed receipt context"
)]
fn receipt_response_with_metric(
    receipt: ReceiptRow,
    commit_sha256: &str,
    context: &worker::Context,
    env: &Env,
    intent: &PutIntentRow,
    token: &AuthenticatedVfsToken,
    requested: &CommitRequest,
    now: u64,
) -> Result<Response> {
    let response = receipt_response(receipt, commit_sha256)?;
    schedule_transfer_metric(context, env, intent, token, requested, now);
    Ok(response)
}

fn schedule_transfer_metric(
    context: &worker::Context,
    env: &Env,
    intent: &PutIntentRow,
    token: &AuthenticatedVfsToken,
    requested: &CommitRequest,
    now: u64,
) {
    transfer_metrics::schedule(
        context,
        env,
        OwnedTransferIdentity {
            operation_id: intent.id.clone(),
            direction: "upload",
            driver_id: intent.driver_id.clone(),
            token_id: token.id.clone(),
            directory_id: intent.directory_id.clone(),
            encoded_bytes: requested.encoded_bytes,
        },
        requested.telemetry.clone(),
        now,
    );
}

async fn store_immutable_manifest(
    bucket: &Bucket,
    key: &str,
    encoded: &[u8],
    digest: &[u8],
) -> Result<String> {
    let expected_bytes = u64::try_from(encoded.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let created = bucket
        .put(key, encoded.to_vec())
        .only_if(Conditional {
            etag_does_not_match: Some("*".to_owned()),
            ..Conditional::default()
        })
        .sha256(digest.to_vec())
        .execute()
        .await?;
    if let Some(object) = created {
        if object.size() != expected_bytes {
            return Err(worker::Error::RustError(
                "stored VFS block-manifest length differs".to_owned(),
            ));
        }
        return Ok(object.version().clone());
    }

    let Some(existing) = bucket.get(key).execute().await? else {
        return Err(worker::Error::RustError(
            "VFS block manifest disappeared after conditional write".to_owned(),
        ));
    };
    let version = existing.version().clone();
    let size = existing.size();
    let Some(body) = existing.body() else {
        return Err(worker::Error::RustError(
            "existing VFS block manifest has no body".to_owned(),
        ));
    };
    let existing_bytes = body.bytes().await?;
    if size != expected_bytes
        || existing_bytes != encoded
        || Sha256::digest(&existing_bytes).as_slice() != digest
    {
        return Err(worker::Error::RustError(
            "content-addressed VFS block-manifest collision".to_owned(),
        ));
    }

    Ok(version)
}

async fn validate_staged_manifest(
    env: &Env,
    intent: &PutIntentRow,
    expected_version: &str,
) -> Result<()> {
    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let Some(object) = bucket.get(&intent.block_manifest_r2_key).execute().await? else {
        return Err(worker::Error::RustError(
            "staged VFS block manifest is missing".to_owned(),
        ));
    };
    if object.version() != expected_version || object.size() != intent.block_manifest_bytes {
        return Err(worker::Error::RustError(
            "staged VFS block-manifest identity changed".to_owned(),
        ));
    }
    let Some(body) = object.body() else {
        return Err(worker::Error::RustError(
            "staged VFS block manifest has no body".to_owned(),
        ));
    };
    let encoded = body.bytes().await?;
    if lowercase_hex(&Sha256::digest(&encoded))? != intent.block_manifest_sha256 {
        return Err(worker::Error::RustError(
            "staged VFS block-manifest hash changed".to_owned(),
        ));
    }
    validate_block_manifest(
        &encoded,
        intent.plaintext_bytes,
        intent.verification_block_bytes,
        intent.verification_block_count,
        decode_digest(&intent.file_root)?,
    )
    .map_err(|error| {
        worker::Error::RustError(format!("validate staged VFS block manifest: {error:?}"))
    })?;

    Ok(())
}

async fn load_intent(
    database: &D1Database,
    intent_id: &str,
    principal_id: &str,
) -> Result<Option<PutIntentRow>> {
    database
        .prepare(
            "SELECT id, filesystem_id, directory_id, entry_name,
                    expected_entry_revision, expected_file_revision,
                    expected_current_version_id, file_id, version_id, location_id,
                    driver_id, storage_key, plaintext_bytes, verification_block_bytes,
                    verification_block_count, file_root, metadata_root,
                    block_manifest_sha256, block_manifest_bytes, block_manifest_r2_key,
                    crypto_suite, key_epoch, encryption_frame_bytes, state, expires_at
             FROM vfs_put_intents
             WHERE id = ?1 AND principal_id = ?2",
        )
        .bind(&[
            JsValue::from_str(intent_id),
            JsValue::from_str(principal_id),
        ])?
        .first::<PutIntentRow>(None)
        .await
}

async fn load_receipt(database: &D1Database, intent_id: &str) -> Result<Option<ReceiptRow>> {
    database
        .prepare(
            "SELECT receipt.intent_id, intent.file_id, intent.version_id,
                    intent.location_id, intent.driver_id, intent.storage_key,
                    receipt.commit_sha256, receipt.block_manifest_r2_version,
                    receipt.encoded_bytes, receipt.encoded_sha256,
                    receipt.verification_method, receipt.native_id,
                    receipt.provider_version, receipt.etag, receipt.entry_revision,
                    receipt.catalog_revision_id, receipt.committed_at
             FROM vfs_put_receipts AS receipt
             JOIN vfs_put_intents AS intent ON intent.id = receipt.intent_id
             WHERE receipt.intent_id = ?1 AND intent.state = 'committed'",
        )
        .bind(&[JsValue::from_str(intent_id)])?
        .first::<ReceiptRow>(None)
        .await
}

async fn load_upload_evidence(
    database: &D1Database,
    intent_id: &str,
) -> Result<Option<UploadEvidenceRow>> {
    database
        .prepare("SELECT commit_sha256 FROM vfs_put_upload_evidence WHERE intent_id = ?1")
        .bind(&[JsValue::from_str(intent_id)])?
        .first::<UploadEvidenceRow>(None)
        .await
}

async fn record_upload_evidence(
    database: &D1Database,
    intent: &PutIntentRow,
    token: &AuthenticatedVfsToken,
    requested: &CommitRequest,
    commit_sha256: &str,
    verified_at: u64,
) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_put_upload_evidence (
                 intent_id, token_id, commit_sha256, block_manifest_r2_version,
                 encoded_bytes, encoded_sha256, verification_method, native_id,
                 provider_version, etag, verified_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(intent_id) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(&intent.id),
            JsValue::from_str(&token.id),
            JsValue::from_str(commit_sha256),
            JsValue::from_str(&requested.block_manifest_r2_version),
            number_binding(requested.encoded_bytes),
            JsValue::from_str(&requested.encoded_sha256),
            JsValue::from_str(requested.verification_method.name()),
            optional_binding(requested.native_id.as_deref()),
            optional_binding(requested.provider_version.as_deref()),
            optional_binding(requested.etag.as_deref()),
            number_binding(verified_at),
        ])?
        .run()
        .await?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the root planner keeps target replacement and every ancestor proof in one walk"
)]
async fn plan_directory_roots(
    database: &D1Database,
    intent: &PutIntentRow,
) -> Result<Option<RootPlan>> {
    let file_state = database
        .prepare("SELECT current_version_id, revision, state FROM vfs_files WHERE id = ?1")
        .bind(&[JsValue::from_str(&intent.file_id)])?
        .first::<FileStateRow>(None)
        .await?;
    if intent.expected_entry_revision == 0 {
        if file_state.is_some() {
            return Ok(None);
        }
    } else if !file_state.is_some_and(|file| {
        file.state == "active"
            && file.revision == intent.expected_file_revision
            && file.current_version_id == intent.expected_current_version_id
    }) {
        return Ok(None);
    }

    let mut visited = BTreeSet::new();
    let mut directories = Vec::new();
    let mut links = Vec::new();
    let mut current_id = intent.directory_id.clone();
    let mut replacement = Replacement::File;

    loop {
        if directories.len() >= MAXIMUM_DIRECTORY_DEPTH || !visited.insert(current_id.clone()) {
            return Err(worker::Error::RustError(
                "VFS directory ancestry is cyclic or too deep".to_owned(),
            ));
        }
        let Some(directory) = load_directory(database, &current_id).await? else {
            return Ok(None);
        };
        if directory.filesystem_id != intent.filesystem_id || directory.state != "active" {
            return Ok(None);
        }
        let stored = load_directory_entries(database, &current_id).await?;
        let current_entries = stored
            .iter()
            .map(|entry| entry.entry.clone())
            .collect::<Vec<_>>();
        let current_root = lowercase_hex(&directory_root(&current_entries).map_err(|error| {
            worker::Error::RustError(format!("verify current VFS directory root: {error:?}"))
        })?)?;
        if current_root != directory.data_root {
            return Err(worker::Error::RustError(format!(
                "VFS directory {} root does not match its entries",
                directory.id
            )));
        }
        let mut entries = Vec::with_capacity(stored.len() + 1);
        let mut matched = None;

        for candidate in stored {
            let replace = match &replacement {
                Replacement::File => entry_name(&candidate.entry) == intent.entry_name,
                Replacement::Child { id, name, .. } => {
                    entry_name(&candidate.entry) == name
                        && matches!(
                            &candidate.entry,
                            DirectoryEntry::Directory { stable_id, .. }
                                if *stable_id == decode_identifier(id)?
                        )
                }
            };
            if replace {
                if matched.replace(candidate).is_some() {
                    return Err(worker::Error::RustError(
                        "VFS directory contains duplicate canonical entries".to_owned(),
                    ));
                }
            } else {
                entries.push(candidate.entry);
            }
        }

        match &replacement {
            Replacement::File => {
                if !target_entry_matches(intent, matched.as_ref()) {
                    return Ok(None);
                }
                entries.push(DirectoryEntry::File {
                    name: intent.entry_name.clone(),
                    stable_id: decode_identifier(&intent.file_id)?,
                    version_id: decode_identifier(&intent.version_id)?,
                    size_bytes: intent.plaintext_bytes,
                    data_root: decode_digest(&intent.file_root)?,
                    metadata_root: decode_digest(&intent.metadata_root)?,
                });
            }
            Replacement::Child {
                id,
                name,
                data_root,
            } => {
                let Some(existing) = matched else {
                    return Ok(None);
                };
                links.push(LinkUpdate {
                    parent_directory_id: directory.id.clone(),
                    child_directory_id: id.clone(),
                    name: name.clone(),
                    expected_revision: existing.revision,
                    new_child_root: data_root.clone(),
                });
                entries.push(DirectoryEntry::Directory {
                    name: name.clone(),
                    stable_id: decode_identifier(id)?,
                    data_root: decode_digest(data_root)?,
                });
            }
        }

        let new_root = lowercase_hex(&directory_root(&entries).map_err(|error| {
            worker::Error::RustError(format!("compute VFS directory root: {error:?}"))
        })?)?;
        if new_root == directory.data_root {
            return Err(worker::Error::RustError(
                "VFS put did not change its directory root".to_owned(),
            ));
        }
        directories.push(DirectoryUpdate {
            directory_id: directory.id.clone(),
            expected_revision: directory.revision,
            expected_root: directory.data_root,
            new_root: new_root.clone(),
        });

        let Some(parent_id) = directory.parent_id else {
            return Ok(Some(RootPlan {
                directories,
                links,
                root: new_root,
            }));
        };
        replacement = Replacement::Child {
            id: directory.id,
            name: directory.name,
            data_root: new_root,
        };
        current_id = parent_id;
    }
}

/// Plans the Merkle path for adding one absent child directory entry.
///
/// Every current directory root is independently recomputed from its stored
/// entries before the new roots are accepted. The returned optimistic proof is
/// consumed by one D1 batch; a concurrent namespace mutation invalidates it and
/// causes the caller to re-plan.
#[allow(
    clippy::too_many_lines,
    reason = "the namespace planner verifies the target and complete ancestor chain in one walk"
)]
pub(crate) async fn plan_new_child_directory_roots(
    database: &D1Database,
    filesystem_id: &str,
    parent_directory_id: &str,
    child_directory_id: &str,
    child_name: &str,
    child_root: &str,
) -> Result<Option<RootPlan>> {
    let mut visited = BTreeSet::new();
    let mut directories = Vec::new();
    let mut links = Vec::new();
    let mut current_id = parent_directory_id.to_owned();
    let mut replacement = Replacement::Child {
        id: child_directory_id.to_owned(),
        name: child_name.to_owned(),
        data_root: child_root.to_owned(),
    };
    let mut adding_child = true;

    loop {
        if directories.len() >= MAXIMUM_DIRECTORY_DEPTH || !visited.insert(current_id.clone()) {
            return Err(worker::Error::RustError(
                "VFS directory ancestry is cyclic or too deep".to_owned(),
            ));
        }
        let Some(directory) = load_directory(database, &current_id).await? else {
            return Ok(None);
        };
        if directory.filesystem_id != filesystem_id || directory.state != "active" {
            return Ok(None);
        }
        let stored = load_directory_entries(database, &current_id).await?;
        let current_entries = stored
            .iter()
            .map(|entry| entry.entry.clone())
            .collect::<Vec<_>>();
        let current_root = lowercase_hex(&directory_root(&current_entries).map_err(|error| {
            worker::Error::RustError(format!("verify current VFS directory root: {error:?}"))
        })?)?;
        if current_root != directory.data_root {
            return Err(worker::Error::RustError(format!(
                "VFS directory {} root does not match its entries",
                directory.id
            )));
        }

        let Replacement::Child {
            id,
            name,
            data_root,
        } = &replacement
        else {
            return Err(worker::Error::RustError(
                "VFS child-directory planner has an invalid replacement".to_owned(),
            ));
        };
        let mut entries = Vec::with_capacity(stored.len() + usize::from(adding_child));
        let mut matched = None;
        for candidate in stored {
            if entry_name(&candidate.entry) == name {
                if matched.replace(candidate).is_some() {
                    return Err(worker::Error::RustError(
                        "VFS directory contains duplicate canonical entries".to_owned(),
                    ));
                }
            } else {
                entries.push(candidate.entry);
            }
        }

        if adding_child {
            if matched.is_some() {
                return Ok(None);
            }
        } else {
            let Some(existing) = matched else {
                return Ok(None);
            };
            if !matches!(
                &existing.entry,
                DirectoryEntry::Directory { stable_id, .. }
                    if *stable_id == decode_identifier(id)?
            ) {
                return Ok(None);
            }
            links.push(LinkUpdate {
                parent_directory_id: directory.id.clone(),
                child_directory_id: id.clone(),
                name: name.clone(),
                expected_revision: existing.revision,
                new_child_root: data_root.clone(),
            });
        }
        entries.push(DirectoryEntry::Directory {
            name: name.clone(),
            stable_id: decode_identifier(id)?,
            data_root: decode_digest(data_root)?,
        });

        let new_root = lowercase_hex(&directory_root(&entries).map_err(|error| {
            worker::Error::RustError(format!("compute VFS directory root: {error:?}"))
        })?)?;
        if new_root == directory.data_root {
            return Err(worker::Error::RustError(
                "VFS directory creation did not change its parent root".to_owned(),
            ));
        }
        directories.push(DirectoryUpdate {
            directory_id: directory.id.clone(),
            expected_revision: directory.revision,
            expected_root: directory.data_root,
            new_root: new_root.clone(),
        });

        let Some(parent_id) = directory.parent_id else {
            return Ok(Some(RootPlan {
                directories,
                links,
                root: new_root,
            }));
        };
        replacement = Replacement::Child {
            id: directory.id,
            name: directory.name,
            data_root: new_root,
        };
        adding_child = false;
        current_id = parent_id;
    }
}

/// Plans removal of one exact entry and propagation of every ancestor root.
/// The optimistic revisions are consumed in the same D1 batch as the removal.
#[allow(
    clippy::too_many_lines,
    reason = "the removal planner verifies the target and complete ancestor chain in one walk"
)]
pub(crate) async fn plan_entry_removal_roots(
    database: &D1Database,
    filesystem_id: &str,
    directory_id: &str,
    entry_name_to_remove: &str,
    expected_entry_revision: u64,
) -> Result<Option<RootPlan>> {
    let mut visited = BTreeSet::new();
    let mut directories = Vec::new();
    let mut links = Vec::new();
    let mut current_id = directory_id.to_owned();
    let mut target_name = entry_name_to_remove.to_owned();
    let mut target_child_id: Option<String> = None;
    let mut replacement_root: Option<String> = None;

    loop {
        if directories.len() >= MAXIMUM_DIRECTORY_DEPTH || !visited.insert(current_id.clone()) {
            return Err(worker::Error::RustError(
                "VFS directory ancestry is cyclic or too deep".to_owned(),
            ));
        }
        let Some(directory) = load_directory(database, &current_id).await? else {
            return Ok(None);
        };
        if directory.filesystem_id != filesystem_id || directory.state != "active" {
            return Ok(None);
        }
        let stored = load_directory_entries(database, &current_id).await?;
        let current_entries = stored
            .iter()
            .map(|entry| entry.entry.clone())
            .collect::<Vec<_>>();
        let current_root = lowercase_hex(&directory_root(&current_entries).map_err(|error| {
            worker::Error::RustError(format!("verify current VFS directory root: {error:?}"))
        })?)?;
        if current_root != directory.data_root {
            return Err(worker::Error::RustError(format!(
                "VFS directory {} root does not match its entries",
                directory.id
            )));
        }

        let mut entries = Vec::with_capacity(stored.len());
        let mut matched = None;
        for candidate in stored {
            if entry_name(&candidate.entry) == target_name {
                if matched.replace(candidate).is_some() {
                    return Err(worker::Error::RustError(
                        "VFS directory contains duplicate canonical entries".to_owned(),
                    ));
                }
            } else {
                entries.push(candidate.entry);
            }
        }
        let Some(existing) = matched else {
            return Ok(None);
        };
        if let Some(new_child_root) = replacement_root.as_ref() {
            let Some(child_id) = target_child_id.as_ref() else {
                return Err(worker::Error::RustError(
                    "VFS removal planner omitted its ancestor child identity".to_owned(),
                ));
            };
            if !matches!(
                &existing.entry,
                DirectoryEntry::Directory { stable_id, .. }
                    if *stable_id == decode_identifier(child_id)?
            ) {
                return Ok(None);
            }
            links.push(LinkUpdate {
                parent_directory_id: directory.id.clone(),
                child_directory_id: child_id.clone(),
                name: target_name.clone(),
                expected_revision: existing.revision,
                new_child_root: new_child_root.clone(),
            });
            entries.push(DirectoryEntry::Directory {
                name: target_name.clone(),
                stable_id: decode_identifier(child_id)?,
                data_root: decode_digest(new_child_root)?,
            });
        } else if existing.revision != expected_entry_revision {
            return Ok(None);
        }

        let new_root = lowercase_hex(&directory_root(&entries).map_err(|error| {
            worker::Error::RustError(format!("compute VFS removal root: {error:?}"))
        })?)?;
        if new_root == directory.data_root {
            return Err(worker::Error::RustError(
                "VFS removal did not change its directory root".to_owned(),
            ));
        }
        directories.push(DirectoryUpdate {
            directory_id: directory.id.clone(),
            expected_revision: directory.revision,
            expected_root: directory.data_root,
            new_root: new_root.clone(),
        });
        let Some(parent_id) = directory.parent_id else {
            return Ok(Some(RootPlan {
                directories,
                links,
                root: new_root,
            }));
        };
        target_child_id = Some(directory.id);
        target_name = directory.name;
        replacement_root = Some(new_root);
        current_id = parent_id;
    }
}

/// Plans an atomic same-filesystem rename or move across two ancestor branches.
/// Both branches are verified against their stored Merkle roots and merged at
/// the lowest common ancestor before one optimistic D1 batch consumes the plan.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the two-branch planner must merge direct edits and ancestor link replacements"
)]
pub(crate) async fn plan_entry_rename_roots(
    database: &D1Database,
    filesystem_id: &str,
    source_directory_id: &str,
    source_name: &str,
    expected_source_revision: u64,
    destination_directory_id: &str,
    destination_name: &str,
) -> Result<Option<RootPlan>> {
    let source_chain = load_ancestor_chain(database, filesystem_id, source_directory_id).await?;
    let destination_chain =
        load_ancestor_chain(database, filesystem_id, destination_directory_id).await?;
    if source_chain.is_empty() || destination_chain.is_empty() {
        return Ok(None);
    }
    let mut rows = std::collections::BTreeMap::new();
    let mut depths = std::collections::BTreeMap::new();
    for chain in [&source_chain, &destination_chain] {
        let chain_depth = chain.len();
        for (index, row) in chain.iter().enumerate() {
            rows.entry(row.id.clone()).or_insert_with(|| row.clone());
            depths
                .entry(row.id.clone())
                .and_modify(|depth: &mut usize| *depth = (*depth).max(chain_depth - index - 1))
                .or_insert(chain_depth - index - 1);
        }
    }
    let mut stored_by_directory = std::collections::BTreeMap::new();
    for (id, row) in &rows {
        let stored = load_directory_entries(database, id).await?;
        let current = stored
            .iter()
            .map(|entry| entry.entry.clone())
            .collect::<Vec<_>>();
        let current_root = lowercase_hex(&directory_root(&current).map_err(|error| {
            worker::Error::RustError(format!("verify current VFS directory root: {error:?}"))
        })?)?;
        if current_root != row.data_root {
            return Err(worker::Error::RustError(format!(
                "VFS directory {} root does not match its entries",
                row.id
            )));
        }
        stored_by_directory.insert(id.clone(), stored);
    }
    let source_stored = stored_by_directory
        .get(source_directory_id)
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry_name(&entry.entry) == source_name)
        })
        .filter(|entry| entry.revision == expected_source_revision)
        .ok_or_else(|| worker::Error::RustError("VFS rename source changed".to_owned()))?;
    if stored_by_directory
        .get(destination_directory_id)
        .is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry_name(&entry.entry) == destination_name)
        })
    {
        return Ok(None);
    }
    if let DirectoryEntry::Directory { stable_id, .. } = &source_stored.entry {
        let moved_id = lowercase_hex(stable_id)?;
        if destination_chain.iter().any(|row| row.id == moved_id) {
            return Ok(None);
        }
    }
    let moved_entry = renamed_entry(&source_stored.entry, destination_name);
    let mut ordered = rows.keys().cloned().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        depths
            .get(right)
            .cmp(&depths.get(left))
            .then_with(|| left.cmp(right))
    });
    let mut new_roots = std::collections::BTreeMap::<String, String>::new();
    let mut directories = Vec::new();
    let mut links = Vec::new();
    for id in ordered {
        let row = rows.get(&id).ok_or_else(|| {
            worker::Error::RustError("VFS rename planner omitted a directory".to_owned())
        })?;
        let stored = stored_by_directory.get(&id).ok_or_else(|| {
            worker::Error::RustError("VFS rename planner omitted directory entries".to_owned())
        })?;
        let mut entries = Vec::with_capacity(stored.len() + 1);
        for candidate in stored {
            if id == source_directory_id && entry_name(&candidate.entry) == source_name {
                continue;
            }
            let mut entry = candidate.entry.clone();
            if let DirectoryEntry::Directory {
                name,
                stable_id,
                data_root,
            } = &mut entry
            {
                let child_id = lowercase_hex(stable_id)?;
                if let Some(root) = new_roots.get(&child_id) {
                    *data_root = decode_digest(root)?;
                    links.push(LinkUpdate {
                        parent_directory_id: id.clone(),
                        child_directory_id: child_id,
                        name: name.clone(),
                        expected_revision: candidate.revision,
                        new_child_root: root.clone(),
                    });
                }
            }
            entries.push(entry);
        }
        if id == destination_directory_id {
            entries.push(moved_entry.clone());
        }
        let new_root = lowercase_hex(&directory_root(&entries).map_err(|error| {
            worker::Error::RustError(format!("compute VFS rename root: {error:?}"))
        })?)?;
        if new_root != row.data_root {
            directories.push(DirectoryUpdate {
                directory_id: id.clone(),
                expected_revision: row.revision,
                expected_root: row.data_root.clone(),
                new_root: new_root.clone(),
            });
            new_roots.insert(id, new_root);
        }
    }
    let root = source_chain
        .last()
        .and_then(|row| new_roots.get(&row.id))
        .cloned()
        .ok_or_else(|| worker::Error::RustError("VFS rename did not change its root".to_owned()))?;
    Ok(Some(RootPlan {
        directories,
        links,
        root,
    }))
}

async fn load_ancestor_chain(
    database: &D1Database,
    filesystem_id: &str,
    directory_id: &str,
) -> Result<Vec<DirectoryRow>> {
    let mut chain = Vec::new();
    let mut current = directory_id.to_owned();
    let mut visited = BTreeSet::new();
    loop {
        if chain.len() >= MAXIMUM_DIRECTORY_DEPTH || !visited.insert(current.clone()) {
            return Err(worker::Error::RustError(
                "VFS directory ancestry is cyclic or too deep".to_owned(),
            ));
        }
        let Some(row) = load_directory(database, &current).await? else {
            return Ok(Vec::new());
        };
        if row.filesystem_id != filesystem_id || row.state != "active" {
            return Ok(Vec::new());
        }
        let parent = row.parent_id.clone();
        chain.push(row);
        let Some(parent) = parent else {
            return Ok(chain);
        };
        current = parent;
    }
}

fn renamed_entry(entry: &DirectoryEntry, name: &str) -> DirectoryEntry {
    match entry {
        DirectoryEntry::File {
            stable_id,
            version_id,
            size_bytes,
            data_root,
            metadata_root,
            ..
        } => DirectoryEntry::File {
            name: name.to_owned(),
            stable_id: *stable_id,
            version_id: *version_id,
            size_bytes: *size_bytes,
            data_root: *data_root,
            metadata_root: *metadata_root,
        },
        DirectoryEntry::Directory {
            stable_id,
            data_root,
            ..
        } => DirectoryEntry::Directory {
            name: name.to_owned(),
            stable_id: *stable_id,
            data_root: *data_root,
        },
    }
}

fn target_entry_matches(intent: &PutIntentRow, entry: Option<&StoredEntry>) -> bool {
    if intent.expected_entry_revision == 0 {
        return entry.is_none();
    }
    entry.is_some_and(|stored| {
        stored.revision == intent.expected_entry_revision
            && matches!(
                &stored.entry,
                DirectoryEntry::File {
                    stable_id,
                    version_id,
                    ..
                } if *stable_id == decode_identifier(&intent.file_id).unwrap_or([0; 16])
                    && Some(lowercase_hex(version_id).unwrap_or_default())
                        == intent.expected_current_version_id
            )
    })
}

async fn load_directory(database: &D1Database, directory_id: &str) -> Result<Option<DirectoryRow>> {
    database
        .prepare(
            "SELECT id, filesystem_id, parent_id, name, data_root, revision, state
             FROM vfs_directories WHERE id = ?1",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<DirectoryRow>(None)
        .await
}

async fn load_directory_entries(
    database: &D1Database,
    directory_id: &str,
) -> Result<Vec<StoredEntry>> {
    let rows = database
        .prepare(
            "SELECT name, kind, file_id, version_id, child_directory_id,
                    size_bytes, data_root, metadata_root, revision
             FROM vfs_directory_entries
             WHERE directory_id = ?1 ORDER BY CAST(name AS BLOB)",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .all()
        .await?
        .results::<StoredEntryRow>()?;

    rows.into_iter().map(stored_entry).collect()
}

fn stored_entry(row: StoredEntryRow) -> Result<StoredEntry> {
    let entry = match row.kind.as_str() {
        "file" => DirectoryEntry::File {
            name: row.name,
            stable_id: decode_identifier(row.file_id.as_deref().unwrap_or_default())?,
            version_id: decode_identifier(row.version_id.as_deref().unwrap_or_default())?,
            size_bytes: row.size_bytes,
            data_root: decode_digest(&row.data_root)?,
            metadata_root: decode_digest(row.metadata_root.as_deref().unwrap_or_default())?,
        },
        "directory" => DirectoryEntry::Directory {
            name: row.name,
            stable_id: decode_identifier(row.child_directory_id.as_deref().unwrap_or_default())?,
            data_root: decode_digest(&row.data_root)?,
        },
        _ => {
            return Err(worker::Error::RustError(
                "VFS directory entry has an unknown kind".to_owned(),
            ));
        }
    };

    Ok(StoredEntry {
        entry,
        revision: row.revision,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the complete atomic VFS put publication remains visible as one statement set"
)]
fn commit_statements(
    database: &D1Database,
    intent: &PutIntentRow,
    token: &AuthenticatedVfsToken,
    requested: &CommitRequest,
    commit_sha256: &str,
    plan: &RootPlan,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    let mut statements = Vec::new();
    for (ordinal, update) in plan.directories.iter().enumerate() {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_put_directory_updates (
                         intent_id, ordinal, directory_id, expected_revision,
                         expected_data_root, new_data_root
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&[
                    JsValue::from_str(&intent.id),
                    number_binding(u64::try_from(ordinal).map_err(|error| {
                        worker::Error::RustError(format!("directory ordinal: {error}"))
                    })?),
                    JsValue::from_str(&update.directory_id),
                    number_binding(update.expected_revision),
                    JsValue::from_str(&update.expected_root),
                    JsValue::from_str(&update.new_root),
                ])?,
        );
    }

    if intent.expected_entry_revision == 0 {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_files (
                         id, filesystem_id, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?3)",
                )
                .bind(&[
                    JsValue::from_str(&intent.file_id),
                    JsValue::from_str(&intent.filesystem_id),
                    number_binding(now),
                ])?,
        );
    }

    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_file_versions (
                     id, file_id, plaintext_bytes, verification_block_bytes,
                     verification_block_count, file_root, block_manifest_sha256,
                     block_manifest_bytes, block_manifest_r2_key,
                     block_manifest_r2_version, crypto_suite, key_epoch,
                     encryption_frame_bytes, encoded_bytes, encoded_sha256, created_at
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                     ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16
                 )",
            )
            .bind(&[
                JsValue::from_str(&intent.version_id),
                JsValue::from_str(&intent.file_id),
                number_binding(intent.plaintext_bytes),
                number_binding(intent.verification_block_bytes),
                number_binding(intent.verification_block_count),
                JsValue::from_str(&intent.file_root),
                JsValue::from_str(&intent.block_manifest_sha256),
                number_binding(intent.block_manifest_bytes),
                JsValue::from_str(&intent.block_manifest_r2_key),
                JsValue::from_str(&requested.block_manifest_r2_version),
                JsValue::from_str(&intent.crypto_suite),
                number_binding(intent.key_epoch),
                number_binding(intent.encryption_frame_bytes),
                number_binding(requested.encoded_bytes),
                JsValue::from_str(&requested.encoded_sha256),
                number_binding(now),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_audit_events (
                     filesystem_id, principal_id, token_id, event_kind,
                     subject_kind, subject_id, details_json, created_at
                 ) VALUES (?1, ?2, ?3, 'upload_committed', 'file_version', ?4, ?5, ?6)",
            )
            .bind(&[
                JsValue::from_str(&intent.filesystem_id),
                JsValue::from_str(&token.principal_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(&intent.version_id),
                JsValue::from_str(
                    &serde_json::json!({
                        "driver_id": intent.driver_id,
                        "location_id": intent.location_id,
                        "encoded_bytes": requested.encoded_bytes,
                    })
                    .to_string(),
                ),
                number_binding(now),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_version_origins (
                     version_id, directory_id, created_at
                 ) VALUES (?1, ?2, ?3)",
            )
            .bind(&[
                JsValue::from_str(&intent.version_id),
                JsValue::from_str(&intent.directory_id),
                number_binding(now),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_locations (
                     id, version_id, driver_id, storage_key, native_id,
                     provider_version, etag, size_bytes, object_sha256,
                     created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            )
            .bind(&[
                JsValue::from_str(&intent.location_id),
                JsValue::from_str(&intent.version_id),
                JsValue::from_str(&intent.driver_id),
                JsValue::from_str(&intent.storage_key),
                optional_binding(requested.native_id.as_deref()),
                optional_binding(requested.provider_version.as_deref()),
                optional_binding(requested.etag.as_deref()),
                number_binding(requested.encoded_bytes),
                JsValue::from_str(&requested.encoded_sha256),
                number_binding(now),
            ])?,
    );
    statements.push(state_update(
        database,
        "UPDATE vfs_locations
         SET state = 'verified', verified_at = ?1,
             revision = revision + 1, updated_at = MAX(updated_at, ?1)
         WHERE id = ?2 AND state = 'staging'",
        now,
        &intent.location_id,
    )?);
    statements.push(state_update(
        database,
        "UPDATE vfs_locations
         SET state = 'available', revision = revision + 1,
             updated_at = MAX(updated_at, ?1)
         WHERE id = ?2 AND state = 'verified'",
        now,
        &intent.location_id,
    )?);
    statements.push(
        database
            .prepare(
                "UPDATE vfs_file_versions SET state = 'verified'
                 WHERE id = ?1 AND state = 'staging'",
            )
            .bind(&[JsValue::from_str(&intent.version_id)])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE vfs_file_versions
                 SET state = 'published', published_at = ?1
                 WHERE id = ?2 AND state = 'verified'",
            )
            .bind(&[number_binding(now), JsValue::from_str(&intent.version_id)])?,
    );

    if intent.expected_entry_revision == 0 {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_files
                     SET current_version_id = ?1, updated_at = MAX(updated_at, ?2)
                     WHERE id = ?3 AND revision = 1 AND current_version_id IS NULL",
                )
                .bind(&[
                    JsValue::from_str(&intent.version_id),
                    number_binding(now),
                    JsValue::from_str(&intent.file_id),
                ])?,
        );
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_directory_entries (
                         directory_id, name, kind, file_id, version_id, size_bytes,
                         data_root, metadata_root, created_at, updated_at
                     ) VALUES (?1, ?2, 'file', ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                )
                .bind(&[
                    JsValue::from_str(&intent.directory_id),
                    JsValue::from_str(&intent.entry_name),
                    JsValue::from_str(&intent.file_id),
                    JsValue::from_str(&intent.version_id),
                    number_binding(intent.plaintext_bytes),
                    JsValue::from_str(&intent.file_root),
                    JsValue::from_str(&intent.metadata_root),
                    number_binding(now),
                ])?,
        );
    } else {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_files
                     SET current_version_id = ?1, revision = revision + 1,
                         updated_at = MAX(updated_at, ?2)
                     WHERE id = ?3 AND revision = ?4 AND current_version_id = ?5",
                )
                .bind(&[
                    JsValue::from_str(&intent.version_id),
                    number_binding(now),
                    JsValue::from_str(&intent.file_id),
                    number_binding(intent.expected_file_revision),
                    JsValue::from_str(
                        intent
                            .expected_current_version_id
                            .as_deref()
                            .unwrap_or_default(),
                    ),
                ])?,
        );
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directory_entries
                     SET version_id = ?1, size_bytes = ?2, data_root = ?3,
                         metadata_root = ?4, revision = revision + 1,
                         updated_at = MAX(updated_at, ?5)
                     WHERE directory_id = ?6 AND name = ?7 AND kind = 'file'
                       AND file_id = ?8 AND version_id = ?9 AND revision = ?10",
                )
                .bind(&[
                    JsValue::from_str(&intent.version_id),
                    number_binding(intent.plaintext_bytes),
                    JsValue::from_str(&intent.file_root),
                    JsValue::from_str(&intent.metadata_root),
                    number_binding(now),
                    JsValue::from_str(&intent.directory_id),
                    JsValue::from_str(&intent.entry_name),
                    JsValue::from_str(&intent.file_id),
                    JsValue::from_str(
                        intent
                            .expected_current_version_id
                            .as_deref()
                            .unwrap_or_default(),
                    ),
                    number_binding(intent.expected_entry_revision),
                ])?,
        );
    }

    for (index, update) in plan.directories.iter().enumerate() {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_directories
                     SET data_root = ?1, revision = revision + 1,
                         updated_at = MAX(updated_at, ?2)
                     WHERE id = ?3 AND revision = ?4 AND data_root = ?5",
                )
                .bind(&[
                    JsValue::from_str(&update.new_root),
                    number_binding(now),
                    JsValue::from_str(&update.directory_id),
                    number_binding(update.expected_revision),
                    JsValue::from_str(&update.expected_root),
                ])?,
        );
        if let Some(link) = plan.links.get(index) {
            statements.push(
                database
                    .prepare(
                        "UPDATE vfs_directory_entries
                         SET data_root = ?1, revision = revision + 1,
                             updated_at = MAX(updated_at, ?2)
                         WHERE directory_id = ?3 AND name = ?4 AND kind = 'directory'
                           AND child_directory_id = ?5 AND revision = ?6",
                    )
                    .bind(&[
                        JsValue::from_str(&link.new_child_root),
                        number_binding(now),
                        JsValue::from_str(&link.parent_directory_id),
                        JsValue::from_str(&link.name),
                        JsValue::from_str(&link.child_directory_id),
                        number_binding(link.expected_revision),
                    ])?,
            );
        }
    }

    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_catalog_revisions (
                     filesystem_id, parent_revision_id, root_data_root, state,
                     created_at, mutation_kind, mutation_id
                 ) VALUES (
                     ?1,
                     (SELECT revision_id FROM vfs_catalog_mutation_heads
                      WHERE filesystem_id = ?1),
                     ?2, 'pending', ?3, 'put', ?4
                 )",
            )
            .bind(&[
                JsValue::from_str(&intent.filesystem_id),
                JsValue::from_str(&plan.root),
                number_binding(now),
                JsValue::from_str(&intent.id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_catalog_outbox (revision_id, updated_at)
                 SELECT id, ?1 FROM vfs_catalog_revisions
                 WHERE mutation_kind = 'put' AND mutation_id = ?2",
            )
            .bind(&[number_binding(now), JsValue::from_str(&intent.id)])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_catalog_mutation_heads (
                     filesystem_id, revision_id, updated_at
                 )
                 SELECT filesystem_id, id, ?1
                 FROM vfs_catalog_revisions
                 WHERE mutation_kind = 'put' AND mutation_id = ?2
                 ON CONFLICT(filesystem_id) DO UPDATE SET
                     revision_id = excluded.revision_id,
                     revision = vfs_catalog_mutation_heads.revision + 1,
                     updated_at = excluded.updated_at",
            )
            .bind(&[number_binding(now), JsValue::from_str(&intent.id)])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_put_receipts (
                     intent_id, token_id, commit_sha256, block_manifest_r2_version,
                     encoded_bytes, encoded_sha256, verification_method, verified_at,
                     native_id, provider_version, etag, entry_revision,
                     catalog_revision_id, committed_at
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                        ?12, catalog.id, ?8
                 FROM vfs_catalog_revisions AS catalog
                 WHERE catalog.mutation_kind = 'put' AND catalog.mutation_id = ?1",
            )
            .bind(&[
                JsValue::from_str(&intent.id),
                JsValue::from_str(&token.id),
                JsValue::from_str(commit_sha256),
                JsValue::from_str(&requested.block_manifest_r2_version),
                number_binding(requested.encoded_bytes),
                JsValue::from_str(&requested.encoded_sha256),
                JsValue::from_str(requested.verification_method.name()),
                number_binding(now),
                optional_binding(requested.native_id.as_deref()),
                optional_binding(requested.provider_version.as_deref()),
                optional_binding(requested.etag.as_deref()),
                number_binding(intent.expected_entry_revision + 1),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE vfs_put_intents
                 SET state = 'committed', committed_at = ?1, revision = revision + 1
                 WHERE id = ?2 AND state = 'prepared' AND revision = 1",
            )
            .bind(&[number_binding(now), JsValue::from_str(&intent.id)])?,
    );

    Ok(statements)
}

fn state_update(
    database: &D1Database,
    sql: &str,
    now: u64,
    identity: &str,
) -> Result<D1PreparedStatement> {
    database
        .prepare(sql)
        .bind(&[number_binding(now), JsValue::from_str(identity)])
}

fn receipt_response(receipt: ReceiptRow, commit_sha256: &str) -> Result<Response> {
    if receipt.commit_sha256 != commit_sha256 {
        return Response::error("VFS put commit identity conflicts with its receipt", 409);
    }

    Response::from_json(&CommitResponse {
        schema: PUT_RECEIPT_SCHEMA,
        intent_id: receipt.intent_id,
        file_id: receipt.file_id,
        version_id: receipt.version_id,
        location_id: receipt.location_id,
        driver_id: receipt.driver_id,
        storage_key: receipt.storage_key,
        block_manifest_r2_version: receipt.block_manifest_r2_version,
        encoded_bytes: receipt.encoded_bytes,
        encoded_sha256: receipt.encoded_sha256,
        verification_method: receipt.verification_method,
        native_id: receipt.native_id,
        provider_version: receipt.provider_version,
        etag: receipt.etag,
        entry_revision: receipt.entry_revision,
        catalog_revision_id: receipt.catalog_revision_id,
        committed_at: receipt.committed_at,
        state: "committed",
    })
}

fn valid_commit_request(request: &CommitRequest) -> bool {
    valid_string(
        &request.block_manifest_r2_version,
        MAXIMUM_PROVIDER_IDENTITY_BYTES,
    ) && i64::try_from(request.encoded_bytes).is_ok()
        && valid_digest(&request.encoded_sha256)
        && request
            .native_id
            .as_deref()
            .is_none_or(|value| valid_string(value, MAXIMUM_PROVIDER_IDENTITY_BYTES))
        && request
            .provider_version
            .as_deref()
            .is_none_or(|value| valid_string(value, MAXIMUM_PROVIDER_IDENTITY_BYTES))
        && request
            .etag
            .as_deref()
            .is_none_or(|value| valid_string(value, MAXIMUM_PROVIDER_IDENTITY_BYTES))
}

fn expected_encoded_bytes(
    crypto_suite: &str,
    plaintext_bytes: u64,
    frame_bytes: u64,
) -> Option<u64> {
    match crypto_suite {
        PLAINTEXT_SUITE => Some(plaintext_bytes),
        ENCRYPTED_SUITE if frame_bytes > 0 => {
            let frame_count = if plaintext_bytes == 0 {
                0
            } else {
                1 + (plaintext_bytes - 1) / frame_bytes
            };
            plaintext_bytes.checked_add(frame_count.checked_mul(AES_GCM_FRAME_TAG_BYTES)?)
        }
        _ => None,
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn commit_identity(request: &CommitRequest) -> Result<String> {
    let encoded = serde_json::to_vec(request)?;
    let mut hasher = Sha256::new();
    hasher.update(b"carrack.vfs.put.commit.v1\0");
    hasher.update(encoded);
    lowercase_hex(&hasher.finalize())
}

fn decode_identifier(value: &str) -> Result<[u8; 16]> {
    decode_hex(value).map_err(|error| {
        worker::Error::RustError(format!("decode VFS identifier {value:?}: {error:?}"))
    })
}

fn decode_digest(value: &str) -> Result<[u8; 32]> {
    decode_hex(value).map_err(|error| {
        worker::Error::RustError(format!("decode VFS digest {value:?}: {error:?}"))
    })
}

fn entry_name(entry: &DirectoryEntry) -> &str {
    match entry {
        DirectoryEntry::File { name, .. } | DirectoryEntry::Directory { name, .. } => name,
    }
}

fn lowercase_hex(bytes: &[u8]) -> Result<String> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}")
            .map_err(|error| worker::Error::RustError(format!("encode VFS digest: {error}")))?;
    }
    Ok(encoded)
}

fn number_binding(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

fn optional_binding(value: Option<&str>) -> JsValue {
    value.map_or_else(JsValue::null, JsValue::from_str)
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> CommitRequest {
        CommitRequest {
            block_manifest_r2_version: "r2-version-1".to_owned(),
            encoded_bytes: 10,
            encoded_sha256: "1".repeat(64),
            verification_method: VerificationMethod::CompleteReadback,
            native_id: Some("native-1".to_owned()),
            provider_version: Some("provider-1".to_owned()),
            etag: None,
            telemetry: None,
        }
    }

    #[test]
    fn commit_identity_is_stable_and_covers_provider_evidence() {
        let request = valid_request();
        let identity = commit_identity(&request).expect("commit identity");
        assert_eq!(
            identity,
            commit_identity(&request).expect("repeat identity")
        );

        let changed = CommitRequest {
            provider_version: Some("provider-2".to_owned()),
            ..valid_request()
        };
        assert_ne!(
            identity,
            commit_identity(&changed).expect("changed identity")
        );
    }

    #[test]
    fn commit_rejects_malformed_provider_evidence() {
        assert!(valid_commit_request(&valid_request()));
        assert!(!valid_commit_request(&CommitRequest {
            encoded_sha256: "A".repeat(64),
            ..valid_request()
        }));
        assert!(!valid_commit_request(&CommitRequest {
            provider_version: Some(String::new()),
            ..valid_request()
        }));
    }

    #[test]
    fn encoded_length_is_exact_for_each_supported_suite() {
        assert_eq!(expected_encoded_bytes(PLAINTEXT_SUITE, 9, 4), Some(9));
        assert_eq!(expected_encoded_bytes(ENCRYPTED_SUITE, 0, 4), Some(0));
        assert_eq!(expected_encoded_bytes(ENCRYPTED_SUITE, 9, 4), Some(57));
        assert_eq!(expected_encoded_bytes(ENCRYPTED_SUITE, 9, 0), None);
        assert_eq!(expected_encoded_bytes("unknown/v1", 9, 4), None);
    }
}
