use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{
    driver_credentials, driver_registry,
    transfer_metrics::{self, OwnedTransferIdentity, TransferTelemetry},
    vfs_access,
    vfs_envelopes::{
        DirectoryEnvelopeRef, PLAINTEXT_SUITE, open_directory_key, open_driver_credential,
    },
    vfs_identifiers,
    vfs_tokens::AuthenticatedVfsToken,
};

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CompletionRequest {
    telemetry: Option<TransferTelemetry>,
}

const MAXIMUM_COMPLETION_BATCH_ITEMS: usize = 64;
const MAXIMUM_COMPLETION_BATCH_BODY_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionBatchRequest {
    schema: String,
    completions: Vec<CompletionBatchItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionBatchItem {
    read_lease_id: String,
    telemetry: Option<TransferTelemetry>,
}

#[derive(Serialize)]
struct CompletionBatchResponse {
    schema: &'static str,
    completed_at: u64,
    results: Vec<CompletionBatchResult>,
}

#[derive(Serialize)]
struct CompletionBatchResult {
    read_lease_id: String,
    status: &'static str,
}

#[derive(Deserialize)]
struct CompletionIdentityRow {
    id: String,
    directory_id: String,
    driver_id: String,
    encoded_bytes: u64,
}

#[derive(Deserialize)]
struct DownloadRow {
    filesystem_id: String,
    authorization_directory_id: String,
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
    driver_config_json: String,
    key_envelope_algorithm: Option<String>,
    key_master_version: Option<String>,
    key_nonce: Option<Vec<u8>>,
    key_ciphertext: Option<Vec<u8>>,
    credential_id: Option<String>,
    credential_algorithm: Option<String>,
    credential_key_version: Option<String>,
    credential_nonce: Option<Vec<u8>>,
    credential_ciphertext: Option<Vec<u8>>,
    credential_revision: Option<u64>,
    credential_expires_at: Option<u64>,
}

#[derive(Serialize)]
struct DownloadResponse {
    schema: &'static str,
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
    config: serde_json::Value,
    credential: Option<serde_json::Value>,
    directory_key: Option<String>,
    read_lease_id: String,
    expires_at: u64,
}

/// Returns one immutable complete-object download plan. Payload bytes never
/// transit the Worker and the response is never cacheable.
#[allow(
    clippy::too_many_lines,
    reason = "authorization, durable read lease, secret grants, and audit share one plan boundary"
)]
pub(crate) async fn plan(
    env: &Env,
    token: &AuthenticatedVfsToken,
    version_id: &str,
) -> Result<Response> {
    if !valid_identifier(version_id) {
        return Response::error("invalid VFS version ID", 400);
    }
    let database = env.d1("CARRACK_INDEX")?;
    let Some(mut row) = load(&database, version_id).await? else {
        return Response::error("published VFS version was not found", 404);
    };
    if !vfs_access::authorized(
        &database,
        token,
        &row.authorization_directory_id,
        "content.read",
    )
    .await?
    {
        return Response::error("VFS content-read authority required", 403);
    }
    // Authorization must precede provider I/O and credential-state mutation.
    if let Some(expires_at) = row.credential_expires_at
        && expires_at <= Date::now().as_millis() / 1_000 + 5 * 60
    {
        if !driver_credentials::ensure_fresh(env, &row.driver_id, expires_at).await? {
            return Response::error("download driver credential requires reauthentication", 503);
        }
        let Some(reloaded) = load(&database, version_id).await? else {
            return Response::error("download location changed during credential renewal", 409);
        };
        row = reloaded;
    }
    // Renewal can race ACL revocation or a location change. Revalidate the
    // live authority before issuing the immutable provider capability.
    if !vfs_access::authorized(
        &database,
        token,
        &row.authorization_directory_id,
        "content.read",
    )
    .await?
    {
        return Response::error("VFS content-read authority required", 403);
    }
    let now = Date::now().as_millis() / 1_000;
    let read_lease_id = vfs_identifiers::new_uuid_v7_hex()?;
    // A plan may be resumed for the full bearer lifetime. Revocation cannot
    // shorten an already issued direct-read capability, while explicit client
    // completion normally releases the lease immediately.
    let lease_expires_at = token.expires_at;
    let leased = database
        .prepare(
            "INSERT INTO vfs_read_leases (
                 id, version_id, location_id, token_id, expires_at, created_at
             )
             SELECT ?1, version.id, location.id, ?2, ?3, ?4
             FROM vfs_file_versions AS version
             JOIN vfs_locations AS location ON location.version_id = version.id
             WHERE version.id = ?5 AND version.state = 'published'
               AND location.id = ?6 AND location.state = 'available'",
        )
        .bind(&[
            JsValue::from_str(&read_lease_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&lease_expires_at.to_string()),
            JsValue::from_str(&now.to_string()),
            JsValue::from_str(&row.version_id),
            JsValue::from_str(&row.location_id),
        ])?
        .run()
        .await?
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default();
    if leased != 1 {
        return Response::error("download location changed concurrently", 409);
    }
    let config = serde_json::from_str(&row.driver_config_json).map_err(|error| {
        worker::Error::RustError(format!("decode stored VFS driver configuration: {error}"))
    })?;
    let credential = decrypt_credential(env, &row, lease_expires_at)?;
    let mut directory_key = decrypt_directory_key(env, &row)?;
    let encoded_key = directory_key
        .as_ref()
        .map(|key| URL_SAFE_NO_PAD.encode(key));
    if let Some(key) = directory_key.as_mut() {
        key.zeroize();
    }
    database
        .prepare(
            "INSERT INTO vfs_audit_events (filesystem_id, principal_id, token_id, event_kind,
                 subject_kind, subject_id, details_json, created_at)
             VALUES (?1, ?2, ?3, 'download_planned', 'file_version', ?4, ?5, ?6)",
        )
        .bind(&[
            JsValue::from_str(&row.filesystem_id),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&row.version_id),
            JsValue::from_str(
                &serde_json::json!({"driver_id": row.driver_id, "location_id": row.location_id})
                    .to_string(),
            ),
            JsValue::from_str(&now.to_string()),
        ])?
        .run()
        .await?;
    let mut response = Response::from_json(&DownloadResponse {
        schema: "carrack.vfs.download-plan.v1",
        filesystem_id: row.filesystem_id,
        directory_id: row.directory_id,
        file_id: row.file_id,
        version_id: row.version_id,
        plaintext_bytes: row.plaintext_bytes,
        verification_block_bytes: row.verification_block_bytes,
        verification_block_count: row.verification_block_count,
        file_root: row.file_root,
        metadata_root: row.metadata_root,
        block_manifest_sha256: row.block_manifest_sha256,
        block_manifest_bytes: row.block_manifest_bytes,
        block_manifest_r2_key: row.block_manifest_r2_key,
        block_manifest_r2_version: row.block_manifest_r2_version,
        crypto_suite: row.crypto_suite,
        key_epoch: row.key_epoch,
        encryption_frame_bytes: row.encryption_frame_bytes,
        encoded_bytes: row.encoded_bytes,
        encoded_sha256: row.encoded_sha256,
        location_id: row.location_id,
        driver_id: row.driver_id,
        storage_key: row.storage_key,
        native_id: row.native_id,
        provider_version: row.provider_version,
        etag: row.etag,
        driver_kind: row.driver_kind,
        driver_revision: row.driver_revision,
        config,
        credential,
        directory_key: encoded_key,
        read_lease_id,
        expires_at: lease_expires_at,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response.headers_mut().set("Pragma", "no-cache")?;
    Ok(response)
}

/// Releases a direct-read lease after the client has finished or abandoned
/// the immutable provider read. Repeating completion is idempotent.
pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    context: &worker::Context,
    token: &AuthenticatedVfsToken,
    lease_id: &str,
) -> Result<Response> {
    if !valid_identifier(lease_id) {
        return Response::error("invalid VFS read lease ID", 400);
    }
    let now = Date::now().as_millis() / 1_000;
    let database = env.d1("CARRACK_INDEX")?;
    let encoded = request.bytes().await.unwrap_or_default();
    let requested = if encoded.is_empty() {
        CompletionRequest::default()
    } else {
        serde_json::from_slice::<CompletionRequest>(&encoded).unwrap_or_default()
    };
    let identity = database
        .prepare(
            "SELECT lease.id, origin.directory_id, location.driver_id, version.encoded_bytes
             FROM vfs_read_leases AS lease
             JOIN vfs_file_versions AS version ON version.id = lease.version_id
             JOIN vfs_version_origins AS origin ON origin.version_id = version.id
             JOIN vfs_locations AS location ON location.id = lease.location_id
             WHERE lease.id = ?1 AND lease.token_id = ?2",
        )
        .bind(&[JsValue::from_str(lease_id), JsValue::from_str(&token.id)])?
        .first::<CompletionIdentityRow>(None)
        .await?;
    let result = database
        .prepare(
            "UPDATE vfs_read_leases SET completed_at = COALESCE(completed_at, ?1)
             WHERE id = ?2 AND token_id = ?3",
        )
        .bind(&[
            JsValue::from_str(&now.to_string()),
            JsValue::from_str(lease_id),
            JsValue::from_str(&token.id),
        ])?
        .run()
        .await?;
    if result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default()
        != 1
    {
        return Response::error("VFS read lease was not found", 404);
    }
    if let Some(identity) = identity {
        transfer_metrics::schedule(
            context,
            env,
            OwnedTransferIdentity {
                operation_id: lease_id.to_owned(),
                direction: "download",
                driver_id: identity.driver_id,
                token_id: token.id.clone(),
                directory_id: identity.directory_id,
                encoded_bytes: identity.encoded_bytes,
            },
            requested.telemetry,
            now,
        );
    }
    Response::from_json(&serde_json::json!({
        "schema": "carrack.vfs.read-lease-completion.v1",
        "read_lease_id": lease_id,
        "completed_at": now,
    }))
}

/// Releases a bounded set of independently verified direct-read leases in one
/// control-plane round trip. The D1 updates commit as one batch; any failure
/// leaves every lease to its normal expiry fallback.
#[allow(
    clippy::too_many_lines,
    reason = "bounded parsing, identity selection, atomic completion, and telemetry form one batch boundary"
)]
pub(crate) async fn complete_batch(
    request: &mut Request,
    env: &Env,
    context: &worker::Context,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    if request
        .headers()
        .get("Content-Length")?
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAXIMUM_COMPLETION_BATCH_BODY_BYTES)
    {
        return Response::error("read-lease completion batch body is too large", 413);
    }
    let encoded = request.bytes().await?;
    if encoded.is_empty() || encoded.len() > MAXIMUM_COMPLETION_BATCH_BODY_BYTES {
        return Response::error("invalid read-lease completion batch body", 400);
    }
    let Ok(requested) = serde_json::from_slice::<CompletionBatchRequest>(&encoded) else {
        return Response::error("invalid read-lease completion batch", 400);
    };
    if requested.schema != "carrack.vfs.read-lease-completion-batch.v1"
        || requested.completions.is_empty()
        || requested.completions.len() > MAXIMUM_COMPLETION_BATCH_ITEMS
        || requested
            .completions
            .iter()
            .any(|item| !valid_identifier(&item.read_lease_id))
    {
        return Response::error("invalid read-lease completion batch", 400);
    }
    let mut unique = HashSet::with_capacity(requested.completions.len());
    if requested
        .completions
        .iter()
        .any(|item| !unique.insert(item.read_lease_id.as_str()))
    {
        return Response::error("duplicate VFS read lease ID", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let placeholders = (1..=requested.completions.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let token_parameter = requested.completions.len() + 1;
    let sql = format!(
        "SELECT lease.id, origin.directory_id, location.driver_id, version.encoded_bytes
         FROM vfs_read_leases AS lease
         JOIN vfs_file_versions AS version ON version.id = lease.version_id
         JOIN vfs_version_origins AS origin ON origin.version_id = version.id
         JOIN vfs_locations AS location ON location.id = lease.location_id
         WHERE lease.id IN ({placeholders}) AND lease.token_id = ?{token_parameter}"
    );
    let mut bindings = requested
        .completions
        .iter()
        .map(|item| JsValue::from_str(&item.read_lease_id))
        .collect::<Vec<_>>();
    bindings.push(JsValue::from_str(&token.id));
    let identities = database
        .prepare(&sql)
        .bind(&bindings)?
        .all()
        .await?
        .results::<CompletionIdentityRow>()?
        .into_iter()
        .map(|identity| (identity.id.clone(), identity))
        .collect::<HashMap<_, _>>();
    if identities.len() != requested.completions.len() {
        return Response::error("one or more VFS read leases were not found", 404);
    }

    let now = Date::now().as_millis() / 1_000;
    let statements = requested
        .completions
        .iter()
        .map(|item| {
            database
                .prepare(
                    "UPDATE vfs_read_leases SET completed_at = COALESCE(completed_at, ?1)
                     WHERE id = ?2 AND token_id = ?3",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&item.read_lease_id),
                    JsValue::from_str(&token.id),
                ])
        })
        .collect::<Result<Vec<_>>>()?;
    database.batch(statements).await?;

    for item in &requested.completions {
        let Some(identity) = identities.get(&item.read_lease_id) else {
            return Err(worker::Error::RustError(
                "read-lease completion identity changed during batching".to_owned(),
            ));
        };
        transfer_metrics::schedule(
            context,
            env,
            OwnedTransferIdentity {
                operation_id: item.read_lease_id.clone(),
                direction: "download",
                driver_id: identity.driver_id.clone(),
                token_id: token.id.clone(),
                directory_id: identity.directory_id.clone(),
                encoded_bytes: identity.encoded_bytes,
            },
            item.telemetry.clone(),
            now,
        );
    }
    Response::from_json(&CompletionBatchResponse {
        schema: "carrack.vfs.read-lease-completion-batch.v1",
        completed_at: now,
        results: requested
            .completions
            .into_iter()
            .map(|item| CompletionBatchResult {
                read_lease_id: item.read_lease_id,
                status: "completed",
            })
            .collect(),
    })
}

async fn load(database: &worker::D1Database, version_id: &str) -> Result<Option<DownloadRow>> {
    database
        .prepare(
            "SELECT file.filesystem_id, entry.directory_id AS authorization_directory_id,
                    origin.directory_id,
                    version.file_id, version.id AS version_id,
                    version.plaintext_bytes, version.verification_block_bytes,
                    version.verification_block_count, version.file_root, entry.metadata_root,
                    version.block_manifest_sha256, version.block_manifest_bytes,
                    version.block_manifest_r2_key, version.block_manifest_r2_version,
                    version.crypto_suite, version.key_epoch, version.encryption_frame_bytes,
                    version.encoded_bytes, version.encoded_sha256,
                    location.id AS location_id, location.driver_id, location.storage_key,
                    location.native_id, location.provider_version, location.etag,
                    driver.kind AS driver_kind, driver.revision AS driver_revision,
                    driver.config_json AS driver_config_json,
                    key_epoch.envelope_algorithm AS key_envelope_algorithm,
                    key_epoch.master_key_version AS key_master_version,
                    key_epoch.nonce AS key_nonce, key_epoch.ciphertext AS key_ciphertext,
                    credential.id AS credential_id,
                    credential.envelope_algorithm AS credential_algorithm,
                    credential.key_version AS credential_key_version,
                    credential.nonce AS credential_nonce,
                    credential.ciphertext AS credential_ciphertext,
                    credential.revision AS credential_revision,
                    credential.expires_at AS credential_expires_at
             FROM vfs_file_versions AS version
             JOIN vfs_files AS file ON file.id = version.file_id
             JOIN vfs_version_origins AS origin ON origin.version_id = version.id
             JOIN vfs_directory_entries AS entry
               ON entry.file_id = file.id AND entry.version_id = version.id AND entry.kind = 'file'
             JOIN vfs_locations AS location
               ON location.version_id = version.id AND location.state = 'available'
             JOIN driver_instances AS driver
               ON driver.id = location.driver_id AND driver.enabled = 1
             LEFT JOIN vfs_directory_drivers AS placement
               ON placement.directory_id = entry.directory_id
              AND placement.driver_id = location.driver_id AND placement.state = 'active'
             LEFT JOIN vfs_directory_key_epochs AS key_epoch
               ON key_epoch.directory_id = origin.directory_id
              AND key_epoch.key_epoch = version.key_epoch
              AND key_epoch.crypto_suite = version.crypto_suite
             LEFT JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE version.id = ?1 AND version.state = 'published'
             ORDER BY CASE WHEN placement.driver_id IS NULL THEN 1 ELSE 0 END,
                      placement.write_priority, location.id
             LIMIT 1",
        )
        .bind(&[JsValue::from_str(version_id)])?
        .first::<DownloadRow>(None)
        .await
}

fn decrypt_directory_key(env: &Env, row: &DownloadRow) -> Result<Option<[u8; 32]>> {
    if row.crypto_suite == PLAINTEXT_SUITE {
        return Ok(None);
    }
    let (Some(algorithm), Some(version), Some(nonce), Some(ciphertext)) = (
        row.key_envelope_algorithm.as_deref(),
        row.key_master_version.as_deref(),
        row.key_nonce.as_deref(),
        row.key_ciphertext.as_deref(),
    ) else {
        return Err(worker::Error::RustError(
            "encrypted download has no complete directory-key envelope".to_owned(),
        ));
    };
    open_directory_key(
        env,
        &DirectoryEnvelopeRef {
            directory_id: &row.directory_id,
            key_epoch: row.key_epoch,
            crypto_suite: &row.crypto_suite,
            algorithm,
            master_key_version: version,
            nonce,
            ciphertext,
        },
    )
    .map(Some)
}

fn decrypt_credential(
    env: &Env,
    row: &DownloadRow,
    expires_at: u64,
) -> Result<Option<serde_json::Value>> {
    let Some(id) = row.credential_id.as_deref() else {
        return Ok(None);
    };
    let (Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        row.credential_algorithm.as_deref(),
        row.credential_key_version.as_deref(),
        row.credential_nonce.as_deref(),
        row.credential_ciphertext.as_deref(),
        row.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "download driver credential envelope is incomplete".to_owned(),
        ));
    };
    let mut plaintext =
        open_driver_credential(env, id, revision, algorithm, version, nonce, ciphertext)?;
    let kind = driver_registry::compiled_kind(&row.driver_kind)?;
    let decoded = driver_registry::project_access_grant(
        kind,
        "GET",
        &row.driver_config_json,
        &row.storage_key,
        &plaintext,
        expires_at,
    );
    plaintext.zeroize();
    Ok(Some(decoded?))
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
