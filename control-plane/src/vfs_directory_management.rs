use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};
use zeroize::Zeroize as _;

use crate::{
    vfs_access,
    vfs_envelopes::{
        ENCRYPTED_SUITE, ENVELOPE_ALGORITHM, MASTER_KEY_VERSION, PLAINTEXT_SUITE, SealedEnvelope,
        blob_binding, seal_directory_key,
    },
    vfs_identifiers::new_uuid_v7_hex,
    vfs_merkle::directory_root,
    vfs_put_commit::{RootPlan, RootPlanResult, plan_new_child_directory_roots},
    vfs_tokens::AuthenticatedVfsToken,
};

const DIRECTORY_CREATE_SCHEMA: &str = "carrack.vfs.directory-create-receipt.v1";
const MAXIMUM_REBASE_ATTEMPTS: usize = 4;
const MAXIMUM_NAME_BYTES: usize = 255;
const MAXIMUM_IDEMPOTENCY_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDirectoryRequest {
    name: String,
    crypto_suite: Option<String>,
    idempotency_key: String,
}

#[derive(Serialize)]
struct CreateDirectoryIdentity<'a> {
    parent_directory_id: &'a str,
    name: &'a str,
    crypto_suite: Option<&'a str>,
    idempotency_key: &'a str,
}

#[derive(Deserialize)]
struct ParentDirectoryRow {
    filesystem_id: String,
    crypto_suite: String,
}

#[derive(Deserialize)]
struct ExistsRow {
    present: u64,
}

#[derive(Deserialize)]
struct CreateDirectoryReceiptRow {
    intent_id: String,
    request_sha256: String,
    filesystem_id: String,
    parent_directory_id: String,
    directory_id: String,
    name: String,
    data_root: String,
    crypto_suite: String,
    key_epoch: u64,
    catalog_revision_id: u64,
    created_at: u64,
}

#[derive(Serialize)]
struct CreateDirectoryResponse {
    schema: &'static str,
    operation_id: String,
    filesystem_id: String,
    parent_directory_id: String,
    directory_id: String,
    name: String,
    data_root: String,
    crypto_suite: String,
    key_epoch: u64,
    catalog_revision_id: u64,
    created_at: u64,
    state: &'static str,
}

/// Creates one empty child directory and atomically republishes every Merkle
/// root from its parent through the filesystem root.
#[allow(
    clippy::too_many_lines,
    reason = "the mkdir handler keeps idempotency, key creation, and bounded rebase together"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    parent_directory_id: &str,
) -> Result<Response> {
    if !valid_identifier(parent_directory_id) {
        return Response::error("invalid VFS parent directory ID", 400);
    }
    let requested = request.json::<CreateDirectoryRequest>().await?;
    if !valid_request(&requested) {
        return Response::error("invalid VFS directory-create request", 400);
    }
    let identity = CreateDirectoryIdentity {
        parent_directory_id,
        name: &requested.name,
        crypto_suite: requested.crypto_suite.as_deref(),
        idempotency_key: &requested.idempotency_key,
    };
    let request_digest = request_identity(&identity)?;
    let request_sha256 = lowercase_hex(&request_digest)?;
    let database = env.d1("SKYDRIVER_INDEX")?;

    if !vfs_access::authorized(&database, token, parent_directory_id, "content.write").await? {
        return Response::error("VFS content-write authority required", 403);
    }
    if let Some(receipt) = load_receipt(&database, &token.id, &requested.idempotency_key).await? {
        return receipt_response(receipt, &request_sha256);
    }

    let Some(parent) = load_parent(&database, parent_directory_id).await? else {
        return Response::error("VFS parent directory not found", 404);
    };
    let crypto_suite = requested
        .crypto_suite
        .as_deref()
        .unwrap_or(&parent.crypto_suite);
    if !matches!(crypto_suite, ENCRYPTED_SUITE | PLAINTEXT_SUITE) {
        return Response::error("unsupported VFS directory crypto suite", 400);
    }
    if !has_enabled_placement(&database, parent_directory_id).await? {
        return Response::error("VFS parent has no usable driver placement", 409);
    }

    let operation_id = new_uuid_v7_hex()?;
    let child_directory_id = new_uuid_v7_hex()?;
    let empty_root = lowercase_hex(&directory_root(&[]).map_err(|error| {
        worker::Error::RustError(format!("compute empty VFS directory root: {error:?}"))
    })?)?;
    let now = current_unix_seconds();
    let mut directory_key = [0_u8; 32];
    let envelope = if crypto_suite == ENCRYPTED_SUITE {
        getrandom::fill(&mut directory_key).map_err(|error| {
            worker::Error::RustError(format!("generate VFS directory key: {error}"))
        })?;
        Some(seal_directory_key(
            env,
            &child_directory_id,
            1,
            crypto_suite,
            &directory_key,
        )?)
    } else {
        None
    };
    directory_key.zeroize();

    for _ in 0..MAXIMUM_REBASE_ATTEMPTS {
        let plan = match plan_new_child_directory_roots(
            &database,
            &parent.filesystem_id,
            parent_directory_id,
            &child_directory_id,
            &requested.name,
            &empty_root,
        )
        .await?
        {
            RootPlanResult::Planned(plan) => plan,
            RootPlanResult::Contended => continue,
            RootPlanResult::PreconditionChanged => {
                return Response::error("VFS directory name is no longer absent", 409);
            }
        };
        let statements = create_statements(
            &database,
            token,
            &requested,
            &request_sha256,
            &operation_id,
            &parent.filesystem_id,
            parent_directory_id,
            &child_directory_id,
            crypto_suite,
            &empty_root,
            envelope.as_ref(),
            &plan,
            now,
        )?;
        if database.batch(statements).await.is_ok() {
            let Some(receipt) =
                load_receipt(&database, &token.id, &requested.idempotency_key).await?
            else {
                return Response::error("VFS directory creation omitted its receipt", 409);
            };
            return receipt_response(receipt, &request_sha256);
        }

        if let Some(receipt) =
            load_receipt(&database, &token.id, &requested.idempotency_key).await?
        {
            return receipt_response(receipt, &request_sha256);
        }
    }

    Response::error("VFS directory roots remained contended", 409)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the atomic mkdir publication remains visible as one statement set"
)]
fn create_statements(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    requested: &CreateDirectoryRequest,
    request_sha256: &str,
    operation_id: &str,
    filesystem_id: &str,
    parent_directory_id: &str,
    child_directory_id: &str,
    crypto_suite: &str,
    empty_root: &str,
    envelope: Option<&SealedEnvelope>,
    plan: &RootPlan,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    let mut statements = vec![
        database
            .prepare(
                "INSERT INTO vfs_directory_create_intents (
                     id, filesystem_id, principal_id, token_id,
                     parent_directory_id, child_directory_id, name,
                     crypto_suite, request_sha256, idempotency_key, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(filesystem_id),
                JsValue::from_str(&token.principal_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(parent_directory_id),
                JsValue::from_str(child_directory_id),
                JsValue::from_str(&requested.name),
                JsValue::from_str(crypto_suite),
                JsValue::from_str(request_sha256),
                JsValue::from_str(&requested.idempotency_key),
                number_binding(now),
            ])?,
    ];

    for (ordinal, update) in plan.directories.iter().enumerate() {
        statements.push(
            database
                .prepare(
                    "INSERT INTO vfs_directory_create_updates (
                         intent_id, ordinal, directory_id, expected_revision,
                         expected_data_root, new_data_root
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .bind(&[
                    JsValue::from_str(operation_id),
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

    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_directories (
                     id, filesystem_id, parent_id, name, data_root, crypto_suite,
                     active_key_epoch, acl_inherits, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1, ?7, ?7)",
            )
            .bind(&[
                JsValue::from_str(child_directory_id),
                JsValue::from_str(filesystem_id),
                JsValue::from_str(parent_directory_id),
                JsValue::from_str(&requested.name),
                JsValue::from_str(empty_root),
                JsValue::from_str(crypto_suite),
                number_binding(now),
            ])?,
    );
    statements.push(directory_key_statement(
        database,
        child_directory_id,
        &token.principal_id,
        crypto_suite,
        envelope,
        now,
    )?);
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_directory_drivers (
                     directory_id, driver_id, write_priority, state, created_by,
                     created_at, updated_at
                 )
                 SELECT ?1, driver_id, write_priority, 'active', ?2, ?3, ?3
                 FROM vfs_directory_drivers
                 WHERE directory_id = ?4 AND state = 'active'",
            )
            .bind(&[
                JsValue::from_str(child_directory_id),
                JsValue::from_str(&token.principal_id),
                number_binding(now),
                JsValue::from_str(parent_directory_id),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_directory_entries (
                     directory_id, name, kind, child_directory_id, size_bytes,
                     data_root, metadata_root, created_at, updated_at
                 ) VALUES (?1, ?2, 'directory', ?3, 0, ?4, NULL, ?5, ?5)",
            )
            .bind(&[
                JsValue::from_str(parent_directory_id),
                JsValue::from_str(&requested.name),
                JsValue::from_str(child_directory_id),
                JsValue::from_str(empty_root),
                number_binding(now),
            ])?,
    );

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

    statements.extend(catalog_statements(
        database,
        filesystem_id,
        operation_id,
        &plan.root,
        now,
    )?);
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_directory_create_receipts (
                     intent_id, token_id, request_sha256, filesystem_id,
                     parent_directory_id, directory_id, name, data_root,
                     crypto_suite, key_epoch, catalog_revision_id, created_at
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, catalog.id, ?10
                 FROM vfs_catalog_revisions AS catalog
                 WHERE catalog.mutation_kind = 'mkdir' AND catalog.mutation_id = ?1",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(request_sha256),
                JsValue::from_str(filesystem_id),
                JsValue::from_str(parent_directory_id),
                JsValue::from_str(child_directory_id),
                JsValue::from_str(&requested.name),
                JsValue::from_str(empty_root),
                JsValue::from_str(crypto_suite),
                number_binding(now),
            ])?,
    );
    let audit_details = serde_json::json!({
        "crypto_suite": crypto_suite,
        "name": requested.name,
        "parent_directory_id": parent_directory_id,
    })
    .to_string();
    statements.push(
        database
            .prepare(
                "INSERT INTO vfs_audit_events (
                     filesystem_id, principal_id, token_id, event_kind,
                     subject_kind, subject_id, details_json, created_at
                 ) VALUES (?1, ?2, ?3, 'directory_created', 'directory', ?4, ?5, ?6)",
            )
            .bind(&[
                JsValue::from_str(filesystem_id),
                JsValue::from_str(&token.principal_id),
                JsValue::from_str(&token.id),
                JsValue::from_str(child_directory_id),
                JsValue::from_str(&audit_details),
                number_binding(now),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE vfs_directory_create_intents
                 SET state = 'committed', committed_at = ?1, revision = revision + 1
                 WHERE id = ?2 AND state = 'prepared' AND revision = 1",
            )
            .bind(&[number_binding(now), JsValue::from_str(operation_id)])?,
    );

    Ok(statements)
}

fn directory_key_statement(
    database: &D1Database,
    directory_id: &str,
    principal_id: &str,
    crypto_suite: &str,
    envelope: Option<&SealedEnvelope>,
    now: u64,
) -> Result<D1PreparedStatement> {
    if crypto_suite == PLAINTEXT_SUITE {
        return database
            .prepare(
                "INSERT INTO vfs_directory_key_epochs (
                     directory_id, key_epoch, crypto_suite, created_by, created_at
                 ) VALUES (?1, 1, ?2, ?3, ?4)",
            )
            .bind(&[
                JsValue::from_str(directory_id),
                JsValue::from_str(crypto_suite),
                JsValue::from_str(principal_id),
                number_binding(now),
            ]);
    }

    let envelope = envelope.ok_or_else(|| {
        worker::Error::RustError("encrypted VFS directory omitted its key envelope".to_owned())
    })?;
    database
        .prepare(
            "INSERT INTO vfs_directory_key_epochs (
                 directory_id, key_epoch, crypto_suite, envelope_algorithm,
                 master_key_version, nonce, ciphertext, created_by, created_at
             ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(crypto_suite),
            JsValue::from_str(ENVELOPE_ALGORITHM),
            JsValue::from_str(MASTER_KEY_VERSION),
            blob_binding(&envelope.nonce),
            blob_binding(&envelope.ciphertext),
            JsValue::from_str(principal_id),
            number_binding(now),
        ])
}

fn catalog_statements(
    database: &D1Database,
    filesystem_id: &str,
    operation_id: &str,
    root: &str,
    now: u64,
) -> Result<Vec<D1PreparedStatement>> {
    Ok(vec![
        database
            .prepare(
                "INSERT INTO vfs_catalog_revisions (
                     filesystem_id, parent_revision_id, root_data_root, state,
                     created_at, mutation_kind, mutation_id
                 ) VALUES (
                     ?1,
                     (SELECT revision_id FROM vfs_catalog_mutation_heads
                      WHERE filesystem_id = ?1),
                     ?2, 'pending', ?3, 'mkdir', ?4
                 )",
            )
            .bind(&[
                JsValue::from_str(filesystem_id),
                JsValue::from_str(root),
                number_binding(now),
                JsValue::from_str(operation_id),
            ])?,
        database
            .prepare(
                "INSERT INTO vfs_catalog_outbox (revision_id, updated_at)
                 SELECT id, ?1 FROM vfs_catalog_revisions
                 WHERE mutation_kind = 'mkdir' AND mutation_id = ?2",
            )
            .bind(&[number_binding(now), JsValue::from_str(operation_id)])?,
        database
            .prepare(
                "INSERT INTO vfs_catalog_mutation_heads (
                     filesystem_id, revision_id, updated_at
                 )
                 SELECT filesystem_id, id, ?1
                 FROM vfs_catalog_revisions
                 WHERE mutation_kind = 'mkdir' AND mutation_id = ?2
                 ON CONFLICT(filesystem_id) DO UPDATE SET
                     revision_id = excluded.revision_id,
                     revision = vfs_catalog_mutation_heads.revision + 1,
                     updated_at = excluded.updated_at",
            )
            .bind(&[number_binding(now), JsValue::from_str(operation_id)])?,
    ])
}

async fn load_parent(
    database: &D1Database,
    directory_id: &str,
) -> Result<Option<ParentDirectoryRow>> {
    database
        .prepare(
            "SELECT filesystem_id, crypto_suite FROM vfs_directories
             WHERE id = ?1 AND state = 'active'",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<ParentDirectoryRow>(None)
        .await
}

async fn has_enabled_placement(database: &D1Database, directory_id: &str) -> Result<bool> {
    let row = database
        .prepare(
            "SELECT EXISTS (
                 SELECT 1
                 FROM vfs_directory_drivers AS placement
                 JOIN driver_instances AS driver ON driver.id = placement.driver_id
                 WHERE placement.directory_id = ?1
                   AND placement.state = 'active'
                   AND driver.enabled = 1
             ) AS present",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<ExistsRow>(None)
        .await?;
    Ok(row.is_some_and(|result| result.present == 1))
}

async fn load_receipt(
    database: &D1Database,
    token_id: &str,
    idempotency_key: &str,
) -> Result<Option<CreateDirectoryReceiptRow>> {
    database
        .prepare(
            "SELECT receipt.intent_id, receipt.request_sha256,
                    receipt.filesystem_id, receipt.parent_directory_id,
                    receipt.directory_id, receipt.name, receipt.data_root,
                    receipt.crypto_suite, receipt.key_epoch,
                    receipt.catalog_revision_id, receipt.created_at
             FROM vfs_directory_create_receipts AS receipt
             JOIN vfs_directory_create_intents AS intent ON intent.id = receipt.intent_id
             WHERE intent.token_id = ?1 AND intent.idempotency_key = ?2
               AND intent.state = 'committed'",
        )
        .bind(&[
            JsValue::from_str(token_id),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<CreateDirectoryReceiptRow>(None)
        .await
}

fn receipt_response(receipt: CreateDirectoryReceiptRow, request_sha256: &str) -> Result<Response> {
    if receipt.request_sha256 != request_sha256 {
        return Response::error("VFS mkdir idempotency key already has another request", 409);
    }
    let mut response = Response::from_json(&CreateDirectoryResponse {
        schema: DIRECTORY_CREATE_SCHEMA,
        operation_id: receipt.intent_id,
        filesystem_id: receipt.filesystem_id,
        parent_directory_id: receipt.parent_directory_id,
        directory_id: receipt.directory_id,
        name: receipt.name,
        data_root: receipt.data_root,
        crypto_suite: receipt.crypto_suite,
        key_epoch: receipt.key_epoch,
        catalog_revision_id: receipt.catalog_revision_id,
        created_at: receipt.created_at,
        state: "committed",
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn valid_request(request: &CreateDirectoryRequest) -> bool {
    valid_name(&request.name)
        && request
            .crypto_suite
            .as_deref()
            .is_none_or(|suite| matches!(suite, ENCRYPTED_SUITE | PLAINTEXT_SUITE))
        && valid_string(&request.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES)
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= MAXIMUM_NAME_BYTES
        && !value.contains('/')
        && !value.contains('\0')
        && value.nfc().eq(value.chars())
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn request_identity(identity: &CreateDirectoryIdentity<'_>) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(identity)?;
    let mut hasher = Sha256::new();
    hasher.update(b"carrack.vfs.directory-create.v1\0");
    hasher.update(encoded);
    Ok(hasher.finalize().into())
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

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_requires_canonical_name() {
        let request = CreateDirectoryRequest {
            name: "releases".to_owned(),
            crypto_suite: None,
            idempotency_key: "mkdir-releases-v1".to_owned(),
        };
        assert!(valid_request(&request));

        let decomposed = CreateDirectoryRequest {
            name: "e\u{301}".to_owned(),
            ..request
        };
        assert!(!valid_request(&decomposed));
    }
}
