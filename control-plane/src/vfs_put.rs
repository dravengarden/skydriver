use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use worker::{D1Database, Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{
    vfs_identifiers::{new_storage_key, new_uuid_v7_hex},
    vfs_tokens::AuthenticatedVfsToken,
};

const PREPARATION_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
const MAXIMUM_FILE_BLOCKS: u64 = 1_000_000;
const MAXIMUM_NAME_BYTES: usize = 255;
const MAXIMUM_IDEMPOTENCY_BYTES: usize = 256;
const MAXIMUM_DRIVER_ID_BYTES: usize = 256;
const MAXIMUM_D1_REVISION: u64 = 9_223_372_036_854_775_807;
const PUT_PREPARATION_SCHEMA: &str = "carrack.vfs.put-preparation.v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    directory_id: String,
    entry_name: String,
    expected_entry_revision: u64,
    plaintext_bytes: u64,
    verification_block_bytes: u64,
    verification_block_count: u64,
    file_root: String,
    metadata_root: String,
    block_manifest_sha256: String,
    block_manifest_bytes: u64,
    encryption_frame_bytes: u64,
    preferred_driver_id: Option<String>,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct PutContextRow {
    filesystem_id: String,
    crypto_suite: String,
    key_epoch: u64,
    driver_id: String,
}

#[derive(Deserialize)]
struct EntryRow {
    kind: String,
    file_id: Option<String>,
    version_id: Option<String>,
    entry_revision: u64,
    file_revision: Option<u64>,
    current_version_id: Option<String>,
}

#[derive(Deserialize)]
struct PutIntentRow {
    id: String,
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
    request_sha256: String,
    state: String,
    expires_at: u64,
}

#[derive(Serialize)]
struct PrepareResponse {
    schema: &'static str,
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

/// Prepares one immutable complete-object VFS upload without performing payload I/O.
///
/// The request fixes the plaintext integrity identity and optimistic entry
/// precondition. The control plane selects an authorized directory driver,
/// allocates `UUIDv7` metadata identities and a separate random 192-bit provider
/// key, and records an idempotent expiring intent. Transfer and provider
/// verification happen outside D1; commit reauthorizes independently.
pub(crate) async fn prepare(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    let requested = request.json::<PrepareRequest>().await?;
    if !valid_prepare_request(&requested) {
        return Response::error("invalid VFS put preparation", 400);
    }

    let database = env.d1("SKYDRIVER_INDEX")?;
    let request_sha256 = request_identity(&requested)?;
    let existing = load_intent(
        &database,
        &token.principal_id,
        &requested.directory_id,
        &requested.idempotency_key,
    )
    .await?;
    let requested_driver = existing
        .as_ref()
        .map(|intent| intent.driver_id.as_str())
        .or(requested.preferred_driver_id.as_deref());
    let Some(context) =
        authorize_context(&database, token, &requested.directory_id, requested_driver).await?
    else {
        return Response::error("VFS put preparation is not authorized", 403);
    };

    if let Some(intent) = existing {
        return replay_response(intent, &request_sha256);
    }

    let current_entry =
        load_entry(&database, &requested.directory_id, &requested.entry_name).await?;
    let (file_id, expected_file_revision, expected_current_version_id) = match current_entry {
        None if requested.expected_entry_revision == 0 => (new_uuid_v7_hex()?, 0, None),
        Some(entry)
            if requested.expected_entry_revision > 0
                && entry.kind == "file"
                && entry.entry_revision == requested.expected_entry_revision
                && entry.file_id.is_some()
                && entry.version_id.is_some()
                && entry.version_id == entry.current_version_id
                && entry.file_revision.is_some() =>
        {
            (
                entry.file_id.expect("checked file identity"),
                entry.file_revision.expect("checked file revision"),
                entry.current_version_id,
            )
        }
        _ => return Response::error("VFS entry precondition changed", 409),
    };

    let intent_id = new_uuid_v7_hex()?;
    let version_id = new_uuid_v7_hex()?;
    let location_id = new_uuid_v7_hex()?;
    let storage_key = new_storage_key()?;
    let block_manifest_r2_key = format!(
        "vfs/blocks/v1/{}/{}",
        &requested.block_manifest_sha256[..2],
        requested.block_manifest_sha256
    );
    let now = current_unix_seconds();
    let expires_at = now
        .checked_add(PREPARATION_LIFETIME_SECONDS)
        .ok_or_else(|| worker::Error::RustError("VFS put expiry overflows".to_owned()))?;
    let insert_result = insert_intent(
        &database,
        token,
        &requested,
        &context,
        &request_sha256,
        &intent_id,
        &file_id,
        expected_file_revision,
        expected_current_version_id.as_deref(),
        &version_id,
        &location_id,
        &storage_key,
        &block_manifest_r2_key,
        now,
        expires_at,
    )
    .await;

    let intent = load_intent(
        &database,
        &token.principal_id,
        &requested.directory_id,
        &requested.idempotency_key,
    )
    .await?;
    let Some(intent) = intent else {
        if insert_result.is_err() {
            return Response::error("VFS put preparation lost its precondition", 409);
        }
        return Response::error("VFS put preparation was not recorded", 409);
    };

    replay_response(intent, &request_sha256)
}

async fn authorize_context(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
    requested_driver: Option<&str>,
) -> Result<Option<PutContextRow>> {
    database
        .prepare(
            "WITH RECURSIVE
             ancestors(id, parent_id) AS (
                 SELECT id, parent_id FROM vfs_directories WHERE id = ?1
                 UNION
                 SELECT parent.id, parent.parent_id
                 FROM vfs_directories AS parent
                 JOIN ancestors AS child ON child.parent_id = parent.id
             ),
             acl_directories(id, parent_id, acl_inherits) AS (
                 SELECT id, parent_id, acl_inherits
                 FROM vfs_directories WHERE id = ?1
                 UNION
                 SELECT parent.id, parent.parent_id, parent.acl_inherits
                 FROM vfs_directories AS parent
                 JOIN acl_directories AS child ON child.parent_id = parent.id
                 WHERE child.acl_inherits = 1
             )
             SELECT directory.filesystem_id, directory.crypto_suite,
                    directory.active_key_epoch AS key_epoch,
                    placement.driver_id
             FROM vfs_directories AS directory
             JOIN vfs_directory_drivers AS placement
               ON placement.directory_id = directory.id
             JOIN driver_instances AS driver ON driver.id = placement.driver_id
             JOIN vfs_token_verifiers AS verifier ON verifier.id = ?2
             JOIN vfs_principals AS principal ON principal.id = verifier.principal_id
             WHERE directory.id = ?1
               AND directory.state = 'active'
               AND directory.crypto_suite IN ('plaintext/v1', 'carrack-vfs-aes256gcm-hkdfsha256-v1')
               AND placement.state = 'active'
               AND driver.enabled = 1
               AND verifier.principal_id = ?3
               AND verifier.sealed_at IS NOT NULL
               AND verifier.revoked_at IS NULL
               AND verifier.expires_at > unixepoch()
               AND verifier.snapshot_id IS NULL
               AND principal.state = 'active'
               AND (?4 IS NULL OR placement.driver_id = ?4)
               AND EXISTS (
                   SELECT 1 FROM ancestors WHERE id = verifier.root_directory_id
               )
               AND EXISTS (
                   SELECT 1 FROM vfs_token_actions
                   WHERE token_id = verifier.id AND action = 'content.write'
               )
               AND EXISTS (
                   SELECT 1 FROM vfs_token_actions
                   WHERE token_id = verifier.id AND action = 'driver.use'
               )
               AND (
                   NOT EXISTS (
                       SELECT 1 FROM vfs_token_drivers WHERE token_id = verifier.id
                   )
                   OR EXISTS (
                       SELECT 1 FROM vfs_token_drivers
                       WHERE token_id = verifier.id AND driver_id = placement.driver_id
                   )
               )
               AND (
                   SELECT COUNT(DISTINCT grant.action)
                   FROM vfs_acl_grants AS grant
                   WHERE grant.action IN ('content.write', 'driver.use')
                     AND grant.directory_id IN (SELECT id FROM acl_directories)
                     AND (
                         grant.principal_id = verifier.principal_id
                         OR EXISTS (
                             SELECT 1
                             FROM vfs_group_members AS membership
                             WHERE membership.group_id = grant.group_id
                               AND membership.principal_id = verifier.principal_id
                         )
                     )
               ) = 2
               AND (
                   directory.crypto_suite = 'plaintext/v1'
                   OR EXISTS (
                       SELECT 1
                       FROM vfs_directory_key_epochs AS key_epoch
                       WHERE key_epoch.directory_id = directory.id
                         AND key_epoch.key_epoch = directory.active_key_epoch
                         AND key_epoch.crypto_suite = directory.crypto_suite
                         AND key_epoch.state = 'available'
                   )
               )
             ORDER BY placement.write_priority, placement.driver_id
             LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&token.principal_id),
            requested_driver.map_or_else(JsValue::null, JsValue::from_str),
        ])?
        .first::<PutContextRow>(None)
        .await
}

pub(crate) async fn authorized(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
    driver_id: &str,
) -> Result<bool> {
    Ok(
        authorize_context(database, token, directory_id, Some(driver_id))
            .await?
            .is_some(),
    )
}

async fn load_entry(
    database: &D1Database,
    directory_id: &str,
    entry_name: &str,
) -> Result<Option<EntryRow>> {
    database
        .prepare(
            "SELECT entry.kind, entry.file_id, entry.version_id,
                    entry.revision AS entry_revision,
                    file.revision AS file_revision,
                    file.current_version_id
             FROM vfs_directory_entries AS entry
             LEFT JOIN vfs_files AS file ON file.id = entry.file_id
             WHERE entry.directory_id = ?1 AND entry.name = ?2",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(entry_name),
        ])?
        .first::<EntryRow>(None)
        .await
}

async fn load_intent(
    database: &D1Database,
    principal_id: &str,
    directory_id: &str,
    idempotency_key: &str,
) -> Result<Option<PutIntentRow>> {
    database
        .prepare(
            "SELECT id, filesystem_id, directory_id, entry_name,
                    expected_entry_revision, file_id, version_id, location_id,
                    driver_id, storage_key, block_manifest_r2_key, crypto_suite,
                    key_epoch, encryption_frame_bytes, request_sha256, state, expires_at
             FROM vfs_put_intents
             WHERE principal_id = ?1 AND directory_id = ?2 AND idempotency_key = ?3",
        )
        .bind(&[
            JsValue::from_str(principal_id),
            JsValue::from_str(directory_id),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<PutIntentRow>(None)
        .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the immutable put intent is bound visibly as one D1 protocol record"
)]
async fn insert_intent(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    requested: &PrepareRequest,
    context: &PutContextRow,
    request_sha256: &str,
    intent_id: &str,
    file_id: &str,
    expected_file_revision: u64,
    expected_current_version_id: Option<&str>,
    version_id: &str,
    location_id: &str,
    storage_key: &str,
    block_manifest_r2_key: &str,
    now: u64,
    expires_at: u64,
) -> Result<()> {
    let values = [
        JsValue::from_str(intent_id),
        JsValue::from_str(&context.filesystem_id),
        JsValue::from_str(&token.principal_id),
        JsValue::from_str(&token.id),
        JsValue::from_str(&requested.directory_id),
        JsValue::from_str(&requested.entry_name),
        number_binding(requested.expected_entry_revision),
        number_binding(expected_file_revision),
        expected_current_version_id.map_or_else(JsValue::null, JsValue::from_str),
        JsValue::from_str(file_id),
        JsValue::from_str(version_id),
        JsValue::from_str(location_id),
        JsValue::from_str(&context.driver_id),
        JsValue::from_str(storage_key),
        number_binding(requested.plaintext_bytes),
        number_binding(requested.verification_block_bytes),
        number_binding(requested.verification_block_count),
        JsValue::from_str(&requested.file_root),
        JsValue::from_str(&requested.metadata_root),
        JsValue::from_str(&requested.block_manifest_sha256),
        number_binding(requested.block_manifest_bytes),
        JsValue::from_str(block_manifest_r2_key),
        JsValue::from_str(&context.crypto_suite),
        number_binding(context.key_epoch),
        number_binding(requested.encryption_frame_bytes),
        JsValue::from_str(request_sha256),
        JsValue::from_str(&requested.idempotency_key),
        number_binding(expires_at),
        number_binding(now),
    ];
    database
        .prepare(
            "INSERT INTO vfs_put_intents (
                 id, filesystem_id, principal_id, token_id, directory_id, entry_name,
                 expected_entry_revision, expected_file_revision,
                 expected_current_version_id, file_id, version_id, location_id,
                 driver_id, storage_key, plaintext_bytes, verification_block_bytes,
                 verification_block_count, file_root, metadata_root,
                 block_manifest_sha256, block_manifest_bytes, block_manifest_r2_key,
                 crypto_suite, key_epoch, encryption_frame_bytes, request_sha256,
                 idempotency_key, expires_at, created_at
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                 ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                 ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29
             )
             ON CONFLICT(principal_id, directory_id, idempotency_key) DO NOTHING",
        )
        .bind(&values)?
        .run()
        .await?;
    Ok(())
}

fn replay_response(intent: PutIntentRow, request_sha256: &str) -> Result<Response> {
    if intent.request_sha256 != request_sha256 {
        return Response::error("idempotency key pins another VFS put", 409);
    }
    if !matches!(intent.state.as_str(), "prepared" | "committed") {
        return Response::error("VFS put intent is no longer resumable", 409);
    }

    Response::from_json(&PrepareResponse {
        schema: PUT_PREPARATION_SCHEMA,
        intent_id: intent.id,
        filesystem_id: intent.filesystem_id,
        directory_id: intent.directory_id,
        entry_name: intent.entry_name,
        expected_entry_revision: intent.expected_entry_revision,
        file_id: intent.file_id,
        version_id: intent.version_id,
        location_id: intent.location_id,
        driver_id: intent.driver_id,
        storage_key: intent.storage_key,
        block_manifest_r2_key: intent.block_manifest_r2_key,
        requires_encryption_key: intent.crypto_suite != "plaintext/v1",
        crypto_suite: intent.crypto_suite,
        key_epoch: intent.key_epoch,
        encryption_frame_bytes: intent.encryption_frame_bytes,
        state: intent.state,
        expires_at: intent.expires_at,
    })
}

fn valid_prepare_request(request: &PrepareRequest) -> bool {
    valid_identifier(&request.directory_id)
        && valid_name(&request.entry_name)
        && request.expected_entry_revision < MAXIMUM_D1_REVISION
        && valid_integer(request.plaintext_bytes)
        && request.verification_block_bytes > 0
        && valid_integer(request.verification_block_bytes)
        && request.verification_block_count
            == expected_block_count(request.plaintext_bytes, request.verification_block_bytes)
        && request.verification_block_count <= MAXIMUM_FILE_BLOCKS
        && valid_digest(&request.file_root)
        && valid_digest(&request.metadata_root)
        && valid_digest(&request.block_manifest_sha256)
        && request.block_manifest_bytes > 0
        && valid_integer(request.block_manifest_bytes)
        && request.encryption_frame_bytes > 0
        && request.encryption_frame_bytes <= request.verification_block_bytes
        && request
            .verification_block_bytes
            .is_multiple_of(request.encryption_frame_bytes)
        && valid_integer(request.encryption_frame_bytes)
        && request
            .preferred_driver_id
            .as_deref()
            .is_none_or(|driver| valid_string(driver, MAXIMUM_DRIVER_ID_BYTES))
        && valid_string(&request.idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES)
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
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

fn valid_integer(value: u64) -> bool {
    i64::try_from(value).is_ok()
}

fn expected_block_count(size_bytes: u64, block_bytes: u64) -> u64 {
    if size_bytes == 0 {
        0
    } else {
        1 + (size_bytes - 1) / block_bytes
    }
}

fn request_identity(request: &PrepareRequest) -> Result<String> {
    let encoded = serde_json::to_vec(request)?;
    let mut hasher = Sha256::new();
    hasher.update(b"carrack.vfs.put.prepare.v1\0");
    hasher.update(encoded);
    lowercase_hex(&hasher.finalize())
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

    fn valid_request() -> PrepareRequest {
        PrepareRequest {
            directory_id: "10000000000000000000000000000001".to_owned(),
            entry_name: "release.bin".to_owned(),
            expected_entry_revision: 0,
            plaintext_bytes: 10,
            verification_block_bytes: 4,
            verification_block_count: 3,
            file_root: "1".repeat(64),
            metadata_root: "2".repeat(64),
            block_manifest_sha256: "3".repeat(64),
            block_manifest_bytes: 128,
            encryption_frame_bytes: 4,
            preferred_driver_id: None,
            idempotency_key: "put-release-v1".to_owned(),
        }
    }

    #[test]
    fn validates_prepare_integrity_and_name_boundaries() {
        let request = valid_request();
        assert!(valid_prepare_request(&request));

        let decomposed = PrepareRequest {
            entry_name: "e\u{301}.txt".to_owned(),
            ..valid_request()
        };
        assert!(!valid_prepare_request(&decomposed));

        let wrong_blocks = PrepareRequest {
            verification_block_count: 2,
            ..valid_request()
        };
        assert!(!valid_prepare_request(&wrong_blocks));

        let misaligned_frame = PrepareRequest {
            encryption_frame_bytes: 3,
            ..valid_request()
        };
        assert!(!valid_prepare_request(&misaligned_frame));
    }

    #[test]
    fn request_identity_is_stable_and_covers_every_precondition() {
        let request = valid_request();
        let identity = request_identity(&request).expect("request identity");
        assert_eq!(
            identity,
            request_identity(&request).expect("repeat identity")
        );

        let changed = PrepareRequest {
            expected_entry_revision: 1,
            ..valid_request()
        };
        assert_ne!(
            identity,
            request_identity(&changed).expect("changed identity")
        );
    }
}
