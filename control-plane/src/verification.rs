use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, manifests};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    driver_id: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Deserialize)]
struct ManifestArchiveRow {
    manifest_sha256: String,
    recovery_sha256: Option<String>,
    r2_storage_key: String,
    r2_version: Option<String>,
    ciphertext_bytes: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct VerifyOperation {
    id: String,
    namespace_id: String,
    kind: String,
    state: String,
    phase: String,
    requested_by: String,
    incarnation: String,
    revision: u64,
    useful_bytes_total: u64,
    version_id: String,
    manifest_sha256: String,
    recovery_revision: u64,
    driver_id: String,
    created_at: u64,
    updated_at: u64,
}

#[allow(
    clippy::too_many_lines,
    reason = "the atomic operation, intent, and component creation protocol remains visible together"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_hex(&requested.namespace_id, 32)
        || !valid_hex(&requested.manifest_sha256, 64)
        || !valid_string(&requested.driver_id, 256)
        || !valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid verify operation", 400);
    }

    let operation_id = random_hex()?;
    let now = current_unix_seconds().to_string();
    let database = env.d1("CARRACK_INDEX")?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'verify', 'planned', 'planned', ?3, ?4, state.incarnation, \
                    (SELECT SUM(location.storage_length) \
                     FROM version_packs AS version_pack \
                     JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                     JOIN locations AS location ON location.extent_id = extent.id \
                     WHERE version_pack.version_id = version.id \
                       AND location.driver_id = ?5 AND location.state = 'available'), \
                    ?6, ?6 \
             FROM control_plane_state AS state \
             JOIN object_versions AS version ON version.manifest_sha256 = ?7 \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE state.singleton = 1 AND state.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                          WHERE recovery.version_id = version.id \
                            AND recovery.manifest_sha256 = version.manifest_sha256 \
                            AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL) \
               AND EXISTS(SELECT 1 FROM version_packs AS version_pack \
                          JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                          JOIN locations AS location ON location.extent_id = extent.id \
                          WHERE version_pack.version_id = version.id \
                            AND location.driver_id = ?5 AND location.state = 'available') \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role = 'administrator') \
             ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(&operation_id),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO verify_intents (\
                 operation_id, version_id, manifest_sha256, recovery_revision, driver_id, created_at\
             ) \
             SELECT operation.id, version.id, version.manifest_sha256, recovery.revision, ?1, ?2 \
             FROM operations AS operation \
             JOIN object_versions AS version ON version.manifest_sha256 = ?3 \
             JOIN recovery_manifests AS recovery ON recovery.version_id = version.id \
             WHERE operation.namespace_id = ?4 AND operation.idempotency_key = ?5 \
               AND operation.requested_by = ?6 AND operation.kind = 'verify'",
        )
        .bind(&[
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, source_driver_id, state, \
                 useful_bytes_total, created_at, updated_at\
             ) \
             SELECT operation.id || '/verify', operation.id, ?1, 'verify', intent.driver_id, \
                    'pending', operation.useful_bytes_total, ?2, ?2 \
             FROM operations AS operation \
             JOIN verify_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'verify'",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&now),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
        ])?;
    database
        .batch(vec![insert_operation, insert_intent, insert_component])
        .await?;

    let operation = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?;
    let Some(operation) = operation else {
        return Response::error("verify rejected or idempotency identity conflicts", 409);
    };
    if operation.manifest_sha256 != requested.manifest_sha256
        || operation.driver_id != requested.driver_id
    {
        return Response::error("idempotency key pins another verify target", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn fetch_manifest(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid verify operation ID", 400);
    }

    let requested = request.json::<ManifestRequest>().await?;
    if !valid_string(&requested.lease_id, 256)
        || !valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error("invalid verify manifest fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let archived = database
        .prepare(
            "SELECT intent.manifest_sha256, recovery.recovery_sha256, \
                    recovery.r2_storage_key, recovery.r2_version, recovery.ciphertext_bytes \
             FROM verify_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery \
               ON recovery.version_id = intent.version_id \
              AND recovery.manifest_sha256 = intent.manifest_sha256 \
              AND recovery.revision = intent.recovery_revision \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'verify' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND state.mode = 'active' \
               AND lease.incarnation = state.incarnation",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            JsValue::from_str(&requested.fencing_token.to_string()),
        ])?
        .first::<ManifestArchiveRow>(None)
        .await?;
    let Some(archived) = archived else {
        return Response::error("verify manifest fence is stale or unavailable", 409);
    };

    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let Some(object) = bucket.get(&archived.r2_storage_key).execute().await? else {
        return Response::error("durable recovery manifest is missing", 503);
    };
    if archived
        .r2_version
        .as_ref()
        .is_some_and(|version| version.as_str() != object.version().as_str())
    {
        return Response::error("durable recovery manifest version changed", 503);
    }
    if object.size() != archived.ciphertext_bytes {
        return Response::error("durable recovery manifest size changed", 503);
    }
    let Some(body) = object.body() else {
        return Response::error("durable recovery manifest body is missing", 503);
    };
    let encoded = body.bytes().await?;
    if archived
        .recovery_sha256
        .as_ref()
        .is_some_and(|expected| expected != &lowercase_hex(&Sha256::digest(&encoded)))
    {
        return Response::error("durable recovery manifest hash changed", 503);
    }
    let Ok(validated) = manifests::validate(&encoded) else {
        return Response::error("durable recovery manifest is corrupt", 503);
    };
    if validated.manifest_sha256 != archived.manifest_sha256 {
        return Response::error("durable recovery manifest identity changed", 503);
    }

    let mut response = Response::from_bytes(encoded)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("ETag", &format!("\"{}\"", archived.manifest_sha256))?;

    Ok(response)
}

async fn find_operation(
    database: &worker::D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<VerifyOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, intent.version_id, \
                    intent.manifest_sha256, intent.recovery_revision, intent.driver_id, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN verify_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'verify'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<VerifyOperation>(None)
        .await
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate verify ID: {error}")))?;

    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

fn valid_hex(value: &str, characters: usize) -> bool {
    value.len() == characters
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{valid_hex, valid_string};

    #[test]
    fn validates_verify_operation_boundaries() {
        assert!(valid_hex("0123456789abcdef0123456789abcdef", 32));
        assert!(!valid_hex("0123456789ABCDEF0123456789ABCDEF", 32));
        assert!(valid_string("driver-1", 256));
        assert!(!valid_string(" driver-1", 256));
    }
}
