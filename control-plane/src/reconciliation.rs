use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    manifest_sha256: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Deserialize, Serialize)]
struct ReconcileOperation {
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
    minimum_available_replicas: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct SnapshotHead {
    manifest_sha256: String,
    recovery_sha256: Option<String>,
    recovery_revision: u64,
    r2_storage_key: String,
    r2_version: Option<String>,
    recovery_bytes: u64,
    minimum_available_replicas: u64,
}

#[derive(Deserialize, Serialize)]
struct IndexedLocation {
    id: String,
    extent_sha256: String,
    driver_id: String,
    storage_key: String,
    provider_version: Option<String>,
    offset: u64,
    length: u64,
    state: String,
}

#[derive(Serialize)]
struct ReconcileSnapshot {
    recovery: serde_json::Value,
    recovery_revision: u64,
    minimum_available_replicas: u64,
    locations: Vec<IndexedLocation>,
}

#[allow(
    clippy::too_many_lines,
    reason = "operation, pinned intent, and component creation remain one visible protocol"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_hex(&requested.namespace_id, 32)
        || !valid_hex(&requested.manifest_sha256, 64)
        || !valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid reconcile operation", 400);
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
             SELECT ?1, ?2, 'reconcile', 'planned', 'planned', ?3, ?4, \
                    control.incarnation, \
                    (SELECT COUNT(*) FROM version_packs AS version_pack \
                     JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
                     JOIN locations AS location ON location.extent_id = extent.id \
                     WHERE version_pack.version_id = version.id), ?5, ?5 \
             FROM control_plane_state AS control \
             JOIN object_versions AS version ON version.manifest_sha256 = ?6 \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN namespaces AS namespace ON namespace.id = object.namespace_id \
             WHERE control.singleton = 1 AND control.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND COALESCE(json_extract(namespace.replica_policy_json, \
                                         '$.minimum_available_replicas'), 1) BETWEEN 1 AND 64 \
               AND EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                          WHERE recovery.version_id = version.id \
                            AND recovery.manifest_sha256 = version.manifest_sha256 \
                            AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL) \
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
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO reconcile_intents (\
                 operation_id, version_id, manifest_sha256, recovery_revision, \
                 minimum_available_replicas, created_at\
             ) \
             SELECT operation.id, version.id, version.manifest_sha256, recovery.revision, \
                    COALESCE(json_extract(namespace.replica_policy_json, \
                                          '$.minimum_available_replicas'), 1), ?1 \
             FROM operations AS operation \
             JOIN object_versions AS version ON version.manifest_sha256 = ?2 \
             JOIN objects AS object ON object.id = version.object_id \
             JOIN namespaces AS namespace ON namespace.id = object.namespace_id \
             JOIN recovery_manifests AS recovery ON recovery.version_id = version.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?5 AND operation.kind = 'reconcile'",
        )
        .bind(&[
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    let insert_component = database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, state, useful_bytes_total, \
                 created_at, updated_at\
             ) \
             SELECT operation.id || '/reconcile', operation.id, ?1, 'reconcile', 'pending', \
                    operation.useful_bytes_total, ?2, ?2 \
             FROM operations AS operation \
             JOIN reconcile_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'reconcile'",
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
        return Response::error("reconcile rejected or idempotency identity conflicts", 409);
    };
    if operation.manifest_sha256 != requested.manifest_sha256 {
        return Response::error("idempotency key pins another reconcile target", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn fetch_snapshot(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid reconcile operation ID", 400);
    }
    let requested = request.json::<SnapshotRequest>().await?;
    if !valid_string(&requested.lease_id, 256)
        || !valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
    {
        return Response::error("invalid reconcile snapshot fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let head = load_snapshot_head(&database, operation_id, client, &requested).await?;
    let Some(head) = head else {
        return Response::error("reconcile snapshot fence is stale or unavailable", 409);
    };
    let loaded = copying::load_recovery(
        env,
        &head.r2_storage_key,
        head.r2_version.as_deref(),
        head.recovery_bytes,
    )
    .await?;
    if loaded.validated.manifest_sha256 != head.manifest_sha256
        || head
            .recovery_sha256
            .as_ref()
            .is_some_and(|digest| digest != &loaded.recovery_sha256)
    {
        return Response::error("reconcile recovery identity changed", 503);
    }
    let recovery = serde_json::from_slice::<serde_json::Value>(&loaded.encoded)?;
    let locations = load_indexed_locations(&database, operation_id).await?;

    Response::from_json(&ReconcileSnapshot {
        recovery,
        recovery_revision: head.recovery_revision,
        minimum_available_replicas: head.minimum_available_replicas,
        locations,
    })
}

async fn load_snapshot_head(
    database: &worker::D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &SnapshotRequest,
) -> Result<Option<SnapshotHead>> {
    database
        .prepare(
            "SELECT intent.manifest_sha256, recovery.recovery_sha256, \
                    intent.recovery_revision, recovery.r2_storage_key, recovery.r2_version, \
                    recovery.ciphertext_bytes AS recovery_bytes, \
                    intent.minimum_available_replicas \
             FROM reconcile_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN recovery_manifests AS recovery ON recovery.version_id = intent.version_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'reconcile' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND recovery.manifest_sha256 = intent.manifest_sha256 \
               AND recovery.revision = intent.recovery_revision \
               AND recovery.state = 'durable' AND recovery.verified_at IS NOT NULL \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND lease.incarnation = control.incarnation \
               AND control.mode = 'active'",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            JsValue::from_str(&requested.fencing_token.to_string()),
        ])?
        .first::<SnapshotHead>(None)
        .await
}

async fn load_indexed_locations(
    database: &worker::D1Database,
    operation_id: &str,
) -> Result<Vec<IndexedLocation>> {
    database
        .prepare(
            "SELECT location.id, extent.ciphertext_sha256 AS extent_sha256, \
                    location.driver_id, location.storage_key, location.provider_version, \
                    location.storage_offset AS offset, location.storage_length AS length, \
                    location.state \
             FROM reconcile_intents AS intent \
             JOIN version_packs AS version_pack ON version_pack.version_id = intent.version_id \
             JOIN extents AS extent ON extent.pack_id = version_pack.pack_id \
             JOIN locations AS location ON location.extent_id = extent.id \
             WHERE intent.operation_id = ?1 ORDER BY location.id",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .all()
        .await?
        .results::<IndexedLocation>()
}

async fn find_operation(
    database: &worker::D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<ReconcileOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, intent.version_id, \
                    intent.manifest_sha256, intent.recovery_revision, \
                    intent.minimum_available_replicas, operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN reconcile_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'reconcile'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<ReconcileOperation>(None)
        .await
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate reconcile ID: {error}")))?;
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
