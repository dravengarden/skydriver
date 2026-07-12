use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::clients::AuthenticatedClient;

const DEFAULT_LEASE_SECONDS: u64 = 60;
const MINIMUM_LEASE_SECONDS: u64 = 15;
const MAXIMUM_LEASE_SECONDS: u64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    idempotency_key: String,
    useful_bytes_total: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    lease_seconds: Option<u64>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct OperationRow {
    pub(crate) id: String,
    pub(crate) namespace_id: String,
    pub(crate) kind: String,
    pub(crate) state: String,
    pub(crate) phase: String,
    pub(crate) requested_by: String,
    pub(crate) incarnation: String,
    pub(crate) revision: u64,
    pub(crate) useful_bytes_total: Option<u64>,
    pub(crate) root_version: u32,
    pub(crate) key_epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) published_object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) published_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) published_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) published_destination_driver_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) published_sidecar_storage_key: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct LeaseRow {
    pub(crate) operation_id: String,
    pub(crate) lease_id: String,
    pub(crate) owner_client_id: String,
    pub(crate) incarnation: String,
    pub(crate) fencing_token: u64,
    pub(crate) expires_at: u64,
    pub(crate) operation_revision: u64,
    pub(crate) operation_state: String,
}

pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_identifier(&requested.namespace_id)
        || !valid_string(&requested.idempotency_key, 256)
        || requested
            .useful_bytes_total
            .is_some_and(|value| value > i64::MAX.unsigned_abs())
    {
        return Response::error("invalid import operation", 400);
    }

    let operation_id = random_hex()?;
    let now = current_unix_seconds().to_string();
    let total = requested.useful_bytes_total.map(|value| value.to_string());
    let database = env.d1("CARRACK_INDEX")?;
    let create_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, ?2, 'import', 'planned', 'planned', ?3, ?4, \
                    state.incarnation, ?5, ?6, ?6 \
             FROM control_plane_state AS state \
             WHERE state.singleton = 1 AND state.mode = 'active' \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role IN ('importer', 'administrator')) \
             ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(&operation_id),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            total
                .as_deref()
                .map_or_else(JsValue::null, JsValue::from_str),
            JsValue::from_str(&now),
        ])?;

    let pin_crypto_context = database
        .prepare(
            "INSERT OR IGNORE INTO import_intents (\
                 operation_id, root_key_version, key_epoch, created_at\
             ) \
             SELECT operation.id, namespace.root_key_version, namespace.active_key_epoch, \
                    operation.created_at \
             FROM operations AS operation \
             JOIN namespaces AS namespace ON namespace.id = operation.namespace_id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'import'",
        )
        .bind(&[
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;

    database
        .batch(vec![create_operation, pin_crypto_context])
        .await?;

    let operation = database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, \
                    intent.root_key_version AS root_version, intent.key_epoch, \
                    publication.object_id AS published_object_id, \
                    publication.generation AS published_generation, \
                    publication.manifest_sha256 AS published_manifest_sha256, \
                    publication.sidecar_driver_id AS published_destination_driver_id, \
                    publication.sidecar_storage_key AS published_sidecar_storage_key, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN import_intents AS intent ON intent.operation_id = operation.id \
             LEFT JOIN publication_intents AS publication \
               ON publication.operation_id = operation.id AND publication.state = 'committed' \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3",
        )
        .bind(&[
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?
        .first::<OperationRow>(None)
        .await?;

    let Some(operation) = operation else {
        return Response::error(
            "operation rejected or idempotency key belongs to another client",
            409,
        );
    };
    if operation.useful_bytes_total != requested.useful_bytes_total {
        return Response::error("import idempotency key owns a different source size", 409);
    }

    ensure_transfer_component(&database, &operation).await?;

    Response::from_json(&operation)
}

async fn ensure_transfer_component(
    database: &worker::D1Database,
    operation: &OperationRow,
) -> Result<()> {
    let component_id = format!("{}/transfer", operation.id);
    let total = operation.useful_bytes_total.map(|value| value.to_string());
    database
        .prepare(
            "INSERT OR IGNORE INTO operation_components (\
                 id, operation_id, client_id, component_kind, state, useful_bytes_total, \
                 created_at, updated_at\
             ) VALUES (?1, ?2, ?3, 'transfer', 'pending', ?4, ?5, ?5)",
        )
        .bind(&[
            JsValue::from_str(&component_id),
            JsValue::from_str(&operation.id),
            JsValue::from_str(&operation.requested_by),
            total
                .as_deref()
                .map_or_else(JsValue::null, JsValue::from_str),
            JsValue::from_str(&operation.created_at.to_string()),
        ])?
        .run()
        .await?;

    Ok(())
}

pub(crate) async fn claim(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_string(operation_id, 128) {
        return Response::error("invalid operation ID", 400);
    }

    let requested = request.json::<ClaimRequest>().await?;
    let lease_seconds = requested.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !(MINIMUM_LEASE_SECONDS..=MAXIMUM_LEASE_SECONDS).contains(&lease_seconds) {
        return Response::error("lease duration is out of range", 400);
    }

    let now = current_unix_seconds();
    let claim = ClaimBindings {
        lease_id: format!("operation/{operation_id}/write"),
        client_id: client.id.clone(),
        operation_id: operation_id.to_owned(),
        now: now.to_string(),
        expiry: (now + lease_seconds).to_string(),
    };
    let database = env.d1("CARRACK_INDEX")?;
    let mut statements = lease_statements(&database, &claim)?;
    statements.extend(attempt_statements(&database, &claim)?);
    database.batch(statements).await?;

    let lease = database
        .prepare(
            "SELECT operation.id AS operation_id, lease.id AS lease_id, \
                    lease.owner_client_id, lease.incarnation, lease.fencing_token, \
                    lease.expires_at, operation.revision AS operation_revision, \
                    operation.state AS operation_state \
             FROM leases AS lease \
             JOIN operations AS operation ON operation.id = lease.operation_id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE lease.id = ?1 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = state.incarnation AND state.mode = 'active' \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch()",
        )
        .bind(&[
            JsValue::from_str(&claim.lease_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<LeaseRow>(None)
        .await?;

    match lease {
        Some(value) => Response::from_json(&value),
        None => Response::error("operation is unavailable or leased by another client", 409),
    }
}

struct ClaimBindings {
    lease_id: String,
    client_id: String,
    operation_id: String,
    now: String,
    expiry: String,
}

fn lease_statements(
    database: &worker::D1Database,
    claim: &ClaimBindings,
) -> Result<Vec<worker::D1PreparedStatement>> {
    let lease_upsert = database
        .prepare(
            "INSERT INTO leases (\
                 id, resource_kind, resource_id, lease_kind, owner_client_id, operation_id, \
                 fencing_token, incarnation, expires_at, created_at, updated_at\
             ) \
             SELECT ?1, 'operation', operation.id, 'write', ?2, operation.id, 1, \
                    state.incarnation, ?3, ?4, ?4 \
             FROM operations AS operation \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE operation.id = ?5 \
               AND operation.kind IN ('import', 'copy', 'move', 'verify', 'reconcile') \
               AND operation.state IN ('planned', 'running') AND state.mode = 'active' \
               AND operation.incarnation = state.incarnation \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?2 AND namespace_id = operation.namespace_id \
                            AND (role = 'administrator' \
                                 OR (operation.kind = 'import' AND role = 'importer') \
                                 OR (operation.kind IN ('copy', 'move') AND role = 'relay') \
                                 OR (operation.kind IN ('verify', 'reconcile') \
                                     AND role = 'administrator'))) \
             ON CONFLICT(resource_kind, resource_id, lease_kind) DO UPDATE SET \
                 id = excluded.id, owner_client_id = excluded.owner_client_id, \
                 operation_id = excluded.operation_id, \
                 fencing_token = CASE \
                     WHEN leases.owner_client_id = excluded.owner_client_id \
                      AND leases.incarnation = excluded.incarnation \
                      AND leases.released_at IS NULL AND leases.expires_at > ?4 \
                     THEN leases.fencing_token ELSE leases.fencing_token + 1 END, \
                 incarnation = excluded.incarnation, expires_at = excluded.expires_at, \
                 released_at = NULL, updated_at = excluded.updated_at \
             WHERE (leases.owner_client_id = excluded.owner_client_id \
                    AND leases.incarnation = excluded.incarnation \
                    AND leases.released_at IS NULL AND leases.expires_at > ?4) \
                OR leases.released_at IS NOT NULL OR leases.expires_at <= ?4 \
                OR leases.incarnation != excluded.incarnation",
        )
        .bind(&[
            JsValue::from_str(&claim.lease_id),
            JsValue::from_str(&claim.client_id),
            JsValue::from_str(&claim.expiry),
            JsValue::from_str(&claim.now),
            JsValue::from_str(&claim.operation_id),
        ])?;
    let start_operation = database
        .prepare(
            "UPDATE operations \
             SET state = 'running', \
                 phase = CASE \
                     WHEN kind = 'verify' THEN 'verifying' \
                     WHEN kind = 'reconcile' THEN 'reconciling' \
                     ELSE 'transferring' END, \
                 revision = revision + CASE WHEN state = 'planned' THEN 1 ELSE 0 END, \
                 started_at = COALESCE(started_at, ?1), updated_at = ?1 \
             WHERE id = ?2 AND state IN ('planned', 'running') \
               AND EXISTS(SELECT 1 FROM leases \
                          WHERE id = ?3 AND owner_client_id = ?4 \
                            AND incarnation = operations.incarnation \
                            AND released_at IS NULL AND expires_at > ?1)",
        )
        .bind(&[
            JsValue::from_str(&claim.now),
            JsValue::from_str(&claim.operation_id),
            JsValue::from_str(&claim.lease_id),
            JsValue::from_str(&claim.client_id),
        ])?;

    Ok(vec![lease_upsert, start_operation])
}

fn attempt_statements(
    database: &worker::D1Database,
    claim: &ClaimBindings,
) -> Result<Vec<worker::D1PreparedStatement>> {
    let supersede_attempts = database
        .prepare(
            "UPDATE operation_attempts \
             SET state = 'superseded', finished_at = ?1 \
             WHERE component_id IN (SELECT id FROM operation_components WHERE operation_id = ?2) \
               AND state = 'running' \
               AND attempt != (SELECT fencing_token FROM leases WHERE id = ?3) \
               AND EXISTS(SELECT 1 FROM leases \
                          WHERE id = ?3 AND owner_client_id = ?4 \
                            AND incarnation = (SELECT incarnation FROM control_plane_state \
                                               WHERE singleton = 1 AND mode = 'active') \
                            AND released_at IS NULL AND expires_at > ?1)",
        )
        .bind(&[
            JsValue::from_str(&claim.now),
            JsValue::from_str(&claim.operation_id),
            JsValue::from_str(&claim.lease_id),
            JsValue::from_str(&claim.client_id),
        ])?;
    let start_attempt = database
        .prepare(
            "INSERT OR IGNORE INTO operation_attempts (\
                 component_id, attempt, client_id, lease_id, fencing_token, incarnation, \
                 state, started_at\
             ) \
             SELECT component.id, lease.fencing_token, ?1, lease.id, lease.fencing_token, \
                    lease.incarnation, 'running', ?2 \
             FROM operation_components AS component \
             JOIN leases AS lease ON lease.operation_id = component.operation_id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE component.operation_id = ?3 AND lease.id = ?4 \
               AND lease.owner_client_id = ?1 AND lease.incarnation = state.incarnation \
               AND state.mode = 'active' AND lease.released_at IS NULL \
               AND lease.expires_at > ?2",
        )
        .bind(&[
            JsValue::from_str(&claim.client_id),
            JsValue::from_str(&claim.now),
            JsValue::from_str(&claim.operation_id),
            JsValue::from_str(&claim.lease_id),
        ])?;
    let start_component = database
        .prepare(
            "UPDATE operation_components \
             SET client_id = ?1, state = 'running', \
                 last_sequence = CASE \
                     WHEN current_attempt != (SELECT fencing_token FROM leases WHERE id = ?2) \
                     THEN 0 ELSE last_sequence END, \
                 current_attempt = (SELECT fencing_token FROM leases WHERE id = ?2), \
                 lease_id = ?2, \
                 fencing_token = (SELECT fencing_token FROM leases WHERE id = ?2), \
                 started_at = COALESCE(started_at, ?3), revision = revision + 1, updated_at = ?3 \
             WHERE operation_id = ?4 AND state IN ('pending', 'running', 'stalled') \
               AND EXISTS(SELECT 1 FROM leases \
                          WHERE id = ?2 AND owner_client_id = ?1 \
                            AND incarnation = (SELECT incarnation FROM control_plane_state \
                                               WHERE singleton = 1 AND mode = 'active') \
                            AND released_at IS NULL AND expires_at > ?3)",
        )
        .bind(&[
            JsValue::from_str(&claim.client_id),
            JsValue::from_str(&claim.lease_id),
            JsValue::from_str(&claim.now),
            JsValue::from_str(&claim.operation_id),
        ])?;

    Ok(vec![supersede_attempts, start_attempt, start_component])
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate operation ID: {error}")))?;

    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
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

#[cfg(test)]
mod tests {
    use super::{valid_identifier, valid_string};

    #[test]
    fn validates_operation_boundaries() {
        assert!(valid_identifier("0123456789abcdef0123456789abcdef"));
        assert!(!valid_identifier("0123456789ABCDEF0123456789ABCDEF"));
        assert!(valid_string("idempotency", 256));
        assert!(!valid_string(" idempotency", 256));
    }
}
