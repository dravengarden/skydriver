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
    manifest_sha256: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    lease_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    plaintext_sha256: String,
    plaintext_bytes: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct RestoreOperation {
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
    object_id: String,
    generation: u64,
    manifest_sha256: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize, Serialize)]
struct ReadLease {
    operation_id: String,
    lease_id: String,
    owner_client_id: String,
    incarnation: String,
    fencing_token: u64,
    expires_at: u64,
    operation_revision: u64,
    operation_state: String,
    version_id: String,
    manifest_sha256: String,
}

#[derive(Serialize)]
struct CompletedRestore {
    operation_id: String,
    manifest_sha256: String,
    state: String,
}

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
        return Response::error("invalid restore operation", 400);
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
             SELECT ?1, ?2, 'restore', 'planned', 'planned', ?3, ?4, \
                    state.incarnation, version.plaintext_bytes, ?5, ?5 \
             FROM control_plane_state AS state \
             JOIN object_versions AS version ON version.manifest_sha256 = ?6 \
             JOIN objects AS object ON object.id = version.object_id \
             WHERE state.singleton = 1 AND state.mode = 'active' \
               AND object.namespace_id = ?2 AND version.state = 'published' \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?4 AND namespace_id = ?2 \
                            AND role IN ('reader', 'restorer', 'administrator')) \
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
            "INSERT OR IGNORE INTO restore_intents (operation_id, version_id, manifest_sha256, created_at) \
             SELECT operation.id, version.id, version.manifest_sha256, ?1 \
             FROM operations AS operation \
             JOIN object_versions AS version ON version.manifest_sha256 = ?2 \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?5 AND operation.kind = 'restore'",
        )
        .bind(&[
            JsValue::from_str(&now),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
        ])?;
    database
        .batch(vec![insert_operation, insert_intent])
        .await?;

    let operation = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?;
    let Some(operation) = operation else {
        return Response::error("restore rejected or idempotency identity conflicts", 409);
    };
    if operation.manifest_sha256 != requested.manifest_sha256 {
        return Response::error("idempotency key pins another manifest", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn claim(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid restore operation ID", 400);
    }

    let requested = request.json::<ClaimRequest>().await?;
    let lease_seconds = requested.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !(MINIMUM_LEASE_SECONDS..=MAXIMUM_LEASE_SECONDS).contains(&lease_seconds) {
        return Response::error("lease duration is out of range", 400);
    }

    let now = current_unix_seconds();
    let lease_id = format!("operation/{operation_id}/read");
    let database = env.d1("CARRACK_INDEX")?;
    let upsert = database
        .prepare(
            "INSERT INTO leases (\
                 id, resource_kind, resource_id, lease_kind, owner_client_id, operation_id, \
                 fencing_token, incarnation, expires_at, created_at, updated_at\
             ) \
             SELECT ?1, 'operation', operation.id, 'read', ?2, operation.id, 1, \
                    state.incarnation, ?3, ?4, ?4 \
             FROM operations AS operation \
             JOIN restore_intents AS intent ON intent.operation_id = operation.id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE operation.id = ?5 AND operation.kind = 'restore' \
               AND operation.state IN ('planned', 'running') AND state.mode = 'active' \
               AND operation.incarnation = state.incarnation \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?2 AND namespace_id = operation.namespace_id \
                            AND role IN ('reader', 'restorer', 'administrator')) \
             ON CONFLICT(resource_kind, resource_id, lease_kind) DO UPDATE SET \
                 owner_client_id = excluded.owner_client_id, operation_id = excluded.operation_id, \
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
            JsValue::from_str(&lease_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&(now + lease_seconds).to_string()),
            JsValue::from_str(&now.to_string()),
            JsValue::from_str(operation_id),
        ])?;
    let start = database
        .prepare(
            "UPDATE operations SET state = 'running', phase = 'restoring', \
                    revision = revision + CASE WHEN state = 'planned' THEN 1 ELSE 0 END, \
                    started_at = COALESCE(started_at, ?1), updated_at = ?1 \
             WHERE id = ?2 AND kind = 'restore' AND state IN ('planned', 'running') \
               AND EXISTS(SELECT 1 FROM leases WHERE id = ?3 AND owner_client_id = ?4 \
                          AND incarnation = operations.incarnation AND released_at IS NULL \
                          AND expires_at > ?1)",
        )
        .bind(&[
            JsValue::from_str(&now.to_string()),
            JsValue::from_str(operation_id),
            JsValue::from_str(&lease_id),
            JsValue::from_str(&client.id),
        ])?;
    database.batch(vec![upsert, start]).await?;

    let lease = database
        .prepare(
            "SELECT operation.id AS operation_id, lease.id AS lease_id, lease.owner_client_id, \
                    lease.incarnation, lease.fencing_token, lease.expires_at, \
                    operation.revision AS operation_revision, operation.state AS operation_state, \
                    intent.version_id, intent.manifest_sha256 \
             FROM leases AS lease \
             JOIN operations AS operation ON operation.id = lease.operation_id \
             JOIN restore_intents AS intent ON intent.operation_id = operation.id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE lease.id = ?1 AND lease.owner_client_id = ?2 AND lease.lease_kind = 'read' \
               AND lease.incarnation = state.incarnation AND state.mode = 'active' \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch()",
        )
        .bind(&[JsValue::from_str(&lease_id), JsValue::from_str(&client.id)])?
        .first::<ReadLease>(None)
        .await?;

    match lease {
        Some(value) => Response::from_json(&value),
        None => Response::error("restore is unavailable or leased by another client", 409),
    }
}

pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !valid_hex(operation_id, 32) {
        return Response::error("invalid restore operation ID", 400);
    }

    let completed = request.json::<CompleteRequest>().await?;
    if !valid_string(&completed.lease_id, 256)
        || !valid_hex(&completed.incarnation, 32)
        || completed.fencing_token == 0
        || !valid_hex(&completed.manifest_sha256, 64)
        || !valid_hex(&completed.plaintext_sha256, 64)
        || completed.plaintext_bytes > i64::MAX.unsigned_abs()
    {
        return Response::error("invalid restore completion", 400);
    }

    let now = current_unix_seconds().to_string();
    let database = env.d1("CARRACK_INDEX")?;
    let verifying = completion_transition(
        &database,
        operation_id,
        client,
        &completed,
        "running",
        "verifying",
        "verifying",
        &now,
    )?;
    let committing = completion_transition(
        &database,
        operation_id,
        client,
        &completed,
        "verifying",
        "committing",
        "committing",
        &now,
    )?;
    let succeeded = completion_transition(
        &database,
        operation_id,
        client,
        &completed,
        "committing",
        "succeeded",
        "completed",
        &now,
    )?;
    let release = database
        .prepare(
            "UPDATE leases SET released_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND operation_id = ?3 AND owner_client_id = ?4 \
               AND incarnation = ?5 AND fencing_token = ?6 AND lease_kind = 'read' \
               AND released_at IS NULL AND expires_at > ?1 \
               AND EXISTS(SELECT 1 FROM operations WHERE id = ?3 AND state = 'succeeded')",
        )
        .bind(&[
            JsValue::from_str(&now),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.incarnation),
            JsValue::from_str(&completed.fencing_token.to_string()),
        ])?;
    database
        .batch(vec![verifying, committing, succeeded, release])
        .await?;

    let state = database
        .prepare(
            "SELECT state FROM operations WHERE id = ?1 AND kind = 'restore' \
             AND requested_by = ?2 AND state = 'succeeded' \
             AND EXISTS(SELECT 1 FROM restore_intents WHERE operation_id = ?1 \
                        AND manifest_sha256 = ?3) \
             AND EXISTS(SELECT 1 FROM leases WHERE id = ?4 AND operation_id = ?1 \
                        AND owner_client_id = ?2 AND incarnation = ?5 \
                        AND fencing_token = ?6 AND lease_kind = 'read' \
                        AND released_at IS NOT NULL)",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.manifest_sha256),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
            JsValue::from_str(&completed.fencing_token.to_string()),
        ])?
        .first::<String>(Some("state"))
        .await?;
    if state.as_deref() != Some("succeeded") {
        return Response::error("restore completion fence is stale or identity changed", 409);
    }

    Response::from_json(&CompletedRestore {
        operation_id: operation_id.to_owned(),
        manifest_sha256: completed.manifest_sha256,
        state: "succeeded".to_owned(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "all transition identities remain explicit SQL bindings"
)]
fn completion_transition(
    database: &worker::D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    completed: &CompleteRequest,
    old_state: &str,
    new_state: &str,
    phase: &str,
    now: &str,
) -> Result<worker::D1PreparedStatement> {
    database
        .prepare(
            "UPDATE operations SET state = ?1, phase = ?2, revision = revision + 1, \
                    useful_bytes_verified = ?3, finished_at = CASE WHEN ?1 = 'succeeded' \
                    THEN ?4 ELSE finished_at END, updated_at = ?4 \
             WHERE id = ?5 AND kind = 'restore' AND state = ?6 AND requested_by = ?7 \
               AND useful_bytes_total = ?3 \
               AND EXISTS(SELECT 1 FROM restore_intents AS intent \
                          JOIN object_versions AS version ON version.id = intent.version_id \
                          WHERE intent.operation_id = ?5 AND intent.manifest_sha256 = ?8 \
                            AND version.plaintext_sha256 = ?9 AND version.plaintext_bytes = ?3) \
               AND EXISTS(SELECT 1 FROM leases WHERE id = ?10 AND operation_id = ?5 \
                          AND owner_client_id = ?7 AND incarnation = ?11 \
                          AND fencing_token = ?12 AND lease_kind = 'read' \
                          AND released_at IS NULL AND expires_at > ?4)",
        )
        .bind(&[
            JsValue::from_str(new_state),
            JsValue::from_str(phase),
            JsValue::from_str(&completed.plaintext_bytes.to_string()),
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(old_state),
            JsValue::from_str(&client.id),
            JsValue::from_str(&completed.manifest_sha256),
            JsValue::from_str(&completed.plaintext_sha256),
            JsValue::from_str(&completed.lease_id),
            JsValue::from_str(&completed.incarnation),
            JsValue::from_str(&completed.fencing_token.to_string()),
        ])
}

async fn find_operation(
    database: &worker::D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<RestoreOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, operation.useful_bytes_total, intent.version_id, \
                    version.object_id, version.generation, intent.manifest_sha256, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN restore_intents AS intent ON intent.operation_id = operation.id \
             JOIN object_versions AS version ON version.id = intent.version_id \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'restore'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<RestoreOperation>(None)
        .await
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate restore ID: {error}")))?;

    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
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
    use super::{valid_hex, valid_string};

    #[test]
    fn validates_restore_boundaries() {
        assert!(valid_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            64
        ));
        assert!(!valid_hex("ABCDEF", 6));
        assert!(valid_string("restore-1", 256));
        assert!(!valid_string(" restore-1", 256));
    }
}
