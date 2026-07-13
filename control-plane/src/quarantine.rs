use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use worker::{D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

const DEFAULT_GRACE_SECONDS: u64 = 86_400;
const MINIMUM_GRACE_SECONDS: u64 = 60;
const MAXIMUM_GRACE_SECONDS: u64 = 31_536_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    action: String,
    driver_id: String,
    storage_key: String,
    expected_revision: u64,
    reason: String,
    idempotency_key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RetentionPolicy {
    #[serde(default, rename = "move_grace_seconds")]
    _move_grace: Option<u64>,
    #[serde(default, rename = "gc_minimum_age_seconds")]
    _gc_minimum_age: Option<u64>,
    #[serde(default, rename = "gc_grace_seconds")]
    _gc_grace: Option<u64>,
    inventory_quarantine_seconds: Option<u64>,
}

#[derive(Deserialize)]
struct TargetRow {
    provider_version: Option<String>,
    etag: Option<String>,
    size_bytes: u64,
    state: String,
    quarantine_until: u64,
    revision: u64,
    driver_revision: u64,
    retention_policy_json: String,
}

#[derive(Deserialize, Serialize)]
struct QuarantineActionOperation {
    id: String,
    namespace_id: String,
    kind: String,
    state: String,
    phase: String,
    requested_by: String,
    incarnation: String,
    revision: u64,
    action: String,
    driver_id: String,
    driver_revision: u64,
    storage_key: String,
    expected_revision: u64,
    provider_version: Option<String>,
    etag: Option<String>,
    size_bytes: u64,
    reason: String,
    grace_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delete_after: Option<u64>,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Deserialize)]
struct LiveAction {
    action: String,
    driver_id: String,
    storage_key: String,
    expected_revision: u64,
    reason: String,
    grace_seconds: u64,
}

#[derive(Deserialize)]
struct CompletionRow {
    action: String,
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    result_revision: u64,
    result_state: String,
    delete_after: Option<u64>,
}

#[derive(Serialize)]
struct CompletedAction {
    operation_id: String,
    action: String,
    state: &'static str,
    quarantine_state: String,
    quarantine_revision: u64,
    delete_after: Option<u64>,
}

#[allow(
    clippy::too_many_lines,
    reason = "operation, exact quarantine identity, policy, and component are one creation protocol"
)]
pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !valid_create_request(&requested) {
        return Response::error("invalid quarantine action", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    if let Some(existing) = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?
    {
        if !same_request(&existing, &requested) {
            return Response::error("idempotency key pins another quarantine action", 409);
        }

        return Response::from_json(&existing);
    }

    let target = load_target(&database, client, &requested).await?;
    let Some(target) = target else {
        return Response::error("quarantine object is unavailable or referenced", 409);
    };
    let now = copying::current_unix_seconds();
    if target.revision != requested.expected_revision
        || !action_available(&requested.action, &target, now)
    {
        return Response::error("quarantine object revision or state changed", 409);
    }
    let grace_seconds = parse_grace(&target.retention_policy_json)?;
    let operation_id = random_hex()?;
    let now_text = now.to_string();
    let database = env.d1("CARRACK_INDEX")?;
    let insert_operation = database
        .prepare(
            "INSERT INTO operations (\
                 id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                 incarnation, useful_bytes_total, created_at, updated_at\
             ) \
             SELECT ?1, namespace.id, 'gc', 'planned', 'planned', ?2, ?3, \
                    control.incarnation, ?4, ?5, ?5 \
             FROM namespaces AS namespace \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE namespace.id = ?6 AND control.mode = 'active' \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?3 AND namespace_id = namespace.id \
                            AND role = 'administrator') \
             ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
        )
        .bind(&[
            JsValue::from_str(&operation_id),
            JsValue::from_str(&requested.idempotency_key),
            JsValue::from_str(&client.id),
            copying::integer(target.size_bytes)?,
            JsValue::from_str(&now_text),
            JsValue::from_str(&requested.namespace_id),
        ])?;
    let insert_intent = database
        .prepare(
            "INSERT OR IGNORE INTO quarantine_action_intents (\
                 operation_id, action, driver_id, driver_revision, storage_key, \
                 expected_revision, provider_version, etag, size_bytes, reason, \
                 grace_seconds, created_at\
             ) \
             SELECT operation.id, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11 \
             FROM operations AS operation \
             WHERE operation.namespace_id = ?12 AND operation.idempotency_key = ?13 \
               AND operation.requested_by = ?14 AND operation.kind = 'gc'",
        )
        .bind(&[
            JsValue::from_str(&requested.action),
            JsValue::from_str(&requested.driver_id),
            copying::integer(target.driver_revision)?,
            JsValue::from_str(&requested.storage_key),
            copying::integer(requested.expected_revision)?,
            optional_string(target.provider_version.as_deref()),
            optional_string(target.etag.as_deref()),
            copying::integer(target.size_bytes)?,
            JsValue::from_str(&requested.reason),
            copying::integer(grace_seconds)?,
            JsValue::from_str(&now_text),
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
             SELECT operation.id || '/quarantine', operation.id, ?1, 'quarantine', \
                    intent.driver_id, 'pending', operation.useful_bytes_total, ?2, ?2 \
             FROM operations AS operation \
             JOIN quarantine_action_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
               AND operation.requested_by = ?1 AND operation.kind = 'gc'",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&now_text),
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
        return Response::error("quarantine action identity conflicts", 409);
    };
    if !same_request(&operation, &requested) {
        return Response::error("idempotency key pins another quarantine action", 409);
    }

    Response::from_json(&operation)
}

pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid quarantine operation ID", 400);
    }
    let requested = request.json::<CompleteRequest>().await?;
    if !valid_complete_request(&requested) {
        return Response::error("invalid quarantine action fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    if let Some(response) = replay_completion(&database, operation_id, client, &requested).await? {
        return Ok(response);
    }
    let live = load_live_action(&database, operation_id, client, &requested).await?;
    let Some(live) = live else {
        return Response::error("quarantine action fence is stale or unavailable", 409);
    };
    let now = copying::current_unix_seconds();
    let delete_after = if live.action == "tombstone" {
        Some(
            now.checked_add(live.grace_seconds)
                .ok_or_else(|| worker::Error::RustError("quarantine grace overflows".to_owned()))?,
        )
    } else {
        None
    };
    let result_state = if live.action == "acknowledge" {
        "acknowledged"
    } else {
        "tombstoned"
    };
    let result_revision = live
        .expected_revision
        .checked_add(1)
        .ok_or_else(|| worker::Error::RustError("quarantine revision overflows".to_owned()))?;
    let now_text = now.to_string();
    let mut statements = action_statements(
        &database,
        operation_id,
        client,
        &requested,
        &live,
        result_state,
        result_revision,
        delete_after,
        &now_text,
    )?;
    append_close_statements(
        &database,
        &mut statements,
        operation_id,
        client,
        &requested,
        result_state,
        result_revision,
        &now_text,
    )?;
    database.batch(statements).await?;

    let completion = load_completion(&database, operation_id, &client.id).await?;
    let Some(completion) = completion else {
        return Response::error("quarantine action was not committed", 409);
    };
    if !same_completion_fence(&completion, &requested) {
        return Response::error("quarantine action completion identity changed", 409);
    }

    completion_response(operation_id, completion)
}

async fn load_target(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
) -> Result<Option<TargetRow>> {
    database
        .prepare(
            "SELECT quarantine.provider_version, quarantine.etag, quarantine.size_bytes, \
                    quarantine.state, quarantine.quarantine_until, quarantine.revision, \
                    quarantine.driver_revision, namespace.retention_policy_json \
             FROM quarantined_provider_objects AS quarantine \
             JOIN namespaces AS namespace ON namespace.id = quarantine.namespace_id \
             JOIN driver_instances AS driver ON driver.id = quarantine.driver_id \
             WHERE quarantine.namespace_id = ?1 AND quarantine.driver_id = ?2 \
               AND quarantine.storage_key = ?3 AND quarantine.revision = ?4 \
               AND driver.enabled = 1 AND driver.revision = quarantine.driver_revision \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?5 AND namespace_id = quarantine.namespace_id \
                            AND role = 'administrator') \
               AND NOT EXISTS(SELECT 1 FROM locations AS location \
                              WHERE location.driver_id = quarantine.driver_id \
                                AND location.storage_key = quarantine.storage_key \
                                AND location.state != 'deleted') \
               AND NOT EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                              WHERE recovery.sidecar_driver_id = quarantine.driver_id \
                                AND recovery.sidecar_storage_key = quarantine.storage_key \
                                AND recovery.state != 'missing')",
        )
        .bind(&[
            JsValue::from_str(&requested.namespace_id),
            JsValue::from_str(&requested.driver_id),
            JsValue::from_str(&requested.storage_key),
            copying::integer(requested.expected_revision)?,
            JsValue::from_str(&client.id),
        ])?
        .first::<TargetRow>(None)
        .await
}

async fn load_live_action(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &CompleteRequest,
) -> Result<Option<LiveAction>> {
    database
        .prepare(
            "SELECT intent.action, intent.driver_id, intent.storage_key, \
                    intent.expected_revision, intent.reason, intent.grace_seconds \
             FROM quarantine_action_intents AS intent \
             JOIN operations AS operation ON operation.id = intent.operation_id \
             JOIN quarantined_provider_objects AS quarantine \
               ON quarantine.driver_id = intent.driver_id \
              AND quarantine.storage_key = intent.storage_key \
             JOIN driver_instances AS driver ON driver.id = intent.driver_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'gc' \
               AND operation.state = 'running' AND operation.phase = 'reviewing_quarantine' \
               AND operation.requested_by = ?2 AND operation.incarnation = control.incarnation \
               AND driver.enabled = 1 AND driver.revision = intent.driver_revision \
               AND lease.id = ?3 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND lease.incarnation = control.incarnation \
               AND control.mode = 'active' \
               AND quarantine.namespace_id = operation.namespace_id \
               AND quarantine.revision = intent.expected_revision \
               AND quarantine.driver_revision = intent.driver_revision \
               AND quarantine.provider_version IS intent.provider_version \
               AND quarantine.etag IS intent.etag \
               AND quarantine.size_bytes = intent.size_bytes \
               AND ((intent.action = 'acknowledge' \
                     AND quarantine.state = 'quarantined' \
                     AND quarantine.quarantine_until <= unixepoch()) \
                    OR (intent.action = 'tombstone' \
                        AND quarantine.state = 'acknowledged')) \
               AND NOT EXISTS(SELECT 1 FROM locations AS location \
                              WHERE location.driver_id = quarantine.driver_id \
                                AND location.storage_key = quarantine.storage_key \
                                AND location.state != 'deleted') \
               AND NOT EXISTS(SELECT 1 FROM recovery_manifests AS recovery \
                              WHERE recovery.sidecar_driver_id = quarantine.driver_id \
                                AND recovery.sidecar_storage_key = quarantine.storage_key \
                                AND recovery.state != 'missing')",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .first::<LiveAction>(None)
        .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "staged result, exact CAS, finding lifecycle, and audit record form one action batch"
)]
fn action_statements(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &CompleteRequest,
    live: &LiveAction,
    result_state: &str,
    result_revision: u64,
    delete_after: Option<u64>,
    now: &str,
) -> Result<Vec<worker::D1PreparedStatement>> {
    let completion = database
        .prepare(
            "INSERT INTO quarantine_action_completions (\
                 operation_id, action, lease_id, incarnation, fencing_token, \
                 result_revision, result_state, delete_after, completed_at\
             ) \
             SELECT operation.id, intent.action, ?1, ?2, ?3, ?4, ?5, ?6, ?7 \
             FROM operations AS operation \
             JOIN quarantine_action_intents AS intent ON intent.operation_id = operation.id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE operation.id = ?8 AND operation.kind = 'gc' \
               AND operation.state = 'running' AND operation.phase = 'reviewing_quarantine' \
               AND operation.requested_by = ?9 AND lease.id = ?1 \
               AND lease.owner_client_id = ?9 AND lease.incarnation = ?2 \
               AND lease.fencing_token = ?3 AND lease.lease_kind = 'write' \
               AND lease.released_at IS NULL AND lease.expires_at > ?7 \
               AND lease.incarnation = control.incarnation AND control.mode = 'active'",
        )
        .bind(&[
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
            copying::integer(result_revision)?,
            JsValue::from_str(result_state),
            optional_integer(delete_after)?,
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
        ])?;
    let update_object = database
        .prepare(
            "UPDATE quarantined_provider_objects \
             SET state = ?1, \
                 acknowledgement_reason = CASE \
                     WHEN ?2 = 'acknowledge' THEN ?3 ELSE acknowledgement_reason END, \
                 acknowledged_at = CASE \
                     WHEN ?2 = 'acknowledge' THEN ?4 ELSE acknowledged_at END, \
                 tombstone_reason = CASE \
                     WHEN ?2 = 'tombstone' THEN ?3 ELSE tombstone_reason END, \
                 tombstoned_at = CASE \
                     WHEN ?2 = 'tombstone' THEN ?4 ELSE tombstoned_at END, \
                 delete_after = CASE \
                     WHEN ?2 = 'tombstone' THEN ?5 ELSE delete_after END, \
                 last_operation_id = ?6, revision = revision + 1 \
             WHERE driver_id = ?7 AND storage_key = ?8 AND revision = ?9 \
               AND EXISTS(SELECT 1 FROM quarantine_action_completions \
                          WHERE operation_id = ?6 AND state = 'staging' \
                            AND result_revision = ?10 AND result_state = ?1)",
        )
        .bind(&[
            JsValue::from_str(result_state),
            JsValue::from_str(&live.action),
            JsValue::from_str(&live.reason),
            JsValue::from_str(now),
            optional_integer(delete_after)?,
            JsValue::from_str(operation_id),
            JsValue::from_str(&live.driver_id),
            JsValue::from_str(&live.storage_key),
            copying::integer(live.expected_revision)?,
            copying::integer(result_revision)?,
        ])?;
    let update_finding = database
        .prepare(
            "UPDATE integrity_findings \
             SET state = ?1, \
                 evidence_json = json_set(\
                     evidence_json, '$.review_action', ?2, '$.review_reason', ?3, \
                     '$.review_operation_id', ?4, '$.reviewed_at', CAST(?5 AS INTEGER), \
                     '$.delete_after', ?6\
                 ), \
                 last_observed_at = ?5, revision = revision + 1 \
             WHERE namespace_id = (SELECT namespace_id FROM operations WHERE id = ?4) \
               AND subject_kind = 'provider_object' \
               AND subject_id = json_array(?7, ?8) AND condition = 'quarantined' \
               AND state = CASE WHEN ?2 = 'acknowledge' THEN 'open' ELSE 'acknowledged' END \
               AND EXISTS(SELECT 1 FROM quarantined_provider_objects \
                          WHERE driver_id = ?7 AND storage_key = ?8 \
                            AND state = ?1 AND revision = ?9 \
                            AND last_operation_id = ?4)",
        )
        .bind(&[
            JsValue::from_str(result_state),
            JsValue::from_str(&live.action),
            JsValue::from_str(&live.reason),
            JsValue::from_str(operation_id),
            JsValue::from_str(now),
            optional_integer(delete_after)?,
            JsValue::from_str(&live.driver_id),
            JsValue::from_str(&live.storage_key),
            copying::integer(result_revision)?,
        ])?;
    let create_delete_task = database
        .prepare(
            "INSERT OR IGNORE INTO quarantine_delete_tasks (\
                 id, operation_id, driver_id, driver_revision, storage_key, expected_revision, \
                 provider_version, etag, size_bytes, delete_after, state, created_at, updated_at\
             ) \
             SELECT operation.id || '/quarantine-delete', operation.id, intent.driver_id, \
                    intent.driver_revision, intent.storage_key, completion.result_revision, \
                    intent.provider_version, intent.etag, intent.size_bytes, \
                    completion.delete_after, 'pending', completion.completed_at, \
                    completion.completed_at \
             FROM operations AS operation \
             JOIN quarantine_action_intents AS intent ON intent.operation_id = operation.id \
             JOIN quarantine_action_completions AS completion \
               ON completion.operation_id = operation.id \
             JOIN quarantined_provider_objects AS quarantine \
               ON quarantine.driver_id = intent.driver_id \
              AND quarantine.storage_key = intent.storage_key \
             WHERE operation.id = ?1 AND operation.kind = 'gc' \
               AND operation.state = 'running' AND operation.phase = 'reviewing_quarantine' \
               AND intent.action = 'tombstone' AND completion.state = 'staging' \
               AND completion.result_state = 'tombstoned' \
               AND quarantine.state = 'tombstoned' \
               AND quarantine.driver_revision = intent.driver_revision \
               AND quarantine.revision = completion.result_revision \
               AND quarantine.provider_version IS intent.provider_version \
               AND quarantine.etag IS intent.etag \
               AND quarantine.size_bytes = intent.size_bytes \
               AND quarantine.delete_after = completion.delete_after",
        )
        .bind(&[JsValue::from_str(operation_id)])?;
    let audit = database
        .prepare(
            "INSERT INTO audit_events (\
                 id, namespace_id, operation_id, client_id, event_kind, subject_kind, \
                 subject_id, details_json, created_at\
             ) \
             SELECT ?1, operation.namespace_id, operation.id, ?2, \
                    'quarantine_' || intent.action, 'provider_object', \
                    json_array(intent.driver_id, intent.storage_key), \
                    json_object(\
                        'action', intent.action, 'reason', intent.reason, \
                        'expected_revision', intent.expected_revision, \
                        'result_revision', ?3, 'result_state', ?4, \
                        'delete_after', ?5\
                    ), ?6 \
             FROM operations AS operation \
             JOIN quarantine_action_intents AS intent ON intent.operation_id = operation.id \
             WHERE operation.id = ?7 \
               AND EXISTS(SELECT 1 FROM quarantined_provider_objects \
                          WHERE driver_id = intent.driver_id \
                            AND storage_key = intent.storage_key \
                            AND state = ?4 AND revision = ?3 \
                            AND last_operation_id = operation.id)",
        )
        .bind(&[
            JsValue::from_str(&format!("{operation_id}/quarantine/{}", live.action)),
            JsValue::from_str(&client.id),
            copying::integer(result_revision)?,
            JsValue::from_str(result_state),
            optional_integer(delete_after)?,
            JsValue::from_str(now),
            JsValue::from_str(operation_id),
        ])?;

    Ok(vec![
        completion,
        update_object,
        create_delete_task,
        update_finding,
        audit,
    ])
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all action closure transitions and fence dimensions remain explicit"
)]
fn append_close_statements(
    database: &D1Database,
    statements: &mut Vec<worker::D1PreparedStatement>,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &CompleteRequest,
    result_state: &str,
    result_revision: u64,
    now: &str,
) -> Result<()> {
    for (from, to, phase) in [
        ("running", "verifying", "verifying_quarantine"),
        ("verifying", "committing", "committing_quarantine"),
        ("committing", "succeeded", "completed"),
    ] {
        statements.push(
            database
                .prepare(
                    "UPDATE operations SET state = ?1, phase = ?2, revision = revision + 1, \
                         finished_at = CASE WHEN ?1 = 'succeeded' THEN ?3 ELSE finished_at END, \
                         updated_at = ?3 \
                     WHERE id = ?4 AND kind = 'gc' AND state = ?5 \
                       AND EXISTS(SELECT 1 FROM quarantine_action_completions \
                                  WHERE operation_id = ?4 AND state = 'staging' \
                                    AND result_state = ?6 AND result_revision = ?7)",
                )
                .bind(&[
                    JsValue::from_str(to),
                    JsValue::from_str(phase),
                    JsValue::from_str(now),
                    JsValue::from_str(operation_id),
                    JsValue::from_str(from),
                    JsValue::from_str(result_state),
                    copying::integer(result_revision)?,
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "UPDATE operation_attempts SET state = 'succeeded', finished_at = ?1 \
                 WHERE component_id = ?2 || '/quarantine' AND attempt = ?3 \
                   AND state = 'running' AND lease_id = ?4 AND incarnation = ?5",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                copying::integer(requested.fencing_token)?,
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.incarnation),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'succeeded', finished_at = ?1, revision = revision + 1, \
                     updated_at = ?1 \
                 WHERE id = ?2 || '/quarantine' AND operation_id = ?2 \
                   AND lease_id = ?3 AND fencing_token = ?4 AND state = 'running' \
                   AND EXISTS(SELECT 1 FROM operations WHERE id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(&requested.lease_id),
                copying::integer(requested.fencing_token)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE leases SET released_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND operation_id = ?3 AND owner_client_id = ?4 \
                   AND incarnation = ?5 AND fencing_token = ?6 AND lease_kind = 'write' \
                   AND released_at IS NULL AND expires_at > ?1 \
                   AND EXISTS(SELECT 1 FROM operations WHERE id = ?3 AND state = 'succeeded')",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                copying::integer(requested.fencing_token)?,
            ])?,
    );
    statements.push(
        database
            .prepare(
                "UPDATE quarantine_action_completions \
                 SET state = 'committed', committed_at = ?1 \
                 WHERE operation_id = ?2 AND result_state = ?3 \
                   AND result_revision = ?4 AND state = 'staging'",
            )
            .bind(&[
                JsValue::from_str(now),
                JsValue::from_str(operation_id),
                JsValue::from_str(result_state),
                copying::integer(result_revision)?,
            ])?,
    );

    Ok(())
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<QuarantineActionOperation>> {
    database
        .prepare(
            "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
                    operation.phase, operation.requested_by, operation.incarnation, \
                    operation.revision, intent.action, intent.driver_id, \
                    intent.driver_revision, intent.storage_key, intent.expected_revision, \
                    intent.provider_version, intent.etag, intent.size_bytes, intent.reason, \
                    intent.grace_seconds, completion.result_revision, \
                    completion.result_state, completion.delete_after, \
                    operation.created_at, operation.updated_at \
             FROM operations AS operation \
             JOIN quarantine_action_intents AS intent ON intent.operation_id = operation.id \
             LEFT JOIN quarantine_action_completions AS completion \
               ON completion.operation_id = operation.id AND completion.state = 'committed' \
             WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
               AND operation.requested_by = ?3 AND operation.kind = 'gc'",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<QuarantineActionOperation>(None)
        .await
}

async fn load_completion(
    database: &D1Database,
    operation_id: &str,
    client_id: &str,
) -> Result<Option<CompletionRow>> {
    database
        .prepare(
            "SELECT completion.action, completion.lease_id, completion.incarnation, \
                    completion.fencing_token, completion.result_revision, \
                    completion.result_state, completion.delete_after \
             FROM quarantine_action_completions AS completion \
             JOIN operations AS operation ON operation.id = completion.operation_id \
             WHERE operation.id = ?1 AND operation.kind = 'gc' \
               AND operation.state = 'succeeded' AND operation.requested_by = ?2 \
               AND completion.state = 'committed'",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(client_id),
        ])?
        .first::<CompletionRow>(None)
        .await
}

async fn replay_completion(
    database: &D1Database,
    operation_id: &str,
    client: &AuthenticatedClient,
    requested: &CompleteRequest,
) -> Result<Option<Response>> {
    let completion = load_completion(database, operation_id, &client.id).await?;
    let Some(completion) = completion else {
        return Ok(None);
    };
    if !same_completion_fence(&completion, requested) {
        return Ok(Some(Response::error(
            "quarantine action completion replay changed its fence",
            409,
        )?));
    }

    Ok(Some(completion_response(operation_id, completion)?))
}

fn same_completion_fence(completion: &CompletionRow, requested: &CompleteRequest) -> bool {
    completion.lease_id == requested.lease_id
        && completion.incarnation == requested.incarnation
        && completion.fencing_token == requested.fencing_token
}

fn completion_response(operation_id: &str, completion: CompletionRow) -> Result<Response> {
    Response::from_json(&CompletedAction {
        operation_id: operation_id.to_owned(),
        action: completion.action,
        state: "succeeded",
        quarantine_state: completion.result_state,
        quarantine_revision: completion.result_revision,
        delete_after: completion.delete_after,
    })
}

fn valid_create_request(request: &CreateRequest) -> bool {
    copying::valid_hex(&request.namespace_id, 32)
        && matches!(request.action.as_str(), "acknowledge" | "tombstone")
        && copying::valid_string(&request.driver_id, 256)
        && valid_storage_key(&request.storage_key)
        && request.expected_revision > 0
        && request.expected_revision < i64::MAX as u64
        && copying::valid_string(&request.reason, 2_048)
        && copying::valid_string(&request.idempotency_key, 256)
}

fn valid_complete_request(request: &CompleteRequest) -> bool {
    copying::valid_string(&request.lease_id, 256)
        && copying::valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
}

fn valid_storage_key(key: &str) -> bool {
    copying::valid_string(key, 4_096)
        && !key.starts_with('/')
        && !key.ends_with('/')
        && !key.contains('\\')
        && key
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn same_request(operation: &QuarantineActionOperation, request: &CreateRequest) -> bool {
    operation.namespace_id == request.namespace_id
        && operation.action == request.action
        && operation.driver_id == request.driver_id
        && operation.storage_key == request.storage_key
        && operation.expected_revision == request.expected_revision
        && operation.reason == request.reason
}

fn action_available(action: &str, target: &TargetRow, now: u64) -> bool {
    (action == "acknowledge" && target.state == "quarantined" && target.quarantine_until <= now)
        || (action == "tombstone" && target.state == "acknowledged")
}

fn parse_grace(encoded: &str) -> Result<u64> {
    let policy = serde_json::from_str::<RetentionPolicy>(encoded)
        .map_err(|error| worker::Error::RustError(format!("decode retention policy: {error}")))?;
    let grace = policy
        .inventory_quarantine_seconds
        .unwrap_or(DEFAULT_GRACE_SECONDS);
    if !(MINIMUM_GRACE_SECONDS..=MAXIMUM_GRACE_SECONDS).contains(&grace) {
        return Err(worker::Error::RustError(
            "quarantine review grace is out of range".to_owned(),
        ));
    }

    Ok(grace)
}

fn optional_string(value: Option<&str>) -> JsValue {
    value.map_or_else(JsValue::null, JsValue::from_str)
}

fn optional_integer(value: Option<u64>) -> Result<JsValue> {
    value.map_or_else(|| Ok(JsValue::null()), copying::integer)
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate quarantine ID: {error}")))?;
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::{CreateRequest, TargetRow, action_available, valid_create_request};

    #[test]
    fn requires_expired_quarantine_before_acknowledgement() {
        let target = TargetRow {
            provider_version: None,
            etag: None,
            size_bytes: 1,
            state: "quarantined".to_owned(),
            quarantine_until: 100,
            revision: 2,
            driver_revision: 1,
            retention_policy_json: "{}".to_owned(),
        };
        assert!(!action_available("acknowledge", &target, 99));
        assert!(action_available("acknowledge", &target, 100));
        assert!(!action_available("tombstone", &target, 100));
    }

    #[test]
    fn validates_exact_action_identity() {
        let request = CreateRequest {
            namespace_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            action: "acknowledge".to_owned(),
            driver_id: "local-main".to_owned(),
            storage_key: "archive/objects/orphan".to_owned(),
            expected_revision: 1,
            reason: "reviewed against the recovery catalog".to_owned(),
            idempotency_key: "acknowledge-orphan-1".to_owned(),
        };
        assert!(valid_create_request(&request));
    }
}
