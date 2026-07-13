use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use worker::{D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

const DEFAULT_MINIMUM_AGE_SECONDS: u64 = 604_800;
const DEFAULT_GRACE_SECONDS: u64 = 86_400;
const MINIMUM_RETENTION_SECONDS: u64 = 60;
const MAXIMUM_RETENTION_SECONDS: u64 = 31_536_000;
const DEFAULT_DELETE_LEASE_SECONDS: u64 = 60;
const MINIMUM_DELETE_LEASE_SECONDS: u64 = 15;
const MAXIMUM_DELETE_LEASE_SECONDS: u64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRequest {
    namespace_id: String,
    idempotency_key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RetentionPolicy {
    #[serde(default, rename = "move_grace_seconds")]
    _move_grace: Option<u64>,
    #[serde(rename = "gc_minimum_age_seconds")]
    gc_minimum_age: Option<u64>,
    #[serde(rename = "gc_grace_seconds")]
    gc_grace: Option<u64>,
    #[serde(default, rename = "inventory_quarantine_seconds")]
    _inventory_quarantine: Option<u64>,
}

#[derive(Deserialize)]
struct RetentionRow {
    retention_policy_json: String,
}

#[derive(Deserialize)]
struct LiveFenceRow {
    lease_id: String,
}

#[derive(Deserialize, Serialize)]
struct GcOperation {
    id: String,
    namespace_id: String,
    kind: String,
    state: String,
    phase: String,
    requested_by: String,
    incarnation: String,
    revision: u64,
    cutoff_at: u64,
    grace_seconds: u64,
    grace_until: Option<u64>,
    gc_state: String,
    candidate_count: u64,
    object_count: u64,
    created_at: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
}

#[derive(Serialize)]
struct MarkResponse {
    operation_id: String,
    candidates_marked: u64,
    objects_marked: u64,
    grace_until: Option<u64>,
    state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    lease_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceRequest {
    task_id: String,
    incarnation: String,
    fencing_token: u64,
    lease_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureRequest {
    task_id: String,
    incarnation: String,
    fencing_token: u64,
    error_code: String,
}

#[derive(Deserialize, Serialize)]
struct DeleteTask {
    task_id: String,
    operation_id: String,
    driver_id: String,
    storage_key: String,
    expected_location_count: u64,
    owner_client_id: String,
    incarnation: String,
    fencing_token: u64,
    lease_expires_at: u64,
    attempt_count: u64,
    state: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    state: String,
    task: Option<DeleteTask>,
}

#[derive(Deserialize, Serialize)]
struct TaskStateRow {
    task_id: String,
    operation_id: String,
    driver_id: String,
    storage_key: String,
    expected_location_count: u64,
    owner_client_id: Option<String>,
    incarnation: Option<String>,
    fencing_token: u64,
    lease_expires_at: Option<u64>,
    attempt_count: u64,
    state: String,
}

#[derive(Serialize)]
struct CompletionResponse {
    task_id: String,
    operation_id: String,
    locations_deleted: u64,
    task_state: &'static str,
    gc_state: String,
}

pub(crate) async fn create(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CreateRequest>().await?;
    if !copying::valid_hex(&requested.namespace_id, 32)
        || !copying::valid_string(&requested.idempotency_key, 256)
    {
        return Response::error("invalid GC operation", 400);
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
        return Response::from_json(&existing);
    }

    let Some(retention) = load_retention(&database, client, &requested.namespace_id).await? else {
        return Response::error("GC namespace is unavailable", 404);
    };
    let (minimum_age_seconds, grace_seconds) = parse_retention(&retention.retention_policy_json)?;
    let now = copying::current_unix_seconds();
    let cutoff_at = now
        .checked_sub(minimum_age_seconds)
        .ok_or_else(|| worker::Error::RustError("GC retention cutoff underflows".to_owned()))?;
    let operation_id = random_hex()?;

    create_operation(
        &database,
        client,
        &requested,
        &operation_id,
        cutoff_at,
        grace_seconds,
        now,
    )
    .await?;

    let Some(operation) = find_operation(
        &database,
        &requested.namespace_id,
        &requested.idempotency_key,
        &client.id,
    )
    .await?
    else {
        return Response::error("GC operation was rejected or idempotency conflicts", 409);
    };

    Response::from_json(&operation)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the complete immutable GC creation identity stays explicit"
)]
async fn create_operation(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &CreateRequest,
    operation_id: &str,
    cutoff_at: u64,
    grace_seconds: u64,
    now: u64,
) -> Result<()> {
    let statements = vec![
        database
            .prepare(
                "INSERT INTO operations (\
                     id, namespace_id, kind, state, phase, idempotency_key, requested_by, \
                     incarnation, created_at, updated_at\
                 ) \
                 SELECT ?1, ?2, 'gc', 'planned', 'planned', ?3, ?4, \
                        control.incarnation, ?5, ?5 \
                 FROM control_plane_state AS control \
                 WHERE control.singleton = 1 AND control.mode = 'active' \
                   AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                              WHERE client_id = ?4 AND namespace_id = ?2 \
                                AND role = 'administrator') \
                 ON CONFLICT(namespace_id, idempotency_key) DO NOTHING",
            )
            .bind(&[
                JsValue::from_str(operation_id),
                JsValue::from_str(&requested.namespace_id),
                JsValue::from_str(&requested.idempotency_key),
                JsValue::from_str(&client.id),
                copying::integer(now)?,
            ])?,
        database
            .prepare(
                "INSERT OR IGNORE INTO gc_epochs (\
                     id, namespace_id, incarnation, state, created_at, updated_at\
                 ) \
                 SELECT operation.id, operation.namespace_id, operation.incarnation, \
                        'marking', ?1, ?1 \
                 FROM operations AS operation \
                 WHERE operation.namespace_id = ?2 AND operation.idempotency_key = ?3 \
                   AND operation.requested_by = ?4 AND operation.kind = 'gc'",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&requested.namespace_id),
                JsValue::from_str(&requested.idempotency_key),
                JsValue::from_str(&client.id),
            ])?,
        database
            .prepare(
                "INSERT OR IGNORE INTO gc_intents (\
                     operation_id, cutoff_at, grace_seconds, created_at\
                 ) \
                 SELECT operation.id, ?1, ?2, ?3 \
                 FROM operations AS operation \
                 JOIN gc_epochs AS epoch ON epoch.id = operation.id \
                 WHERE operation.namespace_id = ?4 AND operation.idempotency_key = ?5 \
                   AND operation.requested_by = ?6 AND operation.kind = 'gc'",
            )
            .bind(&[
                copying::integer(cutoff_at)?,
                copying::integer(grace_seconds)?,
                copying::integer(now)?,
                JsValue::from_str(&requested.namespace_id),
                JsValue::from_str(&requested.idempotency_key),
                JsValue::from_str(&client.id),
            ])?,
        database
            .prepare(
                "INSERT OR IGNORE INTO operation_components (\
                     id, operation_id, client_id, component_kind, state, created_at, updated_at\
                 ) \
                 SELECT operation.id || '/gc', operation.id, ?1, 'gc', 'pending', ?2, ?2 \
                 FROM operations AS operation \
                 JOIN gc_intents AS intent ON intent.operation_id = operation.id \
                 WHERE operation.namespace_id = ?3 AND operation.idempotency_key = ?4 \
                   AND operation.requested_by = ?1 AND operation.kind = 'gc'",
            )
            .bind(&[
                JsValue::from_str(&client.id),
                copying::integer(now)?,
                JsValue::from_str(&requested.namespace_id),
                JsValue::from_str(&requested.idempotency_key),
            ])?,
    ];
    database.batch(statements).await?;

    Ok(())
}

pub(crate) async fn mark(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid GC operation ID", 400);
    }
    let requested = request.json::<MarkRequest>().await?;
    if !valid_mark_request(&requested) {
        return Response::error("invalid GC mark fence", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(operation) = find_operation_by_id(&database, operation_id, &client.id).await? else {
        return Response::error("GC operation is unavailable", 409);
    };
    if operation.gc_state != "marking" {
        if !has_committed_mark_fence(&database, client, operation_id, &requested).await? {
            return Response::error("GC mark replay changed its fence", 409);
        }

        return mark_response(&operation);
    }
    if operation.state != "running" || operation.phase != "marking" {
        return Response::error("GC operation has not been claimed for marking", 409);
    }
    if !has_live_mark_fence(&database, client, operation_id, &requested).await? {
        return Response::error("GC mark fence is stale", 409);
    }

    finalize_mark(&database, client, &requested, &operation).await?;
    let Some(marked) = find_operation_by_id(&database, operation_id, &client.id).await? else {
        return Response::error("GC operation disappeared", 409);
    };
    if marked.gc_state == "marking" {
        return Response::error("GC mark did not commit", 409);
    }

    mark_response(&marked)
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete fenced mark and grace handoff remain one auditable D1 batch"
)]
async fn finalize_mark(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &MarkRequest,
    operation: &GcOperation,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    let grace_until = now
        .checked_add(operation.grace_seconds)
        .ok_or_else(|| worker::Error::RustError("GC grace deadline overflows".to_owned()))?;
    let live_fence = "EXISTS(SELECT 1 FROM leases AS lease \
                      JOIN control_plane_state AS control ON control.singleton = 1 \
                      WHERE lease.id = ?2 AND lease.operation_id = ?1 \
                        AND lease.owner_client_id = ?3 AND lease.incarnation = ?4 \
                        AND lease.incarnation = control.incarnation \
                        AND lease.fencing_token = ?5 AND lease.lease_kind = 'write' \
                        AND lease.released_at IS NULL AND lease.expires_at > ?6 \
                        AND control.mode = 'active')";
    let common = [
        JsValue::from_str(&operation.id),
        JsValue::from_str(&requested.lease_id),
        JsValue::from_str(&client.id),
        JsValue::from_str(&requested.incarnation),
        copying::integer(requested.fencing_token)?,
        copying::integer(now)?,
    ];
    let statements = vec![
        database
            .prepare(format!(
                "INSERT OR IGNORE INTO gc_candidates (\
                     gc_epoch_id, location_id, location_revision, state, reason, marked_at, updated_at\
                 ) \
                 SELECT ?1, location.id, location.revision + 1, 'marked', \
                        'unreachable_retired_generation', ?6, ?6 \
                 FROM gc_markable_locations AS markable \
                 JOIN locations AS location ON location.id = markable.location_id \
                 WHERE markable.operation_id = ?1 AND {live_fence}"
            ))
            .bind(&common)?,
        database
            .prepare(format!(
                "UPDATE locations \
                 SET state = 'tombstoned', tombstoned_at = ?6, \
                     revision = revision + 1, updated_at = ?6 \
                 WHERE state = 'available' \
                   AND id IN (SELECT location_id FROM gc_candidates \
                              WHERE gc_epoch_id = ?1 AND state = 'marked' \
                                AND location_revision = locations.revision + 1) \
                   AND {live_fence}"
            ))
            .bind(&common)?,
        database
            .prepare(format!(
                "INSERT OR IGNORE INTO gc_delete_tasks (\
                     id, operation_id, driver_id, storage_key, expected_location_count, \
                     state, created_at, updated_at\
                 ) \
                 SELECT ?1 || '/' || MIN(candidate.location_id), ?1, \
                        location.driver_id, location.storage_key, COUNT(*), \
                        'pending', ?6, ?6 \
                 FROM gc_candidates AS candidate \
                 JOIN locations AS location ON location.id = candidate.location_id \
                 WHERE candidate.gc_epoch_id = ?1 AND candidate.state = 'marked' \
                   AND location.state = 'tombstoned' \
                   AND candidate.location_revision = location.revision \
                   AND {live_fence} \
                 GROUP BY location.driver_id, location.storage_key"
            ))
            .bind(&common)?,
        database
            .prepare(format!(
                "UPDATE operations \
                 SET useful_bytes_total = (SELECT COUNT(*) FROM gc_candidates \
                                           WHERE gc_epoch_id = ?1), \
                     updated_at = ?6 \
                 WHERE id = ?1 AND kind = 'gc' AND state = 'running' \
                   AND phase = 'marking' AND {live_fence}"
            ))
            .bind(&common)?,
        database
            .prepare(
                "UPDATE gc_epochs \
                 SET state = 'grace', grace_until = ?1, updated_at = ?2 \
                 WHERE id = ?3 AND state = 'marking' \
                   AND EXISTS(SELECT 1 FROM gc_candidates WHERE gc_epoch_id = ?3) \
                   AND EXISTS(SELECT 1 FROM leases AS lease \
                              JOIN control_plane_state AS control ON control.singleton = 1 \
                              WHERE lease.id = ?4 AND lease.operation_id = ?3 \
                                AND lease.owner_client_id = ?5 AND lease.incarnation = ?6 \
                                AND lease.incarnation = control.incarnation \
                                AND lease.fencing_token = ?7 AND lease.lease_kind = 'write' \
                                AND lease.released_at IS NULL AND lease.expires_at > ?2 \
                                AND control.mode = 'active')",
            )
            .bind(&[
                copying::integer(grace_until)?,
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                copying::integer(requested.fencing_token)?,
            ])?,
        database
            .prepare(
                "UPDATE operations SET phase = 'grace', revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'running' AND phase = 'marking' \
                   AND EXISTS(SELECT 1 FROM gc_epochs WHERE id = ?2 AND state = 'grace')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
            ])?,
        database
            .prepare(
                "UPDATE gc_epochs SET state = 'succeeded', updated_at = ?1 \
                 WHERE id = ?2 AND state = 'marking' \
                   AND NOT EXISTS(SELECT 1 FROM gc_candidates WHERE gc_epoch_id = ?2) \
                   AND EXISTS(SELECT 1 FROM leases AS lease \
                              JOIN control_plane_state AS control ON control.singleton = 1 \
                              WHERE lease.id = ?3 AND lease.operation_id = ?2 \
                                AND lease.owner_client_id = ?4 AND lease.incarnation = ?5 \
                                AND lease.incarnation = control.incarnation \
                                AND lease.fencing_token = ?6 AND lease.lease_kind = 'write' \
                                AND lease.released_at IS NULL AND lease.expires_at > ?1 \
                                AND control.mode = 'active')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                copying::integer(requested.fencing_token)?,
            ])?,
        database
            .prepare(
                "UPDATE operation_attempts SET state = 'succeeded', finished_at = ?1 \
                 WHERE component_id = ?2 || '/gc' AND attempt = ?3 AND state = 'running' \
                   AND lease_id = ?4 AND incarnation = ?5 \
                   AND EXISTS(SELECT 1 FROM gc_epochs \
                              WHERE id = ?2 AND state IN ('grace', 'succeeded'))",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
                copying::integer(requested.fencing_token)?,
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&requested.incarnation),
            ])?,
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = CASE WHEN EXISTS(SELECT 1 FROM gc_epochs \
                                              WHERE id = ?1 AND state = 'succeeded') \
                                  THEN 'succeeded' ELSE 'stalled' END, \
                     useful_bytes_total = (SELECT COUNT(*) FROM gc_candidates \
                                           WHERE gc_epoch_id = ?1), \
                     useful_bytes_verified = 0, lease_id = NULL, fencing_token = NULL, \
                     finished_at = CASE WHEN EXISTS(SELECT 1 FROM gc_epochs \
                                                     WHERE id = ?1 AND state = 'succeeded') \
                                        THEN ?2 ELSE NULL END, \
                     revision = revision + 1, updated_at = ?2 \
                 WHERE operation_id = ?1 AND component_kind = 'gc' AND state = 'running' \
                   AND lease_id = ?3 AND fencing_token = ?4 \
                   AND EXISTS(SELECT 1 FROM gc_epochs \
                              WHERE id = ?1 AND state IN ('grace', 'succeeded'))",
            )
            .bind(&[
                JsValue::from_str(&operation.id),
                copying::integer(now)?,
                JsValue::from_str(&requested.lease_id),
                copying::integer(requested.fencing_token)?,
            ])?,
        database
            .prepare(
                "UPDATE operations SET state = 'verifying', phase = 'verifying', \
                        revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'running' \
                   AND EXISTS(SELECT 1 FROM gc_epochs WHERE id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
            ])?,
        database
            .prepare(
                "UPDATE operations SET state = 'committing', phase = 'committing', \
                        revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'verifying'",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
            ])?,
        database
            .prepare(
                "UPDATE operations SET state = 'succeeded', phase = 'succeeded', \
                        useful_bytes_verified = useful_bytes_total, finished_at = ?1, \
                        revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'committing'",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&operation.id),
            ])?,
        database
            .prepare(
                "UPDATE leases SET released_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND operation_id = ?3 AND owner_client_id = ?4 \
                   AND incarnation = ?5 AND fencing_token = ?6 AND lease_kind = 'write' \
                   AND released_at IS NULL \
                   AND EXISTS(SELECT 1 FROM gc_epochs \
                              WHERE id = ?3 AND state IN ('grace', 'succeeded'))",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&requested.lease_id),
                JsValue::from_str(&operation.id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&requested.incarnation),
                copying::integer(requested.fencing_token)?,
            ])?,
    ];
    database.batch(statements).await?;

    Ok(())
}

pub(crate) async fn claim(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid GC operation ID", 400);
    }
    let requested = request.json::<ClaimRequest>().await?;
    let lease_seconds = requested
        .lease_seconds
        .unwrap_or(DEFAULT_DELETE_LEASE_SECONDS);
    if !(MINIMUM_DELETE_LEASE_SECONDS..=MAXIMUM_DELETE_LEASE_SECONDS).contains(&lease_seconds) {
        return Response::error("GC delete lease duration is out of range", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(operation) = find_operation_by_id_any_client(&database, operation_id).await? else {
        return Response::error("GC operation is unavailable", 409);
    };
    if operation.gc_state == "succeeded" && operation.state == "succeeded" {
        return Response::from_json(&ClaimResponse {
            state: "succeeded".to_owned(),
            task: None,
        });
    }
    if let Some(task) = load_resumable_task(&database, client, operation_id).await? {
        start_sweeping(&database, client, &task).await?;

        return Response::from_json(&ClaimResponse {
            state: "claimed".to_owned(),
            task: Some(task),
        });
    }

    let now = copying::current_unix_seconds();
    let Some(candidate) = load_candidate(&database, client, operation_id, now).await? else {
        return Response::error("no safe GC delete task is currently eligible", 409);
    };
    let expiry = now
        .checked_add(lease_seconds)
        .ok_or_else(|| worker::Error::RustError("GC delete lease expiry overflows".to_owned()))?;
    let claim_result = database
        .prepare(
            "UPDATE gc_delete_tasks \
             SET state = 'claimed', owner_client_id = ?1, \
                 incarnation = (SELECT incarnation FROM control_plane_state WHERE singleton = 1), \
                 fencing_token = fencing_token + 1, lease_expires_at = ?2, \
                 attempt_count = attempt_count + 1, claimed_at = ?3, updated_at = ?3 \
             WHERE id = ?4 AND operation_id = ?5 \
               AND (state IN ('pending', 'failed') \
                    OR (state = 'claimed' AND lease_expires_at <= ?3)) \
               AND id IN (SELECT id FROM safe_gc_delete_tasks)",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            copying::integer(expiry)?,
            copying::integer(now)?,
            JsValue::from_str(&candidate.task_id),
            JsValue::from_str(operation_id),
        ])?
        .run()
        .await;
    if claim_result.is_err() {
        return Response::error("GC delete task became unsafe while claiming", 409);
    }

    let Some(task) = load_owned_task(&database, client, &candidate.task_id).await? else {
        return Response::error("GC delete task was claimed concurrently", 409);
    };
    start_sweeping(&database, client, &task).await?;

    Response::from_json(&ClaimResponse {
        state: "claimed".to_owned(),
        task: Some(task),
    })
}

pub(crate) async fn revalidate(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<FenceRequest>().await?;
    let lease_seconds = requested
        .lease_seconds
        .unwrap_or(DEFAULT_DELETE_LEASE_SECONDS);
    if !valid_fence_request(&requested)
        || !(MINIMUM_DELETE_LEASE_SECONDS..=MAXIMUM_DELETE_LEASE_SECONDS).contains(&lease_seconds)
    {
        return Response::error("invalid GC delete revalidation", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    let expiry = now
        .checked_add(lease_seconds)
        .ok_or_else(|| worker::Error::RustError("GC delete lease expiry overflows".to_owned()))?;
    let update = database
        .prepare(
            "UPDATE gc_delete_tasks \
             SET fencing_token = fencing_token + 1, lease_expires_at = ?1, updated_at = ?2 \
             WHERE id = ?3 AND state = 'claimed' AND owner_client_id = ?4 \
               AND incarnation = ?5 AND fencing_token = ?6 AND lease_expires_at > ?2 \
               AND id IN (SELECT id FROM safe_gc_delete_tasks)",
        )
        .bind(&[
            copying::integer(expiry)?,
            copying::integer(now)?,
            JsValue::from_str(&requested.task_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .run()
        .await;
    if update.is_err() {
        return Response::error("GC delete task failed final safety validation", 409);
    }

    let Some(task) = load_owned_task(&database, client, &requested.task_id).await? else {
        return Response::error("GC delete task fence is stale", 409);
    };
    if task.fencing_token != requested.fencing_token + 1 {
        return Response::error("GC delete task fence is stale", 409);
    }

    Response::from_json(&task)
}

pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<FenceRequest>().await?;
    if !valid_fence_request(&requested) {
        return Response::error("invalid GC delete completion", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(task) = load_task(&database, &requested.task_id).await? else {
        return Response::error("GC delete task is unavailable", 409);
    };
    if !task_matches(&task, client, &requested) {
        return Response::error("GC delete task fence is stale", 409);
    }
    if task.state == "deleted" {
        return completion_response(&database, &task).await;
    }
    if task.state != "claimed"
        || task
            .lease_expires_at
            .is_none_or(|expiry| expiry <= copying::current_unix_seconds())
    {
        return Response::error("GC delete task fence expired", 409);
    }

    if let Err(error) = finalize_delete(&database, client, &task).await {
        return Response::error(format!("GC delete completion was rejected: {error}"), 409);
    }
    let Some(completed) = load_task(&database, &requested.task_id).await? else {
        return Response::error("GC delete task disappeared", 409);
    };
    if completed.state != "deleted" {
        return Response::error("GC delete task did not commit", 409);
    }

    completion_response(&database, &completed).await
}

pub(crate) async fn fail(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<FailureRequest>().await?;
    if !copying::valid_string(&requested.task_id, 8_192)
        || !copying::valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
        || !copying::valid_string(&requested.error_code, 256)
    {
        return Response::error("invalid GC delete failure", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    database
        .batch(vec![
            database
                .prepare(
                    "UPDATE gc_delete_tasks \
                     SET state = 'failed', last_error_code = ?1, lease_expires_at = NULL, \
                         updated_at = ?2 \
                     WHERE id = ?3 AND state = 'claimed' AND owner_client_id = ?4 \
                       AND incarnation = ?5 AND fencing_token = ?6",
                )
                .bind(&[
                    JsValue::from_str(&requested.error_code),
                    copying::integer(now)?,
                    JsValue::from_str(&requested.task_id),
                    JsValue::from_str(&client.id),
                    JsValue::from_str(&requested.incarnation),
                    copying::integer(requested.fencing_token)?,
                ])?,
            database
                .prepare(
                    "UPDATE gc_candidates SET state = 'failed', updated_at = ?1 \
                     WHERE state = 'delete_pending' \
                       AND gc_epoch_id = (SELECT operation_id FROM gc_delete_tasks WHERE id = ?2) \
                       AND location_id IN (\
                           SELECT location.id FROM locations AS location \
                           JOIN gc_delete_tasks AS task \
                             ON task.driver_id = location.driver_id \
                            AND task.storage_key = location.storage_key \
                           WHERE task.id = ?2 AND task.state = 'failed'\
                       )",
                )
                .bind(&[
                    copying::integer(now)?,
                    JsValue::from_str(&requested.task_id),
                ])?,
        ])
        .await?;

    let Some(task) = load_task(&database, &requested.task_id).await? else {
        return Response::error("GC delete task is unavailable", 409);
    };
    if task.state != "failed"
        || task.owner_client_id.as_deref() != Some(client.id.as_str())
        || task.incarnation.as_deref() != Some(requested.incarnation.as_str())
        || task.fencing_token != requested.fencing_token
    {
        return Response::error("GC delete failure fence is stale", 409);
    }

    Response::from_json(&task)
}

async fn start_sweeping(
    database: &D1Database,
    client: &AuthenticatedClient,
    task: &DeleteTask,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    database
        .batch(vec![
            database
                .prepare(
                    "UPDATE gc_epochs SET state = 'sweeping', updated_at = ?1 \
                     WHERE id = ?2 AND state = 'grace'",
                )
                .bind(&[
                    copying::integer(now)?,
                    JsValue::from_str(&task.operation_id),
                ])?,
            database
                .prepare(
                    "UPDATE operations SET phase = 'sweeping', revision = revision + 1, \
                            updated_at = ?1 \
                     WHERE id = ?2 AND kind = 'gc' AND state = 'running' \
                       AND phase = 'grace'",
                )
                .bind(&[
                    copying::integer(now)?,
                    JsValue::from_str(&task.operation_id),
                ])?,
            database
                .prepare(
                    "UPDATE gc_candidates SET state = 'delete_pending', updated_at = ?1 \
                     WHERE gc_epoch_id = ?2 AND state IN ('marked', 'failed') \
                       AND location_id IN (SELECT id FROM locations \
                                          WHERE driver_id = ?3 AND storage_key = ?4) \
                       AND EXISTS(SELECT 1 FROM gc_delete_tasks \
                                  WHERE id = ?5 AND state = 'claimed' \
                                    AND owner_client_id = ?6 AND fencing_token = ?7)",
                )
                .bind(&[
                    copying::integer(now)?,
                    JsValue::from_str(&task.operation_id),
                    JsValue::from_str(&task.driver_id),
                    JsValue::from_str(&task.storage_key),
                    JsValue::from_str(&task.task_id),
                    JsValue::from_str(&client.id),
                    copying::integer(task.fencing_token)?,
                ])?,
            database
                .prepare(
                    "UPDATE operation_components \
                     SET client_id = ?1, state = 'running', current_attempt = ?2, \
                         lease_id = ?3, fencing_token = ?2, revision = revision + 1, \
                         updated_at = ?4 \
                     WHERE operation_id = ?5 AND component_kind = 'gc' \
                       AND state IN ('stalled', 'running')",
                )
                .bind(&[
                    JsValue::from_str(&client.id),
                    copying::integer(task.fencing_token)?,
                    JsValue::from_str(&task.task_id),
                    copying::integer(now)?,
                    JsValue::from_str(&task.operation_id),
                ])?,
        ])
        .await?;

    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the fenced object delete and terminal GC transition stay auditable together"
)]
async fn finalize_delete(
    database: &D1Database,
    client: &AuthenticatedClient,
    task: &TaskStateRow,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    let incarnation = task.incarnation.as_deref().unwrap_or_default();
    let statements = vec![
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'deleted', deleted_at = ?1, revision = revision + 1, updated_at = ?1 \
                 WHERE state = 'tombstoned' AND driver_id = ?2 AND storage_key = ?3 \
                   AND id IN (SELECT location_id FROM gc_candidates \
                              WHERE gc_epoch_id = ?4 AND state = 'delete_pending' \
                                AND location_revision = locations.revision) \
                   AND EXISTS(SELECT 1 FROM gc_delete_tasks \
                              WHERE id = ?5 AND state = 'claimed' AND owner_client_id = ?6 \
                                AND incarnation = ?7 AND fencing_token = ?8 \
                                AND lease_expires_at > ?1)",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.driver_id),
                JsValue::from_str(&task.storage_key),
                JsValue::from_str(&task.operation_id),
                JsValue::from_str(&task.task_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(incarnation),
                copying::integer(task.fencing_token)?,
            ])?,
        database
            .prepare(
                "UPDATE gc_candidates SET state = 'deleted', updated_at = ?1 \
                 WHERE gc_epoch_id = ?2 AND state = 'delete_pending' \
                   AND location_id IN (SELECT id FROM locations \
                                      WHERE driver_id = ?3 AND storage_key = ?4 \
                                        AND state = 'deleted')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
                JsValue::from_str(&task.driver_id),
                JsValue::from_str(&task.storage_key),
            ])?,
        database
            .prepare(
                "UPDATE gc_delete_tasks \
                 SET state = 'deleted', deleted_at = ?1, updated_at = ?1 \
                 WHERE id = ?2 AND state = 'claimed' AND owner_client_id = ?3 \
                   AND incarnation = ?4 AND fencing_token = ?5 AND lease_expires_at > ?1",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.task_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(incarnation),
                copying::integer(task.fencing_token)?,
            ])?,
        database
            .prepare(
                "UPDATE gc_epochs SET state = 'succeeded', updated_at = ?1 \
                 WHERE id = ?2 AND state = 'sweeping' \
                   AND NOT EXISTS(SELECT 1 FROM gc_candidates \
                                  WHERE gc_epoch_id = ?2 AND state != 'deleted')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE operations SET state = 'verifying', phase = 'verifying', \
                        revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'running' \
                   AND EXISTS(SELECT 1 FROM gc_epochs WHERE id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE operations SET state = 'committing', phase = 'committing', \
                        revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'verifying'",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'succeeded', \
                     useful_bytes_verified = useful_bytes_total, finished_at = ?1, \
                     lease_id = NULL, fencing_token = NULL, revision = revision + 1, \
                     updated_at = ?1 \
                 WHERE operation_id = ?2 AND component_kind = 'gc' \
                   AND EXISTS(SELECT 1 FROM gc_epochs WHERE id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE operations \
                 SET state = 'succeeded', phase = 'succeeded', \
                     useful_bytes_verified = useful_bytes_total, finished_at = ?1, \
                     revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'gc' AND state = 'committing'",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
    ];
    database.batch(statements).await?;

    Ok(())
}

async fn load_retention(
    database: &D1Database,
    client: &AuthenticatedClient,
    namespace_id: &str,
) -> Result<Option<RetentionRow>> {
    database
        .prepare(
            "SELECT namespace.retention_policy_json \
             FROM namespaces AS namespace \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE namespace.id = ?1 AND control.mode = 'active' \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?2 AND namespace_id = namespace.id \
                            AND role = 'administrator')",
        )
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<RetentionRow>(None)
        .await
}

async fn has_live_mark_fence(
    database: &D1Database,
    client: &AuthenticatedClient,
    operation_id: &str,
    requested: &MarkRequest,
) -> Result<bool> {
    let fence = database
        .prepare(
            "SELECT lease.id AS lease_id \
             FROM leases AS lease \
             JOIN operations AS operation ON operation.id = lease.operation_id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE lease.id = ?1 AND lease.operation_id = ?2 AND lease.owner_client_id = ?3 \
               AND lease.incarnation = ?4 AND lease.incarnation = control.incarnation \
               AND lease.fencing_token = ?5 AND lease.lease_kind = 'write' \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch() \
               AND operation.kind = 'gc' AND operation.state = 'running' \
               AND operation.phase = 'marking' AND operation.incarnation = control.incarnation \
               AND control.mode = 'active'",
        )
        .bind(&[
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .first::<LiveFenceRow>(None)
        .await?;

    Ok(fence.is_some_and(|row| row.lease_id == requested.lease_id))
}

async fn has_committed_mark_fence(
    database: &D1Database,
    client: &AuthenticatedClient,
    operation_id: &str,
    requested: &MarkRequest,
) -> Result<bool> {
    let fence = database
        .prepare(
            "SELECT lease.id AS lease_id \
             FROM leases AS lease \
             JOIN operations AS operation ON operation.id = lease.operation_id \
             JOIN gc_epochs AS epoch ON epoch.id = operation.id \
             WHERE lease.id = ?1 AND lease.operation_id = ?2 AND lease.owner_client_id = ?3 \
               AND lease.incarnation = ?4 AND lease.fencing_token = ?5 \
               AND lease.lease_kind = 'write' AND lease.released_at IS NOT NULL \
               AND operation.kind = 'gc' AND operation.requested_by = ?3 \
               AND epoch.state IN ('grace', 'sweeping', 'succeeded')",
        )
        .bind(&[
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .first::<LiveFenceRow>(None)
        .await?;

    Ok(fence.is_some_and(|row| row.lease_id == requested.lease_id))
}

async fn find_operation(
    database: &D1Database,
    namespace_id: &str,
    idempotency_key: &str,
    client_id: &str,
) -> Result<Option<GcOperation>> {
    database
        .prepare(format!(
            "{} WHERE operation.namespace_id = ?1 AND operation.idempotency_key = ?2 \
             AND operation.requested_by = ?3",
            operation_query()
        ))
        .bind(&[
            JsValue::from_str(namespace_id),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(client_id),
        ])?
        .first::<GcOperation>(None)
        .await
}

async fn find_operation_by_id(
    database: &D1Database,
    operation_id: &str,
    client_id: &str,
) -> Result<Option<GcOperation>> {
    database
        .prepare(format!(
            "{} WHERE operation.id = ?1 AND operation.requested_by = ?2",
            operation_query()
        ))
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(client_id),
        ])?
        .first::<GcOperation>(None)
        .await
}

async fn find_operation_by_id_any_client(
    database: &D1Database,
    operation_id: &str,
) -> Result<Option<GcOperation>> {
    database
        .prepare(format!("{} WHERE operation.id = ?1", operation_query()))
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<GcOperation>(None)
        .await
}

fn operation_query() -> &'static str {
    "SELECT operation.id, operation.namespace_id, operation.kind, operation.state, \
            operation.phase, operation.requested_by, operation.incarnation, \
            operation.revision, intent.cutoff_at, intent.grace_seconds, epoch.grace_until, \
            epoch.state AS gc_state, \
            (SELECT COUNT(*) FROM gc_candidates \
             WHERE gc_epoch_id = operation.id) AS candidate_count, \
            (SELECT COUNT(*) FROM gc_delete_tasks \
             WHERE operation_id = operation.id) AS object_count, \
            operation.created_at, operation.updated_at \
     FROM operations AS operation \
     JOIN gc_intents AS intent ON intent.operation_id = operation.id \
     JOIN gc_epochs AS epoch ON epoch.id = operation.id"
}

async fn load_candidate(
    database: &D1Database,
    client: &AuthenticatedClient,
    operation_id: &str,
    now: u64,
) -> Result<Option<TaskStateRow>> {
    database
        .prepare(
            "SELECT task.id AS task_id, task.operation_id, task.driver_id, task.storage_key, \
                    task.expected_location_count, task.owner_client_id, task.incarnation, \
                    task.fencing_token, task.lease_expires_at, task.attempt_count, task.state \
             FROM gc_delete_tasks AS task \
             JOIN safe_gc_delete_tasks AS safe ON safe.id = task.id \
             JOIN operations AS operation ON operation.id = task.operation_id \
             WHERE task.operation_id = ?1 \
               AND (task.state IN ('pending', 'failed') \
                    OR (task.state = 'claimed' AND task.lease_expires_at <= ?2)) \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?3 AND namespace_id = operation.namespace_id \
                            AND role IN ('janitor', 'administrator')) \
             ORDER BY task.created_at, task.id LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            copying::integer(now)?,
            JsValue::from_str(&client.id),
        ])?
        .first::<TaskStateRow>(None)
        .await
}

async fn load_owned_task(
    database: &D1Database,
    client: &AuthenticatedClient,
    task_id: &str,
) -> Result<Option<DeleteTask>> {
    database
        .prepare(
            "SELECT id AS task_id, operation_id, driver_id, storage_key, \
                    expected_location_count, owner_client_id, incarnation, fencing_token, \
                    lease_expires_at, attempt_count, state \
             FROM gc_delete_tasks \
             WHERE id = ?1 AND state = 'claimed' AND owner_client_id = ?2 \
               AND lease_expires_at > unixepoch()",
        )
        .bind(&[JsValue::from_str(task_id), JsValue::from_str(&client.id)])?
        .first::<DeleteTask>(None)
        .await
}

async fn load_resumable_task(
    database: &D1Database,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Option<DeleteTask>> {
    database
        .prepare(
            "SELECT task.id AS task_id, task.operation_id, task.driver_id, task.storage_key, \
                    task.expected_location_count, task.owner_client_id, task.incarnation, \
                    task.fencing_token, task.lease_expires_at, task.attempt_count, task.state \
             FROM gc_delete_tasks AS task \
             JOIN safe_gc_delete_tasks AS safe ON safe.id = task.id \
             WHERE task.operation_id = ?1 AND task.state = 'claimed' \
               AND task.owner_client_id = ?2 AND task.lease_expires_at > unixepoch() \
             ORDER BY task.claimed_at, task.id LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<DeleteTask>(None)
        .await
}

async fn load_task(database: &D1Database, task_id: &str) -> Result<Option<TaskStateRow>> {
    database
        .prepare(
            "SELECT id AS task_id, operation_id, driver_id, storage_key, \
                    expected_location_count, owner_client_id, incarnation, fencing_token, \
                    lease_expires_at, attempt_count, state \
             FROM gc_delete_tasks WHERE id = ?1",
        )
        .bind(&[JsValue::from_str(task_id)])?
        .first::<TaskStateRow>(None)
        .await
}

async fn completion_response(database: &D1Database, task: &TaskStateRow) -> Result<Response> {
    let state = find_operation_by_id_any_client(database, &task.operation_id)
        .await?
        .map_or_else(|| "unknown".to_owned(), |operation| operation.gc_state);
    Response::from_json(&CompletionResponse {
        task_id: task.task_id.clone(),
        operation_id: task.operation_id.clone(),
        locations_deleted: task.expected_location_count,
        task_state: "deleted",
        gc_state: state,
    })
}

fn mark_response(operation: &GcOperation) -> Result<Response> {
    Response::from_json(&MarkResponse {
        operation_id: operation.id.clone(),
        candidates_marked: operation.candidate_count,
        objects_marked: operation.object_count,
        grace_until: operation.grace_until,
        state: operation.gc_state.clone(),
    })
}

fn parse_retention(encoded: &str) -> Result<(u64, u64)> {
    let policy = serde_json::from_str::<RetentionPolicy>(encoded)
        .map_err(|error| worker::Error::RustError(format!("decode retention policy: {error}")))?;
    let minimum_age = policy.gc_minimum_age.unwrap_or(DEFAULT_MINIMUM_AGE_SECONDS);
    let grace = policy.gc_grace.unwrap_or(DEFAULT_GRACE_SECONDS);
    if !(MINIMUM_RETENTION_SECONDS..=MAXIMUM_RETENTION_SECONDS).contains(&minimum_age)
        || !(MINIMUM_RETENTION_SECONDS..=MAXIMUM_RETENTION_SECONDS).contains(&grace)
    {
        return Err(worker::Error::RustError(
            "GC retention policy is out of range".to_owned(),
        ));
    }

    Ok((minimum_age, grace))
}

fn task_matches(task: &TaskStateRow, client: &AuthenticatedClient, request: &FenceRequest) -> bool {
    task.owner_client_id.as_deref() == Some(client.id.as_str())
        && task.incarnation.as_deref() == Some(request.incarnation.as_str())
        && task.fencing_token == request.fencing_token
}

fn valid_mark_request(request: &MarkRequest) -> bool {
    copying::valid_string(&request.lease_id, 256)
        && copying::valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
}

fn valid_fence_request(request: &FenceRequest) -> bool {
    copying::valid_string(&request.task_id, 8_192)
        && copying::valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate GC operation ID: {error}")))?;
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}
