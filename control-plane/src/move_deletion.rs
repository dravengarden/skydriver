use serde::{Deserialize, Serialize};
use worker::{D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, copying};

const DEFAULT_DELETE_LEASE_SECONDS: u64 = 60;
const MINIMUM_DELETE_LEASE_SECONDS: u64 = 15;
const MAXIMUM_DELETE_LEASE_SECONDS: u64 = 300;

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
    state: &'static str,
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

#[derive(Deserialize)]
struct MoveStateRow {
    state: String,
}

#[derive(Serialize)]
struct CompletionResponse {
    task_id: String,
    operation_id: String,
    locations_deleted: u64,
    task_state: &'static str,
    move_state: String,
}

pub(crate) async fn claim(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid move operation ID", 400);
    }
    let requested = request.json::<ClaimRequest>().await?;
    let lease_seconds = requested
        .lease_seconds
        .unwrap_or(DEFAULT_DELETE_LEASE_SECONDS);
    if !(MINIMUM_DELETE_LEASE_SECONDS..=MAXIMUM_DELETE_LEASE_SECONDS).contains(&lease_seconds) {
        return Response::error("move delete lease duration is out of range", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    ensure_tasks(&database, client, operation_id).await?;
    if move_state(&database, operation_id)
        .await?
        .is_some_and(|state| state.state == "succeeded")
    {
        return Response::from_json(&ClaimResponse {
            state: "succeeded",
            task: None,
        });
    }

    if let Some(task) = load_resumable_task(&database, client, operation_id).await? {
        return Response::from_json(&ClaimResponse {
            state: "claimed",
            task: Some(task),
        });
    }

    let now = copying::current_unix_seconds();
    let candidate = load_candidate(&database, client, operation_id, now).await?;
    let Some(candidate) = candidate else {
        return Response::error("no safe move delete task is currently eligible", 409);
    };
    let expiry = now
        .checked_add(lease_seconds)
        .ok_or_else(|| worker::Error::RustError("delete lease expiry overflows".to_owned()))?;
    let claim_result = database
        .prepare(
            "UPDATE move_delete_tasks \
             SET state = 'claimed', owner_client_id = ?1, \
                 incarnation = (SELECT incarnation FROM control_plane_state WHERE singleton = 1), \
                 fencing_token = fencing_token + 1, lease_expires_at = ?2, \
                 attempt_count = attempt_count + 1, claimed_at = ?3, updated_at = ?3 \
             WHERE id = ?4 AND operation_id = ?5 \
               AND (state IN ('pending', 'failed') \
                    OR (state = 'claimed' AND lease_expires_at <= ?3)) \
               AND id IN (SELECT id FROM safe_move_delete_tasks)",
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
        return Response::error("move delete task became unsafe while claiming", 409);
    }

    let Some(task) = load_owned_task(&database, client, &candidate.task_id).await? else {
        return Response::error("move delete task was claimed concurrently", 409);
    };
    start_deleting(&database, client, &task).await?;

    Response::from_json(&ClaimResponse {
        state: "claimed",
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
        return Response::error("invalid move delete revalidation", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    let expiry = now
        .checked_add(lease_seconds)
        .ok_or_else(|| worker::Error::RustError("delete lease expiry overflows".to_owned()))?;
    let update = database
        .prepare(
            "UPDATE move_delete_tasks \
             SET fencing_token = fencing_token + 1, lease_expires_at = ?1, updated_at = ?2 \
             WHERE id = ?3 AND state = 'claimed' AND owner_client_id = ?4 \
               AND incarnation = ?5 AND fencing_token = ?6 \
               AND lease_expires_at > ?2 \
               AND id IN (SELECT id FROM safe_move_delete_tasks)",
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
        return Response::error("move delete task failed final safety validation", 409);
    }

    let Some(task) = load_owned_task(&database, client, &requested.task_id).await? else {
        return Response::error("move delete task fence is stale", 409);
    };
    if task.fencing_token != requested.fencing_token + 1 {
        return Response::error("move delete task fence is stale", 409);
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
        return Response::error("invalid move delete completion", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(task) = load_task(&database, &requested.task_id).await? else {
        return Response::error("move delete task is unavailable", 409);
    };
    if !task_matches(&task, client, &requested) {
        return Response::error("move delete task fence is stale", 409);
    }
    if task.state == "deleted" {
        return completion_response(&database, &task).await;
    }
    if task.state != "claimed"
        || task
            .lease_expires_at
            .is_none_or(|expiry| expiry <= copying::current_unix_seconds())
    {
        return Response::error("move delete task fence expired", 409);
    }

    if let Err(error) = finalize_delete(&database, client, &task).await {
        return Response::error(format!("move delete completion was rejected: {error}"), 409);
    }
    let Some(completed) = load_task(&database, &requested.task_id).await? else {
        return Response::error("move delete task disappeared", 409);
    };
    if completed.state != "deleted" {
        return Response::error("move delete task did not commit", 409);
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
        return Response::error("invalid move delete failure", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    database
        .prepare(
            "UPDATE move_delete_tasks \
             SET state = 'failed', last_error_code = ?1, lease_expires_at = NULL, \
                 updated_at = ?2 \
             WHERE id = ?3 AND state = 'claimed' AND owner_client_id = ?4 \
               AND incarnation = ?5 AND fencing_token = ?6",
        )
        .bind(&[
            JsValue::from_str(&requested.error_code),
            copying::integer(copying::current_unix_seconds())?,
            JsValue::from_str(&requested.task_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.incarnation),
            copying::integer(requested.fencing_token)?,
        ])?
        .run()
        .await?;

    let Some(task) = load_task(&database, &requested.task_id).await? else {
        return Response::error("move delete task is unavailable", 409);
    };
    if task.state != "failed"
        || task.owner_client_id.as_deref() != Some(client.id.as_str())
        || task.incarnation.as_deref() != Some(requested.incarnation.as_str())
        || task.fencing_token != requested.fencing_token
    {
        return Response::error("move delete failure fence is stale", 409);
    }

    Response::from_json(&task)
}

async fn ensure_tasks(
    database: &D1Database,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    database
        .prepare(
            "INSERT OR IGNORE INTO move_delete_tasks (\
                 id, operation_id, driver_id, storage_key, expected_location_count, \
                 state, created_at, updated_at\
             ) \
             SELECT move.operation_id || '/' || MIN(source.location_id), move.operation_id, \
                    location.driver_id, location.storage_key, COUNT(*), 'pending', ?1, ?1 \
             FROM move_intents AS move \
             JOIN operations AS operation ON operation.id = move.operation_id \
             JOIN move_sources AS source ON source.operation_id = move.operation_id \
             JOIN locations AS location ON location.id = source.location_id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE move.operation_id = ?2 \
               AND move.state IN ('source_delete_pending', 'deleting') \
               AND operation.kind = 'move' AND operation.state = 'running' \
               AND operation.incarnation = control.incarnation AND control.mode = 'active' \
               AND source.state = 'tombstoned' AND location.state = 'tombstoned' \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?3 AND namespace_id = operation.namespace_id \
                            AND role IN ('janitor', 'administrator')) \
             GROUP BY move.operation_id, location.driver_id, location.storage_key",
        )
        .bind(&[
            copying::integer(now)?,
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
        ])?
        .run()
        .await?;

    Ok(())
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
             FROM move_delete_tasks AS task \
             JOIN safe_move_delete_tasks AS safe ON safe.id = task.id \
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
             FROM move_delete_tasks \
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
             FROM move_delete_tasks AS task \
             JOIN safe_move_delete_tasks AS safe ON safe.id = task.id \
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
             FROM move_delete_tasks WHERE id = ?1",
        )
        .bind(&[JsValue::from_str(task_id)])?
        .first::<TaskStateRow>(None)
        .await
}

async fn move_state(database: &D1Database, operation_id: &str) -> Result<Option<MoveStateRow>> {
    database
        .prepare("SELECT state FROM move_intents WHERE operation_id = ?1")
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<MoveStateRow>(None)
        .await
}

async fn start_deleting(
    database: &D1Database,
    client: &AuthenticatedClient,
    task: &DeleteTask,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    database
        .batch(vec![
            database
                .prepare(
                    "UPDATE move_intents SET state = 'deleting', updated_at = ?1 \
                     WHERE operation_id = ?2 AND state = 'source_delete_pending'",
                )
                .bind(&[
                    copying::integer(now)?,
                    JsValue::from_str(&task.operation_id),
                ])?,
            database
                .prepare(
                    "UPDATE operations SET phase = 'deleting', revision = revision + 1, \
                            updated_at = ?1 \
                     WHERE id = ?2 AND kind = 'move' AND state = 'running' \
                       AND phase = 'source_delete_pending'",
                )
                .bind(&[
                    copying::integer(now)?,
                    JsValue::from_str(&task.operation_id),
                ])?,
            database
                .prepare(
                    "UPDATE operation_components \
                     SET client_id = ?1, state = 'running', current_attempt = ?2, \
                         lease_id = ?3, fencing_token = ?2, revision = revision + 1, \
                         updated_at = ?4 \
                     WHERE operation_id = ?5 AND component_kind = 'move' \
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
    reason = "the fenced object deletion and final move transition remain auditable together"
)]
async fn finalize_delete(
    database: &D1Database,
    client: &AuthenticatedClient,
    task: &TaskStateRow,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    let incarnation = task.incarnation.as_deref().unwrap_or_default();
    let mut statements = vec![
        database
            .prepare(
                "UPDATE locations \
                 SET state = 'deleted', deleted_at = ?1, revision = revision + 1, updated_at = ?1 \
                 WHERE state = 'tombstoned' AND driver_id = ?2 AND storage_key = ?3 \
                   AND id IN (SELECT location_id FROM move_sources \
                              WHERE operation_id = ?4 AND state = 'tombstoned') \
                   AND EXISTS(SELECT 1 FROM move_delete_tasks \
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
                "UPDATE move_sources \
                 SET state = 'deleted', deleted_at = ?1, updated_at = ?1 \
                 WHERE operation_id = ?2 AND state = 'tombstoned' \
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
                "UPDATE move_delete_tasks \
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
                "UPDATE move_intents SET state = 'succeeded', updated_at = ?1 \
                 WHERE operation_id = ?2 AND state = 'deleting' \
                   AND NOT EXISTS(SELECT 1 FROM move_sources \
                                  WHERE operation_id = ?2 AND state != 'deleted')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
    ];
    statements.extend([
        database
            .prepare(
                "UPDATE operations \
                 SET state = 'verifying', revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'move' AND state = 'running' \
                   AND EXISTS(SELECT 1 FROM move_intents \
                              WHERE operation_id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE operations \
                 SET state = 'committing', revision = revision + 1, updated_at = ?1 \
                 WHERE id = ?2 AND kind = 'move' AND state = 'verifying' \
                   AND EXISTS(SELECT 1 FROM move_intents \
                              WHERE operation_id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE operation_components \
                 SET state = 'succeeded', finished_at = ?1, lease_id = NULL, \
                     fencing_token = NULL, revision = revision + 1, updated_at = ?1 \
                 WHERE operation_id = ?2 AND component_kind = 'move' \
                   AND EXISTS(SELECT 1 FROM move_intents \
                              WHERE operation_id = ?2 AND state = 'succeeded')",
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
                 WHERE id = ?2 AND kind = 'move' AND state = 'committing' \
                   AND EXISTS(SELECT 1 FROM move_intents \
                              WHERE operation_id = ?2 AND state = 'succeeded')",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.operation_id),
            ])?,
    ]);

    database.batch(statements).await?;

    Ok(())
}

async fn completion_response(database: &D1Database, task: &TaskStateRow) -> Result<Response> {
    let state = move_state(database, &task.operation_id)
        .await?
        .map_or_else(|| "unknown".to_owned(), |row| row.state);
    Response::from_json(&CompletionResponse {
        task_id: task.task_id.clone(),
        operation_id: task.operation_id.clone(),
        locations_deleted: task.expected_location_count,
        task_state: "deleted",
        move_state: state,
    })
}

fn task_matches(task: &TaskStateRow, client: &AuthenticatedClient, request: &FenceRequest) -> bool {
    task.owner_client_id.as_deref() == Some(client.id.as_str())
        && task.incarnation.as_deref() == Some(request.incarnation.as_str())
        && task.fencing_token == request.fencing_token
}

fn valid_fence_request(request: &FenceRequest) -> bool {
    copying::valid_string(&request.task_id, 8_192)
        && copying::valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
}
