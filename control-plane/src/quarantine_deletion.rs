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
struct CompletionRequest {
    task_id: String,
    incarnation: String,
    fencing_token: u64,
    outcome: String,
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
    driver_revision: u64,
    storage_key: String,
    expected_revision: u64,
    provider_version: Option<String>,
    etag: Option<String>,
    size_bytes: u64,
    delete_after: u64,
    owner_client_id: String,
    incarnation: String,
    fencing_token: u64,
    lease_expires_at: u64,
    attempt_count: u64,
    state: String,
}

#[derive(Deserialize, Serialize)]
struct TaskStateRow {
    task_id: String,
    operation_id: String,
    driver_id: String,
    driver_revision: u64,
    storage_key: String,
    expected_revision: u64,
    provider_version: Option<String>,
    etag: Option<String>,
    size_bytes: u64,
    delete_after: u64,
    owner_client_id: Option<String>,
    incarnation: Option<String>,
    fencing_token: u64,
    lease_expires_at: Option<u64>,
    attempt_count: u64,
    state: String,
    completion_outcome: Option<String>,
}

#[derive(Serialize)]
struct ClaimResponse {
    state: String,
    task: Option<DeleteTask>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
}

#[derive(Serialize)]
struct CompletionResponse {
    task_id: String,
    operation_id: String,
    quarantine_revision: u64,
    task_state: String,
    quarantine_state: String,
    outcome: String,
}

#[derive(Deserialize)]
struct CompletionRow {
    task_id: String,
    operation_id: String,
    quarantine_revision: u64,
    task_state: String,
    quarantine_state: String,
    outcome: String,
}

#[derive(Serialize)]
struct FailureResponse {
    task_id: String,
    operation_id: String,
    incarnation: Option<String>,
    fencing_token: u64,
    state: String,
}

pub(crate) async fn claim(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    if !copying::valid_hex(operation_id, 32) {
        return Response::error("invalid quarantine operation ID", 400);
    }
    let requested = request.json::<ClaimRequest>().await?;
    let lease_seconds = requested
        .lease_seconds
        .unwrap_or(DEFAULT_DELETE_LEASE_SECONDS);
    if !valid_lease_seconds(lease_seconds) {
        return Response::error("quarantine delete lease duration is out of range", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(existing) = load_task_by_operation(&database, client, operation_id).await? else {
        return Response::error("quarantine delete task is unavailable", 409);
    };
    if matches!(existing.state.as_str(), "deleted" | "superseded") {
        return terminal_claim_response(existing);
    }
    if let Some(task) = load_resumable_task(&database, client, operation_id).await? {
        return Response::from_json(&ClaimResponse {
            state: "claimed".to_owned(),
            task: Some(task),
            outcome: None,
        });
    }

    let now = copying::current_unix_seconds();
    let Some(candidate) = load_candidate(&database, client, operation_id, now).await? else {
        return Response::error("no safe quarantine delete task is currently eligible", 409);
    };
    let expiry = now.checked_add(lease_seconds).ok_or_else(|| {
        worker::Error::RustError("quarantine delete lease expiry overflows".to_owned())
    })?;
    let update = database
        .prepare(
            "UPDATE quarantine_delete_tasks \
             SET state = 'claimed', owner_client_id = ?1, \
                 incarnation = (SELECT incarnation FROM control_plane_state WHERE singleton = 1), \
                 fencing_token = fencing_token + 1, lease_expires_at = ?2, \
                 attempt_count = attempt_count + 1, last_error_code = NULL, \
                 claimed_at = ?3, updated_at = ?3 \
             WHERE id = ?4 AND operation_id = ?5 \
               AND (state IN ('pending', 'failed') \
                    OR (state = 'claimed' AND (lease_expires_at <= ?3 \
                        OR incarnation != (SELECT incarnation FROM control_plane_state \
                                           WHERE singleton = 1)))) \
               AND id IN (SELECT id FROM safe_quarantine_delete_tasks)",
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
    if update.is_err() {
        return Response::error("quarantine delete task became unsafe while claiming", 409);
    }

    let Some(task) = load_owned_task(&database, client, &candidate.task_id).await? else {
        return Response::error("quarantine delete task was claimed concurrently", 409);
    };
    Response::from_json(&ClaimResponse {
        state: "claimed".to_owned(),
        task: Some(task),
        outcome: None,
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
    if !valid_fence(
        &requested.task_id,
        &requested.incarnation,
        requested.fencing_token,
    ) || !valid_lease_seconds(lease_seconds)
    {
        return Response::error("invalid quarantine delete revalidation", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    let expiry = now.checked_add(lease_seconds).ok_or_else(|| {
        worker::Error::RustError("quarantine delete lease expiry overflows".to_owned())
    })?;
    let update = database
        .prepare(
            "UPDATE quarantine_delete_tasks \
             SET fencing_token = fencing_token + 1, lease_expires_at = ?1, updated_at = ?2 \
             WHERE id = ?3 AND state = 'claimed' AND owner_client_id = ?4 \
               AND incarnation = ?5 AND fencing_token = ?6 AND lease_expires_at > ?2 \
               AND id IN (SELECT id FROM safe_quarantine_delete_tasks)",
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
        return Response::error("quarantine delete task failed final safety validation", 409);
    }

    let Some(task) = load_owned_task(&database, client, &requested.task_id).await? else {
        return Response::error("quarantine delete task fence is stale", 409);
    };
    if task.fencing_token != requested.fencing_token + 1 {
        return Response::error("quarantine delete task fence is stale", 409);
    }

    Response::from_json(&task)
}

pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<CompletionRequest>().await?;
    if !valid_fence(
        &requested.task_id,
        &requested.incarnation,
        requested.fencing_token,
    ) || !matches!(requested.outcome.as_str(), "deleted" | "already_absent")
    {
        return Response::error("invalid quarantine delete completion", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let Some(task) = load_task(&database, &requested.task_id).await? else {
        return Response::error("quarantine delete task is unavailable", 409);
    };
    if !task_matches(
        &task,
        client,
        &requested.incarnation,
        requested.fencing_token,
    ) {
        return Response::error("quarantine delete task fence is stale", 409);
    }
    if task.state == "deleted" {
        if task.completion_outcome.as_deref() != Some(requested.outcome.as_str()) {
            return Response::error("quarantine delete completion outcome changed", 409);
        }

        return completion_response(&database, &task.task_id).await;
    }
    if task.state != "claimed"
        || task
            .lease_expires_at
            .is_none_or(|expiry| expiry <= copying::current_unix_seconds())
    {
        return Response::error("quarantine delete task fence expired", 409);
    }

    if let Err(error) = finalize_delete(&database, client, &task, &requested.outcome).await {
        return Response::error(
            format!("quarantine delete completion was rejected: {error}"),
            409,
        );
    }
    completion_response(&database, &task.task_id).await
}

pub(crate) async fn fail(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<FailureRequest>().await?;
    if !valid_fence(
        &requested.task_id,
        &requested.incarnation,
        requested.fencing_token,
    ) || !copying::valid_string(&requested.error_code, 256)
    {
        return Response::error("invalid quarantine delete failure", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    database
        .prepare(
            "UPDATE quarantine_delete_tasks \
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
        ])?
        .run()
        .await?;

    let Some(task) = load_task(&database, &requested.task_id).await? else {
        return Response::error("quarantine delete task is unavailable", 409);
    };
    if task.state != "failed"
        || !task_matches(
            &task,
            client,
            &requested.incarnation,
            requested.fencing_token,
        )
    {
        return Response::error("quarantine delete failure fence is stale", 409);
    }

    Response::from_json(&FailureResponse {
        task_id: task.task_id,
        operation_id: task.operation_id,
        incarnation: task.incarnation,
        fencing_token: task.fencing_token,
        state: task.state,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the fenced ledger transition, finding resolution, task completion, and audit are atomic"
)]
async fn finalize_delete(
    database: &D1Database,
    client: &AuthenticatedClient,
    task: &TaskStateRow,
    outcome: &str,
) -> Result<()> {
    let now = copying::current_unix_seconds();
    let incarnation = task.incarnation.as_deref().unwrap_or_default();
    let statements = vec![
        database
            .prepare(
                "UPDATE quarantined_provider_objects \
                 SET state = 'deleted', deleted_at = ?1, revision = revision + 1 \
                 WHERE driver_id = ?2 AND storage_key = ?3 AND state = 'tombstoned' \
                   AND driver_revision = ?4 AND revision >= ?5 \
                   AND provider_version IS ?6 AND etag IS ?7 AND size_bytes = ?8 \
                   AND delete_after = ?9 \
                   AND EXISTS(SELECT 1 FROM quarantine_delete_tasks AS task \
                              JOIN safe_quarantine_delete_tasks AS safe ON safe.id = task.id \
                              WHERE task.id = ?10 AND task.state = 'claimed' \
                                AND task.owner_client_id = ?11 AND task.incarnation = ?12 \
                                AND task.fencing_token = ?13 AND task.lease_expires_at > ?1)",
            )
            .bind(&[
                copying::integer(now)?,
                JsValue::from_str(&task.driver_id),
                JsValue::from_str(&task.storage_key),
                copying::integer(task.driver_revision)?,
                copying::integer(task.expected_revision)?,
                optional_string(task.provider_version.as_deref()),
                optional_string(task.etag.as_deref()),
                copying::integer(task.size_bytes)?,
                copying::integer(task.delete_after)?,
                JsValue::from_str(&task.task_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(incarnation),
                copying::integer(task.fencing_token)?,
            ])?,
        database
            .prepare(
                "INSERT INTO integrity_findings (\
                     id, namespace_id, subject_kind, subject_id, condition, state, \
                     evidence_json, first_observed_at, last_observed_at, acknowledged_at, \
                     resolved_at, revision\
                 ) \
                 SELECT task.id || '/finding', operation.namespace_id, 'provider_object', \
                        finding.subject_id, 'quarantined', 'resolved', \
                        json_set(finding.evidence_json, \
                                 '$.delete_task_id', task.id, \
                                 '$.delete_outcome', ?1, \
                                 '$.deleted_at', CAST(?2 AS INTEGER)), \
                        finding.first_observed_at, ?2, finding.acknowledged_at, ?2, \
                        finding.revision + 1 \
                 FROM quarantine_delete_tasks AS task \
                 JOIN operations AS operation ON operation.id = task.operation_id \
                 JOIN quarantined_provider_objects AS quarantine \
                   ON quarantine.driver_id = task.driver_id \
                  AND quarantine.storage_key = task.storage_key \
                 JOIN integrity_findings AS finding \
                   ON finding.namespace_id = operation.namespace_id \
                  AND finding.subject_kind = 'provider_object' \
                  AND finding.subject_id = json_array(task.driver_id, task.storage_key) \
                  AND finding.condition = 'quarantined' AND finding.state = 'tombstoned' \
                 WHERE task.id = ?3 AND quarantine.state = 'deleted' \
                 ON CONFLICT(subject_kind, subject_id, condition, state) DO UPDATE SET \
                     evidence_json = excluded.evidence_json, \
                     last_observed_at = excluded.last_observed_at, \
                     acknowledged_at = excluded.acknowledged_at, \
                     resolved_at = excluded.resolved_at, \
                     revision = integrity_findings.revision + 1",
            )
            .bind(&[
                JsValue::from_str(outcome),
                copying::integer(now)?,
                JsValue::from_str(&task.task_id),
            ])?,
        database
            .prepare(
                "DELETE FROM integrity_findings \
                 WHERE subject_kind = 'provider_object' AND condition = 'quarantined' \
                   AND state = 'tombstoned' \
                   AND subject_id = json_array(?1, ?2) \
                   AND namespace_id = (SELECT namespace_id FROM operations WHERE id = ?3) \
                   AND EXISTS(SELECT 1 FROM quarantined_provider_objects \
                              WHERE driver_id = ?1 AND storage_key = ?2 AND state = 'deleted')",
            )
            .bind(&[
                JsValue::from_str(&task.driver_id),
                JsValue::from_str(&task.storage_key),
                JsValue::from_str(&task.operation_id),
            ])?,
        database
            .prepare(
                "UPDATE quarantine_delete_tasks \
                 SET state = 'deleted', completion_outcome = ?1, deleted_at = ?2, updated_at = ?2 \
                 WHERE id = ?3 AND state = 'claimed' AND owner_client_id = ?4 \
                   AND incarnation = ?5 AND fencing_token = ?6 AND lease_expires_at > ?2",
            )
            .bind(&[
                JsValue::from_str(outcome),
                copying::integer(now)?,
                JsValue::from_str(&task.task_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(incarnation),
                copying::integer(task.fencing_token)?,
            ])?,
        database
            .prepare(
                "INSERT OR IGNORE INTO audit_events (\
                     id, namespace_id, operation_id, client_id, event_kind, subject_kind, \
                     subject_id, details_json, created_at\
                 ) \
                 SELECT task.id || '/audit', operation.namespace_id, operation.id, ?1, \
                        'quarantine_deleted', 'provider_object', \
                        json_array(task.driver_id, task.storage_key), \
                        json_object(\
                            'task_id', task.id, 'outcome', task.completion_outcome, \
                            'driver_revision', task.driver_revision, \
                            'expected_revision', task.expected_revision, \
                            'result_revision', quarantine.revision, \
                            'provider_version', task.provider_version, 'etag', task.etag, \
                            'size_bytes', task.size_bytes, 'delete_after', task.delete_after, \
                            'incarnation', task.incarnation, 'fencing_token', task.fencing_token\
                        ), ?2 \
                 FROM quarantine_delete_tasks AS task \
                 JOIN operations AS operation ON operation.id = task.operation_id \
                 JOIN quarantined_provider_objects AS quarantine \
                   ON quarantine.driver_id = task.driver_id \
                  AND quarantine.storage_key = task.storage_key \
                 WHERE task.id = ?3 AND task.state = 'deleted' \
                   AND quarantine.state = 'deleted'",
            )
            .bind(&[
                JsValue::from_str(&client.id),
                copying::integer(now)?,
                JsValue::from_str(&task.task_id),
            ])?,
    ];
    database.batch(statements).await?;

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
            "SELECT task.id AS task_id, task.operation_id, task.driver_id, \
                    task.driver_revision, task.storage_key, task.expected_revision, \
                    task.provider_version, task.etag, task.size_bytes, task.delete_after, \
                    task.owner_client_id, task.incarnation, task.fencing_token, \
                    task.lease_expires_at, task.attempt_count, task.state, \
                    task.completion_outcome \
             FROM quarantine_delete_tasks AS task \
             JOIN safe_quarantine_delete_tasks AS safe ON safe.id = task.id \
             JOIN operations AS operation ON operation.id = task.operation_id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE task.operation_id = ?1 \
               AND (task.state IN ('pending', 'failed') \
                    OR (task.state = 'claimed' AND (task.lease_expires_at <= ?2 \
                        OR task.incarnation != control.incarnation))) \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?3 AND namespace_id = operation.namespace_id \
                            AND role IN ('janitor', 'administrator')) \
             LIMIT 1",
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
            "SELECT task.id AS task_id, task.operation_id, task.driver_id, \
                    task.driver_revision, task.storage_key, task.expected_revision, \
                    task.provider_version, task.etag, task.size_bytes, task.delete_after, \
                    task.owner_client_id, task.incarnation, task.fencing_token, \
                    task.lease_expires_at, task.attempt_count, task.state \
             FROM quarantine_delete_tasks AS task \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE task.id = ?1 AND task.state = 'claimed' AND task.owner_client_id = ?2 \
               AND task.incarnation = control.incarnation \
               AND task.lease_expires_at > unixepoch()",
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
            "SELECT task.id AS task_id, task.operation_id, task.driver_id, \
                    task.driver_revision, task.storage_key, task.expected_revision, \
                    task.provider_version, task.etag, task.size_bytes, task.delete_after, \
                    task.owner_client_id, task.incarnation, task.fencing_token, \
                    task.lease_expires_at, task.attempt_count, task.state \
             FROM quarantine_delete_tasks AS task \
             JOIN safe_quarantine_delete_tasks AS safe ON safe.id = task.id \
             JOIN control_plane_state AS control ON control.singleton = 1 \
             WHERE task.operation_id = ?1 AND task.state = 'claimed' \
               AND task.owner_client_id = ?2 AND task.incarnation = control.incarnation \
               AND task.lease_expires_at > unixepoch() LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<DeleteTask>(None)
        .await
}

async fn load_task_by_operation(
    database: &D1Database,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Option<TaskStateRow>> {
    database
        .prepare(
            "SELECT task.id AS task_id, task.operation_id, task.driver_id, \
                    task.driver_revision, task.storage_key, task.expected_revision, \
                    task.provider_version, task.etag, task.size_bytes, task.delete_after, \
                    task.owner_client_id, task.incarnation, task.fencing_token, \
                    task.lease_expires_at, task.attempt_count, task.state, \
                    task.completion_outcome \
             FROM quarantine_delete_tasks AS task \
             JOIN operations AS operation ON operation.id = task.operation_id \
             WHERE task.operation_id = ?1 \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?2 AND namespace_id = operation.namespace_id \
                            AND role IN ('janitor', 'administrator'))",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
        ])?
        .first::<TaskStateRow>(None)
        .await
}

async fn load_task(database: &D1Database, task_id: &str) -> Result<Option<TaskStateRow>> {
    database
        .prepare(
            "SELECT id AS task_id, operation_id, driver_id, driver_revision, storage_key, \
                expected_revision, provider_version, etag, size_bytes, delete_after, \
                owner_client_id, incarnation, fencing_token, lease_expires_at, \
                attempt_count, state, completion_outcome \
             FROM quarantine_delete_tasks WHERE id = ?1",
        )
        .bind(&[JsValue::from_str(task_id)])?
        .first::<TaskStateRow>(None)
        .await
}

async fn completion_response(database: &D1Database, task_id: &str) -> Result<Response> {
    let completed = database
        .prepare(
            "SELECT task.id AS task_id, task.operation_id, \
                    quarantine.revision AS quarantine_revision, task.state AS task_state, \
                    quarantine.state AS quarantine_state, task.completion_outcome AS outcome \
             FROM quarantine_delete_tasks AS task \
             JOIN quarantined_provider_objects AS quarantine \
               ON quarantine.driver_id = task.driver_id \
              AND quarantine.storage_key = task.storage_key \
             WHERE task.id = ?1 AND task.state = 'deleted' \
               AND quarantine.state = 'deleted'",
        )
        .bind(&[JsValue::from_str(task_id)])?
        .first::<CompletionRow>(None)
        .await?;
    let Some(completed) = completed else {
        return Response::error("quarantine delete task did not commit", 409);
    };

    Response::from_json(&CompletionResponse {
        task_id: completed.task_id,
        operation_id: completed.operation_id,
        quarantine_revision: completed.quarantine_revision,
        task_state: completed.task_state,
        quarantine_state: completed.quarantine_state,
        outcome: completed.outcome,
    })
}

fn terminal_claim_response(task: TaskStateRow) -> Result<Response> {
    Response::from_json(&ClaimResponse {
        state: task.state,
        task: None,
        outcome: task.completion_outcome,
    })
}

fn task_matches(
    task: &TaskStateRow,
    client: &AuthenticatedClient,
    incarnation: &str,
    fencing_token: u64,
) -> bool {
    task.owner_client_id.as_deref() == Some(client.id.as_str())
        && task.incarnation.as_deref() == Some(incarnation)
        && task.fencing_token == fencing_token
}

fn valid_fence(task_id: &str, incarnation: &str, fencing_token: u64) -> bool {
    copying::valid_string(task_id, 8_192)
        && copying::valid_hex(incarnation, 32)
        && fencing_token > 0
}

fn valid_lease_seconds(value: u64) -> bool {
    (MINIMUM_DELETE_LEASE_SECONDS..=MAXIMUM_DELETE_LEASE_SECONDS).contains(&value)
}

fn optional_string(value: Option<&str>) -> JsValue {
    value.map_or_else(JsValue::null, JsValue::from_str)
}

#[cfg(test)]
mod tests {
    use super::{valid_fence, valid_lease_seconds};

    #[test]
    fn validates_quarantine_delete_boundaries() {
        assert!(valid_lease_seconds(60));
        assert!(!valid_lease_seconds(14));
        assert!(valid_fence(
            "task/quarantine-delete",
            "0123456789abcdef0123456789abcdef",
            1
        ));
    }
}
