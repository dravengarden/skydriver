use serde::{Deserialize, Serialize};
use worker::{D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{copying, vfs_tokens::AuthenticatedVfsToken};

const TASK_SCHEMA: &str = "carrack.vfs.put-delete-task.v1";
const DEFAULT_LEASE_SECONDS: u64 = 60;
const MINIMUM_LEASE_SECONDS: u64 = 15;
const MAXIMUM_LEASE_SECONDS: u64 = 300;
const MAXIMUM_ERROR_CODE_BYTES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    lease_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceRequest {
    incarnation: String,
    fencing_token: u64,
    lease_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionRequest {
    incarnation: String,
    fencing_token: u64,
    outcome: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureRequest {
    incarnation: String,
    fencing_token: u64,
    error_code: String,
}

#[derive(Deserialize, Serialize)]
struct DeleteTask {
    schema: Option<String>,
    task_id: String,
    filesystem_id: String,
    directory_id: String,
    driver_id: String,
    driver_revision: u64,
    storage_key: String,
    native_id: Option<String>,
    provider_version: Option<String>,
    etag: Option<String>,
    size_bytes: u64,
    encoded_sha256: String,
    delete_after: u64,
    incarnation: Option<String>,
    fencing_token: u64,
    lease_expires_at: Option<u64>,
    attempt_count: u64,
    state: String,
    completion_outcome: Option<String>,
}

#[derive(Serialize)]
struct ClaimResponse {
    state: &'static str,
    task: Option<DeleteTask>,
}

/// Claims one safe expired-upload deletion under a short VFS-token fence.
pub(crate) async fn claim(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    let requested = request.json::<ClaimRequest>().await?;
    let lease_seconds = requested.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !valid_lease_seconds(lease_seconds) {
        return Response::error("VFS put-delete lease duration is out of range", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    if let Some(task) = load_owned_task(&database, token, None, now).await? {
        return claim_response(Some(task));
    }

    let Some(task_id) = load_candidate(&database, token, now).await? else {
        return claim_response(None);
    };
    let lease_expires_at = now.checked_add(lease_seconds).ok_or_else(|| {
        worker::Error::RustError("VFS put-delete lease expiry overflows".to_owned())
    })?;
    let update = database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET state = 'claimed', owner_token_id = ?1,
                 incarnation = (SELECT incarnation FROM control_plane_state WHERE singleton = 1),
                 fencing_token = fencing_token + 1, lease_expires_at = ?2,
                 attempt_count = attempt_count + 1, last_error_code = NULL,
                 claimed_at = ?3, revalidated_at = NULL, updated_at = ?3
             WHERE id = ?4
               AND (state IN ('pending', 'failed')
                    OR (state = 'claimed' AND (
                        lease_expires_at <= ?3
                        OR incarnation != (
                            SELECT incarnation FROM control_plane_state WHERE singleton = 1
                        )
                    )))
               AND id IN (SELECT id FROM safe_vfs_put_delete_tasks)",
        )
        .bind(&[
            JsValue::from_str(&token.id),
            integer(lease_expires_at)?,
            integer(now)?,
            JsValue::from_str(&task_id),
        ])?
        .run()
        .await?;
    if changes(&update)? != 1 {
        return Response::error("VFS put-delete task became unsafe while claiming", 409);
    }

    let Some(task) = load_owned_task(&database, token, Some(&task_id), now).await? else {
        return Response::error("VFS put-delete task was claimed concurrently", 409);
    };
    record_audit(&database, token, &task, "put_delete_claimed", now).await?;
    claim_response(Some(task))
}

/// Rotates the fence after provider Stat and immediately before Delete.
pub(crate) async fn revalidate(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    task_id: &str,
) -> Result<Response> {
    let requested = request.json::<FenceRequest>().await?;
    let lease_seconds = requested.lease_seconds.unwrap_or(DEFAULT_LEASE_SECONDS);
    if !valid_task_id(task_id)
        || !valid_task_id(&requested.incarnation)
        || requested.fencing_token == 0
        || !valid_lease_seconds(lease_seconds)
    {
        return Response::error("invalid VFS put-delete revalidation", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let now = copying::current_unix_seconds();
    if !authorized(&database, token, task_id).await? {
        return Response::error("VFS put-delete revalidation is not authorized", 403);
    }
    let lease_expires_at = now.checked_add(lease_seconds).ok_or_else(|| {
        worker::Error::RustError("VFS put-delete lease expiry overflows".to_owned())
    })?;
    let update = database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET fencing_token = fencing_token + 1, lease_expires_at = ?1,
                 revalidated_at = ?2, updated_at = ?2
             WHERE id = ?3 AND state = 'claimed' AND owner_token_id = ?4
               AND incarnation = ?5 AND fencing_token = ?6
               AND lease_expires_at > ?2
               AND id IN (SELECT id FROM safe_vfs_put_delete_tasks)",
        )
        .bind(&[
            integer(lease_expires_at)?,
            integer(now)?,
            JsValue::from_str(task_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
        ])?
        .run()
        .await?;
    if changes(&update)? != 1 {
        return Response::error("VFS put-delete task failed final safety validation", 409);
    }

    let Some(task) = load_owned_task(&database, token, Some(task_id), now).await? else {
        return Response::error("VFS put-delete task fence is stale", 409);
    };
    if task.fencing_token != requested.fencing_token + 1 {
        return Response::error("VFS put-delete task fence is stale", 409);
    }
    record_audit(&database, token, &task, "put_delete_revalidated", now).await?;
    task_response(&task)
}

/// Commits a successful or already-absent provider deletion.
pub(crate) async fn complete(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    task_id: &str,
) -> Result<Response> {
    let requested = request.json::<CompletionRequest>().await?;
    if !valid_task_id(task_id)
        || !valid_task_id(&requested.incarnation)
        || requested.fencing_token == 0
        || !matches!(requested.outcome.as_str(), "deleted" | "already_absent")
    {
        return Response::error("invalid VFS put-delete completion", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    if !authorized(&database, token, task_id).await? {
        return Response::error("VFS put-delete completion is not authorized", 403);
    }
    if let Some(terminal) = load_task(&database, task_id).await?
        && terminal.state == "deleted"
    {
        if terminal.completion_outcome.as_deref() != Some(requested.outcome.as_str()) {
            return Response::error("VFS put-delete completion outcome conflicts", 409);
        }
        return task_response(&terminal);
    }
    let now = copying::current_unix_seconds();
    let update = database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET state = 'deleted', owner_token_id = NULL, incarnation = NULL,
                 lease_expires_at = NULL, last_error_code = NULL,
                 completion_outcome = ?1, completed_at = ?2, updated_at = ?2
             WHERE id = ?3 AND state = 'claimed' AND owner_token_id = ?4
               AND incarnation = ?5 AND fencing_token = ?6
               AND lease_expires_at > ?2 AND revalidated_at IS NOT NULL
               AND id IN (SELECT id FROM safe_vfs_put_delete_tasks)",
        )
        .bind(&[
            JsValue::from_str(&requested.outcome),
            integer(now)?,
            JsValue::from_str(task_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
        ])?
        .run()
        .await?;
    if changes(&update)? != 1 {
        return Response::error("VFS put-delete completion fence is stale", 409);
    }
    let Some(task) = load_task(&database, task_id).await? else {
        return Response::error("VFS put-delete task disappeared", 409);
    };
    if task.state != "deleted" {
        return Response::error("VFS put-delete completion did not commit", 409);
    }
    record_audit(&database, token, &task, "put_delete_completed", now).await?;
    task_response(&task)
}

/// Releases a failed fence for a later conservative retry.
pub(crate) async fn fail(
    request: &mut Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
    task_id: &str,
) -> Result<Response> {
    let requested = request.json::<FailureRequest>().await?;
    if !valid_task_id(task_id)
        || !valid_task_id(&requested.incarnation)
        || requested.fencing_token == 0
        || !valid_error_code(&requested.error_code)
    {
        return Response::error("invalid VFS put-delete failure", 400);
    }
    let database = env.d1("CARRACK_INDEX")?;
    if !authorized(&database, token, task_id).await? {
        return Response::error("VFS put-delete failure is not authorized", 403);
    }
    let now = copying::current_unix_seconds();
    let update = database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET state = 'failed', owner_token_id = NULL, incarnation = NULL,
                 lease_expires_at = NULL, revalidated_at = NULL,
                 last_error_code = ?1, updated_at = ?2
             WHERE id = ?3 AND state = 'claimed' AND owner_token_id = ?4
               AND incarnation = ?5 AND fencing_token = ?6",
        )
        .bind(&[
            JsValue::from_str(&requested.error_code),
            integer(now)?,
            JsValue::from_str(task_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
        ])?
        .run()
        .await?;
    if changes(&update)? != 1 {
        return Response::error("VFS put-delete failure fence is stale", 409);
    }
    let Some(task) = load_task(&database, task_id).await? else {
        return Response::error("VFS put-delete task disappeared", 409);
    };
    record_audit(&database, token, &task, "put_delete_failed", now).await?;
    task_response(&task)
}

async fn load_candidate(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    now: u64,
) -> Result<Option<String>> {
    database
        .prepare(
            "WITH RECURSIVE
             verifier(id, root_directory_id) AS (
                 SELECT id, root_directory_id
                 FROM vfs_token_verifiers
                 WHERE id = ?1 AND principal_id = ?2 AND snapshot_id IS NULL
             ),
             descendants(id) AS (
                 SELECT root_directory_id FROM verifier
                 UNION ALL
                 SELECT directory.id
                 FROM vfs_directories AS directory
                 JOIN descendants AS parent ON directory.parent_id = parent.id
             ),
             acl_directories(task_id, id, parent_id, acl_inherits) AS (
                 SELECT task.id, directory.id, directory.parent_id, directory.acl_inherits
                 FROM vfs_put_delete_tasks AS task
                 JOIN vfs_put_intents AS intent ON intent.id = task.id
                 JOIN vfs_directories AS directory ON directory.id = intent.directory_id
                 WHERE task.id IN (SELECT id FROM safe_vfs_put_delete_tasks)
                 UNION ALL
                 SELECT child.task_id, parent.id, parent.parent_id, parent.acl_inherits
                 FROM vfs_directories AS parent
                 JOIN acl_directories AS child ON child.parent_id = parent.id
                 WHERE child.acl_inherits = 1
             )
             SELECT task.id
             FROM vfs_put_delete_tasks AS task
             JOIN vfs_put_intents AS intent ON intent.id = task.id
             WHERE task.id IN (SELECT id FROM safe_vfs_put_delete_tasks)
               AND intent.directory_id IN (SELECT id FROM descendants)
               AND NOT EXISTS (
                   SELECT action FROM (SELECT 'gc.run' AS action UNION ALL SELECT 'driver.use')
                   WHERE action NOT IN (
                       SELECT action FROM vfs_token_actions WHERE token_id = ?1
                   )
               )
               AND (
                   NOT EXISTS (SELECT 1 FROM vfs_token_drivers WHERE token_id = ?1)
                   OR EXISTS (
                       SELECT 1 FROM vfs_token_drivers
                       WHERE token_id = ?1 AND driver_id = intent.driver_id
                   )
               )
               AND (
                   SELECT COUNT(DISTINCT grant.action)
                   FROM vfs_acl_grants AS grant
                   WHERE grant.action IN ('gc.run', 'driver.use')
                     AND grant.directory_id IN (
                         SELECT id FROM acl_directories WHERE task_id = task.id
                     )
                     AND (
                         grant.principal_id = ?2
                         OR EXISTS (
                             SELECT 1 FROM vfs_group_members AS membership
                             WHERE membership.group_id = grant.group_id
                               AND membership.principal_id = ?2
                         )
                     )
               ) = 2
               AND (task.state IN ('pending', 'failed')
                    OR (task.state = 'claimed' AND (
                        task.lease_expires_at <= ?3
                        OR task.incarnation != (
                            SELECT incarnation FROM control_plane_state WHERE singleton = 1
                        )
                    )))
             ORDER BY task.delete_after, task.updated_at, task.id
             LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(&token.id),
            JsValue::from_str(&token.principal_id),
            integer(now)?,
        ])?
        .first::<String>(Some("id"))
        .await
}

pub(crate) async fn authorized(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    task_id: &str,
) -> Result<bool> {
    let row = database
        .prepare(
            "WITH RECURSIVE
             ancestors(id, parent_id) AS (
                 SELECT directory.id, directory.parent_id
                 FROM vfs_put_delete_tasks AS task
                 JOIN vfs_put_intents AS intent ON intent.id = task.id
                 JOIN vfs_directories AS directory ON directory.id = intent.directory_id
                 WHERE task.id = ?1
                 UNION
                 SELECT parent.id, parent.parent_id
                 FROM vfs_directories AS parent
                 JOIN ancestors AS child ON child.parent_id = parent.id
             ),
             acl_directories(id, parent_id, acl_inherits) AS (
                 SELECT directory.id, directory.parent_id, directory.acl_inherits
                 FROM vfs_put_delete_tasks AS task
                 JOIN vfs_put_intents AS intent ON intent.id = task.id
                 JOIN vfs_directories AS directory ON directory.id = intent.directory_id
                 WHERE task.id = ?1
                 UNION
                 SELECT parent.id, parent.parent_id, parent.acl_inherits
                 FROM vfs_directories AS parent
                 JOIN acl_directories AS child ON child.parent_id = parent.id
                 WHERE child.acl_inherits = 1
             )
             SELECT COUNT(*) = 1 AS allowed
             FROM vfs_put_delete_tasks AS task
             JOIN vfs_put_intents AS intent ON intent.id = task.id
             JOIN vfs_token_verifiers AS verifier ON verifier.id = ?2
             WHERE task.id = ?1
               AND verifier.principal_id = ?3
               AND verifier.snapshot_id IS NULL
               AND EXISTS (SELECT 1 FROM ancestors WHERE id = verifier.root_directory_id)
               AND NOT EXISTS (
                   SELECT action FROM (SELECT 'gc.run' AS action UNION ALL SELECT 'driver.use')
                   WHERE action NOT IN (
                       SELECT action FROM vfs_token_actions WHERE token_id = verifier.id
                   )
               )
               AND (
                   NOT EXISTS (SELECT 1 FROM vfs_token_drivers WHERE token_id = verifier.id)
                   OR EXISTS (
                       SELECT 1 FROM vfs_token_drivers
                       WHERE token_id = verifier.id AND driver_id = intent.driver_id
                   )
               )
               AND (
                   SELECT COUNT(DISTINCT grant.action)
                   FROM vfs_acl_grants AS grant
                   WHERE grant.action IN ('gc.run', 'driver.use')
                     AND grant.directory_id IN (SELECT id FROM acl_directories)
                     AND (
                         grant.principal_id = verifier.principal_id
                         OR EXISTS (
                             SELECT 1 FROM vfs_group_members AS membership
                             WHERE membership.group_id = grant.group_id
                               AND membership.principal_id = verifier.principal_id
                         )
                     )
               ) = 2",
        )
        .bind(&[
            JsValue::from_str(task_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&token.principal_id),
        ])?
        .first::<u64>(Some("allowed"))
        .await?;
    Ok(row == Some(1))
}

async fn load_owned_task(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    task_id: Option<&str>,
    now: u64,
) -> Result<Option<DeleteTask>> {
    let candidate = database
        .prepare(
            "SELECT id FROM vfs_put_delete_tasks
             WHERE state = 'claimed' AND owner_token_id = ?1
               AND lease_expires_at > ?2 AND (?3 IS NULL OR id = ?3)
               AND incarnation = (
                   SELECT incarnation FROM control_plane_state WHERE singleton = 1
               )
             ORDER BY updated_at, id LIMIT 1",
        )
        .bind(&[
            JsValue::from_str(&token.id),
            integer(now)?,
            task_id.map_or_else(JsValue::null, JsValue::from_str),
        ])?
        .first::<String>(Some("id"))
        .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if !authorized(database, token, &candidate).await? {
        return Ok(None);
    }
    load_task(database, &candidate).await
}

async fn load_task(database: &D1Database, task_id: &str) -> Result<Option<DeleteTask>> {
    let mut task = database
        .prepare(
            "SELECT NULL AS schema, task.id AS task_id, intent.filesystem_id,
                    intent.directory_id, intent.driver_id, task.driver_revision,
                    intent.storage_key, evidence.native_id, evidence.provider_version,
                    evidence.etag, evidence.encoded_bytes AS size_bytes,
                    evidence.encoded_sha256, task.delete_after, task.incarnation,
                    task.fencing_token, task.lease_expires_at, task.attempt_count,
                    task.state, task.completion_outcome
             FROM vfs_put_delete_tasks AS task
             JOIN vfs_put_intents AS intent ON intent.id = task.id
             JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = task.id
             WHERE task.id = ?1",
        )
        .bind(&[JsValue::from_str(task_id)])?
        .first::<DeleteTask>(None)
        .await?;
    if let Some(value) = task.as_mut() {
        value.schema = Some(TASK_SCHEMA.to_owned());
    }
    Ok(task)
}

async fn record_audit(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    task: &DeleteTask,
    event_kind: &str,
    now: u64,
) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_audit_events (
                 filesystem_id, principal_id, token_id, event_kind,
                 subject_kind, subject_id, details_json, created_at
             ) VALUES (?1, ?2, ?3, ?4, 'put_delete_task', ?5, ?6, ?7)",
        )
        .bind(&[
            JsValue::from_str(&task.filesystem_id),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(event_kind),
            JsValue::from_str(&task.task_id),
            JsValue::from_str(
                &serde_json::json!({
                    "driver_id": task.driver_id,
                    "fencing_token": task.fencing_token,
                    "state": task.state,
                })
                .to_string(),
            ),
            integer(now)?,
        ])?
        .run()
        .await?;
    Ok(())
}

fn claim_response(task: Option<DeleteTask>) -> Result<Response> {
    Response::from_json(&ClaimResponse {
        state: if task.is_some() { "claimed" } else { "idle" },
        task,
    })
}

fn task_response(task: &DeleteTask) -> Result<Response> {
    Response::from_json(&task)
}

fn integer(value: u64) -> Result<JsValue> {
    let value = i64::try_from(value)
        .map_err(|error| worker::Error::RustError(format!("D1 integer overflow: {error}")))?;
    Ok(JsValue::from_str(&value.to_string()))
}

fn changes(result: &worker::D1Result) -> Result<usize> {
    Ok(result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default())
}

fn valid_lease_seconds(value: u64) -> bool {
    (MINIMUM_LEASE_SECONDS..=MAXIMUM_LEASE_SECONDS).contains(&value)
}

fn valid_task_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_ERROR_CODE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
