//! Bounded, server-owned lifecycle for unreachable complete provider objects.

use serde::Deserialize;
use serde_json::json;
use worker::{
    D1Database, Env, Fetch, Headers, Method, Request, RequestInit, Result, wasm_bindgen::JsValue,
};
use zeroize::Zeroize as _;

use crate::{
    driver_credentials::AliyunCredential, environment_defaults, r2_signing,
    vfs_envelopes::open_driver_credential,
};

const MAXIMUM_MARKS_PER_RUN: u64 = 100;
const MAXIMUM_TASKS_PER_RUN: u64 = 100;
const UNREACHABLE_RETENTION_SECONDS: u64 = 30 * 86_400;
const DELETE_GRACE_SECONDS: u64 = 7 * 86_400;
const CLAIM_SECONDS: u64 = 120;

#[derive(Deserialize)]
struct DeleteTask {
    id: String,
    expected_location_revision: u64,
    native_id: Option<String>,
    storage_key: String,
    fencing_token: u64,
    kind: String,
    config_json: String,
    credential_id: Option<String>,
    credential_algorithm: Option<String>,
    credential_key_version: Option<String>,
    credential_nonce: Option<Vec<u8>>,
    credential_ciphertext: Option<Vec<u8>>,
    credential_revision: Option<u64>,
}

#[derive(Deserialize)]
struct R2CleanupTask {
    intent_id: String,
    storage_key: String,
    upload_id: Option<String>,
    fencing_token: u64,
    config_json: String,
    credential_id: Option<String>,
    credential_algorithm: Option<String>,
    credential_key_version: Option<String>,
    credential_nonce: Option<Vec<u8>>,
    credential_ciphertext: Option<Vec<u8>>,
    credential_revision: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AliyunConfig {
    api_base_url: String,
    drive_type: String,
    root_folder_id: String,
    upload_part_bytes: u64,
}

#[derive(Deserialize)]
#[allow(
    clippy::struct_field_names,
    reason = "fields match the Aliyun wire schema"
)]
struct DriveInfo {
    default_drive_id: String,
    resource_drive_id: String,
    backup_drive_id: String,
}

/// Performs one bounded lifecycle pass. It is safe for overlapping cron
/// invocations: every provider delete is preceded by a D1 lease and a final
/// identity, reachability, driver-revision, and direct-read-lease fence.
pub(crate) async fn run(env: &Env, now: u64) -> Result<()> {
    let database = env.d1("CARRACK_INDEX")?;
    mark_unreachable(&database, now).await?;
    create_tasks(&database, now).await?;
    delete_one(env, &database, now).await?;
    delete_one_abandoned_put(env, &database, now).await?;
    cleanup_one_r2_upload(env, &database, now).await
}

#[allow(
    clippy::too_many_lines,
    reason = "claim, final safety reload, sealed credential use, provider cleanup, and fenced outcome form one lifecycle transaction"
)]
async fn cleanup_one_r2_upload(env: &Env, database: &D1Database, now: u64) -> Result<()> {
    let candidate = database
        .prepare(
            "SELECT intent_id FROM vfs_r2_upload_cleanup_tasks
                 INDEXED BY idx_vfs_r2_cleanup_claim
             WHERE intent_id IN (SELECT intent_id FROM safe_vfs_r2_upload_cleanup_tasks)
               AND state IN ('active', 'cleaning', 'failed')
               AND (state = 'active'
                    OR (state = 'failed' AND retry_at <= ?1)
                    OR (state = 'cleaning' AND lease_expires_at <= ?1))
             ORDER BY COALESCE(retry_at, lease_expires_at), intent_id LIMIT 1",
        )
        .bind(&[integer(now)])?
        .first::<serde_json::Value>(Some("intent_id"))
        .await?;
    let Some(serde_json::Value::String(intent_id)) = candidate else {
        return Ok(());
    };
    let claimed = database
        .prepare(
            "UPDATE vfs_r2_upload_cleanup_tasks
             SET state = 'cleaning', fencing_token = fencing_token + 1,
                 lease_expires_at = ?1, attempt_count = attempt_count + 1,
                 retry_at = NULL, last_error_code = NULL, updated_at = ?2
             WHERE intent_id = ?3
               AND intent_id IN (SELECT intent_id FROM safe_vfs_r2_upload_cleanup_tasks)
               AND (state = 'active'
                    OR (state = 'failed' AND retry_at <= ?2)
                    OR (state = 'cleaning' AND lease_expires_at <= ?2))",
        )
        .bind(&[
            integer(now + CLAIM_SECONDS),
            integer(now),
            JsValue::from_str(&intent_id),
        ])?
        .run()
        .await?;
    if changes(claimed.meta()?) != 1 {
        return Ok(());
    }
    let task = database
        .prepare(
            "SELECT task.intent_id, intent.storage_key, task.upload_id,
                    task.fencing_token, driver.config_json,
                    credential.id AS credential_id,
                    credential.envelope_algorithm AS credential_algorithm,
                    credential.key_version AS credential_key_version,
                    credential.nonce AS credential_nonce,
                    credential.ciphertext AS credential_ciphertext,
                    credential.revision AS credential_revision
             FROM vfs_r2_upload_cleanup_tasks AS task
             JOIN vfs_put_intents AS intent ON intent.id = task.intent_id
             JOIN driver_instances AS driver ON driver.id = intent.driver_id
             LEFT JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE task.intent_id = ?1 AND task.state = 'cleaning'
               AND task.lease_expires_at > ?2
               AND task.intent_id IN (
                   SELECT intent_id FROM safe_vfs_r2_upload_cleanup_tasks
               )",
        )
        .bind(&[JsValue::from_str(&intent_id), integer(now)])?
        .first::<R2CleanupTask>(None)
        .await?;
    let Some(task) = task else {
        return Ok(());
    };
    let result = cleanup_r2_upload(env, &task).await;
    let (state, error, completed_at, retry_at) = if result.is_ok() {
        ("cleaned", JsValue::NULL, integer(now), JsValue::NULL)
    } else {
        worker::console_error!("R2 upload cleanup {} failed", task.intent_id);
        (
            "failed",
            JsValue::from_str("provider_cleanup_failed"),
            JsValue::NULL,
            integer(now + retry_delay(task.fencing_token, task.fencing_token)),
        )
    };
    database
        .prepare(
            "UPDATE vfs_r2_upload_cleanup_tasks
             SET state = ?1, lease_expires_at = NULL, last_error_code = ?2,
                 completed_at = ?3, retry_at = ?4, updated_at = ?5
             WHERE intent_id = ?6 AND state = 'cleaning' AND fencing_token = ?7",
        )
        .bind(&[
            JsValue::from_str(state),
            error,
            completed_at,
            retry_at,
            integer(now),
            JsValue::from_str(&task.intent_id),
            integer(task.fencing_token),
        ])?
        .run()
        .await?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "claim, final safety reload, provider dispatch, and fenced outcome form one lifecycle transaction"
)]
async fn delete_one_abandoned_put(env: &Env, database: &D1Database, now: u64) -> Result<()> {
    let candidate = database
        .prepare(
            "SELECT task.id
             FROM vfs_put_delete_tasks AS task
                  INDEXED BY idx_vfs_put_delete_tasks_server_claim
             WHERE task.id IN (SELECT id FROM safe_vfs_put_delete_tasks)
               AND task.server_blocked_at IS NULL
               AND task.state IN ('pending', 'claimed', 'failed')
               AND ((task.state = 'pending' AND task.delete_after <= ?1)
                    OR (task.state = 'failed' AND task.retry_at <= ?1)
                    OR (task.state = 'claimed' AND task.lease_expires_at <= ?1))
             ORDER BY COALESCE(task.retry_at, task.delete_after), task.id LIMIT 1",
        )
        .bind(&[integer(now)])?
        .first::<serde_json::Value>(Some("id"))
        .await?;
    let Some(serde_json::Value::String(id)) = candidate else {
        return Ok(());
    };
    let claim = database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET state = 'claimed', owner_token_id = (
                     SELECT token_id FROM vfs_put_upload_evidence WHERE intent_id = ?1
                 ),
                 incarnation = (SELECT incarnation FROM control_plane_state WHERE singleton = 1),
                 fencing_token = fencing_token + 1, lease_expires_at = ?2,
                 attempt_count = attempt_count + 1, last_error_code = NULL,
                 retry_at = NULL, claimed_at = ?3, revalidated_at = ?3,
                 updated_at = ?3
             WHERE id = ?1 AND server_blocked_at IS NULL
               AND id IN (SELECT id FROM safe_vfs_put_delete_tasks)
               AND ((state = 'pending' AND delete_after <= ?3)
                    OR (state = 'failed' AND retry_at <= ?3)
                    OR (state = 'claimed' AND lease_expires_at <= ?3))",
        )
        .bind(&[
            JsValue::from_str(&id),
            integer(now + CLAIM_SECONDS),
            integer(now),
        ])?
        .run()
        .await?;
    if changes(claim.meta()?) != 1 {
        return Ok(());
    }
    let Some(fencing_token) =
        load_claim_fencing(database, "vfs_put_delete_tasks", &id, now).await?
    else {
        return Ok(());
    };
    let Some(task) = load_abandoned_put(database, &id, now).await? else {
        fail_abandoned_put(
            database,
            &id,
            fencing_token,
            now,
            "revalidation_failed",
            false,
        )
        .await?;
        return Ok(());
    };
    if task.kind == "local-filesystem/v2" {
        fail_abandoned_put(
            database,
            &id,
            task.fencing_token,
            now,
            "server_cannot_reach_local_driver",
            true,
        )
        .await?;
        return Ok(());
    }
    if !matches!(task.kind.as_str(), "aliyundrive-open/v2" | "r2/v1") {
        fail_abandoned_put(
            database,
            &id,
            task.fencing_token,
            now,
            "unsupported_server_delete_driver",
            true,
        )
        .await?;
        return Ok(());
    }
    let outcome = if task.kind == "r2/v1" {
        delete_r2(env, &task).await
    } else {
        delete_aliyun(env, &task).await
    };
    match outcome {
        Ok(()) => complete_abandoned_put(database, &task, now).await,
        Err(error) => {
            worker::console_error!("server abandoned-Put delete {} failed: {error:?}", task.id);
            fail_abandoned_put(
                database,
                &id,
                task.fencing_token,
                now,
                "provider_delete_failed",
                false,
            )
            .await
        }
    }
}

async fn load_abandoned_put(
    database: &D1Database,
    id: &str,
    now: u64,
) -> Result<Option<DeleteTask>> {
    database
        .prepare(
            "SELECT task.id, 1 AS expected_location_revision,
                    evidence.native_id, intent.storage_key, task.fencing_token,
                    driver.kind, driver.config_json,
                    credential.id AS credential_id,
                    credential.envelope_algorithm AS credential_algorithm,
                    credential.key_version AS credential_key_version,
                    credential.nonce AS credential_nonce,
                    credential.ciphertext AS credential_ciphertext,
                    credential.revision AS credential_revision
             FROM vfs_put_delete_tasks AS task
             JOIN vfs_put_intents AS intent ON intent.id = task.id
             JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = task.id
             JOIN driver_instances AS driver ON driver.id = intent.driver_id
             LEFT JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE task.id = ?1 AND task.state = 'claimed'
               AND task.lease_expires_at > ?2
               AND task.id IN (SELECT id FROM safe_vfs_put_delete_tasks)",
        )
        .bind(&[JsValue::from_str(id), integer(now)])?
        .first::<DeleteTask>(None)
        .await
}

async fn complete_abandoned_put(database: &D1Database, task: &DeleteTask, now: u64) -> Result<()> {
    database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET state = 'deleted', owner_token_id = NULL, incarnation = NULL,
                 lease_expires_at = NULL, retry_at = NULL,
                 completion_outcome = 'deleted',
                 completed_at = ?1, updated_at = ?1
             WHERE id = ?2 AND state = 'claimed' AND fencing_token = ?3
               AND id IN (SELECT id FROM safe_vfs_put_delete_tasks)",
        )
        .bind(&[
            integer(now),
            JsValue::from_str(&task.id),
            integer(task.fencing_token),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn fail_abandoned_put(
    database: &D1Database,
    id: &str,
    fencing_token: u64,
    now: u64,
    code: &str,
    blocked: bool,
) -> Result<()> {
    let retry_at = if blocked {
        JsValue::NULL
    } else {
        integer(now + retry_delay(fencing_token, fencing_token))
    };
    database
        .prepare(
            "UPDATE vfs_put_delete_tasks
             SET state = 'failed', owner_token_id = NULL, incarnation = NULL,
                 lease_expires_at = NULL, retry_at = ?1, last_error_code = ?2,
                 server_blocked_at = CASE WHEN ?3 = 1 THEN ?4 ELSE NULL END,
                 updated_at = ?4
             WHERE id = ?5 AND state = 'claimed' AND fencing_token = ?6",
        )
        .bind(&[
            retry_at,
            JsValue::from_str(code),
            integer(u64::from(blocked)),
            integer(now),
            JsValue::from_str(id),
            integer(fencing_token),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn mark_unreachable(database: &D1Database, now: u64) -> Result<()> {
    database
        .prepare(
            "UPDATE vfs_locations
             SET state = 'tombstoned', delete_after = ?1, revision = revision + 1,
                 updated_at = ?2
             WHERE id IN (
                 SELECT id FROM safe_unreachable_vfs_locations
                 WHERE published_at <= ?3 ORDER BY published_at, id LIMIT ?4
             ) AND state = 'available'",
        )
        .bind(&[
            integer(now + DELETE_GRACE_SECONDS),
            integer(now),
            integer(now.saturating_sub(UNREACHABLE_RETENTION_SECONDS)),
            integer(MAXIMUM_MARKS_PER_RUN),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn create_tasks(database: &D1Database, now: u64) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_location_delete_tasks (
                 id, expected_location_revision, driver_id, driver_revision,
                 storage_key, native_id, provider_version, etag, size_bytes,
                 delete_after, created_at, updated_at
             )
             SELECT location.id, location.revision, location.driver_id, driver.revision,
                    location.storage_key, location.native_id, location.provider_version,
                    location.etag, location.size_bytes, location.delete_after, ?1, ?1
             FROM vfs_locations AS location
             JOIN driver_instances AS driver ON driver.id = location.driver_id
             WHERE location.state = 'tombstoned' AND location.delete_after IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_location_delete_tasks AS task
                   WHERE task.id = location.id
               )
             ORDER BY location.delete_after, location.id LIMIT ?2
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&[integer(now), integer(MAXIMUM_TASKS_PER_RUN)])?
        .run()
        .await?;
    Ok(())
}

async fn delete_one(env: &Env, database: &D1Database, now: u64) -> Result<()> {
    let candidate = database
        .prepare(
            "SELECT id FROM vfs_location_delete_tasks
             WHERE (state = 'pending' AND delete_after <= ?1)
                OR (state = 'retry' AND retry_at <= ?1)
                OR (state = 'claimed' AND lease_expires_at <= ?1)
             ORDER BY COALESCE(retry_at, delete_after), id LIMIT 1",
        )
        .bind(&[integer(now)])?
        .first::<serde_json::Value>(Some("id"))
        .await?;
    let Some(serde_json::Value::String(id)) = candidate else {
        return Ok(());
    };
    let claim = database
        .prepare(
            "UPDATE vfs_location_delete_tasks
             SET state = 'claimed', fencing_token = fencing_token + 1,
                 lease_expires_at = ?1, retry_at = NULL,
                 attempt_count = attempt_count + 1, last_error_code = NULL,
                 updated_at = ?2
             WHERE id = ?3 AND (
                 (state = 'pending' AND delete_after <= ?2)
                 OR (state = 'retry' AND retry_at <= ?2)
                 OR (state = 'claimed' AND lease_expires_at <= ?2)
             )",
        )
        .bind(&[
            integer(now + CLAIM_SECONDS),
            integer(now),
            JsValue::from_str(&id),
        ])?
        .run()
        .await?;
    if changes(claim.meta()?) != 1 {
        return Ok(());
    }
    let Some(fencing_token) =
        load_claim_fencing(database, "vfs_location_delete_tasks", &id, now).await?
    else {
        return Ok(());
    };
    let Some(task) = load_revalidated(database, &id, now).await? else {
        fail(
            database,
            &id,
            fencing_token,
            now,
            "revalidation_failed",
            "blocked",
        )
        .await?;
        return Ok(());
    };
    if task.kind == "local-filesystem/v2" {
        fail(
            database,
            &id,
            task.fencing_token,
            now,
            "server_cannot_reach_local_driver",
            "blocked",
        )
        .await?;
        return Ok(());
    }
    if !matches!(task.kind.as_str(), "aliyundrive-open/v2" | "r2/v1") {
        fail(
            database,
            &id,
            task.fencing_token,
            now,
            "unsupported_server_delete_driver",
            "blocked",
        )
        .await?;
        return Ok(());
    }
    let outcome = if task.kind == "r2/v1" {
        delete_r2(env, &task).await
    } else {
        delete_aliyun(env, &task).await
    };
    match outcome {
        Ok(()) => complete(database, &task, now).await,
        Err(error) => {
            worker::console_error!("server lifecycle delete {} failed: {error:?}", task.id);
            fail(
                database,
                &task.id,
                task.fencing_token,
                now,
                "provider_delete_failed",
                "retry",
            )
            .await
        }
    }
}

async fn load_revalidated(database: &D1Database, id: &str, now: u64) -> Result<Option<DeleteTask>> {
    database
        .prepare(
            "SELECT task.id, task.expected_location_revision, task.native_id, task.storage_key,
                    task.fencing_token, driver.kind, driver.config_json,
                    credential.id AS credential_id,
                    credential.envelope_algorithm AS credential_algorithm,
                    credential.key_version AS credential_key_version,
                    credential.nonce AS credential_nonce,
                    credential.ciphertext AS credential_ciphertext,
                    credential.revision AS credential_revision
             FROM vfs_location_delete_tasks AS task
             JOIN vfs_locations AS location ON location.id = task.id
             JOIN driver_instances AS driver ON driver.id = task.driver_id
             LEFT JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE task.id = ?1 AND task.state = 'claimed' AND task.lease_expires_at > ?2
               AND location.state = 'tombstoned'
               AND location.revision = task.expected_location_revision
               AND location.driver_id = task.driver_id
               AND location.storage_key = task.storage_key
               AND location.size_bytes = task.size_bytes
               AND driver.enabled = 1 AND driver.revision = task.driver_revision
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_read_leases AS lease
                   WHERE lease.location_id = location.id AND lease.completed_at IS NULL
                     AND lease.expires_at > ?2
               )",
        )
        .bind(&[JsValue::from_str(id), integer(now)])?
        .first::<DeleteTask>(None)
        .await
}

async fn delete_aliyun(env: &Env, task: &DeleteTask) -> Result<()> {
    let native_id = task.native_id.as_deref().ok_or_else(|| {
        worker::Error::RustError("Aliyun lifecycle task has no native file ID".to_owned())
    })?;
    let config: AliyunConfig = serde_json::from_str(&task.config_json).map_err(|error| {
        worker::Error::RustError(format!("decode Aliyun lifecycle configuration: {error}"))
    })?;
    let _ = (&config.root_folder_id, config.upload_part_bytes);
    if !config.api_base_url.starts_with("https://") || config.api_base_url.ends_with('/') {
        return Err(worker::Error::RustError(
            "unsafe Aliyun API base URL".to_owned(),
        ));
    }
    let (Some(id), Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        task.credential_id.as_deref(),
        task.credential_algorithm.as_deref(),
        task.credential_key_version.as_deref(),
        task.credential_nonce.as_deref(),
        task.credential_ciphertext.as_deref(),
        task.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "Aliyun lifecycle credential is incomplete".to_owned(),
        ));
    };
    let mut plaintext =
        open_driver_credential(env, id, revision, algorithm, version, nonce, ciphertext)?;
    let decoded = serde_json::from_slice::<AliyunCredential>(&plaintext).map_err(|error| {
        worker::Error::RustError(format!("decode Aliyun lifecycle credential: {error}"))
    });
    plaintext.zeroize();
    let mut credential = decoded?;
    let drive: DriveInfo = aliyun_post(
        &config.api_base_url,
        "/adrive/v1.0/user/getDriveInfo",
        &credential.access_token,
        &json!({}),
    )
    .await?;
    let drive_id = match config.drive_type.as_str() {
        "default" => drive.default_drive_id,
        "resource" => drive.resource_drive_id,
        "backup" => drive.backup_drive_id,
        _ => {
            return Err(worker::Error::RustError(
                "invalid Aliyun drive type".to_owned(),
            ));
        }
    };
    let result = aliyun_post::<serde_json::Value>(
        &config.api_base_url,
        "/adrive/v1.0/openFile/delete",
        &credential.access_token,
        &json!({"drive_id": drive_id, "file_id": native_id}),
    )
    .await;
    credential.access_token.zeroize();
    result.map(|_| ())
}

async fn delete_r2(env: &Env, task: &DeleteTask) -> Result<()> {
    let config =
        serde_json::from_str::<r2_signing::Config>(&task.config_json).map_err(|error| {
            worker::Error::RustError(format!("decode R2 lifecycle configuration: {error}"))
        })?;
    let key = r2_signing::object_key(&config, &task.storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid R2 lifecycle storage key".to_owned()))?;
    if environment_defaults::is_managed_r2_config(env, &config)? {
        return env.bucket("CARRACK_PAYLOAD")?.delete(key).await;
    }
    let (Some(id), Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        task.credential_id.as_deref(),
        task.credential_algorithm.as_deref(),
        task.credential_key_version.as_deref(),
        task.credential_nonce.as_deref(),
        task.credential_ciphertext.as_deref(),
        task.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "R2 lifecycle credential is incomplete".to_owned(),
        ));
    };
    let mut plaintext =
        open_driver_credential(env, id, revision, algorithm, version, nonce, ciphertext)?;
    let result =
        r2_signing::delete_from_plaintext(&task.config_json, &task.storage_key, &plaintext).await;
    plaintext.zeroize();
    result
}

async fn cleanup_r2_upload(env: &Env, task: &R2CleanupTask) -> Result<()> {
    let config =
        serde_json::from_str::<r2_signing::Config>(&task.config_json).map_err(|error| {
            worker::Error::RustError(format!("decode R2 cleanup configuration: {error}"))
        })?;
    let key = r2_signing::object_key(&config, &task.storage_key)
        .ok_or_else(|| worker::Error::RustError("invalid R2 cleanup storage key".to_owned()))?;
    if environment_defaults::is_managed_r2_config(env, &config)? {
        let bucket = env.bucket("CARRACK_PAYLOAD")?;
        if let Some(upload_id) = task.upload_id.as_deref() {
            let upload = bucket.resume_multipart_upload(&key, upload_id)?;
            if let Err(error) = upload.abort().await {
                let rendered = format!("{error:?}");
                if !missing_multipart_upload(&rendered) {
                    return Err(error);
                }
            }
        }
        return bucket.delete(key).await;
    }

    let (Some(id), Some(algorithm), Some(version), Some(nonce), Some(ciphertext), Some(revision)) = (
        task.credential_id.as_deref(),
        task.credential_algorithm.as_deref(),
        task.credential_key_version.as_deref(),
        task.credential_nonce.as_deref(),
        task.credential_ciphertext.as_deref(),
        task.credential_revision,
    ) else {
        return Err(worker::Error::RustError(
            "R2 cleanup credential is incomplete".to_owned(),
        ));
    };
    let mut plaintext =
        open_driver_credential(env, id, revision, algorithm, version, nonce, ciphertext)?;
    let result = r2_signing::cleanup_upload_from_plaintext(
        &task.config_json,
        &task.storage_key,
        task.upload_id.as_deref(),
        &plaintext,
    )
    .await;
    plaintext.zeroize();
    result
}

fn missing_multipart_upload(rendered_error: &str) -> bool {
    rendered_error.contains("NoSuchUpload")
        || (rendered_error.contains("multipart upload")
            && rendered_error.contains("does not exist"))
}

async fn aliyun_post<T: for<'de> Deserialize<'de>>(
    base: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<T> {
    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {token}"))?;
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body.to_string())));
    let request = Request::new_with_init(&format!("{base}{path}"), &init)?;
    let mut response = Fetch::Request(request).send().await?;
    if response.status_code() == 404 {
        return serde_json::from_value(json!({}))
            .map_err(|error| worker::Error::RustError(error.to_string()));
    }
    if !(200..300).contains(&response.status_code()) {
        return Err(worker::Error::RustError(format!(
            "Aliyun delete API returned HTTP {}",
            response.status_code()
        )));
    }
    if response.status_code() == 204 {
        return serde_json::from_value(json!({}))
            .map_err(|error| worker::Error::RustError(error.to_string()));
    }
    response.json::<T>().await
}

async fn complete(database: &D1Database, task: &DeleteTask, now: u64) -> Result<()> {
    let results = database
        .batch(vec![
            database
                .prepare(
            "UPDATE vfs_locations SET state = 'deleted', revision = revision + 1, updated_at = ?1
             WHERE id = ?2 AND state = 'tombstoned' AND revision = ?3
               AND EXISTS (
                   SELECT 1 FROM vfs_location_delete_tasks AS task
                   WHERE task.id = ?2 AND task.state = 'claimed'
                     AND task.fencing_token = ?4 AND task.lease_expires_at > ?1
                     AND task.expected_location_revision = ?3
               )
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_read_leases AS lease
                   WHERE lease.location_id = ?2 AND lease.completed_at IS NULL
                     AND lease.expires_at > ?1
               )",
                )
                .bind(&[
                    integer(now),
                    JsValue::from_str(&task.id),
                    integer(task.expected_location_revision),
                    integer(task.fencing_token),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_location_delete_tasks
                     SET state = 'deleted', lease_expires_at = NULL,
                         completed_at = ?1, updated_at = ?1
                     WHERE id = ?2 AND state = 'claimed' AND fencing_token = ?3
                       AND EXISTS (
                           SELECT 1 FROM vfs_locations AS location
                           WHERE location.id = ?2 AND location.state = 'deleted'
                             AND location.revision = expected_location_revision + 1
                       )",
                )
                .bind(&[
                    integer(now),
                    JsValue::from_str(&task.id),
                    integer(task.fencing_token),
                ])?,
        ])
        .await?;
    let mut committed = results.len() == 2;
    for result in &results {
        committed &= changes(result.meta()?) == 1;
    }
    if !committed {
        fail(
            database,
            &task.id,
            task.fencing_token,
            now,
            "completion_fence_changed",
            "blocked",
        )
        .await?;
        return Ok(());
    }
    Ok(())
}

async fn fail(
    database: &D1Database,
    id: &str,
    fencing_token: u64,
    now: u64,
    code: &str,
    state: &str,
) -> Result<()> {
    let retry_at = if state == "retry" {
        integer(now + retry_delay(fencing_token, fencing_token))
    } else {
        JsValue::NULL
    };
    database
        .prepare(
            "UPDATE vfs_location_delete_tasks
         SET state = ?1, lease_expires_at = NULL, retry_at = ?2,
             last_error_code = ?3, updated_at = ?4
         WHERE id = ?5 AND state = 'claimed' AND fencing_token = ?6",
        )
        .bind(&[
            JsValue::from_str(state),
            retry_at,
            JsValue::from_str(code),
            integer(now),
            JsValue::from_str(id),
            integer(fencing_token),
        ])?
        .run()
        .await?;
    Ok(())
}

fn retry_delay(attempt: u64, fence: u64) -> u64 {
    let exponent = attempt.saturating_sub(1).min(8) as u32;
    (60_u64.saturating_mul(1_u64 << exponent)).min(6 * 60 * 60) + fence % 61
}

async fn load_claim_fencing(
    database: &D1Database,
    table: &str,
    id: &str,
    now: u64,
) -> Result<Option<u64>> {
    let query = match table {
        "vfs_put_delete_tasks" => {
            "SELECT fencing_token FROM vfs_put_delete_tasks
             WHERE id = ?1 AND state = 'claimed' AND lease_expires_at > ?2"
        }
        "vfs_location_delete_tasks" => {
            "SELECT fencing_token FROM vfs_location_delete_tasks
             WHERE id = ?1 AND state = 'claimed' AND lease_expires_at > ?2"
        }
        _ => {
            return Err(worker::Error::RustError(
                "invalid lifecycle task table".to_owned(),
            ));
        }
    };
    database
        .prepare(query)
        .bind(&[JsValue::from_str(id), integer(now)])?
        .first::<serde_json::Value>(Some("fencing_token"))
        .await
        .map(|value| value.and_then(|value| value.as_u64()))
}

fn integer(value: u64) -> JsValue {
    JsValue::from_str(&value.min(i64::MAX as u64).to_string())
}

fn changes(meta: Option<worker::D1ResultMeta>) -> usize {
    meta.and_then(|value| value.changes).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_idempotent_missing_multipart_errors() {
        assert!(missing_multipart_upload("R2Error: NoSuchUpload"));
        assert!(missing_multipart_upload("multipart upload does not exist"));
        assert!(!missing_multipart_upload("R2Error: AccessDenied"));
    }

    #[test]
    fn provider_delete_retry_is_bounded_and_jittered() {
        assert!((60..=120).contains(&retry_delay(1, 60)));
        assert!(retry_delay(2, 2) > retry_delay(1, 1));
        assert!(retry_delay(100, 60) <= 6 * 60 * 60 + 60);
    }
}
