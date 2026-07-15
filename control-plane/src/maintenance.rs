use worker::{Env, Result, wasm_bindgen::JsValue};

use crate::{
    driver_credentials, environment_defaults, vfs_catalog_materialization, vfs_server_lifecycle,
};

const DATABASE_BINDING: &str = "CARRACK_INDEX";
const MAXIMUM_EXPIRED_SESSIONS_PER_RUN: u64 = 500;
const MAXIMUM_EXPIRED_AUTHORIZATION_CLAIMS_PER_RUN: u64 = 250;
const MAXIMUM_EXPIRED_PUTS_PER_RUN: u64 = 250;
const MAXIMUM_EXPIRED_READ_LEASES_PER_RUN: u64 = 1_000;
const MAXIMUM_R2_CLEANUP_EVIDENCE_PER_RUN: u64 = 250;
const VFS_PUT_DELETE_GRACE_SECONDS: u64 = 86_400;
const READ_LEASE_EVIDENCE_SECONDS: u64 = 7 * 86_400;
const R2_CLEANUP_EVIDENCE_SECONDS: u64 = 30 * 86_400;
const TRANSFER_METRICS_RETENTION_SECONDS: u64 = 400 * 86_400;
const MAXIMUM_TRANSFER_METRIC_ROWS_PER_RUN: u64 = 1_000;
const MAXIMUM_ACCESS_AUDIT_ROWS_PER_RUN: u64 = 1_000;
const AUTH_RATE_LIMIT_RETENTION_SECONDS: u64 = 86_400;
const MAXIMUM_AUTH_RATE_LIMIT_ROWS_PER_RUN: u64 = 500;

/// Performs bounded metadata hygiene without touching provider objects.
///
/// Expired sessions are ephemeral and can be deleted. Expired Put intents are
/// retained as durable evidence but leave the claimable `prepared` state. A
/// provider-object janitor remains responsible for any corresponding staging
/// object after the V2 reachability protocol proves it unreachable.
pub(crate) async fn run(env: &Env) -> Result<()> {
    let now = worker::Date::now().as_millis() / 1_000;
    let database = env.d1(DATABASE_BINDING)?;
    environment_defaults::ensure(env, &database, now).await?;
    delete_expired_authorization_claims(&database, now).await?;
    delete_expired_auth_rate_limits(&database, now).await?;

    database
        .batch(vec![
            database
                .prepare(
                    "DELETE FROM admin_configuration_sessions
                     WHERE id IN (
                         SELECT id FROM admin_configuration_sessions
                         WHERE expires_at <= ?1
                         ORDER BY expires_at LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_SESSIONS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "DELETE FROM admin_sessions
                     WHERE id IN (
                         SELECT id FROM admin_sessions
                         WHERE expires_at <= ?1
                         ORDER BY expires_at LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_SESSIONS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_put_intents
                     SET state = 'expired', revision = revision + 1
                     WHERE id IN (
                         SELECT id FROM vfs_put_intents
                         WHERE state = 'prepared' AND expires_at <= ?1
                         ORDER BY expires_at LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_PUTS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "INSERT INTO vfs_put_delete_tasks (
                         id, driver_revision, evidence_sha256,
                         delete_after, created_at, updated_at
                     )
                     SELECT intent.id, driver.revision, evidence.commit_sha256,
                            MAX(intent.expires_at, evidence.verified_at) + ?1, ?2, ?2
                     FROM vfs_put_intents AS intent
                     JOIN vfs_put_upload_evidence AS evidence ON evidence.intent_id = intent.id
                     JOIN driver_instances AS driver ON driver.id = intent.driver_id
                     WHERE intent.state IN ('expired', 'abandoned')
                       AND NOT EXISTS (
                           SELECT 1 FROM vfs_put_receipts WHERE intent_id = intent.id
                       )
                     ORDER BY intent.expires_at
                     LIMIT ?3
                     ON CONFLICT(id) DO NOTHING",
                )
                .bind(&[
                    JsValue::from_str(&VFS_PUT_DELETE_GRACE_SECONDS.to_string()),
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_PUTS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "DELETE FROM vfs_read_leases
                     WHERE id IN (
                         SELECT id FROM vfs_read_leases
                         WHERE COALESCE(completed_at, expires_at) <= ?1
                         ORDER BY COALESCE(completed_at, expires_at), id LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&now.saturating_sub(READ_LEASE_EVIDENCE_SECONDS).to_string()),
                    JsValue::from_str(&MAXIMUM_EXPIRED_READ_LEASES_PER_RUN.to_string()),
                ])?,
        ])
        .await?;

    delete_expired_transfer_observability(&database, now).await?;
    delete_expired_r2_cleanup_evidence(&database, now).await?;
    driver_credentials::run(env, now).await?;
    vfs_server_lifecycle::run(env, now).await?;
    vfs_catalog_materialization::run(env, now).await?;

    Ok(())
}

async fn delete_expired_transfer_observability(
    database: &worker::D1Database,
    now: u64,
) -> Result<()> {
    let before = now.saturating_sub(TRANSFER_METRICS_RETENTION_SECONDS);
    database
        .batch(vec![
            database
                .prepare(
                    "DELETE FROM vfs_transfer_daily_metrics
                     WHERE (day, scope_kind, scope_id, direction) IN (
                         SELECT day, scope_kind, scope_id, direction
                         FROM vfs_transfer_daily_metrics
                         WHERE day < ?1
                         ORDER BY day, scope_kind, scope_id, direction LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&before.to_string()),
                    JsValue::from_str(&MAXIMUM_TRANSFER_METRIC_ROWS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "DELETE FROM vfs_transfer_metric_receipts
                     WHERE operation_id IN (
                         SELECT operation_id FROM vfs_transfer_metric_receipts
                         WHERE recorded_at < ?1
                         ORDER BY recorded_at, operation_id LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&before.to_string()),
                    JsValue::from_str(&MAXIMUM_TRANSFER_METRIC_ROWS_PER_RUN.to_string()),
                ])?,
            database
                .prepare(
                    "DELETE FROM vfs_audit_events
                     WHERE id IN (
                         SELECT id FROM vfs_audit_events
                         WHERE event_kind IN ('download_planned', 'upload_committed')
                           AND created_at < ?1
                         ORDER BY created_at, id LIMIT ?2
                     )",
                )
                .bind(&[
                    JsValue::from_str(&before.to_string()),
                    JsValue::from_str(&MAXIMUM_ACCESS_AUDIT_ROWS_PER_RUN.to_string()),
                ])?,
        ])
        .await?;
    Ok(())
}

async fn delete_expired_r2_cleanup_evidence(database: &worker::D1Database, now: u64) -> Result<()> {
    database
        .prepare(
            "DELETE FROM vfs_r2_upload_cleanup_tasks
             WHERE intent_id IN (
                 SELECT intent_id FROM vfs_r2_upload_cleanup_tasks
                 WHERE state IN ('cleaned', 'superseded') AND completed_at <= ?1
                 ORDER BY completed_at, intent_id LIMIT ?2
             )",
        )
        .bind(&[
            JsValue::from_str(&now.saturating_sub(R2_CLEANUP_EVIDENCE_SECONDS).to_string()),
            JsValue::from_str(&MAXIMUM_R2_CLEANUP_EVIDENCE_PER_RUN.to_string()),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn delete_expired_auth_rate_limits(database: &worker::D1Database, now: u64) -> Result<()> {
    database
        .prepare(
            "DELETE FROM operator_auth_rate_limits
             WHERE (scope, subject) IN (
                 SELECT scope, subject FROM operator_auth_rate_limits
                 WHERE updated_at <= ?1
                 ORDER BY updated_at, scope, subject LIMIT ?2
             )",
        )
        .bind(&[
            JsValue::from_str(
                &now.saturating_sub(AUTH_RATE_LIMIT_RETENTION_SECONDS)
                    .to_string(),
            ),
            JsValue::from_str(&MAXIMUM_AUTH_RATE_LIMIT_ROWS_PER_RUN.to_string()),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn delete_expired_authorization_claims(
    database: &worker::D1Database,
    now: u64,
) -> Result<()> {
    database
        .prepare(
            "DELETE FROM driver_authorization_claims
             WHERE driver_id IN (
                 SELECT driver_id FROM driver_authorization_claims
                 WHERE lease_expires_at <= ?1
                 ORDER BY lease_expires_at LIMIT ?2
             )",
        )
        .bind(&[
            JsValue::from_str(&now.to_string()),
            JsValue::from_str(&MAXIMUM_EXPIRED_AUTHORIZATION_CLAIMS_PER_RUN.to_string()),
        ])?
        .run()
        .await?;
    Ok(())
}
