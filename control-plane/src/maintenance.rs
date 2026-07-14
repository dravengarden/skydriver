use worker::{Env, Result, wasm_bindgen::JsValue};

use crate::{driver_credentials, vfs_server_lifecycle};

const DATABASE_BINDING: &str = "CARRACK_INDEX";
const MAXIMUM_EXPIRED_SESSIONS_PER_RUN: u64 = 500;
const MAXIMUM_EXPIRED_AUTHORIZATION_CLAIMS_PER_RUN: u64 = 250;
const MAXIMUM_EXPIRED_PUTS_PER_RUN: u64 = 250;
const MAXIMUM_EXPIRED_READ_LEASES_PER_RUN: u64 = 1_000;
const VFS_PUT_DELETE_GRACE_SECONDS: u64 = 86_400;
const READ_LEASE_EVIDENCE_SECONDS: u64 = 7 * 86_400;

/// Performs bounded metadata hygiene without touching provider objects.
///
/// Expired sessions are ephemeral and can be deleted. Expired Put intents are
/// retained as durable evidence but leave the claimable `prepared` state. A
/// provider-object janitor remains responsible for any corresponding staging
/// object after the V2 reachability protocol proves it unreachable.
pub(crate) async fn run(env: &Env) -> Result<()> {
    let now = worker::Date::now().as_millis() / 1_000;
    let database = env.d1(DATABASE_BINDING)?;
    delete_expired_authorization_claims(&database, now).await?;

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

    driver_credentials::run(env, now).await?;
    vfs_server_lifecycle::run(env, now).await?;

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
