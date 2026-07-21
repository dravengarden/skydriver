//! Server-owned provider credential renewal.
//!
//! Filesystem clients receive only short-lived access credentials. Refresh
//! authority stays encrypted in D1 and is rotated by a fenced Cron worker.

use serde::Deserialize;
use skydriver_driver_contract::DriverKind;
use worker::{D1Database, Env, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{
    driver_renewal::{self, RenewalFailure},
    vfs_envelopes::{
        ENVELOPE_ALGORITHM, MASTER_KEY_VERSION, blob_binding, open_driver_credential,
        seal_driver_credential,
    },
};

const CLAIM_SECONDS: u64 = 120;
const MINIMUM_GRANT_LIFETIME_SECONDS: u64 = 5 * 60;
const MAXIMUM_REFRESHES_PER_RUN: usize = 4;

#[derive(Deserialize)]
struct RefreshTask {
    credential_id: String,
    driver_id: String,
    driver_kind: String,
    issuer: String,
    observed_credential_revision: u64,
    fencing_token: u64,
    attempt_count: u64,
    envelope_algorithm: String,
    key_version: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct RefreshCommitRow {
    observed_credential_revision: u64,
    state: String,
    last_succeeded_at: Option<u64>,
}

/// Runs a bounded proactive renewal pass. Provider failures are persisted as
/// non-secret state and do not prevent unrelated metadata maintenance.
pub(crate) async fn run(env: &Env, now: u64) -> Result<()> {
    let database = env.d1("SKYDRIVER_INDEX")?;
    for _ in 0..MAXIMUM_REFRESHES_PER_RUN {
        if !refresh_one(env, &database, now, None).await? {
            break;
        }
    }
    Ok(())
}

/// Ensures a driver grant cannot expose an expired or nearly expired access
/// token. A due managed credential is renewed synchronously behind the same
/// D1 fence used by Cron; concurrent callers simply observe the winner.
pub(crate) async fn ensure_fresh(env: &Env, driver_id: &str, expires_at: u64) -> Result<bool> {
    let now = now_seconds();
    if expires_at > now + MINIMUM_GRANT_LIFETIME_SECONDS {
        return Ok(true);
    }
    let database = env.d1("SKYDRIVER_INDEX")?;
    let _ = refresh_one(env, &database, now, Some(driver_id)).await?;
    let current = database
        .prepare(
            "SELECT credential.expires_at
             FROM driver_instances AS driver
             JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE driver.id = ?1",
        )
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<serde_json::Value>(Some("expires_at"))
        .await?;
    Ok(current
        .and_then(|value| value.as_u64())
        .is_some_and(|value| value > now + MINIMUM_GRANT_LIFETIME_SECONDS))
}

async fn refresh_one(
    env: &Env,
    database: &D1Database,
    now: u64,
    driver_id: Option<&str>,
) -> Result<bool> {
    // The explicit state set proves the partial claim index predicate to
    // SQLite; the following per-state deadlines retain the exact due logic.
    let candidate = database
        .prepare(
            "SELECT driver_id FROM driver_credential_refreshes
             WHERE state IN ('ready', 'retry', 'claimed')
               AND (?1 IS NULL OR driver_id = ?1)
               AND (
                 (state = 'ready' AND refresh_after <= ?2)
                 OR (state = 'retry' AND retry_at <= ?2)
                 OR (state = 'claimed' AND lease_expires_at <= ?2)
               )
             ORDER BY COALESCE(retry_at, refresh_after), driver_id LIMIT 1",
        )
        .bind(&[
            driver_id.map_or(JsValue::NULL, JsValue::from_str),
            integer(now),
        ])?
        .first::<serde_json::Value>(Some("driver_id"))
        .await?;
    let Some(serde_json::Value::String(driver_id)) = candidate else {
        return Ok(false);
    };
    let claimed = database
        .prepare(
            "UPDATE driver_credential_refreshes
             SET state = 'claimed', fencing_token = fencing_token + 1,
                 lease_expires_at = ?1, retry_at = NULL,
                 attempt_count = attempt_count + 1, last_error_code = NULL, updated_at = ?2
             WHERE driver_id = ?3 AND (
                 (state = 'ready' AND refresh_after <= ?2)
                 OR (state = 'retry' AND retry_at <= ?2)
                 OR (state = 'claimed' AND lease_expires_at <= ?2)
             )",
        )
        .bind(&[
            integer(now + CLAIM_SECONDS),
            integer(now),
            JsValue::from_str(&driver_id),
        ])?
        .run()
        .await?;
    if changes(claimed.meta()?) != 1 {
        return Ok(true);
    }
    let Some(task) = load_claimed(database, &driver_id, now).await? else {
        return Ok(true);
    };
    let outcome = renew(env, &task).await;
    match outcome {
        Ok(mut material) => {
            let next_revision = task.observed_credential_revision + 1;
            let sealed = seal_driver_credential(
                env,
                &task.credential_id,
                next_revision,
                &material.plaintext,
            );
            material.plaintext.zeroize();
            let sealed = match sealed {
                Ok(sealed) => sealed,
                Err(error) => {
                    fail_refresh(database, &task, now, "credential_seal_failed", false).await?;
                    return Err(error);
                }
            };
            commit_refresh(
                database,
                &task,
                &sealed,
                material.credential_expires_at,
                material.refresh_token_expires_at,
                now,
            )
            .await?;
        }
        Err(RenewalFailure::Retry(code)) => fail_refresh(database, &task, now, code, false).await?,
        Err(RenewalFailure::Reauthenticate(code)) => {
            fail_refresh(database, &task, now, code, true).await?;
        }
        Err(RenewalFailure::Internal(_)) => {
            fail_refresh(database, &task, now, "credential_material_invalid", true).await?;
        }
    }
    Ok(true)
}

async fn load_claimed(
    database: &D1Database,
    driver_id: &str,
    now: u64,
) -> Result<Option<RefreshTask>> {
    database
        .prepare(
            "SELECT refresh.credential_id, refresh.driver_id, driver.kind AS driver_kind,
                    refresh.issuer,
                    refresh.observed_credential_revision, refresh.fencing_token,
                    refresh.attempt_count, credential.envelope_algorithm,
                    credential.key_version, credential.nonce, credential.ciphertext
             FROM driver_credential_refreshes AS refresh
             JOIN driver_instances AS driver ON driver.id = refresh.driver_id
             JOIN credential_envelopes AS credential ON credential.id = refresh.credential_id
             WHERE refresh.driver_id = ?1 AND refresh.state = 'claimed'
               AND refresh.lease_expires_at > ?2
               AND driver.credential_ref = refresh.credential_id
               AND credential.revision = refresh.observed_credential_revision",
        )
        .bind(&[JsValue::from_str(driver_id), integer(now)])?
        .first::<RefreshTask>(None)
        .await
}

async fn renew(
    env: &Env,
    task: &RefreshTask,
) -> std::result::Result<driver_renewal::CredentialMaterial, RenewalFailure> {
    let mut plaintext = open_driver_credential(
        env,
        &task.credential_id,
        task.observed_credential_revision,
        &task.envelope_algorithm,
        &task.key_version,
        &task.nonce,
        &task.ciphertext,
    )
    .map_err(|_| RenewalFailure::Reauthenticate("credential_envelope_invalid"))?;
    let kind = DriverKind::parse(&task.driver_kind)
        .ok_or(RenewalFailure::Reauthenticate("credential_kind_unknown"))?;
    let renewed = driver_renewal::renew(kind, &plaintext, &task.issuer).await;
    plaintext.zeroize();
    renewed
}

async fn commit_refresh(
    database: &D1Database,
    task: &RefreshTask,
    sealed: &crate::vfs_envelopes::SealedEnvelope,
    expires_at: u64,
    refresh_token_expires_at: u64,
    now: u64,
) -> Result<()> {
    let next_revision = task.observed_credential_revision + 1;
    database
        .batch(vec![
            database
                .prepare(
                    "UPDATE credential_envelopes
                     SET envelope_algorithm = ?1, key_version = ?2, nonce = ?3,
                         ciphertext = ?4, expires_at = ?5, revision = ?6, rotated_at = ?7
                     WHERE id = ?8 AND revision = ?9
                       AND EXISTS (
                           SELECT 1 FROM driver_credential_refreshes AS refresh
                           WHERE refresh.credential_id = ?8 AND refresh.state = 'claimed'
                             AND refresh.fencing_token = ?10 AND refresh.lease_expires_at > ?7
                       )",
                )
                .bind(&[
                    JsValue::from_str(ENVELOPE_ALGORITHM),
                    JsValue::from_str(MASTER_KEY_VERSION),
                    blob_binding(&sealed.nonce),
                    blob_binding(&sealed.ciphertext),
                    integer(expires_at),
                    integer(next_revision),
                    integer(now),
                    JsValue::from_str(&task.credential_id),
                    integer(task.observed_credential_revision),
                    integer(task.fencing_token),
                ])?,
            database
                .prepare(
                    "UPDATE driver_credential_refreshes
                     SET observed_credential_revision = ?1, state = 'ready',
                         lease_expires_at = NULL, refresh_after = ?2,
                         refresh_token_expires_at = ?3, retry_at = NULL,
                         attempt_count = 0, last_error_code = NULL,
                         last_succeeded_at = ?4, updated_at = ?4
                     WHERE credential_id = ?5 AND state = 'claimed' AND fencing_token = ?6
                       AND lease_expires_at > ?4
                       AND EXISTS (
                           SELECT 1 FROM credential_envelopes AS credential
                           WHERE credential.id = ?5 AND credential.revision = ?1
                       )",
                )
                .bind(&[
                    integer(next_revision),
                    integer(driver_renewal::refresh_after(expires_at, now)),
                    integer(refresh_token_expires_at),
                    integer(now),
                    JsValue::from_str(&task.credential_id),
                    integer(task.fencing_token),
                ])?,
            database
                .prepare(
                    "INSERT INTO vfs_audit_events (
                         filesystem_id, principal_id, token_id, event_kind, subject_kind,
                         subject_id, details_json, created_at
                     )
                     SELECT NULL, NULL, NULL, 'driver.credential.refreshed', 'driver', ?1,
                            json_object('credential_revision', ?2, 'source', 'control_plane'), ?3
                     WHERE EXISTS (
                         SELECT 1 FROM driver_credential_refreshes AS refresh
                         WHERE refresh.driver_id = ?1 AND refresh.state = 'ready'
                           AND refresh.observed_credential_revision = ?2
                           AND refresh.last_succeeded_at = ?3
                     )",
                )
                .bind(&[
                    JsValue::from_str(&task.driver_id),
                    integer(next_revision),
                    integer(now),
                ])?,
        ])
        .await?;
    let committed = database
        .prepare(
            "SELECT observed_credential_revision, state, last_succeeded_at
             FROM driver_credential_refreshes WHERE credential_id = ?1",
        )
        .bind(&[JsValue::from_str(&task.credential_id)])?
        .first::<RefreshCommitRow>(None)
        .await?;
    if !committed.is_some_and(|row| {
        row.observed_credential_revision == next_revision
            && row.state == "ready"
            && row.last_succeeded_at == Some(now)
    }) {
        return Err(worker::Error::RustError(
            "driver credential refresh lost its D1 fence".to_owned(),
        ));
    }
    Ok(())
}

async fn fail_refresh(
    database: &D1Database,
    task: &RefreshTask,
    now: u64,
    code: &str,
    reauthenticate: bool,
) -> Result<()> {
    let retry_at = now + retry_delay(task.attempt_count, task.fencing_token);
    database
        .prepare(
            "UPDATE driver_credential_refreshes
             SET state = ?1, lease_expires_at = NULL, retry_at = ?2,
                 last_error_code = ?3, updated_at = ?4
             WHERE credential_id = ?5 AND state = 'claimed' AND fencing_token = ?6",
        )
        .bind(&[
            JsValue::from_str(if reauthenticate {
                "reauth_required"
            } else {
                "retry"
            }),
            if reauthenticate {
                JsValue::NULL
            } else {
                integer(retry_at)
            },
            JsValue::from_str(code),
            integer(now),
            JsValue::from_str(&task.credential_id),
            integer(task.fencing_token),
        ])?
        .run()
        .await?;
    Ok(())
}

fn retry_delay(attempt: u64, fence: u64) -> u64 {
    let exponent = attempt.saturating_sub(1).min(8) as u32;
    (60_u64.saturating_mul(1_u64 << exponent)).min(6 * 60 * 60) + fence % 61
}

fn now_seconds() -> u64 {
    worker::Date::now().as_millis() / 1_000
}

fn integer(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

fn changes(meta: Option<worker::D1ResultMeta>) -> u64 {
    meta.and_then(|value| value.changes).unwrap_or(0) as u64
}

#[cfg(test)]
mod tests {
    use super::retry_delay;

    #[test]
    fn retry_is_bounded() {
        assert!((60..=120).contains(&retry_delay(1, 60)));
        assert!(retry_delay(100, 60) <= 6 * 60 * 60 + 60);
    }
}
