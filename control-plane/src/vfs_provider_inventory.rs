use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skydriver_driver_contract::{CredentialPosture, DriverKind, InventoryMode};
use worker::{D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{
    driver_credentials, driver_inventory, operator_sessions, vfs_envelopes::open_driver_credential,
};

const COMPLETE_SCAN_INTERVAL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Deserialize)]
struct Candidate {
    driver_id: String,
    driver_kind: String,
    config_json: String,
    generation: u64,
    state: String,
    cursor: Option<String>,
    attempt_count: u64,
}

#[derive(Deserialize)]
struct RefreshDriver {
    kind: String,
    config_json: String,
}

#[derive(Deserialize)]
struct CredentialEnvelope {
    id: String,
    envelope_algorithm: String,
    key_version: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    revision: u64,
    expires_at: u64,
}

#[derive(Serialize, Deserialize)]
struct InventoryStatus {
    driver_id: String,
    driver_kind: String,
    generation: u64,
    state: String,
    scanned_objects: u64,
    unknown_objects: u64,
    quarantined_objects: u64,
    quarantined_bytes: u64,
    oldest_quarantined_at: Option<u64>,
    last_started_at: Option<u64>,
    last_completed_at: Option<u64>,
    last_error_code: Option<String>,
    next_scan_at: Option<u64>,
    attempt_count: u64,
    updated_at: u64,
}

#[derive(Serialize)]
struct InventorySnapshot {
    schema: &'static str,
    observed_at: u64,
    drivers: Vec<InventoryStatus>,
}

pub(crate) async fn snapshot(request: Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(&request, env).await? {
        return Response::error("authentication required", 401);
    }
    let database = env.d1("SKYDRIVER_INDEX")?;
    ensure_rows(&database, now_seconds()).await?;
    let drivers = database
        .prepare(
            "SELECT state.driver_id, driver.kind AS driver_kind, state.generation,
                    state.state, state.scanned_objects, state.unknown_objects,
                    COUNT(quarantine.storage_key) AS quarantined_objects,
                    COALESCE(SUM(quarantine.size_bytes), 0) AS quarantined_bytes,
                    MIN(quarantine.first_seen_at) AS oldest_quarantined_at,
                    state.last_started_at, state.last_completed_at,
                    state.last_error_code, state.next_scan_at,
                    state.attempt_count, state.updated_at
             FROM vfs_provider_inventory_state AS state
             JOIN driver_instances AS driver ON driver.id = state.driver_id
             LEFT JOIN vfs_provider_quarantine AS quarantine
               ON quarantine.driver_id = state.driver_id AND quarantine.state = 'observed'
             GROUP BY state.driver_id, driver.kind, state.generation, state.state,
                      state.scanned_objects, state.unknown_objects, state.last_started_at,
                      state.last_completed_at, state.last_error_code,
                      state.next_scan_at, state.attempt_count, state.updated_at
             ORDER BY state.driver_id",
        )
        .all()
        .await?
        .results::<InventoryStatus>()?;
    no_store_json(&InventorySnapshot {
        schema: "skydriver.management.provider-inventory.v1",
        observed_at: now_seconds(),
        drivers,
    })
}

/// Schedules one supported hosted driver for the next bounded Cron pass.
pub(crate) async fn refresh(request: Request, env: &Env, driver_id: &str) -> Result<Response> {
    if !operator_sessions::authorized(&request, env).await? {
        return Response::error("authentication required", 401);
    }
    let database = env.d1("SKYDRIVER_INDEX")?;
    let now = now_seconds();
    ensure_rows(&database, now).await?;
    let Some(driver) = database
        .prepare(
            "SELECT kind, config_json FROM driver_instances
             WHERE id = ?1 AND enabled = 1 AND retired_at IS NULL",
        )
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<RefreshDriver>(None)
        .await?
    else {
        return Response::error(
            "hosted provider inventory is unavailable for this driver",
            409,
        );
    };
    let Some(kind) = DriverKind::parse(&driver.kind) else {
        return Response::error(
            "hosted provider inventory is unavailable for this driver",
            409,
        );
    };
    if kind.inventory_mode() == InventoryMode::AgentHost {
        return Response::error(
            "provider inventory must run on this driver's agent host",
            409,
        );
    }
    if !driver_inventory::execution_available(env, kind, &driver.config_json)? {
        return Response::error(
            "provider inventory requires an environment-owned binding",
            409,
        );
    }
    let updated = database
        .prepare(
            "UPDATE vfs_provider_inventory_state
             SET state = CASE WHEN state = 'scanning' THEN state ELSE 'idle' END,
                 cursor = CASE WHEN state = 'scanning' THEN cursor ELSE NULL END,
                 next_scan_at = ?1, attempt_count = 0, last_error_code = NULL,
                 updated_at = ?1
             WHERE driver_id = ?2
               AND EXISTS (
                   SELECT 1 FROM driver_instances AS driver
                   WHERE driver.id = ?2 AND driver.enabled = 1
                     AND driver.retired_at IS NULL
               )",
        )
        .bind(&[integer(now), JsValue::from_str(driver_id)])?
        .run()
        .await?;
    if changes(updated.meta()?) != 1 {
        return Response::error(
            "hosted provider inventory is unavailable for this driver",
            409,
        );
    }
    snapshot(request, env).await
}

/// Runs one bounded provider listing page. Unknown objects are quarantined as
/// evidence only; this subsystem never adopts or deletes them.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded provider page, quarantine evidence, and cursor commit stay visible"
)]
pub(crate) async fn run(env: &Env, now: u64) -> Result<()> {
    let database = env.d1("SKYDRIVER_INDEX")?;
    ensure_rows(&database, now).await?;
    let candidate = database
        .prepare(
            "SELECT driver.id AS driver_id, driver.kind AS driver_kind, driver.config_json,
                    state.generation, state.state, state.cursor, state.attempt_count
             FROM vfs_provider_inventory_state AS state
                  INDEXED BY vfs_provider_inventory_due
             JOIN driver_instances AS driver ON driver.id = state.driver_id
             WHERE driver.enabled = 1 AND driver.retired_at IS NULL
               AND state.state IN ('idle', 'scanning', 'complete', 'error')
               AND state.next_scan_at IS NOT NULL
               AND state.next_scan_at <= ?1
             ORDER BY state.next_scan_at, driver.id LIMIT 1",
        )
        .bind(&[integer(now)])?
        .first::<Candidate>(None)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(());
    };
    let Some(driver_kind) = DriverKind::parse(&candidate.driver_kind) else {
        return mark_driver(
            &database,
            &candidate.driver_id,
            "unsupported",
            "provider_inventory_not_supported",
            now,
        )
        .await;
    };
    if driver_kind.inventory_mode() == InventoryMode::AgentHost {
        return mark_driver(
            &database,
            &candidate.driver_id,
            "unsupported",
            "inventory_runs_on_agent_host",
            now,
        )
        .await;
    }
    if !driver_inventory::execution_available(env, driver_kind, &candidate.config_json)? {
        return mark_driver(
            &database,
            &candidate.driver_id,
            "unsupported",
            "inventory_requires_environment_binding",
            now,
        )
        .await;
    }
    let generation = if candidate.state == "scanning" {
        candidate.generation
    } else {
        candidate.generation + 1
    };
    let expected_cursor = if candidate.state == "scanning" {
        candidate.cursor.clone()
    } else {
        None
    };
    if candidate.state != "scanning" {
        let started = database.prepare("UPDATE vfs_provider_inventory_state SET generation = ?1, state = 'scanning', cursor = NULL, scanned_objects = 0, unknown_objects = 0, last_started_at = ?2, next_scan_at = ?2, last_error_code = NULL, updated_at = ?2 WHERE driver_id = ?3 AND generation = ?4 AND state = ?5 AND cursor IS ?6")
            .bind(&[integer(generation), integer(now), JsValue::from_str(&candidate.driver_id), integer(candidate.generation), JsValue::from_str(&candidate.state), JsValue::NULL])?.run().await?;
        if changes(started.meta()?) != 1 {
            return Ok(());
        }
    }
    let page = match list_page(env, &database, &candidate, driver_kind).await {
        Ok(page) => page,
        Err(error) => {
            mark_driver_error(
                &database,
                &candidate.driver_id,
                "provider_list_failed",
                candidate.attempt_count + 1,
                generation,
                expected_cursor.as_deref(),
                now,
            )
            .await?;
            worker::console_error!(
                "provider inventory {} failed: {error:?}",
                candidate.driver_id
            );
            return Ok(());
        }
    };
    let mut statements = Vec::new();
    let mut unknown = 0_u64;
    let scanned = u64::try_from(page.objects.len()).unwrap_or(u64::MAX);
    for observed in page.objects {
        let known = known(&database, &candidate.driver_id, &observed.storage_key).await?;
        if known {
            statements.push(database.prepare("UPDATE vfs_provider_quarantine SET state = 'resolved', resolved_at = ?1, last_seen_generation = ?2, last_seen_at = ?1 WHERE driver_id = ?3 AND storage_key = ?4 AND state = 'observed' AND EXISTS (SELECT 1 FROM vfs_provider_inventory_state WHERE driver_id = ?3 AND generation = ?2 AND state = 'scanning' AND cursor IS ?5)")
                .bind(&[integer(now), integer(generation), JsValue::from_str(&candidate.driver_id), JsValue::from_str(&observed.storage_key), optional_string(expected_cursor.as_deref())])?);
        } else {
            unknown += 1;
            statements.push(database.prepare("INSERT INTO vfs_provider_quarantine (driver_id, storage_key, storage_key_sha256, state, provider_version, size_bytes, first_seen_generation, last_seen_generation, observation_count, first_seen_at, last_seen_at, resolved_at) SELECT ?1, ?2, ?3, 'observed', ?4, ?5, ?6, ?6, 1, ?7, ?7, NULL WHERE EXISTS (SELECT 1 FROM vfs_provider_inventory_state WHERE driver_id = ?1 AND generation = ?6 AND state = 'scanning' AND cursor IS ?8) ON CONFLICT(driver_id, storage_key) DO UPDATE SET state = 'observed', provider_version = excluded.provider_version, size_bytes = excluded.size_bytes, last_seen_generation = excluded.last_seen_generation, observation_count = vfs_provider_quarantine.observation_count + 1, last_seen_at = excluded.last_seen_at, resolved_at = NULL")
                .bind(&[JsValue::from_str(&candidate.driver_id), JsValue::from_str(&observed.storage_key), JsValue::from_str(&sha256(&observed.storage_key)), JsValue::from_str(&observed.provider_version), integer(observed.size_bytes), integer(generation), integer(now), optional_string(expected_cursor.as_deref())])?);
        }
    }
    if page.next_cursor.is_none() {
        // Only a complete generation proves that an earlier unknown object is
        // absent. Partial pages and failed scans must retain their evidence.
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_provider_quarantine
                     SET state = 'resolved', resolved_at = ?1
                     WHERE driver_id = ?2 AND state = 'observed'
                       AND last_seen_generation < ?3
                       AND EXISTS (
                           SELECT 1 FROM vfs_provider_inventory_state
                           WHERE driver_id = ?2 AND generation = ?3
                             AND state = 'scanning' AND cursor IS ?4
                       )",
                )
                .bind(&[
                    integer(now),
                    JsValue::from_str(&candidate.driver_id),
                    integer(generation),
                    optional_string(expected_cursor.as_deref()),
                ])?,
        );
    }
    let (state, cursor, completed, next_scan_at) = if let Some(cursor) = page.next_cursor {
        (
            "scanning",
            JsValue::from_str(&cursor),
            JsValue::NULL,
            integer(now),
        )
    } else {
        (
            "complete",
            JsValue::NULL,
            integer(now),
            integer(now + COMPLETE_SCAN_INTERVAL_SECONDS),
        )
    };
    statements.push(database.prepare("UPDATE vfs_provider_inventory_state SET state = ?1, cursor = ?2, scanned_objects = scanned_objects + ?3, unknown_objects = unknown_objects + ?4, last_completed_at = COALESCE(?5, last_completed_at), next_scan_at = ?6, attempt_count = 0, last_error_code = NULL, updated_at = ?7 WHERE driver_id = ?8 AND generation = ?9 AND state = 'scanning' AND cursor IS ?10")
        .bind(&[JsValue::from_str(state), cursor, integer(scanned), integer(unknown), completed, next_scan_at, integer(now), JsValue::from_str(&candidate.driver_id), integer(generation), optional_string(expected_cursor.as_deref())])?);
    database.batch(statements).await?;
    Ok(())
}

async fn ensure_rows(database: &D1Database, now: u64) -> Result<()> {
    database.prepare("INSERT INTO vfs_provider_inventory_state (driver_id, next_scan_at, updated_at) SELECT id, ?1, ?1 FROM driver_instances WHERE retired_at IS NULL ON CONFLICT(driver_id) DO NOTHING")
        .bind(&[integer(now)])?.run().await?;
    Ok(())
}

async fn list_page(
    env: &Env,
    database: &D1Database,
    candidate: &Candidate,
    driver_kind: DriverKind,
) -> Result<driver_inventory::ProviderPage> {
    if driver_kind.inventory_mode() == InventoryMode::Hosted
        && driver_kind.credential_posture() == CredentialPosture::Required
    {
        return list_hosted_page(env, database, candidate, driver_kind).await;
    }
    driver_inventory::list_page(
        env,
        driver_kind,
        &candidate.config_json,
        candidate.cursor.as_deref(),
        None,
    )
    .await
}

async fn list_hosted_page(
    env: &Env,
    database: &D1Database,
    candidate: &Candidate,
    driver_kind: DriverKind,
) -> Result<driver_inventory::ProviderPage> {
    let envelope = load_credential(database, &candidate.driver_id).await?;
    if !driver_credentials::ensure_fresh(env, &candidate.driver_id, envelope.expires_at).await? {
        return Err(worker::Error::RustError(
            "Aliyun inventory credential requires reauthorization".to_owned(),
        ));
    }
    let envelope = load_credential(database, &candidate.driver_id).await?;
    let mut plaintext = open_driver_credential(
        env,
        &envelope.id,
        envelope.revision,
        &envelope.envelope_algorithm,
        &envelope.key_version,
        &envelope.nonce,
        &envelope.ciphertext,
    )?;
    let result = driver_inventory::list_page(
        env,
        driver_kind,
        &candidate.config_json,
        candidate.cursor.as_deref(),
        Some(&plaintext),
    )
    .await;
    plaintext.zeroize();
    result
}

async fn load_credential(database: &D1Database, driver_id: &str) -> Result<CredentialEnvelope> {
    database
        .prepare(
            "SELECT credential.id, credential.envelope_algorithm, credential.key_version,
                    credential.nonce, credential.ciphertext, credential.revision,
                    credential.expires_at
             FROM driver_instances AS driver
             JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE driver.id = ?1 AND driver.enabled = 1",
        )
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<CredentialEnvelope>(None)
        .await?
        .ok_or_else(|| {
            worker::Error::RustError("Aliyun inventory credential is missing".to_owned())
        })
}

async fn mark_driver(
    database: &D1Database,
    driver_id: &str,
    state: &str,
    error: &str,
    now: u64,
) -> Result<()> {
    database.prepare("UPDATE vfs_provider_inventory_state SET state = ?1, next_scan_at = NULL, last_error_code = ?2, updated_at = ?3 WHERE driver_id = ?4")
        .bind(&[JsValue::from_str(state), JsValue::from_str(error), integer(now), JsValue::from_str(driver_id)])?.run().await?;
    Ok(())
}

async fn mark_driver_error(
    database: &D1Database,
    driver_id: &str,
    error: &str,
    attempt: u64,
    generation: u64,
    expected_cursor: Option<&str>,
    now: u64,
) -> Result<()> {
    database.prepare("UPDATE vfs_provider_inventory_state SET state = 'error', cursor = NULL, next_scan_at = ?1, attempt_count = ?2, last_error_code = ?3, updated_at = ?4 WHERE driver_id = ?5 AND state = 'scanning' AND generation = ?6 AND cursor IS ?7")
        .bind(&[integer(now + retry_delay(attempt, generation)), integer(attempt), JsValue::from_str(error), integer(now), JsValue::from_str(driver_id), integer(generation), optional_string(expected_cursor)])?.run().await?;
    Ok(())
}

async fn known(database: &D1Database, driver_id: &str, storage_key: &str) -> Result<bool> {
    let value = database.prepare("SELECT EXISTS (
        SELECT 1 FROM vfs_locations WHERE driver_id = ?1 AND storage_key = ?2 AND state != 'deleted'
        UNION ALL
        SELECT 1 FROM vfs_put_intents WHERE driver_id = ?1 AND storage_key = ?2 AND state IN ('prepared', 'uploaded', 'committing', 'committed')
    ) AS present")
        .bind(&[JsValue::from_str(driver_id), JsValue::from_str(storage_key)])?.first::<u64>(Some("present")).await?.unwrap_or(0);
    Ok(value == 1)
}

fn sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    encoded
}
fn retry_delay(attempt: u64, generation: u64) -> u64 {
    let exponent = attempt.saturating_sub(1).min(8) as u32;
    (60_u64.saturating_mul(1_u64 << exponent)).min(6 * 60 * 60) + generation % 61
}
fn changes(meta: Option<worker::D1ResultMeta>) -> usize {
    meta.and_then(|value| value.changes).unwrap_or_default()
}
fn integer(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}
fn optional_string(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, JsValue::from_str)
}
fn now_seconds() -> u64 {
    worker::Date::now().as_millis() / 1_000
}
fn no_store_json<T: Serialize>(value: &T) -> Result<Response> {
    let mut response = Response::from_json(value)?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_retry_is_bounded_and_jittered() {
        assert!((60..=120).contains(&retry_delay(1, 60)));
        assert!(retry_delay(2, 2) > retry_delay(1, 1));
        assert!(retry_delay(100, 60) <= 6 * 60 * 60 + 60);
    }
}
