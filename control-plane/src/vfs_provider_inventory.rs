use std::fmt::Write as _;

use carrack_driver_contract::{DriverKind, InventoryMode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use worker::{
    D1Database, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result,
    wasm_bindgen::JsValue,
};
use zeroize::Zeroize as _;

use crate::{
    driver_credentials::{self, AliyunCredential},
    environment_defaults, operator_sessions, r2_signing,
    vfs_envelopes::open_driver_credential,
};

const PAGE_SIZE: u32 = 100;
const MAXIMUM_ALIYUN_PAGES_PER_RUN: usize = 8;
const MAXIMUM_ALIYUN_CURSOR_BYTES: usize = 64 * 1024;
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

#[derive(Deserialize)]
struct AliyunListResponse {
    #[serde(default)]
    items: Vec<AliyunFile>,
    #[serde(default)]
    next_marker: String,
}

#[derive(Deserialize)]
struct AliyunFile {
    #[serde(default)]
    file_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    file_name: Option<String>,
    #[serde(default)]
    size: Option<i64>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliyunCursor {
    stack: Vec<AliyunFrame>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AliyunFrame {
    folder_id: String,
    path: String,
    marker: String,
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

struct ObservedObject {
    storage_key: String,
    provider_version: String,
    size_bytes: u64,
}

struct ProviderPage {
    objects: Vec<ObservedObject>,
    next_cursor: Option<String>,
}

pub(crate) async fn snapshot(request: Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(&request, env).await? {
        return Response::error("authentication required", 401);
    }
    let database = env.d1("CARRACK_INDEX")?;
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
        schema: "carrack.management.provider-inventory.v1",
        observed_at: now_seconds(),
        drivers,
    })
}

/// Schedules one supported hosted driver for the next bounded Cron pass.
pub(crate) async fn refresh(request: Request, env: &Env, driver_id: &str) -> Result<Response> {
    if !operator_sessions::authorized(&request, env).await? {
        return Response::error("authentication required", 401);
    }
    let database = env.d1("CARRACK_INDEX")?;
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
    match kind.inventory_mode() {
        InventoryMode::AgentHost => {
            return Response::error(
                "provider inventory must run on this driver's agent host",
                409,
            );
        }
        InventoryMode::EnvironmentBinding => {
            let config = serde_json::from_str::<r2_signing::Config>(&driver.config_json)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            if !environment_defaults::is_managed_r2_config(env, &config)? {
                return Response::error(
                    "provider inventory requires an environment-owned binding",
                    409,
                );
            }
        }
        InventoryMode::Hosted => {}
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
    let database = env.d1("CARRACK_INDEX")?;
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
    match driver_kind.inventory_mode() {
        InventoryMode::AgentHost => {
            return mark_driver(
                &database,
                &candidate.driver_id,
                "unsupported",
                "inventory_runs_on_agent_host",
                now,
            )
            .await;
        }
        InventoryMode::EnvironmentBinding => {
            let config = serde_json::from_str::<r2_signing::Config>(&candidate.config_json)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            if environment_defaults::is_managed_r2_config(env, &config)? {
                // The environment binding can enumerate this exact bucket.
            } else {
                return mark_driver(
                    &database,
                    &candidate.driver_id,
                    "unsupported",
                    "inventory_requires_environment_binding",
                    now,
                )
                .await;
            }
        }
        InventoryMode::Hosted => {}
    }
    let generation = if candidate.state == "scanning" {
        candidate.generation
    } else {
        candidate.generation + 1
    };
    if candidate.state != "scanning" {
        database.prepare("UPDATE vfs_provider_inventory_state SET generation = ?1, state = 'scanning', cursor = NULL, scanned_objects = 0, unknown_objects = 0, last_started_at = ?2, next_scan_at = ?2, last_error_code = NULL, updated_at = ?2 WHERE driver_id = ?3")
            .bind(&[integer(generation), integer(now), JsValue::from_str(&candidate.driver_id)])?.run().await?;
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
            statements.push(database.prepare("UPDATE vfs_provider_quarantine SET state = 'resolved', resolved_at = ?1, last_seen_generation = ?2, last_seen_at = ?1 WHERE driver_id = ?3 AND storage_key = ?4 AND state = 'observed'")
                .bind(&[integer(now), integer(generation), JsValue::from_str(&candidate.driver_id), JsValue::from_str(&observed.storage_key)])?);
        } else {
            unknown += 1;
            statements.push(database.prepare("INSERT INTO vfs_provider_quarantine (driver_id, storage_key, storage_key_sha256, state, provider_version, size_bytes, first_seen_generation, last_seen_generation, observation_count, first_seen_at, last_seen_at, resolved_at) VALUES (?1, ?2, ?3, 'observed', ?4, ?5, ?6, ?6, 1, ?7, ?7, NULL) ON CONFLICT(driver_id, storage_key) DO UPDATE SET state = 'observed', provider_version = excluded.provider_version, size_bytes = excluded.size_bytes, last_seen_generation = excluded.last_seen_generation, observation_count = vfs_provider_quarantine.observation_count + 1, last_seen_at = excluded.last_seen_at, resolved_at = NULL")
                .bind(&[JsValue::from_str(&candidate.driver_id), JsValue::from_str(&observed.storage_key), JsValue::from_str(&sha256(&observed.storage_key)), JsValue::from_str(&observed.provider_version), integer(observed.size_bytes), integer(generation), integer(now)])?);
        }
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
    statements.push(database.prepare("UPDATE vfs_provider_inventory_state SET state = ?1, cursor = ?2, scanned_objects = scanned_objects + ?3, unknown_objects = unknown_objects + ?4, last_completed_at = COALESCE(?5, last_completed_at), next_scan_at = ?6, attempt_count = 0, last_error_code = NULL, updated_at = ?7 WHERE driver_id = ?8 AND generation = ?9 AND state = 'scanning'")
        .bind(&[JsValue::from_str(state), cursor, integer(scanned), integer(unknown), completed, next_scan_at, integer(now), JsValue::from_str(&candidate.driver_id), integer(generation)])?);
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
) -> Result<ProviderPage> {
    match driver_kind {
        DriverKind::R2V1 => list_r2_page(env, candidate).await,
        DriverKind::AliyunDriveOpenV2 => list_aliyun_page(env, database, candidate).await,
        DriverKind::LocalFilesystemV2 => Err(worker::Error::RustError(
            "agent-host inventory reached hosted dispatcher".to_owned(),
        )),
    }
}

async fn list_r2_page(env: &Env, candidate: &Candidate) -> Result<ProviderPage> {
    let config = serde_json::from_str::<r2_signing::Config>(&candidate.config_json)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let bucket = env.bucket("CARRACK_PAYLOAD")?;
    let mut list = bucket.list().limit(PAGE_SIZE).prefix(config.prefix.clone());
    if let Some(cursor) = candidate.cursor.as_deref() {
        list = list.cursor(cursor);
    }
    let listed = list.execute().await?;
    let objects = listed
        .objects()
        .into_iter()
        .filter_map(|object| {
            let key = object.key();
            let storage_key = key.strip_prefix(&config.prefix)?.to_owned();
            (!storage_key.is_empty()).then(|| ObservedObject {
                storage_key,
                provider_version: object.version(),
                size_bytes: object.size(),
            })
        })
        .collect();
    Ok(ProviderPage {
        objects,
        next_cursor: listed.truncated().then(|| listed.cursor()).flatten(),
    })
}

async fn list_aliyun_page(
    env: &Env,
    database: &D1Database,
    candidate: &Candidate,
) -> Result<ProviderPage> {
    let config = serde_json::from_str::<AliyunConfig>(&candidate.config_json)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let _ = config.upload_part_bytes;
    if !config.api_base_url.starts_with("https://") || config.api_base_url.ends_with('/') {
        return Err(worker::Error::RustError(
            "unsafe Aliyun inventory API base URL".to_owned(),
        ));
    }
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
    let decoded = serde_json::from_slice::<AliyunCredential>(&plaintext)
        .map_err(|error| worker::Error::RustError(error.to_string()));
    plaintext.zeroize();
    let mut credential = decoded?;
    let result =
        list_aliyun_with_credential(&config, candidate.cursor.as_deref(), &credential).await;
    credential.access_token.zeroize();
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

#[allow(
    clippy::too_many_lines,
    reason = "bounded recursive listing, cursor advancement, and object projection stay one provider-page protocol"
)]
async fn list_aliyun_with_credential(
    config: &AliyunConfig,
    cursor: Option<&str>,
    credential: &AliyunCredential,
) -> Result<ProviderPage> {
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
    let mut traversal = match cursor {
        Some(encoded) => serde_json::from_str::<AliyunCursor>(encoded).map_err(|error| {
            worker::Error::RustError(format!("invalid Aliyun inventory cursor: {error}"))
        })?,
        None => AliyunCursor {
            stack: vec![AliyunFrame {
                folder_id: config.root_folder_id.clone(),
                path: String::new(),
                marker: String::new(),
            }],
        },
    };
    let mut objects = Vec::new();
    for _ in 0..MAXIMUM_ALIYUN_PAGES_PER_RUN {
        let Some(frame) = traversal.stack.pop() else {
            break;
        };
        let page: AliyunListResponse = aliyun_post(
            &config.api_base_url,
            "/adrive/v1.0/openFile/list",
            &credential.access_token,
            &json!({
                "drive_id": drive_id,
                "parent_file_id": frame.folder_id,
                "limit": PAGE_SIZE,
                "marker": frame.marker,
                "order_by": "name",
                "order_direction": "ASC"
            }),
        )
        .await?;
        if !page.next_marker.is_empty() {
            traversal.stack.push(AliyunFrame {
                folder_id: frame.folder_id,
                path: frame.path.clone(),
                marker: page.next_marker,
            });
        }
        let mut folders = Vec::new();
        for item in page.items {
            let Some(file_id) = item.file_id else {
                continue;
            };
            let Some(name) = item.name.filter(|name| !name.is_empty()).or(item.file_name) else {
                continue;
            };
            let path = if frame.path.is_empty() {
                name
            } else {
                format!("{}/{name}", frame.path)
            };
            match item.kind.as_deref() {
                Some("folder") if !file_id.is_empty() => folders.push(AliyunFrame {
                    folder_id: file_id,
                    path,
                    marker: String::new(),
                }),
                Some("file") if !file_id.is_empty() && item.size.is_some_and(|size| size >= 0) => {
                    objects.push(ObservedObject {
                        storage_key: path,
                        provider_version: file_id,
                        size_bytes: u64::try_from(item.size.unwrap_or_default())
                            .unwrap_or_default(),
                    });
                }
                _ => {}
            }
        }
        traversal.stack.extend(folders.into_iter().rev());
        if objects.len() >= usize::try_from(PAGE_SIZE).unwrap_or(usize::MAX) {
            break;
        }
    }
    let next_cursor = if traversal.stack.is_empty() {
        None
    } else {
        let encoded = serde_json::to_string(&traversal)
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
        if encoded.len() > MAXIMUM_ALIYUN_CURSOR_BYTES {
            return Err(worker::Error::RustError(
                "Aliyun inventory cursor exceeds the bounded state limit".to_owned(),
            ));
        }
        Some(encoded)
    };
    Ok(ProviderPage {
        objects,
        next_cursor,
    })
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
    if !(200..300).contains(&response.status_code()) {
        return Err(worker::Error::RustError(format!(
            "Aliyun inventory API returned HTTP {}",
            response.status_code()
        )));
    }
    response.json::<T>().await
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
    now: u64,
) -> Result<()> {
    database.prepare("UPDATE vfs_provider_inventory_state SET state = 'error', cursor = NULL, next_scan_at = ?1, attempt_count = ?2, last_error_code = ?3, updated_at = ?4 WHERE driver_id = ?5 AND state = 'scanning' AND generation = ?6")
        .bind(&[integer(now + retry_delay(attempt, generation)), integer(attempt), JsValue::from_str(error), integer(now), JsValue::from_str(driver_id), integer(generation)])?.run().await?;
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
