use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{management_driver_registration, operator_sessions, vfs_identifiers};

const ADMIN_TOKEN_BINDING: &str = "CARRACK_ADMIN_TOKEN";
const DATABASE_BINDING: &str = "CARRACK_INDEX";
const VALIDATION_LIFETIME_SECONDS: u64 = 5 * 60;
const DRIVER_STATE_KIND: &str = "driver.state";
const VALIDATION_DOMAIN: &[u8] = b"carrack.management.validation.driver-state.v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DriverStateRequest {
    enabled: bool,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    enabled: bool,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct DriverRow {
    kind: String,
    config_json: String,
    credential_present: u64,
    credential_refresh_state: Option<String>,
    enabled: u64,
    revision: u64,
    placement_count: u64,
    available_location_count: u64,
}

#[derive(Deserialize)]
struct ReceiptRow {
    resource_id: String,
    request_sha256: String,
    validation_digest: String,
    result_json: String,
}

#[derive(Serialize)]
struct ValidationResponse {
    schema: &'static str,
    driver_id: String,
    kind: String,
    current_enabled: bool,
    enabled: bool,
    expected_revision: u64,
    placement_count: u64,
    available_location_count: u64,
    validation_expires_at: u64,
    validation_digest: String,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ReceiptResponse {
    schema: &'static str,
    operation_id: String,
    driver_id: String,
    enabled: bool,
    final_revision: u64,
    committed_at: u64,
    state: &'static str,
}

pub(crate) async fn validate(
    request: &mut Request,
    env: &Env,
    driver_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let Some(driver_id) = driver_id.filter(|value| valid_string(value, 256)) else {
        return Response::error("valid driver ID is required", 400);
    };
    let desired = request.json::<DriverStateRequest>().await?;
    if desired.expected_revision == 0 {
        return Response::error("driver revision is required", 400);
    }
    let database = env.d1(DATABASE_BINDING)?;
    let Some(current) = load_driver(&database, driver_id).await? else {
        return Response::error("driver not found", 404);
    };
    if current.revision != desired.expected_revision {
        return Response::error("driver revision conflict", 409);
    }
    if current.enabled == u64::from(desired.enabled) {
        return Response::error("driver already has the requested state", 400);
    }
    if desired.enabled && !valid_driver_configuration(&current) {
        return Response::error("driver configuration is not valid for enablement", 400);
    }

    let validation_expires_at = now_seconds() + VALIDATION_LIFETIME_SECONDS;
    let warnings = state_warnings(&current, desired.enabled);
    no_store_json(&ValidationResponse {
        schema: "carrack.management.driver-state-validation.v1",
        driver_id: driver_id.to_owned(),
        kind: current.kind,
        current_enabled: current.enabled == 1,
        enabled: desired.enabled,
        expected_revision: desired.expected_revision,
        placement_count: current.placement_count,
        available_location_count: current.available_location_count,
        validation_expires_at,
        validation_digest: validation_digest(env, driver_id, &desired, validation_expires_at)?,
        warnings,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "signed validation, CAS, receipt, audit, replay, and conflict mapping form one transaction"
)]
pub(crate) async fn apply(
    request: &mut Request,
    env: &Env,
    driver_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::configuration_authorized(request, env).await? {
        return Response::error("configuration session required", 403);
    }
    let Some(driver_id) = driver_id.filter(|value| valid_string(value, 256)) else {
        return Response::error("valid driver ID is required", 400);
    };
    let requested = request.json::<ApplyRequest>().await?;
    if requested.expected_revision == 0 || !valid_string(&requested.idempotency_key, 256) {
        return Response::error("valid revision and idempotency key are required", 400);
    }
    let desired = DriverStateRequest {
        enabled: requested.enabled,
        expected_revision: requested.expected_revision,
    };
    let now = now_seconds();
    if requested.validation_expires_at < now
        || requested.validation_expires_at > now + VALIDATION_LIFETIME_SECONDS
    {
        return Response::error("validation expired", 409);
    }
    let expected_digest =
        validation_digest(env, driver_id, &desired, requested.validation_expires_at)?;
    if !constant_time_equal(&requested.validation_digest, &expected_digest) {
        return Response::error("validation digest does not match desired state", 409);
    }
    let request_sha256 = request_sha256(driver_id, &desired)?;
    let database = env.d1(DATABASE_BINDING)?;
    if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
        return replay(
            stored,
            driver_id,
            &request_sha256,
            &requested.validation_digest,
        );
    }
    let Some(current) = load_driver(&database, driver_id).await? else {
        return Response::error("driver not found", 404);
    };
    if current.revision != desired.expected_revision
        || current.enabled == u64::from(desired.enabled)
    {
        return Response::error("driver revision conflict", 409);
    }
    if desired.enabled && !valid_driver_configuration(&current) {
        return Response::error("driver configuration is not valid for enablement", 409);
    }

    let operation_id = vfs_identifiers::new_uuid_v7_hex()?;
    let final_revision = desired.expected_revision + 1;
    let receipt = ReceiptResponse {
        schema: "carrack.management.driver-state-receipt.v1",
        operation_id: operation_id.clone(),
        driver_id: driver_id.to_owned(),
        enabled: desired.enabled,
        final_revision,
        committed_at: now,
        state: "committed",
    };
    let result_json = serde_json::to_string(&receipt).map_err(|error| json_error(&error))?;
    let mutation = database
        .batch(vec![
            database
                .prepare(
                    r"UPDATE driver_instances SET enabled = ?1, revision = revision + 1,
                         updated_at = ?2 WHERE id = ?3 AND revision = ?4",
                )
                .bind(&[
                    JsValue::from_bool(desired.enabled),
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(driver_id),
                    JsValue::from_str(&desired.expected_revision.to_string()),
                ])?,
            database
                .prepare(
                    r"INSERT INTO management_mutation_receipts (
                         operation_id, operator_subject, kind, resource_id, idempotency_key,
                         request_sha256, expected_revision, final_revision, validation_digest,
                         result_json, committed_at
                     ) VALUES (?1, 'operator', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .bind(&[
                    JsValue::from_str(&operation_id),
                    JsValue::from_str(DRIVER_STATE_KIND),
                    JsValue::from_str(driver_id),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_sha256),
                    JsValue::from_str(&desired.expected_revision.to_string()),
                    JsValue::from_str(&final_revision.to_string()),
                    JsValue::from_str(&requested.validation_digest),
                    JsValue::from_str(&result_json),
                    JsValue::from_str(&now.to_string()),
                ])?,
            database
                .prepare(
                    r"INSERT INTO vfs_audit_events (
                         filesystem_id, principal_id, token_id, event_kind, subject_kind,
                         subject_id, details_json, created_at
                     ) VALUES (NULL, NULL, NULL, ?1, 'driver', ?2,
                               json_object('enabled', ?3, 'final_revision', ?4,
                                           'source', 'operator'), ?5)",
                )
                .bind(&[
                    JsValue::from_str(DRIVER_STATE_KIND),
                    JsValue::from_str(driver_id),
                    JsValue::from_bool(desired.enabled),
                    JsValue::from_str(&final_revision.to_string()),
                    JsValue::from_str(&now.to_string()),
                ])?,
        ])
        .await;
    if let Err(error) = mutation {
        if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
            return replay(
                stored,
                driver_id,
                &request_sha256,
                &requested.validation_digest,
            );
        }
        if load_driver(&database, driver_id)
            .await?
            .is_some_and(|latest| latest.revision != desired.expected_revision)
        {
            return Response::error("driver revision conflict", 409);
        }
        return Err(worker::Error::RustError(format!(
            "driver state mutation failed: {error}"
        )));
    }
    no_store_json(&receipt)
}

async fn load_driver(database: &worker::D1Database, driver_id: &str) -> Result<Option<DriverRow>> {
    database
        .prepare(
            r"SELECT driver.kind, driver.config_json,
                    CASE WHEN driver.credential_ref IS NULL THEN 0 ELSE 1 END
                        AS credential_present,
                    refresh.state AS credential_refresh_state,
                    driver.enabled, driver.revision,
                    (SELECT COUNT(*) FROM vfs_directory_drivers AS placement
                     WHERE placement.driver_id = driver.id) AS placement_count,
                    (SELECT COUNT(*) FROM vfs_locations AS location
                     WHERE location.driver_id = driver.id AND location.state = 'available')
                        AS available_location_count
             FROM driver_instances AS driver
             LEFT JOIN driver_credential_refreshes AS refresh
               ON refresh.credential_id = driver.credential_ref
             WHERE driver.id = ?1 AND driver.retired_at IS NULL",
        )
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<DriverRow>(None)
        .await
}

async fn load_receipt(
    database: &worker::D1Database,
    idempotency_key: &str,
) -> Result<Option<ReceiptRow>> {
    database
        .prepare(
            r"SELECT resource_id, request_sha256, validation_digest, result_json
             FROM management_mutation_receipts
             WHERE operator_subject = 'operator' AND kind = ?1 AND idempotency_key = ?2",
        )
        .bind(&[
            JsValue::from_str(DRIVER_STATE_KIND),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<ReceiptRow>(None)
        .await
}

fn replay(
    stored: ReceiptRow,
    driver_id: &str,
    request_sha256: &str,
    validation_digest: &str,
) -> Result<Response> {
    if stored.resource_id != driver_id
        || stored.request_sha256 != request_sha256
        || stored.validation_digest != validation_digest
    {
        return Response::error("idempotency key reused for different input", 409);
    }
    let mut response = Response::ok(stored.result_json)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn state_warnings(driver: &DriverRow, enabled: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    if !enabled && driver.placement_count > 0 {
        warnings.push(format!(
            "Disabling this driver removes it from {} active collection placement(s).",
            driver.placement_count
        ));
    }
    if !enabled && driver.available_location_count > 0 {
        warnings.push(format!(
            "{} available object location(s) remain recorded but unusable while disabled.",
            driver.available_location_count
        ));
    }
    warnings
}

fn valid_driver_configuration(driver: &DriverRow) -> bool {
    let structurally_valid = management_driver_registration::valid_stored_configuration(
        &driver.kind,
        &driver.config_json,
        driver.credential_present == 1,
    );
    structurally_valid
        && (driver.kind != "aliyundrive-open/v2"
            || driver.credential_refresh_state.as_deref() == Some("ready"))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validation_digest(
    env: &Env,
    driver_id: &str,
    desired: &DriverStateRequest,
    expires_at: u64,
) -> Result<String> {
    let secret = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(VALIDATION_DOMAIN);
    mac.update(driver_id.as_bytes());
    mac.update(&[0]);
    mac.update(&canonical(desired)?);
    mac.update(&expires_at.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn request_sha256(driver_id: &str, desired: &DriverStateRequest) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(VALIDATION_DOMAIN);
    hash.update(driver_id.as_bytes());
    hash.update([0]);
    hash.update(canonical(desired)?);
    Ok(lowercase_hex(&hash.finalize()))
}

fn canonical(desired: &DriverStateRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(desired).map_err(|error| json_error(&error))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (URL_SAFE_NO_PAD.decode(left), URL_SAFE_NO_PAD.decode(right))
    else {
        return false;
    };
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn no_store_json<T: Serialize>(value: &T) -> Result<Response> {
    let mut response = Response::from_json(value)?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn json_error(error: &serde_json::Error) -> worker::Error {
    worker::Error::RustError(error.to_string())
}

fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::{DriverRow, valid_driver_configuration, valid_string};

    fn local_driver(config_json: &str) -> DriverRow {
        DriverRow {
            kind: "local-filesystem/v2".to_owned(),
            config_json: config_json.to_owned(),
            credential_present: 0,
            credential_refresh_state: None,
            enabled: 0,
            revision: 1,
            placement_count: 0,
            available_location_count: 0,
        }
    }

    #[test]
    fn validates_identifiers_and_local_roots() {
        assert!(valid_string("local-main", 256));
        assert!(!valid_string(" local-main", 256));
    }

    #[test]
    fn enables_only_typed_exact_configuration() {
        assert!(valid_driver_configuration(&local_driver(
            r#"{"root":"/srv/carrack"}"#
        )));
        assert!(!valid_driver_configuration(&local_driver(
            r#"{"root":"/srv/carrack","unknown":true}"#
        )));
        let mut unknown = local_driver(r#"{"root":"/srv/carrack"}"#);
        unknown.kind = "unknown/v1".to_owned();
        assert!(!valid_driver_configuration(&unknown));

        let mut aliyun = local_driver(
            r#"{"api_base_url":"https://openapi.alipan.com","drive_type":"resource","root_folder_id":"root","upload_part_bytes":20971520}"#,
        );
        aliyun.kind = "aliyundrive-open/v2".to_owned();
        aliyun.credential_present = 1;
        assert!(!valid_driver_configuration(&aliyun));
        aliyun.credential_refresh_state = Some("ready".to_owned());
        assert!(valid_driver_configuration(&aliyun));
    }
}
