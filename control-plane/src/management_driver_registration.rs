use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use skydriver_driver_contract::{CredentialPosture, DriverKind};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{driver_configuration, operator_sessions, vfs_identifiers};

const ADMIN_TOKEN_BINDING: &str = "SKYDRIVER_ADMIN_TOKEN";
const DATABASE_BINDING: &str = "SKYDRIVER_INDEX";
const VALIDATION_LIFETIME_SECONDS: u64 = 5 * 60;
const REGISTRATION_KIND: &str = "driver.register";
const VALIDATION_DOMAIN: &[u8] = b"skydriver.management.validation.driver-registration.v1\0";
#[cfg(test)]
const ALIYUN_DRIVE_KIND: &str = DriverKind::AliyunDriveOpenV2.as_str();
#[cfg(test)]
const R2_KIND: &str = DriverKind::R2V1.as_str();
#[cfg(test)]
const AWS_S3_KIND: &str = DriverKind::AwsS3V1.as_str();

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationRequest {
    driver_id: String,
    kind: String,
    config: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    driver_id: String,
    kind: String,
    config: Value,
    validation_expires_at: u64,
    validation_digest: String,
    idempotency_key: String,
}

#[derive(Serialize)]
struct CanonicalRegistration<'a> {
    driver_id: &'a str,
    kind: &'a str,
    config: &'a Value,
}

#[derive(Serialize)]
struct ValidationResponse {
    schema: &'static str,
    driver_id: String,
    kind: String,
    config: Value,
    enabled: bool,
    expected_revision: u64,
    requires_credential: bool,
    validation_expires_at: u64,
    validation_digest: String,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct ReceiptResponse {
    schema: &'static str,
    operation_id: String,
    driver_id: String,
    kind: String,
    config: Value,
    enabled: bool,
    final_revision: u64,
    committed_at: u64,
    state: &'static str,
}

#[derive(Deserialize)]
struct ReceiptRow {
    resource_id: String,
    request_sha256: String,
    validation_digest: String,
    result_json: String,
}

pub(crate) async fn validate(request: &mut Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    let requested = request.json::<RegistrationRequest>().await?;
    let Ok(normalized) = normalize_registration(requested) else {
        return Response::error("driver registration is invalid", 400);
    };
    if !valid_environment_registration(&normalized, env)? {
        return Response::error("driver registration does not match this environment", 400);
    }
    let database = env.d1(DATABASE_BINDING)?;
    if driver_exists(&database, &normalized.driver_id).await? {
        return Response::error("driver already exists", 409);
    }

    let validation_expires_at = now_seconds() + VALIDATION_LIFETIME_SECONDS;
    let validation_digest = validation_digest(env, &normalized, validation_expires_at)?;
    no_store_json(&ValidationResponse {
        schema: "skydriver.management.driver-registration-validation.v1",
        requires_credential: DriverKind::parse(&normalized.kind)
            .is_some_and(|kind| kind.credential_posture() == CredentialPosture::Required),
        warnings: registration_warnings(&normalized.kind),
        driver_id: normalized.driver_id,
        kind: normalized.kind,
        config: normalized.config,
        enabled: false,
        expected_revision: 0,
        validation_expires_at,
        validation_digest,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "signed registration, immutable receipt, audit, replay, and race mapping form one transaction"
)]
pub(crate) async fn apply(request: &mut Request, env: &Env) -> Result<Response> {
    if !operator_sessions::configuration_authorized(request, env).await? {
        return Response::error("configuration session required", 403);
    }

    let requested = request.json::<ApplyRequest>().await?;
    if !valid_string(&requested.idempotency_key, 256) {
        return Response::error("valid idempotency key is required", 400);
    }
    let Ok(normalized) = normalize_registration(RegistrationRequest {
        driver_id: requested.driver_id,
        kind: requested.kind,
        config: requested.config,
    }) else {
        return Response::error("driver registration is invalid", 400);
    };
    if !valid_environment_registration(&normalized, env)? {
        return Response::error("driver registration does not match this environment", 400);
    }
    let now = now_seconds();
    if requested.validation_expires_at < now
        || requested.validation_expires_at > now + VALIDATION_LIFETIME_SECONDS
    {
        return Response::error("validation expired", 409);
    }
    let expected_digest = validation_digest(env, &normalized, requested.validation_expires_at)?;
    if !constant_time_equal(&requested.validation_digest, &expected_digest) {
        return Response::error("validation digest does not match driver registration", 409);
    }

    let request_sha256 = request_sha256(&normalized)?;
    let database = env.d1(DATABASE_BINDING)?;
    if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
        return replay(
            stored,
            &normalized.driver_id,
            &request_sha256,
            &requested.validation_digest,
        );
    }
    if driver_exists(&database, &normalized.driver_id).await? {
        return Response::error("driver already exists", 409);
    }

    let operation_id = vfs_identifiers::new_uuid_v7_hex()?;
    let config_json =
        serde_json::to_string(&normalized.config).map_err(|error| json_error(&error))?;
    let receipt = ReceiptResponse {
        schema: "skydriver.management.driver-registration-receipt.v1",
        operation_id: operation_id.clone(),
        driver_id: normalized.driver_id.clone(),
        kind: normalized.kind.clone(),
        config: normalized.config,
        enabled: false,
        final_revision: 1,
        committed_at: now,
        state: "committed",
    };
    let result_json = serde_json::to_string(&receipt).map_err(|error| json_error(&error))?;
    let mutation = database
        .batch(vec![
            database
                .prepare(
                    r"INSERT INTO driver_instances (
                         id, kind, config_json, credential_ref, enabled, revision,
                         created_at, updated_at
                     ) VALUES (?1, ?2, ?3, NULL, 0, 1, ?4, ?4)",
                )
                .bind(&[
                    JsValue::from_str(&receipt.driver_id),
                    JsValue::from_str(&receipt.kind),
                    JsValue::from_str(&config_json),
                    JsValue::from_str(&now.to_string()),
                ])?,
            database
                .prepare(
                    r"INSERT INTO management_creation_receipts (
                         operation_id, operator_subject, kind, resource_id, idempotency_key,
                         request_sha256, final_revision, validation_digest,
                         result_json, committed_at
                     ) VALUES (?1, 'operator', ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8)",
                )
                .bind(&[
                    JsValue::from_str(&operation_id),
                    JsValue::from_str(REGISTRATION_KIND),
                    JsValue::from_str(&receipt.driver_id),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_sha256),
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
                               json_object('kind', ?3, 'enabled', 0,
                                           'final_revision', 1, 'source', 'operator'), ?4)",
                )
                .bind(&[
                    JsValue::from_str(REGISTRATION_KIND),
                    JsValue::from_str(&receipt.driver_id),
                    JsValue::from_str(&receipt.kind),
                    JsValue::from_str(&now.to_string()),
                ])?,
        ])
        .await;
    if let Err(error) = mutation {
        if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
            return replay(
                stored,
                &receipt.driver_id,
                &request_sha256,
                &requested.validation_digest,
            );
        }
        if driver_exists(&database, &receipt.driver_id).await? {
            return Response::error("driver already exists", 409);
        }
        return Err(worker::Error::RustError(format!(
            "driver registration failed: {error}"
        )));
    }

    no_store_json(&receipt)
}

fn normalize_registration(requested: RegistrationRequest) -> Result<RegistrationRequest> {
    if !valid_string(&requested.driver_id, 256) || !valid_string(&requested.kind, 128) {
        return Err(worker::Error::RustError(
            "valid driver ID and kind are required".to_owned(),
        ));
    }

    let kind = DriverKind::parse(&requested.kind).ok_or_else(|| {
        worker::Error::RustError("driver kind is not compiled by this Skydriver release".to_owned())
    })?;
    let config = driver_configuration::normalize(kind, requested.config)?;

    Ok(RegistrationRequest {
        config,
        ..requested
    })
}

fn valid_environment_registration(request: &RegistrationRequest, _env: &Env) -> Result<bool> {
    let kind = DriverKind::parse(&request.kind).ok_or_else(|| {
        worker::Error::RustError("driver kind is not compiled by this Skydriver release".to_owned())
    })?;
    driver_configuration::operator_registration_allowed(kind, &request.config)
}

fn registration_warnings(kind: &str) -> Vec<String> {
    match DriverKind::parse(kind) {
        Some(DriverKind::R2V1) => vec![
            "The driver is registered disabled and requires a write-only R2 access-key credential before enablement."
                .to_owned(),
            "Payload bytes transfer directly between the client and R2 through short-lived object-scoped signed URLs; long-lived keys never leave the control plane."
                .to_owned(),
            "Complete-object upload uses streaming single PUT below 100 MiB and a resumable concurrent multipart journal above it; download uses concurrent signed ranges when requested."
                .to_owned(),
        ],
        Some(DriverKind::AwsS3V1) => vec![
            "The driver is registered disabled and requires a write-only AWS IAM access-key credential before enablement."
                .to_owned(),
            "Skydriver accepts only an official regional AWS S3 endpoint, signs the expected bucket owner into every request, and rejects versioned or versioning-suspended buckets."
                .to_owned(),
            "Payload bytes transfer directly between clients and S3 through short-lived object-scoped SigV4 URLs; publication and deletion are conditional and complete readback verifies encoded SHA-256."
                .to_owned(),
        ],
        Some(DriverKind::AliyunDriveOpenV2) => vec![
            "The driver is registered disabled and requires a write-only access-token credential before enablement."
                .to_owned(),
            "Aliyun Drive uses native complete-object multipart upload and exact range readback; upload concurrency is intentionally one until provider canaries justify more."
                .to_owned(),
            "Physical deletion is delayed and performed only by the control plane after reachability, grace, read-lease, identity, and driver-revision fences; bounded provider inventory quarantines unknown objects without adopting or deleting them."
                .to_owned(),
        ],
        Some(DriverKind::LocalFilesystemV2) | None => {
            vec!["The driver is registered disabled and must be enabled separately.".to_owned()]
        }
    }
}

async fn driver_exists(database: &worker::D1Database, driver_id: &str) -> Result<bool> {
    Ok(database
        .prepare("SELECT 1 AS present FROM driver_instances WHERE id = ?1")
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<Value>(None)
        .await?
        .is_some())
}

async fn load_receipt(
    database: &worker::D1Database,
    idempotency_key: &str,
) -> Result<Option<ReceiptRow>> {
    database
        .prepare(
            r"SELECT resource_id, request_sha256, validation_digest, result_json
             FROM management_creation_receipts
             WHERE operator_subject = 'operator' AND kind = ?1 AND idempotency_key = ?2",
        )
        .bind(&[
            JsValue::from_str(REGISTRATION_KIND),
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

fn validation_digest(
    env: &Env,
    requested: &RegistrationRequest,
    expires_at: u64,
) -> Result<String> {
    let secret = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(VALIDATION_DOMAIN);
    mac.update(&canonical(requested)?);
    mac.update(&expires_at.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn request_sha256(requested: &RegistrationRequest) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(VALIDATION_DOMAIN);
    hash.update(canonical(requested)?);
    Ok(lowercase_hex(&hash.finalize()))
}

fn canonical(requested: &RegistrationRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(&CanonicalRegistration {
        driver_id: &requested.driver_id,
        kind: &requested.kind,
        config: &requested.config,
    })
    .map_err(|error| json_error(&error))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
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
    use serde_json::json;

    use super::{
        ALIYUN_DRIVE_KIND, AWS_S3_KIND, R2_KIND, RegistrationRequest, driver_configuration,
        normalize_registration,
    };

    #[test]
    fn normalizes_exact_aliyun_defaults() {
        let normalized = normalize_registration(RegistrationRequest {
            driver_id: "aliyun-main".to_owned(),
            kind: ALIYUN_DRIVE_KIND.to_owned(),
            config: json!({}),
        })
        .expect("normalize Aliyun registration");

        assert_eq!(normalized.config["drive_type"], "resource");
        assert_eq!(normalized.config["root_folder_id"], "root");
        assert_eq!(normalized.config["upload_part_bytes"], 20 << 20);
    }

    #[test]
    fn rejects_unknown_kinds_and_fields() {
        for (kind, config) in [
            ("unknown/v1", json!({})),
            (ALIYUN_DRIVE_KIND, json!({"access_token": "secret"})),
        ] {
            assert!(
                normalize_registration(RegistrationRequest {
                    driver_id: "driver".to_owned(),
                    kind: kind.to_owned(),
                    config,
                })
                .is_err()
            );
        }
    }

    #[test]
    fn enablement_requires_kind_specific_credential_posture() {
        assert!(driver_configuration::valid_stored(
            ALIYUN_DRIVE_KIND,
            r#"{"api_base_url":"https://openapi.alipan.com","drive_type":"resource","root_folder_id":"root","upload_part_bytes":20971520}"#,
            true,
        ));
        assert!(!driver_configuration::valid_stored(
            ALIYUN_DRIVE_KIND,
            r#"{"api_base_url":"https://openapi.alipan.com","drive_type":"resource","root_folder_id":"root","upload_part_bytes":20971520}"#,
            false,
        ));
        let r2 = r#"{"endpoint":"https://0123456789abcdef.r2.cloudflarestorage.com","bucket":"skydriver-payload-dev","prefix":"","managed":true}"#;
        assert!(driver_configuration::valid_stored(R2_KIND, r2, true));
        assert!(!driver_configuration::valid_stored(R2_KIND, r2, false));
    }

    #[test]
    fn normalizes_strict_r2_configuration() {
        let normalized = normalize_registration(RegistrationRequest {
            driver_id: "r2-default".to_owned(),
            kind: R2_KIND.to_owned(),
            config: json!({
                "endpoint": "https://0123456789abcdef.r2.cloudflarestorage.com",
                "bucket": "skydriver-payload-dev",
                "managed": true
            }),
        })
        .expect("normalize R2 registration");
        assert_eq!(normalized.config["prefix"], "");
        assert_eq!(normalized.config["managed"], true);
    }

    #[test]
    fn normalizes_strict_aws_s3_configuration() {
        let normalized = normalize_registration(RegistrationRequest {
            driver_id: "s3-main".to_owned(),
            kind: AWS_S3_KIND.to_owned(),
            config: json!({
                "region": "us-east-1",
                "bucket": "skydriver-payload-example",
                "expected_bucket_owner": "123456789012"
            }),
        })
        .expect("normalize AWS S3 registration");
        assert_eq!(normalized.config["prefix"], "");
        assert!(
            normalize_registration(RegistrationRequest {
                driver_id: "s3-unsafe".to_owned(),
                kind: AWS_S3_KIND.to_owned(),
                config: json!({
                    "region": "us-east-1",
                    "bucket": "skydriver-payload-example",
                    "expected_bucket_owner": "123456789012",
                    "endpoint": "https://attacker.example"
                }),
            })
            .is_err()
        );
    }
}
