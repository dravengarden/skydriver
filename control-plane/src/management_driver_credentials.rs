use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{
    management_driver_registration, operator_sessions,
    vfs_envelopes::{ENVELOPE_ALGORITHM, MASTER_KEY_VERSION, blob_binding, seal_driver_credential},
    vfs_identifiers,
};

const ADMIN_TOKEN_BINDING: &str = "CARRACK_ADMIN_TOKEN";
const DATABASE_BINDING: &str = "CARRACK_INDEX";
const VALIDATION_LIFETIME_SECONDS: u64 = 5 * 60;
const CREDENTIAL_KIND: &str = "driver.credential";
const VALIDATION_DOMAIN: &[u8] = b"carrack.management.validation.driver-credential.v1\0";
const ALIYUN_DRIVE_KIND: &str = "aliyundrive-open/v2";
const MAXIMUM_ACCESS_TOKEN_BYTES: usize = 16 << 10;
const MAXIMUM_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AliyunCredential {
    access_token: String,
}

impl Drop for AliyunCredential {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    credential: AliyunCredential,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    credential: AliyunCredential,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct DriverRow {
    kind: String,
    config_json: String,
    credential_id: Option<String>,
    credential_revision: Option<u64>,
    revision: u64,
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
    current_credential_present: bool,
    credential_revision: u64,
    credential_expires_at: u64,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct ReceiptResponse {
    schema: &'static str,
    operation_id: String,
    driver_id: String,
    credential_id: String,
    credential_revision: u64,
    credential_expires_at: u64,
    final_revision: u64,
    rotated_at: u64,
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
    let requested = request.json::<CredentialRequest>().await?;
    let Some(credential_expires_at) = credential_expiry(&requested) else {
        return Response::error("driver credential is invalid", 400);
    };
    if credential_expires_at <= now_seconds() {
        return Response::error("driver credential is expired", 400);
    }

    let database = env.d1(DATABASE_BINDING)?;
    let Some(driver) = load_driver(&database, driver_id).await? else {
        return Response::error("driver not found", 404);
    };
    if driver.revision != requested.expected_revision {
        return Response::error("driver revision conflict", 409);
    }
    if driver.kind != ALIYUN_DRIVE_KIND
        || !management_driver_registration::valid_stored_configuration(
            &driver.kind,
            &driver.config_json,
            true,
        )
    {
        return Response::error("driver kind does not accept this credential", 400);
    }

    let validation_expires_at = now_seconds() + VALIDATION_LIFETIME_SECONDS;
    let validation_digest = validation_digest(env, driver_id, &requested, validation_expires_at)?;
    no_store_json(&ValidationResponse {
        schema: "carrack.management.driver-credential-validation.v1",
        driver_id: driver_id.to_owned(),
        kind: driver.kind,
        current_credential_present: driver.credential_id.is_some(),
        credential_revision: driver.credential_revision.unwrap_or(0) + 1,
        credential_expires_at,
        expected_revision: requested.expected_revision,
        validation_expires_at,
        validation_digest,
        warnings: vec![
            "The credential is write-only and cannot be recovered from Carrack after this request.",
            "Clients holding an earlier credential grant may retain it until that grant or provider token expires.",
        ],
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "secret sealing, CAS, receipt, audit, replay, and conflict mapping form one transaction"
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
    let desired = CredentialRequest {
        credential: requested.credential,
        expected_revision: requested.expected_revision,
    };
    let Some(credential_expires_at) = credential_expiry(&desired) else {
        return Response::error("driver credential apply is invalid", 400);
    };
    if !valid_string(&requested.idempotency_key, 256) {
        return Response::error("driver credential apply is invalid", 400);
    }

    let now = now_seconds();
    if credential_expires_at <= now {
        return Response::error("driver credential is expired", 409);
    }
    if requested.validation_expires_at < now
        || requested.validation_expires_at > now + VALIDATION_LIFETIME_SECONDS
    {
        return Response::error("validation expired", 409);
    }
    let expected_digest =
        validation_digest(env, driver_id, &desired, requested.validation_expires_at)?;
    if !constant_time_equal(&requested.validation_digest, &expected_digest) {
        return Response::error("validation digest does not match credential", 409);
    }

    let request_sha256 = request_sha256(
        driver_id,
        desired.expected_revision,
        &requested.validation_digest,
    );
    let database = env.d1(DATABASE_BINDING)?;
    if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await? {
        return replay(
            stored,
            driver_id,
            &request_sha256,
            &requested.validation_digest,
        );
    }
    let Some(driver) = load_driver(&database, driver_id).await? else {
        return Response::error("driver not found", 404);
    };
    if driver.revision != desired.expected_revision {
        return Response::error("driver revision conflict", 409);
    }
    if driver.kind != ALIYUN_DRIVE_KIND
        || !management_driver_registration::valid_stored_configuration(
            &driver.kind,
            &driver.config_json,
            true,
        )
    {
        return Response::error("driver kind does not accept this credential", 409);
    }

    let credential_id = match driver.credential_id {
        Some(value) => value,
        None => vfs_identifiers::new_uuid_v7_hex()?,
    };
    let credential_revision = driver.credential_revision.unwrap_or(0) + 1;
    let final_revision = driver.revision + 1;
    let mut plaintext =
        serde_json::to_vec(&desired.credential).map_err(|error| json_error(&error))?;
    let sealed = seal_driver_credential(env, &credential_id, credential_revision, &plaintext);
    plaintext.zeroize();
    let sealed = sealed?;
    let operation_id = vfs_identifiers::new_uuid_v7_hex()?;
    let receipt = ReceiptResponse {
        schema: "carrack.management.driver-credential-receipt.v1",
        operation_id: operation_id.clone(),
        driver_id: driver_id.to_owned(),
        credential_id: credential_id.clone(),
        credential_revision,
        credential_expires_at,
        final_revision,
        rotated_at: now,
        state: "committed",
    };
    let result_json = serde_json::to_string(&receipt).map_err(|error| json_error(&error))?;

    let credential_statement = if driver.credential_revision.is_some() {
        database
            .prepare(
                r"UPDATE credential_envelopes
                 SET envelope_algorithm = ?1, key_version = ?2, nonce = ?3,
                     ciphertext = ?4, expires_at = ?5,
                     revision = revision + 1, rotated_at = ?6
                 WHERE id = ?7 AND revision = ?8",
            )
            .bind(&[
                JsValue::from_str(ENVELOPE_ALGORITHM),
                JsValue::from_str(MASTER_KEY_VERSION),
                blob_binding(&sealed.nonce),
                blob_binding(&sealed.ciphertext),
                JsValue::from_str(&credential_expires_at.to_string()),
                JsValue::from_str(&now.to_string()),
                JsValue::from_str(&credential_id),
                JsValue::from_str(&(credential_revision - 1).to_string()),
            ])?
    } else {
        database
            .prepare(
                r"INSERT INTO credential_envelopes (
                     id, envelope_algorithm, key_version, nonce, ciphertext,
                     revision, created_at, rotated_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6, ?7)",
            )
            .bind(&[
                JsValue::from_str(&credential_id),
                JsValue::from_str(ENVELOPE_ALGORITHM),
                JsValue::from_str(MASTER_KEY_VERSION),
                blob_binding(&sealed.nonce),
                blob_binding(&sealed.ciphertext),
                JsValue::from_str(&now.to_string()),
                JsValue::from_str(&credential_expires_at.to_string()),
            ])?
    };

    let mutation = database
        .batch(vec![
            credential_statement,
            database
                .prepare(
                    r"UPDATE driver_instances
                     SET credential_ref = ?1, revision = revision + 1, updated_at = ?2
                     WHERE id = ?3 AND revision = ?4",
                )
                .bind(&[
                    JsValue::from_str(&credential_id),
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(driver_id),
                    JsValue::from_str(&driver.revision.to_string()),
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
                    JsValue::from_str(CREDENTIAL_KIND),
                    JsValue::from_str(driver_id),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_sha256),
                    JsValue::from_str(&driver.revision.to_string()),
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
                               json_object('credential_revision', ?3,
                                           'final_revision', ?4, 'source', 'operator'), ?5)",
                )
                .bind(&[
                    JsValue::from_str(CREDENTIAL_KIND),
                    JsValue::from_str(driver_id),
                    JsValue::from_str(&credential_revision.to_string()),
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
            "driver credential mutation failed: {error}"
        )));
    }

    no_store_json(&receipt)
}

async fn load_driver(database: &worker::D1Database, driver_id: &str) -> Result<Option<DriverRow>> {
    database
        .prepare(
            r"SELECT driver.kind, driver.config_json,
                    credential.id AS credential_id,
                    credential.revision AS credential_revision,
                    driver.revision
             FROM driver_instances AS driver
             LEFT JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             WHERE driver.id = ?1",
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
            JsValue::from_str(CREDENTIAL_KIND),
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

fn credential_expiry(requested: &CredentialRequest) -> Option<u64> {
    let token = &requested.credential.access_token;
    if requested.expected_revision == 0
        || token.is_empty()
        || token.len() > MAXIMUM_ACCESS_TOKEN_BYTES
        || token.chars().any(char::is_control)
    {
        return None;
    }
    let mut segments = token.split('.');
    let header = segments.next()?;
    let payload = segments.next()?;
    let signature = segments.next()?;
    if header.is_empty() || payload.is_empty() || signature.is_empty() || segments.next().is_some()
    {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()?
        .get("exp")?
        .as_u64()
        .filter(|expires_at| (1..=MAXIMUM_JSON_INTEGER).contains(expires_at))
}

fn validation_digest(
    env: &Env,
    driver_id: &str,
    requested: &CredentialRequest,
    expires_at: u64,
) -> Result<String> {
    let secret = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(VALIDATION_DOMAIN);
    mac.update(driver_id.as_bytes());
    mac.update(&[0]);
    mac.update(&serde_json::to_vec(requested).map_err(|error| json_error(&error))?);
    mac.update(&expires_at.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn request_sha256(driver_id: &str, expected_revision: u64, validation_digest: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(VALIDATION_DOMAIN);
    hash.update(driver_id.as_bytes());
    hash.update([0]);
    hash.update(expected_revision.to_be_bytes());
    hash.update(validation_digest.as_bytes());
    lowercase_hex(&hash.finalize())
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{AliyunCredential, CredentialRequest, credential_expiry, request_sha256};

    fn access_token(expires_at: u64) -> String {
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{expires_at}}}"#));
        format!("e30.{payload}.c2ln")
    }

    #[test]
    fn validates_bounded_access_tokens_and_extracts_expiry() {
        assert_eq!(
            credential_expiry(&CredentialRequest {
                credential: AliyunCredential {
                    access_token: access_token(2_000_000_000),
                },
                expected_revision: 1,
            }),
            Some(2_000_000_000)
        );
        assert_eq!(
            credential_expiry(&CredentialRequest {
                credential: AliyunCredential {
                    access_token: "line\nbreak".to_owned(),
                },
                expected_revision: 1,
            }),
            None
        );
        assert_eq!(
            credential_expiry(&CredentialRequest {
                credential: AliyunCredential {
                    access_token: "e30.e30.".to_owned(),
                },
                expected_revision: 1,
            }),
            None
        );
    }

    #[test]
    fn durable_request_identity_uses_server_digest_not_plaintext() {
        let identity = request_sha256("aliyun-main", 1, "server-hmac");
        assert_eq!(identity.len(), 64);
        assert!(!identity.contains("server-hmac"));
    }
}
