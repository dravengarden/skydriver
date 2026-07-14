use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{operator_sessions, vfs_identifiers};

const VALIDATION_LIFETIME_SECONDS: u64 = 300;
const VALIDATION_DOMAIN: &[u8] = b"carrack.management.validation.quota.v1\0";
const MAXIMUM_INTEGER: u64 = 9_007_199_254_740_991;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_field_names,
    reason = "wire names distinguish hard-limit dimensions"
)]
struct Limits {
    max_file_bytes: Option<u64>,
    max_logical_bytes: Option<u64>,
    max_file_count: Option<u64>,
    max_physical_bytes: Option<u64>,
    max_object_count: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidationRequest {
    limits: Limits,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    limits: Limits,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct PolicyRow {
    max_file_bytes: Option<u64>,
    max_logical_bytes: Option<u64>,
    max_file_count: Option<u64>,
    max_physical_bytes: Option<u64>,
    max_object_count: Option<u64>,
    revision: u64,
}

#[derive(Deserialize)]
struct StoredReceipt {
    resource_id: String,
    request_sha256: String,
    validation_digest: String,
    result_json: String,
}

#[derive(Serialize)]
struct ValidationResponse {
    schema: &'static str,
    scope: String,
    resource_id: String,
    current_limits: Limits,
    limits: Limits,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct Receipt {
    schema: &'static str,
    operation_id: String,
    scope: String,
    resource_id: String,
    #[serde(flatten)]
    limits: Limits,
    final_revision: u64,
    committed_at: u64,
    state: &'static str,
}

pub(crate) async fn validate(
    request: &mut Request,
    env: &Env,
    scope: Option<&str>,
    resource_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let Some((scope, resource_id)) = target(scope, resource_id) else {
        return Response::error("valid quota scope and resource ID are required", 400);
    };
    let desired = request.json::<ValidationRequest>().await?;
    if desired.expected_revision == 0 || !valid_limits(scope, &desired.limits) {
        return Response::error("quota policy is invalid", 400);
    }
    let database = env.d1("CARRACK_INDEX")?;
    let Some(current) = load_policy(&database, scope, resource_id).await? else {
        return Response::error("quota resource was not found", 404);
    };
    if current.revision != desired.expected_revision {
        return Response::error("quota policy revision conflict", 409);
    }
    let expires_at = now() + VALIDATION_LIFETIME_SECONDS;
    json(&ValidationResponse {
        schema: "carrack.management.quota-validation.v1",
        scope: scope.to_owned(),
        resource_id: resource_id.to_owned(),
        current_limits: current.limits(),
        validation_digest: digest(env, scope, resource_id, &desired, expires_at)?,
        limits: desired.limits,
        expected_revision: desired.expected_revision,
        validation_expires_at: expires_at,
        warnings: vec![
            "Lower limits do not delete data; new reservations fail until usage is below the hard limit.",
        ],
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "quota CAS, receipt, and audit are one atomic protocol"
)]
pub(crate) async fn apply(
    request: &mut Request,
    env: &Env,
    scope: Option<&str>,
    resource_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::configuration_authorized(request, env).await? {
        return Response::error("configuration session required", 403);
    }
    let Some((scope, resource_id)) = target(scope, resource_id) else {
        return Response::error("valid quota scope and resource ID are required", 400);
    };
    let requested = request.json::<ApplyRequest>().await?;
    if requested.expected_revision == 0
        || !valid_limits(scope, &requested.limits)
        || !valid_text(&requested.idempotency_key, 256)
    {
        return Response::error("quota mutation is invalid", 400);
    }
    let current_time = now();
    if requested.validation_expires_at < current_time
        || requested.validation_expires_at > current_time + VALIDATION_LIFETIME_SECONDS
    {
        return Response::error("validation expired", 409);
    }
    let desired = ValidationRequest {
        limits: requested.limits.clone(),
        expected_revision: requested.expected_revision,
    };
    let wanted_digest = digest(
        env,
        scope,
        resource_id,
        &desired,
        requested.validation_expires_at,
    )?;
    if !constant_time_equal(&requested.validation_digest, &wanted_digest) {
        return Response::error("validation digest does not match quota policy", 409);
    }
    let kind = format!("{scope}.quota");
    let request_hash = request_hash(scope, resource_id, &desired)?;
    let database = env.d1("CARRACK_INDEX")?;
    if let Some(stored) = load_receipt(&database, &kind, &requested.idempotency_key).await? {
        if stored.resource_id != resource_id
            || stored.request_sha256 != request_hash
            || stored.validation_digest != requested.validation_digest
        {
            return Response::error("idempotency key reused for different input", 409);
        }
        return raw_json(stored.result_json);
    }
    let Some(current) = load_policy(&database, scope, resource_id).await? else {
        return Response::error("quota resource was not found", 404);
    };
    if current.revision != requested.expected_revision {
        return Response::error("quota policy revision conflict", 409);
    }

    let operation_id = vfs_identifiers::new_uuid_v7_hex()?;
    let receipt = Receipt {
        schema: "carrack.management.quota-receipt.v1",
        operation_id: operation_id.clone(),
        scope: scope.to_owned(),
        resource_id: resource_id.to_owned(),
        limits: requested.limits,
        final_revision: requested.expected_revision + 1,
        committed_at: current_time,
        state: "committed",
    };
    let result_json = serde_json::to_string(&receipt).map_err(|error| json_error(&error))?;
    let update = policy_update(
        &database,
        scope,
        resource_id,
        &receipt.limits,
        requested.expected_revision,
        current_time,
    )?;
    database
        .batch(vec![
            update,
            database
                .prepare(
                    "INSERT INTO management_mutation_receipts (
                         operation_id, operator_subject, kind, resource_id, idempotency_key,
                         request_sha256, expected_revision, final_revision, validation_digest,
                         result_json, committed_at
                     ) VALUES (?1, 'operator', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .bind(&[
                    JsValue::from_str(&operation_id),
                    JsValue::from_str(&kind),
                    JsValue::from_str(resource_id),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_hash),
                    number(requested.expected_revision),
                    number(receipt.final_revision),
                    JsValue::from_str(&requested.validation_digest),
                    JsValue::from_str(&result_json),
                    number(current_time),
                ])?,
            database
                .prepare(
                    "INSERT INTO vfs_audit_events (
                         filesystem_id, principal_id, token_id, event_kind, subject_kind,
                         subject_id, details_json, created_at
                     ) VALUES (NULL, NULL, NULL, ?1, ?2, ?3,
                               json_object('final_revision', ?4, 'source', 'operator'), ?5)",
                )
                .bind(&[
                    JsValue::from_str(&kind),
                    JsValue::from_str(scope),
                    JsValue::from_str(resource_id),
                    number(receipt.final_revision),
                    number(current_time),
                ])?,
        ])
        .await?;
    json(&receipt)
}

impl PolicyRow {
    fn limits(&self) -> Limits {
        Limits {
            max_file_bytes: self.max_file_bytes,
            max_logical_bytes: self.max_logical_bytes,
            max_file_count: self.max_file_count,
            max_physical_bytes: self.max_physical_bytes,
            max_object_count: self.max_object_count,
        }
    }
}

async fn load_policy(
    database: &worker::D1Database,
    scope: &str,
    resource_id: &str,
) -> Result<Option<PolicyRow>> {
    let sql = if scope == "directory" {
        "SELECT max_file_bytes, max_logical_bytes, max_file_count,
                NULL AS max_physical_bytes, NULL AS max_object_count, revision
         FROM vfs_directory_quota_policies WHERE directory_id = ?1"
    } else {
        "SELECT NULL AS max_file_bytes, NULL AS max_logical_bytes, NULL AS max_file_count,
                max_physical_bytes, max_object_count, revision
         FROM driver_quota_policies WHERE driver_id = ?1"
    };
    database
        .prepare(sql)
        .bind(&[JsValue::from_str(resource_id)])?
        .first::<PolicyRow>(None)
        .await
}

fn policy_update(
    database: &worker::D1Database,
    scope: &str,
    resource_id: &str,
    limits: &Limits,
    revision: u64,
    current_time: u64,
) -> Result<worker::D1PreparedStatement> {
    if scope == "directory" {
        return database
            .prepare(
                "UPDATE vfs_directory_quota_policies
                 SET max_file_bytes = ?1, max_logical_bytes = ?2, max_file_count = ?3,
                     revision = revision + 1, updated_at = ?4
                 WHERE directory_id = ?5 AND revision = ?6",
            )
            .bind(&[
                optional_number(limits.max_file_bytes),
                optional_number(limits.max_logical_bytes),
                optional_number(limits.max_file_count),
                number(current_time),
                JsValue::from_str(resource_id),
                number(revision),
            ]);
    }
    database
        .prepare(
            "UPDATE driver_quota_policies
             SET max_physical_bytes = ?1, max_object_count = ?2,
                 revision = revision + 1, updated_at = ?3
             WHERE driver_id = ?4 AND revision = ?5",
        )
        .bind(&[
            optional_number(limits.max_physical_bytes),
            optional_number(limits.max_object_count),
            number(current_time),
            JsValue::from_str(resource_id),
            number(revision),
        ])
}

async fn load_receipt(
    database: &worker::D1Database,
    kind: &str,
    key: &str,
) -> Result<Option<StoredReceipt>> {
    database
        .prepare(
            "SELECT resource_id, request_sha256, validation_digest, result_json
             FROM management_mutation_receipts
             WHERE operator_subject = 'operator' AND kind = ?1 AND idempotency_key = ?2",
        )
        .bind(&[JsValue::from_str(kind), JsValue::from_str(key)])?
        .first::<StoredReceipt>(None)
        .await
}

fn target<'a>(scope: Option<&'a str>, id: Option<&'a str>) -> Option<(&'a str, &'a str)> {
    let scope = scope.filter(|value| matches!(*value, "directory" | "driver"))?;
    let id = id.filter(|value| {
        if scope == "directory" {
            value.len() == 32
                && *value != "00000000000000000000000000000000"
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        } else {
            valid_text(value, 256)
        }
    })?;
    Some((scope, id))
}

fn valid_limits(scope: &str, limits: &Limits) -> bool {
    if [
        limits.max_file_bytes,
        limits.max_logical_bytes,
        limits.max_file_count,
        limits.max_physical_bytes,
        limits.max_object_count,
    ]
    .into_iter()
    .flatten()
    .any(|value| value == 0 || value > MAXIMUM_INTEGER)
    {
        return false;
    }
    if scope == "directory" {
        limits.max_physical_bytes.is_none() && limits.max_object_count.is_none()
    } else {
        limits.max_file_bytes.is_none()
            && limits.max_logical_bytes.is_none()
            && limits.max_file_count.is_none()
    }
}

fn digest(
    env: &Env,
    scope: &str,
    id: &str,
    desired: &ValidationRequest,
    expires_at: u64,
) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(env.secret("CARRACK_ADMIN_TOKEN")?.to_string().as_bytes())
            .map_err(|error| worker::Error::RustError(error.to_string()))?;
    update_identity(&mut mac, scope, id, desired)?;
    mac.update(&expires_at.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn request_hash(scope: &str, id: &str, desired: &ValidationRequest) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(VALIDATION_DOMAIN);
    hash.update(scope.as_bytes());
    hash.update([0]);
    hash.update(id.as_bytes());
    hash.update([0]);
    hash.update(serde_json::to_vec(desired).map_err(|error| json_error(&error))?);
    Ok(lowercase_hex(&hash.finalize()))
}

fn update_identity(
    mac: &mut HmacSha256,
    scope: &str,
    id: &str,
    desired: &ValidationRequest,
) -> Result<()> {
    mac.update(VALIDATION_DOMAIN);
    mac.update(scope.as_bytes());
    mac.update(&[0]);
    mac.update(id.as_bytes());
    mac.update(&[0]);
    mac.update(&serde_json::to_vec(desired).map_err(|error| json_error(&error))?);
    Ok(())
}

fn number(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

fn optional_number(value: Option<u64>) -> JsValue {
    value.map_or_else(JsValue::null, number)
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.trim() == value && !value.contains('\0')
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn json<T: Serialize>(value: &T) -> Result<Response> {
    raw_json(serde_json::to_string(value).map_err(|error| json_error(&error))?)
}

fn raw_json(body: String) -> Result<Response> {
    let mut response = Response::ok(body)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn now() -> u64 {
    Date::now().as_millis() / 1_000
}

fn json_error(error: &serde_json::Error) -> worker::Error {
    worker::Error::RustError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{Limits, valid_limits};

    #[test]
    fn quota_dimensions_are_scope_exact_and_safely_bounded() {
        let directory = Limits {
            max_file_bytes: Some(1),
            max_logical_bytes: Some(2),
            max_file_count: Some(3),
            max_physical_bytes: None,
            max_object_count: None,
        };
        assert!(valid_limits("directory", &directory));
        assert!(!valid_limits("driver", &directory));

        let driver = Limits {
            max_file_bytes: None,
            max_logical_bytes: None,
            max_file_count: None,
            max_physical_bytes: Some(4),
            max_object_count: Some(5),
        };
        assert!(valid_limits("driver", &driver));
        assert!(!valid_limits("directory", &driver));

        assert!(!valid_limits(
            "driver",
            &Limits {
                max_physical_bytes: Some(0),
                ..driver
            }
        ));
    }
}
