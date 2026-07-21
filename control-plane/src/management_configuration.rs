use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{operator_sessions, vfs_identifiers};

const ADMIN_TOKEN_BINDING: &str = "SKYDRIVER_ADMIN_TOKEN";
const DATABASE_BINDING: &str = "SKYDRIVER_INDEX";
const VALIDATION_LIFETIME_SECONDS: u64 = 5 * 60;
const ANNOTATION_KIND: &str = "token.annotation";
const VALIDATION_DOMAIN: &[u8] = b"carrack.management.validation.token-annotation.v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidateTokenAnnotationRequest {
    label: String,
    note: String,
    expected_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyTokenAnnotationRequest {
    label: String,
    note: String,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
struct TokenMetadataRow {
    label: String,
    note: String,
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
struct TokenAnnotationValidation {
    schema: &'static str,
    token_id: String,
    current_label: String,
    current_note: String,
    label: String,
    note: String,
    expected_revision: u64,
    validation_expires_at: u64,
    validation_digest: String,
    warnings: Vec<String>,
}

#[derive(Serialize)]
struct TokenAnnotationReceipt {
    schema: &'static str,
    operation_id: String,
    token_id: String,
    label: String,
    note: String,
    final_revision: u64,
    committed_at: u64,
    state: &'static str,
}

pub(crate) async fn validate_token_annotation(
    request: &mut Request,
    env: &Env,
    token_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let Some(token_id) = token_id.filter(|value| valid_identifier(value)) else {
        return Response::error("valid token ID is required", 400);
    };
    let requested = request.json::<ValidateTokenAnnotationRequest>().await?;
    let Ok(normalized) = normalize_annotation(&requested) else {
        return Response::error("invalid token annotation", 400);
    };
    let database = env.d1(DATABASE_BINDING)?;
    let Some(current) = load_metadata(&database, token_id).await? else {
        return Response::error("token not found", 404);
    };
    if current.revision != normalized.expected_revision {
        return Response::error("token metadata revision conflict", 409);
    }

    let validation_expires_at = now_seconds() + VALIDATION_LIFETIME_SECONDS;
    let digest = validation_digest(env, token_id, &normalized, validation_expires_at)?;
    no_store_json(&TokenAnnotationValidation {
        schema: "carrack.management.token-annotation-validation.v1",
        token_id: token_id.to_owned(),
        current_label: current.label,
        current_note: current.note,
        label: normalized.label,
        note: normalized.note,
        expected_revision: normalized.expected_revision,
        validation_expires_at,
        validation_digest: digest,
        warnings: Vec::new(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "apply keeps validation, exact replay, optimistic mutation, receipt, and audit atomic"
)]
pub(crate) async fn apply_token_annotation(
    request: &mut Request,
    env: &Env,
    token_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::configuration_authorized(request, env).await? {
        return Response::error("configuration session required", 403);
    }
    let Some(token_id) = token_id.filter(|value| valid_identifier(value)) else {
        return Response::error("valid token ID is required", 400);
    };
    let requested = request.json::<ApplyTokenAnnotationRequest>().await?;
    if !valid_idempotency_key(&requested.idempotency_key) {
        return Response::error("invalid idempotency key", 400);
    }
    let Ok(normalized) = normalize_annotation(&ValidateTokenAnnotationRequest {
        label: requested.label,
        note: requested.note,
        expected_revision: requested.expected_revision,
    }) else {
        return Response::error("invalid token annotation", 400);
    };
    let now = now_seconds();
    if requested.validation_expires_at < now
        || requested.validation_expires_at > now + VALIDATION_LIFETIME_SECONDS
    {
        return Response::error("validation expired", 409);
    }
    let expected_digest =
        validation_digest(env, token_id, &normalized, requested.validation_expires_at)?;
    if !constant_time_equal(&requested.validation_digest, &expected_digest) {
        return Response::error("validation digest does not match desired state", 409);
    }
    let request_sha256 = request_sha256(token_id, &normalized)?;
    let database = env.d1(DATABASE_BINDING)?;
    if let Some(receipt) = load_receipt(&database, &requested.idempotency_key).await? {
        if receipt.resource_id != token_id
            || receipt.request_sha256 != request_sha256
            || receipt.validation_digest != requested.validation_digest
        {
            return Response::error("idempotency key reused for different input", 409);
        }
        let mut response = Response::ok(receipt.result_json)?;
        response
            .headers_mut()
            .set("Content-Type", "application/json")?;
        response
            .headers_mut()
            .set("Cache-Control", "no-store, max-age=0")?;
        return Ok(response);
    }
    let Some(current) = load_metadata(&database, token_id).await? else {
        return Response::error("token not found", 404);
    };
    if current.revision != normalized.expected_revision {
        return Response::error("token metadata revision conflict", 409);
    }

    let operation_id = vfs_identifiers::new_uuid_v7_hex()?;
    let final_revision = normalized.expected_revision + 1;
    let receipt = TokenAnnotationReceipt {
        schema: "carrack.management.token-annotation-receipt.v1",
        operation_id: operation_id.clone(),
        token_id: token_id.to_owned(),
        label: normalized.label.clone(),
        note: normalized.note.clone(),
        final_revision,
        committed_at: now,
        state: "committed",
    };
    let result_json = serde_json::to_string(&receipt).map_err(|error| json_error(&error))?;
    let note_sha256 = lowercase_hex(&Sha256::digest(normalized.note.as_bytes()));
    let mutation = database
        .batch(vec![
            database
                .prepare(
                    r"UPDATE vfs_token_metadata SET label = ?1, note = ?2,
                         revision = revision + 1, updated_by = 'operator', updated_at = ?3
                     WHERE token_id = ?4 AND revision = ?5",
                )
                .bind(&[
                    JsValue::from_str(&normalized.label),
                    JsValue::from_str(&normalized.note),
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(token_id),
                    JsValue::from_str(&normalized.expected_revision.to_string()),
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
                    JsValue::from_str(ANNOTATION_KIND),
                    JsValue::from_str(token_id),
                    JsValue::from_str(&requested.idempotency_key),
                    JsValue::from_str(&request_sha256),
                    JsValue::from_str(&normalized.expected_revision.to_string()),
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
                     ) SELECT directory.filesystem_id, NULL, NULL, ?1, 'token', token.id,
                              json_object('label', ?2, 'note_sha256', ?3,
                                          'final_revision', ?4, 'source', 'operator'), ?5
                       FROM vfs_token_verifiers AS token
                       JOIN vfs_directories AS directory ON directory.id = token.root_directory_id
                       WHERE token.id = ?6",
                )
                .bind(&[
                    JsValue::from_str(ANNOTATION_KIND),
                    JsValue::from_str(&normalized.label),
                    JsValue::from_str(&note_sha256),
                    JsValue::from_str(&final_revision.to_string()),
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(token_id),
                ])?,
        ])
        .await;
    if let Err(error) = mutation {
        if let Some(stored) = load_receipt(&database, &requested.idempotency_key).await?
            && stored.resource_id == token_id
            && stored.request_sha256 == request_sha256
            && stored.validation_digest == requested.validation_digest
        {
            let mut response = Response::ok(stored.result_json)?;
            response
                .headers_mut()
                .set("Content-Type", "application/json")?;
            response
                .headers_mut()
                .set("Cache-Control", "no-store, max-age=0")?;
            return Ok(response);
        }
        if load_metadata(&database, token_id)
            .await?
            .is_some_and(|latest| latest.revision != normalized.expected_revision)
        {
            return Response::error("token metadata revision conflict", 409);
        }
        return Err(worker::Error::RustError(format!(
            "management mutation failed: {error}"
        )));
    }

    no_store_json(&receipt)
}

async fn load_metadata(
    database: &worker::D1Database,
    token_id: &str,
) -> Result<Option<TokenMetadataRow>> {
    database
        .prepare("SELECT label, note, revision FROM vfs_token_metadata WHERE token_id = ?1")
        .bind(&[JsValue::from_str(token_id)])?
        .first::<TokenMetadataRow>(None)
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
            JsValue::from_str(ANNOTATION_KIND),
            JsValue::from_str(idempotency_key),
        ])?
        .first::<ReceiptRow>(None)
        .await
}

fn normalize_annotation(
    requested: &ValidateTokenAnnotationRequest,
) -> std::result::Result<ValidateTokenAnnotationRequest, ()> {
    let label = requested.label.trim().to_owned();
    let note = requested.note.replace("\r\n", "\n").trim().to_owned();
    if requested.expected_revision == 0
        || label.is_empty()
        || label.len() > 128
        || note.len() > 2_048
        || label.chars().any(char::is_control)
        || note
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(());
    }
    Ok(ValidateTokenAnnotationRequest {
        label,
        note,
        expected_revision: requested.expected_revision,
    })
}

fn validation_digest(
    env: &Env,
    token_id: &str,
    requested: &ValidateTokenAnnotationRequest,
    expires_at: u64,
) -> Result<String> {
    let secret = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(VALIDATION_DOMAIN);
    mac.update(token_id.as_bytes());
    mac.update(&[0]);
    mac.update(&canonical_annotation(requested)?);
    mac.update(&expires_at.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn request_sha256(token_id: &str, requested: &ValidateTokenAnnotationRequest) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(VALIDATION_DOMAIN);
    hash.update(token_id.as_bytes());
    hash.update([0]);
    hash.update(canonical_annotation(requested)?);
    Ok(lowercase_hex(&hash.finalize()))
}

fn canonical_annotation(requested: &ValidateTokenAnnotationRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(requested).map_err(|error| json_error(&error))
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (URL_SAFE_NO_PAD.decode(left), URL_SAFE_NO_PAD.decode(right))
    else {
        return false;
    };
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
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
    use super::{ValidateTokenAnnotationRequest, normalize_annotation, valid_idempotency_key};

    #[test]
    fn normalizes_token_annotations() {
        let normalized = normalize_annotation(&ValidateTokenAnnotationRequest {
            label: "  Release agent  ".to_owned(),
            note: "  Publishes releases\r\nfor production.  ".to_owned(),
            expected_revision: 1,
        })
        .expect("annotation should be valid");
        assert_eq!(normalized.label, "Release agent");
        assert_eq!(normalized.note, "Publishes releases\nfor production.");
    }

    #[test]
    fn validates_management_idempotency_keys() {
        assert!(valid_idempotency_key("annotate-release-agent-v1"));
        assert!(!valid_idempotency_key(" trailing "));
        assert!(!valid_idempotency_key("line\nbreak"));
    }
}
