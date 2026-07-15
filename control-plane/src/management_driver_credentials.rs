use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::{
    driver_credentials::{self, RefreshFailure},
    management_driver_registration, operator_sessions, r2_signing,
    vfs_envelopes::{ENVELOPE_ALGORITHM, MASTER_KEY_VERSION, blob_binding, seal_driver_credential},
    vfs_identifiers,
};

const ADMIN_TOKEN_BINDING: &str = "CARRACK_ADMIN_TOKEN";
const DATABASE_BINDING: &str = "CARRACK_INDEX";
const VALIDATION_LIFETIME_SECONDS: u64 = 5 * 60;
const CREDENTIAL_KIND: &str = "driver.credential";
const VALIDATION_DOMAIN: &[u8] = b"carrack.management.validation.driver-credential.v1\0";
const ALIYUN_DRIVE_KIND: &str = "aliyundrive-open/v2";
const AUTHORIZATION_CLAIM_SECONDS: u64 = 5 * 60;
const LONG_LIVED_CREDENTIAL_EXPIRES_AT: u64 = 253_402_300_799;

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    credential: CredentialAuthorization,
    expected_revision: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RefreshAuthorization {
    refresh_token: String,
    refresh_issuer: String,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum CredentialAuthorization {
    Aliyun(RefreshAuthorization),
    R2(r2_signing::Credential),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    credential: CredentialAuthorization,
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

#[derive(Deserialize)]
struct AuthorizationClaimRow {
    idempotency_key: String,
    validation_digest: String,
    fencing_token: u64,
    lease_expires_at: u64,
}

#[derive(Serialize)]
struct ValidationResponse {
    schema: &'static str,
    driver_id: String,
    kind: String,
    current_credential_present: bool,
    credential_revision: u64,
    refresh_token_expires_at: u64,
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
    refresh_token_expires_at: u64,
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
    let database = env.d1(DATABASE_BINDING)?;
    let Some(driver) = load_driver(&database, driver_id).await? else {
        return Response::error("driver not found", 404);
    };
    if driver.revision != requested.expected_revision {
        return Response::error("driver revision conflict", 409);
    }
    if !management_driver_registration::valid_stored_configuration(
        &driver.kind,
        &driver.config_json,
        true,
    ) {
        return Response::error("driver kind does not accept this credential", 400);
    }
    let refresh_token_expires_at = match (&driver.kind[..], &requested.credential) {
        (ALIYUN_DRIVE_KIND, CredentialAuthorization::Aliyun(authorization)) => {
            if authorization.refresh_issuer != driver_credentials::OPENLIST_ONLINE_ISSUER {
                return Response::error("refresh token issuer is unsupported", 400);
            }
            let Some(claims) = driver_credentials::refresh_claims(&authorization.refresh_token)
            else {
                return Response::error("refresh token is invalid", 400);
            };
            if claims.exp <= now_seconds() {
                return Response::error("refresh token is expired", 400);
            }
            claims.exp
        }
        (management_driver_registration::R2_KIND, CredentialAuthorization::R2(credential))
            if r2_signing::valid_credential(credential) =>
        {
            LONG_LIVED_CREDENTIAL_EXPIRES_AT
        }
        _ => return Response::error("credential does not match driver kind", 400),
    };

    let validation_expires_at = now_seconds() + VALIDATION_LIFETIME_SECONDS;
    let validation_digest = validation_digest(env, driver_id, &requested, validation_expires_at)?;
    let is_r2 = driver.kind == management_driver_registration::R2_KIND;
    no_store_json(&ValidationResponse {
        schema: "carrack.management.driver-credential-validation.v1",
        driver_id: driver_id.to_owned(),
        kind: driver.kind,
        current_credential_present: driver.credential_id.is_some(),
        credential_revision: driver.credential_revision.unwrap_or(0) + 1,
        refresh_token_expires_at,
        expected_revision: requested.expected_revision,
        validation_expires_at,
        validation_digest,
        warnings: if is_r2 {
            vec![
                "The R2 access key is write-only and remains encrypted in the control plane.",
                "Applying this validation verifies the key against the configured R2 bucket.",
            ]
        } else {
            vec![
                "The refresh token is write-only and remains encrypted in the control plane.",
                "Applying this validation exchanges and verifies the token with the provider.",
            ]
        },
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
    if !valid_string(&requested.idempotency_key, 256) {
        return Response::error("driver credential apply is invalid", 400);
    }

    let now = now_seconds();
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
    if !management_driver_registration::valid_stored_configuration(
        &driver.kind,
        &driver.config_json,
        true,
    ) {
        return Response::error("driver kind does not accept this credential", 409);
    }

    let Some(authorization_fence) = claim_authorization(
        &database,
        driver_id,
        desired.expected_revision,
        &requested.validation_digest,
        &requested.idempotency_key,
        now,
    )
    .await?
    else {
        return Response::error("driver authorization is already in progress", 409);
    };

    let (mut plaintext, credential_expires_at, refresh_token_expires_at, managed_issuer) =
        match desired.credential {
            CredentialAuthorization::Aliyun(authorization) if driver.kind == ALIYUN_DRIVE_KIND => {
                let Some(refresh_claims) =
                    driver_credentials::refresh_claims(&authorization.refresh_token)
                else {
                    return Response::error("refresh token is invalid", 400);
                };
                if refresh_claims.exp <= now
                    || authorization.refresh_issuer != driver_credentials::OPENLIST_ONLINE_ISSUER
                {
                    return Response::error("refresh authorization is invalid or expired", 409);
                }
                let credential = match driver_credentials::authorize_refresh_token(
                    &authorization.refresh_token,
                    &authorization.refresh_issuer,
                )
                .await
                {
                    Ok(credential) => credential,
                    Err(RefreshFailure::Reauthenticate(_)) => {
                        release_authorization(
                            &database,
                            driver_id,
                            authorization_fence,
                            &requested.idempotency_key,
                        )
                        .await?;
                        return Response::error("refresh token was rejected by the provider", 400);
                    }
                    Err(RefreshFailure::Retry(_)) => {
                        release_authorization(
                            &database,
                            driver_id,
                            authorization_fence,
                            &requested.idempotency_key,
                        )
                        .await?;
                        return Response::error(
                            "provider authorization is temporarily unavailable",
                            503,
                        );
                    }
                };
                let access_expiry = credential.access_expiry().ok_or_else(|| {
                    worker::Error::RustError("provider access token has no expiry".to_owned())
                })?;
                let refresh_expiry = credential
                    .refresh_token
                    .as_deref()
                    .and_then(driver_credentials::refresh_claims)
                    .map(|claims| claims.exp)
                    .ok_or_else(|| {
                        worker::Error::RustError("provider refresh token has no expiry".to_owned())
                    })?;
                let issuer = credential.managed_issuer().map(str::to_owned);
                let bytes = serde_json::to_vec(&credential).map_err(|error| json_error(&error))?;
                (bytes, access_expiry, refresh_expiry, issuer)
            }
            CredentialAuthorization::R2(credential)
                if driver.kind == management_driver_registration::R2_KIND =>
            {
                let config = serde_json::from_str::<r2_signing::Config>(&driver.config_json)
                    .map_err(|error| json_error(&error))?;
                if !r2_signing::verify(&config, &credential).await {
                    release_authorization(
                        &database,
                        driver_id,
                        authorization_fence,
                        &requested.idempotency_key,
                    )
                    .await?;
                    return Response::error(
                        "R2 credential was rejected by the configured bucket",
                        400,
                    );
                }
                let bytes = serde_json::to_vec(&credential).map_err(|error| json_error(&error))?;
                (
                    bytes,
                    LONG_LIVED_CREDENTIAL_EXPIRES_AT,
                    LONG_LIVED_CREDENTIAL_EXPIRES_AT,
                    None,
                )
            }
            _ => return Response::error("credential does not match driver kind", 409),
        };

    let credential_id = match driver.credential_id {
        Some(value) => value,
        None => vfs_identifiers::new_uuid_v7_hex()?,
    };
    let credential_revision = driver.credential_revision.unwrap_or(0) + 1;
    let final_revision = driver.revision + 1;
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
        refresh_token_expires_at,
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

    let refresh_statement = if let Some(issuer) = managed_issuer.as_deref() {
        database
            .prepare(
                r"INSERT INTO driver_credential_refreshes (
                     credential_id, driver_id, issuer, observed_credential_revision,
                     refresh_after, refresh_token_expires_at, last_succeeded_at,
                     created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?7)
                 ON CONFLICT(credential_id) DO UPDATE SET
                     driver_id = excluded.driver_id, issuer = excluded.issuer,
                     observed_credential_revision = excluded.observed_credential_revision,
                     state = 'ready', lease_expires_at = NULL,
                     refresh_after = excluded.refresh_after,
                     refresh_token_expires_at = excluded.refresh_token_expires_at,
                     last_succeeded_at = excluded.last_succeeded_at, retry_at = NULL,
                     attempt_count = 0, last_error_code = NULL,
                     updated_at = excluded.updated_at",
            )
            .bind(&[
                JsValue::from_str(&credential_id),
                JsValue::from_str(driver_id),
                JsValue::from_str(issuer),
                JsValue::from_str(&credential_revision.to_string()),
                JsValue::from_str(
                    &driver_credentials::refresh_after(credential_expires_at, now).to_string(),
                ),
                JsValue::from_str(&refresh_token_expires_at.to_string()),
                JsValue::from_str(&now.to_string()),
            ])?
    } else {
        database
            .prepare("DELETE FROM driver_credential_refreshes WHERE credential_id = ?1")
            .bind(&[JsValue::from_str(&credential_id)])?
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
            refresh_statement,
            database
                .prepare(
                    "DELETE FROM driver_authorization_claims
                     WHERE driver_id = ?1 AND fencing_token = ?2 AND idempotency_key = ?3",
                )
                .bind(&[
                    JsValue::from_str(driver_id),
                    JsValue::from_str(&authorization_fence.to_string()),
                    JsValue::from_str(&requested.idempotency_key),
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

async fn claim_authorization(
    database: &worker::D1Database,
    driver_id: &str,
    expected_revision: u64,
    validation_digest: &str,
    idempotency_key: &str,
    now: u64,
) -> Result<Option<u64>> {
    database
        .prepare(
            r"INSERT INTO driver_authorization_claims (
                 driver_id, expected_driver_revision, validation_digest,
                 idempotency_key, lease_expires_at, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(driver_id) DO UPDATE SET
                 expected_driver_revision = excluded.expected_driver_revision,
                 validation_digest = excluded.validation_digest,
                 idempotency_key = excluded.idempotency_key,
                 fencing_token = driver_authorization_claims.fencing_token + 1,
                 lease_expires_at = excluded.lease_expires_at,
                 updated_at = excluded.updated_at
             WHERE driver_authorization_claims.lease_expires_at <= excluded.updated_at",
        )
        .bind(&[
            JsValue::from_str(driver_id),
            JsValue::from_str(&expected_revision.to_string()),
            JsValue::from_str(validation_digest),
            JsValue::from_str(idempotency_key),
            JsValue::from_str(&(now + AUTHORIZATION_CLAIM_SECONDS).to_string()),
            JsValue::from_str(&now.to_string()),
        ])?
        .run()
        .await?;
    let claim = database
        .prepare(
            "SELECT idempotency_key, validation_digest, fencing_token, lease_expires_at
             FROM driver_authorization_claims WHERE driver_id = ?1",
        )
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<AuthorizationClaimRow>(None)
        .await?;
    Ok(claim.and_then(|claim| {
        (claim.idempotency_key == idempotency_key
            && claim.validation_digest == validation_digest
            && claim.lease_expires_at > now)
            .then_some(claim.fencing_token)
    }))
}

async fn release_authorization(
    database: &worker::D1Database,
    driver_id: &str,
    fencing_token: u64,
    idempotency_key: &str,
) -> Result<()> {
    database
        .prepare(
            "DELETE FROM driver_authorization_claims
             WHERE driver_id = ?1 AND fencing_token = ?2 AND idempotency_key = ?3",
        )
        .bind(&[
            JsValue::from_str(driver_id),
            JsValue::from_str(&fencing_token.to_string()),
            JsValue::from_str(idempotency_key),
        ])?
        .run()
        .await?;
    Ok(())
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
    use super::request_sha256;

    #[test]
    fn durable_request_identity_uses_server_digest_not_plaintext() {
        let identity = request_sha256("aliyun-main", 1, "server-hmac");
        assert_eq!(identity.len(), 64);
        assert!(!identity.contains("server-hmac"));
    }
}
