//! Server-owned provider credential renewal.
//!
//! Filesystem clients receive only short-lived access credentials. Refresh
//! authority stays encrypted in D1 and is rotated by a fenced Cron worker.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use worker::{D1Database, Env, Fetch, Method, Request, RequestInit, Result, wasm_bindgen::JsValue};
use zeroize::Zeroize as _;

use crate::vfs_envelopes::{
    ENVELOPE_ALGORITHM, MASTER_KEY_VERSION, blob_binding, open_driver_credential,
    seal_driver_credential,
};

pub(crate) const OPENLIST_ONLINE_ISSUER: &str = "openlist-online/v1";
const OPENLIST_RENEW_ENDPOINT: &str = "https://api.oplist.org/alicloud/renewapi";
const CLAIM_SECONDS: u64 = 120;
const REFRESH_LEAD_SECONDS: u64 = 30 * 60;
const MINIMUM_GRANT_LIFETIME_SECONDS: u64 = 5 * 60;
const MAXIMUM_REFRESHES_PER_RUN: usize = 4;
const MAXIMUM_TOKEN_BYTES: usize = 16 << 10;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AliyunCredential {
    pub(crate) access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_issuer: Option<String>,
}

impl AliyunCredential {
    pub(crate) fn managed_issuer(&self) -> Option<&str> {
        match (
            self.refresh_token.as_deref(),
            self.refresh_issuer.as_deref(),
        ) {
            (Some(token), Some(OPENLIST_ONLINE_ISSUER)) if valid_token(token) => {
                Some(OPENLIST_ONLINE_ISSUER)
            }
            _ => None,
        }
    }

    pub(crate) fn access_expiry(&self) -> Option<u64> {
        jwt_claims(&self.access_token).map(|claims| claims.exp)
    }

    pub(crate) fn access_grant(&self) -> serde_json::Value {
        serde_json::json!({"access_token": self.access_token})
    }
}

impl Drop for AliyunCredential {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = self.refresh_token.as_mut() {
            token.zeroize();
        }
    }
}

/// Decodes a stored provider credential and returns the least-authority JSON
/// that a filesystem client needs. Refresh material is deliberately omitted.
pub(crate) fn access_grant_from_plaintext(
    driver_kind: &str,
    plaintext: &[u8],
) -> Result<serde_json::Value> {
    if driver_kind != "aliyundrive-open/v2" {
        return serde_json::from_slice(plaintext)
            .map_err(|error| worker::Error::RustError(error.to_string()));
    }
    let credential = serde_json::from_slice::<AliyunCredential>(plaintext)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    Ok(credential.access_grant())
}

#[derive(Deserialize)]
struct RefreshTask {
    credential_id: String,
    driver_id: String,
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
struct OpenListResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct RefreshCommitRow {
    observed_credential_revision: u64,
    state: String,
    last_succeeded_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JwtClaims {
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) exp: u64,
}

pub(crate) enum RefreshFailure {
    Retry(&'static str),
    Reauthenticate(&'static str),
}

pub(crate) fn refresh_claims(token: &str) -> Option<JwtClaims> {
    jwt_claims(token)
}

pub(crate) async fn authorize_refresh_token(
    refresh_token: &str,
    issuer: &str,
) -> std::result::Result<AliyunCredential, RefreshFailure> {
    if issuer != OPENLIST_ONLINE_ISSUER {
        return Err(RefreshFailure::Reauthenticate("refresh_issuer_invalid"));
    }
    let old_refresh =
        jwt_claims(refresh_token).ok_or(RefreshFailure::Reauthenticate("refresh_token_invalid"))?;
    exchange_openlist(refresh_token, &old_refresh, None).await
}

/// Runs a bounded proactive renewal pass. Provider failures are persisted as
/// non-secret state and do not prevent unrelated metadata maintenance.
pub(crate) async fn run(env: &Env, now: u64) -> Result<()> {
    let database = env.d1("CARRACK_INDEX")?;
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
    let database = env.d1("CARRACK_INDEX")?;
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

pub(crate) fn refresh_after(expires_at: u64, now: u64) -> u64 {
    expires_at.saturating_sub(REFRESH_LEAD_SECONDS).max(now + 1)
}

async fn refresh_one(
    env: &Env,
    database: &D1Database,
    now: u64,
    driver_id: Option<&str>,
) -> Result<bool> {
    let candidate = database
        .prepare(
            "SELECT driver_id FROM driver_credential_refreshes
             WHERE (?1 IS NULL OR driver_id = ?1)
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
        Ok(mut credential) => {
            let expires_at = credential.access_expiry().ok_or_else(|| {
                worker::Error::RustError("renewed Aliyun access token has no expiry".to_owned())
            })?;
            let refresh_token_expires_at = credential
                .refresh_token
                .as_deref()
                .and_then(jwt_claims)
                .map(|claims| claims.exp)
                .ok_or_else(|| {
                    worker::Error::RustError(
                        "renewed Aliyun refresh token has no expiry".to_owned(),
                    )
                })?;
            let mut plaintext = serde_json::to_vec(&credential)
                .map_err(|error| worker::Error::RustError(error.to_string()))?;
            let next_revision = task.observed_credential_revision + 1;
            let sealed =
                seal_driver_credential(env, &task.credential_id, next_revision, &plaintext);
            plaintext.zeroize();
            credential.access_token.zeroize();
            let sealed = sealed?;
            commit_refresh(
                database,
                &task,
                &sealed,
                expires_at,
                refresh_token_expires_at,
                now,
            )
            .await?;
        }
        Err(RefreshFailure::Retry(code)) => fail_refresh(database, &task, now, code, false).await?,
        Err(RefreshFailure::Reauthenticate(code)) => {
            fail_refresh(database, &task, now, code, true).await?;
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
            "SELECT refresh.credential_id, refresh.driver_id, refresh.issuer,
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
) -> std::result::Result<AliyunCredential, RefreshFailure> {
    let mut plaintext = open_driver_credential(
        env,
        &task.credential_id,
        task.observed_credential_revision,
        &task.envelope_algorithm,
        &task.key_version,
        &task.nonce,
        &task.ciphertext,
    )
    .map_err(|_| RefreshFailure::Reauthenticate("credential_envelope_invalid"))?;
    let decoded = serde_json::from_slice::<AliyunCredential>(&plaintext);
    plaintext.zeroize();
    let mut current = decoded.map_err(|_| RefreshFailure::Reauthenticate("credential_invalid"))?;
    let Some(refresh_token) = current.refresh_token.as_deref() else {
        return Err(RefreshFailure::Reauthenticate("refresh_token_missing"));
    };
    if task.issuer != OPENLIST_ONLINE_ISSUER
        || current.managed_issuer() != Some(OPENLIST_ONLINE_ISSUER)
    {
        return Err(RefreshFailure::Reauthenticate("refresh_issuer_invalid"));
    }
    let old_access = jwt_claims(&current.access_token)
        .ok_or(RefreshFailure::Reauthenticate("access_token_invalid"))?;
    let old_refresh =
        jwt_claims(refresh_token).ok_or(RefreshFailure::Reauthenticate("refresh_token_invalid"))?;
    let mut refreshed = exchange_openlist(refresh_token, &old_refresh, Some(&old_access)).await?;
    current.access_token = std::mem::take(&mut refreshed.access_token);
    current.refresh_token = refreshed.refresh_token.take();
    Ok(current)
}

async fn exchange_openlist(
    refresh_token: &str,
    old_refresh: &JwtClaims,
    old_access: Option<&JwtClaims>,
) -> std::result::Result<AliyunCredential, RefreshFailure> {
    let url = format!(
        "{OPENLIST_RENEW_ENDPOINT}?refresh_ui={refresh_token}&server_use=true&driver_txt=alicloud_qr"
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let request = Request::new_with_init(&url, &init)
        .map_err(|_| RefreshFailure::Retry("refresh_request_invalid"))?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| RefreshFailure::Retry("refresh_transport_failed"))?;
    let status = response.status_code();
    let refreshed = response.json::<OpenListResponse>().await;
    if !(200..300).contains(&status) {
        return Err(match refreshed {
            Ok(refreshed) if permanent_provider_rejection(&refreshed.text) => {
                RefreshFailure::Reauthenticate("refresh_rejected")
            }
            _ if status == 429 || status >= 500 => {
                RefreshFailure::Retry("refresh_provider_unavailable")
            }
            _ => RefreshFailure::Reauthenticate("refresh_rejected"),
        });
    }
    let refreshed = refreshed.map_err(|_| RefreshFailure::Retry("refresh_response_invalid"))?;
    if !refreshed.text.is_empty()
        || !valid_token(&refreshed.access_token)
        || !valid_token(&refreshed.refresh_token)
    {
        return Err(RefreshFailure::Reauthenticate(
            "refresh_credentials_rejected",
        ));
    }
    let new_access = jwt_claims(&refreshed.access_token)
        .ok_or(RefreshFailure::Reauthenticate("refreshed_access_invalid"))?;
    let new_refresh = jwt_claims(&refreshed.refresh_token)
        .ok_or(RefreshFailure::Reauthenticate("refreshed_refresh_invalid"))?;
    if old_access.is_some_and(|old| old.sub != new_access.sub || old.aud != new_access.aud)
        || old_refresh.sub != new_access.sub
        || old_refresh.aud != new_access.aud
        || old_refresh.sub != new_refresh.sub
        || old_refresh.aud != new_refresh.aud
        || new_access.exp <= now_seconds() + MINIMUM_GRANT_LIFETIME_SECONDS
    {
        return Err(RefreshFailure::Reauthenticate("refresh_identity_mismatch"));
    }
    Ok(AliyunCredential {
        access_token: refreshed.access_token,
        refresh_token: Some(refreshed.refresh_token),
        refresh_issuer: Some(OPENLIST_ONLINE_ISSUER.to_owned()),
    })
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
                    integer(refresh_after(expires_at, now)),
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

fn jwt_claims(token: &str) -> Option<JwtClaims> {
    if !valid_token(token) {
        return None;
    }
    let mut segments = token.split('.');
    let _header = segments.next()?;
    let payload = segments.next()?;
    let _signature = segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value = serde_json::from_slice::<serde_json::Value>(&payload).ok()?;
    Some(JwtClaims {
        sub: value.get("sub")?.as_str()?.to_owned(),
        aud: value.get("aud")?.as_str()?.to_owned(),
        exp: value.get("exp")?.as_u64()?,
    })
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAXIMUM_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn permanent_provider_rejection(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    ["invalid", "expired", "incorrect", "revoked"]
        .iter()
        .any(|needle| normalized.contains(needle))
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{
        AliyunCredential, OPENLIST_ONLINE_ISSUER, jwt_claims, permanent_provider_rejection,
        refresh_after, retry_delay,
    };

    fn jwt(sub: &str, aud: &str, exp: u64) -> String {
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"sub": sub, "aud": aud, "exp": exp})
                .to_string()
                .as_bytes(),
        );
        format!("e30.{payload}.c2ln")
    }

    #[test]
    fn parses_identity_and_expiry_from_jwt() {
        let claims = jwt_claims(&jwt("account", "client", 1234)).expect("JWT claims");
        assert_eq!(claims.sub, "account");
        assert_eq!(claims.aud, "client");
        assert_eq!(claims.exp, 1234);
    }

    #[test]
    fn grant_projection_never_contains_refresh_authority() {
        let credential = AliyunCredential {
            access_token: jwt("account", "client", 1234),
            refresh_token: Some(jwt("account", "client", 5678)),
            refresh_issuer: Some(OPENLIST_ONLINE_ISSUER.to_owned()),
        };
        let grant = credential.access_grant();
        assert!(grant.get("access_token").is_some());
        assert!(grant.get("refresh_token").is_none());
        assert!(grant.get("refresh_issuer").is_none());
    }

    #[test]
    fn refresh_schedule_and_retry_are_bounded() {
        assert_eq!(refresh_after(10_000, 1_000), 8_200);
        assert_eq!(refresh_after(1_100, 1_000), 1_001);
        assert!((60..=120).contains(&retry_delay(1, 60)));
        assert!(retry_delay(100, 60) <= 6 * 60 * 60 + 60);
    }

    #[test]
    fn classifies_openlist_invalid_token_even_when_it_uses_http_500() {
        assert!(permanent_provider_rejection("invalid refresh_token"));
        assert!(!permanent_provider_rejection(
            "upstream temporarily unavailable"
        ));
    }
}
