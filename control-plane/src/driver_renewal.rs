//! Provider credential decoding, least-authority projection, and renewal I/O.
//!
//! This adapter has no D1, claim, fence, envelope, or publication authority.
//! The server renewal state machine supplies already-opened credential bytes
//! and owns every durable transition around the returned material.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use carrack_driver_contract::DriverKind;
use serde::{Deserialize, Serialize};
use worker::{Fetch, Method, Request, RequestInit, Result};
use zeroize::Zeroize as _;

pub(crate) const OPENLIST_ONLINE_ISSUER: &str = "openlist-online/v1";
const OPENLIST_RENEW_ENDPOINT: &str = "https://api.oplist.org/alicloud/renewapi";
const REFRESH_LEAD_SECONDS: u64 = 30 * 60;
const MINIMUM_GRANT_LIFETIME_SECONDS: u64 = 5 * 60;
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

    fn access_grant(&self) -> serde_json::Value {
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

pub(crate) struct CredentialMaterial {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) credential_expires_at: u64,
    pub(crate) refresh_token_expires_at: u64,
    pub(crate) managed_issuer: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JwtClaims {
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) exp: u64,
}

pub(crate) enum RenewalFailure {
    Retry(&'static str),
    Reauthenticate(&'static str),
    Internal(worker::Error),
}

/// Decodes stored authority and returns only what a filesystem client needs.
pub(crate) fn access_grant_from_plaintext(
    driver_kind: DriverKind,
    plaintext: &[u8],
) -> Result<serde_json::Value> {
    if driver_kind != DriverKind::AliyunDriveOpenV2 {
        return serde_json::from_slice(plaintext)
            .map_err(|error| worker::Error::RustError(error.to_string()));
    }
    let credential = serde_json::from_slice::<AliyunCredential>(plaintext)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    Ok(credential.access_grant())
}

/// Proves that credential rotation preserves the provider account identity.
/// Expiry is irrelevant here: an old token remains valid identity evidence
/// after its bearer authority has expired.
pub(crate) fn same_authority(existing: &[u8], replacement: &[u8]) -> bool {
    let Ok(existing) = serde_json::from_slice::<AliyunCredential>(existing) else {
        return false;
    };
    let Ok(replacement) = serde_json::from_slice::<AliyunCredential>(replacement) else {
        return false;
    };
    let Some(existing) = jwt_claims(&existing.access_token) else {
        return false;
    };
    let Some(replacement) = jwt_claims(&replacement.access_token) else {
        return false;
    };
    existing.sub == replacement.sub && existing.aud == replacement.aud
}

pub(crate) fn refresh_claims(token: &str) -> Option<JwtClaims> {
    jwt_claims(token)
}

pub(crate) fn refresh_after(expires_at: u64, now: u64) -> u64 {
    expires_at.saturating_sub(REFRESH_LEAD_SECONDS).max(now + 1)
}

pub(crate) async fn authorize_refresh_token(
    refresh_token: &str,
    issuer: &str,
) -> std::result::Result<CredentialMaterial, RenewalFailure> {
    if issuer != OPENLIST_ONLINE_ISSUER {
        return Err(RenewalFailure::Reauthenticate("refresh_issuer_invalid"));
    }
    let old_refresh =
        jwt_claims(refresh_token).ok_or(RenewalFailure::Reauthenticate("refresh_token_invalid"))?;
    let credential = exchange_openlist(refresh_token, &old_refresh, None).await?;
    material(&credential)
}

pub(crate) async fn renew(
    kind: DriverKind,
    plaintext: &[u8],
    issuer: &str,
) -> std::result::Result<CredentialMaterial, RenewalFailure> {
    if kind != DriverKind::AliyunDriveOpenV2 {
        return Err(RenewalFailure::Reauthenticate(
            "credential_kind_not_refreshable",
        ));
    }
    let mut current = serde_json::from_slice::<AliyunCredential>(plaintext)
        .map_err(|_| RenewalFailure::Reauthenticate("credential_invalid"))?;
    let Some(refresh_token) = current.refresh_token.as_deref() else {
        return Err(RenewalFailure::Reauthenticate("refresh_token_missing"));
    };
    if issuer != OPENLIST_ONLINE_ISSUER || current.managed_issuer() != Some(OPENLIST_ONLINE_ISSUER)
    {
        return Err(RenewalFailure::Reauthenticate("refresh_issuer_invalid"));
    }
    let old_access = jwt_claims(&current.access_token)
        .ok_or(RenewalFailure::Reauthenticate("access_token_invalid"))?;
    let old_refresh =
        jwt_claims(refresh_token).ok_or(RenewalFailure::Reauthenticate("refresh_token_invalid"))?;
    let mut refreshed = exchange_openlist(refresh_token, &old_refresh, Some(&old_access)).await?;
    current.access_token = std::mem::take(&mut refreshed.access_token);
    current.refresh_token = refreshed.refresh_token.take();
    material(&current)
}

fn material(
    credential: &AliyunCredential,
) -> std::result::Result<CredentialMaterial, RenewalFailure> {
    let credential_expires_at = credential.access_expiry().ok_or_else(|| {
        RenewalFailure::Internal(worker::Error::RustError(
            "provider access token has no expiry".to_owned(),
        ))
    })?;
    let refresh_token_expires_at = credential
        .refresh_token
        .as_deref()
        .and_then(jwt_claims)
        .map(|claims| claims.exp)
        .ok_or_else(|| {
            RenewalFailure::Internal(worker::Error::RustError(
                "provider refresh token has no expiry".to_owned(),
            ))
        })?;
    let managed_issuer = credential.managed_issuer().map(str::to_owned);
    let plaintext = serde_json::to_vec(&credential)
        .map_err(|error| RenewalFailure::Internal(worker::Error::RustError(error.to_string())))?;
    Ok(CredentialMaterial {
        plaintext,
        credential_expires_at,
        refresh_token_expires_at,
        managed_issuer,
    })
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

async fn exchange_openlist(
    refresh_token: &str,
    old_refresh: &JwtClaims,
    old_access: Option<&JwtClaims>,
) -> std::result::Result<AliyunCredential, RenewalFailure> {
    let url = format!(
        "{OPENLIST_RENEW_ENDPOINT}?refresh_ui={refresh_token}&server_use=true&driver_txt=alicloud_qr"
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let request = Request::new_with_init(&url, &init)
        .map_err(|_| RenewalFailure::Retry("refresh_request_invalid"))?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| RenewalFailure::Retry("refresh_transport_failed"))?;
    let status = response.status_code();
    let refreshed = response.json::<OpenListResponse>().await;
    if !(200..300).contains(&status) {
        return Err(match refreshed {
            Ok(refreshed) if permanent_provider_rejection(&refreshed.text) => {
                RenewalFailure::Reauthenticate("refresh_rejected")
            }
            _ if status == 429 || status >= 500 => {
                RenewalFailure::Retry("refresh_provider_unavailable")
            }
            _ => RenewalFailure::Reauthenticate("refresh_rejected"),
        });
    }
    let refreshed = refreshed.map_err(|_| RenewalFailure::Retry("refresh_response_invalid"))?;
    if !refreshed.text.is_empty()
        || !valid_token(&refreshed.access_token)
        || !valid_token(&refreshed.refresh_token)
    {
        return Err(RenewalFailure::Reauthenticate(
            "refresh_credentials_rejected",
        ));
    }
    let new_access = jwt_claims(&refreshed.access_token)
        .ok_or(RenewalFailure::Reauthenticate("refreshed_access_invalid"))?;
    let new_refresh = jwt_claims(&refreshed.refresh_token)
        .ok_or(RenewalFailure::Reauthenticate("refreshed_refresh_invalid"))?;
    if old_access.is_some_and(|old| old.sub != new_access.sub || old.aud != new_access.aud)
        || old_refresh.sub != new_access.sub
        || old_refresh.aud != new_access.aud
        || old_refresh.sub != new_refresh.sub
        || old_refresh.aud != new_refresh.aud
        || new_access.exp <= now_seconds() + MINIMUM_GRANT_LIFETIME_SECONDS
    {
        return Err(RenewalFailure::Reauthenticate("refresh_identity_mismatch"));
    }
    Ok(AliyunCredential {
        access_token: refreshed.access_token,
        refresh_token: Some(refreshed.refresh_token),
        refresh_issuer: Some(OPENLIST_ONLINE_ISSUER.to_owned()),
    })
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

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{
        AliyunCredential, OPENLIST_ONLINE_ISSUER, jwt_claims, permanent_provider_rejection,
        refresh_after, same_authority,
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
    fn rotation_preserves_exact_provider_account_identity() {
        let credential = |sub: &str, aud: &str| AliyunCredential {
            access_token: jwt(sub, aud, 1234),
            refresh_token: Some(jwt(sub, aud, 5678)),
            refresh_issuer: Some(OPENLIST_ONLINE_ISSUER.to_owned()),
        };
        let existing = serde_json::to_vec(&credential("account", "client")).expect("existing");
        let same = serde_json::to_vec(&credential("account", "client")).expect("same");
        let other_account =
            serde_json::to_vec(&credential("other", "client")).expect("other account");
        let other_client =
            serde_json::to_vec(&credential("account", "other-client")).expect("other client");
        assert!(same_authority(&existing, &same));
        assert!(!same_authority(&existing, &other_account));
        assert!(!same_authority(&existing, &other_client));
    }

    #[test]
    fn classifies_openlist_invalid_token_even_when_it_uses_http_500() {
        assert!(permanent_provider_rejection("invalid refresh_token"));
        assert!(!permanent_provider_rejection(
            "upstream temporarily unavailable"
        ));
    }

    #[test]
    fn refresh_schedule_preserves_a_bounded_lead() {
        assert_eq!(refresh_after(10_000, 1_000), 8_200);
        assert_eq!(refresh_after(1_100, 1_000), 1_001);
    }
}
