use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

const ADMIN_TOKEN_BINDING: &str = "SKYDRIVER_ADMIN_TOKEN";
const OPERATOR_ACCOUNT_BINDING: &str = "SKYDRIVER_OPERATOR_ACCOUNT";
const DATABASE_BINDING: &str = "SKYDRIVER_INDEX";
const SESSION_COOKIE: &str = "skydriver_session";
const SESSION_LIFETIME_SECONDS: u64 = 12 * 60 * 60;
const CONFIGURATION_SESSION_COOKIE: &str = "skydriver_configuration";
const CONFIGURATION_SESSION_LIFETIME_SECONDS: u64 = 15 * 60;
const MAXIMUM_CREDENTIAL_BYTES: usize = 1_024;
const TOKEN_BYTES: usize = 32;
const ADMIN_TOKEN_COMPARISON_DOMAIN: &[u8] = b"skydriver.operator-credential.v1\0";
const RATE_LIMIT_COMPARISON_DOMAIN: &[u8] = b"skydriver.operator-rate-limit.v1\0";
const RATE_LIMIT_WINDOW_SECONDS: u64 = 15 * 60;
const LOGIN_IP_MAXIMUM_FAILURES: u64 = 20;
const LOGIN_IP_BLOCK_SECONDS: u64 = 15 * 60;
const LOGIN_ACCOUNT_MAXIMUM_FAILURES: u64 = 200;
const LOGIN_ACCOUNT_BLOCK_SECONDS: u64 = 30 * 60;
const CONFIGURATION_IP_MAXIMUM_FAILURES: u64 = 20;
const CONFIGURATION_IP_BLOCK_SECONDS: u64 = 15 * 60;

pub(crate) const OPERATOR_SUBJECT: &str = "operator";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
struct RateLimitPolicy {
    scope: &'static str,
    maximum_failures: u64,
    block_seconds: u64,
}

const LOGIN_IP_POLICY: RateLimitPolicy = RateLimitPolicy {
    scope: "login_ip",
    maximum_failures: LOGIN_IP_MAXIMUM_FAILURES,
    block_seconds: LOGIN_IP_BLOCK_SECONDS,
};
const LOGIN_ACCOUNT_POLICY: RateLimitPolicy = RateLimitPolicy {
    scope: "login_account",
    maximum_failures: LOGIN_ACCOUNT_MAXIMUM_FAILURES,
    block_seconds: LOGIN_ACCOUNT_BLOCK_SECONDS,
};
const CONFIGURATION_IP_POLICY: RateLimitPolicy = RateLimitPolicy {
    scope: "configuration_ip",
    maximum_failures: CONFIGURATION_IP_MAXIMUM_FAILURES,
    block_seconds: CONFIGURATION_IP_BLOCK_SECONDS,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    account: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    password: String,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
}

#[derive(Serialize)]
struct ConfigurationSessionResponse {
    enabled: bool,
    expires_at: Option<u64>,
}

pub(crate) async fn login(request: &mut Request, env: &Env) -> Result<Response> {
    let credentials = request.json::<LoginRequest>().await?;
    let configured_account = env.var(OPERATOR_ACCOUNT_BINDING)?.to_string();
    if !canonical_account(&configured_account) {
        return Err(worker::Error::RustError(
            "SKYDRIVER_OPERATOR_ACCOUNT must be a canonical account name".to_owned(),
        ));
    }
    let configured = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    if !canonical_token(&configured) {
        return Err(worker::Error::RustError(
            "SKYDRIVER_ADMIN_TOKEN must encode exactly 32 bytes".to_owned(),
        ));
    }
    let candidate = if credentials.password.len() <= MAXIMUM_CREDENTIAL_BYTES {
        credentials.password.as_str()
    } else {
        ""
    };
    let database = env.d1(DATABASE_BINDING)?;
    let now = now_seconds();
    let ip = client_ip(request)?;
    let ip_subject = rate_limit_subject(&configured, LOGIN_IP_POLICY.scope, &ip)?;
    let account_is_valid = account_matches(&credentials.account, &configured_account);
    let account_subject = account_is_valid
        .then(|| rate_limit_subject(&configured, LOGIN_ACCOUNT_POLICY.scope, &configured_account))
        .transpose()?;
    let mut policies = vec![(LOGIN_IP_POLICY, ip_subject.as_str())];
    if let Some(subject) = account_subject.as_deref() {
        policies.push((LOGIN_ACCOUNT_POLICY, subject));
    }
    if let Some(retry_after) = retry_after(&database, &policies, now).await? {
        return rate_limited_response(retry_after);
    }
    if !account_is_valid || !credential_matches(candidate, &configured) {
        if let Some(retry_after) = record_failures(&database, &policies, now).await? {
            return rate_limited_response(retry_after);
        }
        return invalid_credentials_response();
    }

    create_browser_session(request, env).await
}

pub(crate) async fn create_browser_session(request: &Request, env: &Env) -> Result<Response> {
    let database = env.d1(DATABASE_BINDING)?;
    let now = now_seconds();
    let ip = client_ip(request)?;
    let token = random_token()?;
    let verifier = token_verifier(&token).ok_or_else(|| {
        worker::Error::RustError("generated an invalid operator session token".to_owned())
    })?;
    let expires_at = now + SESSION_LIFETIME_SECONDS;
    let user_agent = request.headers().get("User-Agent")?.unwrap_or_default();
    database
        .batch(vec![
            database
                .prepare("DELETE FROM admin_sessions WHERE expires_at <= ?1")
                .bind(&[JsValue::from_str(&now.to_string())])?,
            database
                .prepare(
                    "INSERT INTO admin_sessions \
                     (id, expires_at, created_at, last_seen_at, ip, user_agent) \
                     VALUES (?1, ?2, ?3, ?3, ?4, ?5)",
                )
                .bind(&[
                    JsValue::from_str(&verifier),
                    JsValue::from_str(&expires_at.to_string()),
                    JsValue::from_str(&now.to_string()),
                    JsValue::from_str(&ip),
                    JsValue::from_str(&user_agent),
                ])?,
        ])
        .await?;

    session_response(
        true,
        Some(&session_cookie(
            &token,
            SESSION_LIFETIME_SECONDS,
            secure_cookie(env),
        )),
    )
}

pub(crate) fn browser_session_cookie(response: &Response) -> Result<Option<String>> {
    response.headers().get("Set-Cookie")
}

pub(crate) async fn status(request: &Request, env: &Env) -> Result<Response> {
    if !authorized(request, env).await? {
        return Response::error("unauthorized", 401);
    }
    session_response(true, None)
}

pub(crate) async fn logout(request: &Request, env: &Env) -> Result<Response> {
    if let Some(verifier) = session_verifier(request)? {
        env.d1(DATABASE_BINDING)?
            .prepare("DELETE FROM admin_sessions WHERE id = ?1")
            .bind(&[JsValue::from_str(&verifier)])?
            .run()
            .await?;
    }
    session_response(false, Some(&session_cookie("", 0, secure_cookie(env))))
}

pub(crate) async fn enable_configuration(request: &mut Request, env: &Env) -> Result<Response> {
    let Some(admin_session_id) = session_verifier(request)? else {
        return Response::error("authentication required", 401);
    };
    if !authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    let credentials = request.json::<CredentialRequest>().await?;
    let configured = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let candidate = if credentials.password.len() <= MAXIMUM_CREDENTIAL_BYTES {
        credentials.password.as_str()
    } else {
        ""
    };
    if !canonical_token(&configured) {
        return Err(worker::Error::RustError(
            "SKYDRIVER_ADMIN_TOKEN must encode exactly 32 bytes".to_owned(),
        ));
    }
    let database = env.d1(DATABASE_BINDING)?;
    let now = now_seconds();
    let ip = client_ip(request)?;
    let subject = rate_limit_subject(&configured, CONFIGURATION_IP_POLICY.scope, &ip)?;
    let policies = [(CONFIGURATION_IP_POLICY, subject.as_str())];
    if let Some(retry_after) = retry_after(&database, &policies, now).await? {
        return rate_limited_response(retry_after);
    }
    if !credential_matches(candidate, &configured) {
        if let Some(retry_after) = record_failures(&database, &policies, now).await? {
            return rate_limited_response(retry_after);
        }
        return invalid_credentials_response();
    }

    let token = random_token()?;
    let verifier = token_verifier(&token).ok_or_else(|| {
        worker::Error::RustError("generated an invalid configuration session token".to_owned())
    })?;
    let expires_at = now + CONFIGURATION_SESSION_LIFETIME_SECONDS;
    database
        .batch(vec![
            database
                .prepare("DELETE FROM admin_configuration_sessions WHERE expires_at <= ?1")
                .bind(&[JsValue::from_str(&now.to_string())])?,
            database
                .prepare(
                    "INSERT INTO admin_configuration_sessions \
                     (id, admin_session_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(&[
                    JsValue::from_str(&verifier),
                    JsValue::from_str(&admin_session_id),
                    JsValue::from_str(&expires_at.to_string()),
                    JsValue::from_str(&now.to_string()),
                ])?,
        ])
        .await?;

    configuration_session_response(
        true,
        Some(expires_at),
        Some(&configuration_cookie(
            &token,
            CONFIGURATION_SESSION_LIFETIME_SECONDS,
            secure_cookie(env),
        )),
    )
}

pub(crate) async fn configuration_status(request: &Request, env: &Env) -> Result<Response> {
    let expires_at = configuration_expiry(request, env).await?;
    configuration_session_response(expires_at.is_some(), expires_at, None)
}

pub(crate) async fn configuration_authorized(request: &Request, env: &Env) -> Result<bool> {
    Ok(configuration_expiry(request, env).await?.is_some())
}

pub(crate) async fn disable_configuration(request: &Request, env: &Env) -> Result<Response> {
    if let Some(verifier) = configuration_session_verifier(request)? {
        env.d1(DATABASE_BINDING)?
            .prepare("DELETE FROM admin_configuration_sessions WHERE id = ?1")
            .bind(&[JsValue::from_str(&verifier)])?
            .run()
            .await?;
    }

    configuration_session_response(
        false,
        None,
        Some(&configuration_cookie("", 0, secure_cookie(env))),
    )
}

pub(crate) async fn authorized(request: &Request, env: &Env) -> Result<bool> {
    let Some(verifier) = session_verifier(request)? else {
        return Ok(false);
    };
    let now = now_seconds();
    let row = env
        .d1(DATABASE_BINDING)?
        .prepare("SELECT id FROM admin_sessions WHERE id = ?1 AND expires_at > ?2")
        .bind(&[
            JsValue::from_str(&verifier),
            JsValue::from_str(&now.to_string()),
        ])?
        .first::<String>(Some("id"))
        .await?;

    Ok(row.is_some())
}

fn session_response(authenticated: bool, cookie: Option<&str>) -> Result<Response> {
    let mut response = Response::from_json(&SessionResponse { authenticated })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    if let Some(cookie) = cookie {
        response.headers_mut().set("Set-Cookie", cookie)?;
    }
    Ok(response)
}

fn configuration_session_response(
    enabled: bool,
    expires_at: Option<u64>,
    cookie: Option<&str>,
) -> Result<Response> {
    let mut response = Response::from_json(&ConfigurationSessionResponse {
        enabled,
        expires_at,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    if let Some(cookie) = cookie {
        response.headers_mut().set("Set-Cookie", cookie)?;
    }
    Ok(response)
}

async fn configuration_expiry(request: &Request, env: &Env) -> Result<Option<u64>> {
    if !authorized(request, env).await? {
        return Ok(None);
    }
    let Some(admin_session_id) = session_verifier(request)? else {
        return Ok(None);
    };
    let Some(configuration_id) = configuration_session_verifier(request)? else {
        return Ok(None);
    };
    let now = now_seconds();

    env.d1(DATABASE_BINDING)?
        .prepare(
            "SELECT expires_at FROM admin_configuration_sessions \
             WHERE id = ?1 AND admin_session_id = ?2 AND expires_at > ?3",
        )
        .bind(&[
            JsValue::from_str(&configuration_id),
            JsValue::from_str(&admin_session_id),
            JsValue::from_str(&now.to_string()),
        ])?
        .first::<u64>(Some("expires_at"))
        .await
}

fn session_verifier(request: &Request) -> Result<Option<String>> {
    let Some(cookie_header) = request.headers().get("Cookie")? else {
        return Ok(None);
    };
    let Some(token) = cookie_value(&cookie_header, SESSION_COOKIE) else {
        return Ok(None);
    };

    Ok(token_verifier(token))
}

fn configuration_session_verifier(request: &Request) -> Result<Option<String>> {
    let Some(cookie_header) = request.headers().get("Cookie")? else {
        return Ok(None);
    };
    let Some(token) = cookie_value(&cookie_header, CONFIGURATION_SESSION_COOKIE) else {
        return Ok(None);
    };

    Ok(token_verifier(token))
}

fn token_verifier(token: &str) -> Option<String> {
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    if decoded.len() != TOKEN_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != token {
        return None;
    }

    Some(lowercase_hex(&Sha256::digest(token.as_bytes())))
}

fn random_token() -> Result<String> {
    let mut token = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|error| worker::Error::RustError(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn canonical_token(token: &str) -> bool {
    URL_SAFE_NO_PAD.decode(token).is_ok_and(|decoded| {
        decoded.len() == TOKEN_BYTES && URL_SAFE_NO_PAD.encode(decoded) == token
    })
}

fn canonical_account(account: &str) -> bool {
    let bytes = account.as_bytes();
    (1..=64).contains(&bytes.len())
        && account.split_once('@').map_or_else(
            || canonical_account_part(account),
            |(name, realm)| canonical_account_part(name) && canonical_account_part(realm),
        )
}

fn canonical_account_part(part: &str) -> bool {
    let bytes = part.as_bytes();
    !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte))
}

fn account_matches(candidate: &str, configured: &str) -> bool {
    candidate == configured
}

fn credential_matches(candidate: &str, configured: &str) -> bool {
    let Ok(mut expected_mac) = HmacSha256::new_from_slice(configured.as_bytes()) else {
        return false;
    };
    expected_mac.update(ADMIN_TOKEN_COMPARISON_DOMAIN);
    let expected = expected_mac.finalize().into_bytes();

    let Ok(mut candidate_mac) = HmacSha256::new_from_slice(candidate.as_bytes()) else {
        return false;
    };
    candidate_mac.update(ADMIN_TOKEN_COMPARISON_DOMAIN);
    candidate_mac.verify_slice(&expected).is_ok()
}

fn client_ip(request: &Request) -> Result<String> {
    Ok(request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".to_owned()))
}

fn rate_limit_subject(configured: &str, scope: &str, value: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(configured.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(RATE_LIMIT_COMPARISON_DOMAIN);
    mac.update(scope.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    Ok(lowercase_hex(&mac.finalize().into_bytes()))
}

async fn retry_after(
    database: &worker::D1Database,
    policies: &[(RateLimitPolicy, &str)],
    now: u64,
) -> Result<Option<u64>> {
    let mut maximum = None;
    for (policy, subject) in policies {
        let blocked_until = database
            .prepare(
                "SELECT blocked_until FROM operator_auth_rate_limits
                 WHERE scope = ?1 AND subject = ?2 AND blocked_until > ?3",
            )
            .bind(&[
                JsValue::from_str(policy.scope),
                JsValue::from_str(subject),
                JsValue::from_str(&now.to_string()),
            ])?
            .first::<u64>(Some("blocked_until"))
            .await?;
        if let Some(blocked_until) = blocked_until {
            maximum =
                Some(maximum.map_or(blocked_until, |current: u64| current.max(blocked_until)));
        }
    }
    Ok(maximum.map(|blocked_until| blocked_until.saturating_sub(now).max(1)))
}

async fn record_failures(
    database: &worker::D1Database,
    policies: &[(RateLimitPolicy, &str)],
    now: u64,
) -> Result<Option<u64>> {
    let window_cutoff = now.saturating_sub(RATE_LIMIT_WINDOW_SECONDS);
    for (policy, subject) in policies {
        database
            .prepare(
                "INSERT INTO operator_auth_rate_limits (
                     scope, subject, window_started_at, attempts, blocked_until, updated_at
                 ) VALUES (?1, ?2, ?3, 1, 0, ?3)
                 ON CONFLICT(scope, subject) DO UPDATE SET
                     attempts = CASE
                         WHEN window_started_at <= ?4 THEN 1 ELSE attempts + 1
                     END,
                     window_started_at = CASE
                         WHEN window_started_at <= ?4 THEN ?3 ELSE window_started_at
                     END,
                     blocked_until = CASE
                         WHEN blocked_until > ?3 THEN blocked_until
                         WHEN (CASE
                             WHEN window_started_at <= ?4 THEN 1 ELSE attempts + 1
                         END) >= CAST(?5 AS INTEGER) THEN ?3 + ?6
                         ELSE 0
                     END,
                     updated_at = ?3",
            )
            .bind(&[
                JsValue::from_str(policy.scope),
                JsValue::from_str(subject),
                JsValue::from_str(&now.to_string()),
                JsValue::from_str(&window_cutoff.to_string()),
                JsValue::from_str(&policy.maximum_failures.to_string()),
                JsValue::from_str(&policy.block_seconds.to_string()),
            ])?
            .run()
            .await?;
    }
    retry_after(database, policies, now).await
}

fn invalid_credentials_response() -> Result<Response> {
    let mut response = Response::error("invalid credentials", 401)?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn rate_limited_response(retry_after: u64) -> Result<Response> {
    let mut response = Response::error("too many authentication attempts", 429)?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response
        .headers_mut()
        .set("Retry-After", &retry_after.to_string())?;
    Ok(response)
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && !value.is_empty()).then_some(value)
    })
}

fn secure_cookie(env: &Env) -> bool {
    env.var("SKYDRIVER_ENVIRONMENT")
        .map_or(true, |value| value.to_string() != "local")
}

fn session_cookie(token: &str, max_age: u64, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly;{} SameSite=Strict; Max-Age={max_age}",
        if secure { " Secure;" } else { "" }
    )
}

fn configuration_cookie(token: &str, max_age: u64, secure: bool) -> String {
    format!(
        "{CONFIGURATION_SESSION_COOKIE}={token}; Path=/api/; HttpOnly;{} SameSite=Strict; Max-Age={max_age}",
        if secure { " Secure;" } else { "" }
    )
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::{
        account_matches, canonical_account, canonical_token, cookie_value, credential_matches,
        token_verifier,
    };

    const TOKEN: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

    #[test]
    fn accepts_only_canonical_256_bit_credentials() {
        assert!(canonical_token(TOKEN));
        assert!(!canonical_token("short"));
        assert!(!canonical_token(&format!("{TOKEN}=")));
    }

    #[test]
    fn accepts_only_canonical_operator_accounts() {
        assert!(canonical_account("draven"));
        assert!(canonical_account("operator.dev-1"));
        assert!(canonical_account("draven@skydriver-dev"));
        assert!(!canonical_account(""));
        assert!(!canonical_account("Draven"));
        assert!(!canonical_account("-operator"));
        assert!(!canonical_account("draven@@skydriver-dev"));
        assert!(!canonical_account("draven@-skydriver-dev"));
    }

    #[test]
    fn accepts_only_the_exact_configured_account() {
        assert!(account_matches(
            "draven@skydriver-dev",
            "draven@skydriver-dev"
        ));
        assert!(!account_matches("draven", "draven@skydriver-dev"));
        assert!(!account_matches(
            "draven@skydriver-prod",
            "draven@skydriver-dev"
        ));
    }

    #[test]
    fn compares_operator_credentials_without_plaintext_storage() {
        assert!(credential_matches(TOKEN, TOKEN));
        assert!(!credential_matches(
            "AAIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
            TOKEN
        ));
    }

    #[test]
    fn validates_session_cookie_and_verifier() {
        assert_eq!(
            cookie_value(
                "theme=dark; skydriver_session=token; x=1",
                "skydriver_session"
            ),
            Some("token")
        );
        assert_eq!(token_verifier(TOKEN).as_deref().map(str::len), Some(64));
        assert!(token_verifier("invalid").is_none());
    }
}
