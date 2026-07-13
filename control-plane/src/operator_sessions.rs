use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

const ADMIN_TOKEN_BINDING: &str = "CARRACK_ADMIN_TOKEN";
const DATABASE_BINDING: &str = "CARRACK_INDEX";
const SESSION_COOKIE: &str = "carrack_session";
const SESSION_LIFETIME_SECONDS: u64 = 12 * 60 * 60;
const CONFIGURATION_SESSION_COOKIE: &str = "carrack_configuration";
const CONFIGURATION_SESSION_LIFETIME_SECONDS: u64 = 15 * 60;
const MAXIMUM_CREDENTIAL_BYTES: usize = 1_024;
const TOKEN_BYTES: usize = 32;
const ADMIN_TOKEN_COMPARISON_DOMAIN: &[u8] = b"carrack.operator-credential.v1\0";

pub(crate) const OPERATOR_SUBJECT: &str = "operator";

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
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
    let configured = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    if !canonical_token(&configured) {
        return Err(worker::Error::RustError(
            "CARRACK_ADMIN_TOKEN must encode exactly 32 bytes".to_owned(),
        ));
    }
    let candidate = if credentials.password.len() <= MAXIMUM_CREDENTIAL_BYTES {
        credentials.password.as_str()
    } else {
        ""
    };
    if !credential_matches(candidate, &configured) {
        return Response::error("invalid credentials", 401);
    }

    let token = random_token()?;
    let verifier = token_verifier(&token).ok_or_else(|| {
        worker::Error::RustError("generated an invalid operator session token".to_owned())
    })?;
    let now = now_seconds();
    let expires_at = now + SESSION_LIFETIME_SECONDS;
    let database = env.d1(DATABASE_BINDING)?;
    let ip = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_default();
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

    let credentials = request.json::<LoginRequest>().await?;
    let configured = env.secret(ADMIN_TOKEN_BINDING)?.to_string();
    let candidate = if credentials.password.len() <= MAXIMUM_CREDENTIAL_BYTES {
        credentials.password.as_str()
    } else {
        ""
    };
    if !canonical_token(&configured) || !credential_matches(candidate, &configured) {
        return Response::error("invalid credentials", 401);
    }

    let token = random_token()?;
    let verifier = token_verifier(&token).ok_or_else(|| {
        worker::Error::RustError("generated an invalid configuration session token".to_owned())
    })?;
    let now = now_seconds();
    let expires_at = now + CONFIGURATION_SESSION_LIFETIME_SECONDS;
    let database = env.d1(DATABASE_BINDING)?;
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

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && !value.is_empty()).then_some(value)
    })
}

fn secure_cookie(env: &Env) -> bool {
    env.var("CARRACK_ENVIRONMENT")
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
    use super::{canonical_token, cookie_value, credential_matches, token_verifier};

    const TOKEN: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

    #[test]
    fn accepts_only_canonical_256_bit_credentials() {
        assert!(canonical_token(TOKEN));
        assert!(!canonical_token("short"));
        assert!(!canonical_token(&format!("{TOKEN}=")));
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
            cookie_value("theme=dark; carrack_session=token; x=1", "carrack_session"),
            Some("token")
        );
        assert_eq!(token_verifier(TOKEN).as_deref().map(str::len), Some(64));
        assert!(token_verifier("invalid").is_none());
    }
}
