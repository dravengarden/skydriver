//! Carrack's Cloudflare control plane.
//!
//! The Worker serves metadata and the web console. Payload bytes always move
//! directly between Carrack agents and storage providers.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::{Context, Date, Env, Request, Response, Result, Router, event};

const SESSION_COOKIE: &str = "carrack_session";
const SESSION_LIFETIME_SECONDS: u64 = 12 * 60 * 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    transfer_mode: &'static str,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct SessionResponse {
    authenticated: bool,
    username: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    subject: String,
    expires_at: u64,
}

#[derive(Deserialize, Serialize)]
struct SummaryRow {
    jobs: u64,
    objects: u64,
    blocks: u64,
    replicas: u64,
}

/// Handles a Cloudflare Worker fetch event.
///
/// # Errors
///
/// Returns a Worker error when a binding, request body, cryptographic
/// operation, D1 query, or response serialization fails.
#[event(fetch)]
pub async fn main(request: Request, env: Env, _context: Context) -> Result<Response> {
    if !request.path().starts_with("/api/") {
        return env.assets("ASSETS")?.fetch_request(request).await;
    }

    Router::new()
        .get("/api/health", |_, _| {
            Response::from_json(&HealthResponse {
                service: "carrack-control-plane",
                transfer_mode: "direct",
            })
        })
        .post_async("/api/auth/login", |mut request, context| async move {
            login(&mut request, &context.env).await
        })
        .get("/api/auth/session", |request, context| {
            session(&request, &context.env)
        })
        .post("/api/auth/logout", |_, _| logout())
        .get_async("/api/summary", |request, context| async move {
            summary(&request, &context.env).await
        })
        .run(request, env)
        .await
}

async fn login(request: &mut Request, env: &Env) -> Result<Response> {
    let credentials = request.json::<LoginRequest>().await?;
    let configured_username = env.secret("CARRACK_ADMIN_USERNAME")?.to_string();
    let configured_hash = env.secret("CARRACK_ADMIN_PASSWORD_HASH")?.to_string();

    if credentials.username != configured_username
        || !verify_password(&credentials.password, &configured_hash)
    {
        return Response::error("invalid credentials", 401);
    }

    let token = create_session(&configured_username, env)?;
    let mut response = Response::from_json(&SessionResponse {
        authenticated: true,
        username: Some(configured_username),
    })?;
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_LIFETIME_SECONDS}"
        ),
    )?;

    Ok(response)
}

fn session(request: &Request, env: &Env) -> Result<Response> {
    let claims = read_session(request, env)?;

    Response::from_json(&SessionResponse {
        authenticated: claims.is_some(),
        username: claims.map(|value| value.subject),
    })
}

fn logout() -> Result<Response> {
    let mut response = Response::from_json(&SessionResponse {
        authenticated: false,
        username: None,
    })?;
    response.headers_mut().set(
        "Set-Cookie",
        &format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"),
    )?;

    Ok(response)
}

async fn summary(request: &Request, env: &Env) -> Result<Response> {
    if read_session(request, env)?.is_none() {
        return Response::error("authentication required", 401);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "SELECT \
             (SELECT COUNT(*) FROM transfer_jobs) AS jobs, \
             (SELECT COUNT(*) FROM logical_objects) AS objects, \
             (SELECT COUNT(*) FROM blocks) AS blocks, \
             (SELECT COUNT(*) FROM replicas) AS replicas",
        )
        .first::<SummaryRow>(None)
        .await?;

    match result {
        Some(value) => Response::from_json(&value),
        None => Response::error("summary query returned no row", 500),
    }
}

fn verify_password(candidate: &str, configured_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(configured_hash) else {
        return false;
    };

    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed_hash)
        .is_ok()
}

fn create_session(username: &str, env: &Env) -> Result<String> {
    let claims = SessionClaims {
        subject: username.to_owned(),
        expires_at: current_unix_seconds() + SESSION_LIFETIME_SECONDS,
    };
    let payload = serde_json::to_vec(&claims)?;
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
    let signature = sign(encoded_payload.as_bytes(), env)?;

    Ok(format!(
        "{encoded_payload}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn read_session(request: &Request, env: &Env) -> Result<Option<SessionClaims>> {
    let Some(cookie_header) = request.headers().get("Cookie")? else {
        return Ok(None);
    };
    let Some(token) = cookie_value(&cookie_header, SESSION_COOKIE) else {
        return Ok(None);
    };
    let Some((payload, signature)) = token.split_once('.') else {
        return Ok(None);
    };
    let Ok(decoded_signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return Ok(None);
    };

    if !verify_signature(payload.as_bytes(), &decoded_signature, env)? {
        return Ok(None);
    }

    let Ok(decoded_payload) = URL_SAFE_NO_PAD.decode(payload) else {
        return Ok(None);
    };
    let Ok(claims) = serde_json::from_slice::<SessionClaims>(&decoded_payload) else {
        return Ok(None);
    };

    if claims.expires_at <= current_unix_seconds() {
        return Ok(None);
    }

    Ok(Some(claims))
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn sign(payload: &[u8], env: &Env) -> Result<Vec<u8>> {
    let key = env.secret("CARRACK_SESSION_KEY")?.to_string();
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(payload);

    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_signature(payload: &[u8], signature: &[u8], env: &Env) -> Result<bool> {
    let key = env.secret("CARRACK_SESSION_KEY")?.to_string();
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    mac.update(payload);

    Ok(mac.verify_slice(signature).is_ok())
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::cookie_value;

    #[test]
    fn extracts_named_cookie() {
        assert_eq!(
            cookie_value("theme=dark; carrack_session=abc.def", "carrack_session"),
            Some("abc.def")
        );
    }
}
