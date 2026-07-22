use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::{
    Date, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result, Url,
    wasm_bindgen::JsValue,
};

use super::operator_sessions as session;

const ISSUER: &str = "https://cardea.stormbird.xyz";
const CLIENT_ID: &str = "skydriver-dev";
const REDIRECT_URI: &str = "https://dev.skydriver.stormbird.xyz/api/auth/cardea/callback";
const CLIENT_KEY_ID_BINDING: &str = "CARDEA_CLIENT_KEY_ID";
const CLIENT_PRIVATE_KEY_BINDING: &str = "CARDEA_CLIENT_PRIVATE_KEY";
const ID_TOKEN_KEY_ID_BINDING: &str = "CARDEA_ID_TOKEN_KEY_ID";
const ID_TOKEN_PUBLIC_KEY_BINDING: &str = "CARDEA_ID_TOKEN_PUBLIC_KEY";
const STATE_KEY_BINDING: &str = "CARDEA_STATE_KEY";
const STATE_COOKIE: &str = "skydriver_cardea_oidc";
const STATE_LIFETIME_SECONDS: u64 = 5 * 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateCookie {
    state: String,
    nonce: String,
    verifier: String,
    issued_at: u64,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    id_token: String,
}

pub(crate) fn start(env: &Env) -> Result<Response> {
    require_development(env)?;
    let now = now_seconds();
    let state = random_value()?;
    let nonce = random_value()?;
    let verifier = random_value()?;
    let challenge = cardea_oidc_client::pkce_challenge(&verifier)
        .ok_or_else(|| worker::Error::RustError("Cardea PKCE generation failed".to_owned()))?;
    let cookie = encode_state(
        &StateCookie {
            state: state.clone(),
            nonce: nonce.clone(),
            verifier,
            issued_at: now,
        },
        env,
    )?;
    let mut authorization = Url::parse(&format!("{ISSUER}/oauth2/authorize"))?;
    authorization
        .query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let mut response = Response::empty()?.with_status(302);
    response
        .headers_mut()
        .set("Location", authorization.as_str())?;
    response.headers_mut().set("Cache-Control", "no-store")?;
    response
        .headers_mut()
        .set("Set-Cookie", &state_cookie(&cookie, STATE_LIFETIME_SECONDS))?;
    Ok(response)
}

pub(crate) async fn callback(request: &Request, env: &Env) -> Result<Response> {
    require_development(env)?;
    let result = callback_inner(request, env).await;
    match result {
        Ok(session_cookie) => {
            let mut response = Response::empty()?.with_status(303);
            response.headers_mut().set("Location", "/")?;
            response.headers_mut().set("Cache-Control", "no-store")?;
            response
                .headers_mut()
                .append("Set-Cookie", &clear_state_cookie())?;
            response
                .headers_mut()
                .append("Set-Cookie", &session_cookie)?;
            Ok(response)
        }
        Err(error) => {
            worker::console_error!("Cardea callback rejected: {error}");
            let mut response = Response::empty()?.with_status(303);
            response
                .headers_mut()
                .set("Location", "/?authentication=failed")?;
            response.headers_mut().set("Cache-Control", "no-store")?;
            response
                .headers_mut()
                .set("Set-Cookie", &clear_state_cookie())?;
            Ok(response)
        }
    }
}

async fn callback_inner(request: &Request, env: &Env) -> Result<String> {
    let query: CallbackQuery =
        serde_urlencoded::from_str(request.url()?.query().unwrap_or_default())
            .map_err(|_| worker::Error::RustError("invalid Cardea callback query".to_owned()))?;
    if query.code.len() > 512 || query.state.len() != 43 {
        return Err(worker::Error::RustError(
            "invalid Cardea callback values".to_owned(),
        ));
    }
    let encoded = cookie_value(request, STATE_COOKIE)?
        .ok_or_else(|| worker::Error::RustError("Cardea state cookie missing".to_owned()))?;
    let state = decode_state(&encoded, env)?;
    let now = now_seconds();
    if state.state != query.state
        || state.issued_at > now
        || now - state.issued_at > STATE_LIFETIME_SECONDS
    {
        return Err(worker::Error::RustError("Cardea state mismatch".to_owned()));
    }
    let assertion_id = random_value()?;
    let private_key = secret_bytes(env, CLIENT_PRIVATE_KEY_BINDING)?;
    let key_id = env.var(CLIENT_KEY_ID_BINDING)?.to_string();
    let token_endpoint = format!("{ISSUER}/oauth2/token");
    let assertion = cardea_oidc_client::client_assertion(
        &private_key,
        &key_id,
        CLIENT_ID,
        &token_endpoint,
        &assertion_id,
        now,
    )
    .ok_or_else(|| worker::Error::RustError("Cardea assertion generation failed".to_owned()))?;
    let body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
        ("code", query.code.as_str()),
        ("redirect_uri", REDIRECT_URI),
        ("code_verifier", state.verifier.as_str()),
    ])
    .map_err(|_| worker::Error::RustError("Cardea token request encoding failed".to_owned()))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    headers.set("Accept", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body)));
    let token_request = Request::new_with_init(&token_endpoint, &init)?;
    let mut token_response = Fetch::Request(token_request).send().await?;
    if token_response.status_code() != 200 {
        return Err(worker::Error::RustError(
            "Cardea token exchange rejected".to_owned(),
        ));
    }
    let token: TokenResponse = token_response.json().await?;
    if token.token_type != "Bearer" || token.expires_in != 300 || token.access_token.len() > 512 {
        return Err(worker::Error::RustError(
            "Cardea token response invalid".to_owned(),
        ));
    }
    let public_key = variable_bytes(env, ID_TOKEN_PUBLIC_KEY_BINDING)?;
    let signing_key_id = env.var(ID_TOKEN_KEY_ID_BINDING)?.to_string();
    let identity = cardea_oidc_client::verify_id_token(
        &token.id_token,
        &public_key,
        &signing_key_id,
        ISSUER,
        CLIENT_ID,
        &state.nonce,
        now,
    )
    .ok_or_else(|| worker::Error::RustError("Cardea ID token rejected".to_owned()))?;
    if identity.subject != "draven" {
        return Err(worker::Error::RustError(
            "Cardea subject rejected".to_owned(),
        ));
    }
    let session_response = session::create_browser_session(request, env).await?;
    session::browser_session_cookie(&session_response)?
        .ok_or_else(|| worker::Error::RustError("Skydriver session cookie missing".to_owned()))
}

fn encode_state(state: &StateCookie, env: &Env) -> Result<String> {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(state)?);
    let key = secret_bytes(env, STATE_KEY_BINDING)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| worker::Error::RustError("Cardea state key invalid".to_owned()))?;
    mac.update(b"skydriver.cardea.state.v1\0");
    mac.update(payload.as_bytes());
    Ok(format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn decode_state(value: &str, env: &Env) -> Result<StateCookie> {
    let (payload, signature) = value
        .split_once('.')
        .ok_or_else(|| worker::Error::RustError("Cardea state shape invalid".to_owned()))?;
    let key = secret_bytes(env, STATE_KEY_BINDING)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| worker::Error::RustError("Cardea state key invalid".to_owned()))?;
    mac.update(b"skydriver.cardea.state.v1\0");
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| worker::Error::RustError("Cardea state signature invalid".to_owned()))?;
    mac.verify_slice(&signature)
        .map_err(|_| worker::Error::RustError("Cardea state signature invalid".to_owned()))?;
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| worker::Error::RustError("Cardea state payload invalid".to_owned()))?,
    )
    .map_err(Into::into)
}

fn random_value() -> Result<String> {
    let mut value = [0_u8; 32];
    getrandom::fill(&mut value)
        .map_err(|_| worker::Error::RustError("secure randomness unavailable".to_owned()))?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

fn secret_bytes(env: &Env, binding: &str) -> Result<[u8; 32]> {
    decode_bytes(&env.secret(binding)?.to_string(), binding)
}

fn variable_bytes(env: &Env, binding: &str) -> Result<[u8; 32]> {
    decode_bytes(&env.var(binding)?.to_string(), binding)
}

fn decode_bytes(value: &str, binding: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| worker::Error::RustError(format!("{binding} must encode 32 bytes")))
}

fn cookie_value(request: &Request, name: &str) -> Result<Option<String>> {
    let Some(cookie) = request.headers().get("Cookie")? else {
        return Ok(None);
    };
    let values = cookie
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(candidate, _)| *candidate == name)
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(worker::Error::RustError(
            "duplicate Cardea state cookie".to_owned(),
        ));
    }
    Ok(values.first().map(|value| (*value).to_owned()))
}

fn state_cookie(value: &str, maximum_age: u64) -> String {
    format!(
        "{STATE_COOKIE}={value}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/cardea/callback; Max-Age={maximum_age}"
    )
}

fn clear_state_cookie() -> String {
    state_cookie("", 0)
}
fn require_development(env: &Env) -> Result<()> {
    if env.var("SKYDRIVER_ENVIRONMENT")?.to_string() != "dev" {
        return Err(worker::Error::RustError(
            "Cardea OIDC is not configured for this environment".to_owned(),
        ));
    }
    Ok(())
}
fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}
