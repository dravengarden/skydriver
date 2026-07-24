use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;
use worker::{
    Date, Delay, Env, Fetch, Headers, Method, Request, RequestInit, Response, Result,
    wasm_bindgen::JsValue,
};

use super::operator_sessions as session;

const ISSUER: &str = "https://cardea.stormbird.xyz";
const CLIENT_KEY_ID_BINDING: &str = "CARDEA_CLIENT_KEY_ID";
const CLIENT_PRIVATE_KEY_BINDING: &str = "CARDEA_CLIENT_PRIVATE_KEY";
const STATE_KEY_BINDING: &str = "CARDEA_STATE_KEY";
const EMAIL_RATE_LIMIT_BINDING: &str = "SKYDRIVER_CARDEA_EMAIL_RATE_LIMITER";
const STATE_COOKIE: &str = "skydriver_cardea_oidc";
const STATE_LIFETIME_SECONDS: u64 = 5 * 60;
const LOGIN_ACTION: &str = "session.create";
const ERROR_RETRY_SECONDS: u64 = 60;
const SESSION_POLICY_SCHEMA: &str = "dravengarden.cardea.consumer-session-policy/v1";
const MINIMUM_SESSION_LIFETIME_SECONDS: u64 = 5 * 60;
const MAXIMUM_SESSION_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
const STATUS_LONG_POLL_ATTEMPTS: usize = 20;
const STATUS_LONG_POLL_INTERVAL: Duration = Duration::from_millis(500);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy)]
struct Configuration {
    client_id: &'static str,
    display_environment: &'static str,
    resource: &'static str,
    redirect_uri: &'static str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalLoginCookie {
    approval_id: String,
    state: String,
    issued_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalResponse {
    schema: String,
    approval_id: String,
    client_id: String,
    action: String,
    resource: String,
    status: String,
    created_at: u64,
    expires_at: u64,
    decided_at: Option<u64>,
    user_url: String,
    exchange_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalExchangeResponse {
    schema: String,
    approval_id: String,
    client_id: String,
    subject_id: String,
    action: String,
    resource: String,
    state: String,
    decided_at: u64,
    consumed_at: u64,
    session_policy: SessionPolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionPolicy {
    schema: String,
    lifetime_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApprovalStartRequest {
    email: String,
    device_id: String,
}

pub(crate) async fn begin_approval(request: &mut Request, env: &Env) -> Result<Response> {
    let configuration = configuration(env)?;
    let source_ip = request
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "unknown".to_owned());
    let outcome = env
        .rate_limiter(EMAIL_RATE_LIMIT_BINDING)?
        .limit(format!("cardea-email:{source_ip}"))
        .await?;
    if !outcome.success {
        return approval_start_error(429);
    }
    let Ok(start) = request.json::<ApprovalStartRequest>().await else {
        return approval_start_error(400);
    };
    let cf = request.cf();
    let observed = cardea_oidc_client::ObservedRequestContext {
        source_ip: Some(source_ip),
        country: cf.and_then(worker::Cf::country),
        region: cf.and_then(worker::Cf::region),
        city: cf.and_then(worker::Cf::city),
        edge_request_id: request.headers().get("CF-Ray")?,
        edge_colo: cf.map(worker::Cf::colo),
        continuity_device_id: Some(start.device_id),
    };
    let request_started_at = now_seconds();
    let state = random_value()?;
    let idempotency_key = random_value()?;
    let access_token = client_access_token(env, &configuration, request_started_at).await?;
    let request_body = cardea_oidc_client::email_login_approval_request_with_context(
        &idempotency_key,
        "SkyDriver",
        configuration.display_environment,
        configuration.resource,
        configuration.redirect_uri,
        &state,
        &start.email,
        STATE_LIFETIME_SECONDS,
        &observed,
        None,
    )
    .ok_or_else(|| worker::Error::RustError("invalid Cardea approval request".into()));
    let Ok(mut request_body) = request_body else {
        return approval_start_error(400);
    };
    request_body
        .display
        .facts
        .retain(|fact| fact.label != "Email");
    let body = serde_json::to_value(request_body)?;
    let mut approval = cardea_json_request(
        Method::Post,
        "/v1/approval-requests",
        &access_token,
        Some(&body),
    )
    .await?;
    if !matches!(approval.status_code(), 200 | 201) {
        return approval_start_error(503);
    }
    let approval: ApprovalResponse = approval.json().await?;
    let response_received_at = now_seconds();
    if !valid_pending_approval(
        &approval,
        &configuration,
        &state,
        request_started_at,
        response_received_at,
    ) {
        return Response::error("Cardea approval invalid", 503);
    }
    let cookie = encode_approval_cookie(
        &ApprovalLoginCookie {
            approval_id: approval.approval_id,
            state,
            issued_at: request_started_at,
        },
        env,
    )?;
    let mut response = Response::from_json(&serde_json::json!({
        "status": "pending",
        "expires_at": approval.expires_at
    }))?;
    response.headers_mut().set("Cache-Control", "no-store")?;
    response.headers_mut().set(
        "Set-Cookie",
        &approval_cookie(&cookie, STATE_LIFETIME_SECONDS),
    )?;
    Ok(response)
}

fn approval_start_error(status: u16) -> Result<Response> {
    let mut response = Response::error("Verification email unavailable", status)?;
    response.headers_mut().set("Cache-Control", "no-store")?;
    response
        .headers_mut()
        .set("Retry-After", &ERROR_RETRY_SECONDS.to_string())?;
    Ok(response)
}

pub(crate) async fn approval_status(request: &Request, env: &Env) -> Result<Response> {
    let configuration = configuration(env)?;
    let Some(encoded) = cookie_value(request, STATE_COOKIE)? else {
        return Response::error("approval login missing", 401);
    };
    let transaction = decode_approval_cookie(&encoded, env)?;
    let now = now_seconds();
    if transaction.issued_at > now || now - transaction.issued_at >= STATE_LIFETIME_SECONDS {
        return terminal_status("expired");
    }
    let access_token = client_access_token(env, &configuration, now).await?;
    let path = format!("/v1/approval-requests/{}", transaction.approval_id);
    for attempt in 0..STATUS_LONG_POLL_ATTEMPTS {
        let mut response = cardea_json_request(Method::Get, &path, &access_token, None).await?;
        if response.status_code() != 200 {
            return Response::error("Cardea approval unavailable", 503);
        }
        let approval: ApprovalResponse = response.json().await?;
        if !valid_owned_approval(&approval, &configuration, &transaction) {
            return Response::error("Cardea approval invalid", 503);
        }
        match approval.status.as_str() {
            "pending" if attempt + 1 < STATUS_LONG_POLL_ATTEMPTS => {
                Delay::from(STATUS_LONG_POLL_INTERVAL).await;
            }
            "pending" => {
                return Response::from_json(&serde_json::json!({
                    "status": "pending",
                    "expires_at": approval.expires_at
                }));
            }
            "approved" => {
                return complete_approval(
                    request,
                    env,
                    &configuration,
                    &access_token,
                    &transaction,
                    approval,
                )
                .await;
            }
            "denied" | "cancelled" | "expired" => return terminal_status(&approval.status),
            _ => return Response::error("Cardea approval invalid", 503),
        }
    }
    Response::error("Cardea approval unavailable", 503)
}

async fn client_access_token(env: &Env, configuration: &Configuration, now: u64) -> Result<String> {
    let token_endpoint = format!("{ISSUER}/oauth2/token");
    let assertion = cardea_oidc_client::client_assertion(
        &secret_bytes(env, CLIENT_PRIVATE_KEY_BINDING)?,
        &env.var(CLIENT_KEY_ID_BINDING)?.to_string(),
        configuration.client_id,
        &token_endpoint,
        &random_value()?,
        now,
    )
    .ok_or_else(|| worker::Error::RustError("Cardea assertion generation failed".to_owned()))?;
    let body = serde_urlencoded::to_string([
        ("grant_type", "client_credentials"),
        ("client_id", configuration.client_id),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion.as_str()),
    ])
    .map_err(|_| worker::Error::RustError("Cardea token request encoding failed".to_owned()))?;
    let headers = Headers::new();
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;
    headers.set("Accept", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body)));
    let mut response = Fetch::Request(Request::new_with_init(&token_endpoint, &init)?)
        .send()
        .await?;
    if response.status_code() != 200 {
        return Err(worker::Error::RustError(
            "Cardea client authentication rejected".to_owned(),
        ));
    }
    let token: ClientTokenResponse = response.json().await?;
    if token.token_type != "Bearer" || token.expires_in != 300 || token.access_token.len() > 512 {
        return Err(worker::Error::RustError(
            "Cardea client token invalid".to_owned(),
        ));
    }
    Ok(token.access_token)
}

async fn cardea_json_request(
    method: Method,
    path: &str,
    access_token: &str,
    body: Option<&serde_json::Value>,
) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Accept", "application/json")?;
    headers.set("Authorization", &format!("Bearer {access_token}"))?;
    if body.is_some() {
        headers.set("Content-Type", "application/json")?;
    }
    let mut init = RequestInit::new();
    init.with_method(method).with_headers(headers);
    if let Some(body) = body {
        init.with_body(Some(JsValue::from_str(&serde_json::to_string(body)?)));
    }
    Fetch::Request(Request::new_with_init(&format!("{ISSUER}{path}"), &init)?)
        .send()
        .await
}

fn valid_pending_approval(
    approval: &ApprovalResponse,
    configuration: &Configuration,
    state: &str,
    request_started_at: u64,
    response_received_at: u64,
) -> bool {
    approval.schema == "dravengarden.cardea.approval-request/v1"
        && approval.client_id == configuration.client_id
        && approval.action == LOGIN_ACTION
        && approval.resource == configuration.resource
        && approval.status == "pending"
        && approval.approval_id.len() == 43
        && approval.created_at >= request_started_at
        && approval.created_at <= response_received_at
        && approval.expires_at > response_received_at
        && approval.decided_at.is_none()
        && approval.exchange_code.is_none()
        && approval.user_url.starts_with("/approve/")
        && state.len() == 43
}

fn valid_owned_approval(
    approval: &ApprovalResponse,
    configuration: &Configuration,
    transaction: &ApprovalLoginCookie,
) -> bool {
    approval.schema == "dravengarden.cardea.approval-request/v1"
        && approval.approval_id == transaction.approval_id
        && approval.client_id == configuration.client_id
        && approval.action == LOGIN_ACTION
        && approval.resource == configuration.resource
}

async fn complete_approval(
    request: &Request,
    env: &Env,
    configuration: &Configuration,
    access_token: &str,
    transaction: &ApprovalLoginCookie,
    approval: ApprovalResponse,
) -> Result<Response> {
    let Some(code) = approval.exchange_code else {
        return Response::error("Cardea approval invalid", 503);
    };
    let body = serde_json::json!({
        "code": code,
        "redirect_uri": configuration.redirect_uri,
        "session_policy": SESSION_POLICY_SCHEMA,
    });
    let mut response = cardea_json_request(
        Method::Post,
        "/v1/approval-exchanges",
        access_token,
        Some(&body),
    )
    .await?;
    if response.status_code() != 200 {
        return Response::error("Cardea approval exchange rejected", 503);
    }
    let exchange: ApprovalExchangeResponse = response.json().await?;
    if exchange.schema != "dravengarden.cardea.approval-exchange/v1"
        || exchange.approval_id != transaction.approval_id
        || exchange.client_id != configuration.client_id
        || exchange.subject_id != "draven"
        || exchange.action != LOGIN_ACTION
        || exchange.resource != configuration.resource
        || exchange.state != transaction.state
        || exchange.decided_at < transaction.issued_at
        || exchange.consumed_at < exchange.decided_at
        || exchange.session_policy.schema != SESSION_POLICY_SCHEMA
        || !(MINIMUM_SESSION_LIFETIME_SECONDS..=MAXIMUM_SESSION_LIFETIME_SECONDS)
            .contains(&exchange.session_policy.lifetime_seconds)
    {
        return Response::error("Cardea approval exchange invalid", 503);
    }
    let mut session = session::create_browser_session_with_lifetime(
        request,
        env,
        exchange.session_policy.lifetime_seconds,
    )
    .await?;
    session
        .headers_mut()
        .append("Set-Cookie", &clear_approval_cookie())?;
    Ok(session)
}

fn terminal_status(status: &str) -> Result<Response> {
    let mut response = Response::from_json(&serde_json::json!({ "status": status }))?;
    response
        .headers_mut()
        .append("Set-Cookie", &clear_approval_cookie())?;
    Ok(response)
}

fn encode_approval_cookie(state: &ApprovalLoginCookie, env: &Env) -> Result<String> {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(state)?);
    let key = secret_bytes(env, STATE_KEY_BINDING)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| worker::Error::RustError("Cardea state key invalid".to_owned()))?;
    mac.update(b"skydriver.cardea.approval-login.v1\0");
    mac.update(payload.as_bytes());
    Ok(format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn decode_approval_cookie(value: &str, env: &Env) -> Result<ApprovalLoginCookie> {
    let (payload, signature) = value
        .split_once('.')
        .ok_or_else(|| worker::Error::RustError("Cardea approval cookie invalid".to_owned()))?;
    let key = secret_bytes(env, STATE_KEY_BINDING)?;
    let mut mac = HmacSha256::new_from_slice(&key)
        .map_err(|_| worker::Error::RustError("Cardea state key invalid".to_owned()))?;
    mac.update(b"skydriver.cardea.approval-login.v1\0");
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| worker::Error::RustError("Cardea approval cookie invalid".to_owned()))?;
    mac.verify_slice(&signature)
        .map_err(|_| worker::Error::RustError("Cardea approval cookie invalid".to_owned()))?;
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| worker::Error::RustError("Cardea approval cookie invalid".to_owned()))?,
    )
    .map_err(Into::into)
}

fn approval_cookie(value: &str, maximum_age: u64) -> String {
    format!(
        "{STATE_COOKIE}={value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={maximum_age}"
    )
}

fn clear_approval_cookie() -> String {
    approval_cookie("", 0)
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

fn configuration(env: &Env) -> Result<Configuration> {
    match env.var("SKYDRIVER_ENVIRONMENT")?.to_string().as_str() {
        "dev" => Ok(Configuration {
            client_id: "skydriver-dev",
            display_environment: "Development",
            resource: "https://dev.skydriver.stormbird.xyz",
            redirect_uri: "https://dev.skydriver.stormbird.xyz/api/auth/cardea/callback",
        }),
        "prod" => Ok(Configuration {
            client_id: "skydriver-prod",
            display_environment: "Production",
            resource: "https://skydriver.stormbird.xyz",
            redirect_uri: "https://skydriver.stormbird.xyz/api/auth/cardea/callback",
        }),
        _ => Err(worker::Error::RustError(
            "Cardea OIDC is not configured for this environment".to_owned(),
        )),
    }
}
fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_approval(created_at: u64, expires_at: u64) -> ApprovalResponse {
        let configuration = configuration_for_test();
        ApprovalResponse {
            schema: "dravengarden.cardea.approval-request/v1".to_owned(),
            approval_id: "a".repeat(43),
            client_id: configuration.client_id.to_owned(),
            action: LOGIN_ACTION.to_owned(),
            resource: configuration.resource.to_owned(),
            status: "pending".to_owned(),
            created_at,
            expires_at,
            decided_at: None,
            user_url: format!("/approve/{}", "a".repeat(43)),
            exchange_code: None,
        }
    }

    #[test]
    fn pending_approval_accepts_network_delay_across_seconds() {
        let approval = pending_approval(1_002, 1_302);
        let configuration = configuration_for_test();
        assert!(valid_pending_approval(
            &approval,
            &configuration,
            &"s".repeat(43),
            1_000,
            1_004,
        ));
    }

    #[test]
    fn pending_approval_rejects_creation_outside_request_window() {
        let before_request = pending_approval(999, 1_299);
        let after_response = pending_approval(1_005, 1_305);
        let configuration = configuration_for_test();
        assert!(!valid_pending_approval(
            &before_request,
            &configuration,
            &"s".repeat(43),
            1_000,
            1_004,
        ));
        assert!(!valid_pending_approval(
            &after_response,
            &configuration,
            &"s".repeat(43),
            1_000,
            1_004,
        ));
    }

    fn configuration_for_test() -> Configuration {
        Configuration {
            client_id: "skydriver-dev",
            display_environment: "Development",
            resource: "https://dev.skydriver.stormbird.xyz",
            redirect_uri: "https://dev.skydriver.stormbird.xyz/api/auth/cardea/callback",
        }
    }
}
