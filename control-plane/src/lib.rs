//! Carrack's Cloudflare control plane.
//!
//! The Worker serves metadata and the web console. Payload bytes always move
//! directly between Carrack agents and storage providers.

mod clients;
pub mod keys;
mod manifest_archive;
mod manifests;
mod operations;
pub mod protocol;
mod publication;
mod restoration;
mod telemetry;

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use worker::{
    Context, D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, Router, event,
    wasm_bindgen::JsValue,
};

const SESSION_COOKIE: &str = "carrack_session";
const SESSION_LIFETIME_SECONDS: u64 = 12 * 60 * 60;
const MAXIMUM_PASSWORD_BYTES: usize = 1_024;
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ip90n1xsUQEay9O8cV4YhQ$iDsJkzgRGFO44Tlu6RRg7NpZFPp4PMMnKhF12B/RZW8";

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct HealthResponse {
    service: &'static str,
    transfer_mode: &'static str,
    mode: String,
    incarnation: String,
    revision: u64,
    external_maintenance: bool,
    mutations_allowed: bool,
}

#[derive(Deserialize, Serialize)]
struct ControlStateRow {
    incarnation: String,
    mode: String,
    revision: u64,
    recovered_at: Option<u64>,
}

#[derive(Deserialize)]
struct RecoveryTransitionRequest {
    incarnation: String,
    expected_revision: u64,
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

#[derive(Deserialize)]
struct AdminCredentialRow {
    password_hash: String,
}

#[derive(Deserialize, Serialize)]
struct SummaryRow {
    operations: u64,
    objects: u64,
    packs: u64,
    verified_locations: u64,
}

#[derive(Deserialize, Serialize)]
struct LiveComponentRow {
    component_id: String,
    operation_id: String,
    operation_kind: String,
    operation_phase: String,
    component_kind: String,
    component_state: String,
    client_name: Option<String>,
    useful_bytes_total: Option<u64>,
    useful_bytes_verified: u64,
    wire_bytes_read: u64,
    wire_bytes_written: u64,
    retry_count: u64,
    throttle_count: u64,
    last_sample_at: Option<u64>,
    rate_1m_bps: f64,
    rate_5m_bps: f64,
    rate_15m_bps: f64,
    lifetime_active_bps: f64,
}

#[derive(Serialize)]
struct LiveComponentsResponse {
    observed_at: u64,
    components: Vec<LiveComponentRow>,
}

/// Handles a Cloudflare Worker fetch event.
///
/// # Errors
///
/// Returns a Worker error when a binding, request body, cryptographic
/// operation, D1 query, or response serialization fails.
#[event(fetch)]
#[allow(
    clippy::too_many_lines,
    reason = "the fetch entrypoint keeps the complete HTTP route table visible"
)]
pub async fn main(request: Request, env: Env, _context: Context) -> Result<Response> {
    if !request.path().starts_with("/api/") {
        return env.assets("ASSETS")?.fetch_request(request).await;
    }

    Router::new()
        .get_async("/api/health", |_, context| async move {
            health(&context.env).await
        })
        .post_async("/api/auth/login", |mut request, context| async move {
            login(&mut request, &context.env).await
        })
        .get("/api/auth/session", |request, context| {
            session(&request, &context.env)
        })
        .post("/api/auth/logout", |_, _| logout())
        .post_async("/api/clients", |mut request, context| async move {
            if read_session(&request, &context.env)?.is_none() {
                return Response::error("authentication required", 401);
            }

            clients::create(&mut request, &context.env).await
        })
        .get_async("/api/client/session", |request, context| async move {
            match clients::authenticate(&request, &context.env).await? {
                Some(client) => Response::from_json(&client),
                None => Response::error("client authentication required", 401),
            }
        })
        .post_async(
            "/api/v1/recovery-manifests/stage",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                manifest_archive::stage(&mut request, &context.env, &client).await
            },
        )
        .post_async("/api/v1/operations", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            operations::create(&mut request, &context.env, &client).await
        })
        .post_async("/api/v1/restores", |mut request, context| async move {
            if external_maintenance(&context.env) {
                return Response::error("control-plane mutations are disabled", 409);
            }

            let Some(client) = clients::authenticate(&request, &context.env).await? else {
                return Response::error("client authentication required", 401);
            };

            restoration::create(&mut request, &context.env, &client).await
        })
        .post_async(
            "/api/v1/restores/:id/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::claim(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/restores/:id/complete",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::complete(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/restores/:id/manifest",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::fetch_manifest(
                    &mut request,
                    &context.env,
                    &client,
                    operation_id,
                )
                .await
            },
        )
        .post_async(
            "/api/v1/restores/:id/fail",
            |mut request, context| async move {
                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                restoration::fail(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/operations/:id/claim",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };
                let Some(operation_id) = context.param("id") else {
                    return Response::error("operation ID is required", 400);
                };

                operations::claim(&mut request, &context.env, &client, operation_id).await
            },
        )
        .post_async(
            "/api/v1/imports/publish",
            |mut request, context| async move {
                if external_maintenance(&context.env) {
                    return Response::error("control-plane mutations are disabled", 409);
                }

                let Some(client) = clients::authenticate(&request, &context.env).await? else {
                    return Response::error("client authentication required", 401);
                };

                publication::publish(&mut request, &context.env, &client).await
            },
        )
        .post_async(
            "/api/v1/operations/:id/progress",
            |mut request, context| async move {
                let operation_id = context.param("id").cloned();
                report_progress(&mut request, &context.env, operation_id.as_deref()).await
            },
        )
        .get_async("/api/summary", |request, context| async move {
            summary(&request, &context.env).await
        })
        .get_async("/api/components/live", |request, context| async move {
            live_components(&request, &context.env).await
        })
        .post_async("/api/recovery/begin", |mut request, context| async move {
            begin_recovery(&mut request, &context.env).await
        })
        .post_async(
            "/api/recovery/complete",
            |mut request, context| async move {
                complete_recovery(&mut request, &context.env).await
            },
        )
        .run(request, env)
        .await
}

async fn report_progress(
    request: &mut Request,
    env: &Env,
    operation_id: Option<&str>,
) -> Result<Response> {
    if external_maintenance(env) {
        return Response::error("control-plane mutations are disabled", 409);
    }

    let Some(client) = clients::authenticate(request, env).await? else {
        return Response::error("client authentication required", 401);
    };
    let Some(operation_id) = operation_id else {
        return Response::error("operation ID is required", 400);
    };

    telemetry::report(request, env, &client, operation_id).await
}

async fn health(env: &Env) -> Result<Response> {
    let state = load_control_state(env).await?;
    let external_maintenance = external_maintenance(env);

    Response::from_json(&HealthResponse {
        service: "carrack-control-plane",
        transfer_mode: "direct",
        mutations_allowed: state.mode == "active" && !external_maintenance,
        mode: state.mode,
        incarnation: state.incarnation,
        revision: state.revision,
        external_maintenance,
    })
}

async fn login(request: &mut Request, env: &Env) -> Result<Response> {
    let credentials = request.json::<LoginRequest>().await?;
    let stored_hash = if valid_username(&credentials.username) {
        password_hash(env, &credentials.username).await?
    } else {
        None
    };
    let candidate = if credentials.password.len() <= MAXIMUM_PASSWORD_BYTES {
        credentials.password.as_str()
    } else {
        ""
    };
    let verified = verify_password(
        candidate,
        stored_hash.as_deref().unwrap_or(DUMMY_PASSWORD_HASH),
    );

    if stored_hash.is_none() || !verified {
        return Response::error("invalid credentials", 401);
    }

    let token = create_session(&credentials.username, env)?;
    let mut response = Response::from_json(&SessionResponse {
        authenticated: true,
        username: Some(credentials.username),
    })?;
    response.headers_mut().set(
        "Set-Cookie",
        &format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={SESSION_LIFETIME_SECONDS}"
        ),
    )?;

    Ok(response)
}

async fn password_hash(env: &Env, username: &str) -> Result<Option<String>> {
    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "SELECT password_hash FROM admin_users \
             WHERE username = ?1 AND enabled = 1",
        )
        .bind(&[JsValue::from_str(username)])?
        .first::<AdminCredentialRow>(None)
        .await?;

    Ok(result.map(|row| row.password_hash))
}

fn valid_username(username: &str) -> bool {
    !username.is_empty() && username.len() <= 128
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
             (SELECT COUNT(*) FROM operations) AS operations, \
             (SELECT COUNT(*) FROM objects) AS objects, \
             (SELECT COUNT(*) FROM packs) AS packs, \
             (SELECT COUNT(*) FROM locations WHERE state IN ('verified', 'available')) AS verified_locations",
        )
        .first::<SummaryRow>(None)
        .await?;

    match result {
        Some(value) => Response::from_json(&value),
        None => Response::error("summary query returned no row", 500),
    }
}

async fn live_components(request: &Request, env: &Env) -> Result<Response> {
    if read_session(request, env)?.is_none() {
        return Response::error("authentication required", 401);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let query = database.prepare(
        "WITH recent_rates AS (\
             SELECT component_id, \
                    1.0e9 * SUM(CASE WHEN bucket_start >= unixepoch() - 60 \
                                     THEN useful_bytes_verified_delta ELSE 0 END) / \
                        NULLIF(SUM(CASE WHEN bucket_start >= unixepoch() - 60 \
                                        THEN active_nanoseconds_delta ELSE 0 END), 0) AS rate_1m_bps, \
                    1.0e9 * SUM(CASE WHEN bucket_start >= unixepoch() - 300 \
                                     THEN useful_bytes_verified_delta ELSE 0 END) / \
                        NULLIF(SUM(CASE WHEN bucket_start >= unixepoch() - 300 \
                                        THEN active_nanoseconds_delta ELSE 0 END), 0) AS rate_5m_bps, \
                    1.0e9 * SUM(useful_bytes_verified_delta) / \
                        NULLIF(SUM(active_nanoseconds_delta), 0) AS rate_15m_bps \
             FROM telemetry_minute_buckets \
             WHERE bucket_start >= unixepoch() - 900 \
             GROUP BY component_id\
         ) \
         SELECT component.id AS component_id, \
                operation.id AS operation_id, \
                operation.kind AS operation_kind, \
                operation.phase AS operation_phase, \
                component.component_kind AS component_kind, \
                component.state AS component_state, \
                client.name AS client_name, \
                component.useful_bytes_total AS useful_bytes_total, \
                component.useful_bytes_verified AS useful_bytes_verified, \
                component.wire_bytes_read AS wire_bytes_read, \
                component.wire_bytes_written AS wire_bytes_written, \
                component.retry_count AS retry_count, \
                component.throttle_count AS throttle_count, \
                component.last_sample_at AS last_sample_at, \
                COALESCE(recent_rates.rate_1m_bps, 0.0) AS rate_1m_bps, \
                COALESCE(recent_rates.rate_5m_bps, 0.0) AS rate_5m_bps, \
                COALESCE(recent_rates.rate_15m_bps, 0.0) AS rate_15m_bps, \
                COALESCE(1.0e9 * component.useful_bytes_verified / \
                         NULLIF(component.active_nanoseconds, 0), 0.0) AS lifetime_active_bps \
         FROM operation_components AS component \
         JOIN operations AS operation ON operation.id = component.operation_id \
         LEFT JOIN clients AS client ON client.id = component.client_id \
         LEFT JOIN recent_rates ON recent_rates.component_id = component.id \
         WHERE component.state IN ('pending', 'running', 'stalled', 'verifying') \
         ORDER BY component.updated_at DESC \
         LIMIT 200",
    );
    let result = query.all().await?;
    let components = result.results::<LiveComponentRow>()?;

    Response::from_json(&LiveComponentsResponse {
        observed_at: current_unix_seconds(),
        components,
    })
}

async fn begin_recovery(request: &mut Request, env: &Env) -> Result<Response> {
    if read_session(request, env)?.is_none() {
        return Response::error("authentication required", 401);
    }

    if !external_maintenance(env) {
        return Response::error("external maintenance mode is required", 409);
    }

    let transition = request.json::<RecoveryTransitionRequest>().await?;
    if protocol::validate_incarnation(&transition.incarnation).is_err() {
        return Response::error("invalid recovery incarnation", 400);
    }

    let expected_revision = d1_integer(transition.expected_revision)?;
    let now = d1_integer(current_unix_seconds())?;
    let database = env.d1("CARRACK_INDEX")?;
    let statements =
        recovery_statements(&database, &transition.incarnation, &expected_revision, &now)?;
    let results = database.batch(statements).await?;
    let state_changed = results
        .first()
        .and_then(|result| result.meta().ok().flatten())
        .and_then(|metadata| metadata.changes)
        == Some(1);
    let state = load_control_state(env).await?;

    if !state_changed && (state.incarnation != transition.incarnation || state.mode != "recovering")
    {
        return Response::error("recovery state changed concurrently", 409);
    }

    Response::from_json(&state)
}

fn recovery_statements(
    database: &D1Database,
    incarnation: &str,
    expected_revision: &str,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let state_update = database
        .prepare(
            "UPDATE control_plane_state \
             SET incarnation = ?1, mode = 'recovering', revision = revision + 1, \
                 recovered_at = ?2, updated_at = ?2 \
             WHERE singleton = 1 AND revision = ?3 AND incarnation != ?1",
        )
        .bind(&[
            JsValue::from_str(incarnation),
            JsValue::from_str(now),
            JsValue::from_str(expected_revision),
        ])?;
    let fail_components = database
        .prepare(
            "UPDATE operation_components \
             SET state = 'failed', revision = revision + 1, finished_at = ?1, updated_at = ?1 \
             WHERE state IN ('pending', 'running', 'stalled', 'verifying') \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let supersede_attempts = database
        .prepare(
            "UPDATE operation_attempts \
             SET state = 'superseded', finished_at = ?1 \
             WHERE state = 'running' AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let release_leases = database
        .prepare(
            "UPDATE leases SET released_at = ?1, updated_at = ?1 \
             WHERE released_at IS NULL AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let fail_gc = database
        .prepare(
            "UPDATE gc_epochs SET state = 'failed', updated_at = ?1 \
             WHERE state IN ('marking', 'grace', 'sweeping') AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;
    let fail_operations = database
        .prepare(
            "UPDATE operations \
             SET state = CASE WHEN state = 'planned' THEN 'cancelled' ELSE 'failed' END, \
                 phase = 'control_plane_recovered', \
                 error_code = 'control_plane_recovered', \
                 error_message = 'operation invalidated by control-plane recovery', \
                 revision = revision + 1, finished_at = ?1, updated_at = ?1 \
             WHERE state IN ('planned', 'running', 'verifying', 'committing') \
               AND incarnation != ?2 \
               AND EXISTS (SELECT 1 FROM control_plane_state \
                           WHERE singleton = 1 AND incarnation = ?2)",
        )
        .bind(&[JsValue::from_str(now), JsValue::from_str(incarnation)])?;

    Ok(vec![
        state_update,
        fail_components,
        supersede_attempts,
        release_leases,
        fail_gc,
        fail_operations,
    ])
}

async fn complete_recovery(request: &mut Request, env: &Env) -> Result<Response> {
    if read_session(request, env)?.is_none() {
        return Response::error("authentication required", 401);
    }

    if !external_maintenance(env) {
        return Response::error("external maintenance mode is required", 409);
    }

    let transition = request.json::<RecoveryTransitionRequest>().await?;
    if protocol::validate_incarnation(&transition.incarnation).is_err() {
        return Response::error("invalid recovery incarnation", 400);
    }

    let expected_revision = d1_integer(transition.expected_revision)?;
    let now = d1_integer(current_unix_seconds())?;
    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "UPDATE control_plane_state \
             SET mode = 'active', revision = revision + 1, updated_at = ?1 \
             WHERE singleton = 1 AND mode = 'recovering' \
               AND incarnation = ?2 AND revision = ?3",
        )
        .bind(&[
            JsValue::from_str(&now),
            JsValue::from_str(&transition.incarnation),
            JsValue::from_str(&expected_revision),
        ])?
        .run()
        .await?;
    let changed = result
        .meta()?
        .and_then(|metadata| metadata.changes)
        .unwrap_or_default();
    let state = load_control_state(env).await?;

    if changed != 1 && (state.incarnation != transition.incarnation || state.mode != "active") {
        return Response::error("recovery state changed concurrently", 409);
    }

    Response::from_json(&state)
}

async fn load_control_state(env: &Env) -> Result<ControlStateRow> {
    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "SELECT incarnation, mode, revision, recovered_at \
             FROM control_plane_state WHERE singleton = 1",
        )
        .first::<ControlStateRow>(None)
        .await?;

    result.ok_or_else(|| worker::Error::RustError("control-plane state is missing".to_owned()))
}

fn external_maintenance(env: &Env) -> bool {
    let configured = env
        .var("CARRACK_MAINTENANCE")
        .map(|value| value.to_string())
        .or_else(|_| {
            env.secret("CARRACK_MAINTENANCE")
                .map(|value| value.to_string())
        });

    configured.is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "enabled"))
}

fn d1_integer(value: u64) -> Result<String> {
    if value > i64::MAX as u64 {
        return Err(worker::Error::RustError(
            "integer exceeds D1's signed range".to_owned(),
        ));
    }

    Ok(value.to_string())
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
    use super::{DUMMY_PASSWORD_HASH, cookie_value, valid_username, verify_password};

    #[test]
    fn extracts_named_cookie() {
        assert_eq!(
            cookie_value("theme=dark; carrack_session=abc.def", "carrack_session"),
            Some("abc.def")
        );
    }

    #[test]
    fn validates_admin_username_bounds() {
        assert!(valid_username("draven"));
        assert!(!valid_username(""));
        assert!(!valid_username(&"a".repeat(129)));
    }

    #[test]
    fn dummy_hash_exercises_argon2_for_unknown_users() {
        assert!(verify_password("invalid-login", DUMMY_PASSWORD_HASH));
        assert!(!verify_password("wrong-password", DUMMY_PASSWORD_HASH));
    }
}
