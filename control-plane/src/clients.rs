use std::{collections::BTreeMap, fmt::Write as _};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

const TOKEN_BYTES: usize = 32;
const IDENTIFIER_BYTES: usize = 16;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_VERSION_BYTES: usize = 128;
const MAXIMUM_CAPABILITIES: usize = 128;
const MAXIMUM_LABELS: usize = 64;
const MAXIMUM_LABEL_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateClientRequest {
    name: String,
    sdk_version: String,
    capabilities: Vec<String>,
    labels: BTreeMap<String, String>,
    permissions: Vec<PermissionRequest>,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionRequest {
    namespace_id: String,
    role: String,
}

#[derive(Serialize)]
struct CreateClientResponse {
    client_id: String,
    token: String,
    created_at: u64,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct AuthenticatedClient {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) sdk_version: String,
}

pub(crate) async fn create(request: &mut Request, env: &Env) -> Result<Response> {
    let requested = request.json::<CreateClientRequest>().await?;
    if !valid_request(&requested) {
        return Response::error("invalid client registration", 400);
    }

    let now = current_unix_seconds();
    if requested.expires_at.is_some_and(|expiry| expiry <= now) {
        return Response::error("client token expiry must be in the future", 400);
    }

    let client_id = random_hex::<IDENTIFIER_BYTES>()?;
    let verifier_id = random_hex::<IDENTIFIER_BYTES>()?;
    let token = random_token()?;
    let verifier = token_verifier(&token);
    let capabilities = serde_json::to_string(&requested.capabilities)?;
    let labels = serde_json::to_string(&requested.labels)?;
    let now_binding = now.to_string();
    let expires_binding = requested.expires_at.map(|value| value.to_string());
    let database = env.d1("CARRACK_INDEX")?;
    let client_insert = database
        .prepare(
            "INSERT INTO clients (\
                 id, name, sdk_version, capabilities_json, labels_json, state, created_at, updated_at\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'offline', ?6, ?6)",
        )
        .bind(&[
            JsValue::from_str(&client_id),
            JsValue::from_str(&requested.name),
            JsValue::from_str(&requested.sdk_version),
            JsValue::from_str(&capabilities),
            JsValue::from_str(&labels),
            JsValue::from_str(&now_binding),
        ])?;
    let token_insert = database
        .prepare(
            "INSERT INTO client_token_verifiers (\
                 id, client_id, verifier_algorithm, verifier_sha256, expires_at, created_at\
             ) VALUES (?1, ?2, 'sha256/v1', ?3, ?4, ?5)",
        )
        .bind(&[
            JsValue::from_str(&verifier_id),
            JsValue::from_str(&client_id),
            JsValue::from_str(&verifier),
            expires_binding
                .as_deref()
                .map_or_else(JsValue::null, JsValue::from_str),
            JsValue::from_str(&now_binding),
        ])?;
    let mut statements = vec![client_insert, token_insert];

    for permission in requested.permissions {
        statements.push(
            database
                .prepare(
                    "INSERT INTO client_namespace_permissions (\
                         client_id, namespace_id, role, created_at\
                     ) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(&[
                    JsValue::from_str(&client_id),
                    JsValue::from_str(&permission.namespace_id),
                    JsValue::from_str(&permission.role),
                    JsValue::from_str(&now_binding),
                ])?,
        );
    }

    database.batch(statements).await?;

    Response::from_json(&CreateClientResponse {
        client_id,
        token,
        created_at: now,
    })
}

pub(crate) async fn authenticate(
    request: &Request,
    env: &Env,
) -> Result<Option<AuthenticatedClient>> {
    let Some(header) = request.headers().get("Authorization")? else {
        return Ok(None);
    };
    let Some(token) = header.strip_prefix("Bearer ") else {
        return Ok(None);
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(token) else {
        return Ok(None);
    };
    if decoded.len() != TOKEN_BYTES {
        return Ok(None);
    }

    let verifier = token_verifier(token);
    let database = env.d1("CARRACK_INDEX")?;
    let client = database
        .prepare(
            "SELECT client.id, client.name, client.sdk_version \
             FROM client_token_verifiers AS token \
             JOIN clients AS client ON client.id = token.client_id \
             WHERE token.verifier_algorithm = 'sha256/v1' \
               AND token.verifier_sha256 = ?1 \
               AND token.revoked_at IS NULL \
               AND (token.expires_at IS NULL OR token.expires_at > unixepoch()) \
               AND client.state != 'disabled'",
        )
        .bind(&[JsValue::from_str(&verifier)])?
        .first::<AuthenticatedClient>(None)
        .await?;

    Ok(client)
}

fn valid_request(request: &CreateClientRequest) -> bool {
    valid_string(&request.name, MAXIMUM_NAME_BYTES)
        && valid_string(&request.sdk_version, MAXIMUM_VERSION_BYTES)
        && request.capabilities.len() <= MAXIMUM_CAPABILITIES
        && request
            .capabilities
            .iter()
            .all(|value| valid_string(value, MAXIMUM_NAME_BYTES))
        && request.labels.len() <= MAXIMUM_LABELS
        && request.labels.iter().all(|(key, value)| {
            valid_string(key, MAXIMUM_LABEL_BYTES) && value.len() <= MAXIMUM_LABEL_BYTES
        })
        && request.permissions.iter().all(|permission| {
            valid_identifier(&permission.namespace_id) && valid_role(&permission.role)
        })
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn valid_identifier(value: &str) -> bool {
    value.len() == IDENTIFIER_BYTES * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_role(value: &str) -> bool {
    matches!(
        value,
        "reader" | "importer" | "relay" | "restorer" | "janitor" | "administrator"
    )
}

fn random_token() -> Result<String> {
    let mut token = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut token)
        .map_err(|error| worker::Error::RustError(format!("generate client token: {error}")))?;

    Ok(URL_SAFE_NO_PAD.encode(token))
}

fn random_hex<const BYTES: usize>() -> Result<String> {
    let mut random = [0_u8; BYTES];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate identifier: {error}")))?;

    let mut encoded = String::with_capacity(BYTES * 2);
    for byte in random {
        write!(encoded, "{byte:02x}")
            .map_err(|error| worker::Error::RustError(format!("encode identifier: {error}")))?;
    }

    Ok(encoded)
}

fn token_verifier(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    encoded
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        CreateClientRequest, PermissionRequest, random_hex, random_token, token_verifier,
        valid_request,
    };

    #[test]
    fn generates_canonical_random_credentials() {
        let identifier = random_hex::<16>().expect("generate identifier");
        let token = random_token().expect("generate token");

        assert_eq!(identifier.len(), 32);
        assert!(identifier.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(token.len(), 43);
        assert_eq!(token_verifier(&token).len(), 64);
        assert_ne!(token, random_token().expect("generate another token"));
    }

    #[test]
    fn validates_registration_boundaries() {
        let valid = CreateClientRequest {
            name: "hawk-importer".to_owned(),
            sdk_version: "0.1.0".to_owned(),
            capabilities: vec!["import/v1".to_owned()],
            labels: BTreeMap::from([("host".to_owned(), "hawk".to_owned())]),
            permissions: vec![PermissionRequest {
                namespace_id: "0123456789abcdef0123456789abcdef".to_owned(),
                role: "importer".to_owned(),
            }],
            expires_at: None,
        };

        assert!(valid_request(&valid));

        let invalid_role = CreateClientRequest {
            permissions: vec![PermissionRequest {
                namespace_id: "0123456789abcdef0123456789abcdef".to_owned(),
                role: "owner".to_owned(),
            }],
            ..valid
        };
        assert!(!valid_request(&invalid_role));
    }
}
