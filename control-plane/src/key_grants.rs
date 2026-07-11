use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, keys};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    root_version: u32,
    key_epoch: u64,
}

#[derive(Deserialize)]
struct GrantContext {
    namespace_id: String,
    root_version: u32,
    key_epoch: u64,
}

#[derive(Serialize)]
struct GrantResponse {
    operation_id: String,
    manifest_sha256: String,
    root_version: u32,
    key_epoch: u64,
    epoch_key: String,
}

pub(crate) async fn grant_restore(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
) -> Result<Response> {
    let requested = request.json::<GrantRequest>().await?;
    if !valid_hex(operation_id, 32)
        || !valid_string(&requested.lease_id, 256)
        || !valid_hex(&requested.incarnation, 32)
        || requested.fencing_token == 0
        || !valid_hex(&requested.manifest_sha256, 64)
        || requested.root_version == 0
        || requested.key_epoch == 0
    {
        return Response::error("invalid restore key grant", 400);
    }

    let database = env.d1("CARRACK_INDEX")?;
    let context = database
        .prepare(
            "SELECT operation.namespace_id, pack.root_key_version AS root_version, \
                    pack.key_epoch \
             FROM operations AS operation \
             JOIN restore_intents AS intent ON intent.operation_id = operation.id \
             JOIN version_packs AS version_pack ON version_pack.version_id = intent.version_id \
             JOIN packs AS pack ON pack.id = version_pack.pack_id \
             JOIN leases AS lease ON lease.operation_id = operation.id \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             WHERE operation.id = ?1 AND operation.kind = 'restore' \
               AND operation.state = 'running' AND operation.requested_by = ?2 \
               AND intent.manifest_sha256 = ?3 AND pack.root_key_version = ?4 \
               AND pack.key_epoch = ?5 AND lease.id = ?6 AND lease.owner_client_id = ?2 \
               AND lease.incarnation = ?7 AND lease.fencing_token = ?8 \
               AND lease.lease_kind = 'read' AND lease.released_at IS NULL \
               AND lease.expires_at > unixepoch() AND state.mode = 'active' \
               AND state.incarnation = lease.incarnation \
             GROUP BY operation.namespace_id, pack.root_key_version, pack.key_epoch \
             HAVING COUNT(*) = (SELECT COUNT(*) FROM version_packs \
                                WHERE version_id = intent.version_id)",
        )
        .bind(&[
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.root_version.to_string()),
            JsValue::from_str(&requested.key_epoch.to_string()),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.incarnation),
            JsValue::from_str(&requested.fencing_token.to_string()),
        ])?
        .first::<GrantContext>(None)
        .await?;
    let Some(context) = context else {
        return Response::error(
            "restore key grant fence or crypto identity is unavailable",
            409,
        );
    };

    let namespace_id = decode_hex_array::<16>(&context.namespace_id)
        .ok_or_else(|| worker::Error::RustError("invalid stored namespace ID".to_owned()))?;
    let secret_name = format!("CARRACK_ROOT_KEY_V{}", context.root_version);
    let encoded_root = env.secret(&secret_name)?.to_string();
    let mut root_key = decode_base64_array::<32>(&encoded_root)
        .ok_or_else(|| worker::Error::RustError(format!("invalid {secret_name}")))?;
    let mut epoch_key = keys::derive_epoch_key(&root_key, &namespace_id, context.key_epoch)
        .map_err(|error| worker::Error::RustError(format!("derive restore epoch key: {error}")))?;
    root_key.fill(0);

    record_audit(
        env,
        client,
        operation_id,
        &context,
        &requested.manifest_sha256,
    )
    .await?;

    let encoded_epoch = URL_SAFE_NO_PAD.encode(epoch_key);
    epoch_key.fill(0);

    let mut response = Response::from_json(&GrantResponse {
        operation_id: operation_id.to_owned(),
        manifest_sha256: requested.manifest_sha256,
        root_version: context.root_version,
        key_epoch: context.key_epoch,
        epoch_key: encoded_epoch,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    response.headers_mut().set("Pragma", "no-cache")?;

    Ok(response)
}

async fn record_audit(
    env: &Env,
    client: &AuthenticatedClient,
    operation_id: &str,
    context: &GrantContext,
    manifest_sha256: &str,
) -> Result<()> {
    let database = env.d1("CARRACK_INDEX")?;
    let event_id = random_hex()?;
    let details = serde_json::json!({
        "manifest_sha256": manifest_sha256,
        "root_version": context.root_version,
        "key_epoch": context.key_epoch,
    })
    .to_string();
    database
        .prepare(
            "INSERT INTO audit_events (\
                 id, namespace_id, operation_id, client_id, event_kind, subject_kind, \
                 subject_id, details_json, created_at\
             ) VALUES (?1, ?2, ?3, ?4, 'epoch_key_granted', 'operation', ?3, ?5, ?6)",
        )
        .bind(&[
            JsValue::from_str(&event_id),
            JsValue::from_str(&context.namespace_id),
            JsValue::from_str(operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&details),
            JsValue::from_str(&(Date::now().as_millis() / 1_000).to_string()),
        ])?
        .run()
        .await?;

    Ok(())
}

fn decode_hex_array<const BYTES: usize>(encoded: &str) -> Option<[u8; BYTES]> {
    if encoded.len() != BYTES * 2 {
        return None;
    }

    let mut decoded = [0_u8; BYTES];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).ok()?;
    }

    Some(decoded)
}

fn decode_base64_array<const BYTES: usize>(encoded: &str) -> Option<[u8; BYTES]> {
    URL_SAFE_NO_PAD.decode(encoded).ok()?.try_into().ok()
}

fn random_hex() -> Result<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| worker::Error::RustError(format!("generate audit ID: {error}")))?;

    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    Ok(encoded)
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{decode_base64_array, decode_hex_array};

    #[test]
    fn decodes_fixed_key_contexts() {
        assert_eq!(decode_hex_array::<2>("0123"), Some([1, 35]));
        assert!(decode_hex_array::<2>("xyz1").is_none());
        assert_eq!(
            decode_base64_array::<2>(&URL_SAFE_NO_PAD.encode([4, 5])),
            Some([4, 5])
        );
    }
}
