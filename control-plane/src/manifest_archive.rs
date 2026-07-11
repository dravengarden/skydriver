use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{clients::AuthenticatedClient, manifests};

#[derive(Deserialize)]
struct PermissionRow {
    allowed: u64,
}

#[derive(Serialize)]
struct StageResponse {
    manifest_sha256: String,
    recovery_sha256: String,
    namespace_id: String,
    object_id: String,
    generation: u64,
    r2_key: String,
    r2_version: String,
    bytes: u64,
}

pub(crate) async fn stage(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let encoded = request.bytes().await?;
    let validated = match manifests::validate(&encoded) {
        Ok(value) => value,
        Err(error) => return Response::error(error, 400),
    };

    if !authorized(env, &client.id, &validated.namespace_id).await? {
        return Response::error("namespace import permission required", 403);
    }

    let recovery_digest = Sha256::digest(&encoded);
    let recovery_sha256 = lowercase_hex(&recovery_digest);
    let r2_key = format!(
        "manifests/{}/{}/{}/{}.json",
        validated.namespace_id,
        &validated.manifest_sha256[..2],
        validated.manifest_sha256,
        recovery_sha256,
    );
    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let stored = bucket
        .put(&r2_key, encoded.clone())
        .sha256(recovery_digest.to_vec())
        .execute()
        .await?;
    let Some(stored) = stored else {
        return Response::error("R2 rejected recovery manifest precondition", 409);
    };

    let expected_bytes = u64::try_from(encoded.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    if stored.size() != expected_bytes {
        return Response::error("R2 recovery manifest size mismatch", 502);
    }

    Response::from_json(&StageResponse {
        manifest_sha256: validated.manifest_sha256,
        recovery_sha256,
        namespace_id: validated.namespace_id,
        object_id: validated.object_id,
        generation: validated.generation,
        r2_key,
        r2_version: stored.version(),
        bytes: expected_bytes,
    })
}

async fn authorized(env: &Env, client_id: &str, namespace_id: &str) -> Result<bool> {
    let database = env.d1("CARRACK_INDEX")?;
    let result = database
        .prepare(
            "SELECT \
                 EXISTS(SELECT 1 FROM control_plane_state \
                        WHERE singleton = 1 AND mode = 'active') \
                 AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                            WHERE client_id = ?1 AND namespace_id = ?2 \
                              AND role IN ('importer', 'administrator')) AS allowed",
        )
        .bind(&[
            JsValue::from_str(client_id),
            JsValue::from_str(namespace_id),
        ])?
        .first::<PermissionRow>(None)
        .await?;

    Ok(result.is_some_and(|row| row.allowed == 1))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    encoded
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::lowercase_hex;

    #[test]
    fn encodes_content_address_in_lowercase() {
        assert_eq!(
            lowercase_hex(&Sha256::digest(b"carrack")),
            "b16b7c1ad35ee765c910d755e8f118ce8c93851b66cc56ae1449cdcc96b8b9da"
        );
    }
}
