use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Bucket, Conditional, Env, Request, Response, Result, wasm_bindgen::JsValue};

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

struct StoredRecovery {
    version: String,
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
        return Response::error("namespace transfer permission required", 403);
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
    let stored = store_immutable(&bucket, &r2_key, &encoded, &recovery_digest).await?;

    Response::from_json(&StageResponse {
        manifest_sha256: validated.manifest_sha256,
        recovery_sha256,
        namespace_id: validated.namespace_id,
        object_id: validated.object_id,
        generation: validated.generation,
        r2_key,
        r2_version: stored.version,
        bytes: stored.bytes,
    })
}

async fn store_immutable(
    bucket: &Bucket,
    key: &str,
    encoded: &[u8],
    digest: &[u8],
) -> Result<StoredRecovery> {
    let expected_bytes = u64::try_from(encoded.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let created = bucket
        .put(key, encoded.to_vec())
        .only_if(Conditional {
            etag_does_not_match: Some("*".to_owned()),
            ..Conditional::default()
        })
        .sha256(digest.to_vec())
        .execute()
        .await?;
    if let Some(object) = created {
        if object.size() != expected_bytes {
            return Err(worker::Error::RustError(
                "R2 recovery manifest size mismatch".to_owned(),
            ));
        }

        return Ok(StoredRecovery {
            version: object.version().clone(),
            bytes: object.size(),
        });
    }

    let Some(existing) = bucket.get(key).execute().await? else {
        return Err(worker::Error::RustError(
            "R2 recovery manifest disappeared after a conditional write".to_owned(),
        ));
    };
    let existing_bytes = existing.size();
    let existing_version = existing.version().clone();
    let Some(body) = existing.body() else {
        return Err(worker::Error::RustError(
            "existing R2 recovery manifest body is missing".to_owned(),
        ));
    };
    let existing_body = body.bytes().await?;
    if existing_bytes != expected_bytes
        || existing_body != encoded
        || Sha256::digest(&existing_body).as_slice() != digest
    {
        return Err(worker::Error::RustError(
            "content-addressed R2 recovery manifest collision".to_owned(),
        ));
    }

    Ok(StoredRecovery {
        version: existing_version,
        bytes: existing_bytes,
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
                              AND role IN ('importer', 'relay', 'administrator')) AS allowed",
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
