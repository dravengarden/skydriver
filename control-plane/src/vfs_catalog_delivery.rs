//! Authenticated delivery of complete, server-materialized VFS catalogs.

use carrack_sdk_core::MAXIMUM_CATALOG_CHECKPOINT_BYTES;
use serde::Deserialize;
use worker::{D1Database, Env, Response, Result, wasm_bindgen::JsValue};

use crate::vfs_tokens::AuthenticatedVfsToken;

#[derive(Deserialize)]
struct DeliveryRow {
    filesystem_id: String,
    revision_id: u64,
    root_directory_id: String,
    root_data_root: String,
    r2_key: String,
    sha256: String,
    bytes: u64,
    r2_version: String,
}

/// Streams the current complete checkpoint only when the token has safe
/// filesystem-wide list and content-read authority. Narrow roots, snapshots,
/// and filesystems containing an ACL inheritance break receive an empty
/// success response so clients transparently retain paginated traversal.
pub(crate) async fn checkpoint(env: &Env, token: &AuthenticatedVfsToken) -> Result<Response> {
    let database = env.d1("CARRACK_INDEX")?;
    let Some(delivery) = eligible_checkpoint(&database, token).await? else {
        return fallback();
    };
    validate_receipt(&delivery)?;

    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let object = bucket
        .get(delivery.r2_key.clone())
        .execute()
        .await?
        .ok_or_else(|| protocol_error("published catalog checkpoint is missing from R2"))?;
    if object.key() != delivery.r2_key
        || object.version() != delivery.r2_version
        || object.size() != delivery.bytes
    {
        return Err(protocol_error(
            "published catalog checkpoint R2 receipt differs",
        ));
    }
    let body = object
        .body()
        .ok_or_else(|| protocol_error("published catalog checkpoint has no R2 body"))?
        .response_body()?;
    let mut response = Response::from_body(body)?;
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Content-Length", &delivery.bytes.to_string())?;
    response
        .headers_mut()
        .set("Carrack-Catalog-SHA256", &delivery.sha256)?;
    response.headers_mut().set(
        "Carrack-Catalog-Revision",
        &delivery.revision_id.to_string(),
    )?;
    response
        .headers_mut()
        .set("Carrack-Catalog-Root", &delivery.root_data_root)?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store, max-age=0")?;
    response
        .headers_mut()
        .set("X-Content-Type-Options", "nosniff")?;
    Ok(response)
}

async fn eligible_checkpoint(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
) -> Result<Option<DeliveryRow>> {
    database
        .prepare(
            "WITH RECURSIVE token_chain(
                 id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
             ) AS (
                 SELECT id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
                 FROM vfs_token_verifiers WHERE id = ?1
                 UNION
                 SELECT parent.id, parent.parent_token_id, parent.principal_id,
                        parent.sealed_at, parent.revoked_at, parent.expires_at
                 FROM vfs_token_verifiers AS parent
                 JOIN token_chain AS child ON child.parent_token_id = parent.id
             )
             SELECT root.filesystem_id, revision.id AS revision_id,
                    root.id AS root_directory_id, head.root_data_root,
                    artifact.r2_key, artifact.sha256, artifact.bytes,
                    artifact.r2_version
             FROM vfs_token_verifiers AS token
             JOIN vfs_principals AS principal ON principal.id = token.principal_id
             JOIN vfs_directories AS root ON root.id = token.root_directory_id
             JOIN vfs_catalog_heads AS head ON head.filesystem_id = root.filesystem_id
             JOIN vfs_catalog_revisions AS revision
               ON revision.id = head.revision_id
              AND revision.filesystem_id = head.filesystem_id
              AND revision.root_data_root = head.root_data_root
             JOIN vfs_catalog_checkpoint_artifacts AS artifact
               ON artifact.revision_id = revision.id
              AND artifact.r2_key = revision.checkpoint_r2_key
              AND artifact.sha256 = revision.checkpoint_sha256
              AND artifact.r2_version = revision.checkpoint_r2_version
              AND artifact.bytes = revision.checkpoint_bytes
             WHERE token.id = ?1 AND token.principal_id = ?2
               AND token.root_directory_id = ?3
               AND token.sealed_at IS NOT NULL AND token.revoked_at IS NULL
               AND token.expires_at > unixepoch() AND token.snapshot_id IS NULL
               AND principal.state = 'active'
               AND root.parent_id IS NULL AND root.state = 'active'
               AND root.data_root = head.root_data_root
               AND revision.state = 'published' AND artifact.state = 'published'
               AND EXISTS (
                   SELECT 1 FROM vfs_token_actions
                   WHERE token_id = token.id AND action = 'directory.list'
               )
               AND EXISTS (
                   SELECT 1 FROM vfs_token_actions
                   WHERE token_id = token.id AND action = 'content.read'
               )
               AND NOT EXISTS (
                   SELECT 1 FROM token_chain AS chain
                   WHERE chain.sealed_at IS NULL
                      OR chain.revoked_at IS NOT NULL
                      OR chain.expires_at <= unixepoch()
                      OR chain.principal_id != token.principal_id
               )
               AND EXISTS (
                   SELECT 1 FROM vfs_acl_grants AS grant
                   WHERE grant.directory_id = root.id
                     AND grant.action = 'directory.list'
                     AND (
                         grant.principal_id = token.principal_id
                         OR EXISTS (
                             SELECT 1 FROM vfs_group_members AS membership
                             WHERE membership.group_id = grant.group_id
                               AND membership.principal_id = token.principal_id
                         )
                     )
               )
               AND EXISTS (
                   SELECT 1 FROM vfs_acl_grants AS grant
                   WHERE grant.directory_id = root.id
                     AND grant.action = 'content.read'
                     AND (
                         grant.principal_id = token.principal_id
                         OR EXISTS (
                             SELECT 1 FROM vfs_group_members AS membership
                             WHERE membership.group_id = grant.group_id
                               AND membership.principal_id = token.principal_id
                         )
                     )
               )
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_directories AS boundary
                   WHERE boundary.filesystem_id = root.filesystem_id
                     AND boundary.id != root.id
                     AND boundary.state = 'active'
                     AND boundary.acl_inherits = 0
               )",
        )
        .bind(&[
            JsValue::from_str(&token.id),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(&token.root_directory_id),
        ])?
        .first::<DeliveryRow>(None)
        .await
}

fn validate_receipt(delivery: &DeliveryRow) -> Result<()> {
    if delivery.filesystem_id.len() != 32
        || delivery.root_directory_id.len() != 32
        || delivery.revision_id == 0
        || delivery.bytes == 0
        || delivery.bytes > MAXIMUM_CATALOG_CHECKPOINT_BYTES as u64
        || delivery.sha256.len() != 64
        || !delivery
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || delivery.root_data_root.len() != 64
        || delivery.r2_version.is_empty()
        || !delivery
            .r2_key
            .ends_with(&format!("/{}.json", delivery.sha256))
    {
        return Err(protocol_error(
            "published catalog checkpoint receipt is invalid",
        ));
    }
    Ok(())
}

fn fallback() -> Result<Response> {
    let mut response = Response::empty()?.with_status(204);
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store, max-age=0")?;
    Ok(response)
}

fn protocol_error(message: &str) -> worker::Error {
    worker::Error::RustError(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_receipt_whose_key_does_not_match_digest() {
        let receipt = DeliveryRow {
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            root_data_root: "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254"
                .to_owned(),
            r2_key: "vfs/catalog/checkpoints/fs/aa/wrong.json".to_owned(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            bytes: 1,
            r2_version: "version".to_owned(),
        };
        assert!(validate_receipt(&receipt).is_err());
    }
}
