//! Authenticated delivery of complete, server-materialized VFS catalog views.

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use skydriver_sdk_core::{
    CatalogCheckpoint, MAXIMUM_CATALOG_CHECKPOINT_BYTES, MAXIMUM_CATALOG_DELTA_BYTES,
    catalog_checkpoint_etag, catalog_checkpoint_view_etag, project_catalog_checkpoint,
    validate_catalog_checkpoint,
};
use worker::{Bucket, D1Database, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{protocol_compatibility, vfs_tokens::AuthenticatedVfsToken};

const MAXIMUM_PROJECTABLE_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
struct DeliveryRow {
    filesystem_id: String,
    revision_id: u64,
    filesystem_root_directory_id: String,
    filesystem_root_data_root: String,
    root_directory_id: String,
    root_data_root: String,
    r2_key: String,
    sha256: String,
    bytes: u64,
    r2_version: String,
    delta_base_revision_id: Option<u64>,
    delta_base_root_data_root: Option<String>,
    delta_base_checkpoint_sha256: Option<String>,
    delta_checkpoint_sha256: Option<String>,
    delta_r2_key: Option<String>,
    delta_sha256: Option<String>,
    delta_bytes: Option<u64>,
    delta_r2_version: Option<String>,
}

struct DeltaReceipt<'a> {
    r2_key: &'a str,
    sha256: &'a str,
    bytes: u64,
    r2_version: &'a str,
}

/// Current catalog identity that one authenticated token may observe.
///
/// This is deliberately smaller than a checkpoint receipt. Catalog watch is
/// an advisory wake-up channel: clients must still fetch and authenticate the
/// checkpoint, delta, or revision-pinned pages before planning payload I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatalogWatchAuthorization {
    pub(crate) filesystem_id: String,
    pub(crate) revision_id: u64,
    pub(crate) root_directory_id: String,
    pub(crate) root_data_root: String,
    pub(crate) etag: String,
}

/// Re-evaluates the complete current token chain, ACL closure, and published
/// catalog head for a catalog-watch subscriber.
///
/// Durable Object connections call this again for every delivered event. A
/// WebSocket established under authority that is later revoked therefore
/// cannot receive a newly published catalog identity.
pub(crate) async fn watch_authorization(
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Option<CatalogWatchAuthorization>> {
    let database = env.d1("SKYDRIVER_INDEX")?;
    let Some(delivery) = eligible_checkpoint(&database, token).await? else {
        return Ok(None);
    };
    validate_receipt(&delivery)?;
    let etag = delivery_etag(&delivery)?;
    Ok(Some(CatalogWatchAuthorization {
        filesystem_id: delivery.filesystem_id,
        revision_id: delivery.revision_id,
        root_directory_id: delivery.root_directory_id,
        root_data_root: delivery.root_data_root,
        etag,
    }))
}

/// Delivers the current complete checkpoint view when the token has safe list
/// and content-read authority over its complete root closure. A full-root view
/// streams directly from R2; a narrow root is deterministically projected only
/// after the immutable source object is verified. Snapshots and subtrees with
/// descendant ACL inheritance breaks retain the paginated fallback.
pub(crate) async fn checkpoint(
    request: &Request,
    env: &Env,
    token: &AuthenticatedVfsToken,
) -> Result<Response> {
    let database = env.d1("SKYDRIVER_INDEX")?;
    let Some(delivery) = eligible_checkpoint(&database, token).await? else {
        return fallback();
    };
    validate_receipt(&delivery)?;
    if delivery.root_directory_id != delivery.filesystem_root_directory_id
        && (!protocol_compatibility::sdk_version_at_least(request, (0, 3, 1))?
            || delivery.bytes > MAXIMUM_PROJECTABLE_SOURCE_BYTES)
    {
        return fallback();
    }
    let etag = delivery_etag(&delivery)?;
    if request.headers().get("If-None-Match")?.as_deref() == Some(etag.as_str()) {
        return not_modified(&delivery, &etag);
    }

    let bucket = env.bucket("SKYDRIVER_MANIFESTS")?;
    if let Some(delta) = requested_delta(request, &delivery)? {
        return deliver_delta(&bucket, &delivery, &etag, &delta).await;
    }
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
        .ok_or_else(|| protocol_error("published catalog checkpoint has no R2 body"))?;
    if delivery.root_directory_id == delivery.filesystem_root_directory_id {
        let mut response = Response::from_body(body.response_body()?)?;
        set_body_headers(
            &mut response,
            &delivery,
            &etag,
            &delivery.sha256,
            delivery.bytes,
        )?;
        return Ok(response);
    }

    let source = body.bytes().await?;
    let source_bytes = u64::try_from(source.len())
        .map_err(|_| protocol_error("catalog checkpoint source size exceeds u64"))?;
    if source_bytes != delivery.bytes || hex::encode(Sha256::digest(&source)) != delivery.sha256 {
        return Err(protocol_error(
            "published catalog checkpoint body receipt differs",
        ));
    }
    let checkpoint: CatalogCheckpoint = serde_json::from_slice(&source)?;
    if serde_json::to_vec(&checkpoint)? != source {
        return Err(protocol_error(
            "published catalog checkpoint is not canonical",
        ));
    }
    validate_catalog_checkpoint(&checkpoint).map_err(|error| protocol_error(&error.to_string()))?;
    if checkpoint.filesystem_id != delivery.filesystem_id
        || checkpoint.revision_id != delivery.revision_id
        || checkpoint.root_directory_id != delivery.filesystem_root_directory_id
        || checkpoint.root_data_root != delivery.filesystem_root_data_root
    {
        return Err(protocol_error(
            "published catalog checkpoint identity differs",
        ));
    }
    let projected = project_catalog_checkpoint(&checkpoint, &delivery.root_directory_id)
        .map_err(|error| protocol_error(&error.to_string()))?;
    if projected.root_data_root != delivery.root_data_root {
        return Err(protocol_error(
            "projected catalog checkpoint root differs from D1",
        ));
    }
    let encoded = serde_json::to_vec(&projected)?;
    if encoded.is_empty() || encoded.len() > MAXIMUM_CATALOG_CHECKPOINT_BYTES {
        return Err(protocol_error(
            "projected catalog checkpoint exceeds its byte bound",
        ));
    }
    let encoded_bytes = u64::try_from(encoded.len())
        .map_err(|_| protocol_error("projected catalog checkpoint size exceeds u64"))?;
    let encoded_sha256 = hex::encode(Sha256::digest(&encoded));
    let mut response = Response::from_bytes(encoded)?;
    set_body_headers(
        &mut response,
        &delivery,
        &etag,
        &encoded_sha256,
        encoded_bytes,
    )?;
    Ok(response)
}

#[allow(
    clippy::too_many_lines,
    reason = "one D1 statement keeps token-chain, inherited ACL, subtree-boundary, and immutable-head proofs atomic"
)]
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
             ),
             acl_directories(id, parent_id, acl_inherits) AS (
                 SELECT id, parent_id, acl_inherits
                 FROM vfs_directories
                 WHERE id = ?3 AND state = 'active'
                 UNION
                 SELECT parent.id, parent.parent_id, parent.acl_inherits
                 FROM vfs_directories AS parent
                 JOIN acl_directories AS child ON child.parent_id = parent.id
                 WHERE child.acl_inherits = 1 AND parent.state = 'active'
             ),
             subtree(id) AS (
                 SELECT id FROM vfs_directories
                 WHERE id = ?3 AND parent_id IS NOT NULL AND state = 'active'
                 UNION ALL
                 SELECT child.id
                 FROM vfs_directories AS child
                      INDEXED BY idx_vfs_directories_active_parent
                 JOIN subtree AS parent ON child.parent_id = parent.id
                 WHERE child.parent_id IS NOT NULL AND child.state = 'active'
             )
             SELECT root.filesystem_id, revision.id AS revision_id,
                    filesystem_root.id AS filesystem_root_directory_id,
                    head.root_data_root AS filesystem_root_data_root,
                    root.id AS root_directory_id, root.data_root AS root_data_root,
                    artifact.r2_key, artifact.sha256, artifact.bytes,
                    artifact.r2_version,
                    delta.base_revision_id AS delta_base_revision_id,
                    delta.base_root_data_root AS delta_base_root_data_root,
                    delta.base_checkpoint_sha256 AS delta_base_checkpoint_sha256,
                    delta.checkpoint_sha256 AS delta_checkpoint_sha256,
                    delta.r2_key AS delta_r2_key, delta.sha256 AS delta_sha256,
                    delta.bytes AS delta_bytes,
                    delta.r2_version AS delta_r2_version
             FROM vfs_token_verifiers AS token
             JOIN vfs_principals AS principal ON principal.id = token.principal_id
             JOIN vfs_directories AS root ON root.id = token.root_directory_id
             JOIN vfs_directories AS filesystem_root
               ON filesystem_root.filesystem_id = root.filesystem_id
              AND filesystem_root.parent_id IS NULL
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
             LEFT JOIN vfs_catalog_delta_artifacts AS delta
               ON delta.target_revision_id = revision.id
              AND delta.checkpoint_sha256 = artifact.sha256
              AND delta.state = 'published'
             WHERE token.id = ?1 AND token.principal_id = ?2
               AND token.root_directory_id = ?3
               AND token.sealed_at IS NOT NULL AND token.revoked_at IS NULL
               AND token.expires_at > unixepoch() AND token.snapshot_id IS NULL
               AND principal.state = 'active'
               AND root.state = 'active' AND filesystem_root.state = 'active'
               AND filesystem_root.data_root = head.root_data_root
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
                   WHERE grant.action = 'directory.list'
                     AND grant.directory_id IN (SELECT id FROM acl_directories)
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
                   WHERE grant.action = 'content.read'
                     AND grant.directory_id IN (SELECT id FROM acl_directories)
                     AND (
                         grant.principal_id = token.principal_id
                         OR EXISTS (
                             SELECT 1 FROM vfs_group_members AS membership
                             WHERE membership.group_id = grant.group_id
                               AND membership.principal_id = token.principal_id
                         )
                     )
               )
               AND (
                   (root.parent_id IS NULL AND NOT EXISTS (
                       SELECT 1
                       FROM vfs_directories AS boundary
                            INDEXED BY idx_vfs_directories_active_acl_boundaries
                       WHERE boundary.filesystem_id = root.filesystem_id
                         AND boundary.id != root.id
                         AND boundary.state = 'active'
                         AND boundary.acl_inherits = 0
                   ))
                   OR
                   (root.parent_id IS NOT NULL AND NOT EXISTS (
                       SELECT 1 FROM vfs_directories AS boundary
                       JOIN subtree ON subtree.id = boundary.id
                       WHERE boundary.id != root.id AND boundary.acl_inherits = 0
                   ))
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
        || delivery.filesystem_root_directory_id.len() != 32
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
        || delivery.filesystem_root_data_root.len() != 64
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

fn delivery_etag(delivery: &DeliveryRow) -> Result<String> {
    let etag = if delivery.root_directory_id == delivery.filesystem_root_directory_id {
        catalog_checkpoint_etag(&delivery.sha256)
    } else {
        catalog_checkpoint_view_etag(&delivery.sha256, &delivery.root_directory_id)
    };
    etag.map_err(|error| protocol_error(&error.to_string()))
}

fn requested_delta<'a>(
    request: &Request,
    delivery: &'a DeliveryRow,
) -> Result<Option<DeltaReceipt<'a>>> {
    if delivery.root_directory_id != delivery.filesystem_root_directory_id
        || !protocol_compatibility::sdk_version_at_least(request, (0, 3, 2))?
        || request
            .headers()
            .get("Skydriver-Catalog-Accept-Delta")?
            .as_deref()
            != Some("v1")
    {
        return Ok(None);
    }
    let (
        Some(base_revision_id),
        Some(base_root_data_root),
        Some(base_checkpoint_sha256),
        Some(checkpoint_sha256),
        Some(r2_key),
        Some(sha256),
        Some(bytes),
        Some(r2_version),
    ) = (
        delivery.delta_base_revision_id,
        delivery.delta_base_root_data_root.as_deref(),
        delivery.delta_base_checkpoint_sha256.as_deref(),
        delivery.delta_checkpoint_sha256.as_deref(),
        delivery.delta_r2_key.as_deref(),
        delivery.delta_sha256.as_deref(),
        delivery.delta_bytes,
        delivery.delta_r2_version.as_deref(),
    )
    else {
        return Ok(None);
    };
    if checkpoint_sha256 != delivery.sha256
        || base_revision_id == 0
        || base_revision_id >= delivery.revision_id
        || base_root_data_root.len() != 64
        || base_checkpoint_sha256.len() != 64
        || sha256.len() != 64
        || bytes == 0
        || bytes > MAXIMUM_CATALOG_DELTA_BYTES as u64
        || r2_version.is_empty()
        || !r2_key.ends_with(&format!("/{sha256}.json"))
        || ![base_root_data_root, base_checkpoint_sha256, sha256]
            .iter()
            .all(|value| {
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    {
        return Ok(None);
    }
    let expected_base_etag = catalog_checkpoint_etag(base_checkpoint_sha256)
        .map_err(|error| protocol_error(&error.to_string()))?;
    let base_revision = base_revision_id.to_string();
    if request.headers().get("If-None-Match")?.as_deref() != Some(expected_base_etag.as_str())
        || request
            .headers()
            .get("Skydriver-Catalog-Base-Revision")?
            .as_deref()
            != Some(base_revision.as_str())
        || request
            .headers()
            .get("Skydriver-Catalog-Base-Root")?
            .as_deref()
            != Some(base_root_data_root)
        || request
            .headers()
            .get("Skydriver-Catalog-Base-SHA256")?
            .as_deref()
            != Some(base_checkpoint_sha256)
    {
        return Ok(None);
    }
    Ok(Some(DeltaReceipt {
        r2_key,
        sha256,
        bytes,
        r2_version,
    }))
}

async fn deliver_delta(
    bucket: &Bucket,
    delivery: &DeliveryRow,
    etag: &str,
    delta: &DeltaReceipt<'_>,
) -> Result<Response> {
    let object = bucket
        .get(delta.r2_key.to_owned())
        .execute()
        .await?
        .ok_or_else(|| protocol_error("published catalog delta is missing from R2"))?;
    if object.key() != delta.r2_key
        || object.version() != delta.r2_version
        || object.size() != delta.bytes
    {
        return Err(protocol_error("published catalog delta R2 receipt differs"));
    }
    let body = object
        .body()
        .ok_or_else(|| protocol_error("published catalog delta has no R2 body"))?;
    let mut response = Response::from_body(body.response_body()?)?;
    response
        .headers_mut()
        .set("Content-Type", "application/vnd.carrack.catalog-delta+json")?;
    response
        .headers_mut()
        .set("Content-Length", &delta.bytes.to_string())?;
    response
        .headers_mut()
        .set("Skydriver-Catalog-SHA256", &delivery.sha256)?;
    response
        .headers_mut()
        .set("Skydriver-Catalog-Delta-SHA256", delta.sha256)?;
    set_view_headers(&mut response, delivery, etag)?;
    response
        .headers_mut()
        .set("X-Content-Type-Options", "nosniff")?;
    Ok(response)
}

fn fallback() -> Result<Response> {
    let mut response = Response::empty()?.with_status(204);
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store, max-age=0")?;
    Ok(response)
}

fn not_modified(delivery: &DeliveryRow, etag: &str) -> Result<Response> {
    let mut response = Response::empty()?.with_status(304);
    set_view_headers(&mut response, delivery, etag)?;
    Ok(response)
}

fn set_body_headers(
    response: &mut Response,
    delivery: &DeliveryRow,
    etag: &str,
    sha256: &str,
    bytes: u64,
) -> Result<()> {
    response
        .headers_mut()
        .set("Content-Type", "application/json")?;
    response
        .headers_mut()
        .set("Content-Length", &bytes.to_string())?;
    response
        .headers_mut()
        .set("Skydriver-Catalog-SHA256", sha256)?;
    set_view_headers(response, delivery, etag)?;
    response
        .headers_mut()
        .set("X-Content-Type-Options", "nosniff")?;
    Ok(())
}

fn set_view_headers(response: &mut Response, delivery: &DeliveryRow, etag: &str) -> Result<()> {
    response.headers_mut().set("ETag", etag)?;
    response.headers_mut().set(
        "Skydriver-Catalog-Revision",
        &delivery.revision_id.to_string(),
    )?;
    response
        .headers_mut()
        .set("Skydriver-Catalog-Root", &delivery.root_data_root)?;
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store, max-age=0")?;
    Ok(())
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
            filesystem_root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            filesystem_root_data_root:
                "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254".to_owned(),
            root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            root_data_root: "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254"
                .to_owned(),
            r2_key: "vfs/catalog/checkpoints/fs/aa/wrong.json".to_owned(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            bytes: 1,
            r2_version: "version".to_owned(),
            delta_base_revision_id: None,
            delta_base_root_data_root: None,
            delta_base_checkpoint_sha256: None,
            delta_checkpoint_sha256: None,
            delta_r2_key: None,
            delta_sha256: None,
            delta_bytes: None,
            delta_r2_version: None,
        };
        assert!(validate_receipt(&receipt).is_err());
    }

    #[test]
    fn narrow_view_has_an_authority_scoped_entity_tag() {
        let delivery = DeliveryRow {
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            filesystem_root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            filesystem_root_data_root:
                "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254"
                    .to_owned(),
            root_directory_id: "303132333435363738393a3b3c3d3e3f".to_owned(),
            root_data_root:
                "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254"
                    .to_owned(),
            r2_key: "vfs/catalog/checkpoints/fs/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json".to_owned(),
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            bytes: 1,
            r2_version: "version".to_owned(),
            delta_base_revision_id: None,
            delta_base_root_data_root: None,
            delta_base_checkpoint_sha256: None,
            delta_checkpoint_sha256: None,
            delta_r2_key: None,
            delta_sha256: None,
            delta_bytes: None,
            delta_r2_version: None,
        };
        assert_ne!(
            delivery_etag(&delivery).expect("view entity tag"),
            catalog_checkpoint_etag(&delivery.sha256).expect("artifact entity tag")
        );
    }
}
