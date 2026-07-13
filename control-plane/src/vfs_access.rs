use serde::Deserialize;
use worker::{D1Database, Result, wasm_bindgen::JsValue};

use crate::vfs_tokens::AuthenticatedVfsToken;

#[derive(Deserialize)]
struct AuthorizationRow {
    allowed: u64,
}

/// Evaluates the current token chain, directory attenuation, and inherited
/// allow-only ACL for one exact action. Actions never imply other actions.
pub(crate) async fn authorized(
    database: &D1Database,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
    action: &str,
) -> Result<bool> {
    let row = database
        .prepare(
            "WITH RECURSIVE
             ancestors(id, parent_id) AS (
                 SELECT id, parent_id
                 FROM vfs_directories
                 WHERE id = ?1
                 UNION
                 SELECT parent.id, parent.parent_id
                 FROM vfs_directories AS parent
                 JOIN ancestors AS child ON child.parent_id = parent.id
             ),
             acl_directories(id, parent_id, acl_inherits) AS (
                 SELECT id, parent_id, acl_inherits
                 FROM vfs_directories
                 WHERE id = ?1
                 UNION
                 SELECT parent.id, parent.parent_id, parent.acl_inherits
                 FROM vfs_directories AS parent
                 JOIN acl_directories AS child ON child.parent_id = parent.id
                 WHERE child.acl_inherits = 1
             ),
             token_chain(
                 id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
             ) AS (
                 SELECT id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
                 FROM vfs_token_verifiers
                 WHERE id = ?2
                 UNION
                 SELECT parent.id, parent.parent_token_id, parent.principal_id,
                        parent.sealed_at, parent.revoked_at, parent.expires_at
                 FROM vfs_token_verifiers AS parent
                 JOIN token_chain AS child ON child.parent_token_id = parent.id
             )
             SELECT EXISTS (
                 SELECT 1
                 FROM vfs_token_verifiers AS verifier
                 JOIN vfs_principals AS principal
                   ON principal.id = verifier.principal_id
                 JOIN vfs_directories AS target ON target.id = ?1
                 WHERE verifier.id = ?2
                   AND verifier.principal_id = ?3
                   AND verifier.sealed_at IS NOT NULL
                   AND verifier.revoked_at IS NULL
                   AND verifier.expires_at > unixepoch()
                   AND verifier.snapshot_id IS NULL
                   AND principal.state = 'active'
                   AND target.state = 'active'
                   AND EXISTS (
                       SELECT 1 FROM ancestors
                       WHERE id = verifier.root_directory_id
                   )
                   AND EXISTS (
                       SELECT 1 FROM vfs_token_actions
                       WHERE token_id = verifier.id AND action = ?4
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM token_chain AS chain
                       WHERE chain.sealed_at IS NULL
                          OR chain.revoked_at IS NOT NULL
                          OR chain.expires_at <= unixepoch()
                          OR chain.principal_id != verifier.principal_id
                   )
                   AND EXISTS (
                       SELECT 1
                       FROM vfs_acl_grants AS grant
                       WHERE grant.action = ?4
                         AND grant.directory_id IN (
                             SELECT id FROM acl_directories
                         )
                         AND (
                             grant.principal_id = verifier.principal_id
                             OR EXISTS (
                                 SELECT 1
                                 FROM vfs_group_members AS membership
                                 WHERE membership.group_id = grant.group_id
                                   AND membership.principal_id = verifier.principal_id
                             )
                         )
                   )
             ) AS allowed",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(&token.id),
            JsValue::from_str(&token.principal_id),
            JsValue::from_str(action),
        ])?
        .first::<AuthorizationRow>(None)
        .await?;

    Ok(row.is_some_and(|result| result.allowed == 1))
}
