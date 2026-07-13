#![allow(
    dead_code,
    reason = "V2 routes consume token authentication as they are introduced"
)]

use std::fmt::Write as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Env, Request, Result, wasm_bindgen::JsValue};

const TOKEN_BYTES: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AuthenticatedVfsToken {
    pub(crate) id: String,
    pub(crate) principal_id: String,
    pub(crate) expires_at: u64,
}

/// Authenticates a VFS bearer token without authorizing an operation.
///
/// Authorization remains a separate directory/action/driver check and is
/// repeated inside every mutation commit. A child token fails when any token
/// in its attenuation chain is revoked, expired, unsealed, or changes
/// principal identity.
pub(crate) async fn authenticate(
    request: &Request,
    env: &Env,
) -> Result<Option<AuthenticatedVfsToken>> {
    let Some(token) = bearer_token(request)? else {
        return Ok(None);
    };
    let verifier = token_verifier(&token);
    let database = env.d1("CARRACK_INDEX")?;
    let authenticated = database
        .prepare(
            "WITH RECURSIVE token_chain(
                 id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
             ) AS (
                 SELECT id, parent_token_id, principal_id, sealed_at, revoked_at, expires_at
                 FROM vfs_token_verifiers
                 WHERE verifier_algorithm = 'sha256/v1' AND verifier_sha256 = ?1
                 UNION
                 SELECT parent.id, parent.parent_token_id, parent.principal_id,
                        parent.sealed_at, parent.revoked_at, parent.expires_at
                 FROM vfs_token_verifiers AS parent
                 JOIN token_chain AS child ON child.parent_token_id = parent.id
             )
             SELECT token.id, token.principal_id, token.expires_at
             FROM vfs_token_verifiers AS token
             JOIN vfs_principals AS principal ON principal.id = token.principal_id
             WHERE token.verifier_algorithm = 'sha256/v1'
               AND token.verifier_sha256 = ?1
               AND token.sealed_at IS NOT NULL
               AND token.revoked_at IS NULL
               AND token.expires_at > unixepoch()
               AND principal.state = 'active'
               AND NOT EXISTS (
                   SELECT 1
                   FROM token_chain AS chain
                   WHERE chain.sealed_at IS NULL
                      OR chain.revoked_at IS NOT NULL
                      OR chain.expires_at <= unixepoch()
                      OR chain.principal_id != token.principal_id
               )",
        )
        .bind(&[JsValue::from_str(&verifier)])?
        .first::<AuthenticatedVfsToken>(None)
        .await?;

    Ok(authenticated)
}

fn bearer_token(request: &Request) -> Result<Option<String>> {
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

    Ok(Some(token.to_owned()))
}

fn token_verifier(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_stable_and_does_not_store_the_bearer_secret() {
        let token = URL_SAFE_NO_PAD.encode([7_u8; TOKEN_BYTES]);
        let verifier = token_verifier(&token);

        assert_eq!(token.len(), 43);
        assert_eq!(verifier.len(), 64);
        assert!(!verifier.contains(&token));
        assert_eq!(verifier, token_verifier(&token));
    }
}
