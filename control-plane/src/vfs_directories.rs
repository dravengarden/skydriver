use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use worker::{D1Database, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{vfs_access, vfs_tokens::AuthenticatedVfsToken};

const DIRECTORY_LIST_SCHEMA: &str = "skydriver.vfs.directory-list.v1";
const DEFAULT_PAGE_SIZE: u64 = 200;
const MAXIMUM_PAGE_SIZE: u64 = 1_000;

#[derive(Deserialize)]
struct DirectoryRow {
    id: String,
    filesystem_id: String,
    parent_id: Option<String>,
    name: String,
    data_root: String,
    crypto_suite: String,
    active_key_epoch: u64,
    acl_inherits: u64,
    revision: u64,
    acl_revision: u64,
    placement_revision: u64,
}

#[derive(Deserialize, Serialize)]
struct DirectoryEntry {
    name: String,
    kind: String,
    file_id: Option<String>,
    version_id: Option<String>,
    child_directory_id: Option<String>,
    size_bytes: u64,
    data_root: String,
    metadata_root: Option<String>,
    revision: u64,
    updated_at: u64,
}

#[derive(Deserialize, Serialize)]
struct DirectoryCursor {
    directory_id: String,
    directory_revision: u64,
    after_name: String,
}

#[derive(Serialize)]
struct DirectoryIdentity {
    id: String,
    filesystem_id: String,
    parent_id: Option<String>,
    name: String,
    data_root: String,
    crypto_suite: String,
    active_key_epoch: u64,
    acl_inherits: bool,
    revision: u64,
    acl_revision: u64,
    placement_revision: u64,
}

#[derive(Serialize)]
struct DirectoryListResponse {
    schema: &'static str,
    directory: DirectoryIdentity,
    entries: Vec<DirectoryEntry>,
    next_cursor: Option<String>,
}

/// Lists one bounded, revision-consistent page of a VFS directory.
///
/// The cursor pins the directory revision. A concurrent namespace publication
/// returns a conflict instead of silently skipping or duplicating entries.
pub(crate) async fn list(
    request: &Request,
    env: &worker::Env,
    token: &AuthenticatedVfsToken,
    directory_id: &str,
) -> Result<Response> {
    if !valid_identifier(directory_id) {
        return Response::error("invalid VFS directory ID", 400);
    }

    let Some((limit, cursor)) = query_options(request)? else {
        return Response::error("invalid VFS directory-list query", 400);
    };
    let database = env.d1("SKYDRIVER_INDEX")?;
    if !vfs_access::authorized(&database, token, directory_id, "directory.list").await? {
        return Response::error("VFS directory-list authority required", 403);
    }

    let Some(directory) = load_directory(&database, directory_id).await? else {
        return Response::error("VFS directory not found", 404);
    };
    if let Some(position) = &cursor
        && (position.directory_id != directory.id
            || position.directory_revision != directory.revision)
    {
        return Response::error("VFS directory changed while listing", 409);
    }

    let after_name = cursor
        .as_ref()
        .map_or_else(String::new, |position| position.after_name.clone());
    let fetch_limit = limit + 1;
    let mut entries = database
        .prepare(
            "SELECT name, kind, file_id, version_id, child_directory_id,
                    size_bytes, data_root, metadata_root, revision, updated_at
             FROM vfs_directory_entries
             WHERE directory_id = ?1 AND name > ?2 COLLATE BINARY
             ORDER BY name COLLATE BINARY
             LIMIT ?3",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(&after_name),
            number_binding(fetch_limit),
        ])?
        .all()
        .await?
        .results::<DirectoryEntry>()?;

    let Some(revision_after_read) = load_directory_revision(&database, directory_id).await? else {
        return Response::error("VFS directory not found", 404);
    };
    if revision_after_read != directory.revision {
        return Response::error("VFS directory changed while listing", 409);
    }

    let has_more = entries.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    if has_more {
        entries.pop();
    }
    let next_cursor = if has_more {
        entries
            .last()
            .map(|entry| {
                encode_cursor(&DirectoryCursor {
                    directory_id: directory.id.clone(),
                    directory_revision: directory.revision,
                    after_name: entry.name.clone(),
                })
            })
            .transpose()?
    } else {
        None
    };

    let mut response = Response::from_json(&DirectoryListResponse {
        schema: DIRECTORY_LIST_SCHEMA,
        directory: DirectoryIdentity {
            id: directory.id,
            filesystem_id: directory.filesystem_id,
            parent_id: directory.parent_id,
            name: directory.name,
            data_root: directory.data_root,
            crypto_suite: directory.crypto_suite,
            active_key_epoch: directory.active_key_epoch,
            acl_inherits: directory.acl_inherits == 1,
            revision: directory.revision,
            acl_revision: directory.acl_revision,
            placement_revision: directory.placement_revision,
        },
        entries,
        next_cursor,
    })?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

async fn load_directory(database: &D1Database, directory_id: &str) -> Result<Option<DirectoryRow>> {
    database
        .prepare(
            "SELECT id, filesystem_id, parent_id, name, data_root, crypto_suite,
                    active_key_epoch, acl_inherits, revision, acl_revision,
                    placement_revision
             FROM vfs_directories
             WHERE id = ?1 AND state = 'active'",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<DirectoryRow>(None)
        .await
}

#[derive(Deserialize)]
struct DirectoryRevisionRow {
    revision: u64,
}

async fn load_directory_revision(database: &D1Database, directory_id: &str) -> Result<Option<u64>> {
    let row = database
        .prepare("SELECT revision FROM vfs_directories WHERE id = ?1 AND state = 'active'")
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<DirectoryRevisionRow>(None)
        .await?;
    Ok(row.map(|result| result.revision))
}

fn query_options(request: &Request) -> Result<Option<(u64, Option<DirectoryCursor>)>> {
    let url = request.url()?;
    let mut limit = DEFAULT_PAGE_SIZE;
    let mut cursor = None;
    let mut saw_limit = false;
    let mut saw_cursor = false;

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "limit" if !saw_limit => {
                saw_limit = true;
                let Ok(parsed) = value.parse::<u64>() else {
                    return Ok(None);
                };
                if !(1..=MAXIMUM_PAGE_SIZE).contains(&parsed) {
                    return Ok(None);
                }
                limit = parsed;
            }
            "cursor" if !saw_cursor => {
                saw_cursor = true;
                let Some(decoded) = decode_cursor(&value) else {
                    return Ok(None);
                };
                cursor = Some(decoded);
            }
            _ => return Ok(None),
        }
    }

    Ok(Some((limit, cursor)))
}

fn encode_cursor(cursor: &DirectoryCursor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_cursor(encoded: &str) -> Option<DirectoryCursor> {
    if encoded.is_empty() || encoded.len() > 1_024 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let cursor = serde_json::from_slice::<DirectoryCursor>(&bytes).ok()?;
    if !valid_identifier(&cursor.directory_id)
        || cursor.directory_revision == 0
        || !valid_entry_name(&cursor.after_name)
    {
        return None;
    }
    Some(cursor)
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_entry_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && !value.contains('/')
        && !value.contains('\0')
}

fn number_binding(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_pins_directory_and_revision() {
        let cursor = DirectoryCursor {
            directory_id: "019f10b4d77d7000a123456789abcdef".to_owned(),
            directory_revision: 17,
            after_name: "zeta.txt".to_owned(),
        };
        let encoded = encode_cursor(&cursor).expect("encode cursor");
        let decoded = decode_cursor(&encoded).expect("decode cursor");

        assert_eq!(decoded.directory_id, cursor.directory_id);
        assert_eq!(decoded.directory_revision, 17);
        assert_eq!(decoded.after_name, "zeta.txt");
    }

    #[test]
    fn cursor_rejects_noncanonical_position() {
        let encoded = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&DirectoryCursor {
                directory_id: "not-an-id".to_owned(),
                directory_revision: 1,
                after_name: "name".to_owned(),
            })
            .expect("encode fixture"),
        );

        assert!(decode_cursor(&encoded).is_none());
    }
}
