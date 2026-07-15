use serde::{Deserialize, Serialize};
use serde_json::Value;
use worker::{Date, Env, Request, Response, Result, wasm_bindgen::JsValue};

use crate::{environment_defaults, operator_sessions};

const DATABASE_BINDING: &str = "CARRACK_INDEX";
const DEFAULT_EVENT_PAGE_SIZE: u64 = 100;
const MAXIMUM_EVENT_PAGE_SIZE: u64 = 250;

#[derive(Deserialize)]
struct DriverRow {
    id: String,
    kind: String,
    lifecycle_owner: String,
    config_json: String,
    enabled: u64,
    revision: u64,
    credential_present: u64,
    credential_rotated_at: Option<u64>,
    credential_expires_at: Option<u64>,
    credential_refresh_state: Option<String>,
    credential_refresh_after: Option<u64>,
    credential_refresh_last_succeeded_at: Option<u64>,
    credential_refresh_last_error_code: Option<String>,
    credential_refresh_token_expires_at: Option<u64>,
    placement_count: u64,
    location_count: u64,
    available_location_count: u64,
    encoded_bytes: u64,
    file_count: u64,
    quota_revision: u64,
    max_physical_bytes: Option<u64>,
    max_object_count: Option<u64>,
    reserved_physical_bytes: u64,
    reserved_object_count: u64,
    updated_at: u64,
}

#[derive(Serialize)]
struct DriverView {
    id: String,
    kind: String,
    lifecycle_owner: String,
    config: Value,
    enabled: bool,
    revision: u64,
    credential_present: bool,
    credential_rotated_at: Option<u64>,
    credential_expires_at: Option<u64>,
    credential_refresh_state: Option<String>,
    credential_refresh_after: Option<u64>,
    credential_refresh_last_succeeded_at: Option<u64>,
    credential_refresh_last_error_code: Option<String>,
    credential_refresh_token_expires_at: Option<u64>,
    placement_count: u64,
    location_count: u64,
    available_location_count: u64,
    encoded_bytes: u64,
    file_count: u64,
    quota_revision: u64,
    max_physical_bytes: Option<u64>,
    max_object_count: Option<u64>,
    reserved_physical_bytes: u64,
    reserved_object_count: u64,
    updated_at: u64,
}

#[derive(Deserialize, Serialize)]
struct FilesystemView {
    id: String,
    name: String,
    state: String,
    revision: u64,
    root_directory_id: String,
    directory_count: u64,
    file_count: u64,
    logical_bytes: u64,
    available_location_count: u64,
    encoded_bytes: u64,
    updated_at: u64,
}

#[derive(Deserialize)]
struct TokenRow {
    id: String,
    label: String,
    note: String,
    metadata_revision: u64,
    principal_id: String,
    principal_name: String,
    root_directory_id: String,
    root_directory_name: String,
    parent_token_id: Option<String>,
    snapshot_id: Option<String>,
    actions_json: String,
    drivers_json: String,
    expires_at: u64,
    sealed_at: Option<u64>,
    revoked_at: Option<u64>,
    created_at: u64,
    last_used_at: Option<u64>,
}

#[derive(Serialize)]
struct TokenView {
    id: String,
    label: String,
    note: String,
    metadata_revision: u64,
    principal_id: String,
    principal_name: String,
    root_directory_id: String,
    root_directory_name: String,
    parent_token_id: Option<String>,
    snapshot_id: Option<String>,
    actions: Vec<String>,
    driver_ids: Vec<String>,
    expires_at: u64,
    sealed_at: Option<u64>,
    revoked_at: Option<u64>,
    created_at: u64,
    last_used_at: Option<u64>,
}

#[derive(Deserialize)]
struct CursorRow {
    event_cursor: u64,
}

#[derive(Serialize)]
struct CursorResponse {
    schema: &'static str,
    observed_at: u64,
    event_cursor: u64,
}

#[derive(Serialize)]
struct SnapshotResponse {
    schema: &'static str,
    observed_at: u64,
    event_cursor: u64,
    drivers: Vec<DriverView>,
    filesystems: Vec<FilesystemView>,
    tokens: Vec<TokenView>,
}

#[derive(Deserialize)]
struct ActivityItemRow {
    kind: String,
    id: String,
    subject_kind: String,
    subject_id: String,
    state: String,
    driver_id: Option<String>,
    created_at: u64,
    updated_at: u64,
    deadline_at: Option<u64>,
    attempt_count: u64,
    last_error_code: Option<String>,
    attention_required: u64,
}

#[derive(Serialize)]
struct ActivityItemView {
    kind: String,
    id: String,
    subject_kind: String,
    subject_id: String,
    state: String,
    driver_id: Option<String>,
    created_at: u64,
    updated_at: u64,
    deadline_at: Option<u64>,
    attempt_count: u64,
    last_error_code: Option<String>,
    attention_required: bool,
}

#[derive(Deserialize)]
struct ActivityEventRow {
    id: u64,
    filesystem_id: Option<String>,
    principal_id: Option<String>,
    token_id: Option<String>,
    event_kind: String,
    subject_kind: String,
    subject_id: String,
    details_json: String,
    created_at: u64,
}

#[derive(Serialize)]
struct ActivityEventView {
    id: u64,
    filesystem_id: Option<String>,
    principal_id: Option<String>,
    token_id: Option<String>,
    event_kind: String,
    subject_kind: String,
    subject_id: String,
    details: Value,
    created_at: u64,
}

#[derive(Serialize)]
struct ActivityResponse {
    schema: &'static str,
    observed_at: u64,
    event_cursor: u64,
    active_items: Vec<ActivityItemView>,
    events: Vec<ActivityEventView>,
}

#[derive(Serialize)]
struct EventPageResponse {
    schema: &'static str,
    observed_at: u64,
    after: u64,
    event_cursor: u64,
    next_after: u64,
    has_more: bool,
    events: Vec<ActivityEventView>,
}

#[derive(Deserialize, Serialize)]
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
    child_directory_count: u64,
    recursive_directory_count: u64,
    recursive_file_count: u64,
    recursive_logical_bytes: u64,
    quota_revision: u64,
    max_file_bytes: Option<u64>,
    max_logical_bytes: Option<u64>,
    max_file_count: Option<u64>,
}

#[derive(Serialize)]
struct DirectoryView {
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
    child_directory_count: u64,
    recursive_directory_count: u64,
    recursive_file_count: u64,
    recursive_logical_bytes: u64,
    quota_revision: u64,
    max_file_bytes: Option<u64>,
    max_logical_bytes: Option<u64>,
    max_file_count: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct BreadcrumbRow {
    id: String,
    name: String,
    depth: u64,
}

#[derive(Deserialize)]
struct PlacementRow {
    driver_id: String,
}

#[derive(Deserialize)]
struct EntryRow {
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
    driver_ids_json: String,
}

#[derive(Serialize)]
struct EntryView {
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
    driver_ids: Vec<String>,
}

#[derive(Serialize)]
struct DirectoryResponse {
    schema: &'static str,
    observed_at: u64,
    directory: DirectoryView,
    breadcrumbs: Vec<BreadcrumbRow>,
    placements: Vec<String>,
    entries: Vec<EntryView>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the snapshot assembles three independently bounded management read models"
)]
pub(crate) async fn snapshot(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    let database = env.d1(DATABASE_BINDING)?;
    let now = Date::now().as_millis() / 1_000;
    environment_defaults::ensure(env, &database, now).await?;
    let driver_rows = database
        .prepare(
            r"SELECT driver.id, driver.kind, driver.lifecycle_owner, driver.config_json,
                    driver.enabled, driver.revision,
                    CASE WHEN driver.credential_ref IS NULL THEN 0 ELSE 1 END AS credential_present,
                    credential.rotated_at AS credential_rotated_at,
                    credential.expires_at AS credential_expires_at,
                    CASE
                      WHEN driver.kind = 'aliyundrive-open/v2'
                       AND credential.id IS NOT NULL AND refresh.credential_id IS NULL
                      THEN 'reauth_required'
                      ELSE refresh.state
                    END AS credential_refresh_state,
                    refresh.refresh_after AS credential_refresh_after,
                    refresh.last_succeeded_at AS credential_refresh_last_succeeded_at,
                    CASE
                      WHEN driver.kind = 'aliyundrive-open/v2'
                       AND credential.id IS NOT NULL AND refresh.credential_id IS NULL
                      THEN 'refresh_token_missing'
                      ELSE refresh.last_error_code
                    END AS credential_refresh_last_error_code,
                    refresh.refresh_token_expires_at AS credential_refresh_token_expires_at,
                    (SELECT COUNT(*) FROM vfs_directory_drivers AS directory_driver
                     WHERE directory_driver.driver_id = driver.id) AS placement_count,
                    (SELECT COUNT(*) FROM vfs_locations AS location
                     WHERE location.driver_id = driver.id) AS location_count,
                    (SELECT COUNT(*) FROM vfs_locations AS location
                     WHERE location.driver_id = driver.id AND location.state = 'available')
                        AS available_location_count,
                    COALESCE((SELECT SUM(location.size_bytes) FROM vfs_locations AS location
                              WHERE location.driver_id = driver.id
                                AND location.state = 'available'), 0) AS encoded_bytes,
                    (SELECT COUNT(DISTINCT version.file_id)
                     FROM vfs_locations AS location
                     JOIN vfs_file_versions AS version ON version.id = location.version_id
                     WHERE location.driver_id = driver.id AND location.state = 'available')
                        AS file_count,
                    quota.revision AS quota_revision,
                    quota.max_physical_bytes, quota.max_object_count,
                    COALESCE((SELECT SUM(CASE
                        WHEN intent.crypto_suite = 'plaintext/v1' THEN intent.plaintext_bytes
                        ELSE intent.plaintext_bytes + 16 * CASE
                            WHEN intent.plaintext_bytes = 0 THEN 0
                            ELSE 1 + (intent.plaintext_bytes - 1) / intent.encryption_frame_bytes
                        END END)
                     FROM vfs_put_intents AS intent
                     WHERE intent.driver_id = driver.id AND intent.state = 'prepared'
                       AND intent.expires_at > unixepoch()), 0) AS reserved_physical_bytes,
                    (SELECT COUNT(*) FROM vfs_put_intents AS intent
                     WHERE intent.driver_id = driver.id AND intent.state = 'prepared'
                       AND intent.expires_at > unixepoch()) AS reserved_object_count,
                    driver.updated_at
             FROM driver_instances AS driver
             LEFT JOIN credential_envelopes AS credential ON credential.id = driver.credential_ref
             LEFT JOIN driver_credential_refreshes AS refresh
               ON refresh.credential_id = credential.id
             JOIN driver_quota_policies AS quota ON quota.driver_id = driver.id
             WHERE driver.retired_at IS NULL
             ORDER BY driver.id",
        )
        .all()
        .await?
        .results::<DriverRow>()?;
    let drivers = driver_rows
        .into_iter()
        .map(|row| DriverView {
            id: row.id,
            kind: row.kind,
            lifecycle_owner: row.lifecycle_owner,
            config: redact_config(&row.config_json),
            enabled: row.enabled == 1,
            revision: row.revision,
            credential_present: row.credential_present == 1,
            credential_rotated_at: row.credential_rotated_at,
            credential_expires_at: row.credential_expires_at,
            credential_refresh_state: row.credential_refresh_state,
            credential_refresh_after: row.credential_refresh_after,
            credential_refresh_last_succeeded_at: row.credential_refresh_last_succeeded_at,
            credential_refresh_last_error_code: row.credential_refresh_last_error_code,
            credential_refresh_token_expires_at: row.credential_refresh_token_expires_at,
            placement_count: row.placement_count,
            location_count: row.location_count,
            available_location_count: row.available_location_count,
            encoded_bytes: row.encoded_bytes,
            file_count: row.file_count,
            quota_revision: row.quota_revision,
            max_physical_bytes: row.max_physical_bytes,
            max_object_count: row.max_object_count,
            reserved_physical_bytes: row.reserved_physical_bytes,
            reserved_object_count: row.reserved_object_count,
            updated_at: row.updated_at,
        })
        .collect();

    let filesystems = database
        .prepare(
            r"SELECT filesystem.id, filesystem.name, filesystem.state, filesystem.revision,
                    root.id AS root_directory_id,
                    (SELECT COUNT(*) FROM vfs_directories AS directory
                     WHERE directory.filesystem_id = filesystem.id
                       AND directory.state = 'active') AS directory_count,
                    (SELECT COUNT(*) FROM vfs_files AS file
                     WHERE file.filesystem_id = filesystem.id
                       AND file.state = 'active') AS file_count,
                    COALESCE((SELECT SUM(version.plaintext_bytes)
                              FROM vfs_files AS file
                              JOIN vfs_file_versions AS version
                                ON version.id = file.current_version_id
                              WHERE file.filesystem_id = filesystem.id
                                AND file.state = 'active'), 0) AS logical_bytes,
                    (SELECT COUNT(*) FROM vfs_locations AS location
                     JOIN vfs_file_versions AS version ON version.id = location.version_id
                     JOIN vfs_files AS file ON file.id = version.file_id
                     WHERE file.filesystem_id = filesystem.id
                       AND location.state = 'available') AS available_location_count,
                    COALESCE((SELECT SUM(location.size_bytes)
                              FROM vfs_locations AS location
                              JOIN vfs_file_versions AS version ON version.id = location.version_id
                              JOIN vfs_files AS file ON file.id = version.file_id
                              WHERE file.filesystem_id = filesystem.id
                                AND location.state = 'available'), 0) AS encoded_bytes,
                    filesystem.updated_at
             FROM vfs_filesystems AS filesystem
             JOIN vfs_directories AS root
               ON root.filesystem_id = filesystem.id AND root.parent_id IS NULL
             ORDER BY filesystem.name, filesystem.id",
        )
        .all()
        .await?
        .results::<FilesystemView>()?;

    let token_rows = database
        .prepare(
            r"SELECT token.id, metadata.label, metadata.note,
                    metadata.revision AS metadata_revision,
                    token.principal_id, principal.display_name AS principal_name,
                    token.root_directory_id, directory.name AS root_directory_name,
                    token.parent_token_id, token.snapshot_id,
                    COALESCE((SELECT json_group_array(action) FROM
                        (SELECT action FROM vfs_token_actions
                         WHERE token_id = token.id ORDER BY action)), '[]') AS actions_json,
                    COALESCE((SELECT json_group_array(driver_id) FROM
                        (SELECT driver_id FROM vfs_token_drivers
                         WHERE token_id = token.id ORDER BY driver_id)), '[]') AS drivers_json,
                    token.expires_at, token.sealed_at, token.revoked_at, token.created_at,
                    (SELECT MAX(event.created_at) FROM vfs_audit_events AS event
                     WHERE event.token_id = token.id) AS last_used_at
             FROM vfs_token_verifiers AS token
             JOIN vfs_token_metadata AS metadata ON metadata.token_id = token.id
             JOIN vfs_principals AS principal ON principal.id = token.principal_id
             JOIN vfs_directories AS directory ON directory.id = token.root_directory_id
             ORDER BY token.created_at DESC, token.id",
        )
        .all()
        .await?
        .results::<TokenRow>()?;
    let tokens = token_rows
        .into_iter()
        .map(|row| TokenView {
            label: row.label,
            note: row.note,
            metadata_revision: row.metadata_revision,
            id: row.id,
            principal_id: row.principal_id,
            principal_name: row.principal_name,
            root_directory_id: row.root_directory_id,
            root_directory_name: row.root_directory_name,
            parent_token_id: row.parent_token_id,
            snapshot_id: row.snapshot_id,
            actions: parse_string_array(&row.actions_json),
            driver_ids: parse_string_array(&row.drivers_json),
            expires_at: row.expires_at,
            sealed_at: row.sealed_at,
            revoked_at: row.revoked_at,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        })
        .collect();
    let cursor = database
        .prepare("SELECT COALESCE(MAX(id), 0) AS event_cursor FROM vfs_audit_events")
        .first::<CursorRow>(None)
        .await?
        .map_or(0, |row| row.event_cursor);

    no_store_json(&SnapshotResponse {
        schema: "carrack.management.snapshot.v2",
        observed_at: now_seconds(),
        event_cursor: cursor,
        drivers,
        filesystems,
        tokens,
    })
}

pub(crate) async fn event_cursor(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let database = env.d1(DATABASE_BINDING)?;
    let cursor = database
        .prepare("SELECT COALESCE(MAX(id), 0) AS event_cursor FROM vfs_audit_events")
        .first::<CursorRow>(None)
        .await?
        .map_or(0, |row| row.event_cursor);
    no_store_json(&CursorResponse {
        schema: "carrack.management.event-cursor.v1",
        observed_at: now_seconds(),
        event_cursor: cursor,
    })
}

/// Returns one bounded, ascending audit-event page after a monotonic cursor.
///
/// The response pins the current high-water mark before reading rows. Events
/// appended during the request are therefore left for the next page rather
/// than making a busy environment an unbounded response.
pub(crate) async fn events(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let Some((after, limit)) = event_page_options(request)? else {
        return Response::error("invalid management event query", 400);
    };

    let database = env.d1(DATABASE_BINDING)?;
    let event_cursor = database
        .prepare("SELECT COALESCE(MAX(id), 0) AS event_cursor FROM vfs_audit_events")
        .first::<CursorRow>(None)
        .await?
        .map_or(0, |row| row.event_cursor);
    if after > event_cursor {
        return Response::error("management event cursor is ahead of this environment", 409);
    }

    let bindings = [
        JsValue::from_str(&after.to_string()),
        JsValue::from_str(&event_cursor.to_string()),
        JsValue::from_str(&(limit + 1).to_string()),
    ];
    let mut rows = database
        .prepare(
            r"SELECT id, filesystem_id, principal_id, token_id, event_kind,
                     subject_kind, subject_id, details_json, created_at
              FROM vfs_audit_events
              WHERE id > CAST(?1 AS INTEGER) AND id <= CAST(?2 AS INTEGER)
              ORDER BY id
              LIMIT CAST(?3 AS INTEGER)",
        )
        .bind(&bindings)?
        .all()
        .await?
        .results::<ActivityEventRow>()?;
    let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next_after = rows.last().map_or(after, |row| row.id);
    let events = rows.into_iter().map(event_view).collect();

    no_store_json(&EventPageResponse {
        schema: "carrack.management.events.v1",
        observed_at: now_seconds(),
        after,
        event_cursor,
        next_after,
        has_more,
        events,
    })
}

/// Returns bounded, current VFS lifecycle work and the newest audit events.
///
/// Direct provider payload progress remains client-local by design. This view
/// exposes only durable control-plane state, so an empty response never implies
/// that a direct transfer has stopped or failed.
#[allow(
    clippy::too_many_lines,
    reason = "one bounded union keeps the complete VFS lifecycle projection and its attention classification visible"
)]
pub(crate) async fn activity(request: &Request, env: &Env) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }

    let database = env.d1(DATABASE_BINDING)?;
    let now = now_seconds();
    let binding = [JsValue::from_str(&now.to_string())];
    let mut item_rows = database
        .prepare(
            r"SELECT kind, id, subject_kind, subject_id, state, driver_id,
                     created_at, updated_at, deadline_at, attempt_count,
                     last_error_code, attention_required
              FROM (
                  SELECT 'upload' AS kind, intent.id, 'put_intent' AS subject_kind,
                         intent.id AS subject_id, intent.state, intent.driver_id,
                         intent.created_at, intent.created_at AS updated_at,
                         intent.expires_at AS deadline_at, 0 AS attempt_count,
                         NULL AS last_error_code, 0 AS attention_required
                  FROM vfs_put_intents AS intent
                  WHERE intent.state = 'prepared' AND intent.expires_at > CAST(?1 AS INTEGER)
                  UNION ALL
                  SELECT 'download' AS kind, lease.id, 'read_lease' AS subject_kind,
                         lease.version_id AS subject_id, 'active' AS state,
                         location.driver_id, lease.created_at, lease.created_at AS updated_at,
                         lease.expires_at AS deadline_at, 0 AS attempt_count,
                         NULL AS last_error_code, 0 AS attention_required
                  FROM vfs_read_leases AS lease
                  JOIN vfs_locations AS location ON location.id = lease.location_id
                  WHERE lease.completed_at IS NULL
                    AND lease.expires_at > CAST(?1 AS INTEGER)
                  UNION ALL
                  SELECT 'location_delete' AS kind, task.id,
                         'location_delete_task' AS subject_kind, task.id AS subject_id,
                         task.state, task.driver_id, task.created_at, task.updated_at,
                         task.delete_after AS deadline_at, task.attempt_count,
                         task.last_error_code,
                         CASE WHEN task.state IN ('retry', 'blocked') THEN 1 ELSE 0 END
                             AS attention_required
                  FROM vfs_location_delete_tasks AS task
                  WHERE task.state IN ('pending', 'claimed', 'retry', 'blocked')
              )
              ORDER BY attention_required DESC, updated_at DESC, id
              LIMIT 100",
        )
        .bind(&binding)?
        .all()
        .await?
        .results::<ActivityItemRow>()?;
    item_rows.extend(
        database
            .prepare(
                r"SELECT kind, id, subject_kind, subject_id, state, driver_id,
                         created_at, updated_at, deadline_at, attempt_count,
                         last_error_code, attention_required
                  FROM (
                  SELECT 'put_cleanup' AS kind, task.id,
                         'put_delete_task' AS subject_kind, task.id AS subject_id,
                         CASE WHEN task.server_blocked_at IS NULL THEN task.state
                              ELSE 'blocked' END AS state,
                         intent.driver_id, task.created_at, task.updated_at,
                         task.delete_after AS deadline_at, task.attempt_count,
                         task.last_error_code,
                         CASE WHEN task.state = 'failed' OR task.server_blocked_at IS NOT NULL
                              THEN 1 ELSE 0 END AS attention_required
                  FROM vfs_put_delete_tasks AS task
                  JOIN vfs_put_intents AS intent ON intent.id = task.id
                  WHERE task.state IN ('pending', 'claimed', 'failed')
                  UNION ALL
                  SELECT 'r2_upload_cleanup' AS kind, task.intent_id AS id,
                         'r2_upload_cleanup_task' AS subject_kind,
                         task.intent_id AS subject_id, task.state, intent.driver_id,
                         task.created_at, task.updated_at,
                         task.lease_expires_at AS deadline_at, task.attempt_count,
                         task.last_error_code,
                         CASE WHEN task.state = 'failed' THEN 1 ELSE 0 END
                             AS attention_required
                  FROM vfs_r2_upload_cleanup_tasks AS task
                  CROSS JOIN vfs_put_intents AS intent ON intent.id = task.intent_id
                  WHERE task.state IN ('active', 'cleaning', 'failed')
                    AND (task.state IN ('cleaning', 'failed')
                         OR intent.state IN ('expired', 'abandoned'))
                  UNION ALL
                  SELECT 'credential_refresh' AS kind, refresh.credential_id AS id,
                         'driver_credential' AS subject_kind,
                         refresh.driver_id AS subject_id, refresh.state,
                         refresh.driver_id, refresh.created_at, refresh.updated_at,
                         COALESCE(refresh.retry_at, refresh.lease_expires_at,
                                  refresh.refresh_after) AS deadline_at,
                         refresh.attempt_count, refresh.last_error_code,
                         CASE WHEN refresh.state IN ('retry', 'reauth_required')
                              THEN 1 ELSE 0 END AS attention_required
                  FROM driver_credential_refreshes AS refresh
                  WHERE refresh.state IN ('claimed', 'retry', 'reauth_required')
                  )
                  ORDER BY attention_required DESC, updated_at DESC, id
                  LIMIT 100",
            )
            .all()
            .await?
            .results::<ActivityItemRow>()?,
    );
    item_rows.sort_by(|left, right| {
        right
            .attention_required
            .cmp(&left.attention_required)
            .then_with(|| right.updated_at.cmp(&left.updated_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    item_rows.truncate(100);
    let active_items = item_rows
        .into_iter()
        .map(|row| ActivityItemView {
            kind: row.kind,
            id: row.id,
            subject_kind: row.subject_kind,
            subject_id: row.subject_id,
            state: row.state,
            driver_id: row.driver_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            deadline_at: row.deadline_at,
            attempt_count: row.attempt_count,
            last_error_code: row.last_error_code,
            attention_required: row.attention_required == 1,
        })
        .collect();

    let event_rows = database
        .prepare(
            r"SELECT id, filesystem_id, principal_id, token_id, event_kind,
                     subject_kind, subject_id, details_json, created_at
              FROM vfs_audit_events
              ORDER BY id DESC
              LIMIT 100",
        )
        .all()
        .await?
        .results::<ActivityEventRow>()?;
    let event_cursor = event_rows.first().map_or(0, |row| row.id);
    let events = event_rows.into_iter().map(event_view).collect();

    no_store_json(&ActivityResponse {
        schema: "carrack.management.activity.v1",
        observed_at: now,
        event_cursor,
        active_items,
        events,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the directory response keeps identity, aggregates, path, placements, and entries revision-consistent"
)]
pub(crate) async fn directory(
    request: &Request,
    env: &Env,
    directory_id: Option<&str>,
) -> Result<Response> {
    if !operator_sessions::authorized(request, env).await? {
        return Response::error("authentication required", 401);
    }
    let Some(directory_id) = directory_id.filter(|value| valid_identifier(value)) else {
        return Response::error("valid directory ID is required", 400);
    };

    let database = env.d1(DATABASE_BINDING)?;
    let binding = [JsValue::from_str(directory_id)];
    let Some(row) = database
        .prepare(
            r"WITH RECURSIVE descendants(id) AS (
                 SELECT id FROM vfs_directories WHERE id = ?1
                 UNION ALL
                 SELECT child.id FROM vfs_directories AS child
                 JOIN descendants AS parent ON child.parent_id = parent.id
                 WHERE child.state = 'active'
             )
             SELECT directory.id, directory.filesystem_id, directory.parent_id, directory.name,
                    directory.data_root, directory.crypto_suite, directory.active_key_epoch,
                    directory.acl_inherits, directory.revision, directory.acl_revision,
                    directory.placement_revision,
                    quota.revision AS quota_revision, quota.max_file_bytes,
                    quota.max_logical_bytes, quota.max_file_count,
                    (SELECT COUNT(*) FROM vfs_directories AS child
                     WHERE child.parent_id = directory.id AND child.state = 'active')
                        AS child_directory_count,
                    (SELECT COUNT(*) - 1 FROM descendants) AS recursive_directory_count,
                    (SELECT COUNT(*) FROM vfs_directory_entries AS entry
                     WHERE entry.directory_id IN (SELECT id FROM descendants)
                       AND entry.kind = 'file') AS recursive_file_count,
                    COALESCE((SELECT SUM(entry.size_bytes) FROM vfs_directory_entries AS entry
                              WHERE entry.directory_id IN (SELECT id FROM descendants)
                                AND entry.kind = 'file'), 0) AS recursive_logical_bytes
             FROM vfs_directories AS directory
             JOIN vfs_directory_quota_policies AS quota ON quota.directory_id = directory.id
             WHERE directory.id = ?1 AND directory.state = 'active'",
        )
        .bind(&binding)?
        .first::<DirectoryRow>(None)
        .await?
    else {
        return Response::error("directory not found", 404);
    };

    let mut breadcrumbs = database
        .prepare(
            r"WITH RECURSIVE ancestors(id, name, parent_id, depth) AS (
                 SELECT id, name, parent_id, 0 FROM vfs_directories WHERE id = ?1
                 UNION ALL
                 SELECT parent.id, parent.name, parent.parent_id, child.depth + 1
                 FROM vfs_directories AS parent
                 JOIN ancestors AS child ON child.parent_id = parent.id
             ) SELECT id, name, depth FROM ancestors ORDER BY depth DESC",
        )
        .bind(&binding)?
        .all()
        .await?
        .results::<BreadcrumbRow>()?;
    if let Some(root) = breadcrumbs.first_mut()
        && root.name.is_empty()
    {
        "/".clone_into(&mut root.name);
    }

    let placements = database
        .prepare(
            r"SELECT driver_id FROM vfs_directory_drivers
             WHERE directory_id = ?1 AND state = 'active'
             ORDER BY write_priority, driver_id",
        )
        .bind(&binding)?
        .all()
        .await?
        .results::<PlacementRow>()?
        .into_iter()
        .map(|row| row.driver_id)
        .collect();
    let entry_rows = database
        .prepare(
            r"SELECT entry.name, entry.kind, entry.file_id, entry.version_id,
                    entry.child_directory_id, entry.size_bytes, entry.data_root,
                    entry.metadata_root, entry.revision, entry.updated_at,
                    CASE WHEN entry.version_id IS NULL THEN '[]' ELSE
                        COALESCE((SELECT json_group_array(driver_id) FROM
                            (SELECT location.driver_id FROM vfs_locations AS location
                             WHERE location.version_id = entry.version_id
                               AND location.state = 'available'
                             ORDER BY location.driver_id)), '[]') END AS driver_ids_json
             FROM vfs_directory_entries AS entry
             WHERE entry.directory_id = ?1
             ORDER BY entry.kind, entry.name LIMIT 1000",
        )
        .bind(&binding)?
        .all()
        .await?
        .results::<EntryRow>()?;
    let entries = entry_rows
        .into_iter()
        .map(|entry| EntryView {
            name: entry.name,
            kind: entry.kind,
            file_id: entry.file_id,
            version_id: entry.version_id,
            child_directory_id: entry.child_directory_id,
            size_bytes: entry.size_bytes,
            data_root: entry.data_root,
            metadata_root: entry.metadata_root,
            revision: entry.revision,
            updated_at: entry.updated_at,
            driver_ids: parse_string_array(&entry.driver_ids_json),
        })
        .collect();

    no_store_json(&DirectoryResponse {
        schema: "carrack.management.directory.v1",
        observed_at: now_seconds(),
        directory: DirectoryView {
            id: row.id,
            filesystem_id: row.filesystem_id,
            parent_id: row.parent_id,
            name: row.name,
            data_root: row.data_root,
            crypto_suite: row.crypto_suite,
            active_key_epoch: row.active_key_epoch,
            acl_inherits: row.acl_inherits == 1,
            revision: row.revision,
            acl_revision: row.acl_revision,
            placement_revision: row.placement_revision,
            child_directory_count: row.child_directory_count,
            recursive_directory_count: row.recursive_directory_count,
            recursive_file_count: row.recursive_file_count,
            recursive_logical_bytes: row.recursive_logical_bytes,
            quota_revision: row.quota_revision,
            max_file_bytes: row.max_file_bytes,
            max_logical_bytes: row.max_logical_bytes,
            max_file_count: row.max_file_count,
        },
        breadcrumbs,
        placements,
        entries,
    })
}

fn no_store_json<T: Serialize>(value: &T) -> Result<Response> {
    let mut response = Response::from_json(value)?;
    response
        .headers_mut()
        .set("Cache-Control", "no-store, max-age=0")?;
    Ok(response)
}

fn parse_string_array(encoded: &str) -> Vec<String> {
    serde_json::from_str(encoded).unwrap_or_default()
}

fn redact_config(encoded: &str) -> Value {
    let mut value = serde_json::from_str(encoded).unwrap_or(Value::Null);
    redact_value(&mut value);
    value
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if sensitive_key(key) {
                    *value = Value::String("[redacted]".to_owned());
                } else {
                    redact_value(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(redact_value),
        _ => {}
    }
}

fn sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    [
        "secret",
        "password",
        "credential",
        "token",
        "private_key",
        "access_key",
        "client_secret",
    ]
    .iter()
    .any(|needle| key == *needle || key.ends_with(&format!("_{needle}")))
}

fn event_view(row: ActivityEventRow) -> ActivityEventView {
    let mut details = serde_json::from_str(&row.details_json).unwrap_or(Value::Null);
    redact_value(&mut details);
    ActivityEventView {
        id: row.id,
        filesystem_id: row.filesystem_id,
        principal_id: row.principal_id,
        token_id: row.token_id,
        event_kind: row.event_kind,
        subject_kind: row.subject_kind,
        subject_id: row.subject_id,
        details,
        created_at: row.created_at,
    }
}

fn event_page_options(request: &Request) -> Result<Option<(u64, u64)>> {
    let url = request.url()?;
    let mut after = 0;
    let mut limit = DEFAULT_EVENT_PAGE_SIZE;
    let mut saw_after = false;
    let mut saw_limit = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "after" if !saw_after => {
                saw_after = true;
                let Some(parsed) = canonical_integer(&value) else {
                    return Ok(None);
                };
                after = parsed;
            }
            "limit" if !saw_limit => {
                saw_limit = true;
                let Some(parsed) = canonical_integer(&value) else {
                    return Ok(None);
                };
                if !(1..=MAXIMUM_EVENT_PAGE_SIZE).contains(&parsed) {
                    return Ok(None);
                }
                limit = parsed;
            }
            _ => return Ok(None),
        }
    }
    Ok(Some((after, limit)))
}

fn canonical_integer(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| i64::try_from(*parsed).is_ok())
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 32
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{canonical_integer, redact_value, sensitive_key, valid_identifier};

    #[test]
    fn redacts_secret_shaped_driver_configuration() {
        let mut value = json!({
            "root": "/srv/carrack",
            "nested": { "access_key": "secret", "bucket": "archive" },
            "client-secret": "secret"
        });
        redact_value(&mut value);

        assert_eq!(value["root"], "/srv/carrack");
        assert_eq!(value["nested"]["bucket"], "archive");
        assert_eq!(value["nested"]["access_key"], "[redacted]");
        assert_eq!(value["client-secret"], "[redacted]");
        assert!(sensitive_key("provider_token"));
    }

    #[test]
    fn accepts_only_canonical_management_identifiers() {
        assert!(valid_identifier("0123456789abcdef0123456789abcdef"));
        assert!(!valid_identifier("0123456789ABCDEF0123456789ABCDEF"));
        assert!(!valid_identifier("00000000000000000000000000000000"));
        assert!(!valid_identifier("short"));
    }

    #[test]
    fn accepts_only_canonical_d1_event_cursors() {
        assert_eq!(canonical_integer("0"), Some(0));
        assert_eq!(canonical_integer("250"), Some(250));
        assert_eq!(canonical_integer("01"), None);
        assert_eq!(canonical_integer("+1"), None);
        assert_eq!(canonical_integer("-1"), None);
        assert_eq!(canonical_integer("9223372036854775808"), None);
    }
}
