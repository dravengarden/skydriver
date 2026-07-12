use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{
    D1Database, D1PreparedStatement, Date, Env, Request, Response, Result, wasm_bindgen::JsValue,
};

use crate::{clients::AuthenticatedClient, manifests};

const METADATA_BATCH_STATEMENTS: usize = 40;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    operation_id: String,
    lease_id: String,
    incarnation: String,
    fencing_token: u64,
    manifest_sha256: String,
    recovery_sha256: String,
    r2_key: String,
    r2_version: String,
    sidecar_driver_id: String,
    sidecar_storage_key: String,
    expected_object_revision: u64,
}

#[derive(Deserialize)]
struct IntentRow {
    operation_id: String,
    client_id: String,
    manifest_sha256: String,
    recovery_sha256: String,
    r2_storage_key: String,
    r2_version: String,
    sidecar_driver_id: String,
    sidecar_storage_key: String,
    expected_object_revision: u64,
    incarnation: String,
    lease_id: String,
    fencing_token: u64,
    state: String,
}

#[derive(Serialize)]
struct PublishResponse {
    operation_id: String,
    object_id: String,
    generation: u64,
    manifest_sha256: String,
    state: &'static str,
}

pub(crate) async fn publish(
    request: &mut Request,
    env: &Env,
    client: &AuthenticatedClient,
) -> Result<Response> {
    let requested = request.json::<PublishRequest>().await?;
    if !valid_request(&requested) {
        return Response::error("invalid import publication", 400);
    }

    let (validated, r2_bytes) = load_recovery(env, &requested).await?;
    let database = env.d1("CARRACK_INDEX")?;
    create_intent(&database, client, &requested, &validated).await?;

    let Some(intent) = load_intent(&database, &requested.operation_id).await? else {
        return Response::error("publication fence or object revision was rejected", 409);
    };
    if !intent_matches(&intent, client, &requested) {
        return Response::error("operation already owns a different publication", 409);
    }

    if intent.state == "committed" {
        return published_response(&requested, &validated);
    }

    stage_metadata(&database, client, &requested, &validated).await?;
    finalize(&database, client, &requested, &validated, r2_bytes).await?;

    let committed = load_intent(&database, &requested.operation_id)
        .await?
        .is_some_and(|value| value.state == "committed");
    if !committed {
        return Response::error("publication did not commit", 409);
    }

    published_response(&requested, &validated)
}

async fn load_recovery(
    env: &Env,
    requested: &PublishRequest,
) -> Result<(manifests::ValidatedRecovery, u64)> {
    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    let Some(object) = bucket.get(&requested.r2_key).execute().await? else {
        return Err(worker::Error::RustError(
            "staged R2 recovery manifest is missing".to_owned(),
        ));
    };
    if object.version() != requested.r2_version {
        return Err(worker::Error::RustError(
            "staged R2 recovery version changed".to_owned(),
        ));
    }

    let Some(body) = object.body() else {
        return Err(worker::Error::RustError(
            "staged R2 recovery body is missing".to_owned(),
        ));
    };
    let encoded = body.bytes().await?;
    let recovery_digest = lowercase_hex(&Sha256::digest(&encoded));
    if recovery_digest != requested.recovery_sha256 {
        return Err(worker::Error::RustError(
            "staged R2 recovery hash changed".to_owned(),
        ));
    }

    let validated = manifests::validate(&encoded)
        .map_err(|error| worker::Error::RustError(format!("validate staged recovery: {error}")))?;
    if validated.manifest_sha256 != requested.manifest_sha256 {
        return Err(worker::Error::RustError(
            "staged content manifest identity changed".to_owned(),
        ));
    }

    let bytes = u64::try_from(encoded.len())
        .map_err(|error| worker::Error::RustError(error.to_string()))?;

    Ok((validated, bytes))
}

async fn create_intent(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    database
        .prepare(
            "INSERT INTO publication_intents (\
                 operation_id, client_id, namespace_id, object_id, generation, \
                 manifest_sha256, recovery_sha256, r2_storage_key, r2_version, \
                 sidecar_driver_id, sidecar_storage_key, expected_object_revision, \
                 incarnation, lease_id, fencing_token, state, created_at, updated_at\
             ) \
             SELECT operation.id, ?1, operation.namespace_id, ?2, ?3, ?4, ?5, ?6, ?7, \
                    ?8, ?9, ?10, state.incarnation, lease.id, lease.fencing_token, \
                    'staging', ?11, ?11 \
             FROM operations AS operation \
             JOIN control_plane_state AS state ON state.singleton = 1 \
             JOIN leases AS lease ON lease.id = ?12 AND lease.operation_id = operation.id \
             WHERE operation.id = ?13 AND operation.kind = 'import' \
               AND operation.state = 'running' AND operation.incarnation = state.incarnation \
               AND operation.namespace_id = ?14 AND state.mode = 'active' \
               AND state.incarnation = ?15 AND lease.owner_client_id = ?1 \
               AND lease.incarnation = state.incarnation AND lease.fencing_token = ?16 \
               AND lease.released_at IS NULL AND lease.expires_at > unixepoch() \
               AND EXISTS(SELECT 1 FROM client_namespace_permissions \
                          WHERE client_id = ?1 AND namespace_id = operation.namespace_id \
                            AND role IN ('importer', 'administrator')) \
               AND (NOT EXISTS(SELECT 1 FROM objects WHERE id = ?2) \
                    OR EXISTS(SELECT 1 FROM objects \
                              WHERE id = ?2 AND namespace_id = ?14 AND logical_name = ?2)) \
               AND NOT EXISTS(\
                   SELECT 1 FROM object_versions AS version \
                   JOIN objects AS object ON object.id = version.object_id \
                   WHERE object.id = ?2 AND version.generation = ?3 \
                     AND version.manifest_sha256 != ?4\
               ) \
             ON CONFLICT(operation_id) DO UPDATE SET \
                 client_id = excluded.client_id, incarnation = excluded.incarnation, \
                 lease_id = excluded.lease_id, fencing_token = excluded.fencing_token, \
                 updated_at = excluded.updated_at \
             WHERE publication_intents.state = 'staging' \
               AND publication_intents.namespace_id = excluded.namespace_id \
               AND publication_intents.object_id = excluded.object_id \
               AND publication_intents.generation = excluded.generation \
               AND publication_intents.manifest_sha256 = excluded.manifest_sha256 \
               AND publication_intents.recovery_sha256 = excluded.recovery_sha256 \
               AND publication_intents.r2_storage_key = excluded.r2_storage_key \
               AND publication_intents.r2_version = excluded.r2_version \
               AND publication_intents.sidecar_driver_id = excluded.sidecar_driver_id \
               AND publication_intents.sidecar_storage_key = excluded.sidecar_storage_key \
               AND publication_intents.expected_object_revision = excluded.expected_object_revision",
        )
        .bind(&[
            JsValue::from_str(&client.id),
            JsValue::from_str(&validated.object_id),
            integer(validated.generation)?,
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&requested.recovery_sha256),
            JsValue::from_str(&requested.r2_key),
            JsValue::from_str(&requested.r2_version),
            JsValue::from_str(&requested.sidecar_driver_id),
            JsValue::from_str(&requested.sidecar_storage_key),
            integer(requested.expected_object_revision)?,
            JsValue::from_str(&now),
            JsValue::from_str(&requested.lease_id),
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&validated.namespace_id),
            JsValue::from_str(&requested.incarnation),
            integer(requested.fencing_token)?,
        ])?
        .run()
        .await?;

    Ok(())
}

async fn load_intent(database: &D1Database, operation_id: &str) -> Result<Option<IntentRow>> {
    database
        .prepare(
            "SELECT operation_id, client_id, manifest_sha256, recovery_sha256, \
                    r2_storage_key, r2_version, sidecar_driver_id, sidecar_storage_key, \
                    expected_object_revision, incarnation, lease_id, fencing_token, state \
             FROM publication_intents WHERE operation_id = ?1",
        )
        .bind(&[JsValue::from_str(operation_id)])?
        .first::<IntentRow>(None)
        .await
}

fn intent_matches(
    intent: &IntentRow,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
) -> bool {
    intent.operation_id == requested.operation_id
        && intent.client_id == client.id
        && intent.manifest_sha256 == requested.manifest_sha256
        && intent.recovery_sha256 == requested.recovery_sha256
        && intent.r2_storage_key == requested.r2_key
        && intent.r2_version == requested.r2_version
        && intent.sidecar_driver_id == requested.sidecar_driver_id
        && intent.sidecar_storage_key == requested.sidecar_storage_key
        && intent.expected_object_revision == requested.expected_object_revision
        && intent.incarnation == requested.incarnation
        && intent.lease_id == requested.lease_id
        && intent.fencing_token == requested.fencing_token
}

async fn stage_metadata(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    let content = &validated.recovery.manifest;
    let extent_count = content
        .packs
        .iter()
        .map(|pack| pack.extents.len())
        .sum::<usize>();
    let mut statements = Vec::new();

    statements.push(object_statement(
        database, client, requested, validated, &now,
    )?);
    statements.push(version_statement(
        database,
        client,
        requested,
        validated,
        extent_count,
        &now,
    )?);

    for pack in &content.packs {
        statements.push(pack_statement(
            database, client, requested, validated, pack, &now,
        )?);
        statements.push(version_pack_statement(database, client, requested, pack)?);

        for extent in &pack.extents {
            statements.push(extent_statement(
                database, client, requested, extent, pack, &now,
            )?);
        }
    }

    for location in &validated.recovery.locations {
        statements.extend(location_statements(
            database, client, requested, location, &now,
        )?);
    }

    for chunk in statements.chunks(METADATA_BATCH_STATEMENTS) {
        database.batch(chunk.to_vec()).await?;
    }

    Ok(())
}

fn intent_guard() -> &'static str {
    "EXISTS(SELECT 1 FROM publication_intents \
            WHERE operation_id = ?1 AND client_id = ?2 AND state = 'staging')"
}

fn object_statement(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
    now: &str,
) -> Result<D1PreparedStatement> {
    database
        .prepare(format!(
            "INSERT OR IGNORE INTO objects (\
                 id, namespace_id, logical_name, created_at, updated_at\
             ) SELECT ?3, ?4, ?3, ?5, ?5 WHERE {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&validated.object_id),
            JsValue::from_str(&validated.namespace_id),
            JsValue::from_str(now),
        ])
}

fn version_statement(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
    extent_count: usize,
    now: &str,
) -> Result<D1PreparedStatement> {
    let content = &validated.recovery.manifest;

    database
        .prepare(format!(
            "INSERT OR IGNORE INTO object_versions (\
                 id, object_id, generation, manifest_sha256, plaintext_sha256, \
                 plaintext_bytes, chunk_count, pack_count, state, created_at\
             ) SELECT ?3, ?4, ?5, ?3, ?6, ?7, ?8, ?9, 'staging', ?10 WHERE {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.manifest_sha256),
            JsValue::from_str(&validated.object_id),
            integer(validated.generation)?,
            JsValue::from_str(&content.plaintext_sha256),
            integer(content.plaintext_size)?,
            integer_usize(extent_count)?,
            integer_usize(content.packs.len())?,
            JsValue::from_str(now),
        ])
}

fn pack_statement(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
    pack: &manifests::Pack,
    now: &str,
) -> Result<D1PreparedStatement> {
    let content = &validated.recovery.manifest;

    database
        .prepare(format!(
            "INSERT OR IGNORE INTO packs (\
                 id, namespace_id, crypto_suite, root_key_version, key_epoch, \
                 ciphertext_sha256, plaintext_bytes, ciphertext_bytes, frame_bytes, created_at\
             ) SELECT ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12 WHERE {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&pack.id),
            JsValue::from_str(&validated.namespace_id),
            JsValue::from_str(&content.crypto.suite),
            JsValue::from_str(&content.crypto.root_version.to_string()),
            integer(content.crypto.key_epoch)?,
            JsValue::from_str(&pack.ciphertext_sha256),
            integer(pack.plaintext_size)?,
            integer(pack.ciphertext_size)?,
            integer(content.layout.crypto_frame)?,
            JsValue::from_str(now),
        ])
}

fn version_pack_statement(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    pack: &manifests::Pack,
) -> Result<D1PreparedStatement> {
    database
        .prepare(format!(
            "INSERT OR IGNORE INTO version_packs (\
                 version_id, ordinal, pack_id, plaintext_offset\
             ) SELECT ?3, ?4, ?5, ?6 WHERE {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&requested.manifest_sha256),
            integer(pack.ordinal)?,
            JsValue::from_str(&pack.id),
            integer(pack.plaintext_offset)?,
        ])
}

fn extent_statement(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    extent: &manifests::Extent,
    pack: &manifests::Pack,
    now: &str,
) -> Result<D1PreparedStatement> {
    database
        .prepare(format!(
            "INSERT OR IGNORE INTO extents (\
                 id, pack_id, ordinal, first_frame, frame_count, ciphertext_offset, \
                 ciphertext_bytes, ciphertext_sha256, created_at\
             ) SELECT ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?3, ?10 WHERE {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&extent.ciphertext_sha256),
            JsValue::from_str(&pack.id),
            integer(extent.ordinal)?,
            integer(extent.first_frame)?,
            integer(extent.frame_count)?,
            integer(extent.ciphertext_offset)?,
            integer(extent.ciphertext_size)?,
            JsValue::from_str(now),
        ])
}

fn location_statements(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    location: &manifests::Location,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let location_id = manifests::location_id(location);
    let insert = database
        .prepare(format!(
            "INSERT OR IGNORE INTO locations (\
                 id, extent_id, driver_id, storage_key, provider_version, \
                 storage_offset, storage_length, ciphertext_sha256, ciphertext_bytes, \
                 state, created_at, updated_at\
             ) SELECT ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?4, ?9, 'staging', ?10, ?10 WHERE {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(&location_id),
            JsValue::from_str(&location.extent_sha256),
            JsValue::from_str(&location.driver_id),
            JsValue::from_str(&location.storage_key),
            location
                .provider_version
                .as_deref()
                .map_or_else(JsValue::null, JsValue::from_str),
            integer(location.offset)?,
            integer(location.length)?,
            JsValue::from_str(now),
        ])?;
    let verify = database
        .prepare(format!(
            "UPDATE locations SET state = 'verified', verified_at = ?3, \
                    revision = revision + 1, updated_at = ?3 \
             WHERE id = ?4 AND state = 'staging' AND {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(now),
            JsValue::from_str(&location_id),
        ])?;
    let publish = database
        .prepare(format!(
            "UPDATE locations SET state = 'available', revision = revision + 1, updated_at = ?3 \
             WHERE id = ?4 AND state = 'verified' AND {}",
            intent_guard()
        ))
        .bind(&[
            JsValue::from_str(&requested.operation_id),
            JsValue::from_str(&client.id),
            JsValue::from_str(now),
            JsValue::from_str(&location_id),
        ])?;

    Ok(vec![insert, verify, publish])
}

async fn finalize(
    database: &D1Database,
    client: &AuthenticatedClient,
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
    recovery_bytes: u64,
) -> Result<()> {
    let now = current_unix_seconds().to_string();
    let guard = "EXISTS(SELECT 1 FROM publication_intents AS intent \
                        JOIN leases AS lease ON lease.id = intent.lease_id \
                        JOIN control_plane_state AS state ON state.singleton = 1 \
                        WHERE intent.operation_id = ?1 AND intent.client_id = ?2 \
                          AND intent.state = 'staging' AND state.mode = 'active' \
                          AND intent.incarnation = state.incarnation \
                          AND lease.owner_client_id = ?2 \
                          AND lease.fencing_token = intent.fencing_token \
                          AND lease.incarnation = state.incarnation \
                          AND lease.released_at IS NULL AND lease.expires_at > unixepoch())";
    let mut statements = Vec::new();

    statements.push(
        database
            .prepare(format!(
                "UPDATE operations SET state = 'verifying', phase = 'verifying', \
                        revision = revision + 1, updated_at = ?3 \
                 WHERE id = ?1 AND state = 'running' AND {guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "UPDATE operations SET state = 'committing', phase = 'committing', \
                        revision = revision + 1, updated_at = ?3 \
                 WHERE id = ?1 AND state = 'verifying' AND {guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "INSERT OR IGNORE INTO recovery_manifests (\
                     manifest_sha256, version_id, schema_version, recovery_sha256, \
                     r2_storage_key, r2_version, sidecar_driver_id, sidecar_storage_key, \
                     state, ciphertext_bytes, verified_at, created_at, updated_at\
                 ) SELECT ?4, ?4, 'carrack.recovery.v1', ?5, ?6, ?7, ?8, ?9, \
                          'durable', ?10, ?3, ?3, ?3 WHERE {guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
                JsValue::from_str(&requested.manifest_sha256),
                JsValue::from_str(&requested.recovery_sha256),
                JsValue::from_str(&requested.r2_key),
                JsValue::from_str(&requested.r2_version),
                JsValue::from_str(&requested.sidecar_driver_id),
                JsValue::from_str(&requested.sidecar_storage_key),
                integer(recovery_bytes)?,
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "UPDATE object_versions SET state = 'published', published_at = ?3 \
                 WHERE id = ?4 AND state = 'staging' AND {guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                JsValue::from_str(&now),
                JsValue::from_str(&requested.manifest_sha256),
            ])?,
    );
    statements.push(
        database
            .prepare(format!(
                "UPDATE objects SET current_generation = ?3, revision = revision + 1, updated_at = ?4 \
                 WHERE id = ?5 AND revision = ?6 AND {guard}"
            ))
            .bind(&[
                JsValue::from_str(&requested.operation_id),
                JsValue::from_str(&client.id),
                integer(validated.generation)?,
                JsValue::from_str(&now),
                JsValue::from_str(&validated.object_id),
                integer(requested.expected_object_revision)?,
            ])?,
    );
    statements.extend(completion_statements(database, requested, &now)?);

    database.batch(statements).await?;

    Ok(())
}

fn completion_statements(
    database: &D1Database,
    requested: &PublishRequest,
    now: &str,
) -> Result<Vec<D1PreparedStatement>> {
    let commit = database
        .prepare(
            "UPDATE publication_intents \
             SET state = 'committed', committed_at = ?1, updated_at = ?1 \
             WHERE operation_id = ?2 AND state = 'staging'",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(&requested.operation_id),
        ])?;
    let succeed = database
        .prepare(
            "UPDATE operations SET state = 'succeeded', phase = 'succeeded', \
                    revision = revision + 1, finished_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND state = 'committing'",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(&requested.operation_id),
        ])?;
    let release = database
        .prepare(
            "UPDATE leases SET released_at = ?1, updated_at = ?1 \
             WHERE id = ?2 AND fencing_token = ?3 AND incarnation = ?4 \
               AND released_at IS NULL",
        )
        .bind(&[
            JsValue::from_str(now),
            JsValue::from_str(&requested.lease_id),
            integer(requested.fencing_token)?,
            JsValue::from_str(&requested.incarnation),
        ])?;

    Ok(vec![commit, succeed, release])
}

fn published_response(
    requested: &PublishRequest,
    validated: &manifests::ValidatedRecovery,
) -> Result<Response> {
    Response::from_json(&PublishResponse {
        operation_id: requested.operation_id.clone(),
        object_id: validated.object_id.clone(),
        generation: validated.generation,
        manifest_sha256: requested.manifest_sha256.clone(),
        state: "published",
    })
}

fn valid_request(request: &PublishRequest) -> bool {
    valid_string(&request.operation_id, 128)
        && valid_string(&request.lease_id, 256)
        && valid_hex(&request.incarnation, 32)
        && request.fencing_token > 0
        && valid_hex(&request.manifest_sha256, 64)
        && valid_hex(&request.recovery_sha256, 64)
        && valid_string(&request.r2_key, 4_096)
        && valid_string(&request.r2_version, 1_024)
        && valid_string(&request.sidecar_driver_id, 256)
        && valid_string(&request.sidecar_storage_key, 4_096)
        && request.expected_object_revision > 0
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }

    encoded
}

fn integer(value: u64) -> Result<JsValue> {
    if value > i64::MAX.unsigned_abs() {
        return Err(worker::Error::RustError(
            "integer exceeds D1 signed range".to_owned(),
        ));
    }

    Ok(JsValue::from_str(&value.to_string()))
}

fn integer_usize(value: usize) -> Result<JsValue> {
    let converted =
        u64::try_from(value).map_err(|error| worker::Error::RustError(error.to_string()))?;

    integer(converted)
}

fn current_unix_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

#[cfg(test)]
mod tests {
    use super::valid_hex;
    use crate::manifests::Location;

    #[test]
    fn location_identity_is_deterministic_and_position_sensitive() {
        let location = Location {
            extent_sha256: "11".repeat(32),
            driver_id: "driver".to_owned(),
            storage_key: "object".to_owned(),
            provider_version: None,
            offset: 0,
            length: 64,
        };
        let first = crate::manifests::location_id(&location);
        let mut moved = location;
        moved.offset = 1;

        assert!(valid_hex(&first, 64));
        assert_ne!(first, crate::manifests::location_id(&moved));
    }
}
