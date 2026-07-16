//! Server-owned, root-fenced VFS catalog checkpoint materialization.

use std::{collections::HashMap, fmt::Write as _};

use carrack_sdk_core::{
    CATALOG_CHECKPOINT_SCHEMA, CatalogCheckpoint, CatalogCheckpointDirectory,
    CatalogCheckpointEntry, CatalogCheckpointEntryKind, MAXIMUM_CATALOG_CHECKPOINT_BYTES,
    MAXIMUM_CATALOG_DELTA_BYTES, MAXIMUM_CATALOG_DIRECTORIES, MAXIMUM_CATALOG_ENTRIES,
    build_catalog_delta, validate_catalog_checkpoint,
};
#[cfg(test)]
use carrack_sdk_core::{DirectoryMerkleEntry, directory_merkle_root};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Bucket, Conditional, D1Database, Date, Env, Result, wasm_bindgen::JsValue};

use crate::vfs_identifiers;

const MAXIMUM_COLLAPSES_PER_RUN: u64 = 500;
const CLAIM_SECONDS: u64 = 300;
const ORPHAN_GRACE_SECONDS: u64 = 86_400;
const MAXIMUM_DELTA_SOURCE_BYTES: u64 = MAXIMUM_CATALOG_DELTA_BYTES as u64;
const MAXIMUM_ARTIFACT_RETIREMENTS_PER_RUN: u64 = 100;

#[derive(Deserialize)]
struct RevisionIdRow {
    revision_id: u64,
}

#[derive(Deserialize)]
struct ClaimedOutboxState {
    attempts: u64,
    current_head: u64,
}

#[derive(Deserialize)]
struct Candidate {
    revision_id: u64,
    filesystem_id: String,
    parent_revision_id: Option<u64>,
    root_directory_id: String,
    root_data_root: String,
    created_at: u64,
    lease_owner: String,
    attempts: u64,
}

#[derive(Clone, Deserialize, Serialize)]
struct DirectoryRow {
    id: String,
    parent_id: Option<String>,
    name: String,
    data_root: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct EntryRow {
    directory_id: String,
    name: String,
    kind: String,
    file_id: Option<String>,
    version_id: Option<String>,
    child_directory_id: Option<String>,
    size_bytes: u64,
    data_root: String,
    metadata_root: Option<String>,
}

#[derive(Deserialize)]
struct ArtifactRow {
    r2_key: String,
    sha256: String,
    bytes: u64,
    r2_version: Option<String>,
    state: String,
}

#[derive(Deserialize)]
struct CleanupRow {
    revision_id: u64,
    r2_key: String,
    state: String,
}

#[derive(Deserialize)]
struct PublicationRow {
    revision_id: u64,
}

#[derive(Deserialize)]
struct PublishedCheckpointRow {
    revision_id: u64,
    root_directory_id: String,
    root_data_root: String,
    r2_key: String,
    sha256: String,
    bytes: u64,
    r2_version: String,
}

#[derive(Deserialize)]
struct DeltaArtifactRow {
    base_revision_id: u64,
    base_root_data_root: String,
    base_checkpoint_sha256: String,
    checkpoint_sha256: String,
    r2_key: String,
    sha256: String,
    bytes: u64,
    r2_version: Option<String>,
    state: String,
}

struct PreparedDelta {
    base_revision_id: u64,
    base_root_data_root: String,
    base_checkpoint_sha256: String,
    checkpoint_sha256: String,
    r2_key: String,
    sha256: String,
    bytes: u64,
    r2_version: String,
}

struct StoredObject {
    version: String,
    bytes: u64,
}

/// Materializes at most one latest filesystem checkpoint and reclaims at most
/// one tracked abandoned R2 object. Historical pending revisions are collapsed
/// only after a newer complete checkpoint has been verified and published.
pub(crate) async fn run(env: &Env, now: u64) -> Result<()> {
    let database = env.d1("CARRACK_INDEX")?;
    let bucket = env.bucket("CARRACK_MANIFESTS")?;
    cleanup_one_delta(&database, &bucket, now).await?;
    cleanup_one(&database, &bucket, now).await?;
    if let Some(candidate) = claim_latest(&database, now).await?
        && let Err(error) = materialize(&database, &bucket, &candidate, now).await
    {
        let release_now = now_seconds();
        release_claim(
            &database,
            candidate.revision_id,
            &candidate.lease_owner,
            "checkpoint_materialization_failed",
            release_now,
            candidate.attempts,
            true,
        )
        .await?;
        return Err(error);
    }
    collapse_historical(&database, now_seconds()).await?;
    retire_historical_artifacts(&database, now_seconds()).await?;
    Ok(())
}

async fn claim_latest(database: &D1Database, now: u64) -> Result<Option<Candidate>> {
    // Both outbox predicates are deliberate: one proves the partial-index
    // predicate while the equality set lets SQLite seek by live state.
    let candidate = database
        .prepare(
            "SELECT outbox.revision_id
             FROM vfs_catalog_outbox AS outbox
                  INDEXED BY idx_vfs_catalog_outbox_claimable
             JOIN vfs_catalog_revisions AS revision ON revision.id = outbox.revision_id
             JOIN vfs_catalog_mutation_heads AS head
               ON head.filesystem_id = revision.filesystem_id
              AND head.revision_id = revision.id
             WHERE revision.state = 'pending'
               AND outbox.state != 'done'
               AND outbox.state IN ('pending', 'claimed')
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_catalog_revision_collapses AS collapse
                   WHERE collapse.revision_id = revision.id
               )
               AND ((outbox.state = 'pending'
                     AND (outbox.retry_at IS NULL OR outbox.retry_at <= ?1))
                    OR (outbox.state = 'claimed' AND outbox.lease_expires_at <= ?1))
             ORDER BY COALESCE(outbox.retry_at, outbox.updated_at), outbox.revision_id
             LIMIT 1",
        )
        .bind(&[number(now)])?
        .first::<RevisionIdRow>(None)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let lease_owner = vfs_identifiers::new_uuid_v7_hex()?;
    let claimed = database
        .prepare(
            "UPDATE vfs_catalog_outbox
             SET state = 'claimed', attempts = attempts + 1, lease_owner = ?1,
                 lease_expires_at = ?2, retry_at = NULL,
                 last_error_code = NULL, updated_at = ?3
             WHERE revision_id = ?4
               AND ((state = 'pending' AND (retry_at IS NULL OR retry_at <= ?3))
                    OR (state = 'claimed' AND lease_expires_at <= ?3))
               AND EXISTS (
                   SELECT 1
                   FROM vfs_catalog_revisions AS revision
                   JOIN vfs_catalog_mutation_heads AS head
                     ON head.filesystem_id = revision.filesystem_id
                    AND head.revision_id = revision.id
                   WHERE revision.id = vfs_catalog_outbox.revision_id
                     AND revision.state = 'pending'
               )",
        )
        .bind(&[
            JsValue::from_str(&lease_owner),
            number(now + CLAIM_SECONDS),
            number(now),
            number(candidate.revision_id),
        ])?
        .run()
        .await?;
    if changes(claimed.meta()?) != 1 {
        return Ok(None);
    }
    let loaded = load_candidate(database, candidate.revision_id, &lease_owner, now).await?;
    if loaded.is_some() {
        return Ok(loaded);
    }
    release_unloadable_claim(database, candidate.revision_id, &lease_owner).await?;
    Ok(None)
}

async fn release_unloadable_claim(
    database: &D1Database,
    revision_id: u64,
    lease_owner: &str,
) -> Result<()> {
    let claim = database
        .prepare(
            "SELECT outbox.attempts,
                    EXISTS (
                        SELECT 1
                        FROM vfs_catalog_revisions AS revision
                        JOIN vfs_catalog_mutation_heads AS head
                          ON head.filesystem_id = revision.filesystem_id
                         AND head.revision_id = revision.id
                        WHERE revision.id = outbox.revision_id
                    ) AS current_head
             FROM vfs_catalog_outbox AS outbox
             WHERE outbox.revision_id = ?1 AND outbox.state = 'claimed'
               AND outbox.lease_owner = ?2",
        )
        .bind(&[number(revision_id), JsValue::from_str(lease_owner)])?
        .first::<ClaimedOutboxState>(None)
        .await?;
    if let Some(claim) = claim {
        release_claim(
            database,
            revision_id,
            lease_owner,
            if claim.current_head == 0 {
                "superseded_before_checkpoint"
            } else {
                "checkpoint_materialization_failed"
            },
            now_seconds(),
            claim.attempts,
            claim.current_head != 0,
        )
        .await?;
    }
    Ok(())
}

async fn load_candidate(
    database: &D1Database,
    revision_id: u64,
    lease_owner: &str,
    now: u64,
) -> Result<Option<Candidate>> {
    database
        .prepare(
            "SELECT revision.id AS revision_id, revision.filesystem_id,
                    revision.parent_revision_id, root.id AS root_directory_id,
                    revision.root_data_root, revision.created_at, outbox.lease_owner,
                    outbox.attempts
             FROM vfs_catalog_revisions AS revision
             JOIN vfs_catalog_mutation_heads AS head
               ON head.filesystem_id = revision.filesystem_id
              AND head.revision_id = revision.id
             JOIN vfs_filesystems AS filesystem ON filesystem.id = revision.filesystem_id
             JOIN vfs_directories AS root
               ON root.filesystem_id = filesystem.id AND root.parent_id IS NULL
             JOIN vfs_catalog_outbox AS outbox ON outbox.revision_id = revision.id
             WHERE revision.id = ?1 AND revision.state = 'pending'
               AND root.state = 'active' AND root.data_root = revision.root_data_root
               AND outbox.state = 'claimed' AND outbox.lease_owner = ?2
               AND outbox.lease_expires_at > ?3",
        )
        .bind(&[
            number(revision_id),
            JsValue::from_str(lease_owner),
            number(now),
        ])?
        .first::<Candidate>(None)
        .await
}

#[allow(
    clippy::too_many_lines,
    reason = "checkpoint publication and its optional delta share one root fence while keeping the checkpoint independently sufficient"
)]
async fn materialize(
    database: &D1Database,
    bucket: &Bucket,
    candidate: &Candidate,
    now: u64,
) -> Result<()> {
    let previous = load_published_checkpoint(database, candidate).await?;
    let checkpoint = load_checkpoint(database, candidate).await?;
    let encoded = serde_json::to_vec(&checkpoint)?;
    if encoded.is_empty() || encoded.len() > MAXIMUM_CATALOG_CHECKPOINT_BYTES {
        return Err(protocol_error("catalog checkpoint exceeds its byte bound"));
    }
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    let sha256 = lowercase_hex(&digest);
    let r2_key = format!(
        "vfs/catalog/checkpoints/{}/{}/{}.json",
        candidate.filesystem_id,
        &sha256[..2],
        sha256
    );
    let bytes = u64::try_from(encoded.len())
        .map_err(|_| protocol_error("catalog checkpoint size exceeds u64"))?;
    record_writing(
        database,
        candidate.revision_id,
        &r2_key,
        &sha256,
        bytes,
        now,
    )
    .await?;
    let stored = store_immutable(bucket, &r2_key, &encoded, &digest).await?;
    if stored.bytes != bytes {
        return Err(protocol_error("stored catalog checkpoint size differs"));
    }
    mark_staged(
        database,
        candidate.revision_id,
        &r2_key,
        &sha256,
        bytes,
        &stored.version,
        now,
    )
    .await?;
    let delta = if let Some(previous) = previous {
        match prepare_delta(
            database,
            bucket,
            candidate,
            &previous,
            &checkpoint,
            &sha256,
            bytes,
            now,
        )
        .await
        {
            Ok(delta) => delta,
            Err(error) => {
                worker::console_warn!(
                    "optional VFS catalog delta {} failed: {error:?}",
                    candidate.revision_id
                );
                if let Err(cleanup_error) =
                    discard_optional_delta(database, bucket, candidate.revision_id, now_seconds())
                        .await
                {
                    worker::console_warn!(
                        "optional VFS catalog delta {} cleanup deferred: {cleanup_error:?}",
                        candidate.revision_id
                    );
                }
                None
            }
        }
    } else {
        None
    };

    let fence_now = now_seconds();
    if load_candidate(
        database,
        candidate.revision_id,
        &candidate.lease_owner,
        fence_now,
    )
    .await?
    .is_none()
    {
        mark_orphaned(database, candidate.revision_id, fence_now).await?;
        release_claim(
            database,
            candidate.revision_id,
            &candidate.lease_owner,
            "superseded_during_checkpoint",
            fence_now,
            candidate.attempts,
            false,
        )
        .await?;
        return Ok(());
    }

    if !publish(
        database,
        candidate,
        &r2_key,
        &sha256,
        bytes,
        &stored.version,
        delta.as_ref(),
        fence_now,
    )
    .await?
    {
        mark_orphaned(database, candidate.revision_id, fence_now).await?;
        release_claim(
            database,
            candidate.revision_id,
            &candidate.lease_owner,
            "superseded_during_checkpoint",
            fence_now,
            candidate.attempts,
            false,
        )
        .await?;
    }
    Ok(())
}

async fn load_checkpoint(
    database: &D1Database,
    candidate: &Candidate,
) -> Result<CatalogCheckpoint> {
    let directories = database
        .prepare(
            "SELECT id, parent_id, name, data_root
             FROM vfs_directories
             WHERE filesystem_id = ?1 AND state = 'active'
             ORDER BY id
             LIMIT ?2",
        )
        .bind(&[
            JsValue::from_str(&candidate.filesystem_id),
            number((MAXIMUM_CATALOG_DIRECTORIES + 1) as u64),
        ])?
        .all()
        .await?
        .results::<DirectoryRow>()?;
    if directories.is_empty() || directories.len() > MAXIMUM_CATALOG_DIRECTORIES {
        return Err(protocol_error("catalog directory bound exceeded"));
    }
    let entries = database
        .prepare(
            "SELECT entry.directory_id, entry.name, entry.kind, entry.file_id,
                    entry.version_id, entry.child_directory_id, entry.size_bytes,
                    entry.data_root, entry.metadata_root
             FROM vfs_directory_entries AS entry
             JOIN vfs_directories AS directory ON directory.id = entry.directory_id
             WHERE directory.filesystem_id = ?1 AND directory.state = 'active'
             ORDER BY entry.directory_id, entry.name COLLATE BINARY
             LIMIT ?2",
        )
        .bind(&[
            JsValue::from_str(&candidate.filesystem_id),
            number((MAXIMUM_CATALOG_ENTRIES + 1) as u64),
        ])?
        .all()
        .await?
        .results::<EntryRow>()?;
    if entries.len() > MAXIMUM_CATALOG_ENTRIES {
        return Err(protocol_error("catalog entry bound exceeded"));
    }
    assemble_checkpoint(candidate, directories, entries)
}

async fn load_published_checkpoint(
    database: &D1Database,
    candidate: &Candidate,
) -> Result<Option<PublishedCheckpointRow>> {
    database
        .prepare(
            "SELECT revision.id AS revision_id, root.id AS root_directory_id,
                    revision.root_data_root, artifact.r2_key, artifact.sha256,
                    artifact.bytes, artifact.r2_version
             FROM vfs_catalog_heads AS head
             JOIN vfs_catalog_revisions AS revision ON revision.id = head.revision_id
             JOIN vfs_filesystems AS filesystem ON filesystem.id = revision.filesystem_id
             JOIN vfs_directories AS root
               ON root.filesystem_id = filesystem.id AND root.parent_id IS NULL
             JOIN vfs_catalog_checkpoint_artifacts AS artifact
               ON artifact.revision_id = revision.id
              AND artifact.r2_key = revision.checkpoint_r2_key
              AND artifact.sha256 = revision.checkpoint_sha256
              AND artifact.r2_version = revision.checkpoint_r2_version
              AND artifact.bytes = revision.checkpoint_bytes
             WHERE head.filesystem_id = ?1 AND head.revision_id < ?2
               AND head.root_data_root = revision.root_data_root
               AND revision.state = 'published' AND artifact.state = 'published'
               AND root.state = 'active'",
        )
        .bind(&[
            JsValue::from_str(&candidate.filesystem_id),
            number(candidate.revision_id),
        ])?
        .first::<PublishedCheckpointRow>(None)
        .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "optional delta preparation binds both immutable endpoint receipts before any R2 side effect"
)]
async fn prepare_delta(
    database: &D1Database,
    bucket: &Bucket,
    candidate: &Candidate,
    previous: &PublishedCheckpointRow,
    checkpoint: &CatalogCheckpoint,
    checkpoint_sha256: &str,
    checkpoint_bytes: u64,
    now: u64,
) -> Result<Option<PreparedDelta>> {
    if previous.bytes > MAXIMUM_DELTA_SOURCE_BYTES
        || checkpoint_bytes > MAXIMUM_DELTA_SOURCE_BYTES
        || previous.root_directory_id != checkpoint.root_directory_id
    {
        return Ok(None);
    }
    let base = load_verified_checkpoint(bucket, previous).await?;
    let delta = build_catalog_delta(&base, &previous.sha256, checkpoint, checkpoint_sha256)
        .map_err(|error| protocol_error(&error.to_string()))?;
    let encoded = serde_json::to_vec(&delta)?;
    if encoded.is_empty()
        || encoded.len() > MAXIMUM_CATALOG_DELTA_BYTES
        || u64::try_from(encoded.len()).unwrap_or(u64::MAX) >= checkpoint_bytes
    {
        return Ok(None);
    }
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    let sha256 = lowercase_hex(&digest);
    let r2_key = format!(
        "vfs/catalog/deltas/{}/{}/{}.json",
        candidate.filesystem_id,
        &sha256[..2],
        sha256
    );
    let bytes = u64::try_from(encoded.len())
        .map_err(|_| protocol_error("catalog delta size exceeds u64"))?;
    record_delta_writing(
        database,
        candidate.revision_id,
        previous,
        checkpoint_sha256,
        &r2_key,
        &sha256,
        bytes,
        now,
    )
    .await?;
    let stored = store_immutable(bucket, &r2_key, &encoded, &digest).await?;
    if stored.bytes != bytes {
        return Err(protocol_error("stored catalog delta size differs"));
    }
    mark_delta_staged(
        database,
        candidate.revision_id,
        &r2_key,
        &sha256,
        bytes,
        &stored.version,
        now,
    )
    .await?;
    Ok(Some(PreparedDelta {
        base_revision_id: previous.revision_id,
        base_root_data_root: previous.root_data_root.clone(),
        base_checkpoint_sha256: previous.sha256.clone(),
        checkpoint_sha256: checkpoint_sha256.to_owned(),
        r2_key,
        sha256,
        bytes,
        r2_version: stored.version,
    }))
}

async fn load_verified_checkpoint(
    bucket: &Bucket,
    receipt: &PublishedCheckpointRow,
) -> Result<CatalogCheckpoint> {
    let object = bucket
        .get(receipt.r2_key.clone())
        .execute()
        .await?
        .ok_or_else(|| protocol_error("delta base checkpoint is missing from R2"))?;
    if object.key() != receipt.r2_key
        || object.version() != receipt.r2_version
        || object.size() != receipt.bytes
    {
        return Err(protocol_error("delta base checkpoint R2 receipt differs"));
    }
    let body = object
        .body()
        .ok_or_else(|| protocol_error("delta base checkpoint has no R2 body"))?
        .bytes()
        .await?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) != receipt.bytes
        || hex::encode(Sha256::digest(&body)) != receipt.sha256
    {
        return Err(protocol_error("delta base checkpoint body receipt differs"));
    }
    let checkpoint: CatalogCheckpoint = serde_json::from_slice(&body)?;
    if serde_json::to_vec(&checkpoint)? != body {
        return Err(protocol_error("delta base checkpoint is not canonical"));
    }
    validate_catalog_checkpoint(&checkpoint).map_err(|error| protocol_error(&error.to_string()))?;
    if checkpoint.revision_id != receipt.revision_id
        || checkpoint.root_directory_id != receipt.root_directory_id
        || checkpoint.root_data_root != receipt.root_data_root
    {
        return Err(protocol_error("delta base checkpoint identity differs"));
    }
    Ok(checkpoint)
}

fn assemble_checkpoint(
    candidate: &Candidate,
    directories: Vec<DirectoryRow>,
    entries: Vec<EntryRow>,
) -> Result<CatalogCheckpoint> {
    let mut grouped = HashMap::<String, Vec<CatalogCheckpointEntry>>::new();
    for entry in entries {
        let kind = match entry.kind.as_str() {
            "file" => CatalogCheckpointEntryKind::File,
            "directory" => CatalogCheckpointEntryKind::Directory,
            _ => return Err(protocol_error("catalog entry kind is invalid")),
        };
        grouped
            .entry(entry.directory_id)
            .or_default()
            .push(CatalogCheckpointEntry {
                name: entry.name,
                kind,
                file_id: entry.file_id,
                version_id: entry.version_id,
                child_directory_id: entry.child_directory_id,
                size_bytes: entry.size_bytes,
                data_root: entry.data_root,
                metadata_root: entry.metadata_root,
            });
    }
    let mut checkpoint_directories = Vec::with_capacity(directories.len());
    for directory in directories {
        checkpoint_directories.push(CatalogCheckpointDirectory {
            entries: grouped.remove(&directory.id).unwrap_or_default(),
            directory_id: directory.id,
            parent_directory_id: directory.parent_id,
            name: directory.name,
            data_root: directory.data_root,
        });
    }
    if !grouped.is_empty() {
        return Err(protocol_error(
            "catalog entries reference an inactive directory",
        ));
    }
    let checkpoint = CatalogCheckpoint {
        schema: CATALOG_CHECKPOINT_SCHEMA.to_owned(),
        filesystem_id: candidate.filesystem_id.clone(),
        revision_id: candidate.revision_id,
        parent_revision_id: candidate.parent_revision_id,
        root_directory_id: candidate.root_directory_id.clone(),
        root_data_root: candidate.root_data_root.clone(),
        created_at: candidate.created_at,
        directories: checkpoint_directories,
    };
    validate_catalog_checkpoint(&checkpoint).map_err(|error| protocol_error(&error.to_string()))?;
    Ok(checkpoint)
}

async fn record_writing(
    database: &D1Database,
    revision_id: u64,
    r2_key: &str,
    sha256: &str,
    bytes: u64,
    now: u64,
) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_catalog_checkpoint_artifacts (
                 revision_id, r2_key, sha256, bytes, state, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, 'writing', ?5, ?5)
             ON CONFLICT(revision_id) DO NOTHING",
        )
        .bind(&[
            number(revision_id),
            JsValue::from_str(r2_key),
            JsValue::from_str(sha256),
            number(bytes),
            number(now),
        ])?
        .run()
        .await?;
    let artifact = load_artifact(database, revision_id).await?;
    if artifact.is_some_and(|artifact| {
        artifact.r2_key == r2_key
            && artifact.sha256 == sha256
            && artifact.bytes == bytes
            && matches!(artifact.state.as_str(), "writing" | "staged")
    }) {
        return Ok(());
    }
    Err(protocol_error(
        "catalog checkpoint artifact identity differs",
    ))
}

async fn mark_staged(
    database: &D1Database,
    revision_id: u64,
    r2_key: &str,
    sha256: &str,
    bytes: u64,
    r2_version: &str,
    now: u64,
) -> Result<()> {
    database
        .prepare(
            "UPDATE vfs_catalog_checkpoint_artifacts
             SET state = 'staged', r2_version = ?1, updated_at = ?2
             WHERE revision_id = ?3 AND r2_key = ?4 AND sha256 = ?5 AND bytes = ?6
               AND state = 'writing'",
        )
        .bind(&[
            JsValue::from_str(r2_version),
            number(now),
            number(revision_id),
            JsValue::from_str(r2_key),
            JsValue::from_str(sha256),
            number(bytes),
        ])?
        .run()
        .await?;
    let artifact = load_artifact(database, revision_id).await?;
    if artifact.is_some_and(|artifact| {
        artifact.r2_key == r2_key
            && artifact.sha256 == sha256
            && artifact.bytes == bytes
            && artifact.r2_version.as_deref() == Some(r2_version)
            && artifact.state == "staged"
    }) {
        return Ok(());
    }
    Err(protocol_error("catalog checkpoint staging receipt differs"))
}

async fn load_artifact(database: &D1Database, revision_id: u64) -> Result<Option<ArtifactRow>> {
    database
        .prepare(
            "SELECT r2_key, sha256, bytes, r2_version, state
             FROM vfs_catalog_checkpoint_artifacts WHERE revision_id = ?1",
        )
        .bind(&[number(revision_id)])?
        .first::<ArtifactRow>(None)
        .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the delta writing receipt persists every immutable chain and object identity before R2 I/O"
)]
async fn record_delta_writing(
    database: &D1Database,
    target_revision_id: u64,
    base: &PublishedCheckpointRow,
    checkpoint_sha256: &str,
    r2_key: &str,
    sha256: &str,
    bytes: u64,
    now: u64,
) -> Result<()> {
    database
        .prepare(
            "INSERT INTO vfs_catalog_delta_artifacts (
                 target_revision_id, base_revision_id, base_root_data_root,
                 base_checkpoint_sha256, checkpoint_sha256, r2_key, sha256,
                 bytes, state, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'writing', ?9, ?9)
             ON CONFLICT(target_revision_id) DO NOTHING",
        )
        .bind(&[
            number(target_revision_id),
            number(base.revision_id),
            JsValue::from_str(&base.root_data_root),
            JsValue::from_str(&base.sha256),
            JsValue::from_str(checkpoint_sha256),
            JsValue::from_str(r2_key),
            JsValue::from_str(sha256),
            number(bytes),
            number(now),
        ])?
        .run()
        .await?;
    let artifact = load_delta_artifact(database, target_revision_id).await?;
    if artifact.is_some_and(|artifact| {
        artifact.base_revision_id == base.revision_id
            && artifact.base_root_data_root == base.root_data_root
            && artifact.base_checkpoint_sha256 == base.sha256
            && artifact.checkpoint_sha256 == checkpoint_sha256
            && artifact.r2_key == r2_key
            && artifact.sha256 == sha256
            && artifact.bytes == bytes
            && matches!(artifact.state.as_str(), "writing" | "staged")
    }) {
        return Ok(());
    }
    Err(protocol_error("catalog delta artifact identity differs"))
}

async fn mark_delta_staged(
    database: &D1Database,
    target_revision_id: u64,
    r2_key: &str,
    sha256: &str,
    bytes: u64,
    r2_version: &str,
    now: u64,
) -> Result<()> {
    database
        .prepare(
            "UPDATE vfs_catalog_delta_artifacts
             SET state = 'staged', r2_version = ?1, updated_at = ?2
             WHERE target_revision_id = ?3 AND r2_key = ?4
               AND sha256 = ?5 AND bytes = ?6 AND state = 'writing'",
        )
        .bind(&[
            JsValue::from_str(r2_version),
            number(now),
            number(target_revision_id),
            JsValue::from_str(r2_key),
            JsValue::from_str(sha256),
            number(bytes),
        ])?
        .run()
        .await?;
    let artifact = load_delta_artifact(database, target_revision_id).await?;
    if artifact.is_some_and(|artifact| {
        artifact.r2_key == r2_key
            && artifact.sha256 == sha256
            && artifact.bytes == bytes
            && artifact.r2_version.as_deref() == Some(r2_version)
            && artifact.state == "staged"
    }) {
        return Ok(());
    }
    Err(protocol_error("catalog delta staging receipt differs"))
}

async fn load_delta_artifact(
    database: &D1Database,
    target_revision_id: u64,
) -> Result<Option<DeltaArtifactRow>> {
    database
        .prepare(
            "SELECT base_revision_id, base_root_data_root,
                    base_checkpoint_sha256, checkpoint_sha256, r2_key,
                    sha256, bytes, r2_version, state
             FROM vfs_catalog_delta_artifacts WHERE target_revision_id = ?1",
        )
        .bind(&[number(target_revision_id)])?
        .first::<DeltaArtifactRow>(None)
        .await
}

async fn discard_optional_delta(
    database: &D1Database,
    bucket: &Bucket,
    target_revision_id: u64,
    now: u64,
) -> Result<()> {
    let Some(artifact) = load_delta_artifact(database, target_revision_id).await? else {
        return Ok(());
    };
    match artifact.state.as_str() {
        "writing" => {
            bucket.delete(&artifact.r2_key).await?;
            database
                .prepare(
                    "DELETE FROM vfs_catalog_delta_artifacts
                     WHERE target_revision_id = ?1 AND r2_key = ?2
                       AND sha256 = ?3 AND state = 'writing'",
                )
                .bind(&[
                    number(target_revision_id),
                    JsValue::from_str(&artifact.r2_key),
                    JsValue::from_str(&artifact.sha256),
                ])?
                .run()
                .await?;
        }
        "staged" => {
            database
                .prepare(
                    "UPDATE vfs_catalog_delta_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE target_revision_id = ?2 AND r2_key = ?3
                       AND sha256 = ?4 AND state = 'staged'",
                )
                .bind(&[
                    number(now),
                    number(target_revision_id),
                    JsValue::from_str(&artifact.r2_key),
                    JsValue::from_str(&artifact.sha256),
                ])?
                .run()
                .await?;
        }
        _ => {}
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one atomic publication batch carries every immutable R2 identity and collapse fence explicitly"
)]
async fn publish(
    database: &D1Database,
    candidate: &Candidate,
    r2_key: &str,
    sha256: &str,
    bytes: u64,
    r2_version: &str,
    delta: Option<&PreparedDelta>,
    now: u64,
) -> Result<bool> {
    let mut statements = vec![
        database
            .prepare(
                "UPDATE vfs_catalog_revisions
                     SET state = 'materialized', checkpoint_r2_key = ?1,
                         checkpoint_sha256 = ?2, checkpoint_r2_version = ?3,
                         checkpoint_bytes = ?4, materialized_at = ?5
                     WHERE id = ?6 AND filesystem_id = ?7 AND root_data_root = ?8
                       AND state = 'pending'
                       AND EXISTS (
                           SELECT 1 FROM vfs_catalog_mutation_heads
                           WHERE filesystem_id = ?7 AND revision_id = ?6
                       )
                       AND EXISTS (
                           SELECT 1 FROM vfs_catalog_outbox
                           WHERE revision_id = ?6 AND state = 'claimed'
                             AND lease_owner = ?9 AND lease_expires_at > ?5
                       )
                       AND EXISTS (
                           SELECT 1 FROM vfs_catalog_checkpoint_artifacts
                           WHERE revision_id = ?6 AND r2_key = ?1 AND sha256 = ?2
                             AND r2_version = ?3 AND bytes = ?4 AND state = 'staged'
                       )",
            )
            .bind(&[
                JsValue::from_str(r2_key),
                JsValue::from_str(sha256),
                JsValue::from_str(r2_version),
                number(bytes),
                number(now),
                number(candidate.revision_id),
                JsValue::from_str(&candidate.filesystem_id),
                JsValue::from_str(&candidate.root_data_root),
                JsValue::from_str(&candidate.lease_owner),
            ])?,
        database
            .prepare(
                "UPDATE vfs_catalog_revisions
                     SET state = 'published', published_at = ?1
                     WHERE id = ?2 AND state = 'materialized'
                       AND checkpoint_r2_key = ?3 AND checkpoint_sha256 = ?4
                       AND checkpoint_r2_version = ?5 AND checkpoint_bytes = ?6",
            )
            .bind(&[
                number(now),
                number(candidate.revision_id),
                JsValue::from_str(r2_key),
                JsValue::from_str(sha256),
                JsValue::from_str(r2_version),
                number(bytes),
            ])?,
        database
            .prepare(
                "UPDATE vfs_catalog_checkpoint_artifacts
                     SET state = 'published', updated_at = ?1
                     WHERE revision_id = ?2 AND state = 'staged'
                       AND EXISTS (
                           SELECT 1 FROM vfs_catalog_revisions
                           WHERE id = ?2 AND state = 'published'
                       )",
            )
            .bind(&[number(now), number(candidate.revision_id)])?,
    ];
    if let Some(delta) = delta {
        statements.push(
            database
                .prepare(
                    "UPDATE vfs_catalog_delta_artifacts
                     SET state = 'published', updated_at = ?1
                     WHERE target_revision_id = ?2 AND base_revision_id = ?3
                       AND base_root_data_root = ?4
                       AND base_checkpoint_sha256 = ?5
                       AND checkpoint_sha256 = ?6 AND r2_key = ?7
                       AND sha256 = ?8 AND bytes = ?9 AND r2_version = ?10
                       AND state = 'staged'",
                )
                .bind(&[
                    number(now),
                    number(candidate.revision_id),
                    number(delta.base_revision_id),
                    JsValue::from_str(&delta.base_root_data_root),
                    JsValue::from_str(&delta.base_checkpoint_sha256),
                    JsValue::from_str(&delta.checkpoint_sha256),
                    JsValue::from_str(&delta.r2_key),
                    JsValue::from_str(&delta.sha256),
                    number(delta.bytes),
                    JsValue::from_str(&delta.r2_version),
                ])?,
        );
    }
    statements.extend([
        database
            .prepare(
                "INSERT INTO vfs_catalog_heads (
                         filesystem_id, revision_id, root_data_root, updated_at
                     )
                     SELECT revision.filesystem_id, revision.id,
                            revision.root_data_root, ?1
                     FROM vfs_catalog_revisions AS revision
                     JOIN vfs_catalog_mutation_heads AS mutation
                       ON mutation.filesystem_id = revision.filesystem_id
                      AND mutation.revision_id = revision.id
                     WHERE revision.id = ?2 AND revision.state = 'published'
                     ON CONFLICT(filesystem_id) DO UPDATE SET
                         revision_id = excluded.revision_id,
                         root_data_root = excluded.root_data_root,
                         revision = vfs_catalog_heads.revision + 1,
                         updated_at = excluded.updated_at",
            )
            .bind(&[number(now), number(candidate.revision_id)])?,
        database
            .prepare(
                "UPDATE vfs_catalog_outbox
                     SET state = 'done', lease_owner = NULL, lease_expires_at = NULL,
                         retry_at = NULL, last_error_code = NULL, updated_at = ?1
                     WHERE revision_id = ?2 AND state = 'claimed' AND lease_owner = ?3
                       AND EXISTS (
                           SELECT 1 FROM vfs_catalog_revisions
                           WHERE id = ?2 AND state = 'published'
                       )",
            )
            .bind(&[
                number(now),
                number(candidate.revision_id),
                JsValue::from_str(&candidate.lease_owner),
            ])?,
    ]);
    database.batch(statements).await?;
    let publication = database
        .prepare(
            "SELECT head.revision_id
             FROM vfs_catalog_heads AS head
             JOIN vfs_catalog_revisions AS revision ON revision.id = head.revision_id
             JOIN vfs_catalog_outbox AS outbox ON outbox.revision_id = revision.id
             JOIN vfs_catalog_checkpoint_artifacts AS artifact
               ON artifact.revision_id = revision.id
             WHERE head.filesystem_id = ?1 AND head.revision_id = ?2
               AND revision.state = 'published' AND outbox.state = 'done'
               AND artifact.state = 'published'",
        )
        .bind(&[
            JsValue::from_str(&candidate.filesystem_id),
            number(candidate.revision_id),
        ])?
        .first::<PublicationRow>(None)
        .await?;
    Ok(publication.is_some_and(|row| row.revision_id == candidate.revision_id))
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded D1 batch collapses revisions and retires every staged artifact type under the same published checkpoint proof"
)]
async fn collapse_historical(database: &D1Database, now: u64) -> Result<()> {
    let checkpoint = database
        .prepare(
            "SELECT head.revision_id
             FROM vfs_catalog_heads AS head
             WHERE EXISTS (
                 SELECT 1
                 FROM vfs_catalog_revisions AS older
                 WHERE older.filesystem_id = head.filesystem_id
                   AND older.id < head.revision_id AND older.state = 'pending'
                   AND NOT EXISTS (
                       SELECT 1 FROM vfs_catalog_revision_collapses AS collapse
                       WHERE collapse.revision_id = older.id
                   )
             )
             ORDER BY head.updated_at, head.revision_id
             LIMIT 1",
        )
        .first::<RevisionIdRow>(None)
        .await?;
    let Some(checkpoint) = checkpoint else {
        return Ok(());
    };
    database
        .batch(vec![
            database
                .prepare(
                    "INSERT OR IGNORE INTO vfs_catalog_revision_collapses (
                         revision_id, superseded_by_revision_id, collapsed_at
                     )
                     SELECT older.id, published.id, ?1
                     FROM vfs_catalog_revisions AS published
                     JOIN vfs_catalog_revisions AS older
                       ON older.filesystem_id = published.filesystem_id
                      AND older.id < published.id AND older.state = 'pending'
                     WHERE published.id = ?2 AND published.state = 'published'
                       AND NOT EXISTS (
                           SELECT 1 FROM vfs_catalog_revision_collapses AS collapse
                           WHERE collapse.revision_id = older.id
                       )
                     ORDER BY older.id
                     LIMIT ?3",
                )
                .bind(&[
                    number(now),
                    number(checkpoint.revision_id),
                    number(MAXIMUM_COLLAPSES_PER_RUN),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_catalog_delta_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE state = 'staged' AND target_revision_id IN (
                         SELECT collapse.revision_id
                         FROM vfs_catalog_revision_collapses AS collapse
                         JOIN vfs_catalog_outbox AS outbox
                           ON outbox.revision_id = collapse.revision_id
                         WHERE collapse.superseded_by_revision_id = ?2
                           AND outbox.state != 'done'
                         ORDER BY collapse.revision_id LIMIT ?3
                     )",
                )
                .bind(&[
                    number(now),
                    number(checkpoint.revision_id),
                    number(MAXIMUM_COLLAPSES_PER_RUN),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_catalog_checkpoint_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE state = 'staged' AND revision_id IN (
                         SELECT collapse.revision_id
                         FROM vfs_catalog_revision_collapses AS collapse
                         JOIN vfs_catalog_outbox AS outbox
                           ON outbox.revision_id = collapse.revision_id
                         WHERE collapse.superseded_by_revision_id = ?2
                           AND outbox.state != 'done'
                         ORDER BY collapse.revision_id LIMIT ?3
                     )",
                )
                .bind(&[
                    number(now),
                    number(checkpoint.revision_id),
                    number(MAXIMUM_COLLAPSES_PER_RUN),
                ])?,
            database
                .prepare(
                    "UPDATE vfs_catalog_outbox
                     SET state = 'done', lease_owner = NULL, lease_expires_at = NULL,
                         retry_at = NULL, last_error_code = 'collapsed_to_checkpoint',
                         updated_at = ?1
                     WHERE state != 'done' AND revision_id IN (
                         SELECT collapse.revision_id
                         FROM vfs_catalog_revision_collapses AS collapse
                         JOIN vfs_catalog_outbox AS unresolved
                           ON unresolved.revision_id = collapse.revision_id
                         WHERE collapse.superseded_by_revision_id = ?2
                           AND unresolved.state != 'done'
                         ORDER BY collapse.revision_id LIMIT ?3
                     )",
                )
                .bind(&[
                    number(now),
                    number(checkpoint.revision_id),
                    number(MAXIMUM_COLLAPSES_PER_RUN),
                ])?,
        ])
        .await?;
    Ok(())
}

async fn retire_historical_artifacts(database: &D1Database, now: u64) -> Result<()> {
    database
        .batch(vec![
            database
                .prepare(
                    "UPDATE vfs_catalog_checkpoint_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE revision_id IN (
                         SELECT artifact.revision_id
                         FROM vfs_catalog_checkpoint_artifacts AS artifact
                              INDEXED BY idx_vfs_catalog_checkpoint_artifacts_retirement
                         WHERE artifact.state = 'published'
                           AND NOT EXISTS (
                               SELECT 1 FROM vfs_catalog_heads AS head
                               WHERE head.revision_id = artifact.revision_id
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM vfs_catalog_mutation_heads AS head
                               JOIN vfs_catalog_revisions AS revision
                                 ON revision.id = artifact.revision_id
                                AND head.filesystem_id = revision.filesystem_id
                                AND head.revision_id = revision.id
                           )
                         ORDER BY artifact.updated_at, artifact.revision_id
                         LIMIT ?2
                     )",
                )
                .bind(&[number(now), number(MAXIMUM_ARTIFACT_RETIREMENTS_PER_RUN)])?,
            database
                .prepare(
                    "UPDATE vfs_catalog_delta_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE target_revision_id IN (
                         SELECT artifact.target_revision_id
                         FROM vfs_catalog_delta_artifacts AS artifact
                              INDEXED BY idx_vfs_catalog_delta_artifacts_retirement
                         WHERE artifact.state = 'published'
                           AND NOT EXISTS (
                               SELECT 1 FROM vfs_catalog_heads AS head
                               WHERE head.revision_id = artifact.target_revision_id
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM vfs_catalog_mutation_heads AS head
                               JOIN vfs_catalog_revisions AS revision
                                 ON revision.id = artifact.target_revision_id
                                AND head.filesystem_id = revision.filesystem_id
                                AND head.revision_id = revision.id
                           )
                         ORDER BY artifact.updated_at, artifact.target_revision_id
                         LIMIT ?2
                     )",
                )
                .bind(&[number(now), number(MAXIMUM_ARTIFACT_RETIREMENTS_PER_RUN)])?,
        ])
        .await?;
    Ok(())
}

async fn mark_orphaned(database: &D1Database, revision_id: u64, now: u64) -> Result<()> {
    database
        .batch(vec![
            database
                .prepare(
                    "UPDATE vfs_catalog_checkpoint_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE revision_id = ?2 AND state = 'staged'
                       AND NOT EXISTS (
                           SELECT 1 FROM vfs_catalog_heads WHERE revision_id = ?2
                       )
                       AND NOT EXISTS (
                           SELECT 1
                           FROM vfs_catalog_mutation_heads AS head
                           JOIN vfs_catalog_revisions AS revision
                             ON revision.id = ?2
                            AND head.filesystem_id = revision.filesystem_id
                            AND head.revision_id = revision.id
                       )",
                )
                .bind(&[number(now), number(revision_id)])?,
            database
                .prepare(
                    "UPDATE vfs_catalog_delta_artifacts
                     SET state = 'orphaned', updated_at = ?1
                     WHERE target_revision_id = ?2 AND state = 'staged'
                       AND NOT EXISTS (
                           SELECT 1 FROM vfs_catalog_heads WHERE revision_id = ?2
                       )
                       AND NOT EXISTS (
                           SELECT 1
                           FROM vfs_catalog_mutation_heads AS head
                           JOIN vfs_catalog_revisions AS revision
                             ON revision.id = ?2
                            AND head.filesystem_id = revision.filesystem_id
                            AND head.revision_id = revision.id
                       )",
                )
                .bind(&[number(now), number(revision_id)])?,
        ])
        .await?;
    Ok(())
}

async fn release_claim(
    database: &D1Database,
    revision_id: u64,
    lease_owner: &str,
    error_code: &str,
    now: u64,
    attempts: u64,
    retry: bool,
) -> Result<()> {
    let retry_at = if retry {
        number(now + retry_delay(attempts, revision_id))
    } else {
        JsValue::NULL
    };
    database
        .prepare(
            "UPDATE vfs_catalog_outbox
             SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL,
                 retry_at = ?1, last_error_code = ?2, updated_at = ?3
             WHERE revision_id = ?4 AND state = 'claimed' AND lease_owner = ?5",
        )
        .bind(&[
            retry_at,
            JsValue::from_str(error_code),
            number(now),
            number(revision_id),
            JsValue::from_str(lease_owner),
        ])?
        .run()
        .await?;
    Ok(())
}

fn retry_delay(attempt: u64, revision_id: u64) -> u64 {
    let exponent = attempt.saturating_sub(1).min(8) as u32;
    (60_u64.saturating_mul(1_u64 << exponent)).min(6 * 60 * 60) + revision_id % 61
}

async fn cleanup_one_delta(database: &D1Database, bucket: &Bucket, now: u64) -> Result<()> {
    let cutoff = now.saturating_sub(ORPHAN_GRACE_SECONDS);
    let candidate = database
        .prepare(
            "SELECT artifact.target_revision_id AS revision_id,
                    artifact.r2_key, artifact.state
             FROM vfs_catalog_delta_artifacts AS artifact
                  INDEXED BY idx_vfs_catalog_delta_artifacts_cleanup
             WHERE artifact.updated_at <= ?1
               AND artifact.state IN ('writing', 'orphaned')
               AND (
                   artifact.state = 'orphaned'
                   OR (
                       artifact.state = 'writing'
                       AND NOT EXISTS (
                           SELECT 1 FROM vfs_catalog_mutation_heads AS head
                           JOIN vfs_catalog_revisions AS revision
                             ON revision.id = artifact.target_revision_id
                            AND head.filesystem_id = revision.filesystem_id
                            AND head.revision_id = revision.id
                       )
                   )
               )
             ORDER BY artifact.updated_at, artifact.target_revision_id
             LIMIT 1",
        )
        .bind(&[number(cutoff)])?
        .first::<CleanupRow>(None)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(());
    };
    bucket.delete(&candidate.r2_key).await?;
    database
        .prepare(
            "DELETE FROM vfs_catalog_delta_artifacts
             WHERE target_revision_id = ?1 AND r2_key = ?2 AND state = ?3
               AND updated_at <= ?4",
        )
        .bind(&[
            number(candidate.revision_id),
            JsValue::from_str(&candidate.r2_key),
            JsValue::from_str(&candidate.state),
            number(cutoff),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn cleanup_one(database: &D1Database, bucket: &Bucket, now: u64) -> Result<()> {
    let cutoff = now.saturating_sub(ORPHAN_GRACE_SECONDS);
    let candidate = database
        .prepare(
            "SELECT artifact.revision_id, artifact.r2_key, artifact.state
             FROM vfs_catalog_checkpoint_artifacts AS artifact
                  INDEXED BY idx_vfs_catalog_checkpoint_artifacts_cleanup
             WHERE artifact.updated_at <= ?1
               AND artifact.state IN ('writing', 'orphaned')
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_catalog_heads AS head
                   WHERE head.revision_id = artifact.revision_id
               )
               AND (
                   artifact.state = 'orphaned'
                   OR (
                       artifact.state = 'writing'
                       AND NOT EXISTS (
                           SELECT 1 FROM vfs_catalog_mutation_heads AS head
                           JOIN vfs_catalog_revisions AS revision
                             ON revision.id = artifact.revision_id
                            AND head.filesystem_id = revision.filesystem_id
                            AND head.revision_id = revision.id
                       )
                   )
               )
             ORDER BY artifact.updated_at, artifact.revision_id
             LIMIT 1",
        )
        .bind(&[number(cutoff)])?
        .first::<CleanupRow>(None)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(());
    };
    bucket.delete(&candidate.r2_key).await?;
    database
        .prepare(
            "DELETE FROM vfs_catalog_checkpoint_artifacts
             WHERE revision_id = ?1 AND r2_key = ?2 AND state = ?3
               AND updated_at <= ?4
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_catalog_heads WHERE revision_id = ?1
               )",
        )
        .bind(&[
            number(candidate.revision_id),
            JsValue::from_str(&candidate.r2_key),
            JsValue::from_str(&candidate.state),
            number(cutoff),
        ])?
        .run()
        .await?;
    Ok(())
}

async fn store_immutable(
    bucket: &Bucket,
    key: &str,
    encoded: &[u8],
    digest: &[u8; 32],
) -> Result<StoredObject> {
    let expected_bytes = u64::try_from(encoded.len())
        .map_err(|_| protocol_error("catalog checkpoint size exceeds u64"))?;
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
            return Err(protocol_error("R2 catalog checkpoint size differs"));
        }
        return Ok(StoredObject {
            version: object.version().clone(),
            bytes: object.size(),
        });
    }
    let Some(existing) = bucket.get(key).execute().await? else {
        return Err(protocol_error(
            "R2 catalog checkpoint disappeared after conditional write",
        ));
    };
    let existing_bytes = existing.size();
    let existing_version = existing.version().clone();
    let Some(body) = existing.body() else {
        return Err(protocol_error("existing R2 catalog checkpoint has no body"));
    };
    let existing_body = body.bytes().await?;
    if existing_bytes != expected_bytes
        || existing_body != encoded
        || Sha256::digest(&existing_body).as_slice() != digest
    {
        return Err(protocol_error(
            "content-addressed R2 catalog checkpoint collision",
        ));
    }
    Ok(StoredObject {
        version: existing_version,
        bytes: existing_bytes,
    })
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn changes(meta: Option<worker::D1ResultMeta>) -> usize {
    meta.and_then(|value| value.changes).unwrap_or_default()
}

fn number(value: u64) -> JsValue {
    JsValue::from_str(&value.to_string())
}

fn now_seconds() -> u64 {
    Date::now().as_millis() / 1_000
}

fn protocol_error(message: &str) -> worker::Error {
    worker::Error::RustError(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_and_rejects_unreachable_catalogs() {
        let root_id = "202122232425262728292a2b2c2d2e2f";
        let child_id = "303132333435363738393a3b3c3d3e3f";
        let empty_root = "9b510ca4b7de6a996568f09b2eb0a5793f14c207d2a5a0f3735b11a2d109a254";
        let child_root: [u8; 32] = hex::decode(empty_root)
            .expect("empty root hex")
            .try_into()
            .expect("empty root length");
        let root_data_root = lowercase_hex(
            &directory_merkle_root(&[DirectoryMerkleEntry::Directory {
                name: "docs",
                stable_id: hex::decode(child_id)
                    .expect("child identity hex")
                    .try_into()
                    .expect("child identity length"),
                data_root: child_root,
            }])
            .expect("root Merkle root"),
        );
        let candidate = Candidate {
            revision_id: 7,
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            parent_revision_id: Some(6),
            root_directory_id: root_id.to_owned(),
            root_data_root: root_data_root.clone(),
            created_at: 1_700_000_000,
            lease_owner: "404142434445464748494a4b4c4d4e4f".to_owned(),
            attempts: 1,
        };
        let directories = vec![
            DirectoryRow {
                id: root_id.to_owned(),
                parent_id: None,
                name: String::new(),
                data_root: root_data_root,
            },
            DirectoryRow {
                id: child_id.to_owned(),
                parent_id: Some(root_id.to_owned()),
                name: "docs".to_owned(),
                data_root: empty_root.to_owned(),
            },
        ];
        let entries = vec![EntryRow {
            directory_id: root_id.to_owned(),
            name: "docs".to_owned(),
            kind: "directory".to_owned(),
            file_id: None,
            version_id: None,
            child_directory_id: Some(child_id.to_owned()),
            size_bytes: 0,
            data_root: empty_root.to_owned(),
            metadata_root: None,
        }];

        let checkpoint = assemble_checkpoint(&candidate, directories.clone(), entries.clone())
            .expect("valid checkpoint");
        assert_eq!(checkpoint.directories.len(), 2);

        let mut unreachable = directories;
        unreachable.push(DirectoryRow {
            id: "505152535455565758595a5b5c5d5e5f".to_owned(),
            parent_id: Some(root_id.to_owned()),
            name: "orphan".to_owned(),
            data_root: empty_root.to_owned(),
        });
        assert!(assemble_checkpoint(&candidate, unreachable, entries).is_err());
    }

    #[test]
    fn catalog_retry_is_bounded_and_jittered() {
        assert!((60..=120).contains(&retry_delay(1, 60)));
        assert!(retry_delay(2, 2) > retry_delay(1, 1));
        assert!(retry_delay(100, 60) <= 6 * 60 * 60 + 60);
    }
}
