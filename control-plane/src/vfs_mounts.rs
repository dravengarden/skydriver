//! Linux-like VFS mount policy queries shared by namespace and policy transactions.
//!
//! D1 triggers remain the final transaction authority. These helpers provide
//! the same semantics for early diagnostics without duplicating them across
//! request handlers.

use serde::Deserialize;
use worker::{D1Database, Result, wasm_bindgen::JsValue};

/// Desired relationship between one directory and its effective driver.
pub(crate) enum DesiredMount {
    RootDefault,
    Explicit,
    Inherited,
}

impl DesiredMount {
    pub(crate) const fn stored_kind(&self) -> Option<&'static str> {
        match self {
            Self::RootDefault => Some("default"),
            Self::Explicit => Some("mount"),
            Self::Inherited => None,
        }
    }
}

/// Resolves whether selecting `driver_id` means default, mount, or inheritance.
pub(crate) async fn desired(
    database: &D1Database,
    directory_id: &str,
    driver_id: &str,
) -> Result<Option<DesiredMount>> {
    #[derive(Deserialize)]
    struct MountContext {
        parent_id: Option<String>,
        parent_driver_id: Option<String>,
        nested: u64,
    }
    let context = database
        .prepare(
            "WITH RECURSIVE ancestors(id, parent_id) AS (
                 SELECT parent.id, parent.parent_id
                 FROM vfs_directories AS target
                 JOIN vfs_directories AS parent ON parent.id = target.parent_id
                 WHERE target.id = ?1
                 UNION ALL
                 SELECT parent.id, parent.parent_id
                 FROM ancestors AS child
                 JOIN vfs_directories AS parent ON parent.id = child.parent_id
             )
             SELECT target.parent_id,
                    parent_placement.driver_id AS parent_driver_id,
                    EXISTS (
                        SELECT 1
                        FROM ancestors
                        JOIN vfs_directory_mounts AS mount
                          ON mount.directory_id = ancestors.id
                        WHERE mount.kind = 'mount'
                    ) AS nested
             FROM vfs_directories AS target
             LEFT JOIN vfs_directory_drivers AS parent_placement
               ON parent_placement.directory_id = target.parent_id
             WHERE target.id = ?1 AND target.state = 'active'",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<MountContext>(None)
        .await?;
    let Some(context) = context else {
        return Ok(None);
    };
    if context.parent_id.is_none() {
        return Ok(Some(DesiredMount::RootDefault));
    }
    let Some(parent_driver_id) = context.parent_driver_id else {
        return Ok(None);
    };
    if parent_driver_id == driver_id {
        return Ok(Some(DesiredMount::Inherited));
    }
    if context.nested == 1 {
        return Ok(None);
    }
    Ok(Some(DesiredMount::Explicit))
}

/// Returns true when selecting the driver cannot strand an existing subtree.
pub(crate) async fn change_is_safe(
    database: &D1Database,
    directory_id: &str,
    requested_driver_id: &str,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct SafetyRow {
        safe: u64,
    }
    let row = database
        .prepare(
            "WITH RECURSIVE descendants(id) AS (
                 SELECT id FROM vfs_directories WHERE id = ?1
                 UNION ALL
                 SELECT child.id
                 FROM descendants AS parent
                 JOIN vfs_directories AS child ON child.parent_id = parent.id
                 WHERE child.state = 'active'
             )
             SELECT (
                 EXISTS (
                     SELECT 1 FROM vfs_directory_drivers
                     WHERE directory_id = ?1 AND driver_id = ?2
                 )
                 OR NOT EXISTS (
                     SELECT 1 FROM vfs_directory_entries
                     WHERE directory_id IN (SELECT id FROM descendants)
                 )
             ) AS safe",
        )
        .bind(&[
            JsValue::from_str(directory_id),
            JsValue::from_str(requested_driver_id),
        ])?
        .first::<SafetyRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.safe == 1))
}

/// Returns true only for an explicit non-root mount point.
pub(crate) async fn is_explicit(database: &D1Database, directory_id: &str) -> Result<bool> {
    #[derive(Deserialize)]
    struct MountRow {
        mounted: u64,
    }
    let row = database
        .prepare(
            "SELECT EXISTS (
                 SELECT 1 FROM vfs_directory_mounts
                 WHERE directory_id = ?1 AND kind = 'mount'
             ) AS mounted",
        )
        .bind(&[JsValue::from_str(directory_id)])?
        .first::<MountRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.mounted == 1))
}

/// Compares the materialized effective drivers for two directories.
pub(crate) async fn same_effective_driver(
    database: &D1Database,
    left_directory_id: &str,
    right_directory_id: &str,
) -> Result<bool> {
    #[derive(Deserialize)]
    struct SameDriverRow {
        same_driver: u64,
    }
    let row = database
        .prepare(
            "SELECT EXISTS (
                 SELECT 1
                 FROM vfs_directory_drivers AS left_driver
                 JOIN vfs_directory_drivers AS right_driver
                   ON right_driver.driver_id = left_driver.driver_id
                 WHERE left_driver.directory_id = ?1
                   AND right_driver.directory_id = ?2
                   AND left_driver.state = 'active'
                   AND right_driver.state = 'active'
             ) AS same_driver",
        )
        .bind(&[
            JsValue::from_str(left_directory_id),
            JsValue::from_str(right_directory_id),
        ])?
        .first::<SameDriverRow>(None)
        .await?;
    Ok(row.is_some_and(|row| row.same_driver == 1))
}
