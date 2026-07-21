//! Environment-owned storage identities derived from Worker bindings.

use serde::Deserialize;
use skydriver_driver_contract::DriverKind;
use worker::{D1Database, Env, Result, wasm_bindgen::JsValue};

use crate::r2_signing;

pub(crate) const DEFAULT_R2_DRIVER_ID: &str = "r2-default";
const DEFAULT_R2_MAX_PHYSICAL_BYTES_BINDING: &str = "SKYDRIVER_DEFAULT_R2_MAX_PHYSICAL_BYTES";
const MAXIMUM_D1_INTEGER: u64 = 9_007_199_254_740_991;
const R2_KIND: &str = DriverKind::R2V1.as_str();
const LOCAL_FILESYSTEM_KIND: &str = DriverKind::LocalFilesystemV2.as_str();

#[derive(Deserialize)]
struct DriverRow {
    kind: String,
    config_json: String,
    lifecycle_owner: String,
    retired_at: Option<u64>,
}

#[derive(Deserialize)]
struct LegacyDriverRow {
    id: String,
    revision: u64,
}

/// Materializes immutable environment identities and retires empty bootstrap
/// adapters. The operation is idempotent and safe under overlapping cron and
/// management requests.
pub(crate) async fn ensure(env: &Env, database: &D1Database, now: u64) -> Result<()> {
    let Some(config) = configured_r2(env)? else {
        return Ok(());
    };
    let config_json = serde_json::to_string(&config).map_err(|error| json_error(&error))?;
    if let Some(existing) = load_driver(database, DEFAULT_R2_DRIVER_ID).await? {
        validate_existing(&existing, &config_json)?;
    } else {
        let initial_max_physical_bytes = configured_initial_max_physical_bytes(env)?;
        let inserted = database
            .batch(vec![
                database
                    .prepare(
                        r"INSERT INTO driver_instances (
                             id, kind, config_json, credential_ref, enabled, revision,
                             created_at, updated_at, lifecycle_owner
                         ) VALUES (?1, ?2, ?3, NULL, 0, 1, ?4, ?4, 'environment')",
                    )
                    .bind(&[
                        JsValue::from_str(DEFAULT_R2_DRIVER_ID),
                        JsValue::from_str(R2_KIND),
                        JsValue::from_str(&config_json),
                        integer(now),
                    ])?,
                database
                    .prepare(
                        r"UPDATE driver_quota_policies
                         SET max_physical_bytes = ?1, revision = revision + 1,
                             updated_at = MAX(updated_at, ?2)
                         WHERE driver_id = ?3 AND revision = 1
                           AND max_physical_bytes IS NULL AND max_object_count IS NULL",
                    )
                    .bind(&[
                        integer(initial_max_physical_bytes),
                        integer(now),
                        JsValue::from_str(DEFAULT_R2_DRIVER_ID),
                    ])?,
                database
                    .prepare(
                        r"INSERT INTO vfs_audit_events (
                             filesystem_id, principal_id, token_id, event_kind,
                             subject_kind, subject_id, details_json, created_at
                         ) VALUES (
                             NULL, NULL, NULL, 'environment.driver.materialized',
                             'driver', ?1,
                             json_object(
                                 'kind', ?2, 'enabled', 0, 'source', 'environment',
                                 'initial_max_physical_bytes', CAST(?3 AS INTEGER)
                             ), ?4
                         )",
                    )
                    .bind(&[
                        JsValue::from_str(DEFAULT_R2_DRIVER_ID),
                        JsValue::from_str(R2_KIND),
                        integer(initial_max_physical_bytes),
                        integer(now),
                    ])?,
            ])
            .await;
        if let Err(error) = inserted {
            let Some(existing) = load_driver(database, DEFAULT_R2_DRIVER_ID).await? else {
                return Err(worker::Error::RustError(format!(
                    "materialize environment R2 driver: {error}"
                )));
            };
            validate_existing(&existing, &config_json)?;
        }
    }

    retire_empty_legacy_bootstrap(database, now).await
}

pub(crate) fn is_managed_r2_config(env: &Env, config: &r2_signing::Config) -> Result<bool> {
    Ok(configured_r2(env)?.as_ref() == Some(config))
}

pub(crate) fn configured_r2(env: &Env) -> Result<Option<r2_signing::Config>> {
    let environment = env.var("SKYDRIVER_ENVIRONMENT")?.to_string();
    if !matches!(environment.as_str(), "dev" | "prod") {
        return Ok(None);
    }
    let endpoint = env.var("SKYDRIVER_R2_ENDPOINT")?.to_string();
    desired_r2_config_from_values(&environment, &endpoint).map(Some)
}

fn configured_initial_max_physical_bytes(env: &Env) -> Result<u64> {
    let value = env.var(DEFAULT_R2_MAX_PHYSICAL_BYTES_BINDING)?.to_string();
    parse_initial_max_physical_bytes(&value)
}

fn parse_initial_max_physical_bytes(value: &str) -> Result<u64> {
    let parsed = value.parse::<u64>().map_err(|_| {
        worker::Error::RustError(
            "invalid environment-managed R2 initial physical-byte quota".to_owned(),
        )
    })?;
    if parsed == 0 || parsed > MAXIMUM_D1_INTEGER {
        return Err(worker::Error::RustError(
            "invalid environment-managed R2 initial physical-byte quota".to_owned(),
        ));
    }
    Ok(parsed)
}

fn desired_r2_config_from_values(environment: &str, endpoint: &str) -> Result<r2_signing::Config> {
    let config = r2_signing::Config {
        endpoint: endpoint.to_owned(),
        bucket: format!("carrack-payload-{environment}"),
        prefix: String::new(),
        managed: true,
    };
    if !matches!(environment, "dev" | "prod") || !r2_signing::valid_config(&config) {
        return Err(worker::Error::RustError(
            "invalid environment-managed R2 configuration".to_owned(),
        ));
    }
    Ok(config)
}

async fn load_driver(database: &D1Database, driver_id: &str) -> Result<Option<DriverRow>> {
    database
        .prepare(
            r"SELECT kind, config_json, lifecycle_owner, retired_at
             FROM driver_instances WHERE id = ?1",
        )
        .bind(&[JsValue::from_str(driver_id)])?
        .first::<DriverRow>(None)
        .await
}

fn validate_existing(existing: &DriverRow, expected_config_json: &str) -> Result<()> {
    if existing.kind == R2_KIND
        && existing.config_json == expected_config_json
        && existing.lifecycle_owner == "environment"
        && existing.retired_at.is_none()
    {
        return Ok(());
    }
    Err(worker::Error::RustError(
        "r2-default conflicts with the environment binding".to_owned(),
    ))
}

async fn retire_empty_legacy_bootstrap(database: &D1Database, now: u64) -> Result<()> {
    let candidate = database
        .prepare(
            r"SELECT driver.id, driver.revision
             FROM driver_instances AS driver
             WHERE driver.lifecycle_owner = 'legacy-bootstrap'
               AND driver.kind = ?1 AND driver.enabled = 0 AND driver.retired_at IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_directory_drivers WHERE driver_id = driver.id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_locations WHERE driver_id = driver.id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM vfs_put_intents WHERE driver_id = driver.id
               )
             ORDER BY driver.id LIMIT 1",
        )
        .bind(&[JsValue::from_str(LOCAL_FILESYSTEM_KIND)])?
        .first::<LegacyDriverRow>(None)
        .await?;
    let Some(candidate) = candidate else {
        return Ok(());
    };
    let result = database
        .batch(vec![
            database
                .prepare(
                    r"UPDATE driver_instances
                     SET retired_at = ?1, revision = revision + 1, updated_at = ?1
                     WHERE id = ?2 AND revision = ?3 AND enabled = 0
                       AND retired_at IS NULL",
                )
                .bind(&[
                    integer(now),
                    JsValue::from_str(&candidate.id),
                    integer(candidate.revision),
                ])?,
            database
                .prepare(
                    r"INSERT INTO vfs_audit_events (
                         filesystem_id, principal_id, token_id, event_kind,
                         subject_kind, subject_id, details_json, created_at
                     ) SELECT NULL, NULL, NULL, 'driver.retired', 'driver', ?1,
                              json_object('kind', ?2, 'source', 'environment'), ?3
                       FROM driver_instances
                       WHERE id = ?1 AND retired_at = ?3",
                )
                .bind(&[
                    JsValue::from_str(&candidate.id),
                    JsValue::from_str(LOCAL_FILESYSTEM_KIND),
                    integer(now),
                ])?,
        ])
        .await;
    if let Err(error) = result {
        let current = load_driver(database, &candidate.id).await?;
        if current.is_some_and(|driver| driver.retired_at.is_some()) {
            return Ok(());
        }
        return Err(worker::Error::RustError(format!(
            "retire legacy bootstrap driver: {error}"
        )));
    }
    Ok(())
}

fn integer(value: u64) -> JsValue {
    JsValue::from_str(&value.min(i64::MAX as u64).to_string())
}

fn json_error(error: &serde_json::Error) -> worker::Error {
    worker::Error::RustError(format!("encode environment R2 configuration: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_isolated_environment_buckets() {
        let endpoint = "https://0123456789abcdef.r2.cloudflarestorage.com";
        let dev = desired_r2_config_from_values("dev", endpoint).expect("dev config");
        let prod = desired_r2_config_from_values("prod", endpoint).expect("prod config");
        assert_eq!(dev.bucket, "carrack-payload-dev");
        assert_eq!(prod.bucket, "carrack-payload-prod");
        assert_ne!(dev.bucket, prod.bucket);
        assert!(dev.managed && prod.managed);
    }

    #[test]
    fn rejects_unknown_environments_and_unsafe_endpoints() {
        assert!(
            desired_r2_config_from_values(
                "preview",
                "https://0123456789abcdef.r2.cloudflarestorage.com"
            )
            .is_err()
        );
        assert!(desired_r2_config_from_values("dev", "http://example.com").is_err());
    }

    #[test]
    fn validates_environment_initial_physical_byte_quota() {
        assert_eq!(
            parse_initial_max_physical_bytes("107374182400").expect("100 GiB quota"),
            100 * 1024 * 1024 * 1024
        );
        assert!(parse_initial_max_physical_bytes("0").is_err());
        assert!(parse_initial_max_physical_bytes(&(MAXIMUM_D1_INTEGER + 1).to_string()).is_err());
        assert!(parse_initial_max_physical_bytes("100 GiB").is_err());
    }
}
