//! Pure compiled-driver configuration validation.
//!
//! Management transactions, D1 state, credentials, and provider I/O do not
//! belong here. Every management path uses this module so registration,
//! credential replacement, and enablement cannot interpret config differently.

use carrack_driver_contract::{AliyunDriveConfig, DriverKind, LocalFilesystemConfig};
use serde_json::Value;
use worker::Result;

use crate::{aws_s3_signing, r2_signing};

const MAXIMUM_ALIYUN_UPLOAD_PART_BYTES: u64 = 512 << 20;

pub(crate) fn normalize(kind: DriverKind, config: Value) -> Result<Value> {
    match kind {
        DriverKind::LocalFilesystemV2 => {
            let config: LocalFilesystemConfig =
                serde_json::from_value(config).map_err(|error| json_error(&error))?;
            if !valid_local_root(&config.root) {
                return Err(worker::Error::RustError(
                    "local filesystem root is invalid".to_owned(),
                ));
            }
            serde_json::to_value(config).map_err(|error| json_error(&error))
        }
        DriverKind::AliyunDriveOpenV2 => {
            let config: AliyunDriveConfig =
                serde_json::from_value(config).map_err(|error| json_error(&error))?;
            if !valid_aliyun(&config) {
                return Err(worker::Error::RustError(
                    "Aliyun Drive configuration is invalid".to_owned(),
                ));
            }
            serde_json::to_value(config).map_err(|error| json_error(&error))
        }
        DriverKind::R2V1 => {
            let config: r2_signing::Config =
                serde_json::from_value(config).map_err(|error| json_error(&error))?;
            if !r2_signing::valid_config(&config) {
                return Err(worker::Error::RustError(
                    "R2 configuration is invalid".to_owned(),
                ));
            }
            serde_json::to_value(config).map_err(|error| json_error(&error))
        }
        DriverKind::AwsS3V1 => {
            let config: aws_s3_signing::Config =
                serde_json::from_value(config).map_err(|error| json_error(&error))?;
            if !aws_s3_signing::valid_config(&config) {
                return Err(worker::Error::RustError(
                    "AWS S3 configuration is invalid".to_owned(),
                ));
            }
            serde_json::to_value(config).map_err(|error| json_error(&error))
        }
    }
}

pub(crate) fn operator_registration_allowed(kind: DriverKind, config: &Value) -> Result<bool> {
    if kind != DriverKind::R2V1 {
        return Ok(true);
    }
    let config = serde_json::from_value::<r2_signing::Config>(config.clone())
        .map_err(|error| json_error(&error))?;
    Ok(!config.managed)
}

pub(crate) fn valid_stored(kind: &str, config_json: &str, credential_present: bool) -> bool {
    let Some(kind) = DriverKind::parse(kind) else {
        return false;
    };
    let posture_matches = match kind.credential_posture() {
        carrack_driver_contract::CredentialPosture::Required => credential_present,
        carrack_driver_contract::CredentialPosture::Forbidden => !credential_present,
    };
    posture_matches
        && serde_json::from_str::<Value>(config_json)
            .ok()
            .and_then(|config| normalize(kind, config).ok())
            .is_some()
}

fn valid_aliyun(config: &AliyunDriveConfig) -> bool {
    config.api_base_url.starts_with("https://")
        && !config.api_base_url.contains('@')
        && !config.api_base_url.contains('#')
        && !config.api_base_url.contains('?')
        && !config.api_base_url.ends_with('/')
        && matches!(
            config.drive_type.as_str(),
            "default" | "resource" | "backup"
        )
        && valid_bounded_string(&config.root_folder_id, 256)
        && config.upload_part_bytes > 0
        && config.upload_part_bytes <= MAXIMUM_ALIYUN_UPLOAD_PART_BYTES
}

fn valid_local_root(root: &str) -> bool {
    root.starts_with('/')
        && root.len() <= 4_096
        && !root.contains('\0')
        && !root.chars().any(char::is_control)
        && (root == "/" || !root.ends_with('/'))
        && !root
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

fn valid_bounded_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn json_error(error: &serde_json::Error) -> worker::Error {
    worker::Error::RustError(error.to_string())
}

#[cfg(test)]
mod tests {
    use carrack_driver_contract::DriverKind;
    use serde_json::json;

    use super::{normalize, valid_stored};

    #[test]
    fn normalizes_defaults_and_rejects_unknown_fields() {
        let aliyun =
            normalize(DriverKind::AliyunDriveOpenV2, json!({})).expect("normalize Aliyun defaults");
        assert_eq!(aliyun["drive_type"], "resource");
        assert_eq!(aliyun["root_folder_id"], "root");
        assert_eq!(aliyun["upload_part_bytes"], 20 << 20);
        assert!(
            normalize(
                DriverKind::AliyunDriveOpenV2,
                json!({"access_token": "secret"}),
            )
            .is_err()
        );
    }

    #[test]
    fn stored_configuration_enforces_credential_posture() {
        let aliyun = r#"{"api_base_url":"https://openapi.alipan.com","drive_type":"resource","root_folder_id":"root","upload_part_bytes":20971520}"#;
        assert!(valid_stored(
            DriverKind::AliyunDriveOpenV2.as_str(),
            aliyun,
            true
        ));
        assert!(!valid_stored(
            DriverKind::AliyunDriveOpenV2.as_str(),
            aliyun,
            false
        ));
        let local = r#"{"root":"/srv/carrack"}"#;
        assert!(valid_stored(
            DriverKind::LocalFilesystemV2.as_str(),
            local,
            false
        ));
        assert!(!valid_stored(
            DriverKind::LocalFilesystemV2.as_str(),
            local,
            true
        ));
    }
}
