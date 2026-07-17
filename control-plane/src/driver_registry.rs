//! Stable control-plane registry for provider-specific grant projection.
//!
//! Authorization, envelope opening, D1 fences, and plaintext zeroization stay
//! with their owning subsystems. This module only converts already-authorized
//! provider authority into the least-privilege object grant declared by the
//! shared driver contract.

use carrack_driver_contract::{DriverKind, GrantMode};
use worker::Result;

use crate::{aws_s3_signing, driver_renewal, r2_signing};

pub(crate) fn compiled_kind(value: &str) -> Result<DriverKind> {
    DriverKind::parse(value)
        .ok_or_else(|| worker::Error::RustError(format!("driver kind is not compiled: {value}")))
}

pub(crate) fn project_access_grant(
    kind: DriverKind,
    method: &str,
    config_json: &str,
    storage_key: &str,
    plaintext: &[u8],
    expires_at: u64,
) -> Result<serde_json::Value> {
    match kind.grant_mode() {
        GrantMode::SignedObject => match kind {
            DriverKind::R2V1 => r2_signing::access_grant_from_plaintext(
                method,
                config_json,
                storage_key,
                plaintext,
                expires_at,
            ),
            DriverKind::AwsS3V1 => aws_s3_signing::access_grant_from_plaintext(
                method,
                config_json,
                storage_key,
                plaintext,
                expires_at,
            ),
            DriverKind::AliyunDriveOpenV2 | DriverKind::LocalFilesystemV2 => None,
        }
        .ok_or_else(|| worker::Error::RustError("sign object-scoped driver grant".to_owned())),
        GrantMode::StoredAccess => driver_renewal::access_grant_from_plaintext(kind, plaintext)
            .map_err(|error| {
                worker::Error::RustError(format!("decode stored driver authority: {error}"))
            }),
        GrantMode::None => Err(worker::Error::RustError(
            "credential-free driver unexpectedly stored authority".to_owned(),
        )),
    }
}

pub(crate) async fn live_authority_valid(
    kind: DriverKind,
    config_json: &str,
    plaintext: &[u8],
) -> bool {
    match kind {
        DriverKind::AwsS3V1 => aws_s3_signing::authority_healthy(config_json, plaintext).await,
        DriverKind::AliyunDriveOpenV2 | DriverKind::R2V1 | DriverKind::LocalFilesystemV2 => true,
    }
}

pub(crate) struct MultipartGrantRequest<'a> {
    pub(crate) config_json: &'a str,
    pub(crate) storage_key: &'a str,
    pub(crate) plaintext: &'a [u8],
    pub(crate) upload_id: &'a str,
    pub(crate) first_part: u32,
    pub(crate) part_count: u32,
    pub(crate) maximum_expires_at: u64,
}

pub(crate) fn project_multipart_grant(
    kind: DriverKind,
    request: &MultipartGrantRequest<'_>,
) -> Result<serde_json::Value> {
    if !kind.capabilities().resumable_upload.available()
        || !kind.capabilities().parallel_upload_parts.available()
        || !kind.capabilities().abort.available()
    {
        return Err(worker::Error::RustError(
            "driver does not support resumable multipart grants".to_owned(),
        ));
    }
    match kind {
        DriverKind::R2V1 => r2_signing::multipart_grant_from_plaintext(
            request.config_json,
            request.storage_key,
            request.plaintext,
            request.upload_id,
            request.first_part,
            request.part_count,
            request.maximum_expires_at,
        )
        .ok_or_else(|| worker::Error::RustError("invalid multipart grant request".to_owned())),
        DriverKind::AwsS3V1 => aws_s3_signing::multipart_grant_from_plaintext(
            request.config_json,
            request.storage_key,
            request.plaintext,
            request.upload_id,
            request.first_part,
            request.part_count,
            request.maximum_expires_at,
        )
        .ok_or_else(|| worker::Error::RustError("invalid multipart grant request".to_owned())),
        DriverKind::AliyunDriveOpenV2 | DriverKind::LocalFilesystemV2 => Err(
            worker::Error::RustError("driver has no hosted multipart grant adapter".to_owned()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use carrack_driver_contract::DriverKind;

    use super::{
        MultipartGrantRequest, compiled_kind, project_access_grant, project_multipart_grant,
    };

    #[test]
    fn registry_rejects_unknown_and_credential_free_grants() {
        assert!(compiled_kind("plugin/from-server").is_err());
        assert!(
            project_access_grant(
                DriverKind::LocalFilesystemV2,
                "GET",
                r#"{"root":"/tmp"}"#,
                "object",
                b"{}",
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn stored_access_projection_omits_refresh_authority() {
        let projected = project_access_grant(
            DriverKind::AliyunDriveOpenV2,
            "GET",
            "{}",
            "object",
            br#"{"access_token":"short","refresh_token":"long","refresh_issuer":"openlist-online/v1"}"#,
            1,
        )
        .expect("project Aliyun access authority");
        assert_eq!(projected, serde_json::json!({"access_token": "short"}));
    }

    #[test]
    fn hosted_multipart_projection_fails_closed_for_unregistered_adapters() {
        for kind in [DriverKind::AliyunDriveOpenV2, DriverKind::LocalFilesystemV2] {
            assert!(
                project_multipart_grant(
                    kind,
                    &MultipartGrantRequest {
                        config_json: "{}",
                        storage_key: "object",
                        plaintext: b"{}",
                        upload_id: "upload",
                        first_part: 1,
                        part_count: 1,
                        maximum_expires_at: 1,
                    },
                )
                .is_err()
            );
        }
    }
}
