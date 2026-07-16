//! Stable control-plane registry for provider-specific grant projection.
//!
//! Authorization, envelope opening, D1 fences, and plaintext zeroization stay
//! with their owning subsystems. This module only converts already-authorized
//! provider authority into the least-privilege object grant declared by the
//! shared driver contract.

use carrack_driver_contract::{DriverKind, GrantMode};
use worker::Result;

use crate::{driver_credentials, r2_signing};

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
        GrantMode::SignedObject => r2_signing::access_grant_from_plaintext(
            method,
            config_json,
            storage_key,
            plaintext,
            expires_at,
        )
        .ok_or_else(|| worker::Error::RustError("sign object-scoped driver grant".to_owned())),
        GrantMode::StoredAccess => driver_credentials::access_grant_from_plaintext(kind, plaintext)
            .map_err(|error| {
                worker::Error::RustError(format!("decode stored driver authority: {error}"))
            }),
        GrantMode::None => Err(worker::Error::RustError(
            "credential-free driver unexpectedly stored authority".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use carrack_driver_contract::DriverKind;

    use super::{compiled_kind, project_access_grant};

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
}
