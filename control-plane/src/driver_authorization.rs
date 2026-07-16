//! Provider credential validation and authorization adapters.
//!
//! Management claims, D1 fences, envelope sealing, receipts, and audits stay
//! with the credential transaction. This module owns provider credential wire
//! shapes and the network verification needed before a credential can commit.

use carrack_driver_contract::DriverKind;
use serde::{Deserialize, Serialize};

use crate::{driver_renewal, r2_signing};

pub(crate) const LONG_LIVED_CREDENTIAL_EXPIRES_AT: u64 = 253_402_300_799;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefreshAuthorization {
    refresh_token: String,
    refresh_issuer: String,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum CredentialAuthorization {
    Aliyun(RefreshAuthorization),
    R2(r2_signing::Credential),
}

pub(crate) struct CredentialMaterial {
    pub(crate) plaintext: Vec<u8>,
    pub(crate) credential_expires_at: u64,
    pub(crate) refresh_token_expires_at: u64,
    pub(crate) managed_issuer: Option<String>,
}

pub(crate) enum AuthorizationFailure {
    Invalid,
    Rejected,
    Retry,
    Internal(worker::Error),
}

pub(crate) fn refresh_after(expires_at: u64, now: u64) -> u64 {
    driver_renewal::refresh_after(expires_at, now)
}

pub(crate) fn same_authority(kind: DriverKind, existing: &[u8], replacement: &[u8]) -> bool {
    match kind {
        DriverKind::AliyunDriveOpenV2 => driver_renewal::same_authority(existing, replacement),
        // R2 configuration pins the endpoint, bucket, and object prefix, and
        // authorize() has already proved the replacement against that bucket.
        DriverKind::R2V1 => true,
        DriverKind::LocalFilesystemV2 => false,
    }
}

pub(crate) fn validate(
    kind: DriverKind,
    authorization: &CredentialAuthorization,
    now: u64,
) -> Option<u64> {
    match (kind, authorization) {
        (DriverKind::AliyunDriveOpenV2, CredentialAuthorization::Aliyun(authorization))
            if authorization.refresh_issuer == driver_renewal::OPENLIST_ONLINE_ISSUER =>
        {
            driver_renewal::refresh_claims(&authorization.refresh_token)
                .filter(|claims| claims.exp > now)
                .map(|claims| claims.exp)
        }
        (DriverKind::R2V1, CredentialAuthorization::R2(credential))
            if r2_signing::valid_credential(credential) =>
        {
            Some(LONG_LIVED_CREDENTIAL_EXPIRES_AT)
        }
        _ => None,
    }
}

pub(crate) async fn authorize(
    kind: DriverKind,
    config_json: &str,
    authorization: CredentialAuthorization,
    now: u64,
) -> std::result::Result<CredentialMaterial, AuthorizationFailure> {
    if validate(kind, &authorization, now).is_none() {
        return Err(AuthorizationFailure::Invalid);
    }
    match (kind, authorization) {
        (DriverKind::AliyunDriveOpenV2, CredentialAuthorization::Aliyun(authorization)) => {
            let material = driver_renewal::authorize_refresh_token(
                &authorization.refresh_token,
                &authorization.refresh_issuer,
            )
            .await
            .map_err(|failure| match failure {
                driver_renewal::RenewalFailure::Reauthenticate(_) => AuthorizationFailure::Rejected,
                driver_renewal::RenewalFailure::Retry(_) => AuthorizationFailure::Retry,
                driver_renewal::RenewalFailure::Internal(error) => {
                    AuthorizationFailure::Internal(error)
                }
            })?;
            Ok(CredentialMaterial {
                plaintext: material.plaintext,
                credential_expires_at: material.credential_expires_at,
                refresh_token_expires_at: material.refresh_token_expires_at,
                managed_issuer: material.managed_issuer,
            })
        }
        (DriverKind::R2V1, CredentialAuthorization::R2(credential)) => {
            let config =
                serde_json::from_str::<r2_signing::Config>(config_json).map_err(|error| {
                    AuthorizationFailure::Internal(worker::Error::RustError(error.to_string()))
                })?;
            if !r2_signing::verify(&config, &credential).await {
                return Err(AuthorizationFailure::Rejected);
            }
            let plaintext = serde_json::to_vec(&credential).map_err(|error| {
                AuthorizationFailure::Internal(worker::Error::RustError(error.to_string()))
            })?;
            Ok(CredentialMaterial {
                plaintext,
                credential_expires_at: LONG_LIVED_CREDENTIAL_EXPIRES_AT,
                refresh_token_expires_at: LONG_LIVED_CREDENTIAL_EXPIRES_AT,
                managed_issuer: None,
            })
        }
        _ => Err(AuthorizationFailure::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use carrack_driver_contract::DriverKind;

    use super::{CredentialAuthorization, RefreshAuthorization, validate};

    #[test]
    fn rejects_cross_driver_and_invalid_authority_without_io() {
        let aliyun = CredentialAuthorization::Aliyun(RefreshAuthorization {
            refresh_token: "not-a-jwt".to_owned(),
            refresh_issuer: "unknown".to_owned(),
        });
        assert!(validate(DriverKind::AliyunDriveOpenV2, &aliyun, 1).is_none());
        assert!(validate(DriverKind::R2V1, &aliyun, 1).is_none());
    }
}
