//! Stable compiled native-driver interface and registry.
//!
//! Control-plane data selects only an adapter already compiled into this
//! binary. Provider-specific configuration, credentials, and behavior remain
//! behind this module; transfer orchestration sees one uniform interface.

use serde_json::Value;
use skydriver_driver_contract::{CredentialPosture, DriverCapabilities, DriverKind, SupportMode};
use std::path::{Component, Path, PathBuf};

use crate::{Error, crypto::StagedObject};

/// One authorized, typed instance opened from the compiled registry.
pub(crate) struct OpenedDriver {
    kind: DriverKind,
    config: Value,
    credential: Option<Value>,
}

/// Immutable upload request accepted by every compiled adapter.
pub(crate) struct UploadRequest<'a> {
    pub(crate) control: &'a crate::Client,
    pub(crate) token: &'a str,
    pub(crate) intent_id: &'a str,
    pub(crate) storage_key: &'a str,
    pub(crate) staged: &'a StagedObject,
    pub(crate) part_bytes: u64,
    pub(crate) maximum_concurrency: usize,
}

/// Immutable download request accepted by every compiled adapter.
pub(crate) struct DownloadRequest<'a> {
    pub(crate) http: &'a reqwest::Client,
    pub(crate) storage_key: &'a str,
    pub(crate) native_id: Option<&'a str>,
    pub(crate) staging_directory: &'a Path,
    pub(crate) version_id: &'a str,
    pub(crate) encoded_bytes: u64,
    pub(crate) encoded_sha256: &'a str,
    pub(crate) part_bytes: u64,
    pub(crate) maximum_concurrency: usize,
}

/// Exact immutable provider evidence returned after complete readback.
pub(crate) struct ProviderObject {
    pub(crate) native_id: String,
    pub(crate) provider_version: String,
    pub(crate) etag: String,
}

/// Static registry of native adapters compiled into this SDK build.
pub(crate) struct DriverRegistry;

impl DriverRegistry {
    pub(crate) fn open(
        kind: &str,
        config: Value,
        credential: Option<Value>,
    ) -> Result<OpenedDriver, Error> {
        if !config.is_object() || credential.as_ref().is_some_and(|value| !value.is_object()) {
            return Err(Error::InvalidResponse(
                "driver grant must contain typed JSON objects".to_owned(),
            ));
        }
        let kind = DriverKind::parse(kind).ok_or_else(|| {
            Error::InvalidResponse(format!("native driver kind is not compiled: {kind}"))
        })?;
        if !kind.capabilities().is_consistent() {
            return Err(Error::InvalidResponse(
                "compiled driver capability descriptor is contradictory".to_owned(),
            ));
        }
        if kind.credential_posture() == CredentialPosture::Forbidden && credential.is_some() {
            return Err(Error::InvalidResponse(
                "local driver unexpectedly received credentials".to_owned(),
            ));
        }
        if kind.credential_posture() == CredentialPosture::Required && credential.is_none() {
            return Err(Error::InvalidResponse(
                "hosted driver omitted its object-scoped credential".to_owned(),
            ));
        }
        Ok(OpenedDriver {
            kind,
            config,
            credential,
        })
    }
}

impl OpenedDriver {
    pub(crate) const fn capabilities(&self) -> DriverCapabilities {
        self.kind.capabilities()
    }

    pub(crate) fn upload_warnings(&self, requested: usize) -> Vec<String> {
        if requested > 1 && self.capabilities().parallel_upload_parts == SupportMode::Unavailable {
            return vec![
                "This driver safely degrades upload concurrency to one; use an S3 or R2 driver when parallel multipart upload is required."
                    .to_owned(),
            ];
        }
        Vec::new()
    }

    pub(crate) fn download_warnings(&self, requested: usize) -> Vec<String> {
        if requested > 1 && self.capabilities().parallel_range_reads == SupportMode::Unavailable {
            return vec![
                "This driver safely degrades exact-range download concurrency to one; use an S3 or R2 driver when parallel ranges are required."
                    .to_owned(),
            ];
        }
        Vec::new()
    }

    pub(crate) async fn upload(
        &mut self,
        request: UploadRequest<'_>,
    ) -> Result<ProviderObject, Error> {
        match self.kind {
            DriverKind::AliyunDriveOpenV2 => {
                let credential = self.take_credential()?;
                let object = crate::aliyun::upload(
                    request.http(),
                    &self.config,
                    credential,
                    request.storage_key,
                    &request.staged.path,
                    request.staged.encoded_bytes,
                    &request.staged.encoded_sha256,
                )
                .await?;
                Ok(ProviderObject {
                    native_id: object.native_id,
                    provider_version: object.provider_version,
                    etag: object.etag,
                })
            }
            DriverKind::R2V1 | DriverKind::AwsS3V1 => {
                let credential = self.take_credential()?;
                let (native_id, provider_version, etag) = crate::r2::upload(
                    request.control,
                    request.token,
                    request.intent_id,
                    credential,
                    &request.staged.path,
                    request.staged.encoded_bytes,
                    &request.staged.encoded_sha256,
                    request.part_bytes,
                    request.maximum_concurrency,
                )
                .await?;
                Ok(ProviderObject {
                    native_id,
                    provider_version,
                    etag,
                })
            }
            DriverKind::LocalFilesystemV2 => {
                let root = local_root(&self.config)?;
                let object = crate::local::upload(
                    root,
                    request.intent_id,
                    request.storage_key,
                    &request.staged.path,
                    request.staged.encoded_bytes,
                    &request.staged.encoded_sha256,
                    request.part_bytes,
                    request.maximum_concurrency,
                )?;
                Ok(ProviderObject {
                    native_id: object.native_id,
                    provider_version: object.provider_version,
                    etag: object.etag,
                })
            }
        }
    }

    pub(crate) async fn download(
        &mut self,
        request: DownloadRequest<'_>,
    ) -> Result<PathBuf, Error> {
        match self.kind {
            DriverKind::AliyunDriveOpenV2 => {
                let credential = self.take_credential()?;
                crate::aliyun::download(
                    request.http,
                    &self.config,
                    credential,
                    request.storage_key,
                    request.native_id,
                    request.staging_directory,
                    request.version_id,
                    request.encoded_bytes,
                    request.encoded_sha256,
                )
                .await
            }
            DriverKind::R2V1 | DriverKind::AwsS3V1 => {
                let credential = self.take_credential()?;
                crate::r2::download(
                    request.http,
                    credential,
                    request.staging_directory,
                    request.version_id,
                    request.encoded_bytes,
                    request.encoded_sha256,
                    request.part_bytes,
                    request.maximum_concurrency,
                )
                .await
            }
            DriverKind::LocalFilesystemV2 => crate::local::download(
                local_root(&self.config)?,
                request.storage_key,
                request.staging_directory,
                request.version_id,
                request.encoded_bytes,
                request.encoded_sha256,
                request.part_bytes,
                request.maximum_concurrency,
            ),
        }
    }

    fn take_credential(&mut self) -> Result<Value, Error> {
        self.credential.take().ok_or_else(|| {
            Error::InvalidResponse("driver credential was already consumed".to_owned())
        })
    }
}

impl UploadRequest<'_> {
    fn http(&self) -> &reqwest::Client {
        &self.control.http
    }
}

fn local_root(config: &Value) -> Result<&str, Error> {
    config
        .get("root")
        .and_then(Value::as_str)
        .filter(|root| !root.is_empty())
        .ok_or_else(|| Error::InvalidResponse("local driver root is missing".to_owned()))
}

pub(crate) fn safe_storage_key(value: &str) -> Result<PathBuf, Error> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(Error::InvalidResponse(
            "unsafe provider storage key".to_owned(),
        ));
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DriverKind, DriverRegistry, SupportMode};

    #[test]
    fn registry_is_closed_and_capabilities_are_explicit() {
        assert!(DriverRegistry::open("plugin/from-server", json!({}), None).is_err());
        let local = DriverRegistry::open(
            DriverKind::LocalFilesystemV2.as_str(),
            json!({"root": "/tmp/skydriver"}),
            None,
        )
        .expect("open compiled local adapter");
        let capabilities = local.capabilities();
        assert_eq!(capabilities.complete_upload, SupportMode::Native);
        assert_eq!(capabilities.resumable_upload, SupportMode::Emulated);
        assert_eq!(capabilities.delete, SupportMode::Native);
        assert!(!capabilities.external_http_proxy);
    }

    #[test]
    fn registry_enforces_credential_posture_before_io() {
        assert!(
            DriverRegistry::open(
                DriverKind::LocalFilesystemV2.as_str(),
                json!({"root": "/tmp/skydriver"}),
                Some(json!({"secret": "wrong"})),
            )
            .is_err()
        );
        assert!(DriverRegistry::open(DriverKind::R2V1.as_str(), json!({}), None).is_err());
    }

    #[test]
    fn capability_fallbacks_are_explicit_and_name_a_replacement() {
        let aliyun = DriverRegistry::open(
            DriverKind::AliyunDriveOpenV2.as_str(),
            json!({}),
            Some(json!({"access_token": "object-scoped"})),
        )
        .expect("open compiled Aliyun adapter");
        let upload = aliyun.upload_warnings(4);
        let download = aliyun.download_warnings(4);
        assert_eq!(upload.len(), 1);
        assert_eq!(download.len(), 1);
        assert!(upload[0].contains("degrades"));
        assert!(upload[0].contains("R2"));
        assert!(download[0].contains("degrades"));
        assert!(download[0].contains("R2"));

        let r2 = DriverRegistry::open(
            DriverKind::R2V1.as_str(),
            json!({}),
            Some(json!({"method": "GET"})),
        )
        .expect("open compiled R2 adapter");
        assert!(r2.upload_warnings(4).is_empty());
        assert!(r2.download_warnings(4).is_empty());
    }
}
