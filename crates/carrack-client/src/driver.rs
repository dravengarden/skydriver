//! Stable compiled native-driver interface and registry.
//!
//! Control-plane data selects only an adapter already compiled into this
//! binary. Provider-specific configuration, credentials, and behavior remain
//! behind this module; transfer orchestration sees one uniform interface.

use serde_json::Value;
use std::path::{Component, Path, PathBuf};

use crate::{Error, crypto::StagedObject};

/// How an adapter preserves one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SupportMode {
    Native,
    Emulated,
    Unavailable,
}

impl SupportMode {
    const fn available(self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// Complete explicit capability posture of one compiled adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DriverCapabilities {
    pub(crate) complete_upload: SupportMode,
    pub(crate) exact_range_read: SupportMode,
    pub(crate) resumable_upload: SupportMode,
    pub(crate) parallel_upload_parts: SupportMode,
    pub(crate) parallel_range_reads: SupportMode,
    pub(crate) strong_upload_checksum: SupportMode,
    pub(crate) stable_object_identity: SupportMode,
    pub(crate) stat: SupportMode,
    pub(crate) abort: SupportMode,
    pub(crate) delete: SupportMode,
    /// Zero means no adapter-specific bound below the Carrack protocol bound.
    pub(crate) maximum_object_bytes: u64,
    pub(crate) external_http_proxy: bool,
    pub(crate) external_socks_proxy: bool,
}

impl DriverCapabilities {
    fn validate(self) -> Result<(), Error> {
        if !self.complete_upload.available()
            || !self.exact_range_read.available()
            || !self.strong_upload_checksum.available()
            || !self.stable_object_identity.available()
            || !self.stat.available()
            || !self.delete.available()
            || (self.parallel_upload_parts.available() && !self.resumable_upload.available())
            || (self.external_socks_proxy && !self.external_http_proxy)
        {
            return Err(Error::InvalidResponse(
                "compiled driver capability descriptor is contradictory".to_owned(),
            ));
        }
        let _ = (self.abort, self.maximum_object_bytes);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriverKind {
    AliyunDriveOpenV2,
    R2V1,
    LocalFilesystemV2,
}

impl DriverKind {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "aliyundrive-open/v2" => Ok(Self::AliyunDriveOpenV2),
            "r2/v1" => Ok(Self::R2V1),
            "local-filesystem/v2" => Ok(Self::LocalFilesystemV2),
            _ => Err(Error::InvalidResponse(format!(
                "native driver kind is not compiled: {value}"
            ))),
        }
    }

    const fn capabilities(self) -> DriverCapabilities {
        match self {
            Self::AliyunDriveOpenV2 => DriverCapabilities {
                complete_upload: SupportMode::Native,
                exact_range_read: SupportMode::Native,
                resumable_upload: SupportMode::Unavailable,
                parallel_upload_parts: SupportMode::Unavailable,
                parallel_range_reads: SupportMode::Unavailable,
                strong_upload_checksum: SupportMode::Emulated,
                stable_object_identity: SupportMode::Native,
                stat: SupportMode::Native,
                abort: SupportMode::Unavailable,
                delete: SupportMode::Native,
                maximum_object_bytes: 0,
                external_http_proxy: true,
                external_socks_proxy: false,
            },
            Self::R2V1 => DriverCapabilities {
                complete_upload: SupportMode::Native,
                exact_range_read: SupportMode::Native,
                resumable_upload: SupportMode::Native,
                parallel_upload_parts: SupportMode::Native,
                parallel_range_reads: SupportMode::Native,
                strong_upload_checksum: SupportMode::Emulated,
                stable_object_identity: SupportMode::Native,
                stat: SupportMode::Native,
                abort: SupportMode::Native,
                delete: SupportMode::Native,
                maximum_object_bytes: 0,
                external_http_proxy: true,
                external_socks_proxy: false,
            },
            Self::LocalFilesystemV2 => DriverCapabilities {
                complete_upload: SupportMode::Native,
                exact_range_read: SupportMode::Native,
                resumable_upload: SupportMode::Emulated,
                parallel_upload_parts: SupportMode::Emulated,
                parallel_range_reads: SupportMode::Emulated,
                strong_upload_checksum: SupportMode::Emulated,
                stable_object_identity: SupportMode::Emulated,
                stat: SupportMode::Native,
                abort: SupportMode::Emulated,
                delete: SupportMode::Native,
                maximum_object_bytes: 0,
                external_http_proxy: false,
                external_socks_proxy: false,
            },
        }
    }
}

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
        let kind = DriverKind::parse(kind)?;
        kind.capabilities().validate()?;
        if matches!(kind, DriverKind::LocalFilesystemV2) && credential.is_some() {
            return Err(Error::InvalidResponse(
                "local driver unexpectedly received credentials".to_owned(),
            ));
        }
        if !matches!(kind, DriverKind::LocalFilesystemV2) && credential.is_none() {
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
                    "aliyundrive-open/v2",
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
            DriverKind::R2V1 => {
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
                    "aliyundrive-open/v2",
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
            DriverKind::R2V1 => {
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

    use super::{DriverRegistry, SupportMode};

    #[test]
    fn registry_is_closed_and_capabilities_are_explicit() {
        assert!(DriverRegistry::open("plugin/from-server", json!({}), None).is_err());
        let local =
            DriverRegistry::open("local-filesystem/v2", json!({"root": "/tmp/carrack"}), None)
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
                "local-filesystem/v2",
                json!({"root": "/tmp/carrack"}),
                Some(json!({"secret": "wrong"})),
            )
            .is_err()
        );
        assert!(DriverRegistry::open("r2/v1", json!({}), None).is_err());
    }

    #[test]
    fn capability_fallbacks_are_explicit_and_name_a_replacement() {
        let aliyun = DriverRegistry::open(
            "aliyundrive-open/v2",
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

        let r2 = DriverRegistry::open("r2/v1", json!({}), Some(json!({"method": "GET"})))
            .expect("open compiled R2 adapter");
        assert!(r2.upload_warnings(4).is_empty());
        assert!(r2.download_warnings(4).is_empty());
    }
}
