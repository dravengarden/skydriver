//! Portable, I/O-free contract shared by Skydriver driver registries.
//!
//! This crate names only adapters compiled into one Skydriver release and their
//! explicit capability posture. Native client and control-plane registries own
//! execution; server data can select a kind but cannot supply executable code.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Root-confined local filesystem driver configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalFilesystemConfig {
    /// Absolute provider root available to the filesystem agent.
    pub root: String,
}

/// Aliyun Drive Open adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AliyunDriveConfig {
    /// HTTPS Open API origin without a trailing slash.
    #[serde(default = "default_aliyun_api_base_url")]
    pub api_base_url: String,
    /// Provider drive selector: default, resource, or backup.
    #[serde(default = "default_aliyun_drive_type")]
    pub drive_type: String,
    /// Provider folder beneath which opaque complete objects are stored.
    #[serde(default = "default_aliyun_root_folder_id")]
    pub root_folder_id: String,
    /// Provider multipart upload unit.
    #[serde(default = "default_aliyun_upload_part_bytes")]
    pub upload_part_bytes: u64,
}

/// Cloudflare R2 S3-compatible adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct R2Config {
    /// Account-scoped HTTPS S3 endpoint.
    pub endpoint: String,
    /// Exact bucket name.
    pub bucket: String,
    /// Optional object-key prefix ending in `/`.
    #[serde(default)]
    pub prefix: String,
    /// Whether a Worker environment binding owns inventory and lifecycle I/O.
    #[serde(default)]
    pub managed: bool,
}

/// Official AWS S3 complete-object adapter configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsS3Config {
    /// Exact AWS region used for the regional endpoint and `SigV4` scope.
    pub region: String,
    /// Exact DNS-label bucket name.
    pub bucket: String,
    /// Twelve-digit AWS account ID that must own the bucket.
    pub expected_bucket_owner: String,
    /// Optional object-key prefix ending in `/`.
    #[serde(default)]
    pub prefix: String,
}

fn default_aliyun_api_base_url() -> String {
    "https://openapi.alipan.com".to_owned()
}

fn default_aliyun_drive_type() -> String {
    "resource".to_owned()
}

fn default_aliyun_root_folder_id() -> String {
    "root".to_owned()
}

const fn default_aliyun_upload_part_bytes() -> u64 {
    20 << 20
}

/// How a compiled adapter preserves one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportMode {
    /// The provider or native transport directly supplies the capability.
    Native,
    /// Skydriver preserves the capability with additional verified work.
    Emulated,
    /// The capability is unavailable and must fail closed or safely degrade.
    Unavailable,
}

impl SupportMode {
    /// Returns whether the capability has a correctness-preserving implementation.
    #[must_use]
    pub const fn available(self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

/// Versioned native driver kinds compiled into this Skydriver release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverKind {
    /// Aliyun Drive Open API complete-object adapter version 2.
    AliyunDriveOpenV2,
    /// Cloudflare R2 S3-compatible adapter version 1.
    R2V1,
    /// Official AWS S3 complete-object adapter version 1.
    AwsS3V1,
    /// Root-confined local filesystem adapter version 2.
    LocalFilesystemV2,
}

impl DriverKind {
    /// Every kind compiled into this release.
    pub const ALL: [Self; 4] = [
        Self::AliyunDriveOpenV2,
        Self::R2V1,
        Self::AwsS3V1,
        Self::LocalFilesystemV2,
    ];

    /// Parses one exact wire kind; unknown server values remain closed.
    #[must_use]
    pub const fn parse(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"aliyundrive-open/v2" => Some(Self::AliyunDriveOpenV2),
            b"r2/v1" => Some(Self::R2V1),
            b"aws-s3/v1" => Some(Self::AwsS3V1),
            b"local-filesystem/v2" => Some(Self::LocalFilesystemV2),
            _ => None,
        }
    }

    /// Returns the canonical wire kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AliyunDriveOpenV2 => "aliyundrive-open/v2",
            Self::R2V1 => "r2/v1",
            Self::AwsS3V1 => "aws-s3/v1",
            Self::LocalFilesystemV2 => "local-filesystem/v2",
        }
    }

    /// Returns the complete native data-path capability descriptor.
    #[must_use]
    pub const fn capabilities(self) -> DriverCapabilities {
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
            Self::R2V1 | Self::AwsS3V1 => DriverCapabilities {
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

    /// Returns how long-lived provider authority is represented.
    #[must_use]
    pub const fn credential_posture(self) -> CredentialPosture {
        match self {
            Self::AliyunDriveOpenV2 | Self::R2V1 | Self::AwsS3V1 => CredentialPosture::Required,
            Self::LocalFilesystemV2 => CredentialPosture::Forbidden,
        }
    }

    /// Returns how the control plane derives a short-lived object grant.
    #[must_use]
    pub const fn grant_mode(self) -> GrantMode {
        match self {
            Self::AliyunDriveOpenV2 => GrantMode::StoredAccess,
            Self::R2V1 | Self::AwsS3V1 => GrantMode::SignedObject,
            Self::LocalFilesystemV2 => GrantMode::None,
        }
    }

    /// Returns where inventory must execute.
    #[must_use]
    pub const fn inventory_mode(self) -> InventoryMode {
        match self {
            Self::AliyunDriveOpenV2 | Self::AwsS3V1 => InventoryMode::Hosted,
            Self::R2V1 => InventoryMode::EnvironmentBinding,
            Self::LocalFilesystemV2 => InventoryMode::AgentHost,
        }
    }

    /// Returns where delayed physical lifecycle work must execute.
    #[must_use]
    pub const fn lifecycle_mode(self) -> LifecycleMode {
        match self {
            Self::AliyunDriveOpenV2 | Self::R2V1 | Self::AwsS3V1 => LifecycleMode::ControlPlane,
            Self::LocalFilesystemV2 => LifecycleMode::AgentHost,
        }
    }
}

impl fmt::Display for DriverKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether a driver instance owns long-lived provider authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPosture {
    /// A validated encrypted provider credential is required.
    Required,
    /// A provider credential is invalid for this driver.
    Forbidden,
}

/// How object-scoped client authority is produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantMode {
    /// Project a stored access credential while omitting refresh authority.
    StoredAccess,
    /// Sign an object- and method-scoped grant in the control plane.
    SignedObject,
    /// No provider credential is sent to the client.
    None,
}

/// Execution location for provider inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryMode {
    /// The control plane can contact the hosted provider directly.
    Hosted,
    /// Inventory requires an environment-owned provider binding.
    EnvironmentBinding,
    /// Inventory must run on the filesystem agent host.
    AgentHost,
}

/// Execution location for delayed Stat and Delete work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleMode {
    /// The control plane owns delayed physical lifecycle operations.
    ControlPlane,
    /// An authorized agent on the provider host must perform lifecycle work.
    AgentHost,
}

/// Complete explicit native data-path capability posture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverCapabilities {
    /// Complete-object upload.
    pub complete_upload: SupportMode,
    /// Exact bounded range read.
    pub exact_range_read: SupportMode,
    /// Durable resumable upload.
    pub resumable_upload: SupportMode,
    /// Concurrent upload parts.
    pub parallel_upload_parts: SupportMode,
    /// Concurrent exact-range reads.
    pub parallel_range_reads: SupportMode,
    /// Strong encoded-object checksum verification.
    pub strong_upload_checksum: SupportMode,
    /// Stable provider-native immutable identity.
    pub stable_object_identity: SupportMode,
    /// Exact provider Stat.
    pub stat: SupportMode,
    /// Idempotent abort of incomplete provider work.
    pub abort: SupportMode,
    /// Idempotent physical Delete.
    pub delete: SupportMode,
    /// Adapter-specific maximum object bytes, or zero for the protocol bound.
    pub maximum_object_bytes: u64,
    /// Native external HTTP/HTTPS proxy support.
    pub external_http_proxy: bool,
    /// Native external SOCKS5/SOCKS5H proxy support.
    pub external_socks_proxy: bool,
}

impl DriverCapabilities {
    /// Validates internal descriptor dependencies.
    #[must_use]
    pub const fn is_consistent(self) -> bool {
        self.complete_upload.available()
            && self.exact_range_read.available()
            && self.strong_upload_checksum.available()
            && self.stable_object_identity.available()
            && self.stat.available()
            && self.delete.available()
            && (!self.parallel_upload_parts.available() || self.resumable_upload.available())
            && (!self.external_socks_proxy || self.external_http_proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AliyunDriveConfig, AwsS3Config, CredentialPosture, DriverKind, GrantMode, InventoryMode,
        LifecycleMode, R2Config,
    };

    #[test]
    fn all_wire_kinds_round_trip_and_descriptors_are_consistent() {
        for kind in DriverKind::ALL {
            assert_eq!(DriverKind::parse(kind.as_str()), Some(kind));
            assert!(kind.capabilities().is_consistent());
        }
        assert_eq!(DriverKind::parse("plugin/from-server"), None);
    }

    #[test]
    fn control_plane_postures_are_explicit() {
        assert_eq!(
            DriverKind::R2V1.credential_posture(),
            CredentialPosture::Required
        );
        assert_eq!(DriverKind::R2V1.grant_mode(), GrantMode::SignedObject);
        assert_eq!(
            DriverKind::R2V1.inventory_mode(),
            InventoryMode::EnvironmentBinding
        );
        assert_eq!(
            DriverKind::LocalFilesystemV2.lifecycle_mode(),
            LifecycleMode::AgentHost
        );
    }

    #[test]
    fn configuration_shapes_are_strict_and_defaults_are_canonical() {
        let aliyun = serde_json::from_str::<AliyunDriveConfig>("{}")
            .expect("normalize default Aliyun configuration");
        assert_eq!(aliyun.api_base_url, "https://openapi.alipan.com");
        assert_eq!(aliyun.drive_type, "resource");
        assert_eq!(aliyun.root_folder_id, "root");
        assert_eq!(aliyun.upload_part_bytes, 20 << 20);
        assert!(serde_json::from_str::<AliyunDriveConfig>(r#"{"unknown":true}"#).is_err());

        let r2 = R2Config {
            endpoint: "https://account.r2.cloudflarestorage.com".to_owned(),
            bucket: "payload".to_owned(),
            prefix: "objects/".to_owned(),
            managed: true,
        };
        let encoded = serde_json::to_string(&r2).expect("encode R2 configuration");
        assert_eq!(
            serde_json::from_str::<R2Config>(&encoded).expect("decode R2 configuration"),
            r2
        );

        let s3 = AwsS3Config {
            region: "us-east-1".to_owned(),
            bucket: "skydriver-payload-example".to_owned(),
            expected_bucket_owner: "123456789012".to_owned(),
            prefix: "objects/".to_owned(),
        };
        let encoded = serde_json::to_string(&s3).expect("encode AWS S3 configuration");
        assert_eq!(
            serde_json::from_str::<AwsS3Config>(&encoded).expect("decode AWS S3 configuration"),
            s3
        );
        assert!(
            serde_json::from_str::<AwsS3Config>(
                r#"{"region":"us-east-1","bucket":"payload","expected_bucket_owner":"123456789012","endpoint":"https://example.com"}"#,
            )
            .is_err()
        );
    }
}
