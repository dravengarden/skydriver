//! Portable, I/O-free contract shared by Carrack driver registries.
//!
//! This crate names only adapters compiled into one Carrack release and their
//! explicit capability posture. Native client and control-plane registries own
//! execution; server data can select a kind but cannot supply executable code.

use core::fmt;

/// How a compiled adapter preserves one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportMode {
    /// The provider or native transport directly supplies the capability.
    Native,
    /// Carrack preserves the capability with additional verified work.
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

/// Versioned native driver kinds compiled into this Carrack release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverKind {
    /// Aliyun Drive Open API complete-object adapter version 2.
    AliyunDriveOpenV2,
    /// Cloudflare R2 S3-compatible adapter version 1.
    R2V1,
    /// Root-confined local filesystem adapter version 2.
    LocalFilesystemV2,
}

impl DriverKind {
    /// Every kind compiled into this release.
    pub const ALL: [Self; 3] = [Self::AliyunDriveOpenV2, Self::R2V1, Self::LocalFilesystemV2];

    /// Parses one exact wire kind; unknown server values remain closed.
    #[must_use]
    pub const fn parse(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"aliyundrive-open/v2" => Some(Self::AliyunDriveOpenV2),
            b"r2/v1" => Some(Self::R2V1),
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

    /// Returns how long-lived provider authority is represented.
    #[must_use]
    pub const fn credential_posture(self) -> CredentialPosture {
        match self {
            Self::AliyunDriveOpenV2 | Self::R2V1 => CredentialPosture::Required,
            Self::LocalFilesystemV2 => CredentialPosture::Forbidden,
        }
    }

    /// Returns how the control plane derives a short-lived object grant.
    #[must_use]
    pub const fn grant_mode(self) -> GrantMode {
        match self {
            Self::AliyunDriveOpenV2 => GrantMode::StoredAccess,
            Self::R2V1 => GrantMode::SignedObject,
            Self::LocalFilesystemV2 => GrantMode::None,
        }
    }

    /// Returns where inventory must execute.
    #[must_use]
    pub const fn inventory_mode(self) -> InventoryMode {
        match self {
            Self::AliyunDriveOpenV2 => InventoryMode::Hosted,
            Self::R2V1 => InventoryMode::EnvironmentBinding,
            Self::LocalFilesystemV2 => InventoryMode::AgentHost,
        }
    }

    /// Returns where delayed physical lifecycle work must execute.
    #[must_use]
    pub const fn lifecycle_mode(self) -> LifecycleMode {
        match self {
            Self::AliyunDriveOpenV2 | Self::R2V1 => LifecycleMode::ControlPlane,
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
    use super::{CredentialPosture, DriverKind, GrantMode, InventoryMode, LifecycleMode};

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
}
