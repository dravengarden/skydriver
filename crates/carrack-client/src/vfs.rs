//! Filesystem-oriented VFS metadata client.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use carrack_metadata_cache::MetadataCacheCipher;
use carrack_sdk_core::{
    CatalogCheckpoint, CatalogDelta, MAXIMUM_CATALOG_CHECKPOINT_BYTES, MAXIMUM_CATALOG_DELTA_BYTES,
    catalog_checkpoint_etag, validate_catalog_checkpoint, validate_catalog_checkpoint_etag,
    validate_catalog_delta,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Client, Error, OptionalBytesResponse,
    catalog::{CatalogCheckpointCondition, CatalogEntry, merkle_entry},
};

const TOKEN_BYTES: usize = 32;
const DEFAULT_DIRECTORY_PAGE_SIZE: usize = 200;
const MAXIMUM_DIRECTORY_PAGE_SIZE: u32 = 1_000;
const ENCRYPTED_SUITE: &str = "carrack-vfs-aes256gcm-hkdfsha256-v1";
const PLAINTEXT_SUITE: &str = "plaintext/v1";
const MAXIMUM_IDEMPOTENCY_BYTES: usize = 256;
const MAXIMUM_DRIVER_ID_BYTES: usize = 256;

/// One canonical 256-bit VFS bearer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VfsToken([u8; TOKEN_BYTES]);

impl VfsToken {
    /// Parses canonical unpadded base64url token material.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, or all-zero tokens.
    pub fn parse(encoded: &str) -> Result<Self, Error> {
        let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
            Error::InvalidEndpoint("VFS token must be canonical base64url".to_owned())
        })?;
        if decoded.len() != TOKEN_BYTES || decoded.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidEndpoint(
                "VFS token must encode 32 nonzero bytes".to_owned(),
            ));
        }
        let mut token = [0_u8; TOKEN_BYTES];
        token.copy_from_slice(&decoded);
        Ok(Self(token))
    }

    pub(crate) fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub(crate) fn metadata_cache_cipher(
        &self,
        token_id: &[u8; 16],
    ) -> Result<MetadataCacheCipher, Error> {
        MetadataCacheCipher::new(&self.0, token_id)
            .map_err(|error| Error::InvalidResponse(error.to_string()))
    }
}

/// Non-secret VFS session identity used for path resolution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VfsSession {
    /// Stable schema identity.
    pub schema: String,
    /// Current token identity.
    pub token_id: String,
    /// Principal identity.
    pub principal_id: String,
    /// Directory treated as `/` by this token.
    pub root_directory_id: String,
    /// Server-clock expiry.
    pub expires_at: u64,
}

pub(crate) struct CatalogCheckpointDelivery {
    pub(crate) checkpoint: CatalogCheckpoint,
    pub(crate) etag: String,
}

pub(crate) struct CatalogDeltaDelivery {
    pub(crate) delta: CatalogDelta,
    pub(crate) etag: String,
}

pub(crate) enum CatalogCheckpointOutcome {
    Unavailable,
    Unchanged,
    Delivered(CatalogCheckpointDelivery),
    Delta(CatalogDeltaDelivery),
}

/// One live directory and its optimistic revisions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    /// Stable directory identity.
    pub id: String,
    /// Owning filesystem identity.
    pub filesystem_id: String,
    /// Parent identity, absent for the filesystem root.
    pub parent_id: Option<String>,
    /// Canonical entry name.
    pub name: String,
    /// Authenticated directory Merkle root.
    pub data_root: String,
    /// Content encryption suite.
    pub crypto_suite: String,
    /// Active directory-key epoch.
    pub active_key_epoch: u64,
    /// Whether ACL lookup continues through the parent.
    pub acl_inherits: bool,
    /// Namespace content revision.
    pub revision: u64,
    /// Direct ACL revision.
    pub acl_revision: u64,
    /// Driver placement revision.
    pub placement_revision: u64,
}

/// Directory entry kind.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// Complete immutable file version.
    File,
    /// Child directory.
    Directory,
}

/// One immutable live directory entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    /// Canonical entry name.
    pub name: String,
    /// File or directory discriminator.
    pub kind: EntryKind,
    /// Stable file identity for file entries.
    pub file_id: Option<String>,
    /// Immutable version identity for file entries.
    pub version_id: Option<String>,
    /// Stable child identity for directory entries.
    pub child_directory_id: Option<String>,
    /// Plaintext logical size.
    pub size_bytes: u64,
    /// File or child-directory Merkle root.
    pub data_root: String,
    /// File metadata root when applicable.
    pub metadata_root: Option<String>,
    /// Entry replacement revision.
    pub revision: u64,
    /// Server-clock update time.
    pub updated_at: u64,
}

/// One revision-consistent directory page.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPage {
    /// Stable response schema.
    pub schema: String,
    /// Directory identity pinned by this page.
    pub directory: Directory,
    /// Canonically ordered entries.
    pub entries: Vec<DirectoryEntry>,
    /// Opaque continuation cursor.
    pub next_cursor: Option<String>,
}

/// Durable mkdir receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryCreation {
    /// Stable response schema.
    pub schema: String,
    /// Idempotent operation identity.
    pub operation_id: String,
    /// Owning filesystem identity.
    pub filesystem_id: String,
    /// Parent directory identity.
    pub parent_directory_id: String,
    /// Created directory identity.
    pub directory_id: String,
    /// Canonical child name.
    pub name: String,
    /// Empty directory Merkle root.
    pub data_root: String,
    /// Effective content encryption suite.
    pub crypto_suite: String,
    /// Initial directory-key epoch.
    pub key_epoch: u64,
    /// Durable catalog publication identity.
    pub catalog_revision_id: u64,
    /// Server-clock creation time.
    pub created_at: u64,
    /// Durable operation state.
    pub state: String,
}

/// Durable logical removal and server-GC tombstone receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveReceipt {
    /// Stable response schema.
    pub schema: String,
    /// Idempotent operation identity.
    pub operation_id: String,
    /// Owning filesystem identity.
    pub filesystem_id: String,
    /// Former parent directory identity.
    pub directory_id: String,
    /// Removed entry name.
    pub name: String,
    /// Removed entry kind.
    pub kind: EntryKind,
    /// Tombstoned file or directory identity.
    pub subject_id: String,
    /// Durable catalog publication identity.
    pub catalog_revision_id: u64,
    /// Earliest server-owned physical deletion time for file payloads.
    pub delete_after: Option<u64>,
    /// Server-clock commit time.
    pub committed_at: u64,
    /// Durable operation state.
    pub state: String,
}

/// Durable atomic rename or same-filesystem move receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenameReceipt {
    /// Stable response schema.
    pub schema: String,
    /// Idempotent operation identity.
    pub operation_id: String,
    /// Owning filesystem identity.
    pub filesystem_id: String,
    /// Former parent directory identity.
    pub source_directory_id: String,
    /// Former canonical entry name.
    pub source_name: String,
    /// New parent directory identity.
    pub destination_directory_id: String,
    /// New canonical entry name.
    pub destination_name: String,
    /// Moved entry kind.
    pub kind: EntryKind,
    /// Stable file or directory identity.
    pub subject_id: String,
    /// New destination entry revision.
    pub entry_revision: u64,
    /// Durable catalog publication identity.
    pub catalog_revision_id: u64,
    /// Server-clock commit time.
    pub committed_at: u64,
    /// Durable operation state.
    pub state: String,
}

/// One effective direct ACL grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclGrant {
    /// Stable grant identity.
    pub id: String,
    /// Direct principal subject, when this is not a group grant.
    pub principal_id: Option<String>,
    /// Direct group subject, when this is not a principal grant.
    pub group_id: Option<String>,
    /// Exact allowed action.
    pub action: String,
    /// Named role that expanded into this action, when applicable.
    pub source_role: Option<String>,
}

/// One complete directory ACL view.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclPolicy {
    /// Stable schema identity.
    pub schema: String,
    /// Directory governed by this policy.
    pub directory_id: String,
    /// Whether parent grants remain effective.
    pub acl_inherits: bool,
    /// Optimistic ACL revision.
    pub acl_revision: u64,
    /// Canonically ordered direct grants.
    pub grants: Vec<AclGrant>,
}

/// One requested driver placement.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Placement {
    /// Registered driver identity.
    pub driver_id: String,
    /// Lower values receive writes first.
    pub write_priority: u64,
}

/// One effective placement with current driver identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementView {
    /// Registered driver identity.
    pub driver_id: String,
    /// Versioned driver implementation kind.
    pub driver_kind: String,
    /// Configuration and credential revision.
    pub driver_revision: u64,
    /// Lower values receive writes first.
    pub write_priority: u64,
    /// Placement lifecycle state.
    pub state: String,
}

/// One complete directory placement policy.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementPolicy {
    /// Stable schema identity.
    pub schema: String,
    /// Directory governed by this policy.
    pub directory_id: String,
    /// Optimistic placement revision.
    pub placement_revision: u64,
    /// Ordered active placements.
    pub placements: Vec<PlacementView>,
}

/// Durable policy replacement receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMutationReceipt {
    /// Stable schema identity.
    pub schema: String,
    /// Durable operation identity.
    pub operation_id: String,
    /// `acl.replace` or `placement.replace`.
    pub kind: String,
    /// Mutated directory.
    pub directory_id: String,
    /// Revision after the replacement.
    pub final_revision: u64,
    /// Canonical committed policy payload.
    pub policy: serde_json::Value,
    /// Server-clock commit time.
    pub committed_at: u64,
    /// Durable operation state.
    pub state: String,
}

/// Newly issued narrower child token. The bearer appears only here.
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct IssuedToken {
    /// Stable schema identity.
    #[zeroize(skip)]
    pub schema: String,
    /// Child token identity.
    #[zeroize(skip)]
    pub token_id: String,
    /// Same-principal identity inherited from the parent.
    #[zeroize(skip)]
    pub principal_id: String,
    /// Issuing parent token identity.
    #[zeroize(skip)]
    pub parent_token_id: String,
    /// Child root directory.
    #[zeroize(skip)]
    pub root_directory_id: String,
    /// Narrowed actions.
    #[zeroize(skip)]
    pub actions: Vec<String>,
    /// Optional narrowed driver set.
    #[zeroize(skip)]
    pub driver_ids: Option<Vec<String>>,
    /// Server-clock expiry.
    #[zeroize(skip)]
    pub expires_at: u64,
    /// Secret canonical bearer; store it securely because it is not returned again.
    pub token: String,
}

/// Durable child-token revocation receipt.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedToken {
    /// Stable schema identity.
    pub schema: String,
    /// Revoked token identity.
    pub token_id: String,
    /// Owning principal identity.
    pub principal_id: String,
    /// Revoked token root directory.
    pub root_directory_id: String,
    /// Server-clock revocation time.
    pub revoked_at: u64,
    /// Durable operation state.
    pub state: String,
}

/// Path resolution result returned by the high-level filesystem facade.
#[derive(Clone, Debug, Serialize)]
pub struct ResolvedEntry {
    /// Canonical absolute VFS path.
    pub path: String,
    /// Parent directory containing the entry.
    pub parent: Directory,
    /// Entry metadata, or `None` for the token root itself.
    pub entry: Option<DirectoryEntry>,
}

/// Authenticated complete-object VFS client.
#[derive(Clone)]
pub struct VfsClient {
    pub(crate) control: Client,
    pub(crate) token: VfsToken,
}

impl VfsClient {
    /// Constructs a VFS client and copies the bearer into zeroizing storage.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe endpoint.
    pub fn new(endpoint: &str, token: VfsToken) -> Result<Self, Error> {
        Ok(Self {
            control: Client::new(endpoint)?,
            token,
        })
    }

    /// Performs the mandatory compatibility preflight.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable or incompatible control plane.
    pub async fn check_compatibility(&self) -> Result<crate::ProtocolCompatibility, Error> {
        self.control.check_compatibility().await
    }

    /// Reads the non-secret token root identity.
    ///
    /// # Errors
    ///
    /// Returns an authentication, protocol, or transport error.
    pub async fn session(&self) -> Result<VfsSession, Error> {
        let token = self.token.encode();
        let session = self
            .control
            .send_json::<VfsSession, ()>(Method::GET, "api/v2/session", Some(&token), &[], None)
            .await?;
        validate_session(&session)?;
        Ok(session)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transport boundary validates full, unchanged, unavailable, and hash-linked delta responses without partially trusted intermediates"
    )]
    pub(crate) async fn catalog_checkpoint(
        &self,
        session: &VfsSession,
        condition: Option<&CatalogCheckpointCondition>,
    ) -> Result<CatalogCheckpointOutcome, Error> {
        let token = self.token.encode();
        let base_revision = condition.map(|value| value.revision_id.to_string());
        let request_headers = condition
            .zip(base_revision.as_deref())
            .map(|(value, revision)| {
                vec![
                    ("Carrack-Catalog-Accept-Delta", "v1"),
                    ("Carrack-Catalog-Base-Revision", revision),
                    ("Carrack-Catalog-Base-Root", value.root_data_root.as_str()),
                    (
                        "Carrack-Catalog-Base-SHA256",
                        value.checkpoint_sha256.as_str(),
                    ),
                ]
            })
            .unwrap_or_default();
        let response = match self
            .control
            .send_optional_bytes(
                "api/v2/catalog/checkpoint",
                &token,
                MAXIMUM_CATALOG_CHECKPOINT_BYTES,
                condition.map(|value| value.etag.as_str()),
                &request_headers,
            )
            .await?
        {
            OptionalBytesResponse::Unavailable => {
                return Ok(CatalogCheckpointOutcome::Unavailable);
            }
            OptionalBytesResponse::NotModified => {
                return Ok(CatalogCheckpointOutcome::Unchanged);
            }
            OptionalBytesResponse::Body(response) => response,
        };
        let content_type = required_header(&response.headers, "content-type")?;
        let content_length = required_header(&response.headers, "content-length")?
            .parse::<usize>()
            .map_err(|_| {
                Error::InvalidResponse("catalog checkpoint length header is invalid".to_owned())
            })?;
        let expected_sha256 = required_header(&response.headers, "carrack-catalog-sha256")?;
        let expected_etag = required_header(&response.headers, "etag")?;
        validate_catalog_checkpoint_etag(expected_etag)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        let expected_revision = required_header(&response.headers, "carrack-catalog-revision")?
            .parse::<u64>()
            .map_err(|_| {
                Error::InvalidResponse("catalog checkpoint revision header is invalid".to_owned())
            })?;
        let expected_root = required_header(&response.headers, "carrack-catalog-root")?;
        if content_length != response.body.len() || response.body.is_empty() {
            return Err(Error::InvalidResponse(
                "catalog checkpoint transport receipt differs".to_owned(),
            ));
        }
        if content_type == "application/vnd.carrack.catalog-delta+json" {
            if response.body.len() > MAXIMUM_CATALOG_DELTA_BYTES {
                return Err(Error::InvalidResponse(
                    "catalog delta exceeds its transport bound".to_owned(),
                ));
            }
            let expected_delta_sha256 =
                required_header(&response.headers, "carrack-catalog-delta-sha256")?;
            if expected_delta_sha256 != hex::encode(Sha256::digest(&response.body)) {
                return Err(Error::InvalidResponse(
                    "catalog delta transport receipt differs".to_owned(),
                ));
            }
            let delta: CatalogDelta = serde_json::from_slice(&response.body).map_err(|error| {
                Error::InvalidResponse(format!("decode catalog delta: {error}"))
            })?;
            if serde_json::to_vec(&delta)
                .map_err(|error| Error::InvalidResponse(format!("encode catalog delta: {error}")))?
                != response.body
            {
                return Err(Error::InvalidResponse(
                    "catalog delta is not canonically encoded".to_owned(),
                ));
            }
            validate_catalog_delta(&delta)
                .map_err(|error| Error::InvalidResponse(error.to_string()))?;
            let base = condition.ok_or_else(|| {
                Error::InvalidResponse("catalog delta has no requested base".to_owned())
            })?;
            if delta.filesystem_id != base.filesystem_id
                || delta.base_revision_id != base.revision_id
                || delta.base_root_directory_id != base.root_directory_id
                || delta.base_root_data_root != base.root_data_root
                || delta.base_checkpoint_sha256 != base.checkpoint_sha256
                || delta.root_directory_id != session.root_directory_id
                || delta.revision_id != expected_revision
                || delta.root_data_root != expected_root
                || delta.checkpoint_sha256 != expected_sha256
                || catalog_checkpoint_etag(expected_sha256)
                    .map_err(|error| Error::InvalidResponse(error.to_string()))?
                    != expected_etag
            {
                return Err(Error::InvalidResponse(
                    "catalog delta identity differs from its base, session, or receipt".to_owned(),
                ));
            }
            return Ok(CatalogCheckpointOutcome::Delta(CatalogDeltaDelivery {
                delta,
                etag: expected_etag.to_owned(),
            }));
        }
        if content_type != "application/json"
            || expected_sha256 != hex::encode(Sha256::digest(&response.body))
        {
            return Err(Error::InvalidResponse(
                "catalog checkpoint transport receipt differs".to_owned(),
            ));
        }
        let checkpoint: CatalogCheckpoint =
            serde_json::from_slice(&response.body).map_err(|error| {
                Error::InvalidResponse(format!("decode catalog checkpoint: {error}"))
            })?;
        if serde_json::to_vec(&checkpoint).map_err(|error| {
            Error::InvalidResponse(format!("encode catalog checkpoint: {error}"))
        })? != response.body
        {
            return Err(Error::InvalidResponse(
                "catalog checkpoint is not canonically encoded".to_owned(),
            ));
        }
        validate_catalog_checkpoint(&checkpoint)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        if checkpoint.root_directory_id != session.root_directory_id
            || checkpoint.revision_id != expected_revision
            || checkpoint.root_data_root != expected_root
        {
            return Err(Error::InvalidResponse(
                "catalog checkpoint identity differs from its session or receipt".to_owned(),
            ));
        }
        Ok(CatalogCheckpointOutcome::Delivered(
            CatalogCheckpointDelivery {
                checkpoint,
                etag: expected_etag.to_owned(),
            },
        ))
    }

    /// Reads one revision-consistent directory page.
    ///
    /// # Errors
    ///
    /// Returns an authorization, revision, protocol, or transport error.
    pub async fn list_directory(
        &self,
        directory_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<DirectoryPage, Error> {
        validate_nonzero_hex_input::<16>(directory_id, "VFS directory identity")?;
        if limit > MAXIMUM_DIRECTORY_PAGE_SIZE {
            return Err(Error::InvalidEndpoint(
                "VFS directory page limit exceeds 1000".to_owned(),
            ));
        }
        let mut query = Vec::new();
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor.to_owned()));
        }
        if limit != 0 {
            query.push(("limit", limit.to_string()));
        }
        let token = self.token.encode();
        let page = self
            .control
            .send_json::<DirectoryPage, ()>(
                Method::GET,
                &format!("api/v2/directories/{directory_id}/entries"),
                Some(&token),
                &query,
                None,
            )
            .await?;
        validate_directory_page(
            &page,
            directory_id,
            if limit == 0 {
                DEFAULT_DIRECTORY_PAGE_SIZE
            } else {
                limit as usize
            },
        )?;
        Ok(page)
    }

    /// Lists every entry in a directory while preserving one revision.
    ///
    /// # Errors
    ///
    /// Returns an error when a page is rejected, malformed, or changes revision.
    pub async fn list_all(&self, directory_id: &str) -> Result<DirectoryPage, Error> {
        let mut page = self.list_directory(directory_id, None, 1_000).await?;
        let expected_directory = page.directory.clone();
        let expected_root =
            validate_nonzero_hex::<32>(&expected_directory.data_root, "VFS directory data root")?;
        let mut accumulator = carrack_sdk_core::DirectoryMerkleAccumulator::new();
        authenticate_directory_entries(&mut accumulator, &page.entries)?;
        let mut cursor = page.next_cursor.take();
        while let Some(next) = cursor {
            let mut continuation = self
                .list_directory(directory_id, Some(&next), 1_000)
                .await?;
            if continuation.directory != expected_directory {
                return Err(Error::InvalidResponse(
                    "directory identity changed across pages".to_owned(),
                ));
            }
            authenticate_directory_entries(&mut accumulator, &continuation.entries)?;
            page.entries.append(&mut continuation.entries);
            cursor = continuation.next_cursor.take();
        }
        let actual_root = accumulator
            .finish()
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
        if actual_root != expected_root {
            return Err(Error::InvalidResponse(
                "paged VFS directory Merkle root differs".to_owned(),
            ));
        }
        Ok(page)
    }

    /// Resolves a canonical absolute path relative to the token root.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, missing entries, or rejected reads.
    pub async fn resolve(&self, path: &str) -> Result<ResolvedEntry, Error> {
        let components = canonical_components(path)?;
        let session = self.session().await?;
        let mut directory_id = session.root_directory_id;
        let mut root_page = self.list_all(&directory_id).await?;
        if components.is_empty() {
            return Ok(ResolvedEntry {
                path: "/".to_owned(),
                parent: root_page.directory,
                entry: None,
            });
        }
        for (index, component) in components.iter().enumerate() {
            let entry = root_page
                .entries
                .iter()
                .find(|entry| entry.name == *component)
                .cloned()
                .ok_or_else(|| Error::Rejected {
                    status: 404,
                    message: format!("VFS path not found: {path}"),
                })?;
            if index + 1 == components.len() {
                return Ok(ResolvedEntry {
                    path: canonical_path(&components),
                    parent: root_page.directory,
                    entry: Some(entry),
                });
            }
            if entry.kind != EntryKind::Directory {
                return Err(Error::Rejected {
                    status: 404,
                    message: format!("VFS path component is not a directory: {component}"),
                });
            }
            directory_id = entry.child_directory_id.ok_or_else(|| {
                Error::InvalidResponse("directory entry omitted child identity".to_owned())
            })?;
            root_page = self.list_all(&directory_id).await?;
        }
        unreachable!("nonempty path returns from the resolution loop")
    }

    /// Lists a canonical absolute directory path relative to the token root.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, missing entries, non-directories, or rejected reads.
    pub async fn list_path(&self, path: &str) -> Result<DirectoryPage, Error> {
        let resolved = self.resolve(path).await?;
        match resolved.entry {
            None => self.list_all(&resolved.parent.id).await,
            Some(entry) if entry.kind == EntryKind::Directory => {
                let child = entry.child_directory_id.ok_or_else(|| {
                    Error::InvalidResponse("directory entry omitted child identity".to_owned())
                })?;
                self.list_all(&child).await
            }
            Some(_) => Err(Error::Rejected {
                status: 400,
                message: format!("VFS path is not a directory: {path}"),
            }),
        }
    }

    /// Creates one directory at a canonical absolute path.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, missing parents, conflicts, or rejected writes.
    pub async fn mkdir(
        &self,
        path: &str,
        idempotency_key: &str,
    ) -> Result<DirectoryCreation, Error> {
        validate_idempotency_key(idempotency_key)?;
        let components = canonical_components(path)?;
        let (name, parent_components) = components
            .split_last()
            .ok_or_else(|| Error::InvalidResponse("cannot create the VFS root".to_owned()))?;
        let parent_path = canonical_path(parent_components);
        let parent = self.resolve(&parent_path).await?;
        let parent_id = match parent.entry {
            Some(entry) if entry.kind == EntryKind::Directory => entry.child_directory_id,
            None => Some(parent.parent.id),
            _ => None,
        }
        .ok_or_else(|| Error::InvalidResponse("mkdir parent is not a directory".to_owned()))?;
        let body = CreateDirectoryRequest {
            name: name.clone(),
            crypto_suite: None,
            idempotency_key: idempotency_key.to_owned(),
        };
        let token = self.token.encode();
        let receipt = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{parent_id}/children"),
                Some(&token),
                &[],
                Some(&body),
            )
            .await?;
        validate_directory_creation(&receipt, &parent_id, name)?;
        Ok(receipt)
    }

    /// Logically removes one file or empty directory by path.
    ///
    /// # Errors
    ///
    /// Returns an error for missing paths, revision races, nonempty directories,
    /// authorization failures, or invalid tombstone receipts.
    pub async fn remove(&self, path: &str, idempotency_key: &str) -> Result<RemoveReceipt, Error> {
        validate_idempotency_key(idempotency_key)?;
        let components = canonical_components(path)?;
        let (name, parent_components) = components
            .split_last()
            .ok_or_else(|| Error::InvalidResponse("cannot remove the VFS root".to_owned()))?;
        let parent_id = self
            .resolve_directory_id(&canonical_path(parent_components))
            .await?;
        if let Some(receipt) = self.lookup_remove_receipt(idempotency_key).await? {
            validate_remove_receipt(&receipt, &parent_id, name, None)?;
            return Ok(receipt);
        }
        let entry = self
            .list_all(&parent_id)
            .await?
            .entries
            .into_iter()
            .find(|entry| entry.name == *name)
            .ok_or_else(|| Error::Rejected {
                status: 404,
                message: format!("VFS path not found: {path}"),
            })?;
        let body = RemoveRequest {
            name: entry.name.clone(),
            expected_entry_revision: entry.revision,
            idempotency_key: idempotency_key.to_owned(),
        };
        let token = self.token.encode();
        let receipt: RemoveReceipt = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{parent_id}/remove"),
                Some(&token),
                &[],
                Some(&body),
            )
            .await?;
        validate_remove_receipt(&receipt, &parent_id, &entry.name, Some(entry.kind))?;
        Ok(receipt)
    }

    /// Atomically renames or moves one entry inside its filesystem.
    ///
    /// File payload bytes are never copied. Directory moves are rejected when
    /// the destination is inside the moved directory.
    ///
    /// # Errors
    ///
    /// Returns an error for missing paths, occupied destinations, cross-filesystem
    /// moves, authorization failures, revision races, or invalid receipts.
    pub async fn rename(
        &self,
        source: &str,
        destination: &str,
        idempotency_key: &str,
    ) -> Result<RenameReceipt, Error> {
        validate_idempotency_key(idempotency_key)?;
        let source_components = canonical_components(source)?;
        let (source_name, source_parent_components) = source_components
            .split_last()
            .ok_or_else(|| Error::InvalidResponse("cannot rename the VFS root".to_owned()))?;
        let source_directory_id = self
            .resolve_directory_id(&canonical_path(source_parent_components))
            .await?;
        let destination_components = canonical_components(destination)?;
        let (destination_name, destination_parent_components) = destination_components
            .split_last()
            .ok_or_else(|| Error::InvalidResponse("cannot replace the VFS root".to_owned()))?;
        let destination_directory_id = self
            .resolve_directory_id(&canonical_path(destination_parent_components))
            .await?;
        if let Some(receipt) = self.lookup_rename_receipt(idempotency_key).await? {
            validate_rename_receipt(
                &receipt,
                &source_directory_id,
                source_name,
                &destination_directory_id,
                destination_name,
                None,
                None,
            )?;
            return Ok(receipt);
        }
        let entry = self
            .list_all(&source_directory_id)
            .await?
            .entries
            .into_iter()
            .find(|entry| entry.name == *source_name)
            .ok_or_else(|| Error::Rejected {
                status: 404,
                message: format!("VFS path not found: {source}"),
            })?;
        let body = RenameRequest {
            source_name: entry.name.clone(),
            expected_source_revision: entry.revision,
            destination_directory_id: destination_directory_id.clone(),
            destination_name: destination_name.clone(),
            idempotency_key: idempotency_key.to_owned(),
        };
        let token = self.token.encode();
        let receipt: RenameReceipt = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{source_directory_id}/rename"),
                Some(&token),
                &[],
                Some(&body),
            )
            .await?;
        validate_rename_receipt(
            &receipt,
            &source_directory_id,
            &entry.name,
            &destination_directory_id,
            destination_name,
            Some(entry.kind),
            Some(entry.revision),
        )?;
        Ok(receipt)
    }

    /// Reads the direct ACL policy for one directory path.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, insufficient authority, or malformed policy.
    pub async fn acl(&self, path: &str) -> Result<AclPolicy, Error> {
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        let policy = self
            .control
            .send_json::<AclPolicy, ()>(
                Method::GET,
                &format!("api/v2/directories/{directory_id}/acl"),
                Some(&token),
                &[],
                None,
            )
            .await?;
        validate_acl_policy(&policy, &directory_id)?;
        Ok(policy)
    }

    /// Atomically replaces one principal's complete direct ACL grant set.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid input, insufficient authority, or a revision conflict.
    pub async fn replace_acl(
        &self,
        path: &str,
        principal_id: &str,
        actions: Vec<String>,
        expected_acl_revision: u64,
        idempotency_key: &str,
    ) -> Result<PolicyMutationReceipt, Error> {
        validate_nonzero_hex_input::<16>(principal_id, "VFS principal identity")?;
        let actions = canonical_actions(actions)?;
        validate_mutation_input(expected_acl_revision, idempotency_key)?;
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        let expected_policy = serde_json::json!({
            "principal_id": principal_id,
            "group_id": null,
            "actions": actions.clone(),
            "source_role": null
        });
        let receipt = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{directory_id}/acl/replace"),
                Some(&token),
                &[],
                Some(&ReplaceAclRequest {
                    principal_id: Some(principal_id),
                    group_id: None,
                    actions,
                    expected_acl_revision,
                    idempotency_key,
                }),
            )
            .await?;
        validate_policy_receipt(
            &receipt,
            "acl.replace",
            &directory_id,
            expected_acl_revision,
            &expected_policy,
        )?;
        Ok(receipt)
    }

    /// Atomically replaces one group's complete direct ACL grant set.
    ///
    /// # Errors
    ///
    /// Returns an error for an unavailable group, insufficient authority, or a revision conflict.
    pub async fn replace_group_acl(
        &self,
        path: &str,
        group_id: &str,
        actions: Vec<String>,
        expected_acl_revision: u64,
        idempotency_key: &str,
    ) -> Result<PolicyMutationReceipt, Error> {
        validate_nonzero_hex_input::<16>(group_id, "VFS group identity")?;
        let actions = canonical_actions(actions)?;
        validate_mutation_input(expected_acl_revision, idempotency_key)?;
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        let expected_policy = serde_json::json!({
            "principal_id": null,
            "group_id": group_id,
            "actions": actions.clone(),
            "source_role": null
        });
        let receipt = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{directory_id}/acl/replace"),
                Some(&token),
                &[],
                Some(&ReplaceAclRequest {
                    principal_id: None,
                    group_id: Some(group_id),
                    actions,
                    expected_acl_revision,
                    idempotency_key,
                }),
            )
            .await?;
        validate_policy_receipt(
            &receipt,
            "acl.replace",
            &directory_id,
            expected_acl_revision,
            &expected_policy,
        )?;
        Ok(receipt)
    }

    /// Reads the ordered driver placement policy for one directory path.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, insufficient authority, or malformed policy.
    pub async fn placements(&self, path: &str) -> Result<PlacementPolicy, Error> {
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        let policy = self
            .control
            .send_json::<PlacementPolicy, ()>(
                Method::GET,
                &format!("api/v2/directories/{directory_id}/placements"),
                Some(&token),
                &[],
                None,
            )
            .await?;
        validate_placement_policy(&policy, &directory_id)?;
        Ok(policy)
    }

    /// Atomically replaces a directory's complete driver placement policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid drivers, insufficient authority, or a revision conflict.
    pub async fn replace_placements(
        &self,
        path: &str,
        mut placements: Vec<Placement>,
        expected_placement_revision: u64,
        idempotency_key: &str,
    ) -> Result<PolicyMutationReceipt, Error> {
        validate_mutation_input(expected_placement_revision, idempotency_key)?;
        canonicalize_placements(&mut placements)?;
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        let expected_policy = serde_json::json!({ "placements": placements.clone() });
        let receipt = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{directory_id}/placements/replace"),
                Some(&token),
                &[],
                Some(&ReplacePlacementsRequest {
                    placements,
                    expected_placement_revision,
                    idempotency_key,
                }),
            )
            .await?;
        validate_policy_receipt(
            &receipt,
            "placement.replace",
            &directory_id,
            expected_placement_revision,
            &expected_policy,
        )?;
        Ok(receipt)
    }

    /// Issues a same-principal child token that can only narrow this token.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested root, actions, drivers, or expiry widen the parent.
    pub async fn issue_token(
        &self,
        root_directory_id: &str,
        actions: Vec<String>,
        driver_ids: Option<Vec<String>>,
        expires_at: u64,
        idempotency_key: &str,
    ) -> Result<IssuedToken, Error> {
        validate_nonzero_hex_input::<16>(root_directory_id, "VFS token root identity")?;
        let actions = canonical_actions(actions)?;
        let driver_ids = canonical_driver_scope(driver_ids)?;
        if expires_at == 0 || expires_at > i64::MAX as u64 {
            return Err(Error::InvalidEndpoint(
                "VFS token expiry must be nonzero".to_owned(),
            ));
        }
        validate_idempotency_key(idempotency_key)?;
        let session = self.session().await?;
        let token = self.token.encode();
        let issued = self
            .control
            .send_json(
                Method::POST,
                "api/v2/tokens",
                Some(&token),
                &[],
                Some(&IssueTokenRequest {
                    root_directory_id,
                    actions: actions.clone(),
                    driver_ids: driver_ids.clone(),
                    expires_at,
                    idempotency_key,
                }),
            )
            .await?;
        let issued_bearer = validate_issued_token(
            &issued,
            &session,
            root_directory_id,
            &actions,
            driver_ids.as_deref(),
            expires_at,
        )?;
        let issued_session = Self {
            control: self.control.clone(),
            token: issued_bearer,
        }
        .session()
        .await?;
        validate_issued_session(&issued_session, &issued)?;
        Ok(issued)
    }

    /// Revokes one same-principal child token idempotently.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target, insufficient authority, or a protocol failure.
    pub async fn revoke_token(
        &self,
        token_id: &str,
        idempotency_key: &str,
    ) -> Result<RevokedToken, Error> {
        validate_nonzero_hex_input::<16>(token_id, "VFS revoked token identity")?;
        validate_idempotency_key(idempotency_key)?;
        let session = self.session().await?;
        let token = self.token.encode();
        let revoked = self
            .control
            .send_json(
                Method::POST,
                &format!("api/v2/tokens/{token_id}/revoke"),
                Some(&token),
                &[],
                Some(&RevokeTokenRequest { idempotency_key }),
            )
            .await?;
        validate_revoked_token(&revoked, &session, token_id)?;
        Ok(revoked)
    }

    async fn resolve_directory_id(&self, path: &str) -> Result<String, Error> {
        let resolved = self.resolve(path).await?;
        match resolved.entry {
            Some(entry) if entry.kind == EntryKind::Directory => entry
                .child_directory_id
                .ok_or_else(|| Error::InvalidResponse("directory omitted its identity".to_owned())),
            None => Ok(resolved.parent.id),
            Some(_) => Err(Error::Rejected {
                status: 400,
                message: format!("VFS path is not a directory: {path}"),
            }),
        }
    }

    async fn lookup_remove_receipt(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<RemoveReceipt>, Error> {
        let token = self.token.encode();
        match self
            .control
            .send_json::<RemoveReceipt, ()>(
                Method::GET,
                "api/v2/remove-receipts",
                Some(&token),
                &[("idempotency_key", idempotency_key.to_owned())],
                None,
            )
            .await
        {
            Ok(receipt) => Ok(Some(receipt)),
            Err(Error::Rejected { status: 404, .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn lookup_rename_receipt(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<RenameReceipt>, Error> {
        let token = self.token.encode();
        match self
            .control
            .send_json::<RenameReceipt, ()>(
                Method::GET,
                "api/v2/rename-receipts",
                Some(&token),
                &[("idempotency_key", idempotency_key.to_owned())],
                None,
            )
            .await
        {
            Ok(receipt) => Ok(Some(receipt)),
            Err(Error::Rejected { status: 404, .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

fn required_header<'a>(
    headers: &'a reqwest::header::HeaderMap,
    name: &'static str,
) -> Result<&'a str, Error> {
    headers
        .get(name)
        .ok_or_else(|| Error::InvalidResponse(format!("catalog checkpoint omitted {name}")))?
        .to_str()
        .map_err(|_| Error::InvalidResponse(format!("catalog checkpoint {name} is invalid")))
}

fn validate_remove_receipt(
    receipt: &RemoveReceipt,
    parent_id: &str,
    name: &str,
    expected_kind: Option<EntryKind>,
) -> Result<(), Error> {
    validate_nonzero_hex::<16>(&receipt.operation_id, "VFS remove operation identity")?;
    validate_nonzero_hex::<16>(&receipt.filesystem_id, "VFS remove filesystem identity")?;
    validate_nonzero_hex::<16>(&receipt.subject_id, "VFS removed subject identity")?;
    if receipt.schema != "carrack.vfs.remove-receipt.v1"
        || receipt.directory_id != parent_id
        || receipt.name != name
        || expected_kind.is_some_and(|kind| receipt.kind != kind)
        || receipt.catalog_revision_id == 0
        || receipt.committed_at == 0
        || receipt.state != "committed"
        || (receipt.kind == EntryKind::File) != receipt.delete_after.is_some()
    {
        return Err(Error::InvalidResponse(
            "invalid remove receipt identity".to_owned(),
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "receipt validation binds both namespace endpoints and optimistic revision"
)]
fn validate_rename_receipt(
    receipt: &RenameReceipt,
    source_directory_id: &str,
    source_name: &str,
    destination_directory_id: &str,
    destination_name: &str,
    expected_kind: Option<EntryKind>,
    previous_revision: Option<u64>,
) -> Result<(), Error> {
    validate_nonzero_hex::<16>(&receipt.operation_id, "VFS rename operation identity")?;
    validate_nonzero_hex::<16>(&receipt.filesystem_id, "VFS rename filesystem identity")?;
    validate_nonzero_hex::<16>(&receipt.subject_id, "VFS renamed subject identity")?;
    if receipt.schema != "carrack.vfs.rename-receipt.v1"
        || receipt.source_directory_id != source_directory_id
        || receipt.source_name != source_name
        || receipt.destination_directory_id != destination_directory_id
        || receipt.destination_name != destination_name
        || expected_kind.is_some_and(|kind| receipt.kind != kind)
        || previous_revision.is_some_and(|revision| receipt.entry_revision <= revision)
        || receipt.entry_revision == 0
        || receipt.catalog_revision_id == 0
        || receipt.committed_at == 0
        || receipt.state != "committed"
    {
        return Err(Error::InvalidResponse(
            "invalid rename receipt identity".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct CreateDirectoryRequest {
    name: String,
    crypto_suite: Option<String>,
    idempotency_key: String,
}

#[derive(Serialize)]
struct RemoveRequest {
    name: String,
    expected_entry_revision: u64,
    idempotency_key: String,
}

#[derive(Serialize)]
struct RenameRequest {
    source_name: String,
    expected_source_revision: u64,
    destination_directory_id: String,
    destination_name: String,
    idempotency_key: String,
}

#[derive(Serialize)]
struct ReplaceAclRequest<'a> {
    principal_id: Option<&'a str>,
    group_id: Option<&'a str>,
    actions: Vec<String>,
    expected_acl_revision: u64,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct ReplacePlacementsRequest<'a> {
    placements: Vec<Placement>,
    expected_placement_revision: u64,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct IssueTokenRequest<'a> {
    root_directory_id: &'a str,
    actions: Vec<String>,
    driver_ids: Option<Vec<String>>,
    expires_at: u64,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct RevokeTokenRequest<'a> {
    idempotency_key: &'a str,
}

fn validate_directory_creation(
    receipt: &DirectoryCreation,
    parent_directory_id: &str,
    name: &str,
) -> Result<(), Error> {
    validate_nonzero_hex::<16>(&receipt.operation_id, "VFS mkdir operation identity")?;
    validate_nonzero_hex::<16>(&receipt.filesystem_id, "VFS mkdir filesystem identity")?;
    validate_nonzero_hex::<16>(&receipt.directory_id, "VFS created directory identity")?;
    let empty_root = carrack_sdk_core::directory_merkle_root(&[])
        .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    if receipt.schema != "carrack.vfs.directory-create-receipt.v1"
        || receipt.parent_directory_id != parent_directory_id
        || receipt.name != name
        || validate_nonzero_hex::<32>(&receipt.data_root, "VFS created directory root")?
            != empty_root
        || !matches!(
            receipt.crypto_suite.as_str(),
            ENCRYPTED_SUITE | PLAINTEXT_SUITE
        )
        || receipt.key_epoch == 0
        || receipt.catalog_revision_id == 0
        || receipt.created_at == 0
        || receipt.state != "committed"
    {
        return Err(Error::InvalidResponse(
            "invalid VFS directory creation receipt".to_owned(),
        ));
    }
    Ok(())
}

fn validate_acl_policy(policy: &AclPolicy, directory_id: &str) -> Result<(), Error> {
    if policy.schema != "carrack.vfs.acl.v1"
        || policy.directory_id != directory_id
        || policy.acl_revision == 0
    {
        return Err(Error::InvalidResponse("invalid VFS ACL policy".to_owned()));
    }
    let mut previous: Option<(String, String)> = None;
    for grant in &policy.grants {
        validate_nonzero_hex::<16>(&grant.id, "VFS ACL grant identity")?;
        let subject = match (grant.principal_id.as_deref(), grant.group_id.as_deref()) {
            (Some(principal_id), None) => {
                validate_nonzero_hex::<16>(principal_id, "VFS ACL principal identity")?;
                principal_id
            }
            (None, Some(group_id)) => {
                validate_nonzero_hex::<16>(group_id, "VFS ACL group identity")?;
                group_id
            }
            _ => {
                return Err(Error::InvalidResponse(
                    "invalid VFS ACL grant subject".to_owned(),
                ));
            }
        };
        if !carrack_sdk_core::VFS_ACTIONS.contains(&grant.action.as_str())
            || grant
                .source_role
                .as_deref()
                .is_some_and(|role| !valid_bounded_string(role, 64))
        {
            return Err(Error::InvalidResponse(
                "invalid VFS ACL grant scope".to_owned(),
            ));
        }
        let identity = (subject.to_owned(), grant.action.clone());
        if previous.as_ref().is_some_and(|value| value >= &identity) {
            return Err(Error::InvalidResponse(
                "VFS ACL grants are not canonically ordered".to_owned(),
            ));
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_placement_policy(policy: &PlacementPolicy, directory_id: &str) -> Result<(), Error> {
    if policy.schema != "carrack.vfs.placements.v1"
        || policy.directory_id != directory_id
        || policy.placement_revision == 0
        || policy.placements.is_empty()
    {
        return Err(Error::InvalidResponse(
            "invalid VFS placement policy".to_owned(),
        ));
    }
    let mut previous: Option<(u64, String)> = None;
    for placement in &policy.placements {
        if !valid_bounded_string(&placement.driver_id, MAXIMUM_DRIVER_ID_BYTES)
            || carrack_driver_contract::DriverKind::parse(&placement.driver_kind).is_none()
            || placement.driver_revision == 0
            || placement.write_priority > i64::MAX as u64
            || placement.state != "active"
        {
            return Err(Error::InvalidResponse(
                "invalid VFS placement identity".to_owned(),
            ));
        }
        let identity = (placement.write_priority, placement.driver_id.clone());
        if previous.as_ref().is_some_and(|value| value >= &identity) {
            return Err(Error::InvalidResponse(
                "VFS placements are not canonically ordered".to_owned(),
            ));
        }
        previous = Some(identity);
    }
    Ok(())
}

fn validate_policy_receipt(
    receipt: &PolicyMutationReceipt,
    kind: &str,
    directory_id: &str,
    previous_revision: u64,
    expected_policy: &serde_json::Value,
) -> Result<(), Error> {
    validate_nonzero_hex::<16>(&receipt.operation_id, "VFS policy operation identity")?;
    if receipt.schema != "carrack.vfs.policy-mutation-receipt.v1"
        || receipt.kind != kind
        || receipt.directory_id != directory_id
        || receipt.final_revision <= previous_revision
        || receipt.policy != *expected_policy
        || receipt.committed_at == 0
        || receipt.state != "committed"
    {
        return Err(Error::InvalidResponse(
            "invalid VFS policy mutation receipt".to_owned(),
        ));
    }
    Ok(())
}

fn validate_issued_token(
    issued: &IssuedToken,
    parent: &VfsSession,
    root_directory_id: &str,
    actions: &[String],
    driver_ids: Option<&[String]>,
    expires_at: u64,
) -> Result<VfsToken, Error> {
    validate_nonzero_hex::<16>(&issued.token_id, "VFS issued token identity")?;
    validate_nonzero_hex::<16>(&issued.principal_id, "VFS issued principal identity")?;
    validate_nonzero_hex::<16>(&issued.parent_token_id, "VFS parent token identity")?;
    validate_nonzero_hex::<16>(&issued.root_directory_id, "VFS issued root identity")?;
    let bearer = VfsToken::parse(&issued.token).map_err(|error| {
        Error::InvalidResponse(format!("VFS issued bearer is invalid: {error}"))
    })?;
    if issued.schema != "carrack.vfs.token-issue-receipt.v1"
        || issued.principal_id != parent.principal_id
        || issued.parent_token_id != parent.token_id
        || issued.root_directory_id != root_directory_id
        || issued.actions != actions
        || issued.driver_ids.as_deref() != driver_ids
        || issued.expires_at != expires_at
    {
        return Err(Error::InvalidResponse(
            "invalid VFS token issue receipt".to_owned(),
        ));
    }
    Ok(bearer)
}

fn validate_issued_session(session: &VfsSession, issued: &IssuedToken) -> Result<(), Error> {
    if session.token_id != issued.token_id
        || session.principal_id != issued.principal_id
        || session.root_directory_id != issued.root_directory_id
        || session.expires_at != issued.expires_at
    {
        return Err(Error::InvalidResponse(
            "issued VFS bearer session differs from its receipt".to_owned(),
        ));
    }
    Ok(())
}

fn validate_revoked_token(
    revoked: &RevokedToken,
    authorizer: &VfsSession,
    token_id: &str,
) -> Result<(), Error> {
    validate_nonzero_hex::<16>(&revoked.principal_id, "VFS revoked principal identity")?;
    validate_nonzero_hex::<16>(&revoked.root_directory_id, "VFS revoked root identity")?;
    if revoked.schema != "carrack.vfs.token-revoke-receipt.v1"
        || revoked.token_id != token_id
        || revoked.principal_id != authorizer.principal_id
        || revoked.revoked_at == 0
        || revoked.state != "revoked"
    {
        return Err(Error::InvalidResponse(
            "invalid VFS token revoke receipt".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_actions(actions: Vec<String>) -> Result<Vec<String>, Error> {
    carrack_sdk_core::canonicalize_vfs_actions(actions)
        .map_err(|error| Error::InvalidEndpoint(error.to_string()))
}

fn canonical_driver_scope(
    mut driver_ids: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, Error> {
    if let Some(values) = &mut driver_ids {
        values.sort();
        values.dedup();
        if values.is_empty()
            || values.len() > 256
            || !values
                .iter()
                .all(|value| valid_bounded_string(value, MAXIMUM_DRIVER_ID_BYTES))
        {
            return Err(Error::InvalidEndpoint(
                "VFS token driver scope is invalid".to_owned(),
            ));
        }
    }
    Ok(driver_ids)
}

fn canonicalize_placements(placements: &mut [Placement]) -> Result<(), Error> {
    placements.sort_by(|left, right| {
        left.write_priority
            .cmp(&right.write_priority)
            .then_with(|| left.driver_id.cmp(&right.driver_id))
    });
    let unique_drivers = placements
        .iter()
        .map(|placement| placement.driver_id.as_str())
        .collect::<BTreeSet<_>>();
    let unique_priorities = placements
        .iter()
        .map(|placement| placement.write_priority)
        .collect::<BTreeSet<_>>();
    if placements.is_empty()
        || placements.len() > 256
        || placements.iter().any(|placement| {
            !valid_bounded_string(&placement.driver_id, MAXIMUM_DRIVER_ID_BYTES)
                || placement.write_priority > i64::MAX as u64
        })
        || unique_drivers.len() != placements.len()
        || unique_priorities.len() != placements.len()
    {
        return Err(Error::InvalidEndpoint(
            "VFS placements are invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_mutation_input(revision: u64, idempotency_key: &str) -> Result<(), Error> {
    if revision == 0 || revision > i64::MAX as u64 {
        return Err(Error::InvalidEndpoint(
            "VFS policy revision must be nonzero".to_owned(),
        ));
    }
    validate_idempotency_key(idempotency_key)
}

fn validate_idempotency_key(idempotency_key: &str) -> Result<(), Error> {
    if !valid_bounded_string(idempotency_key, MAXIMUM_IDEMPOTENCY_BYTES) {
        return Err(Error::InvalidEndpoint(
            "VFS idempotency key is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_nonzero_hex_input<const N: usize>(value: &str, context: &str) -> Result<(), Error> {
    let decoded = carrack_sdk_core::decode_lower_hex::<N>(value)
        .map_err(|error| Error::InvalidEndpoint(format!("{context}: {error}")))?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidEndpoint(format!("{context} is zero")));
    }
    Ok(())
}

fn valid_bounded_string(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= maximum_bytes
}

fn validate_session(session: &VfsSession) -> Result<(), Error> {
    if session.schema != "carrack.vfs.session.v1" || session.expires_at == 0 {
        return Err(Error::InvalidResponse(
            "VFS session identity differs".to_owned(),
        ));
    }
    validate_nonzero_hex::<16>(&session.token_id, "VFS session token identity")?;
    validate_nonzero_hex::<16>(&session.principal_id, "VFS session principal identity")?;
    validate_nonzero_hex::<16>(
        &session.root_directory_id,
        "VFS session root directory identity",
    )?;
    Ok(())
}

fn validate_directory_page(
    page: &DirectoryPage,
    requested_directory_id: &str,
    maximum_entries: usize,
) -> Result<(), Error> {
    if page.schema != "carrack.vfs.directory-list.v1"
        || page.directory.id != requested_directory_id
        || page.entries.len() > maximum_entries
        || (page.next_cursor.is_some() && page.entries.is_empty())
    {
        return Err(Error::InvalidResponse(
            "VFS directory page identity differs".to_owned(),
        ));
    }
    validate_directory(&page.directory)?;
    let mut accumulator = carrack_sdk_core::DirectoryMerkleAccumulator::new();
    authenticate_directory_entries(&mut accumulator, &page.entries)
}

fn validate_directory(directory: &Directory) -> Result<(), Error> {
    validate_nonzero_hex::<16>(&directory.id, "VFS directory identity")?;
    validate_nonzero_hex::<16>(&directory.filesystem_id, "VFS filesystem identity")?;
    if let Some(parent_id) = directory.parent_id.as_deref() {
        validate_nonzero_hex::<16>(parent_id, "VFS parent directory identity")?;
    }
    validate_nonzero_hex::<32>(&directory.data_root, "VFS directory data root")?;
    let root_name = directory.parent_id.is_none() && directory.name.is_empty();
    let child_name = directory.parent_id.is_some() && canonical_entry_name(&directory.name);
    if (!root_name && !child_name)
        || !matches!(
            directory.crypto_suite.as_str(),
            ENCRYPTED_SUITE | PLAINTEXT_SUITE
        )
        || directory.active_key_epoch == 0
        || directory.revision == 0
        || directory.acl_revision == 0
        || directory.placement_revision == 0
    {
        return Err(Error::InvalidResponse(
            "VFS directory identity is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn authenticate_directory_entries(
    accumulator: &mut carrack_sdk_core::DirectoryMerkleAccumulator,
    entries: &[DirectoryEntry],
) -> Result<(), Error> {
    for entry in entries {
        if entry.revision == 0 || entry.updated_at == 0 {
            return Err(Error::InvalidResponse(
                "VFS directory entry revision is invalid".to_owned(),
            ));
        }
        let catalog_entry = CatalogEntry::from(entry);
        accumulator
            .push(&merkle_entry(&catalog_entry)?)
            .map_err(|error| Error::InvalidResponse(error.to_string()))?;
    }
    Ok(())
}

fn validate_nonzero_hex<const N: usize>(value: &str, context: &str) -> Result<[u8; N], Error> {
    let decoded = carrack_sdk_core::decode_lower_hex::<N>(value)
        .map_err(|error| Error::InvalidResponse(format!("{context}: {error}")))?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidResponse(format!("{context} is zero")));
    }
    Ok(decoded)
}

fn canonical_entry_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && !value.contains(['/', '\0'])
        && value.nfc().eq(value.chars())
}

pub(crate) fn canonical_components(path: &str) -> Result<Vec<String>, Error> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(Error::InvalidResponse(
            "VFS path must be absolute".to_owned(),
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if !canonical_entry_name(component) {
            return Err(Error::InvalidResponse(
                "VFS path contains an invalid component".to_owned(),
            ));
        }
        components.push(component.to_owned());
    }
    Ok(components)
}

pub(crate) fn canonical_path(components: &[String]) -> String {
    if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use carrack_sdk_core::{
        CATALOG_CHECKPOINT_SCHEMA, CatalogCheckpoint, CatalogCheckpointDirectory,
        directory_merkle_root,
    };
    use httpmock::{Method::GET, MockServer};

    use super::{
        CatalogCheckpointOutcome, DirectoryCreation, IssuedToken, PolicyMutationReceipt, VfsClient,
        VfsSession, VfsToken, validate_directory_creation, validate_issued_session,
        validate_issued_token, validate_policy_receipt,
    };
    use crate::{Error, catalog::CatalogCheckpointCondition};

    fn client(server: &MockServer) -> VfsClient {
        let token = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        VfsClient::new(
            &format!("{}/", server.base_url()),
            VfsToken::parse(&token).expect("VFS token"),
        )
        .expect("VFS client")
    }

    fn session() -> VfsSession {
        VfsSession {
            schema: "carrack.vfs.session.v1".to_owned(),
            token_id: "303132333435363738393a3b3c3d3e3f".to_owned(),
            principal_id: "404142434445464748494a4b4c4d4e4f".to_owned(),
            root_directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            expires_at: 2_000_000_000,
        }
    }

    fn empty_directory_page(data_root: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": "carrack.vfs.directory-list.v1",
            "directory": {
                "id": "202122232425262728292a2b2c2d2e2f",
                "filesystem_id": "101112131415161718191a1b1c1d1e1f",
                "parent_id": null,
                "name": "",
                "data_root": data_root,
                "crypto_suite": "carrack-vfs-aes256gcm-hkdfsha256-v1",
                "active_key_epoch": 1,
                "acl_inherits": false,
                "revision": 1,
                "acl_revision": 1,
                "placement_revision": 1
            },
            "entries": [],
            "next_cursor": null
        })
    }

    #[tokio::test]
    async fn session_rejects_noncanonical_server_identity() {
        let server = MockServer::start_async().await;
        let delivery = server
            .mock_async(|when, then| {
                when.method(GET).path("/api/v2/session");
                then.status(200).json_body(serde_json::json!({
                    "schema": "carrack.vfs.session.v1",
                    "token_id": "NOT-CANONICAL",
                    "principal_id": "404142434445464748494a4b4c4d4e4f",
                    "root_directory_id": "202122232425262728292a2b2c2d2e2f",
                    "expires_at": 2_000_000_000_u64
                }));
            })
            .await;

        assert!(matches!(
            client(&server).session().await,
            Err(Error::InvalidResponse(message))
                if message.contains("VFS session token identity")
        ));
        delivery.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn list_directory_rejects_malformed_entry_union() {
        let server = MockServer::start_async().await;
        let root = hex::encode(directory_merkle_root(&[]).expect("empty root"));
        let mut body = empty_directory_page(&root);
        body["entries"] = serde_json::json!([{
            "name": "child",
            "kind": "directory",
            "file_id": "303132333435363738393a3b3c3d3e3f",
            "version_id": null,
            "child_directory_id": "404142434445464748494a4b4c4d4e4f",
            "size_bytes": 0,
            "data_root": root,
            "metadata_root": null,
            "revision": 1,
            "updated_at": 1_700_000_000_u64
        }]);
        let delivery = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/api/v2/directories/202122232425262728292a2b2c2d2e2f/entries")
                    .query_param("limit", "1000");
                then.status(200).json_body(body);
            })
            .await;

        assert!(matches!(
            client(&server)
                .list_directory("202122232425262728292a2b2c2d2e2f", None, 1_000)
                .await,
            Err(Error::InvalidResponse(message))
                if message == "catalog directory entry union is invalid"
        ));
        delivery.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn list_all_authenticates_complete_directory_root() {
        let server = MockServer::start_async().await;
        let delivery = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/api/v2/directories/202122232425262728292a2b2c2d2e2f/entries")
                    .query_param("limit", "1000");
                then.status(200).json_body(empty_directory_page(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ));
            })
            .await;

        assert!(matches!(
            client(&server)
                .list_all("202122232425262728292a2b2c2d2e2f")
                .await,
            Err(Error::InvalidResponse(message))
                if message == "paged VFS directory Merkle root differs"
        ));
        delivery.assert_calls_async(1).await;
    }

    #[test]
    fn directory_creation_receipt_binds_empty_root_and_request() {
        let receipt = DirectoryCreation {
            schema: "carrack.vfs.directory-create-receipt.v1".to_owned(),
            operation_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            filesystem_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            parent_directory_id: "303132333435363738393a3b3c3d3e3f".to_owned(),
            directory_id: "404142434445464748494a4b4c4d4e4f".to_owned(),
            name: "docs".to_owned(),
            data_root: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            crypto_suite: "carrack-vfs-aes256gcm-hkdfsha256-v1".to_owned(),
            key_epoch: 1,
            catalog_revision_id: 1,
            created_at: 1_700_000_000,
            state: "committed".to_owned(),
        };

        assert!(matches!(
            validate_directory_creation(
                &receipt,
                "303132333435363738393a3b3c3d3e3f",
                "docs"
            ),
            Err(Error::InvalidResponse(message))
                if message == "invalid VFS directory creation receipt"
        ));
    }

    #[test]
    fn token_issue_receipt_binds_parent_and_requested_scope() {
        let issued = IssuedToken {
            schema: "carrack.vfs.token-issue-receipt.v1".to_owned(),
            token_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            principal_id: session().principal_id.clone(),
            parent_token_id: session().token_id.clone(),
            root_directory_id: session().root_directory_id.clone(),
            actions: vec!["content.read".to_owned()],
            driver_ids: None,
            expires_at: 2_000_000_000,
            token: URL_SAFE_NO_PAD.encode([9_u8; 32]),
        };

        assert!(matches!(
            validate_issued_token(
                &issued,
                &session(),
                &issued.root_directory_id,
                &["directory.list".to_owned()],
                None,
                issued.expires_at
            ),
            Err(Error::InvalidResponse(message))
                if message == "invalid VFS token issue receipt"
        ));
    }

    #[test]
    fn issued_bearer_session_must_match_the_receipt() {
        let issued = IssuedToken {
            schema: "carrack.vfs.token-issue-receipt.v1".to_owned(),
            token_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            principal_id: session().principal_id.clone(),
            parent_token_id: session().token_id.clone(),
            root_directory_id: session().root_directory_id.clone(),
            actions: vec!["content.read".to_owned()],
            driver_ids: None,
            expires_at: 2_000_000_000,
            token: URL_SAFE_NO_PAD.encode([9_u8; 32]),
        };
        let mut authenticated = session();
        authenticated.token_id = "303132333435363738393a3b3c3d3e3f".to_owned();

        assert!(matches!(
            validate_issued_session(&authenticated, &issued),
            Err(Error::InvalidResponse(message))
                if message == "issued VFS bearer session differs from its receipt"
        ));
    }

    #[test]
    fn policy_receipt_binds_exact_normalized_payload() {
        let receipt = PolicyMutationReceipt {
            schema: "carrack.vfs.policy-mutation-receipt.v1".to_owned(),
            operation_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            kind: "acl.replace".to_owned(),
            directory_id: "202122232425262728292a2b2c2d2e2f".to_owned(),
            final_revision: 3,
            policy: serde_json::json!({ "actions": ["content.read"] }),
            committed_at: 1_700_000_000,
            state: "committed".to_owned(),
        };

        assert!(matches!(
            validate_policy_receipt(
                &receipt,
                "acl.replace",
                &receipt.directory_id,
                2,
                &serde_json::json!({ "actions": ["directory.list"] })
            ),
            Err(Error::InvalidResponse(message))
                if message == "invalid VFS policy mutation receipt"
        ));
    }

    #[tokio::test]
    async fn checkpoint_absence_is_optional() {
        let server = MockServer::start_async().await;
        let delivery = server
            .mock_async(|when, then| {
                when.method(GET).path("/api/v2/catalog/checkpoint");
                then.status(204);
            })
            .await;
        assert!(matches!(
            client(&server)
                .catalog_checkpoint(&session(), None)
                .await
                .expect("optional checkpoint request"),
            CatalogCheckpointOutcome::Unavailable
        ));
        delivery.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn matching_checkpoint_condition_accepts_only_exact_304() {
        let server = MockServer::start_async().await;
        let etag = "\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";
        let condition = CatalogCheckpointCondition {
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            root_directory_id: session().root_directory_id,
            root_data_root: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
            checkpoint_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            etag: etag.to_owned(),
        };
        let delivery = server
            .mock_async(|when, then| {
                when.method(GET)
                    .path("/api/v2/catalog/checkpoint")
                    .header("If-None-Match", etag);
                then.status(304).header("ETag", etag);
            })
            .await;
        assert!(matches!(
            client(&server)
                .catalog_checkpoint(&session(), Some(&condition))
                .await
                .expect("unchanged checkpoint"),
            CatalogCheckpointOutcome::Unchanged
        ));
        delivery.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn checkpoint_checksum_mismatch_fails_closed() {
        let server = MockServer::start_async().await;
        let session = session();
        let root = hex::encode(directory_merkle_root(&[]).expect("empty root"));
        let body = serde_json::to_vec(&CatalogCheckpoint {
            schema: CATALOG_CHECKPOINT_SCHEMA.to_owned(),
            filesystem_id: "101112131415161718191a1b1c1d1e1f".to_owned(),
            revision_id: 1,
            parent_revision_id: None,
            root_directory_id: session.root_directory_id.clone(),
            root_data_root: root.clone(),
            created_at: 1_700_000_000,
            directories: vec![CatalogCheckpointDirectory {
                directory_id: session.root_directory_id.clone(),
                parent_directory_id: None,
                name: String::new(),
                data_root: root.clone(),
                entries: Vec::new(),
            }],
        })
        .expect("encode checkpoint");
        let delivery = server
            .mock_async(|when, then| {
                when.method(GET).path("/api/v2/catalog/checkpoint");
                then.status(200)
                    .header("Content-Type", "application/json")
                    .header("Content-Length", body.len().to_string())
                    .header(
                        "ETag",
                        "\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
                    )
                    .header(
                        "Carrack-Catalog-SHA256",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .header("Carrack-Catalog-Revision", "1")
                    .header("Carrack-Catalog-Root", root)
                    .body(body);
            })
            .await;
        assert!(matches!(
            client(&server).catalog_checkpoint(&session, None).await,
            Err(Error::InvalidResponse(message))
                if message == "catalog checkpoint transport receipt differs"
        ));
        delivery.assert_calls_async(1).await;
    }
}
