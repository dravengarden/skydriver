//! Filesystem-oriented VFS metadata client.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use carrack_sdk_core::{
    CatalogCheckpoint, CatalogDelta, MAXIMUM_CATALOG_CHECKPOINT_BYTES, MAXIMUM_CATALOG_DELTA_BYTES,
    catalog_checkpoint_etag, validate_catalog_checkpoint, validate_catalog_checkpoint_etag,
    validate_catalog_delta,
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Client, Error, OptionalBytesResponse, catalog::CatalogCheckpointCondition};

const TOKEN_BYTES: usize = 32;

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
}

/// Non-secret VFS session identity used for path resolution.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
        self.control
            .send_json::<VfsSession, ()>(Method::GET, "api/v2/session", Some(&token), &[], None)
            .await
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
        let mut query = Vec::new();
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor.to_owned()));
        }
        if limit != 0 {
            query.push(("limit", limit.to_string()));
        }
        let token = self.token.encode();
        self.control
            .send_json::<DirectoryPage, ()>(
                Method::GET,
                &format!("api/v2/directories/{directory_id}/entries"),
                Some(&token),
                &query,
                None,
            )
            .await
    }

    /// Lists every entry in a directory while preserving one revision.
    ///
    /// # Errors
    ///
    /// Returns an error when a page is rejected, malformed, or changes revision.
    pub async fn list_all(&self, directory_id: &str) -> Result<DirectoryPage, Error> {
        let mut page = self.list_directory(directory_id, None, 1_000).await?;
        let mut cursor = page.next_cursor.take();
        while let Some(next) = cursor {
            let mut continuation = self
                .list_directory(directory_id, Some(&next), 1_000)
                .await?;
            if continuation.directory.revision != page.directory.revision {
                return Err(Error::InvalidResponse(
                    "directory revision changed across pages".to_owned(),
                ));
            }
            page.entries.append(&mut continuation.entries);
            cursor = continuation.next_cursor.take();
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
        self.control
            .send_json(
                Method::POST,
                &format!("api/v2/directories/{parent_id}/children"),
                Some(&token),
                &[],
                Some(&body),
            )
            .await
    }

    /// Logically removes one file or empty directory by path.
    ///
    /// # Errors
    ///
    /// Returns an error for missing paths, revision races, nonempty directories,
    /// authorization failures, or invalid tombstone receipts.
    pub async fn remove(&self, path: &str, idempotency_key: &str) -> Result<RemoveReceipt, Error> {
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
        self.control
            .send_json::<AclPolicy, ()>(
                Method::GET,
                &format!("api/v2/directories/{directory_id}/acl"),
                Some(&token),
                &[],
                None,
            )
            .await
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
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        self.control
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
            .await
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
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        self.control
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
            .await
    }

    /// Reads the ordered driver placement policy for one directory path.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path, insufficient authority, or malformed policy.
    pub async fn placements(&self, path: &str) -> Result<PlacementPolicy, Error> {
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        self.control
            .send_json::<PlacementPolicy, ()>(
                Method::GET,
                &format!("api/v2/directories/{directory_id}/placements"),
                Some(&token),
                &[],
                None,
            )
            .await
    }

    /// Atomically replaces a directory's complete driver placement policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid drivers, insufficient authority, or a revision conflict.
    pub async fn replace_placements(
        &self,
        path: &str,
        placements: Vec<Placement>,
        expected_placement_revision: u64,
        idempotency_key: &str,
    ) -> Result<PolicyMutationReceipt, Error> {
        let directory_id = self.resolve_directory_id(path).await?;
        let token = self.token.encode();
        self.control
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
            .await
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
        let token = self.token.encode();
        self.control
            .send_json(
                Method::POST,
                "api/v2/tokens",
                Some(&token),
                &[],
                Some(&IssueTokenRequest {
                    root_directory_id,
                    actions,
                    driver_ids,
                    expires_at,
                    idempotency_key,
                }),
            )
            .await
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
        let token = self.token.encode();
        self.control
            .send_json(
                Method::POST,
                &format!("api/v2/tokens/{token_id}/revoke"),
                Some(&token),
                &[],
                Some(&RevokeTokenRequest { idempotency_key }),
            )
            .await
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

pub(crate) fn canonical_components(path: &str) -> Result<Vec<String>, Error> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(Error::InvalidResponse(
            "VFS path must be absolute".to_owned(),
        ));
    }
    let mut components = Vec::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        if component == "." || component == ".." || component.len() > 255 {
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

    use super::{CatalogCheckpointOutcome, VfsClient, VfsSession, VfsToken};
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
        delivery.assert_hits_async(1).await;
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
        delivery.assert_hits_async(1).await;
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
        delivery.assert_hits_async(1).await;
    }
}
