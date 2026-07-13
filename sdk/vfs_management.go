package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strconv"
)

const (
	vfsDirectoryListSchema   = "carrack.vfs.directory-list.v1"
	vfsDirectoryCreateSchema = "carrack.vfs.directory-create-receipt.v1"
	vfsTokenIssueSchema      = "carrack.vfs.token-issue-receipt.v1"  // #nosec G101 -- protocol schema, not a credential.
	vfsTokenRevokeSchema     = "carrack.vfs.token-revoke-receipt.v1" // #nosec G101 -- protocol schema, not a credential.
	maximumVFSListLimit      = uint32(1_000)
	vfsActionCount           = 12
	vfsEntryKindFile         = "file"
	vfsEntryKindDirectory    = "directory"
)

// VFSAction is one exact, non-implying VFS authorization action.
type VFSAction string

// Fixed VFS authorization actions. Administrative actions do not imply
// content access, and every operation checks its exact action.
const (
	VFSActionDirectoryList   VFSAction = "directory.list"
	VFSActionContentRead     VFSAction = "content.read"
	VFSActionContentWrite    VFSAction = "content.write"
	VFSActionEntryDelete     VFSAction = "entry.delete"
	VFSActionSnapshotPublish VFSAction = "snapshot.publish"
	VFSActionACLManage       VFSAction = "acl.manage"
	VFSActionTokenIssue      VFSAction = "token.issue"
	VFSActionDriverUse       VFSAction = "driver.use"
	VFSActionDriverManage    VFSAction = "driver.manage"
	VFSActionGCRun           VFSAction = "gc.run"
	VFSActionAuditRead       VFSAction = "audit.read"
	VFSActionSystemManage    VFSAction = "system.manage"
)

// VFSDirectory describes one live directory identity and the revisions that
// pin namespace and ACL observations.
type VFSDirectory struct {
	ID                string  `json:"id"`
	FilesystemID      string  `json:"filesystem_id"`
	ParentID          *string `json:"parent_id"`
	Name              string  `json:"name"`
	DataRoot          string  `json:"data_root"`
	CryptoSuite       string  `json:"crypto_suite"`
	ActiveKeyEpoch    uint64  `json:"active_key_epoch"`
	ACLInherits       bool    `json:"acl_inherits"`
	Revision          uint64  `json:"revision"`
	ACLRevision       uint64  `json:"acl_revision"`
	PlacementRevision uint64  `json:"placement_revision"`
}

// VFSDirectoryEntry pins either one immutable file version or one child
// directory root at a specific entry revision.
type VFSDirectoryEntry struct {
	Name             string  `json:"name"`
	Kind             string  `json:"kind"`
	FileID           *string `json:"file_id"`
	VersionID        *string `json:"version_id"`
	ChildDirectoryID *string `json:"child_directory_id"`
	SizeBytes        uint64  `json:"size_bytes"`
	DataRoot         string  `json:"data_root"`
	MetadataRoot     *string `json:"metadata_root"`
	Revision         uint64  `json:"revision"`
	UpdatedAt        uint64  `json:"updated_at"`
}

// VFSDirectoryPage is one bounded, directory-revision-consistent page. Pass
// NextCursor unchanged to ListDirectory; a concurrent mutation returns a
// conflict rather than an ambiguous continuation.
type VFSDirectoryPage struct {
	Schema     string              `json:"schema"`
	Directory  VFSDirectory        `json:"directory"`
	Entries    []VFSDirectoryEntry `json:"entries"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

// VFSCreateDirectoryRequest creates one empty child collection. Empty
// CryptoSuite inherits the parent suite; either choice still creates a fresh
// independent directory secret when encryption is active.
type VFSCreateDirectoryRequest struct {
	Name           string `json:"name"`
	CryptoSuite    string `json:"crypto_suite,omitempty"`
	IdempotencyKey string `json:"idempotency_key"`
}

// VFSDirectoryCreation is the durable namespace and catalog publication for
// one Merkle-linked child directory.
type VFSDirectoryCreation struct {
	Schema            string `json:"schema"`
	OperationID       string `json:"operation_id"`
	FilesystemID      string `json:"filesystem_id"`
	ParentDirectoryID string `json:"parent_directory_id"`
	DirectoryID       string `json:"directory_id"`
	Name              string `json:"name"`
	DataRoot          string `json:"data_root"`
	CryptoSuite       string `json:"crypto_suite"`
	KeyEpoch          uint64 `json:"key_epoch"`
	CatalogRevisionID uint64 `json:"catalog_revision_id"`
	CreatedAt         uint64 `json:"created_at"`
	State             string `json:"state"`
}

// VFSIssueTokenRequest requests a same-principal attenuated child token.
// Nil DriverIDs inherit an unrestricted parent driver scope; a non-empty slice
// narrows it. An empty non-nil slice is invalid.
type VFSIssueTokenRequest struct {
	RootDirectoryID string      `json:"root_directory_id"`
	Actions         []VFSAction `json:"actions"`
	DriverIDs       []string    `json:"driver_ids"`
	ExpiresAt       uint64      `json:"expires_at"`
	IdempotencyKey  string      `json:"idempotency_key"`
}

type vfsIssueTokenWireRequest struct {
	RootDirectoryID string   `json:"root_directory_id"`
	Actions         []string `json:"actions"`
	DriverIDs       []string `json:"driver_ids"`
	ExpiresAt       uint64   `json:"expires_at"`
	IdempotencyKey  string   `json:"idempotency_key"`
}

type vfsIssueTokenWireResponse struct {
	Schema          string   `json:"schema"`
	TokenID         string   `json:"token_id"`
	PrincipalID     string   `json:"principal_id"`
	ParentTokenID   string   `json:"parent_token_id"`
	RootDirectoryID string   `json:"root_directory_id"`
	Actions         []string `json:"actions"`
	DriverIDs       []string `json:"driver_ids"`
	ExpiresAt       uint64   `json:"expires_at"`
	Token           string   `json:"token"`
}

// VFSIssuedToken contains one durable token identity plus its one recoverable
// bearer. Call Clear after copying it into the intended secret store.
type VFSIssuedToken struct {
	Schema          string      `json:"schema"`
	TokenID         string      `json:"token_id"`
	PrincipalID     string      `json:"principal_id"`
	ParentTokenID   string      `json:"parent_token_id"`
	RootDirectoryID string      `json:"root_directory_id"`
	Actions         []VFSAction `json:"actions"`
	DriverIDs       []string    `json:"driver_ids,omitempty"`
	ExpiresAt       uint64      `json:"expires_at"`
	Bearer          VFSToken    `json:"-"`
}

// Clear overwrites this issued bearer and releases copied scope slices.
func (issued *VFSIssuedToken) Clear() {
	if issued == nil {
		return
	}

	issued.Bearer.Clear()
	clear(issued.Actions)
	clear(issued.DriverIDs)
	issued.Actions = nil
	issued.DriverIDs = nil
}

// VFSTokenRevocation is the durable result of monotonic token revocation.
type VFSTokenRevocation struct {
	Schema          string `json:"schema"`
	TokenID         string `json:"token_id"`
	PrincipalID     string `json:"principal_id"`
	RootDirectoryID string `json:"root_directory_id"`
	RevokedAt       uint64 `json:"revoked_at"`
	State           string `json:"state"`
}

// ListDirectory reads one bounded page of live VFS namespace metadata. Limit
// zero selects the server default; accepted explicit limits are 1 through
// 1,000. Snapshot-scoped tokens require a future snapshot-read endpoint and
// are rejected here rather than being served live metadata.
func (client *VFSControlClient) ListDirectory(
	ctx context.Context,
	directoryID, cursor string,
	limit uint32,
) (VFSDirectoryPage, error) {
	if client == nil || client.control == nil || !validIdentifier(directoryID) ||
		limit > maximumVFSListLimit || cursor != "" && !validControlString(cursor, 1_024) {
		return VFSDirectoryPage{}, fmt.Errorf("%w: invalid VFS directory list", ErrInvalidControlPlane)
	}

	query := make(url.Values, 2)
	if cursor != "" {
		query.Set("cursor", cursor)
	}

	if limit != 0 {
		query.Set("limit", strconv.FormatUint(uint64(limit), 10))
	}

	var page VFSDirectoryPage

	path := "/api/v2/directories/" + directoryID + "/entries"
	if err := client.control.authenticatedGet(ctx, path, query, &page); err != nil {
		return VFSDirectoryPage{}, err
	}

	if !validVFSDirectoryPage(page, directoryID, limit) {
		return VFSDirectoryPage{}, fmt.Errorf("%w: invalid VFS directory page", ErrControlPlaneResponse)
	}

	return page, nil
}

// CreateDirectory atomically adds one child entry, creates its independent key
// epoch, inherits active placements, and republishes the parent-to-root Merkle
// path. Concurrent creation of the same name returns a conflict.
func (client *VFSControlClient) CreateDirectory(
	ctx context.Context,
	parentDirectoryID string,
	requested VFSCreateDirectoryRequest,
) (VFSDirectoryCreation, error) {
	if client == nil || client.control == nil ||
		!validVFSCreateDirectoryRequest(parentDirectoryID, requested) {
		return VFSDirectoryCreation{}, fmt.Errorf("%w: invalid VFS directory creation", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return VFSDirectoryCreation{}, fmt.Errorf("marshal VFS directory creation: %w", err)
	}

	var response VFSDirectoryCreation

	path := "/api/v2/directories/" + parentDirectoryID + "/children"
	if postErr := client.postJSON(ctx, path, body, &response); postErr != nil {
		return VFSDirectoryCreation{}, postErr
	}

	if !validVFSDirectoryCreation(response, parentDirectoryID, requested) {
		return VFSDirectoryCreation{}, fmt.Errorf("%w: invalid VFS directory-create receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

func validVFSCreateDirectoryRequest(
	parentDirectoryID string,
	request VFSCreateDirectoryRequest,
) bool {
	return validIdentifier(parentDirectoryID) && validVFSName(request.Name) &&
		validControlString(request.IdempotencyKey, 256) &&
		(request.CryptoSuite == "" || request.CryptoSuite == VFSEncryptedSuite ||
			request.CryptoSuite == VFSPlaintextSuite)
}

func validVFSDirectoryCreation(
	response VFSDirectoryCreation,
	parentDirectoryID string,
	request VFSCreateDirectoryRequest,
) bool {
	return response.Schema == vfsDirectoryCreateSchema && validIdentifier(response.OperationID) &&
		validIdentifier(response.FilesystemID) && response.ParentDirectoryID == parentDirectoryID &&
		validIdentifier(response.DirectoryID) && response.Name == request.Name &&
		validDigest(response.DataRoot) && response.KeyEpoch > 0 && response.CatalogRevisionID > 0 &&
		response.CreatedAt > 0 && response.State == vfsCommittedState &&
		(response.CryptoSuite == VFSEncryptedSuite || response.CryptoSuite == VFSPlaintextSuite) &&
		(request.CryptoSuite == "" || response.CryptoSuite == request.CryptoSuite)
}

// IssueToken creates or exactly replays one attenuated child-token request.
// D1 stores only the verifier; an exact idempotent retry recovers the same
// bearer from the control-plane master key.
func (client *VFSControlClient) IssueToken(
	ctx context.Context,
	requested VFSIssueTokenRequest,
) (VFSIssuedToken, error) {
	wireRequest, err := canonicalVFSIssueTokenRequest(requested)
	if err != nil {
		return VFSIssuedToken{}, err
	}

	body, err := json.Marshal(wireRequest)
	if err != nil {
		return VFSIssuedToken{}, fmt.Errorf("marshal VFS token issue: %w", err)
	}

	var response vfsIssueTokenWireResponse
	if postErr := client.postJSON(ctx, "/api/v2/tokens", body, &response); postErr != nil {
		return VFSIssuedToken{}, postErr
	}

	issued, err := validateIssuedVFSToken(response, wireRequest)
	if err != nil {
		return VFSIssuedToken{}, err
	}

	if slices.Equal(issued.Bearer[:], client.control.token[:]) {
		issued.Clear()

		return VFSIssuedToken{}, fmt.Errorf("%w: child bearer equals its parent", ErrControlPlaneResponse)
	}

	return issued, nil
}

// RevokeToken atomically and monotonically revokes one same-principal token.
// The current bearer cannot revoke itself; use a separate security token.
func (client *VFSControlClient) RevokeToken(
	ctx context.Context,
	tokenID, idempotencyKey string,
) (VFSTokenRevocation, error) {
	if !validIdentifier(tokenID) || !validControlString(idempotencyKey, 256) {
		return VFSTokenRevocation{}, fmt.Errorf("%w: invalid VFS token revocation", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(map[string]string{"idempotency_key": idempotencyKey})
	if err != nil {
		return VFSTokenRevocation{}, fmt.Errorf("marshal VFS token revocation: %w", err)
	}

	var response VFSTokenRevocation

	path := "/api/v2/tokens/" + tokenID + "/revoke"
	if err := client.postJSON(ctx, path, body, &response); err != nil {
		return VFSTokenRevocation{}, err
	}

	if response.Schema != vfsTokenRevokeSchema || response.TokenID != tokenID ||
		!validIdentifier(response.PrincipalID) || !validIdentifier(response.RootDirectoryID) ||
		response.RevokedAt == 0 || response.State != "revoked" {
		return VFSTokenRevocation{}, fmt.Errorf("%w: invalid VFS token revocation receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

func canonicalVFSIssueTokenRequest(
	requested VFSIssueTokenRequest,
) (vfsIssueTokenWireRequest, error) {
	if !validIdentifier(requested.RootDirectoryID) || requested.ExpiresAt == 0 ||
		requested.ExpiresAt > math.MaxInt64 || !validControlString(requested.IdempotencyKey, 256) ||
		len(requested.Actions) == 0 || len(requested.Actions) > vfsActionCount ||
		requested.DriverIDs != nil && len(requested.DriverIDs) == 0 || len(requested.DriverIDs) > 256 {
		return vfsIssueTokenWireRequest{}, fmt.Errorf("%w: invalid VFS token issue", ErrInvalidControlPlane)
	}

	actionSet := make(map[string]struct{}, len(requested.Actions))
	for _, action := range requested.Actions {
		if !validVFSAction(action) {
			return vfsIssueTokenWireRequest{}, fmt.Errorf("%w: unknown VFS action %q", ErrInvalidControlPlane, action)
		}

		actionSet[string(action)] = struct{}{}
	}

	actions := make([]string, 0, len(actionSet))
	for action := range actionSet {
		actions = append(actions, action)
	}

	slices.Sort(actions)

	var driverIDs []string

	if requested.DriverIDs != nil {
		driverSet := make(map[string]struct{}, len(requested.DriverIDs))
		for _, driverID := range requested.DriverIDs {
			if !validControlString(driverID, 256) {
				return vfsIssueTokenWireRequest{}, fmt.Errorf("%w: invalid VFS driver scope", ErrInvalidControlPlane)
			}

			driverSet[driverID] = struct{}{}
		}

		driverIDs = make([]string, 0, len(driverSet))
		for driverID := range driverSet {
			driverIDs = append(driverIDs, driverID)
		}

		slices.Sort(driverIDs)
	}

	return vfsIssueTokenWireRequest{
		RootDirectoryID: requested.RootDirectoryID,
		Actions:         actions,
		DriverIDs:       driverIDs,
		ExpiresAt:       requested.ExpiresAt,
		IdempotencyKey:  requested.IdempotencyKey,
	}, nil
}

func validateIssuedVFSToken(
	response vfsIssueTokenWireResponse,
	requested vfsIssueTokenWireRequest,
) (VFSIssuedToken, error) {
	if response.Schema != vfsTokenIssueSchema || !validIdentifier(response.TokenID) ||
		!validIdentifier(response.PrincipalID) || !validIdentifier(response.ParentTokenID) ||
		response.RootDirectoryID != requested.RootDirectoryID || response.ExpiresAt != requested.ExpiresAt ||
		!slices.Equal(response.Actions, requested.Actions) || !slices.Equal(response.DriverIDs, requested.DriverIDs) {
		return VFSIssuedToken{}, fmt.Errorf("%w: VFS child-token identity changed", ErrControlPlaneResponse)
	}

	bearer, err := ParseVFSToken(response.Token)
	if err != nil {
		return VFSIssuedToken{}, fmt.Errorf("%w: invalid VFS child bearer", ErrControlPlaneResponse)
	}

	actions := make([]VFSAction, len(response.Actions))
	for index, action := range response.Actions {
		actions[index] = VFSAction(action)
	}

	return VFSIssuedToken{
		Schema:          response.Schema,
		TokenID:         response.TokenID,
		PrincipalID:     response.PrincipalID,
		ParentTokenID:   response.ParentTokenID,
		RootDirectoryID: response.RootDirectoryID,
		Actions:         actions,
		DriverIDs:       slices.Clone(response.DriverIDs),
		ExpiresAt:       response.ExpiresAt,
		Bearer:          bearer,
	}, nil
}

func validVFSDirectoryPage(page VFSDirectoryPage, expectedDirectoryID string, limit uint32) bool {
	directory := page.Directory
	if page.Schema != vfsDirectoryListSchema || !validVFSDirectoryIdentity(directory, expectedDirectoryID) ||
		page.NextCursor != "" && !validControlString(page.NextCursor, 1_024) ||
		limit != 0 && len(page.Entries) > int(limit) || len(page.Entries) > int(maximumVFSListLimit) {
		return false
	}

	for index, entry := range page.Entries {
		if !validVFSDirectoryEntry(entry) || index > 0 && page.Entries[index-1].Name >= entry.Name {
			return false
		}
	}

	return true
}

func validVFSDirectoryIdentity(directory VFSDirectory, expectedDirectoryID string) bool {
	if directory.ID != expectedDirectoryID || !validIdentifier(directory.FilesystemID) ||
		!validDigest(directory.DataRoot) || !validControlString(directory.CryptoSuite, 128) ||
		directory.ActiveKeyEpoch == 0 || directory.Revision == 0 || directory.ACLRevision == 0 ||
		directory.PlacementRevision == 0 {
		return false
	}

	if directory.ParentID == nil {
		return directory.Name == "" && !directory.ACLInherits
	}

	return validIdentifier(*directory.ParentID) && validVFSName(directory.Name)
}

func validVFSAction(action VFSAction) bool {
	switch action {
	case VFSActionDirectoryList,
		VFSActionContentRead,
		VFSActionContentWrite,
		VFSActionEntryDelete,
		VFSActionSnapshotPublish,
		VFSActionACLManage,
		VFSActionTokenIssue,
		VFSActionDriverUse,
		VFSActionDriverManage,
		VFSActionGCRun,
		VFSActionAuditRead,
		VFSActionSystemManage:
		return true
	default:
		return false
	}
}

func validVFSDirectoryEntry(entry VFSDirectoryEntry) bool {
	if !validVFSName(entry.Name) || !validDigest(entry.DataRoot) ||
		entry.Revision == 0 || entry.UpdatedAt == 0 {
		return false
	}

	switch entry.Kind {
	case vfsEntryKindFile:
		return entry.FileID != nil && validIdentifier(*entry.FileID) &&
			entry.VersionID != nil && validIdentifier(*entry.VersionID) &&
			entry.ChildDirectoryID == nil && entry.MetadataRoot != nil && validDigest(*entry.MetadataRoot)
	case vfsEntryKindDirectory:
		return entry.FileID == nil && entry.VersionID == nil && entry.ChildDirectoryID != nil &&
			validIdentifier(*entry.ChildDirectoryID) && entry.SizeBytes == 0 && entry.MetadataRoot == nil
	default:
		return false
	}
}
