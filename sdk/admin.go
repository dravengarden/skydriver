package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
)

const (
	operatorCredentialBytes            = 32
	managementSnapshotSchema           = "carrack.management.snapshot.v2"
	managementDirectorySchema          = "carrack.management.directory.v1"
	tokenAnnotationValidationSchema    = "carrack.management.token-annotation-validation.v1"
	tokenAnnotationReceiptSchema       = "carrack.management.token-annotation-receipt.v1"
	driverStateValidationSchema        = "carrack.management.driver-state-validation.v1"
	driverStateReceiptSchema           = "carrack.management.driver-state-receipt.v1"
	driverRegistrationValidationSchema = "carrack.management.driver-registration-validation.v1"
	driverRegistrationReceiptSchema    = "carrack.management.driver-registration-receipt.v1"
	driverCredentialValidationSchema   = "carrack.management.driver-credential-validation.v1"
	driverCredentialReceiptSchema      = "carrack.management.driver-credential-receipt.v1"
)

// OperatorCredential is the environment-scoped break-glass management
// credential. It authenticates short-lived management sessions and does not
// grant VFS content access.
type OperatorCredential [operatorCredentialBytes]byte

// ParseOperatorCredential decodes one canonical unpadded base64url credential.
func ParseOperatorCredential(encoded string) (OperatorCredential, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != operatorCredentialBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return OperatorCredential{}, fmt.Errorf(
			"%w: operator credential must canonically encode exactly 32 bytes",
			ErrInvalidControlPlane,
		)
	}

	var credential OperatorCredential
	copy(credential[:], decoded)

	return credential, nil
}

// Clear overwrites this credential instance.
func (credential *OperatorCredential) Clear() {
	if credential != nil {
		clear(credential[:])
	}
}

// ManagementDriver is one redacted driver read model.
type ManagementDriver struct {
	ID                               string          `json:"id"`
	Kind                             string          `json:"kind"`
	Config                           json.RawMessage `json:"config"`
	Enabled                          bool            `json:"enabled"`
	Revision                         uint64          `json:"revision"`
	CredentialPresent                bool            `json:"credential_present"`
	CredentialRotatedAt              *uint64         `json:"credential_rotated_at"`
	CredentialExpiresAt              *uint64         `json:"credential_expires_at"`
	CredentialRefreshState           *string         `json:"credential_refresh_state"`
	CredentialRefreshAfter           *uint64         `json:"credential_refresh_after"`
	CredentialRefreshLastSucceededAt *uint64         `json:"credential_refresh_last_succeeded_at"`
	CredentialRefreshLastErrorCode   *string         `json:"credential_refresh_last_error_code"`
	PlacementCount                   uint64          `json:"placement_count"`
	LocationCount                    uint64          `json:"location_count"`
	AvailableLocationCount           uint64          `json:"available_location_count"`
	EncodedBytes                     uint64          `json:"encoded_bytes"`
	FileCount                        uint64          `json:"file_count"`
	UpdatedAt                        uint64          `json:"updated_at"`
}

// ManagementFilesystem is one filesystem and recursive storage summary.
type ManagementFilesystem struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	State                  string `json:"state"`
	Revision               uint64 `json:"revision"`
	RootDirectoryID        string `json:"root_directory_id"`
	DirectoryCount         uint64 `json:"directory_count"`
	FileCount              uint64 `json:"file_count"`
	LogicalBytes           uint64 `json:"logical_bytes"`
	AvailableLocationCount uint64 `json:"available_location_count"`
	EncodedBytes           uint64 `json:"encoded_bytes"`
	UpdatedAt              uint64 `json:"updated_at"`
}

// ManagementToken is non-secret token authority and usage metadata. It never
// contains the bearer or verifier.
type ManagementToken struct {
	ID                string   `json:"id"`
	Label             string   `json:"label"`
	Note              string   `json:"note"`
	MetadataRevision  uint64   `json:"metadata_revision"`
	PrincipalID       string   `json:"principal_id"`
	PrincipalName     string   `json:"principal_name"`
	RootDirectoryID   string   `json:"root_directory_id"`
	RootDirectoryName string   `json:"root_directory_name"`
	ParentTokenID     *string  `json:"parent_token_id"`
	SnapshotID        *string  `json:"snapshot_id"`
	Actions           []string `json:"actions"`
	DriverIDs         []string `json:"driver_ids"`
	ExpiresAt         uint64   `json:"expires_at"`
	SealedAt          *uint64  `json:"sealed_at"`
	RevokedAt         *uint64  `json:"revoked_at"`
	CreatedAt         uint64   `json:"created_at"`
	LastUsedAt        *uint64  `json:"last_used_at"`
}

// ManagementSnapshot is one redacted operator view and global audit cursor.
type ManagementSnapshot struct {
	Schema      string                 `json:"schema"`
	ObservedAt  uint64                 `json:"observed_at"`
	EventCursor uint64                 `json:"event_cursor"`
	Drivers     []ManagementDriver     `json:"drivers"`
	Filesystems []ManagementFilesystem `json:"filesystems"`
	Tokens      []ManagementToken      `json:"tokens"`
}

// ManagementDirectoryIdentity contains recursive collection statistics.
type ManagementDirectoryIdentity struct {
	ID                      string  `json:"id"`
	FilesystemID            string  `json:"filesystem_id"`
	ParentID                *string `json:"parent_id"`
	Name                    string  `json:"name"`
	DataRoot                string  `json:"data_root"`
	CryptoSuite             string  `json:"crypto_suite"`
	ActiveKeyEpoch          uint64  `json:"active_key_epoch"`
	ACLInherits             bool    `json:"acl_inherits"`
	Revision                uint64  `json:"revision"`
	ACLRevision             uint64  `json:"acl_revision"`
	PlacementRevision       uint64  `json:"placement_revision"`
	ChildDirectoryCount     uint64  `json:"child_directory_count"`
	RecursiveDirectoryCount uint64  `json:"recursive_directory_count"`
	RecursiveFileCount      uint64  `json:"recursive_file_count"`
	RecursiveLogicalBytes   uint64  `json:"recursive_logical_bytes"`
}

// ManagementBreadcrumb is one root-to-current path component.
type ManagementBreadcrumb struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Depth uint64 `json:"depth"`
}

// ManagementDirectoryEntry is one complete file or child collection.
type ManagementDirectoryEntry struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	FileID           *string  `json:"file_id"`
	VersionID        *string  `json:"version_id"`
	ChildDirectoryID *string  `json:"child_directory_id"`
	SizeBytes        uint64   `json:"size_bytes"`
	DataRoot         string   `json:"data_root"`
	MetadataRoot     *string  `json:"metadata_root"`
	Revision         uint64   `json:"revision"`
	UpdatedAt        uint64   `json:"updated_at"`
	DriverIDs        []string `json:"driver_ids"`
}

// ManagementDirectory is one bounded collection page and recursive summary.
type ManagementDirectory struct {
	Schema      string                      `json:"schema"`
	ObservedAt  uint64                      `json:"observed_at"`
	Directory   ManagementDirectoryIdentity `json:"directory"`
	Breadcrumbs []ManagementBreadcrumb      `json:"breadcrumbs"`
	Placements  []string                    `json:"placements"`
	Entries     []ManagementDirectoryEntry  `json:"entries"`
}

// ValidateTokenAnnotationRequest is a complete desired token label and note at
// one observed metadata revision.
type ValidateTokenAnnotationRequest struct {
	Label            string `json:"label"`
	Note             string `json:"note"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// TokenAnnotationValidation is the server-normalized diff and short-lived
// digest required by ApplyTokenAnnotation.
type TokenAnnotationValidation struct {
	Schema              string   `json:"schema"`
	TokenID             string   `json:"token_id"`
	CurrentLabel        string   `json:"current_label"`
	CurrentNote         string   `json:"current_note"`
	Label               string   `json:"label"`
	Note                string   `json:"note"`
	ExpectedRevision    uint64   `json:"expected_revision"`
	ValidationExpiresAt uint64   `json:"validation_expires_at"`
	ValidationDigest    string   `json:"validation_digest"`
	Warnings            []string `json:"warnings"`
}

// ApplyTokenAnnotationRequest binds apply to one exact validation and
// idempotency identity.
type ApplyTokenAnnotationRequest struct {
	Label               string `json:"label"`
	Note                string `json:"note"`
	ExpectedRevision    uint64 `json:"expected_revision"`
	ValidationExpiresAt uint64 `json:"validation_expires_at"`
	ValidationDigest    string `json:"validation_digest"`
	IdempotencyKey      string `json:"idempotency_key"`
}

// TokenAnnotationReceipt is the durable, idempotent annotation mutation.
type TokenAnnotationReceipt struct {
	Schema        string `json:"schema"`
	OperationID   string `json:"operation_id"`
	TokenID       string `json:"token_id"`
	Label         string `json:"label"`
	Note          string `json:"note"`
	FinalRevision uint64 `json:"final_revision"`
	CommittedAt   uint64 `json:"committed_at"`
	State         string `json:"state"`
}

// ValidateDriverStateRequest pins one desired enabled state to an observed
// driver revision.
type ValidateDriverStateRequest struct {
	Enabled          bool   `json:"enabled"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

// DriverStateValidation includes the exact signed transition and its impact.
type DriverStateValidation struct {
	Schema                 string   `json:"schema"`
	DriverID               string   `json:"driver_id"`
	Kind                   string   `json:"kind"`
	CurrentEnabled         bool     `json:"current_enabled"`
	Enabled                bool     `json:"enabled"`
	ExpectedRevision       uint64   `json:"expected_revision"`
	PlacementCount         uint64   `json:"placement_count"`
	AvailableLocationCount uint64   `json:"available_location_count"`
	ValidationExpiresAt    uint64   `json:"validation_expires_at"`
	ValidationDigest       string   `json:"validation_digest"`
	Warnings               []string `json:"warnings"`
}

// ApplyDriverStateRequest binds apply to one signed validation and stable
// idempotency identity.
type ApplyDriverStateRequest struct {
	Enabled             bool   `json:"enabled"`
	ExpectedRevision    uint64 `json:"expected_revision"`
	ValidationExpiresAt uint64 `json:"validation_expires_at"`
	ValidationDigest    string `json:"validation_digest"`
	IdempotencyKey      string `json:"idempotency_key"`
}

// DriverStateReceipt is the durable driver state mutation result.
type DriverStateReceipt struct {
	Schema        string `json:"schema"`
	OperationID   string `json:"operation_id"`
	DriverID      string `json:"driver_id"`
	Enabled       bool   `json:"enabled"`
	FinalRevision uint64 `json:"final_revision"`
	CommittedAt   uint64 `json:"committed_at"`
	State         string `json:"state"`
}

// ValidateDriverRegistrationRequest describes one new disabled typed driver.
// Config contains non-secret fields only.
type ValidateDriverRegistrationRequest struct {
	DriverID string          `json:"driver_id"`
	Kind     string          `json:"kind"`
	Config   json.RawMessage `json:"config"`
}

// DriverRegistrationValidation is the normalized, signed registration and
// its capability or credential warnings.
type DriverRegistrationValidation struct {
	Schema              string          `json:"schema"`
	DriverID            string          `json:"driver_id"`
	Kind                string          `json:"kind"`
	Config              json.RawMessage `json:"config"`
	Enabled             bool            `json:"enabled"`
	ExpectedRevision    uint64          `json:"expected_revision"`
	RequiresCredential  bool            `json:"requires_credential"`
	ValidationExpiresAt uint64          `json:"validation_expires_at"`
	ValidationDigest    string          `json:"validation_digest"`
	Warnings            []string        `json:"warnings"`
}

// ApplyDriverRegistrationRequest binds one normalized registration to its
// signed validation and stable idempotency identity.
type ApplyDriverRegistrationRequest struct {
	DriverID            string          `json:"driver_id"`
	Kind                string          `json:"kind"`
	Config              json.RawMessage `json:"config"`
	ValidationExpiresAt uint64          `json:"validation_expires_at"`
	ValidationDigest    string          `json:"validation_digest"`
	IdempotencyKey      string          `json:"idempotency_key"`
}

// DriverRegistrationReceipt is the durable disabled driver registration.
type DriverRegistrationReceipt struct {
	Schema        string          `json:"schema"`
	OperationID   string          `json:"operation_id"`
	DriverID      string          `json:"driver_id"`
	Kind          string          `json:"kind"`
	Config        json.RawMessage `json:"config"`
	Enabled       bool            `json:"enabled"`
	FinalRevision uint64          `json:"final_revision"`
	CommittedAt   uint64          `json:"committed_at"`
	State         string          `json:"state"`
}

// ValidateDriverCredentialRequest carries one write-only typed credential at
// an exact observed driver revision. Call Clear immediately after use.
type ValidateDriverCredentialRequest struct {
	Credential       json.RawMessage `json:"credential"`
	ExpectedRevision uint64          `json:"expected_revision"`
}

// Clear overwrites the transient credential JSON.
func (requested *ValidateDriverCredentialRequest) Clear() {
	if requested != nil {
		clear(requested.Credential)
		requested.Credential = nil
	}
}

// DriverCredentialValidation contains no credential material; its digest
// binds the exact write-only request.
type DriverCredentialValidation struct {
	Schema                   string   `json:"schema"`
	DriverID                 string   `json:"driver_id"`
	Kind                     string   `json:"kind"`
	CurrentCredentialPresent bool     `json:"current_credential_present"`
	CredentialRevision       uint64   `json:"credential_revision"`
	ExpectedRevision         uint64   `json:"expected_revision"`
	ValidationExpiresAt      uint64   `json:"validation_expires_at"`
	ValidationDigest         string   `json:"validation_digest"`
	Warnings                 []string `json:"warnings"`
}

// ApplyDriverCredentialRequest resubmits the write-only credential with its
// exact signed validation. Call Clear immediately after use.
type ApplyDriverCredentialRequest struct {
	Credential          json.RawMessage `json:"credential"`
	ExpectedRevision    uint64          `json:"expected_revision"`
	ValidationExpiresAt uint64          `json:"validation_expires_at"`
	ValidationDigest    string          `json:"validation_digest"`
	IdempotencyKey      string          `json:"idempotency_key"`
}

// Clear overwrites the transient credential JSON.
func (requested *ApplyDriverCredentialRequest) Clear() {
	if requested != nil {
		clear(requested.Credential)
		requested.Credential = nil
	}
}

// DriverCredentialReceipt proves one encrypted credential revision without
// exposing secret material or its ciphertext.
type DriverCredentialReceipt struct {
	Schema             string `json:"schema"`
	OperationID        string `json:"operation_id"`
	DriverID           string `json:"driver_id"`
	CredentialID       string `json:"credential_id"`
	CredentialRevision uint64 `json:"credential_revision"`
	FinalRevision      uint64 `json:"final_revision"`
	RotatedAt          uint64 `json:"rotated_at"`
	State              string `json:"state"`
}

// AdminClient accesses redacted management APIs through a revocable operator
// session. It never sends this credential as a URL parameter or bearer header.
type AdminClient struct {
	baseURL    *url.URL
	credential OperatorCredential
	httpClient *http.Client
}

// NewAdminClient validates the endpoint and creates an isolated cookie jar.
func NewAdminClient(
	endpoint string,
	credential OperatorCredential,
	httpClient *http.Client,
) (*AdminClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: parse admin endpoint: %w", ErrInvalidControlPlane, err)
	}

	if validationErr := validateControlURL(parsed); validationErr != nil {
		return nil, validationErr
	}

	if httpClient == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", ErrInvalidControlPlane)
	}

	if allZeroOperatorCredential(credential) {
		return nil, fmt.Errorf("%w: operator credential must not be zero", ErrInvalidControlPlane)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create Carrack admin cookie jar: %w", err)
	}

	clientCopy := *httpClient
	clientCopy.Jar = jar
	baseURL := *parsed
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")

	return &AdminClient{
		baseURL:    &baseURL,
		credential: credential,
		httpClient: &clientCopy,
	}, nil
}

// Clear overwrites the copied operator credential.
func (client *AdminClient) Clear() {
	if client != nil {
		client.credential.Clear()
	}
}

// Snapshot authenticates and reads the current redacted management snapshot.
func (client *AdminClient) Snapshot(ctx context.Context) (ManagementSnapshot, error) {
	if err := client.login(ctx); err != nil {
		return ManagementSnapshot{}, err
	}

	var response ManagementSnapshot

	if err := client.request(ctx, http.MethodGet, "/api/admin/snapshot", nil, &response); err != nil {
		return ManagementSnapshot{}, err
	}

	if !validManagementSnapshot(response) {
		return ManagementSnapshot{}, fmt.Errorf("%w: invalid management snapshot", ErrControlPlaneResponse)
	}

	return response, nil
}

// Directory authenticates and reads one collection with file and driver metadata.
func (client *AdminClient) Directory(ctx context.Context, directoryID string) (ManagementDirectory, error) {
	if !validIdentifier(directoryID) {
		return ManagementDirectory{}, fmt.Errorf("%w: invalid management directory ID", ErrInvalidControlPlane)
	}

	if err := client.login(ctx); err != nil {
		return ManagementDirectory{}, err
	}

	var response ManagementDirectory

	path := "/api/admin/directories/" + directoryID

	if err := client.request(ctx, http.MethodGet, path, nil, &response); err != nil {
		return ManagementDirectory{}, err
	}

	if response.Schema != managementDirectorySchema || response.Directory.ID != directoryID {
		return ManagementDirectory{}, fmt.Errorf("%w: invalid management directory", ErrControlPlaneResponse)
	}

	return response, nil
}

// ValidateTokenAnnotation performs local validation, authenticates, and asks
// the server to normalize and validate one complete desired annotation.
func (client *AdminClient) ValidateTokenAnnotation(
	ctx context.Context,
	tokenID string,
	requested ValidateTokenAnnotationRequest,
) (TokenAnnotationValidation, error) {
	normalized, err := canonicalTokenAnnotation(requested)
	if err != nil || !validIdentifier(tokenID) {
		return TokenAnnotationValidation{}, fmt.Errorf("%w: invalid token annotation", ErrInvalidControlPlane)
	}

	if loginErr := client.login(ctx); loginErr != nil {
		return TokenAnnotationValidation{}, loginErr
	}

	body, err := json.Marshal(normalized)
	if err != nil {
		return TokenAnnotationValidation{}, fmt.Errorf("marshal token annotation validation: %w", err)
	}

	var response TokenAnnotationValidation

	path := "/api/admin/tokens/" + tokenID + "/annotation/validate"
	if err := client.request(ctx, http.MethodPost, path, body, &response); err != nil {
		return TokenAnnotationValidation{}, err
	}

	if response.Schema != tokenAnnotationValidationSchema || response.TokenID != tokenID ||
		response.Label != normalized.Label || response.Note != normalized.Note ||
		response.ExpectedRevision != normalized.ExpectedRevision ||
		response.ValidationExpiresAt == 0 || !validManagementDigest(response.ValidationDigest) {
		return TokenAnnotationValidation{}, fmt.Errorf("%w: invalid token annotation validation", ErrControlPlaneResponse)
	}

	return response, nil
}

// EnableConfiguration reauthenticates this operator session for a bounded
// mutation window. The credential is sent only in a JSON request body.
func (client *AdminClient) EnableConfiguration(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{
		"password": base64.RawURLEncoding.EncodeToString(client.credential[:]),
	})
	if err != nil {
		return fmt.Errorf("marshal Carrack configuration login: %w", err)
	}

	var response struct {
		Enabled   bool    `json:"enabled"`
		ExpiresAt *uint64 `json:"expires_at"`
	}

	if err := client.request(ctx, http.MethodPost, "/api/auth/configuration/enable", body, &response); err != nil {
		return err
	}

	if !response.Enabled || response.ExpiresAt == nil || *response.ExpiresAt == 0 {
		return fmt.Errorf("%w: configuration session was not enabled", ErrControlPlaneResponse)
	}

	return nil
}

// ApplyTokenAnnotation submits the exact normalized validation and verifies
// the durable receipt before reporting success.
func (client *AdminClient) ApplyTokenAnnotation(
	ctx context.Context,
	tokenID string,
	requested ApplyTokenAnnotationRequest,
) (TokenAnnotationReceipt, error) {
	if !validIdentifier(tokenID) || !validManagementDigest(requested.ValidationDigest) ||
		!validIdempotencyKey(requested.IdempotencyKey) || requested.ValidationExpiresAt == 0 {
		return TokenAnnotationReceipt{}, fmt.Errorf("%w: invalid token annotation apply", ErrInvalidControlPlane)
	}

	normalized, err := canonicalTokenAnnotation(ValidateTokenAnnotationRequest{
		Label: requested.Label, Note: requested.Note, ExpectedRevision: requested.ExpectedRevision,
	})
	if err != nil || normalized.Label != requested.Label || normalized.Note != requested.Note {
		return TokenAnnotationReceipt{}, fmt.Errorf("%w: apply input is not normalized", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return TokenAnnotationReceipt{}, fmt.Errorf("marshal token annotation apply: %w", err)
	}

	var response TokenAnnotationReceipt

	path := "/api/admin/tokens/" + tokenID + "/annotation/apply"
	if err := client.request(ctx, http.MethodPost, path, body, &response); err != nil {
		return TokenAnnotationReceipt{}, err
	}

	if response.Schema != tokenAnnotationReceiptSchema || response.TokenID != tokenID ||
		response.Label != requested.Label || response.Note != requested.Note ||
		response.FinalRevision != requested.ExpectedRevision+1 || response.CommittedAt == 0 ||
		response.State != vfsCommittedState || !validIdentifier(response.OperationID) {
		return TokenAnnotationReceipt{}, fmt.Errorf("%w: invalid token annotation receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

// ValidateDriverState performs local boundary checks and asks the server to
// validate the typed driver configuration and transition impact.
func (client *AdminClient) ValidateDriverState(
	ctx context.Context,
	driverID string,
	requested ValidateDriverStateRequest,
) (DriverStateValidation, error) {
	if !validControlString(driverID, 256) || requested.ExpectedRevision == 0 {
		return DriverStateValidation{}, fmt.Errorf("%w: invalid driver state", ErrInvalidControlPlane)
	}

	if err := client.login(ctx); err != nil {
		return DriverStateValidation{}, err
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return DriverStateValidation{}, fmt.Errorf("marshal driver state validation: %w", err)
	}

	var response DriverStateValidation

	path := "/api/admin/drivers/" + url.PathEscape(driverID) + "/state/validate"

	if err := client.request(ctx, http.MethodPost, path, body, &response); err != nil {
		return DriverStateValidation{}, err
	}

	if response.Schema != driverStateValidationSchema || response.DriverID != driverID ||
		response.Enabled != requested.Enabled || response.CurrentEnabled == response.Enabled ||
		response.ExpectedRevision != requested.ExpectedRevision || response.ValidationExpiresAt == 0 ||
		!validControlString(response.Kind, 128) || !validManagementDigest(response.ValidationDigest) {
		return DriverStateValidation{}, fmt.Errorf("%w: invalid driver state validation", ErrControlPlaneResponse)
	}

	return response, nil
}

// ApplyDriverState applies one exact validation and verifies the durable receipt.
func (client *AdminClient) ApplyDriverState(
	ctx context.Context,
	driverID string,
	requested ApplyDriverStateRequest,
) (DriverStateReceipt, error) {
	if !validControlString(driverID, 256) || requested.ExpectedRevision == 0 ||
		requested.ValidationExpiresAt == 0 || !validManagementDigest(requested.ValidationDigest) ||
		!validIdempotencyKey(requested.IdempotencyKey) {
		return DriverStateReceipt{}, fmt.Errorf("%w: invalid driver state apply", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return DriverStateReceipt{}, fmt.Errorf("marshal driver state apply: %w", err)
	}

	var response DriverStateReceipt

	path := "/api/admin/drivers/" + url.PathEscape(driverID) + "/state/apply"

	if err := client.request(ctx, http.MethodPost, path, body, &response); err != nil {
		return DriverStateReceipt{}, err
	}

	if response.Schema != driverStateReceiptSchema || response.DriverID != driverID ||
		response.Enabled != requested.Enabled || response.FinalRevision != requested.ExpectedRevision+1 ||
		response.CommittedAt == 0 || response.State != vfsCommittedState ||
		!validIdentifier(response.OperationID) {
		return DriverStateReceipt{}, fmt.Errorf("%w: invalid driver state receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

// ValidateDriverRegistration authenticates and asks the server to normalize
// one new non-secret typed driver configuration.
func (client *AdminClient) ValidateDriverRegistration(
	ctx context.Context,
	requested ValidateDriverRegistrationRequest,
) (DriverRegistrationValidation, error) {
	if !validControlString(requested.DriverID, 256) || !validControlString(requested.Kind, 128) ||
		!validJSONObjectWire(requested.Config) {
		return DriverRegistrationValidation{}, fmt.Errorf("%w: invalid driver registration", ErrInvalidControlPlane)
	}

	if err := client.login(ctx); err != nil {
		return DriverRegistrationValidation{}, err
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return DriverRegistrationValidation{}, fmt.Errorf("marshal driver registration validation: %w", err)
	}

	var response DriverRegistrationValidation

	if err := client.request(
		ctx,
		http.MethodPost,
		"/api/admin/drivers/registration/validate",
		body,
		&response,
	); err != nil {
		return DriverRegistrationValidation{}, err
	}

	if response.Schema != driverRegistrationValidationSchema ||
		response.DriverID != requested.DriverID || response.Kind != requested.Kind ||
		response.Enabled || response.ExpectedRevision != 0 || !validJSONObjectWire(response.Config) ||
		response.ValidationExpiresAt == 0 || !validManagementDigest(response.ValidationDigest) {
		return DriverRegistrationValidation{}, fmt.Errorf("%w: invalid driver registration validation", ErrControlPlaneResponse)
	}

	return response, nil
}

// ApplyDriverRegistration applies one exact normalized validation and verifies
// the durable disabled-driver receipt.
func (client *AdminClient) ApplyDriverRegistration(
	ctx context.Context,
	requested ApplyDriverRegistrationRequest,
) (DriverRegistrationReceipt, error) {
	if !validControlString(requested.DriverID, 256) || !validControlString(requested.Kind, 128) ||
		!validJSONObjectWire(requested.Config) || requested.ValidationExpiresAt == 0 ||
		!validManagementDigest(requested.ValidationDigest) ||
		!validIdempotencyKey(requested.IdempotencyKey) {
		return DriverRegistrationReceipt{}, fmt.Errorf("%w: invalid driver registration apply", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return DriverRegistrationReceipt{}, fmt.Errorf("marshal driver registration apply: %w", err)
	}

	var response DriverRegistrationReceipt

	if err := client.request(
		ctx,
		http.MethodPost,
		"/api/admin/drivers/registration/apply",
		body,
		&response,
	); err != nil {
		return DriverRegistrationReceipt{}, err
	}

	if response.Schema != driverRegistrationReceiptSchema ||
		response.DriverID != requested.DriverID || response.Kind != requested.Kind ||
		!bytes.Equal(response.Config, requested.Config) || response.Enabled ||
		response.FinalRevision != 1 || response.CommittedAt == 0 || response.State != vfsCommittedState ||
		!validIdentifier(response.OperationID) {
		return DriverRegistrationReceipt{}, fmt.Errorf("%w: invalid driver registration receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

// ValidateDriverCredential performs local boundary checks and asks the server
// to validate one exact write-only credential.
func (client *AdminClient) ValidateDriverCredential(
	ctx context.Context,
	driverID string,
	requested ValidateDriverCredentialRequest,
) (DriverCredentialValidation, error) {
	if !validControlString(driverID, 256) || requested.ExpectedRevision == 0 ||
		!validJSONObjectWire(requested.Credential) {
		return DriverCredentialValidation{}, fmt.Errorf("%w: invalid driver credential", ErrInvalidControlPlane)
	}

	if err := client.login(ctx); err != nil {
		return DriverCredentialValidation{}, err
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return DriverCredentialValidation{}, fmt.Errorf("marshal driver credential validation: %w", err)
	}
	defer clear(body)

	var response DriverCredentialValidation

	path := "/api/admin/drivers/" + url.PathEscape(driverID) + "/credential/validate"
	if err := client.request(ctx, http.MethodPost, path, body, &response); err != nil {
		return DriverCredentialValidation{}, err
	}

	if response.Schema != driverCredentialValidationSchema || response.DriverID != driverID ||
		!validControlString(response.Kind, 128) || response.CredentialRevision == 0 ||
		response.ExpectedRevision != requested.ExpectedRevision || response.ValidationExpiresAt == 0 ||
		!validManagementDigest(response.ValidationDigest) {
		return DriverCredentialValidation{}, fmt.Errorf("%w: invalid driver credential validation", ErrControlPlaneResponse)
	}

	return response, nil
}

// ApplyDriverCredential seals one exact credential and verifies its durable
// non-secret receipt.
func (client *AdminClient) ApplyDriverCredential(
	ctx context.Context,
	driverID string,
	requested ApplyDriverCredentialRequest,
) (DriverCredentialReceipt, error) {
	if !validControlString(driverID, 256) || requested.ExpectedRevision == 0 ||
		!validJSONObjectWire(requested.Credential) || requested.ValidationExpiresAt == 0 ||
		!validManagementDigest(requested.ValidationDigest) ||
		!validIdempotencyKey(requested.IdempotencyKey) {
		return DriverCredentialReceipt{}, fmt.Errorf("%w: invalid driver credential apply", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return DriverCredentialReceipt{}, fmt.Errorf("marshal driver credential apply: %w", err)
	}
	defer clear(body)

	var response DriverCredentialReceipt

	path := "/api/admin/drivers/" + url.PathEscape(driverID) + "/credential/apply"
	if err := client.request(ctx, http.MethodPost, path, body, &response); err != nil {
		return DriverCredentialReceipt{}, err
	}

	if response.Schema != driverCredentialReceiptSchema || response.DriverID != driverID ||
		!validIdentifier(response.CredentialID) || response.CredentialRevision == 0 ||
		response.FinalRevision != requested.ExpectedRevision+1 || response.RotatedAt == 0 ||
		response.State != vfsCommittedState || !validIdentifier(response.OperationID) {
		return DriverCredentialReceipt{}, fmt.Errorf("%w: invalid driver credential receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

func (client *AdminClient) login(ctx context.Context) error {
	if client == nil || client.baseURL == nil || client.httpClient == nil {
		return fmt.Errorf("%w: admin client is not initialized", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(map[string]string{
		"password": base64.RawURLEncoding.EncodeToString(client.credential[:]),
	})
	if err != nil {
		return fmt.Errorf("marshal Carrack operator login: %w", err)
	}

	var response struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := client.request(ctx, http.MethodPost, "/api/auth/login", body, &response); err != nil {
		return err
	}

	if !response.Authenticated {
		return fmt.Errorf("%w: operator session was not authenticated", ErrControlPlaneResponse)
	}

	return nil
}

func (client *AdminClient) request(
	ctx context.Context,
	method, path string,
	body []byte,
	destination any,
) error {
	endpoint := *client.baseURL
	endpoint.Path += path

	requestBody := io.Reader(http.NoBody)
	if body != nil {
		requestBody = bytes.NewReader(body)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return fmt.Errorf("create Carrack admin request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("Carrack-Protocol-Epoch", strconv.FormatUint(ProtocolEpoch, 10))
	request.Header.Set("Carrack-Sdk-Version", SDKVersion)

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send Carrack admin request: %w", err)
	}

	limited := io.LimitReader(response.Body, maximumControlBodyBytes+1)
	responseBody, readErr := io.ReadAll(limited)

	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("read Carrack admin response: %w", errors.Join(readErr, closeErr))
	}

	if len(responseBody) > maximumControlBodyBytes {
		return fmt.Errorf("%w: management body exceeds limit", ErrControlPlaneResponse)
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: HTTP status %d", ErrControlPlaneResponse, response.StatusCode)
	}

	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode management JSON: %w", ErrControlPlaneResponse, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing management JSON", ErrControlPlaneResponse)
	}

	return nil
}

func validManagementSnapshot(snapshot ManagementSnapshot) bool {
	if snapshot.Schema != managementSnapshotSchema || snapshot.ObservedAt == 0 {
		return false
	}

	for _, driver := range snapshot.Drivers {
		if !validControlString(driver.ID, 256) || !validControlString(driver.Kind, 256) ||
			driver.Revision == 0 || !json.Valid(driver.Config) {
			return false
		}
	}

	for _, filesystem := range snapshot.Filesystems {
		if !validIdentifier(filesystem.ID) || !validIdentifier(filesystem.RootDirectoryID) ||
			!validControlString(filesystem.Name, 256) || filesystem.Revision == 0 {
			return false
		}
	}

	for _, token := range snapshot.Tokens {
		if !validIdentifier(token.ID) || !validIdentifier(token.PrincipalID) ||
			!validIdentifier(token.RootDirectoryID) || token.ExpiresAt == 0 {
			return false
		}
	}

	return true
}

func canonicalTokenAnnotation(
	requested ValidateTokenAnnotationRequest,
) (ValidateTokenAnnotationRequest, error) {
	requested.Label = strings.TrimSpace(requested.Label)

	requested.Note = strings.TrimSpace(strings.ReplaceAll(requested.Note, "\r\n", "\n"))
	if requested.ExpectedRevision == 0 || requested.Label == "" || len(requested.Label) > 128 ||
		len(requested.Note) > 2_048 || strings.ContainsAny(requested.Label, "\r\n\t") {
		return ValidateTokenAnnotationRequest{}, fmt.Errorf("%w: invalid token annotation fields", ErrInvalidControlPlane)
	}

	for _, character := range requested.Label {
		if character < ' ' || character == 0x7f {
			return ValidateTokenAnnotationRequest{}, fmt.Errorf("%w: invalid token label control character", ErrInvalidControlPlane)
		}
	}

	for _, character := range requested.Note {
		if character < ' ' && character != '\n' && character != '\t' || character == 0x7f {
			return ValidateTokenAnnotationRequest{}, fmt.Errorf("%w: invalid token note control character", ErrInvalidControlPlane)
		}
	}

	return requested, nil
}

func validManagementDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)

	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validIdempotencyKey(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\r\n\t")
}

func allZeroOperatorCredential(credential OperatorCredential) bool {
	var combined byte
	for _, value := range credential {
		combined |= value
	}

	return combined == 0
}
