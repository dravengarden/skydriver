package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

const (
	minimumOperationLeaseSeconds = 15
	maximumOperationLeaseSeconds = 300
)

// CreateImportOperationRequest identifies one idempotent import attempt.
type CreateImportOperationRequest struct {
	NamespaceID      string
	IdempotencyKey   string
	UsefulBytesTotal *uint64
}

// ImportOperation is the durable control-plane identity for an import.
type ImportOperation struct {
	ID               string  `json:"id"`
	NamespaceID      string  `json:"namespace_id"`
	Kind             string  `json:"kind"`
	State            string  `json:"state"`
	Phase            string  `json:"phase"`
	RequestedBy      string  `json:"requested_by"`
	Incarnation      string  `json:"incarnation"`
	Revision         uint64  `json:"revision"`
	UsefulBytesTotal *uint64 `json:"useful_bytes_total"`
	CreatedAt        uint64  `json:"created_at"`
	UpdatedAt        uint64  `json:"updated_at"`
}

// OperationLease is a renewable, incarnation-scoped write fence.
type OperationLease struct {
	OperationID       string `json:"operation_id"`
	LeaseID           string `json:"lease_id"`
	OwnerClientID     string `json:"owner_client_id"`
	Incarnation       string `json:"incarnation"`
	FencingToken      uint64 `json:"fencing_token"`
	ExpiresAt         uint64 `json:"expires_at"`
	OperationRevision uint64 `json:"operation_revision"`
	OperationState    string `json:"operation_state"`
}

// PublishImportRequest atomically publishes an already verified import.
type PublishImportRequest struct {
	Operation              ImportOperation
	Lease                  OperationLease
	StagedRecovery         StagedRecovery
	Result                 ImportResult
	ExpectedObjectRevision uint64
}

// PublishedImport identifies the immutable version made visible in D1.
type PublishedImport struct {
	OperationID    string `json:"operation_id"`
	ObjectID       string `json:"object_id"`
	Generation     uint64 `json:"generation"`
	ManifestSHA256 string `json:"manifest_sha256"`
	State          string `json:"state"`
}

type createImportOperationBody struct {
	NamespaceID      string  `json:"namespace_id"`
	IdempotencyKey   string  `json:"idempotency_key"`
	UsefulBytesTotal *uint64 `json:"useful_bytes_total,omitempty"`
}

type claimOperationBody struct {
	LeaseSeconds uint64 `json:"lease_seconds"`
}

type publishImportBody struct {
	OperationID            string `json:"operation_id"`
	LeaseID                string `json:"lease_id"`
	Incarnation            string `json:"incarnation"`
	FencingToken           uint64 `json:"fencing_token"`
	ManifestSHA256         string `json:"manifest_sha256"`
	RecoverySHA256         string `json:"recovery_sha256"`
	R2Key                  string `json:"r2_key"`
	R2Version              string `json:"r2_version"`
	SidecarDriverID        string `json:"sidecar_driver_id"`
	SidecarStorageKey      string `json:"sidecar_storage_key"`
	ExpectedObjectRevision uint64 `json:"expected_object_revision"`
}

// CreateImportOperation creates or returns one client-owned idempotent import.
func (client *ControlClient) CreateImportOperation(
	ctx context.Context,
	requested CreateImportOperationRequest,
) (ImportOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlString(requested.IdempotencyKey, 256) ||
		(requested.UsefulBytesTotal != nil && *requested.UsefulBytesTotal > math.MaxInt64) {
		return ImportOperation{}, fmt.Errorf("%w: invalid import operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createImportOperationBody(requested))
	if err != nil {
		return ImportOperation{}, fmt.Errorf("marshal import operation: %w", err)
	}

	var response ImportOperation
	if err := client.authenticatedPost(ctx, "/api/v1/operations", body, &response); err != nil {
		return ImportOperation{}, err
	}

	if response.NamespaceID != requested.NamespaceID || response.Kind != "import" ||
		!validControlHex(response.ID, 32) || !validControlHex(response.Incarnation, 32) ||
		response.Revision == 0 {
		return ImportOperation{}, fmt.Errorf("%w: invalid import operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimImportOperation acquires or renews the current import write fence.
func (client *ControlClient) ClaimImportOperation(
	ctx context.Context,
	operation ImportOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid operation lease request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(claimOperationBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return OperationLease{}, fmt.Errorf("marshal operation lease: %w", err)
	}

	var response OperationLease

	path := "/api/v1/operations/" + operation.ID + "/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return OperationLease{}, err
	}

	if response.OperationID != operation.ID || response.Incarnation != operation.Incarnation ||
		response.LeaseID == "" || response.OwnerClientID == "" || response.FencingToken == 0 ||
		response.OperationRevision == 0 || response.OperationState != "running" {
		return OperationLease{}, fmt.Errorf("%w: invalid operation lease identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// PublishImport commits manifest metadata and switches object visibility under
// the supplied lease fence. Repeating the exact request is idempotent.
func (client *ControlClient) PublishImport(
	ctx context.Context,
	requested PublishImportRequest,
) (PublishedImport, error) {
	if err := validatePublication(requested); err != nil {
		return PublishedImport{}, err
	}

	body, err := json.Marshal(publishImportBody{
		OperationID:            requested.Operation.ID,
		LeaseID:                requested.Lease.LeaseID,
		Incarnation:            requested.Lease.Incarnation,
		FencingToken:           requested.Lease.FencingToken,
		ManifestSHA256:         requested.StagedRecovery.ManifestSHA256,
		RecoverySHA256:         requested.StagedRecovery.RecoverySHA256,
		R2Key:                  requested.StagedRecovery.R2Key,
		R2Version:              requested.StagedRecovery.R2Version,
		SidecarDriverID:        requested.Result.DestinationDriverID,
		SidecarStorageKey:      requested.Result.RecoveryKey,
		ExpectedObjectRevision: requested.ExpectedObjectRevision,
	})
	if err != nil {
		return PublishedImport{}, fmt.Errorf("marshal import publication: %w", err)
	}

	var response PublishedImport
	if err := client.authenticatedPost(ctx, "/api/v1/imports/publish", body, &response); err != nil {
		return PublishedImport{}, err
	}

	if response.OperationID != requested.Operation.ID ||
		response.ObjectID != requested.Result.Manifest.ObjectID ||
		response.Generation != requested.Result.Manifest.Generation ||
		response.ManifestSHA256 != requested.StagedRecovery.ManifestSHA256 ||
		response.State != "published" {
		return PublishedImport{}, fmt.Errorf("%w: published import identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func validatePublication(requested PublishImportRequest) error {
	manifest := requested.Result.Manifest
	staged := requested.StagedRecovery

	if requested.Operation.ID == "" || requested.Lease.OperationID != requested.Operation.ID ||
		requested.Lease.LeaseID == "" || requested.Lease.FencingToken == 0 ||
		requested.Lease.Incarnation != requested.Operation.Incarnation ||
		requested.ExpectedObjectRevision == 0 || requested.Result.DestinationDriverID == "" ||
		requested.Result.RecoveryKey == "" || staged.R2Key == "" || staged.R2Version == "" ||
		!validControlHex(staged.RecoverySHA256, 64) {
		return fmt.Errorf("%w: invalid import publication fence", ErrInvalidControlPlane)
	}

	if err := requested.Result.Recovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid recovery manifest: %w", ErrInvalidControlPlane, err)
	}

	manifestDigest, err := manifest.Digest()
	if err != nil {
		return fmt.Errorf("%w: invalid content manifest: %w", ErrInvalidControlPlane, err)
	}

	if requested.Result.Recovery.ManifestSHA256 != staged.ManifestSHA256 ||
		manifestDigest != staged.ManifestSHA256 ||
		manifest.NamespaceID != requested.Operation.NamespaceID ||
		manifest.NamespaceID != staged.NamespaceID || manifest.ObjectID != staged.ObjectID ||
		manifest.Generation != staged.Generation {
		return fmt.Errorf("%w: import publication identities differ", ErrInvalidControlPlane)
	}

	return nil
}

func validControlHex(value string, characters int) bool {
	if len(value) != characters {
		return false
	}

	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}

func validControlString(value string, maximumBytes int) bool {
	return value != "" && strings.TrimSpace(value) == value && len(value) <= maximumBytes
}
