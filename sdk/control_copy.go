package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/dravengarden/carrack/manifest"
)

// CreateCopyOperationRequest pins one published recovery view and destination.
type CreateCopyOperationRequest struct {
	NamespaceID         string
	ManifestSHA256      string
	DestinationDriverID string
	IdempotencyKey      string
}

// CopyOperation is the durable control-plane identity for one ciphertext copy.
type CopyOperation struct {
	ID                     string `json:"id"`
	NamespaceID            string `json:"namespace_id"`
	Kind                   string `json:"kind"`
	State                  string `json:"state"`
	Phase                  string `json:"phase"`
	RequestedBy            string `json:"requested_by"`
	Incarnation            string `json:"incarnation"`
	Revision               uint64 `json:"revision"`
	UsefulBytesTotal       uint64 `json:"useful_bytes_total"`
	VersionID              string `json:"version_id"`
	ObjectID               string `json:"object_id"`
	Generation             uint64 `json:"generation"`
	ManifestSHA256         string `json:"manifest_sha256"`
	SourceRecoverySHA256   string `json:"source_recovery_sha256"`
	SourceRecoveryRevision uint64 `json:"source_recovery_revision"`
	DestinationDriverID    string `json:"destination_driver_id"`
	CreatedAt              uint64 `json:"created_at"`
	UpdatedAt              uint64 `json:"updated_at"`
}

// PublishCopyRequest atomically makes an already verified replica discoverable.
type PublishCopyRequest struct {
	Operation      CopyOperation
	Lease          OperationLease
	StagedRecovery StagedRecovery
	Result         ReplicationResult
}

// PublishedCopy identifies the recovery revision made visible by a copy.
type PublishedCopy struct {
	OperationID         string `json:"operation_id"`
	ManifestSHA256      string `json:"manifest_sha256"`
	RecoverySHA256      string `json:"recovery_sha256"`
	DestinationDriverID string `json:"destination_driver_id"`
	LocationsAdded      uint64 `json:"locations_added"`
	RecoveryRevision    uint64 `json:"recovery_revision"`
	State               string `json:"state"`
}

type createCopyOperationBody struct {
	NamespaceID         string `json:"namespace_id"`
	ManifestSHA256      string `json:"manifest_sha256"`
	DestinationDriverID string `json:"destination_driver_id"`
	IdempotencyKey      string `json:"idempotency_key"`
}

type copyManifestBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type publishCopyBody struct {
	OperationID       string `json:"operation_id"`
	LeaseID           string `json:"lease_id"`
	Incarnation       string `json:"incarnation"`
	FencingToken      uint64 `json:"fencing_token"`
	ManifestSHA256    string `json:"manifest_sha256"`
	RecoverySHA256    string `json:"recovery_sha256"`
	R2Key             string `json:"r2_key"`
	R2Version         string `json:"r2_version"`
	SidecarDriverID   string `json:"sidecar_driver_id"`
	SidecarStorageKey string `json:"sidecar_storage_key"`
}

// CreateCopyOperation creates or returns an idempotent pinned copy intent.
func (client *ControlClient) CreateCopyOperation(
	ctx context.Context,
	requested CreateCopyOperationRequest,
) (CopyOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.DestinationDriverID, 256) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return CopyOperation{}, fmt.Errorf("%w: invalid copy operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createCopyOperationBody(requested))
	if err != nil {
		return CopyOperation{}, fmt.Errorf("marshal copy operation: %w", err)
	}

	var response CopyOperation
	if err := client.authenticatedPost(ctx, "/api/v1/copies", body, &response); err != nil {
		return CopyOperation{}, err
	}

	if !validCopyOperation(response, requested) {
		return CopyOperation{}, fmt.Errorf("%w: invalid copy operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimCopyOperation acquires or renews the current copy write fence.
func (client *ControlClient) ClaimCopyOperation(
	ctx context.Context,
	operation CopyOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindCopy || !validControlHex(operation.ManifestSHA256, 64) ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid copy lease request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(claimOperationBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return OperationLease{}, fmt.Errorf("marshal copy lease: %w", err)
	}

	var response OperationLease

	path := "/api/v1/operations/" + operation.ID + "/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return OperationLease{}, err
	}

	if response.OperationID != operation.ID || response.Incarnation != operation.Incarnation ||
		response.LeaseID == "" || response.OwnerClientID == "" || response.FencingToken == 0 ||
		response.OperationRevision == 0 || response.OperationState != operationStateRunning {
		return OperationLease{}, fmt.Errorf("%w: invalid copy lease identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// FetchCopyManifest downloads the recovery snapshot pinned by a live copy fence.
func (client *ControlClient) FetchCopyManifest(
	ctx context.Context,
	operation CopyOperation,
	lease OperationLease,
) (manifest.RecoveryManifest, error) {
	return client.fetchTransferManifest(
		ctx,
		"/api/v1/copies/"+operation.ID+"/manifest",
		lease,
		transferManifestIdentity{
			operationID: operation.ID, incarnation: operation.Incarnation,
			namespaceID: operation.NamespaceID, objectID: operation.ObjectID,
			generation: operation.Generation, manifestSHA256: operation.ManifestSHA256,
			recoverySHA256: operation.SourceRecoverySHA256, kind: "copy",
		},
	)
}

type transferManifestIdentity struct {
	operationID    string
	incarnation    string
	namespaceID    string
	objectID       string
	generation     uint64
	manifestSHA256 string
	recoverySHA256 string
	kind           string
}

func (client *ControlClient) fetchTransferManifest(
	ctx context.Context,
	path string,
	lease OperationLease,
	identity transferManifestIdentity,
) (manifest.RecoveryManifest, error) {
	if lease.OperationID != identity.operationID || lease.Incarnation != identity.incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return manifest.RecoveryManifest{}, fmt.Errorf(
			"%w: invalid %s manifest fence",
			ErrInvalidControlPlane,
			identity.kind,
		)
	}

	body, err := json.Marshal(copyManifestBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
	})
	if err != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf("marshal %s manifest fence: %w", identity.kind, err)
	}

	var response manifest.RecoveryManifest

	if requestErr := client.authenticatedPost(ctx, path, body, &response); requestErr != nil {
		return manifest.RecoveryManifest{}, requestErr
	}

	if validationErr := response.Validate(); validationErr != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf(
			"%w: invalid %s manifest: %w",
			ErrControlPlaneResponse,
			identity.kind,
			validationErr,
		)
	}

	recoverySHA256, err := recoveryDigest(response)
	if err != nil {
		return manifest.RecoveryManifest{}, err
	}

	if response.ManifestSHA256 != identity.manifestSHA256 ||
		response.Manifest.NamespaceID != identity.namespaceID ||
		response.Manifest.ObjectID != identity.objectID ||
		response.Manifest.Generation != identity.generation || recoverySHA256 != identity.recoverySHA256 {
		return manifest.RecoveryManifest{}, fmt.Errorf(
			"%w: %s manifest identity changed",
			ErrControlPlaneResponse,
			identity.kind,
		)
	}

	return response, nil
}

// ReportCopyProgress idempotently records cumulative ciphertext copy counters.
func (client *ControlClient) ReportCopyProgress(
	ctx context.Context,
	operation CopyOperation,
	lease OperationLease,
	sample ProgressSample,
) (ProgressSnapshot, error) {
	if !validControlHex(operation.ID, 32) || lease.OperationID != operation.ID ||
		lease.LeaseID == "" || lease.Incarnation != operation.Incarnation ||
		lease.FencingToken == 0 || sample.Sequence == 0 || !signedProgressCounters(sample) {
		return ProgressSnapshot{}, fmt.Errorf("%w: invalid copy progress", ErrInvalidControlPlane)
	}

	return client.reportOperationProgress(ctx, progressIdentity{
		operationID: operation.ID,
		componentID: operation.ID + "/copy",
		leaseID:     lease.LeaseID,
		incarnation: lease.Incarnation,
		fence:       lease.FencingToken,
	}, sample)
}

// PublishCopy switches the current recovery head under the pinned source revision.
// Repeating the exact request after a lost response is idempotent.
func (client *ControlClient) PublishCopy(
	ctx context.Context,
	requested PublishCopyRequest,
) (PublishedCopy, error) {
	if err := validateCopyPublication(requested); err != nil {
		return PublishedCopy{}, err
	}

	body, err := json.Marshal(publishCopyBody{
		OperationID: requested.Operation.ID, LeaseID: requested.Lease.LeaseID,
		Incarnation: requested.Lease.Incarnation, FencingToken: requested.Lease.FencingToken,
		ManifestSHA256: requested.StagedRecovery.ManifestSHA256,
		RecoverySHA256: requested.StagedRecovery.RecoverySHA256,
		R2Key:          requested.StagedRecovery.R2Key, R2Version: requested.StagedRecovery.R2Version,
		SidecarDriverID:   requested.Operation.DestinationDriverID,
		SidecarStorageKey: requested.Result.RecoveryKey,
	})
	if err != nil {
		return PublishedCopy{}, fmt.Errorf("marshal copy publication: %w", err)
	}

	var response PublishedCopy
	if err := client.authenticatedPost(ctx, "/api/v1/copies/publish", body, &response); err != nil {
		return PublishedCopy{}, err
	}

	expectedRevision := requested.Operation.SourceRecoveryRevision + 1

	if response.OperationID != requested.Operation.ID ||
		response.ManifestSHA256 != requested.Operation.ManifestSHA256 ||
		response.RecoverySHA256 != requested.StagedRecovery.RecoverySHA256 ||
		response.DestinationDriverID != requested.Operation.DestinationDriverID ||
		response.LocationsAdded != uint64(len(requested.Result.Locations)) ||
		response.RecoveryRevision != expectedRevision || response.State != publicationStatePublished {
		return PublishedCopy{}, fmt.Errorf("%w: published copy identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func validCopyOperation(response CopyOperation, requested CreateCopyOperationRequest) bool {
	return validControlHex(response.ID, 32) && response.NamespaceID == requested.NamespaceID &&
		response.Kind == operationKindCopy && response.State != "" && response.Phase != "" &&
		response.RequestedBy != "" && validControlHex(response.Incarnation, 32) &&
		response.Revision > 0 && response.VersionID != "" && response.ObjectID != "" &&
		response.Generation > 0 && response.ManifestSHA256 == requested.ManifestSHA256 &&
		validControlHex(response.SourceRecoverySHA256, 64) && response.SourceRecoveryRevision > 0 &&
		response.SourceRecoveryRevision < math.MaxUint64 &&
		response.DestinationDriverID == requested.DestinationDriverID
}

func validateCopyPublication(requested PublishCopyRequest) error {
	if !validCopyPublicationFence(requested) {
		return fmt.Errorf("%w: invalid copy publication fence", ErrInvalidControlPlane)
	}

	return validateCopiedRecovery(requested)
}

func validCopyPublicationFence(requested PublishCopyRequest) bool {
	operation := requested.Operation
	staged := requested.StagedRecovery
	result := requested.Result

	return operation.Kind == operationKindCopy && validControlHex(operation.ID, 32) &&
		validControlHex(operation.Incarnation, 32) &&
		requested.Lease.OperationID == operation.ID && requested.Lease.LeaseID != "" &&
		requested.Lease.FencingToken != 0 && requested.Lease.Incarnation == operation.Incarnation &&
		operation.SourceRecoveryRevision > 0 && operation.SourceRecoveryRevision < math.MaxUint64 &&
		validControlString(operation.DestinationDriverID, 256) &&
		validControlString(result.RecoveryKey, 4_096) && validControlString(staged.R2Key, 4_096) &&
		validControlString(staged.R2Version, 1_024) && validControlHex(staged.RecoverySHA256, 64)
}

func validateCopiedRecovery(requested PublishCopyRequest) error {
	operation := requested.Operation
	staged := requested.StagedRecovery
	result := requested.Result

	if err := result.Recovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid copied recovery manifest: %w", ErrInvalidControlPlane, err)
	}

	manifestSHA256, err := result.Recovery.Manifest.Digest()
	if err != nil {
		return fmt.Errorf("%w: invalid copied content manifest: %w", ErrInvalidControlPlane, err)
	}

	recoverySHA256, err := recoveryDigest(result.Recovery)
	if err != nil {
		return err
	}

	if result.Recovery.ManifestSHA256 != operation.ManifestSHA256 ||
		manifestSHA256 != operation.ManifestSHA256 || staged.ManifestSHA256 != operation.ManifestSHA256 ||
		staged.RecoverySHA256 != recoverySHA256 || staged.NamespaceID != operation.NamespaceID ||
		staged.ObjectID != operation.ObjectID || staged.Generation != operation.Generation {
		return fmt.Errorf("%w: copy publication identities differ", ErrInvalidControlPlane)
	}

	if !copiedLocationsMatchDestination(result, operation.DestinationDriverID) {
		return fmt.Errorf("%w: copied location uses another destination", ErrInvalidControlPlane)
	}

	return nil
}

func copiedLocationsMatchDestination(result ReplicationResult, destinationDriverID string) bool {
	for _, location := range result.Locations {
		if location.DriverID != destinationDriverID {
			return false
		}
	}

	return true
}

func recoveryDigest(recovery manifest.RecoveryManifest) (string, error) {
	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		return "", fmt.Errorf("%w: marshal recovery identity: %w", ErrInvalidControlPlane, err)
	}

	digest := sha256.Sum256(encoded)

	return hex.EncodeToString(digest[:]), nil
}
