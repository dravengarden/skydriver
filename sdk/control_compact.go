package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
)

// CreateCompactOperationRequest pins the current multi-pack generation and destination.
type CreateCompactOperationRequest struct {
	NamespaceID         string
	ManifestSHA256      string
	DestinationDriverID string
	IdempotencyKey      string
}

// CompactOperation is the immutable source and target identity for one compaction.
type CompactOperation struct {
	ID                         string `json:"id"`
	NamespaceID                string `json:"namespace_id"`
	Kind                       string `json:"kind"`
	State                      string `json:"state"`
	Phase                      string `json:"phase"`
	RequestedBy                string `json:"requested_by"`
	Incarnation                string `json:"incarnation"`
	Revision                   uint64 `json:"revision"`
	UsefulBytesTotal           uint64 `json:"useful_bytes_total"`
	VersionID                  string `json:"version_id"`
	ObjectID                   string `json:"object_id"`
	SourceGeneration           uint64 `json:"source_generation"`
	SourceManifestSHA256       string `json:"source_manifest_sha256"`
	SourceRecoverySHA256       string `json:"source_recovery_sha256"`
	SourceRecoveryRevision     uint64 `json:"source_recovery_revision"`
	SourcePlaintextSHA256      string `json:"source_plaintext_sha256"`
	SourcePackCount            uint64 `json:"source_pack_count"`
	SourceRootVersion          uint32 `json:"source_root_version"`
	SourceKeyEpoch             uint64 `json:"source_key_epoch"`
	ExpectedObjectRevision     uint64 `json:"expected_object_revision"`
	TargetGeneration           uint64 `json:"target_generation"`
	TargetRootVersion          uint32 `json:"target_root_version"`
	TargetKeyEpoch             uint64 `json:"target_key_epoch"`
	DestinationDriverID        string `json:"destination_driver_id"`
	PublishedManifestSHA256    string `json:"published_manifest_sha256"`
	PublishedSidecarStorageKey string `json:"published_sidecar_storage_key"`
	CreatedAt                  uint64 `json:"created_at"`
	UpdatedAt                  uint64 `json:"updated_at"`
}

// PublishCompactRequest conditionally installs a smaller immutable replacement generation.
type PublishCompactRequest struct {
	Operation      CompactOperation
	Lease          OperationLease
	SourceRecovery manifest.RecoveryManifest
	StagedRecovery StagedRecovery
	Result         ImportResult
}

type createCompactOperationBody struct {
	NamespaceID         string `json:"namespace_id"`
	ManifestSHA256      string `json:"manifest_sha256"`
	DestinationDriverID string `json:"destination_driver_id"`
	IdempotencyKey      string `json:"idempotency_key"`
}

type compactKeyGrantBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	RootVersion  uint32 `json:"root_version"`
	KeyEpoch     uint64 `json:"key_epoch"`
}

type compactKeyGrant struct {
	OperationID string `json:"operation_id"`
	Purpose     string `json:"purpose"`
	RootVersion uint32 `json:"root_version"`
	KeyEpoch    uint64 `json:"key_epoch"`
	EpochKey    string `json:"epoch_key"`
}

// CreateCompactOperation creates or returns one idempotent source-generation pin.
func (client *ControlClient) CreateCompactOperation(
	ctx context.Context,
	requested CreateCompactOperationRequest,
) (CompactOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.DestinationDriverID, 256) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return CompactOperation{}, fmt.Errorf("%w: invalid compact operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createCompactOperationBody(requested))
	if err != nil {
		return CompactOperation{}, fmt.Errorf("marshal compact operation: %w", err)
	}

	var response CompactOperation
	if err := client.authenticatedPost(ctx, "/api/v1/compactions", body, &response); err != nil {
		return CompactOperation{}, err
	}

	if !validCompactOperation(response, requested) {
		return CompactOperation{}, fmt.Errorf("%w: invalid compact operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimCompactOperation acquires or renews the current compact write fence.
func (client *ControlClient) ClaimCompactOperation(
	ctx context.Context,
	operation CompactOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindCompact || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid compact lease request", ErrInvalidControlPlane)
	}

	return client.claimOperation(ctx, operation.ID, operation.Incarnation, leaseSeconds, "compact")
}

// FetchCompactManifest returns the exact source recovery pinned by the live fence.
func (client *ControlClient) FetchCompactManifest(
	ctx context.Context,
	operation CompactOperation,
	lease OperationLease,
) (manifest.RecoveryManifest, error) {
	return client.fetchTransferManifest(
		ctx,
		"/api/v1/compactions/"+operation.ID+"/manifest",
		lease,
		transferManifestIdentity{
			operationID: operation.ID, incarnation: operation.Incarnation,
			namespaceID: operation.NamespaceID, objectID: operation.ObjectID,
			generation: operation.SourceGeneration, manifestSHA256: operation.SourceManifestSHA256,
			recoverySHA256: operation.SourceRecoverySHA256, kind: "compact",
		},
	)
}

// GrantCompactSourceEpochKey grants only the source generation's pinned crypto context.
func (client *ControlClient) GrantCompactSourceEpochKey(
	ctx context.Context,
	operation CompactOperation,
	lease OperationLease,
) (cryptostream.EpochKey, error) {
	return client.grantCompactEpochKey(
		ctx, operation, lease, "source", operation.SourceRootVersion, operation.SourceKeyEpoch,
	)
}

// GrantCompactTargetEpochKey grants the namespace crypto context pinned for the new generation.
func (client *ControlClient) GrantCompactTargetEpochKey(
	ctx context.Context,
	operation CompactOperation,
	lease OperationLease,
) (cryptostream.EpochKey, error) {
	return client.grantCompactEpochKey(
		ctx, operation, lease, "target", operation.TargetRootVersion, operation.TargetKeyEpoch,
	)
}

func (client *ControlClient) grantCompactEpochKey(
	ctx context.Context,
	operation CompactOperation,
	lease OperationLease,
	purpose string,
	rootVersion uint32,
	keyEpoch uint64,
) (cryptostream.EpochKey, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 || rootVersion == 0 || keyEpoch == 0 {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: invalid compact %s key fence", ErrInvalidControlPlane, purpose)
	}

	body, err := json.Marshal(compactKeyGrantBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, RootVersion: rootVersion, KeyEpoch: keyEpoch,
	})
	if err != nil {
		return cryptostream.EpochKey{}, fmt.Errorf("marshal compact %s key grant: %w", purpose, err)
	}

	var response compactKeyGrant

	path := "/api/v1/compactions/" + operation.ID + "/" + purpose + "-key"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return cryptostream.EpochKey{}, err
	}

	if response.OperationID != operation.ID || response.Purpose != purpose ||
		response.RootVersion != rootVersion || response.KeyEpoch != keyEpoch {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: compact %s key identity changed", ErrControlPlaneResponse, purpose)
	}

	return decodeGrantedEpochKey(response.EpochKey, "compact "+purpose)
}

// ReportCompactProgress records cumulative plaintext read and replacement-write work.
func (client *ControlClient) ReportCompactProgress(
	ctx context.Context,
	operation CompactOperation,
	lease OperationLease,
	sample ProgressSample,
) (ProgressSnapshot, error) {
	if lease.OperationID != operation.ID || lease.LeaseID == "" ||
		lease.Incarnation != operation.Incarnation || lease.FencingToken == 0 ||
		sample.Sequence == 0 || !signedProgressCounters(sample) {
		return ProgressSnapshot{}, fmt.Errorf("%w: invalid compact progress", ErrInvalidControlPlane)
	}

	return client.reportOperationProgress(ctx, progressIdentity{
		operationID: operation.ID, componentID: operation.ID + "/compact",
		leaseID: lease.LeaseID, incarnation: lease.Incarnation, fence: lease.FencingToken,
	}, sample)
}

// PublishCompact selects the CAS winner and retires its pinned source generation atomically.
func (client *ControlClient) PublishCompact(
	ctx context.Context,
	requested PublishCompactRequest,
) (PublishedImport, error) {
	if err := validateCompactPublication(requested); err != nil {
		return PublishedImport{}, err
	}

	body, err := json.Marshal(publishImportBody{
		OperationID: requested.Operation.ID, LeaseID: requested.Lease.LeaseID,
		Incarnation: requested.Lease.Incarnation, FencingToken: requested.Lease.FencingToken,
		ManifestSHA256: requested.StagedRecovery.ManifestSHA256,
		RecoverySHA256: requested.StagedRecovery.RecoverySHA256,
		R2Key:          requested.StagedRecovery.R2Key, R2Version: requested.StagedRecovery.R2Version,
		SidecarDriverID:        requested.Result.DestinationDriverID,
		SidecarStorageKey:      requested.Result.RecoveryKey,
		ExpectedObjectRevision: requested.Operation.ExpectedObjectRevision,
	})
	if err != nil {
		return PublishedImport{}, fmt.Errorf("marshal compact publication: %w", err)
	}

	var response PublishedImport
	if err := client.authenticatedPost(ctx, "/api/v1/compactions/publish", body, &response); err != nil {
		return PublishedImport{}, err
	}

	if response.OperationID != requested.Operation.ID ||
		response.ObjectID != requested.Operation.ObjectID ||
		response.Generation != requested.Operation.TargetGeneration ||
		response.ManifestSHA256 != requested.StagedRecovery.ManifestSHA256 ||
		response.State != publicationStatePublished {
		return PublishedImport{}, fmt.Errorf("%w: published compact identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

//nolint:cyclop,gocyclo // The server-owned compact identity is validated as one exact contract.
func validCompactOperation(
	operation CompactOperation,
	requested CreateCompactOperationRequest,
) bool {
	published := operation.PublishedManifestSHA256 != "" || operation.PublishedSidecarStorageKey != ""

	validPublication := !published
	if operation.State == operationStateSucceeded {
		validPublication = validControlHex(operation.PublishedManifestSHA256, 64) &&
			validControlString(operation.PublishedSidecarStorageKey, 4_096)
	}

	return operation.NamespaceID == requested.NamespaceID && operation.Kind == operationKindCompact &&
		operation.SourceManifestSHA256 == requested.ManifestSHA256 &&
		operation.DestinationDriverID == requested.DestinationDriverID &&
		validCompactOperationState(operation) &&
		validControlHex(operation.ID, 32) && validControlHex(operation.Incarnation, 32) &&
		validControlString(operation.RequestedBy, 2_048) &&
		validControlHex(operation.SourceManifestSHA256, 64) &&
		validControlHex(operation.SourceRecoverySHA256, 64) &&
		validControlHex(operation.SourcePlaintextSHA256, 64) && operation.Revision > 0 &&
		operation.UsefulBytesTotal > 0 && operation.UsefulBytesTotal <= math.MaxInt64 &&
		operation.SourceGeneration > 0 && operation.SourceGeneration < math.MaxUint64 &&
		operation.TargetGeneration == operation.SourceGeneration+1 && operation.SourcePackCount > 1 &&
		operation.SourceRootVersion > 0 && operation.SourceKeyEpoch > 0 &&
		operation.TargetRootVersion > 0 && operation.TargetKeyEpoch > 0 &&
		operation.SourceRecoveryRevision > 0 && operation.ExpectedObjectRevision > 0 &&
		validControlString(operation.ObjectID, 2_048) && validControlString(operation.VersionID, 2_048) &&
		validControlString(operation.DestinationDriverID, 256) && operation.CreatedAt > 0 &&
		operation.UpdatedAt >= operation.CreatedAt && validPublication
}

func validCompactOperationState(operation CompactOperation) bool {
	switch operation.State {
	case operationStatePlanned:
		return operation.Phase == operationStatePlanned
	case operationStateRunning:
		return operation.Phase == "compacting"
	case operationStateSucceeded:
		return operation.Phase == operationStateSucceeded
	case operationStateFailed, operationStateCancelled:
		return operation.Phase == operationPhaseRecovered
	default:
		return false
	}
}

//nolint:cyclop,gocyclo // Every compact wire identity is intentionally checked locally.
func validateCompactPublication(requested PublishCompactRequest) error {
	operation := requested.Operation

	target := requested.Result.Manifest
	if operation.Kind != operationKindCompact || requested.Lease.OperationID != operation.ID ||
		requested.Lease.LeaseID == "" || requested.Lease.FencingToken == 0 ||
		requested.Lease.Incarnation != operation.Incarnation ||
		requested.Result.DestinationDriverID != operation.DestinationDriverID ||
		requested.Result.RecoveryKey == "" || requested.StagedRecovery.R2Key == "" ||
		requested.StagedRecovery.R2Version == "" ||
		!validControlHex(requested.StagedRecovery.RecoverySHA256, 64) {
		return fmt.Errorf("%w: invalid compact publication fence", ErrInvalidControlPlane)
	}

	if err := requested.SourceRecovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid compact source recovery: %w", ErrInvalidControlPlane, err)
	}

	if err := requested.Result.Recovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid compact target recovery: %w", ErrInvalidControlPlane, err)
	}

	targetDigest, err := target.Digest()
	if err != nil {
		return fmt.Errorf("%w: invalid compact target manifest: %w", ErrInvalidControlPlane, err)
	}

	sourcePackIDs := make(map[string]struct{}, len(requested.SourceRecovery.Manifest.Packs))
	for _, pack := range requested.SourceRecovery.Manifest.Packs {
		sourcePackIDs[pack.PackID] = struct{}{}
	}

	for _, pack := range target.Packs {
		if _, reused := sourcePackIDs[pack.PackID]; reused {
			return fmt.Errorf("%w: compact target reused a source pack", ErrInvalidControlPlane)
		}
	}

	if requested.SourceRecovery.ManifestSHA256 != operation.SourceManifestSHA256 ||
		requested.SourceRecovery.Manifest.PlaintextSHA256 != operation.SourcePlaintextSHA256 ||
		target.NamespaceID != operation.NamespaceID || target.ObjectID != operation.ObjectID ||
		target.Generation != operation.TargetGeneration ||
		target.PlaintextSHA256 != operation.SourcePlaintextSHA256 ||
		target.PlaintextSize != operation.UsefulBytesTotal || len(target.Packs) == 0 ||
		uint64(len(target.Packs)) >= operation.SourcePackCount ||
		target.Crypto.RootVersion != operation.TargetRootVersion ||
		target.Crypto.KeyEpoch != operation.TargetKeyEpoch ||
		targetDigest != requested.StagedRecovery.ManifestSHA256 ||
		requested.Result.Recovery.ManifestSHA256 != targetDigest ||
		requested.StagedRecovery.NamespaceID != operation.NamespaceID ||
		requested.StagedRecovery.ObjectID != operation.ObjectID ||
		requested.StagedRecovery.Generation != operation.TargetGeneration {
		return fmt.Errorf("%w: compact publication identities differ", ErrInvalidControlPlane)
	}

	return nil
}
