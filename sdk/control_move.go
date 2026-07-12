package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/dravengarden/carrack/manifest"
)

// CreateMoveOperationRequest pins one source replica set and destination.
type CreateMoveOperationRequest struct {
	NamespaceID         string
	ManifestSHA256      string
	SourceDriverID      string
	DestinationDriverID string
	IdempotencyKey      string
}

// MoveOperation is the durable control-plane identity for one move saga.
type MoveOperation struct {
	ID                       string `json:"id"`
	NamespaceID              string `json:"namespace_id"`
	Kind                     string `json:"kind"`
	State                    string `json:"state"`
	Phase                    string `json:"phase"`
	RequestedBy              string `json:"requested_by"`
	Incarnation              string `json:"incarnation"`
	Revision                 uint64 `json:"revision"`
	UsefulBytesTotal         uint64 `json:"useful_bytes_total"`
	VersionID                string `json:"version_id"`
	ObjectID                 string `json:"object_id"`
	Generation               uint64 `json:"generation"`
	ManifestSHA256           string `json:"manifest_sha256"`
	SourceRecoverySHA256     string `json:"source_recovery_sha256"`
	SourceRecoveryRevision   uint64 `json:"source_recovery_revision"`
	SourceDriverID           string `json:"source_driver_id"`
	DestinationDriverID      string `json:"destination_driver_id"`
	SourceLocationCount      uint64 `json:"source_location_count"`
	MinimumAvailableReplicas uint64 `json:"minimum_available_replicas"`
	GraceSeconds             uint64 `json:"grace_seconds"`
	MoveState                string `json:"move_state"`
	CreatedAt                uint64 `json:"created_at"`
	UpdatedAt                uint64 `json:"updated_at"`
}

// PublishMoveDestinationRequest makes verified destination replicas discoverable.
type PublishMoveDestinationRequest struct {
	Operation      MoveOperation
	Lease          OperationLease
	StagedRecovery StagedRecovery
	Result         ReplicationResult
}

// PublishedMoveDestination identifies the intermediate recovery revision.
type PublishedMoveDestination struct {
	OperationID         string `json:"operation_id"`
	ManifestSHA256      string `json:"manifest_sha256"`
	RecoverySHA256      string `json:"recovery_sha256"`
	DestinationDriverID string `json:"destination_driver_id"`
	LocationsAdded      uint64 `json:"locations_added"`
	RecoveryRevision    uint64 `json:"recovery_revision"`
	State               string `json:"state"`
}

// TombstoneMoveSourceRequest atomically removes the pinned sources from the
// recovery head and starts their physical-deletion grace period.
type TombstoneMoveSourceRequest struct {
	Operation       MoveOperation
	Lease           OperationLease
	CurrentRecovery manifest.RecoveryManifest
	FinalSidecar    RecoverySidecar
	StagedRecovery  StagedRecovery
}

// TombstonedMoveSource is the durable handoff to the delayed delete janitor.
type TombstonedMoveSource struct {
	OperationID               string `json:"operation_id"`
	ManifestSHA256            string `json:"manifest_sha256"`
	RecoverySHA256            string `json:"recovery_sha256"`
	SourceDriverID            string `json:"source_driver_id"`
	SourceLocationsTombstoned uint64 `json:"source_locations_tombstoned"`
	RecoveryRevision          uint64 `json:"recovery_revision"`
	GraceUntil                uint64 `json:"grace_until"`
	State                     string `json:"state"`
}

type createMoveOperationBody struct {
	NamespaceID         string `json:"namespace_id"`
	ManifestSHA256      string `json:"manifest_sha256"`
	SourceDriverID      string `json:"source_driver_id"`
	DestinationDriverID string `json:"destination_driver_id"`
	IdempotencyKey      string `json:"idempotency_key"`
}

// CreateMoveOperation creates or returns an idempotent pinned move intent.
func (client *ControlClient) CreateMoveOperation(
	ctx context.Context,
	requested CreateMoveOperationRequest,
) (MoveOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.SourceDriverID, 256) ||
		!validControlString(requested.DestinationDriverID, 256) ||
		requested.SourceDriverID == requested.DestinationDriverID ||
		!validControlString(requested.IdempotencyKey, 256) {
		return MoveOperation{}, fmt.Errorf("%w: invalid move operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createMoveOperationBody(requested))
	if err != nil {
		return MoveOperation{}, fmt.Errorf("marshal move operation: %w", err)
	}

	var response MoveOperation
	if err := client.authenticatedPost(ctx, "/api/v1/moves", body, &response); err != nil {
		return MoveOperation{}, err
	}

	if !validMoveOperation(response, requested) {
		return MoveOperation{}, fmt.Errorf("%w: invalid move operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimMoveOperation acquires or renews the current move write fence.
func (client *ControlClient) ClaimMoveOperation(
	ctx context.Context,
	operation MoveOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindMove ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid move lease request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(claimOperationBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return OperationLease{}, fmt.Errorf("marshal move lease: %w", err)
	}

	var response OperationLease

	path := "/api/v1/operations/" + operation.ID + "/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return OperationLease{}, err
	}

	if response.OperationID != operation.ID || response.Incarnation != operation.Incarnation ||
		response.LeaseID == "" || response.OwnerClientID == "" || response.FencingToken == 0 ||
		response.OperationRevision == 0 || response.OperationState != operationStateRunning {
		return OperationLease{}, fmt.Errorf("%w: invalid move lease identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// FetchMoveManifest downloads the recovery snapshot pinned at move creation.
func (client *ControlClient) FetchMoveManifest(
	ctx context.Context,
	operation MoveOperation,
	lease OperationLease,
) (manifest.RecoveryManifest, error) {
	return client.fetchTransferManifest(
		ctx,
		"/api/v1/moves/"+operation.ID+"/manifest",
		lease,
		transferManifestIdentity{
			operationID: operation.ID, incarnation: operation.Incarnation,
			namespaceID: operation.NamespaceID, objectID: operation.ObjectID,
			generation: operation.Generation, manifestSHA256: operation.ManifestSHA256,
			recoverySHA256: operation.SourceRecoverySHA256, kind: "move",
		},
	)
}

// ReportMoveProgress idempotently records cumulative payload-copy counters.
func (client *ControlClient) ReportMoveProgress(
	ctx context.Context,
	operation MoveOperation,
	lease OperationLease,
	sample ProgressSample,
) (ProgressSnapshot, error) {
	if !validControlHex(operation.ID, 32) || lease.OperationID != operation.ID ||
		lease.LeaseID == "" || lease.Incarnation != operation.Incarnation ||
		lease.FencingToken == 0 || sample.Sequence == 0 || !signedProgressCounters(sample) {
		return ProgressSnapshot{}, fmt.Errorf("%w: invalid move progress", ErrInvalidControlPlane)
	}

	return client.reportOperationProgress(ctx, progressIdentity{
		operationID: operation.ID, componentID: operation.ID + "/move",
		leaseID: lease.LeaseID, incarnation: lease.Incarnation, fence: lease.FencingToken,
	}, sample)
}

// PublishMoveDestination publishes verified destination replicas but keeps the
// move operation active for its source-tombstone transition.
func (client *ControlClient) PublishMoveDestination(
	ctx context.Context,
	requested PublishMoveDestinationRequest,
) (PublishedMoveDestination, error) {
	if err := validateMovePublication(requested); err != nil {
		return PublishedMoveDestination{}, err
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
		return PublishedMoveDestination{}, fmt.Errorf("marshal move destination publication: %w", err)
	}

	var response PublishedMoveDestination
	if err := client.authenticatedPost(ctx, "/api/v1/moves/publish-destination", body, &response); err != nil {
		return PublishedMoveDestination{}, err
	}

	if response.OperationID != requested.Operation.ID ||
		response.ManifestSHA256 != requested.Operation.ManifestSHA256 ||
		response.RecoverySHA256 != requested.StagedRecovery.RecoverySHA256 ||
		response.DestinationDriverID != requested.Operation.DestinationDriverID ||
		response.LocationsAdded != uint64(len(requested.Result.Locations)) ||
		response.RecoveryRevision != requested.Operation.SourceRecoveryRevision+1 ||
		response.State != "destination_published" {
		return PublishedMoveDestination{}, fmt.Errorf("%w: published move identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// TombstoneMoveSource removes exactly the source locations pinned by the move.
func (client *ControlClient) TombstoneMoveSource(
	ctx context.Context,
	requested TombstoneMoveSourceRequest,
) (TombstonedMoveSource, error) {
	if err := validateMoveTombstone(requested); err != nil {
		return TombstonedMoveSource{}, err
	}

	body, err := json.Marshal(publishCopyBody{
		OperationID: requested.Operation.ID, LeaseID: requested.Lease.LeaseID,
		Incarnation: requested.Lease.Incarnation, FencingToken: requested.Lease.FencingToken,
		ManifestSHA256: requested.StagedRecovery.ManifestSHA256,
		RecoverySHA256: requested.StagedRecovery.RecoverySHA256,
		R2Key:          requested.StagedRecovery.R2Key, R2Version: requested.StagedRecovery.R2Version,
		SidecarDriverID:   requested.Operation.DestinationDriverID,
		SidecarStorageKey: requested.FinalSidecar.Key,
	})
	if err != nil {
		return TombstonedMoveSource{}, fmt.Errorf("marshal move tombstone: %w", err)
	}

	var response TombstonedMoveSource
	if err := client.authenticatedPost(ctx, "/api/v1/moves/tombstone-source", body, &response); err != nil {
		return TombstonedMoveSource{}, err
	}

	if response.OperationID != requested.Operation.ID ||
		response.ManifestSHA256 != requested.Operation.ManifestSHA256 ||
		response.RecoverySHA256 != requested.StagedRecovery.RecoverySHA256 ||
		response.SourceDriverID != requested.Operation.SourceDriverID ||
		response.SourceLocationsTombstoned != requested.Operation.SourceLocationCount ||
		response.RecoveryRevision != requested.Operation.SourceRecoveryRevision+2 ||
		response.GraceUntil == 0 || response.State != "source_delete_pending" {
		return TombstonedMoveSource{}, fmt.Errorf("%w: tombstoned move identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func validMoveOperation(response MoveOperation, requested CreateMoveOperationRequest) bool {
	return validMoveOperationIdentity(response, requested) && validMoveOperationPolicy(response, requested)
}

func validMoveOperationIdentity(response MoveOperation, requested CreateMoveOperationRequest) bool {
	return validControlHex(response.ID, 32) && response.NamespaceID == requested.NamespaceID &&
		response.Kind == operationKindMove && response.State != "" && response.Phase != "" &&
		response.RequestedBy != "" && validControlHex(response.Incarnation, 32) &&
		response.Revision > 0 && response.VersionID != "" && response.ObjectID != "" &&
		response.Generation > 0 && response.ManifestSHA256 == requested.ManifestSHA256 &&
		validControlHex(response.SourceRecoverySHA256, 64) && response.SourceRecoveryRevision > 0 &&
		response.SourceRecoveryRevision < math.MaxUint64
}

func validMoveOperationPolicy(response MoveOperation, requested CreateMoveOperationRequest) bool {
	return response.SourceDriverID == requested.SourceDriverID &&
		response.DestinationDriverID == requested.DestinationDriverID &&
		response.SourceLocationCount > 0 && response.MinimumAvailableReplicas > 0 &&
		response.GraceSeconds > 0 && response.MoveState != ""
}

func validateMovePublication(requested PublishMoveDestinationRequest) error {
	operation := requested.Operation
	if operation.Kind != operationKindMove || !validControlHex(operation.ID, 32) ||
		!validControlHex(operation.Incarnation, 32) || requested.Lease.OperationID != operation.ID ||
		requested.Lease.LeaseID == "" || requested.Lease.FencingToken == 0 ||
		requested.Lease.Incarnation != operation.Incarnation ||
		operation.SourceRecoveryRevision == 0 || operation.SourceRecoveryRevision == math.MaxUint64 ||
		!validControlString(operation.DestinationDriverID, 256) ||
		!validControlString(requested.Result.RecoveryKey, 4_096) ||
		!validControlString(requested.StagedRecovery.R2Key, 4_096) ||
		!validControlString(requested.StagedRecovery.R2Version, 1_024) {
		return fmt.Errorf("%w: invalid move publication fence", ErrInvalidControlPlane)
	}

	copyOperation := CopyOperation{
		ID: operation.ID, NamespaceID: operation.NamespaceID, Kind: operationKindCopy,
		Incarnation: operation.Incarnation, ObjectID: operation.ObjectID,
		Generation: operation.Generation, ManifestSHA256: operation.ManifestSHA256,
		SourceRecoveryRevision: operation.SourceRecoveryRevision,
		DestinationDriverID:    operation.DestinationDriverID,
	}

	return validateCopiedRecovery(PublishCopyRequest{
		Operation: copyOperation, Lease: requested.Lease,
		StagedRecovery: requested.StagedRecovery, Result: requested.Result,
	})
}

func validateMoveTombstone(requested TombstoneMoveSourceRequest) error {
	operation := requested.Operation
	if operation.Kind != operationKindMove || requested.Lease.OperationID != operation.ID ||
		requested.Lease.LeaseID == "" || requested.Lease.FencingToken == 0 ||
		requested.Lease.Incarnation != operation.Incarnation ||
		!validControlString(requested.FinalSidecar.Key, 4_096) ||
		!validControlString(requested.StagedRecovery.R2Key, 4_096) ||
		!validControlString(requested.StagedRecovery.R2Version, 1_024) {
		return fmt.Errorf("%w: invalid move tombstone fence", ErrInvalidControlPlane)
	}

	if err := requested.CurrentRecovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid current move recovery: %w", ErrInvalidControlPlane, err)
	}

	if err := requested.FinalSidecar.Recovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid final move recovery: %w", ErrInvalidControlPlane, err)
	}

	finalDigest, err := recoveryDigest(requested.FinalSidecar.Recovery)
	if err != nil {
		return err
	}

	if requested.FinalSidecar.Recovery.ManifestSHA256 != operation.ManifestSHA256 ||
		requested.StagedRecovery.ManifestSHA256 != operation.ManifestSHA256 ||
		requested.StagedRecovery.RecoverySHA256 != finalDigest ||
		requested.StagedRecovery.NamespaceID != operation.NamespaceID ||
		requested.StagedRecovery.ObjectID != operation.ObjectID ||
		requested.StagedRecovery.Generation != operation.Generation ||
		!moveLocationsRemovedExactly(
			requested.CurrentRecovery.Locations,
			requested.FinalSidecar.Recovery.Locations,
			operation.SourceDriverID,
			operation.SourceLocationCount,
		) {
		return fmt.Errorf("%w: move tombstone identities differ", ErrInvalidControlPlane)
	}

	return nil
}

func moveLocationsRemovedExactly(current, final []manifest.Location, sourceDriverID string, count uint64) bool {
	expected := make(map[replicationLocationIdentity]manifest.Location, len(current))
	removed := uint64(0)

	for _, location := range current {
		if location.DriverID == sourceDriverID {
			removed++

			continue
		}

		expected[replicationLocationKey(location)] = location
	}

	if removed != count || len(expected) != len(final) {
		return false
	}

	for _, location := range final {
		prior, ok := expected[replicationLocationKey(location)]
		if !ok || prior.ProviderVersion != location.ProviderVersion {
			return false
		}
	}

	return true
}
