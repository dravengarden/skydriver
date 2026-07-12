package sdk

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
)

const operationProtocolRepair = "repair"

// CreateRepairOperationRequest identifies one idempotent missing-location repair.
type CreateRepairOperationRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	TargetDriverID string
	IdempotencyKey string
}

// RepairOperation pins one recovery revision and exact missing-location set.
// Kind remains copy because repair is a location-preserving copy protocol.
type RepairOperation struct {
	ID                  string `json:"id"`
	NamespaceID         string `json:"namespace_id"`
	Kind                string `json:"kind"`
	State               string `json:"state"`
	Phase               string `json:"phase"`
	RequestedBy         string `json:"requested_by"`
	Incarnation         string `json:"incarnation"`
	Revision            uint64 `json:"revision"`
	UsefulBytesTotal    uint64 `json:"useful_bytes_total"`
	VersionID           string `json:"version_id"`
	ObjectID            string `json:"object_id"`
	Generation          uint64 `json:"generation"`
	ManifestSHA256      string `json:"manifest_sha256"`
	RecoveryRevision    uint64 `json:"recovery_revision"`
	TargetDriverID      string `json:"target_driver_id"`
	ExpectedObjectCount uint64 `json:"expected_object_count"`
	ExpectedTargetCount uint64 `json:"expected_target_count"`
	CreatedAt           uint64 `json:"created_at"`
	UpdatedAt           uint64 `json:"updated_at"`
}

// RepairSnapshot contains the server-pinned targets and all candidate sources.
type RepairSnapshot struct {
	Recovery          manifest.RecoveryManifest `json:"recovery"`
	RecoveryRevision  uint64                    `json:"recovery_revision"`
	TargetDriverID    string                    `json:"target_driver_id"`
	TargetLocationIDs []string                  `json:"target_location_ids"`
	Locations         []IndexedLocation         `json:"locations"`
}

// CompletedRepair confirms that exact missing locations became available
// without changing the portable recovery head.
type CompletedRepair struct {
	OperationID       string `json:"operation_id"`
	ManifestSHA256    string `json:"manifest_sha256"`
	State             string `json:"state"`
	ObjectsRepaired   uint64 `json:"objects_repaired"`
	LocationsRepaired uint64 `json:"locations_repaired"`
	CiphertextBytes   uint64 `json:"ciphertext_bytes"`
	RecoveryRevision  uint64 `json:"recovery_revision"`
}

type createRepairOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	TargetDriverID string `json:"target_driver_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

type repairSnapshotBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type completeRepairBody struct {
	LeaseID        string                  `json:"lease_id"`
	Incarnation    string                  `json:"incarnation"`
	FencingToken   uint64                  `json:"fencing_token"`
	ManifestSHA256 string                  `json:"manifest_sha256"`
	Objects        []completedRepairObject `json:"objects"`
}

type completedRepairObject struct {
	DriverID        string `json:"driver_id"`
	StorageKey      string `json:"storage_key"`
	ProviderVersion string `json:"provider_version,omitempty"`
	ETag            string `json:"etag,omitempty"`
	SizeBytes       uint64 `json:"size_bytes"`
}

// CreateRepairOperation creates or returns one exact missing-location plan.
func (client *ControlClient) CreateRepairOperation(
	ctx context.Context,
	requested CreateRepairOperationRequest,
) (RepairOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.TargetDriverID, 256) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return RepairOperation{}, fmt.Errorf("%w: invalid repair operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createRepairOperationBody(requested))
	if err != nil {
		return RepairOperation{}, fmt.Errorf("marshal repair operation: %w", err)
	}

	var response RepairOperation
	if err := client.authenticatedPost(ctx, "/api/v1/repairs", body, &response); err != nil {
		return RepairOperation{}, err
	}

	if !validRepairOperation(response, requested) {
		return RepairOperation{}, fmt.Errorf("%w: invalid repair operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimRepairOperation acquires or renews the repair write fence.
func (client *ControlClient) ClaimRepairOperation(
	ctx context.Context,
	operation RepairOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindCopy || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid repair lease request", ErrInvalidControlPlane)
	}

	return client.claimOperation(
		ctx,
		operation.ID,
		operation.Incarnation,
		leaseSeconds,
		operationProtocolRepair,
	)
}

// FetchRepairSnapshot obtains the exact targets and current source candidates
// under one live operation fence.
func (client *ControlClient) FetchRepairSnapshot(
	ctx context.Context,
	operation RepairOperation,
	lease OperationLease,
) (RepairSnapshot, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return RepairSnapshot{}, fmt.Errorf("%w: invalid repair snapshot fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(repairSnapshotBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
	})
	if err != nil {
		return RepairSnapshot{}, fmt.Errorf("marshal repair snapshot fence: %w", err)
	}

	var response RepairSnapshot

	path := "/api/v1/repairs/" + operation.ID + "/snapshot"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return RepairSnapshot{}, err
	}

	if err := validateRepairSnapshot(response, operation); err != nil {
		return RepairSnapshot{}, err
	}

	return response, nil
}

// CompleteRepair atomically reactivates the pinned missing locations after all
// reconstructed provider objects have passed independent readback.
func (client *ControlClient) CompleteRepair(
	ctx context.Context,
	operation RepairOperation,
	lease OperationLease,
	plan RepairPlan,
	result RepairResult,
) (CompletedRepair, error) {
	objects, err := validateRepairCompletion(operation, lease, plan, result)
	if err != nil {
		return CompletedRepair{}, err
	}

	body, err := json.Marshal(completeRepairBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, ManifestSHA256: result.ManifestSHA256,
		Objects: objects,
	})
	if err != nil {
		return CompletedRepair{}, fmt.Errorf("marshal repair completion: %w", err)
	}

	var response CompletedRepair

	path := "/api/v1/repairs/" + operation.ID + "/complete"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedRepair{}, err
	}

	if response.OperationID != operation.ID ||
		response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.State != operationStateSucceeded ||
		response.ObjectsRepaired != operation.ExpectedObjectCount ||
		response.LocationsRepaired != operation.ExpectedTargetCount ||
		response.CiphertextBytes != operation.UsefulBytesTotal ||
		response.RecoveryRevision != operation.RecoveryRevision {
		return CompletedRepair{}, fmt.Errorf("%w: repair completion identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func validateRepairCompletion(
	operation RepairOperation,
	lease OperationLease,
	plan RepairPlan,
	result RepairResult,
) ([]completedRepairObject, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 ||
		plan.ManifestSHA256 != operation.ManifestSHA256 ||
		result.ManifestSHA256 != operation.ManifestSHA256 ||
		uint64(len(plan.Objects)) != operation.ExpectedObjectCount ||
		uint64(len(result.ProviderObjects)) != operation.ExpectedObjectCount ||
		result.ObjectsRepaired != operation.ExpectedObjectCount ||
		result.CiphertextBytes != operation.UsefulBytesTotal {
		return nil, fmt.Errorf("%w: invalid repair completion", ErrInvalidControlPlane)
	}

	plannedByKey := make(map[string]RepairObject, len(plan.Objects))
	for _, object := range plan.Objects {
		if object.DriverID != operation.TargetDriverID || object.Length == 0 {
			return nil, fmt.Errorf("%w: repair plan changed its target", ErrInvalidControlPlane)
		}

		if _, duplicate := plannedByKey[object.StorageKey]; duplicate {
			return nil, fmt.Errorf("%w: duplicate repair plan object", ErrInvalidControlPlane)
		}

		plannedByKey[object.StorageKey] = object
	}

	objects := make([]completedRepairObject, 0, len(result.ProviderObjects))
	for _, uploaded := range result.ProviderObjects {
		completed, completionErr := completedRepairEvidence(
			operation.TargetDriverID,
			uploaded,
			plannedByKey,
		)
		if completionErr != nil {
			return nil, completionErr
		}

		delete(plannedByKey, uploaded.Key)

		objects = append(objects, completed)
	}

	if len(plannedByKey) != 0 {
		return nil, fmt.Errorf("%w: repair result omitted a provider object", ErrInvalidControlPlane)
	}

	slices.SortFunc(objects, func(left, right completedRepairObject) int {
		return cmp.Compare(left.StorageKey, right.StorageKey)
	})

	return objects, nil
}

func completedRepairEvidence(
	driverID string,
	uploaded provider.Object,
	planned map[string]RepairObject,
) (completedRepairObject, error) {
	expected, exists := planned[uploaded.Key]
	if !exists || uploaded.SizeBytes != expected.Length ||
		(expected.ProviderVersion != "" && uploaded.Version != expected.ProviderVersion) ||
		(uploaded.Version != "" && !validControlString(uploaded.Version, 1_024)) ||
		(uploaded.ETag != "" && !validControlString(uploaded.ETag, 4_096)) {
		return completedRepairObject{}, fmt.Errorf(
			"%w: repaired provider object changed identity",
			ErrInvalidControlPlane,
		)
	}

	return completedRepairObject{
		DriverID: driverID, StorageKey: uploaded.Key, ProviderVersion: uploaded.Version,
		ETag: uploaded.ETag, SizeBytes: uploaded.SizeBytes,
	}, nil
}

func validRepairOperation(
	response RepairOperation,
	requested CreateRepairOperationRequest,
) bool {
	return validControlHex(response.ID, 32) && response.NamespaceID == requested.NamespaceID &&
		response.Kind == operationKindCopy && validRepairOperationState(response) &&
		validControlString(response.RequestedBy, 2_048) &&
		validControlHex(response.Incarnation, 32) && response.Revision > 0 &&
		response.UsefulBytesTotal > 0 && response.UsefulBytesTotal <= math.MaxInt64 &&
		validControlString(response.VersionID, 2_048) &&
		validControlString(response.ObjectID, 2_048) && response.Generation > 0 &&
		response.ManifestSHA256 == requested.ManifestSHA256 && response.RecoveryRevision > 0 &&
		response.TargetDriverID == requested.TargetDriverID && response.ExpectedObjectCount > 0 &&
		response.ExpectedTargetCount > 0
}

func validRepairOperationState(operation RepairOperation) bool {
	switch operation.State {
	case operationStatePlanned:
		return operation.Phase == operationStatePlanned
	case operationStateRunning:
		return operation.Phase == "repairing"
	case operationStateSucceeded:
		return operation.Phase == "completed"
	case operationStateFailed, "cancelled":
		return operation.Phase == "control_plane_recovered"
	default:
		return false
	}
}

func validateRepairSnapshot(response RepairSnapshot, operation RepairOperation) error {
	if err := response.Recovery.Validate(); err != nil {
		return fmt.Errorf("%w: invalid repair recovery: %w", ErrControlPlaneResponse, err)
	}

	if response.Recovery.ManifestSHA256 != operation.ManifestSHA256 ||
		response.RecoveryRevision != operation.RecoveryRevision ||
		response.TargetDriverID != operation.TargetDriverID || response.Locations == nil ||
		uint64(len(response.TargetLocationIDs)) != operation.ExpectedTargetCount {
		return fmt.Errorf("%w: repair snapshot identity changed", ErrControlPlaneResponse)
	}

	locationsByID := make(map[string]IndexedLocation, len(response.Locations))
	for _, location := range response.Locations {
		if err := validateIndexedLocation(location); err != nil {
			return fmt.Errorf("%w: repair snapshot location: %w", ErrControlPlaneResponse, err)
		}

		if _, duplicate := locationsByID[location.ID]; duplicate {
			return fmt.Errorf("%w: duplicate repair snapshot location ID", ErrControlPlaneResponse)
		}

		locationsByID[location.ID] = location
	}

	targets := make(map[string]struct{}, len(response.TargetLocationIDs))
	for _, locationID := range response.TargetLocationIDs {
		if !validControlHex(locationID, 64) {
			return fmt.Errorf("%w: malformed repair target ID", ErrControlPlaneResponse)
		}

		if _, duplicate := targets[locationID]; duplicate {
			return fmt.Errorf("%w: duplicate repair target ID", ErrControlPlaneResponse)
		}

		targets[locationID] = struct{}{}

		location, exists := locationsByID[locationID]
		if !exists || location.DriverID != operation.TargetDriverID ||
			location.State != indexedStateMissing {
			return fmt.Errorf("%w: repair target is not pinned missing metadata", ErrControlPlaneResponse)
		}
	}

	return nil
}
