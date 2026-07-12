package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/dravengarden/carrack/manifest"
)

const operationKindReconcile = "reconcile"

// CreateReconcileOperationRequest identifies one idempotent metadata audit.
type CreateReconcileOperationRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	IdempotencyKey string
}

// ReconcileOperation pins one published recovery revision and replica policy.
type ReconcileOperation struct {
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
	ManifestSHA256           string `json:"manifest_sha256"`
	RecoveryRevision         uint64 `json:"recovery_revision"`
	MinimumAvailableReplicas uint64 `json:"minimum_available_replicas"`
	CompletedReportSHA256    string `json:"completed_report_sha256"`
	CompletedUnindexed       uint64 `json:"completed_unindexed"`
	CompletedOrphan          uint64 `json:"completed_orphan"`
	CompletedDegraded        uint64 `json:"completed_degraded"`
	CreatedAt                uint64 `json:"created_at"`
	UpdatedAt                uint64 `json:"updated_at"`
}

// ReconcileSnapshot is one fenced recovery and D1 metadata view.
type ReconcileSnapshot struct {
	Recovery                 manifest.RecoveryManifest `json:"recovery"`
	RecoveryRevision         uint64                    `json:"recovery_revision"`
	MinimumAvailableReplicas uint64                    `json:"minimum_available_replicas"`
	Locations                []IndexedLocation         `json:"locations"`
}

type createReconcileOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	IdempotencyKey string `json:"idempotency_key"`
}

type reconcileSnapshotBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type completeReconcileBody struct {
	LeaseID        string                   `json:"lease_id"`
	Incarnation    string                   `json:"incarnation"`
	FencingToken   uint64                   `json:"fencing_token"`
	ManifestSHA256 string                   `json:"manifest_sha256"`
	Evidence       []ReconciliationEvidence `json:"evidence"`
}

// CompletedReconcile confirms durable findings and released ownership.
type CompletedReconcile struct {
	OperationID    string `json:"operation_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	State          string `json:"state"`
	ReportSHA256   string `json:"report_sha256"`
	Unindexed      uint64 `json:"unindexed"`
	Orphan         uint64 `json:"orphan"`
	Degraded       uint64 `json:"degraded"`
}

// CreateReconcileOperation creates or returns one pinned metadata audit.
func (client *ControlClient) CreateReconcileOperation(
	ctx context.Context,
	requested CreateReconcileOperationRequest,
) (ReconcileOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ReconcileOperation{}, fmt.Errorf("%w: invalid reconcile operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createReconcileOperationBody(requested))
	if err != nil {
		return ReconcileOperation{}, fmt.Errorf("marshal reconcile operation: %w", err)
	}

	var response ReconcileOperation
	if err := client.authenticatedPost(ctx, "/api/v1/reconciliations", body, &response); err != nil {
		return ReconcileOperation{}, err
	}

	if !validReconcileOperation(response, requested) {
		return ReconcileOperation{}, fmt.Errorf("%w: invalid reconcile operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

func validReconcileOperation(
	operation ReconcileOperation,
	requested CreateReconcileOperationRequest,
) bool {
	return operation.NamespaceID == requested.NamespaceID &&
		operation.ManifestSHA256 == requested.ManifestSHA256 &&
		operation.Kind == operationKindReconcile && validReconcileOperationState(operation) &&
		validReconcileCompletion(operation) && validControlHex(operation.ID, 32) &&
		validControlHex(operation.Incarnation, 32) &&
		validControlString(operation.RequestedBy, 2_048) &&
		validControlString(operation.VersionID, 2_048) && operation.Revision > 0 &&
		operation.UsefulBytesTotal > 0 && operation.UsefulBytesTotal <= math.MaxInt64 &&
		operation.RecoveryRevision > 0 && operation.MinimumAvailableReplicas > 0 &&
		operation.MinimumAvailableReplicas <= 64 && operation.CreatedAt > 0 &&
		operation.UpdatedAt >= operation.CreatedAt
}

func validReconcileOperationState(operation ReconcileOperation) bool {
	switch operation.State {
	case operationStatePlanned:
		return operation.Phase == operationStatePlanned
	case operationStateRunning:
		return operation.Phase == "reconciling"
	case operationStateSucceeded:
		return operation.Phase == operationPhaseCompleted
	case operationStateFailed, operationStateCancelled:
		return operation.Phase == operationPhaseRecovered
	default:
		return false
	}
}

func validReconcileCompletion(operation ReconcileOperation) bool {
	for _, count := range []uint64{
		operation.CompletedUnindexed,
		operation.CompletedOrphan,
		operation.CompletedDegraded,
	} {
		if count > math.MaxInt64 {
			return false
		}
	}

	if operation.State == operationStateSucceeded {
		return validControlHex(operation.CompletedReportSHA256, 64)
	}

	return operation.CompletedReportSHA256 == "" && operation.CompletedUnindexed == 0 &&
		operation.CompletedOrphan == 0 && operation.CompletedDegraded == 0
}

// ClaimReconcileOperation acquires or renews the metadata audit fence.
func (client *ControlClient) ClaimReconcileOperation(
	ctx context.Context,
	operation ReconcileOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindReconcile || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid reconcile lease request", ErrInvalidControlPlane)
	}

	return client.claimOperation(
		ctx,
		operation.ID,
		operation.Incarnation,
		leaseSeconds,
		operationKindReconcile,
	)
}

// FetchReconcileSnapshot obtains recovery and D1 locations under one live fence.
func (client *ControlClient) FetchReconcileSnapshot(
	ctx context.Context,
	operation ReconcileOperation,
	lease OperationLease,
) (ReconcileSnapshot, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return ReconcileSnapshot{}, fmt.Errorf("%w: invalid reconcile snapshot fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(reconcileSnapshotBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
	})
	if err != nil {
		return ReconcileSnapshot{}, fmt.Errorf("marshal reconcile snapshot fence: %w", err)
	}

	var response ReconcileSnapshot

	path := "/api/v1/reconciliations/" + operation.ID + "/snapshot"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return ReconcileSnapshot{}, err
	}

	if err := response.Recovery.Validate(); err != nil {
		return ReconcileSnapshot{}, fmt.Errorf("%w: invalid reconcile recovery: %w", ErrControlPlaneResponse, err)
	}

	if response.Recovery.ManifestSHA256 != operation.ManifestSHA256 ||
		response.RecoveryRevision != operation.RecoveryRevision ||
		response.MinimumAvailableReplicas != operation.MinimumAvailableReplicas ||
		response.Locations == nil {
		return ReconcileSnapshot{}, fmt.Errorf("%w: reconcile snapshot identity changed", ErrControlPlaneResponse)
	}

	for _, location := range response.Locations {
		if err := validateIndexedLocation(location); err != nil {
			return ReconcileSnapshot{}, fmt.Errorf("%w: reconcile snapshot location: %w", ErrControlPlaneResponse, err)
		}
	}

	return response, nil
}

// CompleteReconcile submits the deterministic report for server recomputation and commit.
func (client *ControlClient) CompleteReconcile(
	ctx context.Context,
	operation ReconcileOperation,
	lease OperationLease,
	result ReconciliationResult,
) (CompletedReconcile, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 ||
		result.ManifestSHA256 != operation.ManifestSHA256 {
		return CompletedReconcile{}, fmt.Errorf("%w: invalid reconcile completion", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(completeReconcileBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, ManifestSHA256: result.ManifestSHA256,
		Evidence: result.Evidence,
	})
	if err != nil {
		return CompletedReconcile{}, fmt.Errorf("marshal reconcile completion: %w", err)
	}

	var response CompletedReconcile

	path := "/api/v1/reconciliations/" + operation.ID + "/complete"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedReconcile{}, err
	}

	if response.OperationID != operation.ID || response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.State != operationStateSucceeded || !validControlHex(response.ReportSHA256, 64) ||
		response.Unindexed != result.RecoveryOnly ||
		response.Orphan != result.IndexOnly || response.Degraded != result.Degraded {
		return CompletedReconcile{}, fmt.Errorf("%w: reconcile completion identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}
