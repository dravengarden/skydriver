package sdk

import (
	"context"
	"encoding/json"
	"fmt"

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

	if response.NamespaceID != requested.NamespaceID ||
		response.ManifestSHA256 != requested.ManifestSHA256 ||
		response.Kind != operationKindReconcile || !validControlHex(response.ID, 32) ||
		!validControlHex(response.Incarnation, 32) ||
		!validControlString(response.VersionID, 2_048) || response.Revision == 0 ||
		response.RecoveryRevision == 0 || response.MinimumAvailableReplicas == 0 ||
		response.MinimumAvailableReplicas > 64 {
		return ReconcileOperation{}, fmt.Errorf("%w: invalid reconcile operation identity", ErrControlPlaneResponse)
	}

	return response, nil
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
