package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
)

// CreateRestoreOperationRequest pins one published immutable manifest.
type CreateRestoreOperationRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	IdempotencyKey string
}

// RestoreOperation is the durable control-plane identity for one local restore.
type RestoreOperation struct {
	ID               string `json:"id"`
	NamespaceID      string `json:"namespace_id"`
	Kind             string `json:"kind"`
	State            string `json:"state"`
	Phase            string `json:"phase"`
	RequestedBy      string `json:"requested_by"`
	Incarnation      string `json:"incarnation"`
	Revision         uint64 `json:"revision"`
	UsefulBytesTotal uint64 `json:"useful_bytes_total"`
	VersionID        string `json:"version_id"`
	ObjectID         string `json:"object_id"`
	Generation       uint64 `json:"generation"`
	ManifestSHA256   string `json:"manifest_sha256"`
	CreatedAt        uint64 `json:"created_at"`
	UpdatedAt        uint64 `json:"updated_at"`
}

// RestoreReadLease protects the pinned version from final-replica deletion.
type RestoreReadLease struct {
	OperationID       string `json:"operation_id"`
	LeaseID           string `json:"lease_id"`
	OwnerClientID     string `json:"owner_client_id"`
	Incarnation       string `json:"incarnation"`
	FencingToken      uint64 `json:"fencing_token"`
	ExpiresAt         uint64 `json:"expires_at"`
	OperationRevision uint64 `json:"operation_revision"`
	OperationState    string `json:"operation_state"`
	VersionID         string `json:"version_id"`
	ManifestSHA256    string `json:"manifest_sha256"`
}

// CompletedRestore confirms that the pinned plaintext was verified locally.
type CompletedRestore struct {
	OperationID    string `json:"operation_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	State          string `json:"state"`
}

type createRestoreOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	IdempotencyKey string `json:"idempotency_key"`
}

type completeRestoreBody struct {
	LeaseID         string `json:"lease_id"`
	Incarnation     string `json:"incarnation"`
	FencingToken    uint64 `json:"fencing_token"`
	ManifestSHA256  string `json:"manifest_sha256"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	PlaintextBytes  uint64 `json:"plaintext_bytes"`
}

// CreateRestoreOperation creates or returns an idempotent manifest pin.
func (client *ControlClient) CreateRestoreOperation(
	ctx context.Context,
	requested CreateRestoreOperationRequest,
) (RestoreOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return RestoreOperation{}, fmt.Errorf("%w: invalid restore operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createRestoreOperationBody(requested))
	if err != nil {
		return RestoreOperation{}, fmt.Errorf("marshal restore operation: %w", err)
	}

	var response RestoreOperation
	if err := client.authenticatedPost(ctx, "/api/v1/restores", body, &response); err != nil {
		return RestoreOperation{}, err
	}

	if !validRestoreOperation(response, requested) {
		return RestoreOperation{}, fmt.Errorf("%w: invalid restore operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimRestoreOperation acquires or renews the operation-scoped read lease.
func (client *ControlClient) ClaimRestoreOperation(
	ctx context.Context,
	operation RestoreOperation,
	leaseSeconds uint64,
) (RestoreReadLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		!validControlHex(operation.ManifestSHA256, 64) || operation.VersionID == "" ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return RestoreReadLease{}, fmt.Errorf("%w: invalid restore lease request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(claimOperationBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return RestoreReadLease{}, fmt.Errorf("marshal restore lease: %w", err)
	}

	var response RestoreReadLease

	path := "/api/v1/restores/" + operation.ID + "/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return RestoreReadLease{}, err
	}

	if response.OperationID != operation.ID || response.Incarnation != operation.Incarnation ||
		response.VersionID != operation.VersionID || response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.LeaseID == "" || response.OwnerClientID == "" || response.FencingToken == 0 ||
		response.OperationRevision == 0 || response.OperationState != "running" {
		return RestoreReadLease{}, fmt.Errorf("%w: invalid restore lease identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// CompleteRestoreOperation records verified plaintext and releases the read lease.
func (client *ControlClient) CompleteRestoreOperation(
	ctx context.Context,
	operation RestoreOperation,
	lease RestoreReadLease,
	result RestoreResult,
	plaintextSHA256 string,
) (CompletedRestore, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.VersionID != operation.VersionID || result.ManifestSHA256 != operation.ManifestSHA256 ||
		result.PlaintextBytes != operation.UsefulBytesTotal || !validControlHex(plaintextSHA256, 64) ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return CompletedRestore{}, fmt.Errorf("%w: invalid restore completion", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(completeRestoreBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
		ManifestSHA256:  operation.ManifestSHA256,
		PlaintextSHA256: plaintextSHA256, PlaintextBytes: result.PlaintextBytes,
	})
	if err != nil {
		return CompletedRestore{}, fmt.Errorf("marshal restore completion: %w", err)
	}

	var response CompletedRestore

	path := "/api/v1/restores/" + operation.ID + "/complete"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedRestore{}, err
	}

	if response.OperationID != operation.ID || response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.State != "succeeded" {
		return CompletedRestore{}, fmt.Errorf("%w: invalid restore completion identity", ErrControlPlaneResponse)
	}

	return response, nil
}

func validRestoreOperation(
	operation RestoreOperation,
	requested CreateRestoreOperationRequest,
) bool {
	return validControlHex(operation.ID, 32) && operation.NamespaceID == requested.NamespaceID &&
		operation.Kind == "restore" && operation.State == "planned" && operation.Phase == "planned" &&
		validControlHex(operation.Incarnation, 32) && operation.Revision > 0 &&
		operation.UsefulBytesTotal <= math.MaxInt64 && operation.VersionID != "" &&
		operation.ObjectID != "" && operation.Generation > 0 &&
		operation.ManifestSHA256 == requested.ManifestSHA256
}
