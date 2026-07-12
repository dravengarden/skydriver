package sdk

import (
	"context"
	"encoding/json"
	"fmt"
)

const operationKindVerify = "verify"

// CreateVerifyOperationRequest identifies one idempotent driver audit.
type CreateVerifyOperationRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	DriverID       string
	IdempotencyKey string
}

// VerifyOperation pins one published recovery revision and provider driver.
type VerifyOperation struct {
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
	ManifestSHA256   string `json:"manifest_sha256"`
	RecoveryRevision uint64 `json:"recovery_revision"`
	DriverID         string `json:"driver_id"`
	CreatedAt        uint64 `json:"created_at"`
	UpdatedAt        uint64 `json:"updated_at"`
}

type createVerifyOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	DriverID       string `json:"driver_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

// CreateVerifyOperation creates or returns a client-owned verification target.
func (client *ControlClient) CreateVerifyOperation(
	ctx context.Context,
	requested CreateVerifyOperationRequest,
) (VerifyOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.DriverID, 256) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return VerifyOperation{}, fmt.Errorf("%w: invalid verify operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createVerifyOperationBody(requested))
	if err != nil {
		return VerifyOperation{}, fmt.Errorf("marshal verify operation: %w", err)
	}

	var response VerifyOperation
	if err := client.authenticatedPost(ctx, "/api/v1/verifications", body, &response); err != nil {
		return VerifyOperation{}, err
	}

	if response.NamespaceID != requested.NamespaceID ||
		response.ManifestSHA256 != requested.ManifestSHA256 ||
		response.DriverID != requested.DriverID || response.Kind != operationKindVerify ||
		!validControlHex(response.ID, 32) || !validControlHex(response.Incarnation, 32) ||
		!validControlString(response.VersionID, 2_048) || response.Revision == 0 ||
		response.RecoveryRevision == 0 || response.UsefulBytesTotal == 0 {
		return VerifyOperation{}, fmt.Errorf("%w: invalid verify operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimVerifyOperation acquires or renews the verification write fence.
func (client *ControlClient) ClaimVerifyOperation(
	ctx context.Context,
	operation VerifyOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindVerify || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid verify lease request", ErrInvalidControlPlane)
	}

	return client.claimOperation(ctx, operation.ID, operation.Incarnation, leaseSeconds, operationKindVerify)
}
