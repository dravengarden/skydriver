package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/dravengarden/carrack/manifest"
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
	ID                   string `json:"id"`
	NamespaceID          string `json:"namespace_id"`
	Kind                 string `json:"kind"`
	State                string `json:"state"`
	Phase                string `json:"phase"`
	RequestedBy          string `json:"requested_by"`
	Incarnation          string `json:"incarnation"`
	Revision             uint64 `json:"revision"`
	UsefulBytesTotal     uint64 `json:"useful_bytes_total"`
	VersionID            string `json:"version_id"`
	ManifestSHA256       string `json:"manifest_sha256"`
	RecoveryRevision     uint64 `json:"recovery_revision"`
	DriverID             string `json:"driver_id"`
	CompletedVerified    uint64 `json:"completed_verified"`
	CompletedMissing     uint64 `json:"completed_missing"`
	CompletedCorrupt     uint64 `json:"completed_corrupt"`
	CompletedUnavailable uint64 `json:"completed_unavailable"`
	CreatedAt            uint64 `json:"created_at"`
	UpdatedAt            uint64 `json:"updated_at"`
}

type createVerifyOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	DriverID       string `json:"driver_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

type verifyManifestBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type completeVerifyBody struct {
	LeaseID        string                 `json:"lease_id"`
	Incarnation    string                 `json:"incarnation"`
	FencingToken   uint64                 `json:"fencing_token"`
	ManifestSHA256 string                 `json:"manifest_sha256"`
	Evidence       []VerificationEvidence `json:"evidence"`
}

// CompletedVerify confirms durable evidence and released operation ownership.
type CompletedVerify struct {
	OperationID    string `json:"operation_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	State          string `json:"state"`
	Verified       uint64 `json:"verified"`
	Missing        uint64 `json:"missing"`
	Corrupt        uint64 `json:"corrupt"`
	Unavailable    uint64 `json:"unavailable"`
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

	if !validVerifyOperation(response, requested) {
		return VerifyOperation{}, fmt.Errorf("%w: invalid verify operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

func validVerifyOperation(
	operation VerifyOperation,
	requested CreateVerifyOperationRequest,
) bool {
	return operation.NamespaceID == requested.NamespaceID &&
		operation.ManifestSHA256 == requested.ManifestSHA256 &&
		operation.DriverID == requested.DriverID && operation.Kind == operationKindVerify &&
		validVerifyOperationState(operation) && validVerifyCompletionCounts(operation) &&
		validControlHex(operation.ID, 32) && validControlHex(operation.Incarnation, 32) &&
		validControlString(operation.RequestedBy, 2_048) &&
		validControlString(operation.VersionID, 2_048) && operation.Revision > 0 &&
		operation.RecoveryRevision > 0 && operation.UsefulBytesTotal > 0 &&
		operation.UsefulBytesTotal <= math.MaxInt64 && operation.CreatedAt > 0 &&
		operation.UpdatedAt >= operation.CreatedAt
}

func validVerifyOperationState(operation VerifyOperation) bool {
	switch operation.State {
	case operationStatePlanned:
		return operation.Phase == operationStatePlanned
	case operationStateRunning:
		return operation.Phase == "verifying"
	case operationStateSucceeded:
		return operation.Phase == operationPhaseCompleted
	case operationStateFailed, operationStateCancelled:
		return operation.Phase == operationPhaseRecovered
	default:
		return false
	}
}

func validVerifyCompletionCounts(operation VerifyOperation) bool {
	maximum := uint64(math.MaxInt64)
	total := uint64(0)

	for _, count := range []uint64{
		operation.CompletedVerified,
		operation.CompletedMissing,
		operation.CompletedCorrupt,
		operation.CompletedUnavailable,
	} {
		if count > maximum-total {
			return false
		}

		total += count
	}

	if operation.State == operationStateSucceeded {
		return total > 0
	}

	return total == 0
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

// FetchVerifyManifest downloads the pinned recovery metadata under the live fence.
func (client *ControlClient) FetchVerifyManifest(
	ctx context.Context,
	operation VerifyOperation,
	lease OperationLease,
) (manifest.RecoveryManifest, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 || operation.RecoveryRevision == 0 {
		return manifest.RecoveryManifest{}, fmt.Errorf("%w: invalid verify manifest fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(verifyManifestBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
	})
	if err != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf("marshal verify manifest fence: %w", err)
	}

	var response manifest.RecoveryManifest

	path := "/api/v1/verifications/" + operation.ID + "/manifest"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return manifest.RecoveryManifest{}, err
	}

	if err := response.Validate(); err != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf("%w: invalid verify manifest: %w", ErrControlPlaneResponse, err)
	}

	if response.ManifestSHA256 != operation.ManifestSHA256 {
		return manifest.RecoveryManifest{}, fmt.Errorf("%w: verify manifest identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// CompleteVerify atomically records the complete selected-driver evidence set.
func (client *ControlClient) CompleteVerify(
	ctx context.Context,
	operation VerifyOperation,
	lease OperationLease,
	result VerificationResult,
) (CompletedVerify, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 ||
		result.ManifestSHA256 != operation.ManifestSHA256 || len(result.Evidence) == 0 {
		return CompletedVerify{}, fmt.Errorf("%w: invalid verify completion", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(completeVerifyBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, ManifestSHA256: result.ManifestSHA256,
		Evidence: result.Evidence,
	})
	if err != nil {
		return CompletedVerify{}, fmt.Errorf("marshal verify completion: %w", err)
	}

	var response CompletedVerify

	path := "/api/v1/verifications/" + operation.ID + "/complete"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedVerify{}, err
	}

	if response.OperationID != operation.ID || response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.State != operationStateSucceeded || response.Verified != result.Verified ||
		response.Missing != result.Missing || response.Corrupt != result.Corrupt ||
		response.Unavailable != result.Unavailable {
		return CompletedVerify{}, fmt.Errorf("%w: verify completion identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}
