package sdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"

	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
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

type failRestoreBody struct {
	LeaseID        string `json:"lease_id"`
	Incarnation    string `json:"incarnation"`
	FencingToken   uint64 `json:"fencing_token"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ErrorCode      string `json:"error_code"`
}

type restoreManifestBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type restoreKeyGrantBody struct {
	LeaseID        string `json:"lease_id"`
	Incarnation    string `json:"incarnation"`
	FencingToken   uint64 `json:"fencing_token"`
	ManifestSHA256 string `json:"manifest_sha256"`
	RootVersion    uint32 `json:"root_version"`
	KeyEpoch       uint64 `json:"key_epoch"`
}

type restoreKeyGrant struct {
	OperationID    string `json:"operation_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	RootVersion    uint32 `json:"root_version"`
	KeyEpoch       uint64 `json:"key_epoch"`
	EpochKey       string `json:"epoch_key"`
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
		response.OperationRevision == 0 || response.OperationState != operationStateRunning {
		return RestoreReadLease{}, fmt.Errorf("%w: invalid restore lease identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// FetchRestoreManifest downloads the pinned portable metadata under a live read lease.
func (client *ControlClient) FetchRestoreManifest(
	ctx context.Context,
	operation RestoreOperation,
	lease RestoreReadLease,
) (manifest.RecoveryManifest, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.VersionID != operation.VersionID || lease.ManifestSHA256 != operation.ManifestSHA256 ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return manifest.RecoveryManifest{}, fmt.Errorf("%w: invalid restore manifest fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(restoreManifestBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
	})
	if err != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf("marshal restore manifest fence: %w", err)
	}

	var response manifest.RecoveryManifest

	path := "/api/v1/restores/" + operation.ID + "/manifest"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return manifest.RecoveryManifest{}, err
	}

	if err := response.Validate(); err != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf("%w: invalid restore manifest: %w", ErrControlPlaneResponse, err)
	}

	if response.ManifestSHA256 != operation.ManifestSHA256 {
		return manifest.RecoveryManifest{}, fmt.Errorf("%w: restore manifest identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// GrantRestoreEpochKey derives the pinned namespace epoch under a live read fence.
func (client *ControlClient) GrantRestoreEpochKey(
	ctx context.Context,
	operation RestoreOperation,
	lease RestoreReadLease,
	recovery manifest.RecoveryManifest,
) (cryptostream.EpochKey, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.ManifestSHA256 != operation.ManifestSHA256 ||
		recovery.ManifestSHA256 != operation.ManifestSHA256 || lease.LeaseID == "" ||
		lease.FencingToken == 0 {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: invalid restore key fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(restoreKeyGrantBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, ManifestSHA256: operation.ManifestSHA256,
		RootVersion: recovery.Manifest.Crypto.RootVersion,
		KeyEpoch:    recovery.Manifest.Crypto.KeyEpoch,
	})
	if err != nil {
		return cryptostream.EpochKey{}, fmt.Errorf("marshal restore key grant: %w", err)
	}

	var response restoreKeyGrant

	path := "/api/v1/restores/" + operation.ID + "/key"
	if requestErr := client.authenticatedPost(ctx, path, body, &response); requestErr != nil {
		return cryptostream.EpochKey{}, requestErr
	}

	if response.OperationID != operation.ID || response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.RootVersion != recovery.Manifest.Crypto.RootVersion ||
		response.KeyEpoch != recovery.Manifest.Crypto.KeyEpoch {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: restore key identity changed", ErrControlPlaneResponse)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(response.EpochKey)
	if err != nil || len(decoded) != len(cryptostream.EpochKey{}) {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: invalid restore epoch key", ErrControlPlaneResponse)
	}

	var combined byte
	for _, value := range decoded {
		combined |= value
	}

	if combined == 0 {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: zero restore epoch key", ErrControlPlaneResponse)
	}

	return cryptostream.EpochKey(decoded), nil
}

// ReportRestoreProgress idempotently records cumulative restore counters.
func (client *ControlClient) ReportRestoreProgress(
	ctx context.Context,
	operation RestoreOperation,
	lease RestoreReadLease,
	sample ProgressSample,
) (ProgressSnapshot, error) {
	if !validControlHex(operation.ID, 32) || lease.OperationID != operation.ID ||
		lease.LeaseID == "" || lease.Incarnation != operation.Incarnation ||
		lease.FencingToken == 0 || sample.Sequence == 0 || !signedProgressCounters(sample) {
		return ProgressSnapshot{}, fmt.Errorf("%w: invalid restore progress", ErrInvalidControlPlane)
	}

	return client.reportOperationProgress(ctx, progressIdentity{
		operationID: operation.ID,
		componentID: operation.ID + "/restore",
		leaseID:     lease.LeaseID,
		incarnation: lease.Incarnation,
		fence:       lease.FencingToken,
	}, sample)
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

// FailRestoreOperation records a terminal local integrity failure and releases the read lease.
func (client *ControlClient) FailRestoreOperation(
	ctx context.Context,
	operation RestoreOperation,
	lease RestoreReadLease,
	errorCode string,
) (CompletedRestore, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.VersionID != operation.VersionID || lease.ManifestSHA256 != operation.ManifestSHA256 ||
		lease.LeaseID == "" || lease.FencingToken == 0 || !validControlString(errorCode, 128) {
		return CompletedRestore{}, fmt.Errorf("%w: invalid restore failure", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(failRestoreBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
		ManifestSHA256: operation.ManifestSHA256, ErrorCode: errorCode,
	})
	if err != nil {
		return CompletedRestore{}, fmt.Errorf("marshal restore failure: %w", err)
	}

	var response CompletedRestore

	path := "/api/v1/restores/" + operation.ID + "/fail"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedRestore{}, err
	}

	if response.OperationID != operation.ID || response.ManifestSHA256 != operation.ManifestSHA256 ||
		response.State != "failed" {
		return CompletedRestore{}, fmt.Errorf("%w: invalid restore failure identity", ErrControlPlaneResponse)
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
