package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
)

// QuarantineAction is one explicit provider-object review transition.
type QuarantineAction string

const (
	// QuarantineActionAcknowledge records completed ownership and recovery review.
	QuarantineActionAcknowledge QuarantineAction = "acknowledge"
	// QuarantineActionTombstone starts a new grace period before cleanup eligibility.
	QuarantineActionTombstone QuarantineAction = "tombstone"
)

// CreateQuarantineActionRequest pins one exact quarantine revision and operator reason.
type CreateQuarantineActionRequest struct {
	NamespaceID      string
	Action           QuarantineAction
	DriverID         string
	StorageKey       string
	ExpectedRevision uint64
	Reason           string
	IdempotencyKey   string
}

// QuarantineActionOperation is one durable, fenced review intent.
type QuarantineActionOperation struct {
	ID               string           `json:"id"`
	NamespaceID      string           `json:"namespace_id"`
	Kind             string           `json:"kind"`
	State            string           `json:"state"`
	Phase            string           `json:"phase"`
	RequestedBy      string           `json:"requested_by"`
	Incarnation      string           `json:"incarnation"`
	Revision         uint64           `json:"revision"`
	Action           QuarantineAction `json:"action"`
	DriverID         string           `json:"driver_id"`
	DriverRevision   uint64           `json:"driver_revision"`
	StorageKey       string           `json:"storage_key"`
	ExpectedRevision uint64           `json:"expected_revision"`
	ProviderVersion  string           `json:"provider_version,omitempty"`
	ETag             string           `json:"etag,omitempty"`
	SizeBytes        uint64           `json:"size_bytes"`
	Reason           string           `json:"reason"`
	GraceSeconds     uint64           `json:"grace_seconds"`
	ResultRevision   *uint64          `json:"result_revision,omitempty"`
	ResultState      *string          `json:"result_state,omitempty"`
	DeleteAfter      *uint64          `json:"delete_after,omitempty"`
	CreatedAt        uint64           `json:"created_at"`
	UpdatedAt        uint64           `json:"updated_at"`
}

type createQuarantineActionBody struct {
	NamespaceID      string           `json:"namespace_id"`
	Action           QuarantineAction `json:"action"`
	DriverID         string           `json:"driver_id"`
	StorageKey       string           `json:"storage_key"`
	ExpectedRevision uint64           `json:"expected_revision"`
	Reason           string           `json:"reason"`
	IdempotencyKey   string           `json:"idempotency_key"`
}

type completeQuarantineActionBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

// CompletedQuarantineAction confirms the exact D1 lifecycle transition.
type CompletedQuarantineAction struct {
	OperationID        string           `json:"operation_id"`
	Action             QuarantineAction `json:"action"`
	State              string           `json:"state"`
	QuarantineState    string           `json:"quarantine_state"`
	QuarantineRevision uint64           `json:"quarantine_revision"`
	DeleteAfter        *uint64          `json:"delete_after"`
}

// CreateQuarantineAction creates or returns one exact review intent.
func (client *ControlClient) CreateQuarantineAction(
	ctx context.Context,
	requested CreateQuarantineActionRequest,
) (QuarantineActionOperation, error) {
	if !validQuarantineActionRequest(requested) {
		return QuarantineActionOperation{}, fmt.Errorf("%w: invalid quarantine action request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createQuarantineActionBody(requested))
	if err != nil {
		return QuarantineActionOperation{}, fmt.Errorf("marshal quarantine action: %w", err)
	}

	var response QuarantineActionOperation
	if err := client.authenticatedPost(ctx, "/api/v1/quarantine-actions", body, &response); err != nil {
		return QuarantineActionOperation{}, err
	}

	if !validQuarantineActionOperation(response, requested) {
		return QuarantineActionOperation{}, fmt.Errorf("%w: quarantine action identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimQuarantineAction acquires the exact review operation fence.
func (client *ControlClient) ClaimQuarantineAction(
	ctx context.Context,
	operation QuarantineActionOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindGC || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid quarantine action lease", ErrInvalidControlPlane)
	}

	return client.claimOperation(ctx, operation.ID, operation.Incarnation, leaseSeconds, operationKindGC)
}

// CompleteQuarantineAction commits one acknowledged or tombstoned CAS transition.
func (client *ControlClient) CompleteQuarantineAction(
	ctx context.Context,
	operation QuarantineActionOperation,
	lease OperationLease,
) (CompletedQuarantineAction, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return CompletedQuarantineAction{}, fmt.Errorf("%w: invalid quarantine action fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(completeQuarantineActionBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation, FencingToken: lease.FencingToken,
	})
	if err != nil {
		return CompletedQuarantineAction{}, fmt.Errorf("marshal quarantine action fence: %w", err)
	}

	var response CompletedQuarantineAction

	path := "/api/v1/quarantine-actions/" + operation.ID + "/complete"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedQuarantineAction{}, err
	}

	if !validCompletedQuarantineAction(response, operation) {
		return CompletedQuarantineAction{}, fmt.Errorf("%w: quarantine action result changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func validQuarantineActionRequest(request CreateQuarantineActionRequest) bool {
	return validControlHex(request.NamespaceID, 32) && validQuarantineAction(request.Action) &&
		validControlString(request.DriverID, 256) && validInventoryPath(request.StorageKey, 4_096) &&
		request.ExpectedRevision > 0 && request.ExpectedRevision < math.MaxInt64 &&
		validControlString(request.Reason, 2_048) &&
		validControlString(request.IdempotencyKey, 256)
}

func validQuarantineActionOperation(
	operation QuarantineActionOperation,
	requested CreateQuarantineActionRequest,
) bool {
	if !validQuarantineOperationIdentity(operation, requested) {
		return false
	}

	if operation.State == operationStateSucceeded {
		return operation.ResultRevision != nil && operation.ResultState != nil &&
			validCompletedResult(operation)
	}

	return (operation.State == operationStatePlanned || operation.State == operationStateRunning) &&
		operation.ResultRevision == nil && operation.ResultState == nil && operation.DeleteAfter == nil
}

func validQuarantineOperationIdentity(
	operation QuarantineActionOperation,
	requested CreateQuarantineActionRequest,
) bool {
	return operation.NamespaceID == requested.NamespaceID && operation.Action == requested.Action &&
		operation.DriverID == requested.DriverID && operation.StorageKey == requested.StorageKey &&
		operation.ExpectedRevision == requested.ExpectedRevision && operation.Reason == requested.Reason &&
		operation.Kind == operationKindGC && validControlHex(operation.ID, 32) &&
		validControlHex(operation.Incarnation, 32) && operation.Revision > 0 &&
		operation.DriverRevision > 0 && operation.SizeBytes <= math.MaxInt64 &&
		validOptionalInventoryIdentity(operation.ProviderVersion) &&
		validOptionalInventoryIdentity(operation.ETag) && operation.GraceSeconds >= 60 &&
		operation.GraceSeconds <= 31_536_000
}

func validCompletedResult(operation QuarantineActionOperation) bool {
	if operation.ResultRevision == nil || *operation.ResultRevision != operation.ExpectedRevision+1 ||
		operation.ResultState == nil {
		return false
	}

	if operation.Action == QuarantineActionAcknowledge {
		return *operation.ResultState == operationStateAcknowledged && operation.DeleteAfter == nil
	}

	return *operation.ResultState == operationStateTombstoned && operation.DeleteAfter != nil
}

func validCompletedQuarantineAction(
	completed CompletedQuarantineAction,
	operation QuarantineActionOperation,
) bool {
	if completed.OperationID != operation.ID || completed.Action != operation.Action ||
		completed.State != operationStateSucceeded ||
		completed.QuarantineRevision != operation.ExpectedRevision+1 {
		return false
	}

	if completed.Action == QuarantineActionAcknowledge {
		return completed.QuarantineState == operationStateAcknowledged && completed.DeleteAfter == nil
	}

	return completed.QuarantineState == operationStateTombstoned && completed.DeleteAfter != nil
}

func validQuarantineAction(action QuarantineAction) bool {
	return action == QuarantineActionAcknowledge || action == QuarantineActionTombstone
}
