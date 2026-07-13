package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
)

const operationKindGC = "gc"

// CreateGCOperationRequest identifies one idempotent namespace collection epoch.
type CreateGCOperationRequest struct {
	NamespaceID    string
	IdempotencyKey string
}

// GCOperation is the durable mark, grace, and sweep identity.
type GCOperation struct {
	ID             string  `json:"id"`
	NamespaceID    string  `json:"namespace_id"`
	Kind           string  `json:"kind"`
	State          string  `json:"state"`
	Phase          string  `json:"phase"`
	RequestedBy    string  `json:"requested_by"`
	Incarnation    string  `json:"incarnation"`
	Revision       uint64  `json:"revision"`
	CutoffAt       uint64  `json:"cutoff_at"`
	GraceSeconds   uint64  `json:"grace_seconds"`
	GraceUntil     *uint64 `json:"grace_until"`
	GCState        string  `json:"gc_state"`
	CandidateCount uint64  `json:"candidate_count"`
	ObjectCount    uint64  `json:"object_count"`
	CreatedAt      uint64  `json:"created_at"`
	UpdatedAt      uint64  `json:"updated_at"`
}

// GCMark records immutable provider ranges as tombstoned for one grace period.
type GCMark struct {
	OperationID      string  `json:"operation_id"`
	CandidatesMarked uint64  `json:"candidates_marked"`
	ObjectsMarked    uint64  `json:"objects_marked"`
	GraceUntil       *uint64 `json:"grace_until"`
	State            string  `json:"state"`
}

// GCDeleteTask authorizes one idempotent provider-object deletion.
type GCDeleteTask = ProviderDeleteTask

// GCDeleteClaim is one safe provider object or a completed epoch signal.
type GCDeleteClaim = ProviderDeleteClaim

// CompletedGCDelete records one provider object and all its ranges as deleted.
type CompletedGCDelete struct {
	TaskID           string `json:"task_id"`
	OperationID      string `json:"operation_id"`
	LocationsDeleted uint64 `json:"locations_deleted"`
	TaskState        string `json:"task_state"`
	GCState          string `json:"gc_state"`
}

type createGCOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

type gcMarkBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

// CreateGCOperation creates or returns one policy-derived collection epoch.
func (client *ControlClient) CreateGCOperation(
	ctx context.Context,
	requested CreateGCOperationRequest,
) (GCOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return GCOperation{}, fmt.Errorf("%w: invalid GC operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createGCOperationBody(requested))
	if err != nil {
		return GCOperation{}, fmt.Errorf("marshal GC operation: %w", err)
	}

	var response GCOperation
	if err := client.authenticatedPost(ctx, "/api/v1/gc/epochs", body, &response); err != nil {
		return GCOperation{}, err
	}

	if !validGCOperation(response, requested.NamespaceID) {
		return GCOperation{}, fmt.Errorf("%w: invalid GC operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimGCOperation acquires or renews the short mark-phase write fence.
func (client *ControlClient) ClaimGCOperation(
	ctx context.Context,
	operation GCOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validGCOperation(operation, operation.NamespaceID) || operation.GCState != operationPhaseMarking ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid GC operation lease", ErrInvalidControlPlane)
	}

	return client.claimOperation(ctx, operation.ID, operation.Incarnation, leaseSeconds, operationKindGC)
}

// MarkGC atomically tombstones the complete currently safe provider-object set.
func (client *ControlClient) MarkGC(
	ctx context.Context,
	operation GCOperation,
	lease OperationLease,
) (GCMark, error) {
	if !validGCOperation(operation, operation.NamespaceID) || operation.GCState != operationPhaseMarking ||
		lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return GCMark{}, fmt.Errorf("%w: invalid GC mark fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(gcMarkBody{
		LeaseID:      lease.LeaseID,
		Incarnation:  lease.Incarnation,
		FencingToken: lease.FencingToken,
	})
	if err != nil {
		return GCMark{}, fmt.Errorf("marshal GC mark: %w", err)
	}

	var response GCMark

	path := "/api/v1/gc/" + operation.ID + "/mark"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return GCMark{}, err
	}

	if !validGCMark(response, operation.ID) {
		return GCMark{}, fmt.Errorf("%w: invalid GC mark result", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimGCDelete claims or resumes one object after grace and reachability checks.
func (client *ControlClient) ClaimGCDelete(
	ctx context.Context,
	operationID string,
	leaseSeconds uint64,
) (GCDeleteClaim, error) {
	return client.claimProviderDelete(ctx, operationID, leaseSeconds, gcDeleteProtocol)
}

// RevalidateGCDelete rotates the fence after repeating every destructive check.
func (client *ControlClient) RevalidateGCDelete(
	ctx context.Context,
	task GCDeleteTask,
	leaseSeconds uint64,
) (GCDeleteTask, error) {
	return client.revalidateProviderDelete(ctx, task, leaseSeconds, gcDeleteProtocol)
}

// CompleteGCDelete commits provider deletion under the revalidated task fence.
func (client *ControlClient) CompleteGCDelete(
	ctx context.Context,
	task GCDeleteTask,
) (CompletedGCDelete, error) {
	completed, err := client.completeProviderDelete(ctx, task, gcDeleteProtocol)
	if err != nil {
		return CompletedGCDelete{}, err
	}

	return CompletedGCDelete{
		TaskID: completed.TaskID, OperationID: completed.OperationID,
		LocationsDeleted: completed.LocationsDeleted, TaskState: operationStateDeleted,
		GCState: completed.WorkflowState,
	}, nil
}

// FailGCDelete releases a failed task for a later fenced retry.
func (client *ControlClient) FailGCDelete(
	ctx context.Context,
	task GCDeleteTask,
	errorCode string,
) error {
	return client.failProviderDelete(ctx, task, errorCode, gcDeleteProtocol)
}

func validGCOperation(operation GCOperation, namespaceID string) bool {
	if operation.NamespaceID != namespaceID || operation.Kind != operationKindGC ||
		!validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		!validControlString(operation.RequestedBy, 2_048) || operation.Revision == 0 ||
		operation.CutoffAt == 0 || operation.CutoffAt > math.MaxInt64 ||
		operation.GraceSeconds < 60 || operation.GraceSeconds > 31_536_000 ||
		operation.CandidateCount > math.MaxInt64 || operation.ObjectCount > operation.CandidateCount ||
		operation.CreatedAt == 0 || operation.UpdatedAt < operation.CreatedAt ||
		(operation.GraceUntil != nil && (*operation.GraceUntil == 0 || *operation.GraceUntil > math.MaxInt64)) {
		return false
	}

	return validGCOperationState(operation)
}

func validGCOperationState(operation GCOperation) bool {
	switch operation.GCState {
	case operationPhaseMarking:
		return validMarkingGCOperation(operation)
	case operationPhaseGrace:
		return operation.State == operationStateRunning && operation.Phase == operationPhaseGrace &&
			validMarkedGCCounts(operation)
	case operationPhaseSweeping:
		return operation.State == operationStateRunning && operation.Phase == operationPhaseSweeping &&
			validMarkedGCCounts(operation)
	case operationStateSucceeded:
		return operation.State == operationStateSucceeded && operation.Phase == operationStateSucceeded &&
			validTerminalGCCounts(operation)
	case operationStateFailed:
		return (operation.State == operationStateFailed || operation.State == operationStateCancelled) &&
			operation.Phase == operationPhaseRecovered && validTerminalGCCounts(operation)
	default:
		return false
	}
}

func validMarkingGCOperation(operation GCOperation) bool {
	statePhaseValid := operation.State == operationStatePlanned && operation.Phase == operationStatePlanned ||
		operation.State == operationStateRunning && operation.Phase == operationPhaseMarking

	return statePhaseValid && operation.GraceUntil == nil &&
		operation.CandidateCount == 0 && operation.ObjectCount == 0
}

func validMarkedGCCounts(operation GCOperation) bool {
	return operation.GraceUntil != nil && operation.CandidateCount > 0 &&
		operation.ObjectCount > 0 && operation.ObjectCount <= operation.CandidateCount
}

func validTerminalGCCounts(operation GCOperation) bool {
	zero := operation.CandidateCount == 0 && operation.ObjectCount == 0 && operation.GraceUntil == nil
	marked := validMarkedGCCounts(operation)

	return zero || marked
}

func validGCMark(mark GCMark, operationID string) bool {
	if mark.OperationID != operationID || mark.CandidatesMarked > math.MaxInt64 ||
		mark.ObjectsMarked > mark.CandidatesMarked ||
		(mark.GraceUntil != nil && (*mark.GraceUntil == 0 || *mark.GraceUntil > math.MaxInt64)) {
		return false
	}

	zero := mark.CandidatesMarked == 0 && mark.ObjectsMarked == 0 && mark.GraceUntil == nil
	marked := mark.CandidatesMarked > 0 && mark.ObjectsMarked > 0 && mark.GraceUntil != nil

	return mark.State == operationStateSucceeded && zero ||
		(mark.State == operationPhaseGrace || mark.State == operationPhaseSweeping ||
			mark.State == operationStateSucceeded) && marked
}
