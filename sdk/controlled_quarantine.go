package sdk

import (
	"context"
	"errors"
	"fmt"
)

// ErrQuarantineOperationFailed indicates that control-plane recovery
// invalidated an exact idempotent review before it could complete.
var ErrQuarantineOperationFailed = errors.New("carrack quarantine operation previously failed")

// ControlledQuarantineRequest identifies one exact object review transition.
type ControlledQuarantineRequest struct {
	NamespaceID      string
	Action           QuarantineAction
	DriverID         string
	StorageKey       string
	ExpectedRevision uint64
	Reason           string
	IdempotencyKey   string
}

// ControlledQuarantineResult contains the pinned intent and committed lifecycle state.
type ControlledQuarantineResult struct {
	Operation        QuarantineActionOperation
	Completion       CompletedQuarantineAction
	AlreadyCompleted bool
}

// ControlledQuarantineReviewer coordinates short, fenced D1 review transitions.
type ControlledQuarantineReviewer struct {
	control      *ControlClient
	leaseSeconds uint64
}

// NewControlledQuarantineReviewer constructs an explicit quarantine reviewer.
func NewControlledQuarantineReviewer(
	control *ControlClient,
	leaseSeconds uint64,
) (*ControlledQuarantineReviewer, error) {
	if control == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return nil, fmt.Errorf("%w: invalid quarantine reviewer configuration", ErrInvalidConfiguration)
	}

	return &ControlledQuarantineReviewer{control: control, leaseSeconds: leaseSeconds}, nil
}

// Act creates, claims, and commits one exact acknowledge or tombstone action.
func (reviewer *ControlledQuarantineReviewer) Act(
	ctx context.Context,
	requested ControlledQuarantineRequest,
) (ControlledQuarantineResult, error) {
	if reviewer == nil || reviewer.control == nil ||
		!validQuarantineActionRequest(CreateQuarantineActionRequest(requested)) {
		return ControlledQuarantineResult{}, fmt.Errorf("%w: invalid controlled quarantine request", ErrInvalidConfiguration)
	}

	operation, err := reviewer.control.CreateQuarantineAction(
		ctx,
		CreateQuarantineActionRequest(requested),
	)
	if err != nil {
		return ControlledQuarantineResult{}, fmt.Errorf("create controlled quarantine action: %w", err)
	}

	switch operation.State {
	case operationStateSucceeded:
		return completedControlledQuarantine(operation), nil
	case operationStateFailed, operationStateCancelled:
		return ControlledQuarantineResult{Operation: operation}, fmt.Errorf(
			"%w: operation %s",
			ErrQuarantineOperationFailed,
			operation.ID,
		)
	case operationStatePlanned, operationStateRunning:
	default:
		return ControlledQuarantineResult{}, fmt.Errorf(
			"%w: unsupported controlled quarantine state",
			ErrControlPlaneResponse,
		)
	}

	lease, err := reviewer.control.ClaimQuarantineAction(ctx, operation, reviewer.leaseSeconds)
	if err != nil {
		return ControlledQuarantineResult{}, fmt.Errorf("claim controlled quarantine action: %w", err)
	}

	completion, err := reviewer.control.CompleteQuarantineAction(ctx, operation, lease)
	if err != nil {
		return ControlledQuarantineResult{}, fmt.Errorf("complete controlled quarantine action: %w", err)
	}

	return ControlledQuarantineResult{Operation: operation, Completion: completion}, nil
}

func completedControlledQuarantine(
	operation QuarantineActionOperation,
) ControlledQuarantineResult {
	return ControlledQuarantineResult{
		Operation: operation, Completion: completedQuarantineActionFromOperation(operation),
		AlreadyCompleted: true,
	}
}

func completedQuarantineActionFromOperation(
	operation QuarantineActionOperation,
) CompletedQuarantineAction {
	return CompletedQuarantineAction{
		OperationID:        operation.ID,
		Action:             operation.Action,
		State:              operationStateSucceeded,
		QuarantineState:    *operation.ResultState,
		QuarantineRevision: *operation.ResultRevision,
		DeleteAfter:        operation.DeleteAfter,
	}
}
