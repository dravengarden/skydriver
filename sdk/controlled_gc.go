package sdk

import (
	"context"
	"errors"
	"fmt"
)

// ErrGCOperationFailed indicates that control-plane recovery invalidated an
// exact idempotent GC epoch before its mark phase completed.
var ErrGCOperationFailed = errors.New("carrack GC operation previously failed")

// ControlledGCRequest identifies one policy-derived namespace mark pass.
type ControlledGCRequest struct {
	NamespaceID    string
	IdempotencyKey string
}

// ControlledGCResult contains the durable epoch and its mark/grace handoff.
type ControlledGCResult struct {
	Operation     GCOperation
	Mark          GCMark
	AlreadyMarked bool
}

// ControlledGarbageCollector coordinates the short fenced mark phase.
type ControlledGarbageCollector struct {
	control      *ControlClient
	leaseSeconds uint64
}

// NewControlledGarbageCollector constructs a mark coordinator.
func NewControlledGarbageCollector(
	control *ControlClient,
	leaseSeconds uint64,
) (*ControlledGarbageCollector, error) {
	if control == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return nil, fmt.Errorf("%w: invalid controlled GC configuration", ErrInvalidConfiguration)
	}

	return &ControlledGarbageCollector{control: control, leaseSeconds: leaseSeconds}, nil
}

// Mark creates, claims, and atomically tombstones the current safe candidate set.
func (collector *ControlledGarbageCollector) Mark(
	ctx context.Context,
	requested ControlledGCRequest,
) (ControlledGCResult, error) {
	if collector == nil || collector.control == nil ||
		!validControlHex(requested.NamespaceID, 32) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ControlledGCResult{}, fmt.Errorf("%w: invalid controlled GC request", ErrInvalidConfiguration)
	}

	operation, err := collector.control.CreateGCOperation(ctx, CreateGCOperationRequest(requested))
	if err != nil {
		return ControlledGCResult{}, fmt.Errorf("create controlled GC: %w", err)
	}

	switch operation.GCState {
	case operationPhaseGrace, operationPhaseSweeping, operationStateSucceeded:
		return completedControlledGCMark(operation), nil
	case operationStateFailed:
		return ControlledGCResult{Operation: operation}, fmt.Errorf(
			"%w: operation %s",
			ErrGCOperationFailed,
			operation.ID,
		)
	case operationPhaseMarking:
	default:
		return ControlledGCResult{}, fmt.Errorf(
			"%w: unsupported controlled GC state",
			ErrControlPlaneResponse,
		)
	}

	lease, err := collector.control.ClaimGCOperation(ctx, operation, collector.leaseSeconds)
	if err != nil {
		return ControlledGCResult{}, fmt.Errorf("claim controlled GC: %w", err)
	}

	mark, err := collector.control.MarkGC(ctx, operation, lease)
	if err != nil {
		return ControlledGCResult{}, fmt.Errorf("mark controlled GC: %w", err)
	}

	return ControlledGCResult{Operation: operation, Mark: mark}, nil
}

func completedControlledGCMark(operation GCOperation) ControlledGCResult {
	return ControlledGCResult{
		Operation: operation, Mark: gcMarkFromOperation(operation), AlreadyMarked: true,
	}
}

func gcMarkFromOperation(operation GCOperation) GCMark {
	return GCMark{
		OperationID: operation.ID, CandidatesMarked: operation.CandidateCount,
		ObjectsMarked: operation.ObjectCount, GraceUntil: operation.GraceUntil,
		State: operation.GCState,
	}
}
