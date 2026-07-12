package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrRepairLeaseLost indicates that repair I/O was cancelled after renewal failed.
	ErrRepairLeaseLost = errors.New("carrack repair write lease was lost")
	// ErrRepairOperationFailed indicates that recovery invalidated an exact
	// idempotent repair before it could complete.
	ErrRepairOperationFailed = errors.New("carrack repair operation previously failed")
)

// ControlledRepairer coordinates one location-preserving missing-object repair.
type ControlledRepairer struct {
	control         *ControlClient
	repairer        *Repairer
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledRepairRequest identifies one bounded missing-location repair.
type ControlledRepairRequest struct {
	NamespaceID      string
	ManifestSHA256   string
	TargetDriverID   string
	IdempotencyKey   string
	StagingDirectory string
}

// ControlledRepairResult contains the pinned plan, verified writes, and commit.
type ControlledRepairResult struct {
	Operation        RepairOperation
	Plan             RepairPlan
	Repair           RepairResult
	Completion       CompletedRepair
	AlreadyCompleted bool
}

// NewControlledRepairer constructs a repair coordinator with renewable fencing.
func NewControlledRepairer(
	control *ControlClient,
	repairer *Repairer,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledRepairer, error) {
	if control == nil || repairer == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled repair configuration", ErrInvalidConfiguration)
	}

	return &ControlledRepairer{
		control: control, repairer: repairer, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Repair reconstructs every pinned provider object and commits metadata only
// after exact destination readback succeeds under the current write fence.
func (coordinator *ControlledRepairer) Repair(
	ctx context.Context,
	requested ControlledRepairRequest,
) (ControlledRepairResult, error) {
	if coordinator == nil || coordinator.control == nil || coordinator.repairer == nil {
		return ControlledRepairResult{}, fmt.Errorf("%w: controlled repairer is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.TargetDriverID, 256) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ControlledRepairResult{}, fmt.Errorf("%w: invalid controlled repair request", ErrInvalidConfiguration)
	}

	if err := validateStagingDirectory(requested.StagingDirectory); err != nil {
		return ControlledRepairResult{}, fmt.Errorf("%w: invalid controlled repair staging: %w", ErrInvalidConfiguration, err)
	}

	operation, err := coordinator.control.CreateRepairOperation(ctx, CreateRepairOperationRequest{
		NamespaceID: requested.NamespaceID, ManifestSHA256: requested.ManifestSHA256,
		TargetDriverID: requested.TargetDriverID, IdempotencyKey: requested.IdempotencyKey,
	})
	if err != nil {
		return ControlledRepairResult{}, fmt.Errorf("create controlled repair: %w", err)
	}

	switch operation.State {
	case operationStateSucceeded:
		return completedControlledRepair(operation), nil
	case operationStateFailed, operationStateCancelled:
		return ControlledRepairResult{Operation: operation}, fmt.Errorf(
			"%w: operation %s",
			ErrRepairOperationFailed,
			operation.ID,
		)
	case operationStatePlanned, operationStateRunning:
	default:
		return ControlledRepairResult{}, fmt.Errorf(
			"%w: unsupported controlled repair state",
			ErrControlPlaneResponse,
		)
	}

	lease, err := coordinator.control.ClaimRepairOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledRepairResult{}, fmt.Errorf("claim controlled repair: %w", err)
	}

	repairContext, cancelRepair := context.WithCancel(ctx)
	leaseState := &renewedRepairLease{lease: lease}
	renewalErrors := make(chan error, 1)
	renewalDone := make(chan struct{})

	go coordinator.renewLease(
		repairContext,
		cancelRepair,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	snapshot, err := coordinator.control.FetchRepairSnapshot(repairContext, operation, lease)
	if err != nil {
		return failControlledRepair(cancelRepair, renewalDone, renewalErrors, err)
	}

	plan, err := (RepairPlanner{}).PlanMissing(
		snapshot.Recovery,
		snapshot.Locations,
		snapshot.TargetLocationIDs,
	)
	if err != nil {
		return failControlledRepair(cancelRepair, renewalDone, renewalErrors, err)
	}

	repaired, err := coordinator.repairer.Repair(
		repairContext,
		plan,
		requested.StagingDirectory,
	)
	if err != nil {
		return failControlledRepair(cancelRepair, renewalDone, renewalErrors, err)
	}

	completion, err := coordinator.control.CompleteRepair(
		repairContext,
		operation,
		leaseState.current(),
		plan,
		repaired,
	)

	cancelRepair()
	<-renewalDone

	if err != nil {
		return ControlledRepairResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
	}

	return ControlledRepairResult{
		Operation: operation, Plan: plan, Repair: repaired, Completion: completion,
	}, nil
}

func completedControlledRepair(operation RepairOperation) ControlledRepairResult {
	return ControlledRepairResult{
		Operation: operation,
		Completion: CompletedRepair{
			OperationID: operation.ID, ManifestSHA256: operation.ManifestSHA256,
			State: operationStateSucceeded, ObjectsRepaired: operation.ExpectedObjectCount,
			LocationsRepaired: operation.ExpectedTargetCount,
			CiphertextBytes:   operation.UsefulBytesTotal, RecoveryRevision: operation.RecoveryRevision,
		},
		AlreadyCompleted: true,
	}
}

func failControlledRepair(
	cancel context.CancelFunc,
	done <-chan struct{},
	renewalErrors <-chan error,
	err error,
) (ControlledRepairResult, error) {
	cancel()
	<-done

	return ControlledRepairResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
}

type renewedRepairLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedRepairLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedRepairLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledRepairer) renewLease(
	ctx context.Context,
	cancelRepair context.CancelFunc,
	operation RepairOperation,
	state *renewedRepairLease,
	renewalErrors chan<- error,
	done chan<- struct{},
) {
	defer close(done)

	ticker := time.NewTicker(coordinator.renewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewed, err := coordinator.control.ClaimRepairOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrRepairLeaseLost, err):
				default:
				}

				cancelRepair()

				return
			}

			state.replace(renewed)
		}
	}
}
