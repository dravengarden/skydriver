package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrReconcileLeaseLost indicates that reconciliation stopped after renewal failed.
	ErrReconcileLeaseLost = errors.New("carrack reconcile write lease was lost")
	// ErrReconcileOperationFailed indicates that control-plane recovery invalidated
	// an exact idempotent reconciliation before it could complete.
	ErrReconcileOperationFailed = errors.New("carrack reconcile operation previously failed")
)

// ControlledReconciler coordinates one fenced metadata audit.
type ControlledReconciler struct {
	control         *ControlClient
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledReconcileRequest identifies one idempotent metadata audit.
type ControlledReconcileRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	IdempotencyKey string
}

// ControlledReconcileResult contains the pinned comparison and durable completion.
type ControlledReconcileResult struct {
	Operation        ReconcileOperation
	Reconciliation   ReconciliationResult
	Completion       CompletedReconcile
	AlreadyCompleted bool
}

// NewControlledReconciler constructs a coordinator with an explicit renewal cadence.
func NewControlledReconciler(
	control *ControlClient,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledReconciler, error) {
	if control == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled reconcile configuration", ErrInvalidConfiguration)
	}

	return &ControlledReconciler{
		control: control, leaseSeconds: leaseSeconds, renewalInterval: renewalInterval,
	}, nil
}

// Reconcile obtains one fenced metadata snapshot and commits only the complete,
// deterministic comparison report recomputed by the control plane.
func (coordinator *ControlledReconciler) Reconcile(
	ctx context.Context,
	requested ControlledReconcileRequest,
) (ControlledReconcileResult, error) {
	if coordinator == nil || coordinator.control == nil {
		return ControlledReconcileResult{}, fmt.Errorf("%w: controlled reconciler is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ControlledReconcileResult{}, fmt.Errorf("%w: invalid controlled reconcile request", ErrInvalidConfiguration)
	}

	operation, err := coordinator.control.CreateReconcileOperation(ctx, CreateReconcileOperationRequest(requested))
	if err != nil {
		return ControlledReconcileResult{}, fmt.Errorf("create controlled reconcile: %w", err)
	}

	switch operation.State {
	case operationStateSucceeded:
		return completedControlledReconcile(operation), nil
	case operationStateFailed, operationStateCancelled:
		return ControlledReconcileResult{Operation: operation}, fmt.Errorf(
			"%w: operation %s",
			ErrReconcileOperationFailed,
			operation.ID,
		)
	case operationStatePlanned, operationStateRunning:
	default:
		return ControlledReconcileResult{}, fmt.Errorf(
			"%w: unsupported controlled reconcile state",
			ErrControlPlaneResponse,
		)
	}

	lease, err := coordinator.control.ClaimReconcileOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledReconcileResult{}, fmt.Errorf("claim controlled reconcile: %w", err)
	}

	reconcileContext, cancelReconcile := context.WithCancel(ctx)
	leaseState := &renewedReconcileLease{lease: lease}
	renewalErrors := make(chan error, 1)

	renewalDone := make(chan struct{})
	go coordinator.renewLease(
		reconcileContext,
		cancelReconcile,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	snapshot, err := coordinator.control.FetchReconcileSnapshot(
		reconcileContext,
		operation,
		lease,
	)
	if err != nil {
		return failControlledReconcile(cancelReconcile, renewalDone, renewalErrors, err)
	}

	reconciliation, err := (Reconciler{}).Reconcile(
		snapshot.Recovery,
		snapshot.Locations,
		snapshot.MinimumAvailableReplicas,
	)
	if err != nil {
		return failControlledReconcile(cancelReconcile, renewalDone, renewalErrors, err)
	}

	completion, err := coordinator.control.CompleteReconcile(
		reconcileContext,
		operation,
		leaseState.current(),
		reconciliation,
	)

	cancelReconcile()
	<-renewalDone

	if err != nil {
		return ControlledReconcileResult{}, errors.Join(
			err,
			receiveRenewalError(renewalErrors),
		)
	}

	return ControlledReconcileResult{
		Operation: operation, Reconciliation: reconciliation, Completion: completion,
	}, nil
}

func completedControlledReconcile(operation ReconcileOperation) ControlledReconcileResult {
	return ControlledReconcileResult{
		Operation: operation,
		Completion: CompletedReconcile{
			OperationID: operation.ID, ManifestSHA256: operation.ManifestSHA256,
			State: operationStateSucceeded, ReportSHA256: operation.CompletedReportSHA256,
			Unindexed: operation.CompletedUnindexed, Orphan: operation.CompletedOrphan,
			Degraded: operation.CompletedDegraded,
		},
		AlreadyCompleted: true,
	}
}

func failControlledReconcile(
	cancel context.CancelFunc,
	done <-chan struct{},
	renewalErrors <-chan error,
	err error,
) (ControlledReconcileResult, error) {
	cancel()
	<-done

	return ControlledReconcileResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
}

type renewedReconcileLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedReconcileLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedReconcileLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledReconciler) renewLease(
	ctx context.Context,
	cancelReconcile context.CancelFunc,
	operation ReconcileOperation,
	state *renewedReconcileLease,
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
			renewed, err := coordinator.control.ClaimReconcileOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrReconcileLeaseLost, err):
				default:
				}

				cancelReconcile()

				return
			}

			state.replace(renewed)
		}
	}
}
