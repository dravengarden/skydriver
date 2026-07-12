package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/dravengarden/carrack/provider"
)

var (
	// ErrInvalidMoveJanitor indicates missing control-plane or delete capabilities.
	ErrInvalidMoveJanitor = errors.New("invalid Carrack move janitor")
	// ErrMoveProviderDelete indicates that an authorized provider delete failed.
	ErrMoveProviderDelete = errors.New("carrack move provider delete failed")
)

// MoveJanitor performs only control-plane-authorized provider deletions.
type MoveJanitor struct {
	control      *ControlClient
	deleters     map[string]provider.Deleter
	leaseSeconds uint64
}

// MoveSweepResult summarizes object deletions completed during one move sweep.
type MoveSweepResult struct {
	OperationID      string
	ObjectsDeleted   uint64
	LocationsDeleted uint64
	State            string
}

// NewMoveJanitor copies an explicit driver-to-deleter capability map.
func NewMoveJanitor(
	control *ControlClient,
	deleters map[string]provider.Deleter,
	leaseSeconds uint64,
) (*MoveJanitor, error) {
	if control == nil || len(deleters) == 0 ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return nil, fmt.Errorf("%w: invalid configuration", ErrInvalidMoveJanitor)
	}

	copied := make(map[string]provider.Deleter, len(deleters))
	for driverID, deleter := range deleters {
		if !validControlString(driverID, 256) || deleter == nil {
			return nil, fmt.Errorf("%w: invalid driver deleter", ErrInvalidMoveJanitor)
		}

		copied[driverID] = deleter
	}

	return &MoveJanitor{control: control, deleters: copied, leaseSeconds: leaseSeconds}, nil
}

// SweepMove drains every currently authorized object task for one move. The
// provider delete is retried safely because every Deleter must be idempotent.
func (janitor *MoveJanitor) SweepMove(
	ctx context.Context,
	operationID string,
) (MoveSweepResult, error) {
	if janitor == nil || janitor.control == nil || !validControlHex(operationID, 32) {
		return MoveSweepResult{}, fmt.Errorf("%w: invalid sweep", ErrInvalidMoveJanitor)
	}

	result := MoveSweepResult{OperationID: operationID, State: "deleting"}
	for {
		claim, err := janitor.control.ClaimMoveDelete(ctx, operationID, janitor.leaseSeconds)
		if err != nil {
			return result, fmt.Errorf("claim move delete: %w", err)
		}

		if claim.State == operationStateSucceeded {
			result.State = operationStateSucceeded

			return result, nil
		}

		task := *claim.Task

		deleter, exists := janitor.deleters[task.DriverID]
		if !exists {
			failErr := janitor.control.FailMoveDelete(ctx, task, "delete_capability_unavailable")

			return result, errors.Join(
				fmt.Errorf("%w: driver %q", ErrInvalidMoveJanitor, task.DriverID),
				failErr,
			)
		}

		revalidated, err := janitor.control.RevalidateMoveDelete(ctx, task, janitor.leaseSeconds)
		if err != nil {
			return result, fmt.Errorf("revalidate move delete: %w", err)
		}

		if deleteErr := deleter.Delete(ctx, revalidated.StorageKey); deleteErr != nil {
			failErr := janitor.control.FailMoveDelete(ctx, revalidated, "provider_delete_failed")

			return result, errors.Join(
				fmt.Errorf("%w: %w", ErrMoveProviderDelete, deleteErr),
				failErr,
			)
		}

		completed, err := janitor.control.CompleteMoveDelete(ctx, revalidated)
		if err != nil {
			return result, fmt.Errorf("complete move delete: %w", err)
		}

		result.ObjectsDeleted++
		result.LocationsDeleted += completed.LocationsDeleted
		result.State = completed.MoveState
	}
}
