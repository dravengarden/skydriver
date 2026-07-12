//nolint:dupl // Move and GC keep distinct public facades over the shared delete runner.
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
	janitor *providerObjectJanitor
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
	janitor, err := newProviderObjectJanitor(
		control,
		deleters,
		leaseSeconds,
		moveDeleteProtocol,
		ErrInvalidMoveJanitor,
		ErrMoveProviderDelete,
	)
	if err != nil {
		return nil, err
	}

	return &MoveJanitor{janitor: janitor}, nil
}

// SweepMove drains every currently authorized object task for one move. The
// provider delete is retried safely because every Deleter must be idempotent.
func (janitor *MoveJanitor) SweepMove(
	ctx context.Context,
	operationID string,
) (MoveSweepResult, error) {
	if janitor == nil || janitor.janitor == nil {
		return MoveSweepResult{}, fmt.Errorf("%w: invalid sweep", ErrInvalidMoveJanitor)
	}

	result, err := janitor.janitor.sweep(ctx, operationID)

	return MoveSweepResult{
		OperationID: result.operationID, ObjectsDeleted: result.objectsDeleted,
		LocationsDeleted: result.locationsDeleted, State: result.state,
	}, err
}
