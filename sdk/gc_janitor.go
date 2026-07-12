//nolint:dupl // GC and Move keep distinct public facades over the shared delete runner.
package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/dravengarden/carrack/provider"
)

var (
	// ErrInvalidGCJanitor indicates missing control-plane or delete capabilities.
	ErrInvalidGCJanitor = errors.New("invalid Carrack GC janitor")
	// ErrGCProviderDelete indicates that an authorized provider delete failed.
	ErrGCProviderDelete = errors.New("carrack GC provider delete failed")
)

// GCJanitor performs only control-plane-authorized provider deletions.
type GCJanitor struct {
	janitor *providerObjectJanitor
}

// GCSweepResult summarizes object deletions completed during one epoch sweep.
type GCSweepResult struct {
	OperationID      string
	ObjectsDeleted   uint64
	LocationsDeleted uint64
	State            string
}

// NewGCJanitor copies an explicit driver-to-deleter capability map.
func NewGCJanitor(
	control *ControlClient,
	deleters map[string]provider.Deleter,
	leaseSeconds uint64,
) (*GCJanitor, error) {
	janitor, err := newProviderObjectJanitor(
		control,
		deleters,
		leaseSeconds,
		gcDeleteProtocol,
		ErrInvalidGCJanitor,
		ErrGCProviderDelete,
	)
	if err != nil {
		return nil, err
	}

	return &GCJanitor{janitor: janitor}, nil
}

// Sweep drains every currently authorized object task for one GC epoch.
func (janitor *GCJanitor) Sweep(
	ctx context.Context,
	operationID string,
) (GCSweepResult, error) {
	if janitor == nil || janitor.janitor == nil {
		return GCSweepResult{}, fmt.Errorf("%w: invalid sweep", ErrInvalidGCJanitor)
	}

	result, err := janitor.janitor.sweep(ctx, operationID)

	return GCSweepResult{
		OperationID: result.operationID, ObjectsDeleted: result.objectsDeleted,
		LocationsDeleted: result.locationsDeleted, State: result.state,
	}, err
}
