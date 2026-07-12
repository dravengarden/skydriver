package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/dravengarden/carrack/provider"
)

type providerObjectJanitor struct {
	control       *ControlClient
	deleters      map[string]provider.Deleter
	leaseSeconds  uint64
	protocol      deleteTaskProtocol
	invalidError  error
	providerError error
	initialState  string
}

type providerObjectSweep struct {
	operationID      string
	objectsDeleted   uint64
	locationsDeleted uint64
	state            string
}

func newProviderObjectJanitor(
	control *ControlClient,
	deleters map[string]provider.Deleter,
	leaseSeconds uint64,
	protocol deleteTaskProtocol,
	invalidError error,
	providerError error,
) (*providerObjectJanitor, error) {
	if control == nil || len(deleters) == 0 || !validDeleteLeaseSeconds(leaseSeconds) {
		return nil, fmt.Errorf("%w: invalid configuration", invalidError)
	}

	copied := make(map[string]provider.Deleter, len(deleters))
	for driverID, deleter := range deleters {
		if !validControlString(driverID, 256) || deleter == nil {
			return nil, fmt.Errorf("%w: invalid driver deleter", invalidError)
		}

		copied[driverID] = deleter
	}

	return &providerObjectJanitor{
		control: control, deleters: copied, leaseSeconds: leaseSeconds, protocol: protocol,
		invalidError: invalidError, providerError: providerError, initialState: protocol.runningState,
	}, nil
}

func (janitor *providerObjectJanitor) sweep(
	ctx context.Context,
	operationID string,
) (providerObjectSweep, error) {
	if janitor == nil || janitor.control == nil || !validControlHex(operationID, 32) {
		return providerObjectSweep{}, fmt.Errorf("%w: invalid sweep", janitor.invalidError)
	}

	result := providerObjectSweep{operationID: operationID, state: janitor.initialState}
	for {
		claim, err := janitor.control.claimProviderDelete(
			ctx,
			operationID,
			janitor.leaseSeconds,
			janitor.protocol,
		)
		if err != nil {
			return result, fmt.Errorf("claim %s delete: %w", janitor.protocol.label, err)
		}

		if claim.State == operationStateSucceeded {
			result.state = operationStateSucceeded

			return result, nil
		}

		if err := janitor.deleteClaimedObject(ctx, *claim.Task, &result); err != nil {
			return result, err
		}
	}
}

func (janitor *providerObjectJanitor) deleteClaimedObject(
	ctx context.Context,
	task ProviderDeleteTask,
	result *providerObjectSweep,
) error {
	deleter, exists := janitor.deleters[task.DriverID]
	if !exists {
		failErr := janitor.control.failProviderDelete(
			ctx,
			task,
			"delete_capability_unavailable",
			janitor.protocol,
		)

		return errors.Join(
			fmt.Errorf("%w: driver %q", janitor.invalidError, task.DriverID),
			failErr,
		)
	}

	revalidated, err := janitor.control.revalidateProviderDelete(
		ctx,
		task,
		janitor.leaseSeconds,
		janitor.protocol,
	)
	if err != nil {
		return fmt.Errorf("revalidate %s delete: %w", janitor.protocol.label, err)
	}

	if deleteErr := deleter.Delete(ctx, revalidated.StorageKey); deleteErr != nil {
		failErr := janitor.control.failProviderDelete(
			ctx,
			revalidated,
			"provider_delete_failed",
			janitor.protocol,
		)

		return errors.Join(fmt.Errorf("%w: %w", janitor.providerError, deleteErr), failErr)
	}

	completed, err := janitor.control.completeProviderDelete(ctx, revalidated, janitor.protocol)
	if err != nil {
		return fmt.Errorf("complete %s delete: %w", janitor.protocol.label, err)
	}

	result.objectsDeleted++
	result.locationsDeleted += completed.LocationsDeleted
	result.state = completed.WorkflowState

	return nil
}
