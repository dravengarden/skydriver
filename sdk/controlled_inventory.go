package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dravengarden/carrack/provider"
)

// ErrInventoryLeaseLost indicates that enumeration stopped after renewal failed.
var ErrInventoryLeaseLost = errors.New("carrack inventory write lease was lost")

// ControlledInventoryReconciler coordinates one complete provider inventory report.
type ControlledInventoryReconciler struct {
	control         *ControlClient
	inventory       provider.Inventory
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledInventoryRequest identifies one idempotent provider inventory scope.
type ControlledInventoryRequest struct {
	NamespaceID    string
	DriverID       string
	Prefix         string
	IdempotencyKey string
}

// ControlledInventoryResult contains the pinned scope and durable classifications.
type ControlledInventoryResult struct {
	Operation  InventoryOperation
	Completion CompletedInventory
}

// NewControlledInventoryReconciler constructs an inventory coordinator.
func NewControlledInventoryReconciler(
	control *ControlClient,
	inventory provider.Inventory,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledInventoryReconciler, error) {
	if control == nil || inventory == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled inventory configuration", ErrInvalidConfiguration)
	}

	return &ControlledInventoryReconciler{
		control: control, inventory: inventory, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Reconcile enumerates every bounded page under one renewable fence, then
// commits quarantine and missing-object findings for the complete report.
func (coordinator *ControlledInventoryReconciler) Reconcile(
	ctx context.Context,
	requested ControlledInventoryRequest,
) (ControlledInventoryResult, error) {
	if coordinator == nil || coordinator.control == nil || coordinator.inventory == nil {
		return ControlledInventoryResult{}, fmt.Errorf("%w: controlled inventory is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlString(requested.DriverID, 256) ||
		!validInventoryPath(requested.Prefix, 2_048) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ControlledInventoryResult{}, fmt.Errorf("%w: invalid controlled inventory request", ErrInvalidConfiguration)
	}

	operation, err := coordinator.control.CreateInventoryOperation(
		ctx,
		CreateInventoryOperationRequest(requested),
	)
	if err != nil {
		return ControlledInventoryResult{}, fmt.Errorf("create controlled inventory: %w", err)
	}

	lease, err := coordinator.control.ClaimInventoryOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledInventoryResult{}, fmt.Errorf("claim controlled inventory: %w", err)
	}

	inventoryContext, cancelInventory := context.WithCancel(ctx)
	leaseState := &renewedInventoryLease{lease: lease}
	renewalErrors := make(chan error, 1)

	renewalDone := make(chan struct{})
	go coordinator.renewLease(
		inventoryContext,
		cancelInventory,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	pageHashes := make([]string, 0, 8)

	var cursor string
	for sequence := uint64(1); ; sequence++ {
		page, listErr := coordinator.inventory.List(inventoryContext, operation.Prefix, cursor)
		if listErr != nil {
			return failControlledInventory(
				cancelInventory,
				renewalDone,
				renewalErrors,
				fmt.Errorf("list inventory page %d: %w", sequence, listErr),
			)
		}

		receipt, reportErr := coordinator.control.ReportInventoryPage(
			inventoryContext,
			operation,
			leaseState.current(),
			sequence,
			cursor,
			page,
		)
		if reportErr != nil {
			return failControlledInventory(cancelInventory, renewalDone, renewalErrors, reportErr)
		}

		pageHashes = append(pageHashes, receipt.ReportSHA256)

		if page.NextCursor == "" {
			break
		}

		if page.NextCursor == cursor {
			return failControlledInventory(
				cancelInventory,
				renewalDone,
				renewalErrors,
				fmt.Errorf("%w: inventory cursor did not advance", ErrControlPlaneResponse),
			)
		}

		cursor = page.NextCursor
	}

	reportSHA256, err := inventoryReportSHA256(pageHashes)
	if err != nil {
		return failControlledInventory(cancelInventory, renewalDone, renewalErrors, err)
	}

	completion, err := coordinator.control.CompleteInventory(
		inventoryContext,
		operation,
		leaseState.current(),
		uint64(len(pageHashes)),
		reportSHA256,
	)

	cancelInventory()
	<-renewalDone

	if err != nil {
		return ControlledInventoryResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
	}

	return ControlledInventoryResult{Operation: operation, Completion: completion}, nil
}

func failControlledInventory(
	cancel context.CancelFunc,
	done <-chan struct{},
	renewalErrors <-chan error,
	err error,
) (ControlledInventoryResult, error) {
	cancel()
	<-done

	return ControlledInventoryResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
}

type renewedInventoryLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedInventoryLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedInventoryLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledInventoryReconciler) renewLease(
	ctx context.Context,
	cancelInventory context.CancelFunc,
	operation InventoryOperation,
	state *renewedInventoryLease,
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
			renewed, err := coordinator.control.ClaimInventoryOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrInventoryLeaseLost, err):
				default:
				}

				cancelInventory()

				return
			}

			state.replace(renewed)
		}
	}
}
