package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dravengarden/carrack/manifest"
)

// ErrMoveLeaseLost indicates that move I/O was cancelled after renewal failed.
var ErrMoveLeaseLost = errors.New("carrack move write lease was lost")

// ControlledMover coordinates destination publication and source tombstoning.
type ControlledMover struct {
	control         *ControlClient
	replicator      *Replicator
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledMoveRequest identifies one complete ciphertext move saga.
type ControlledMoveRequest struct {
	NamespaceID         string
	ManifestSHA256      string
	SourceDriverID      string
	DestinationDriverID string
	DestinationPrefix   string
	IdempotencyKey      string
	StagingDirectory    string
}

// ControlledMoveResult ends at the durable source-delete grace handoff.
type ControlledMoveResult struct {
	Operation              MoveOperation
	Replication            ReplicationResult
	DestinationStaging     StagedRecovery
	DestinationPublication PublishedMoveDestination
	FinalSidecar           RecoverySidecar
	FinalStaging           StagedRecovery
	SourceTombstone        TombstonedMoveSource
}

// NewControlledMover constructs a move coordinator with an explicit renewal cadence.
func NewControlledMover(
	control *ControlClient,
	replicator *Replicator,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledMover, error) {
	if control == nil || replicator == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled move configuration", ErrInvalidConfiguration)
	}

	return &ControlledMover{
		control: control, replicator: replicator, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Move publishes verified destination replicas, then atomically removes the
// pinned source locations from recovery and starts their deletion grace period.
// Physical provider deletion remains the janitor's separate responsibility.
func (coordinator *ControlledMover) Move(
	ctx context.Context,
	requested ControlledMoveRequest,
) (ControlledMoveResult, error) {
	if err := validateControlledMove(coordinator, requested); err != nil {
		return ControlledMoveResult{}, err
	}

	operation, err := coordinator.control.CreateMoveOperation(ctx, CreateMoveOperationRequest{
		NamespaceID: requested.NamespaceID, ManifestSHA256: requested.ManifestSHA256,
		SourceDriverID:      requested.SourceDriverID,
		DestinationDriverID: requested.DestinationDriverID,
		IdempotencyKey:      requested.IdempotencyKey,
	})
	if err != nil {
		return ControlledMoveResult{}, fmt.Errorf("create controlled move: %w", err)
	}

	lease, err := coordinator.control.ClaimMoveOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledMoveResult{}, fmt.Errorf("claim controlled move: %w", err)
	}

	recovery, err := coordinator.control.FetchMoveManifest(ctx, operation, lease)
	if err != nil {
		return ControlledMoveResult{}, fmt.Errorf("fetch controlled move manifest: %w", err)
	}

	moveContext, cancelMove := context.WithCancel(ctx)
	leaseState := &renewedMoveLease{lease: lease}
	renewalErrors := make(chan error, 1)
	renewalDone := make(chan struct{})

	go coordinator.renewLease(
		moveContext,
		cancelMove,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	replicated, err := coordinator.replicator.Replicate(moveContext, ReplicationRequest{
		Recovery: recovery, DestinationDriverID: requested.DestinationDriverID,
		DestinationPrefix: requested.DestinationPrefix,
		StagingDirectory:  requested.StagingDirectory,
	})
	if err != nil {
		return failControlledMove(cancelMove, renewalDone, renewalErrors, err)
	}

	destinationStaging, err := coordinator.control.StageRecovery(moveContext, replicated.Recovery)
	if err != nil {
		return failControlledMove(cancelMove, renewalDone, renewalErrors, err)
	}

	destinationPublication, err := coordinator.control.PublishMoveDestination(
		moveContext,
		PublishMoveDestinationRequest{
			Operation: operation, Lease: leaseState.current(),
			StagedRecovery: destinationStaging, Result: replicated,
		},
	)
	if err != nil {
		return failControlledMove(cancelMove, renewalDone, renewalErrors, err)
	}

	finalRecovery, err := recoveryWithoutDriver(
		replicated.Recovery,
		operation.SourceDriverID,
		operation.SourceLocationCount,
	)
	if err != nil {
		return failControlledMove(cancelMove, renewalDone, renewalErrors, err)
	}

	finalSidecar, err := coordinator.replicator.WriteRecoverySidecar(
		moveContext,
		requested.DestinationPrefix,
		finalRecovery,
	)
	if err != nil {
		return failControlledMove(cancelMove, renewalDone, renewalErrors, err)
	}

	finalStaging, err := coordinator.control.StageRecovery(moveContext, finalRecovery)
	if err != nil {
		return failControlledMove(cancelMove, renewalDone, renewalErrors, err)
	}

	tombstone, err := coordinator.control.TombstoneMoveSource(
		moveContext,
		TombstoneMoveSourceRequest{
			Operation: operation, Lease: leaseState.current(), CurrentRecovery: replicated.Recovery,
			FinalSidecar: finalSidecar, StagedRecovery: finalStaging,
		},
	)

	cancelMove()
	<-renewalDone

	if err != nil {
		return ControlledMoveResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
	}

	return ControlledMoveResult{
		Operation: operation, Replication: replicated,
		DestinationStaging: destinationStaging, DestinationPublication: destinationPublication,
		FinalSidecar: finalSidecar, FinalStaging: finalStaging, SourceTombstone: tombstone,
	}, nil
}

func failControlledMove(
	cancel context.CancelFunc,
	done <-chan struct{},
	renewalErrors <-chan error,
	err error,
) (ControlledMoveResult, error) {
	cancel()
	<-done

	return ControlledMoveResult{}, errors.Join(err, receiveRenewalError(renewalErrors))
}

type renewedMoveLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedMoveLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedMoveLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledMover) renewLease(
	ctx context.Context,
	cancelMove context.CancelFunc,
	operation MoveOperation,
	state *renewedMoveLease,
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
			renewed, err := coordinator.control.ClaimMoveOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrMoveLeaseLost, err):
				default:
				}

				cancelMove()

				return
			}

			state.replace(renewed)
		}
	}
}

func recoveryWithoutDriver(
	recovery manifest.RecoveryManifest,
	driverID string,
	expectedLocations uint64,
) (manifest.RecoveryManifest, error) {
	locations := make([]manifest.Location, 0, len(recovery.Locations))
	removed := uint64(0)

	for _, location := range recovery.Locations {
		if location.DriverID == driverID {
			removed++
			continue
		}

		locations = append(locations, location)
	}

	if removed != expectedLocations {
		return manifest.RecoveryManifest{}, fmt.Errorf(
			"%w: move source location count changed: removed %d, expected %d",
			ErrInvalidReplication,
			removed,
			expectedLocations,
		)
	}

	finalRecovery, err := manifest.NewRecoveryManifest(recovery.Manifest, locations)
	if err != nil {
		return manifest.RecoveryManifest{}, fmt.Errorf("construct move tombstone recovery: %w", err)
	}

	return finalRecovery, nil
}

func validateControlledMove(coordinator *ControlledMover, requested ControlledMoveRequest) error {
	if coordinator == nil || coordinator.control == nil || coordinator.replicator == nil {
		return fmt.Errorf("%w: controlled mover is not initialized", ErrInvalidConfiguration)
	}

	if !validControlledMoveIdentity(requested) {
		return fmt.Errorf("%w: invalid controlled move request", ErrInvalidConfiguration)
	}

	if err := validateStagingDirectory(requested.StagingDirectory); err != nil {
		return fmt.Errorf("%w: invalid controlled move staging: %w", ErrInvalidConfiguration, err)
	}

	return nil
}

func validControlledMoveIdentity(requested ControlledMoveRequest) bool {
	return validControlHex(requested.NamespaceID, 32) &&
		validControlHex(requested.ManifestSHA256, 64) &&
		validControlString(requested.SourceDriverID, 256) &&
		validControlString(requested.DestinationDriverID, 256) &&
		requested.SourceDriverID != requested.DestinationDriverID &&
		validDestinationPrefix(requested.DestinationPrefix) &&
		validControlString(requested.IdempotencyKey, 256)
}
