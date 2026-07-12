package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrCopyLeaseLost indicates that copy I/O was cancelled after renewal failed.
var ErrCopyLeaseLost = errors.New("carrack copy write lease was lost")

// ControlledReplicator coordinates a fenced copy with direct provider I/O.
type ControlledReplicator struct {
	control         *ControlClient
	replicator      *Replicator
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledCopyRequest identifies one complete ciphertext replication.
type ControlledCopyRequest struct {
	NamespaceID         string
	ManifestSHA256      string
	DestinationDriverID string
	DestinationPrefix   string
	IdempotencyKey      string
	StagingDirectory    string
}

// ControlledCopyResult contains the verified payload and fenced publication.
type ControlledCopyResult struct {
	Operation      CopyOperation
	Replication    ReplicationResult
	StagedRecovery StagedRecovery
	Publication    PublishedCopy
}

// NewControlledReplicator constructs a copy coordinator with an explicit renewal cadence.
func NewControlledReplicator(
	control *ControlClient,
	replicator *Replicator,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledReplicator, error) {
	if control == nil || replicator == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled copy configuration", ErrInvalidConfiguration)
	}

	return &ControlledReplicator{
		control: control, replicator: replicator, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Copy pins a recovery snapshot, maintains its write fence, replicates every
// ciphertext extent, and publishes the new recovery head only after readback.
func (coordinator *ControlledReplicator) Copy(
	ctx context.Context,
	requested ControlledCopyRequest,
) (ControlledCopyResult, error) {
	if coordinator == nil || coordinator.control == nil || coordinator.replicator == nil {
		return ControlledCopyResult{}, fmt.Errorf("%w: controlled replicator is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.DestinationDriverID, 256) ||
		!validDestinationPrefix(requested.DestinationPrefix) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ControlledCopyResult{}, fmt.Errorf("%w: invalid controlled copy request", ErrInvalidConfiguration)
	}

	if err := validateStagingDirectory(requested.StagingDirectory); err != nil {
		return ControlledCopyResult{}, fmt.Errorf("%w: invalid controlled copy staging: %w", ErrInvalidConfiguration, err)
	}

	operation, err := coordinator.control.CreateCopyOperation(ctx, CreateCopyOperationRequest{
		NamespaceID: requested.NamespaceID, ManifestSHA256: requested.ManifestSHA256,
		DestinationDriverID: requested.DestinationDriverID,
		IdempotencyKey:      requested.IdempotencyKey,
	})
	if err != nil {
		return ControlledCopyResult{}, fmt.Errorf("create controlled copy: %w", err)
	}

	lease, err := coordinator.control.ClaimCopyOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledCopyResult{}, fmt.Errorf("claim controlled copy: %w", err)
	}

	recovery, err := coordinator.control.FetchCopyManifest(ctx, operation, lease)
	if err != nil {
		return ControlledCopyResult{}, fmt.Errorf("fetch controlled copy manifest: %w", err)
	}

	copyContext, cancelCopy := context.WithCancel(ctx)
	leaseState := &renewedCopyLease{lease: lease}
	renewalErrors := make(chan error, 1)
	renewalDone := make(chan struct{})

	go coordinator.renewLease(
		copyContext,
		cancelCopy,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	replicated, replicationErr := coordinator.replicator.Replicate(
		copyContext,
		ReplicationRequest{
			Recovery: recovery, DestinationDriverID: requested.DestinationDriverID,
			DestinationPrefix: requested.DestinationPrefix,
			StagingDirectory:  requested.StagingDirectory,
		},
	)
	if replicationErr != nil {
		cancelCopy()
		<-renewalDone

		return ControlledCopyResult{}, errors.Join(replicationErr, receiveRenewalError(renewalErrors))
	}

	staged, stageErr := coordinator.control.StageRecovery(copyContext, replicated.Recovery)
	if stageErr != nil {
		cancelCopy()
		<-renewalDone

		return ControlledCopyResult{}, errors.Join(stageErr, receiveRenewalError(renewalErrors))
	}

	published, publicationErr := coordinator.control.PublishCopy(copyContext, PublishCopyRequest{
		Operation: operation, Lease: leaseState.current(), StagedRecovery: staged, Result: replicated,
	})

	cancelCopy()
	<-renewalDone

	if publicationErr != nil {
		return ControlledCopyResult{}, errors.Join(
			publicationErr,
			receiveRenewalError(renewalErrors),
		)
	}

	return ControlledCopyResult{
		Operation: operation, Replication: replicated,
		StagedRecovery: staged, Publication: published,
	}, nil
}

type renewedCopyLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedCopyLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedCopyLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledReplicator) renewLease(
	ctx context.Context,
	cancelCopy context.CancelFunc,
	operation CopyOperation,
	state *renewedCopyLease,
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
			renewed, err := coordinator.control.ClaimCopyOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrCopyLeaseLost, err):
				default:
				}

				cancelCopy()

				return
			}

			state.replace(renewed)
		}
	}
}
