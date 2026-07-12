package sdk

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"
)

var (
	// ErrCompactLeaseLost indicates that compaction I/O was cancelled after renewal failed.
	ErrCompactLeaseLost = errors.New("carrack compact write lease was lost")
	// ErrCompactOperationFailed indicates that control-plane recovery invalidated
	// an exact idempotent compaction before it could publish.
	ErrCompactOperationFailed = errors.New("carrack compact operation previously failed")
)

// ControlledCompactor coordinates a plaintext bridge with one fenced generation CAS.
type ControlledCompactor struct {
	control         *ControlClient
	compactor       *Compactor
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledCompactRequest identifies one resumable immutable repack.
type ControlledCompactRequest struct {
	NamespaceID         string
	ManifestSHA256      string
	DestinationDriverID string
	DestinationPrefix   string
	IdempotencyKey      string
	StagingDirectory    string
	PlaintextPath       string
	PlanFile            string
}

// ControlledCompactResult contains the replacement payload and conditional publication.
type ControlledCompactResult struct {
	Operation        CompactOperation
	Execution        CompactExecutionResult
	StagedRecovery   StagedRecovery
	Publication      PublishedImport
	TelemetryWarning string
	CleanupWarning   string
	AlreadyPublished bool
}

// NewControlledCompactor constructs a compact coordinator with explicit renewal cadence.
func NewControlledCompactor(
	control *ControlClient,
	compactor *Compactor,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledCompactor, error) {
	if control == nil || compactor == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled compact configuration", ErrInvalidConfiguration)
	}

	return &ControlledCompactor{
		control: control, compactor: compactor, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Compact decrypts the pinned source, persists new pack IDs, writes a verified
// replacement, and publishes it only while the source object revision is current.
//
//nolint:funlen // The ordered lease, two-key, plaintext bridge, and publication saga stays explicit.
func (coordinator *ControlledCompactor) Compact(
	ctx context.Context,
	requested ControlledCompactRequest,
) (ControlledCompactResult, error) {
	if err := validateControlledCompact(coordinator, requested); err != nil {
		return ControlledCompactResult{}, err
	}

	operation, err := coordinator.control.CreateCompactOperation(ctx, CreateCompactOperationRequest{
		NamespaceID: requested.NamespaceID, ManifestSHA256: requested.ManifestSHA256,
		DestinationDriverID: requested.DestinationDriverID,
		IdempotencyKey:      requested.IdempotencyKey,
	})
	if err != nil {
		return ControlledCompactResult{}, fmt.Errorf("create controlled compact: %w", err)
	}

	switch operation.State {
	case operationStateSucceeded:
		return completedControlledCompact(operation, requested.PlaintextPath)
	case operationStateFailed, operationStateCancelled:
		return ControlledCompactResult{Operation: operation}, fmt.Errorf(
			"%w: operation %s",
			ErrCompactOperationFailed,
			operation.ID,
		)
	case operationStatePlanned, operationStateRunning:
	default:
		return ControlledCompactResult{}, fmt.Errorf(
			"%w: unsupported controlled compact state",
			ErrControlPlaneResponse,
		)
	}

	lease, err := coordinator.control.ClaimCompactOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledCompactResult{}, fmt.Errorf("claim controlled compact: %w", err)
	}

	compactContext, cancelCompact := context.WithCancel(ctx)
	leaseState := &renewedCompactLease{lease: lease}
	renewalErrors := make(chan error, 1)
	renewalDone := make(chan struct{})

	go coordinator.renewLease(
		compactContext, cancelCompact, operation, leaseState, renewalErrors, renewalDone,
	)

	sourceRecovery, err := coordinator.control.FetchCompactManifest(
		compactContext,
		operation,
		leaseState.current(),
	)
	if err != nil {
		return ControlledCompactResult{}, failControlledCompact(
			cancelCompact, renewalDone, renewalErrors, fmt.Errorf("fetch compact source: %w", err),
		)
	}

	if sourceRecovery.Manifest.PlaintextSHA256 != operation.SourcePlaintextSHA256 ||
		sourceRecovery.Manifest.PlaintextSize != operation.UsefulBytesTotal ||
		uint64(len(sourceRecovery.Manifest.Packs)) != operation.SourcePackCount {
		return ControlledCompactResult{}, failControlledCompact(
			cancelCompact,
			renewalDone,
			renewalErrors,
			fmt.Errorf("%w: compact source identity changed", ErrControlPlaneResponse),
		)
	}

	sourceKey, err := coordinator.control.GrantCompactSourceEpochKey(
		compactContext,
		operation,
		leaseState.current(),
	)
	if err != nil {
		return ControlledCompactResult{}, failControlledCompact(
			cancelCompact, renewalDone, renewalErrors, fmt.Errorf("grant compact source key: %w", err),
		)
	}
	defer clear(sourceKey[:])

	targetKey, err := coordinator.control.GrantCompactTargetEpochKey(
		compactContext,
		operation,
		leaseState.current(),
	)
	if err != nil {
		return ControlledCompactResult{}, failControlledCompact(
			cancelCompact, renewalDone, renewalErrors, fmt.Errorf("grant compact target key: %w", err),
		)
	}
	defer clear(targetKey[:])

	startedAt := time.Now()

	executed, err := coordinator.compactor.Execute(compactContext, CompactExecutionRequest{
		SourceRecovery: sourceRecovery, SourceEpochKey: sourceKey, TargetEpochKey: targetKey,
		ObjectID: operation.ObjectID, TargetGeneration: operation.TargetGeneration,
		TargetRootVersion: operation.TargetRootVersion, TargetKeyEpoch: operation.TargetKeyEpoch,
		DestinationDriverID: requested.DestinationDriverID,
		DestinationPrefix:   requested.DestinationPrefix, PlaintextPath: requested.PlaintextPath,
		PlanFile: requested.PlanFile, StagingDirectory: requested.StagingDirectory,
	})
	if err != nil {
		return ControlledCompactResult{}, failControlledCompact(
			cancelCompact, renewalDone, renewalErrors, err,
		)
	}

	staged, err := coordinator.control.StageRecovery(compactContext, executed.Import.Recovery)
	if err != nil {
		return ControlledCompactResult{}, failControlledCompact(
			cancelCompact, renewalDone, renewalErrors, err,
		)
	}

	telemetryWarning := coordinator.reportFinalProgress(
		compactContext,
		operation,
		leaseState.current(),
		executed,
		time.Since(startedAt),
	)
	published, publicationErr := coordinator.control.PublishCompact(
		compactContext,
		PublishCompactRequest{
			Operation: operation, Lease: leaseState.current(), SourceRecovery: sourceRecovery,
			StagedRecovery: staged, Result: executed.Import,
		},
	)

	cancelCompact()
	<-renewalDone

	if publicationErr != nil {
		return ControlledCompactResult{}, errors.Join(
			publicationErr,
			receiveRenewalError(renewalErrors),
		)
	}

	return ControlledCompactResult{
		Operation: operation, Execution: executed, StagedRecovery: staged,
		Publication: published, TelemetryWarning: telemetryWarning,
		CleanupWarning: cleanupCompactPlaintext(requested.PlaintextPath),
	}, nil
}

func completedControlledCompact(
	operation CompactOperation,
	plaintextPath string,
) (ControlledCompactResult, error) {
	if !validControlHex(operation.PublishedManifestSHA256, 64) ||
		!validControlString(operation.PublishedSidecarStorageKey, 4_096) {
		return ControlledCompactResult{}, fmt.Errorf(
			"%w: completed compact publication is incomplete",
			ErrControlPlaneResponse,
		)
	}

	return ControlledCompactResult{
		Operation: operation,
		Publication: PublishedImport{
			OperationID: operation.ID, ObjectID: operation.ObjectID,
			Generation:     operation.TargetGeneration,
			ManifestSHA256: operation.PublishedManifestSHA256, State: publicationStatePublished,
		},
		CleanupWarning: cleanupCompactPlaintext(plaintextPath), AlreadyPublished: true,
	}, nil
}

func validateControlledCompact(
	coordinator *ControlledCompactor,
	requested ControlledCompactRequest,
) error {
	if coordinator == nil || coordinator.control == nil || coordinator.compactor == nil {
		return fmt.Errorf("%w: controlled compactor is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.DestinationDriverID, 256) ||
		!validDestinationPrefix(requested.DestinationPrefix) ||
		!validControlString(requested.IdempotencyKey, 256) || requested.PlaintextPath == "" ||
		requested.PlanFile == "" {
		return fmt.Errorf("%w: invalid controlled compact request", ErrInvalidConfiguration)
	}

	if err := validateStagingDirectory(requested.StagingDirectory); err != nil {
		return fmt.Errorf("%w: invalid controlled compact staging: %w", ErrInvalidConfiguration, err)
	}

	return nil
}

func (coordinator *ControlledCompactor) reportFinalProgress(
	ctx context.Context,
	operation CompactOperation,
	lease OperationLease,
	executed CompactExecutionResult,
	active time.Duration,
) string {
	sample, err := finalImportProgress(executed.Import, active)
	if err != nil {
		return err.Error()
	}

	if executed.RestoreProgress.WireBytesRead > math.MaxUint64-sample.WireBytesRead ||
		executed.RestoreProgress.RetryCount > math.MaxUint64-sample.RetryCount {
		return "compact progress counters overflow"
	}

	sample.WireBytesRead += executed.RestoreProgress.WireBytesRead

	sample.RetryCount += executed.RestoreProgress.RetryCount
	if !signedProgressCounters(sample) {
		return "compact progress exceeds signed range"
	}

	if _, err := coordinator.control.ReportCompactProgress(ctx, operation, lease, sample); err != nil {
		return err.Error()
	}

	return ""
}

func cleanupCompactPlaintext(path string) string {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err.Error()
	}

	return ""
}

func failControlledCompact(
	cancel context.CancelFunc,
	done <-chan struct{},
	renewalErrors <-chan error,
	err error,
) error {
	cancel()
	<-done

	return errors.Join(err, receiveRenewalError(renewalErrors))
}

type renewedCompactLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedCompactLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedCompactLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledCompactor) renewLease(
	ctx context.Context,
	cancelCompact context.CancelFunc,
	operation CompactOperation,
	state *renewedCompactLease,
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
			renewed, err := coordinator.control.ClaimCompactOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrCompactLeaseLost, err):
				default:
				}

				cancelCompact()

				return
			}

			state.replace(renewed)
		}
	}
}
