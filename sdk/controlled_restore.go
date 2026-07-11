package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dravengarden/carrack/cryptostream"
)

// ErrRestoreLeaseLost indicates that provider I/O was cancelled after renewal failed.
var ErrRestoreLeaseLost = errors.New("carrack restore read lease was lost")

// ControlledRestorer coordinates the control-plane read lease with local I/O.
type ControlledRestorer struct {
	control         *ControlClient
	restorer        *Restorer
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledRestoreRequest identifies and authorizes one complete local restore.
type ControlledRestoreRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	IdempotencyKey string
	EpochKey       cryptostream.EpochKey
	Destination    string
}

// ControlledRestoreResult contains both local and control-plane publication results.
type ControlledRestoreResult struct {
	Operation        RestoreOperation
	Restore          RestoreResult
	Completion       CompletedRestore
	TelemetryWarning string
}

// NewControlledRestorer constructs a restore coordinator with an explicit renewal cadence.
func NewControlledRestorer(
	control *ControlClient,
	restorer *Restorer,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledRestorer, error) {
	if control == nil || restorer == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled restore configuration", ErrInvalidConfiguration)
	}

	return &ControlledRestorer{
		control: control, restorer: restorer, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Restore pins metadata, maintains its read lease during provider I/O, and
// records success only after the local restorer verifies and publishes plaintext.
func (coordinator *ControlledRestorer) Restore(
	ctx context.Context,
	requested ControlledRestoreRequest,
) (ControlledRestoreResult, error) {
	if coordinator == nil || coordinator.control == nil || coordinator.restorer == nil {
		return ControlledRestoreResult{}, fmt.Errorf("%w: controlled restorer is not initialized", ErrInvalidConfiguration)
	}

	operation, err := coordinator.control.CreateRestoreOperation(ctx, CreateRestoreOperationRequest{
		NamespaceID: requested.NamespaceID, ManifestSHA256: requested.ManifestSHA256,
		IdempotencyKey: requested.IdempotencyKey,
	})
	if err != nil {
		return ControlledRestoreResult{}, fmt.Errorf("create controlled restore: %w", err)
	}

	lease, err := coordinator.control.ClaimRestoreOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledRestoreResult{}, fmt.Errorf("claim controlled restore: %w", err)
	}

	recovery, err := coordinator.control.FetchRestoreManifest(ctx, operation, lease)
	if err != nil {
		return ControlledRestoreResult{}, fmt.Errorf("fetch controlled restore manifest: %w", err)
	}

	transferContext, cancelTransfer := context.WithCancel(ctx)
	leaseState := &renewedRestoreLease{lease: lease}
	progressReporter := &restoreProgressReporter{
		control: coordinator.control, operation: operation, leaseState: leaseState,
	}
	renewalErrors := make(chan error, 1)
	renewalDone := make(chan struct{})

	go coordinator.renewLease(
		transferContext,
		cancelTransfer,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	restored, restoreErr := coordinator.restorer.RestoreWithProgress(
		transferContext,
		recovery,
		requested.EpochKey,
		requested.Destination,
		func(progress RestoreProgress) {
			progressReporter.observe(transferContext, progress)
		},
	)

	cancelTransfer()
	<-renewalDone

	renewalErr := receiveRenewalError(renewalErrors)
	if restoreErr != nil || renewalErr != nil {
		if renewalErr == nil && terminalRestoreFailure(restoreErr) {
			_, failureErr := coordinator.control.FailRestoreOperation(
				ctx,
				operation,
				leaseState.current(),
				"plaintext_integrity",
			)

			return ControlledRestoreResult{}, errors.Join(restoreErr, failureErr)
		}

		return ControlledRestoreResult{}, errors.Join(restoreErr, renewalErr)
	}

	progressReporter.flush(ctx)

	completion, err := coordinator.control.CompleteRestoreOperation(
		ctx,
		operation,
		leaseState.current(),
		restored,
		recovery.Manifest.PlaintextSHA256,
	)
	if err != nil {
		return ControlledRestoreResult{}, fmt.Errorf("complete controlled restore: %w", err)
	}

	return ControlledRestoreResult{
		Operation: operation, Restore: restored, Completion: completion,
		TelemetryWarning: progressReporter.warning(),
	}, nil
}

func terminalRestoreFailure(err error) bool {
	return errors.Is(err, cryptostream.ErrFrameAuthentication) || errors.Is(err, ErrRestoreIntegrity)
}

type renewedRestoreLease struct {
	mutex sync.RWMutex
	lease RestoreReadLease
}

func (state *renewedRestoreLease) current() RestoreReadLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedRestoreLease) replace(lease RestoreReadLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledRestorer) renewLease(
	ctx context.Context,
	cancelTransfer context.CancelFunc,
	operation RestoreOperation,
	state *renewedRestoreLease,
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
			renewed, err := coordinator.control.ClaimRestoreOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrRestoreLeaseLost, err):
				default:
				}

				cancelTransfer()

				return
			}

			state.replace(renewed)
		}
	}
}

func receiveRenewalError(renewalErrors <-chan error) error {
	select {
	case err := <-renewalErrors:
		return err
	default:
		return nil
	}
}

type restoreProgressReporter struct {
	control    *ControlClient
	operation  RestoreOperation
	leaseState *renewedRestoreLease
	sequence   uint64
	latest     RestoreProgress
	pending    *ProgressSample
	lastError  error
}

func (reporter *restoreProgressReporter) observe(ctx context.Context, progress RestoreProgress) {
	reporter.latest = progress
	reporter.flush(ctx)
}

func (reporter *restoreProgressReporter) flush(ctx context.Context) {
	if reporter.pending != nil {
		if !reporter.send(ctx, *reporter.pending) {
			return
		}

		reporter.pending = nil
	}

	sample := ProgressSample{
		Sequence: reporter.sequence + 1, WireBytesRead: reporter.latest.WireBytesRead,
		UsefulBytesVerified: reporter.latest.UsefulBytesVerified,
		ActiveNanoseconds:   reporter.latest.ActiveNanoseconds,
		RetryCount:          reporter.latest.RetryCount,
	}
	if sample.Sequence == 1 && sample.UsefulBytesVerified == 0 {
		return
	}

	if !reporter.send(ctx, sample) {
		reporter.pending = &sample
	}
}

func (reporter *restoreProgressReporter) send(ctx context.Context, sample ProgressSample) bool {
	_, err := reporter.control.ReportRestoreProgress(
		ctx,
		reporter.operation,
		reporter.leaseState.current(),
		sample,
	)
	if err != nil {
		reporter.lastError = err

		return false
	}

	reporter.sequence = sample.Sequence
	reporter.lastError = nil

	return true
}

func (reporter *restoreProgressReporter) warning() string {
	if reporter.pending == nil || reporter.lastError == nil {
		return ""
	}

	return reporter.lastError.Error()
}
