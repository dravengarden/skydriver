package sdk

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrImportLeaseLost indicates that import I/O was cancelled after renewal failed.
var ErrImportLeaseLost = errors.New("carrack import write lease was lost")

// ControlledImporter coordinates a persisted import plan with fenced publication.
type ControlledImporter struct {
	control         *ControlClient
	importer        *Importer
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledImportRequest identifies one resumable encrypted import.
type ControlledImportRequest struct {
	NamespaceID            string
	ObjectID               string
	Generation             uint64
	SourceKey              string
	DestinationDriverID    string
	DestinationPrefix      string
	IdempotencyKey         string
	UsefulBytesTotal       *uint64
	ExpectedObjectRevision uint64
	StagingDirectory       string
	PlanFile               string
}

// ControlledImportResult contains the persisted plan and atomic publication result.
type ControlledImportResult struct {
	Operation        ImportOperation
	Plan             ImportPlan
	Import           ImportResult
	StagedRecovery   StagedRecovery
	Publication      PublishedImport
	TelemetryWarning string
	AlreadyPublished bool
}

// NewControlledImporter constructs an import coordinator with explicit lease renewal.
func NewControlledImporter(
	control *ControlClient,
	importer *Importer,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledImporter, error) {
	if control == nil || importer == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled import configuration", ErrInvalidConfiguration)
	}

	return &ControlledImporter{
		control: control, importer: importer, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Import persists every random pack identity before provider I/O, renews the
// write fence, and publishes only the verified payload and recovery copies.
func (coordinator *ControlledImporter) Import(
	ctx context.Context,
	requested ControlledImportRequest,
) (ControlledImportResult, error) {
	if err := validateControlledImport(coordinator, requested); err != nil {
		return ControlledImportResult{}, err
	}

	operation, err := coordinator.control.CreateImportOperation(ctx, CreateImportOperationRequest{
		NamespaceID: requested.NamespaceID, IdempotencyKey: requested.IdempotencyKey,
		UsefulBytesTotal: requested.UsefulBytesTotal,
	})
	if err != nil {
		return ControlledImportResult{}, fmt.Errorf("create controlled import: %w", err)
	}

	plan, err := coordinator.loadOrCreatePlan(ctx, requested, operation)
	if err != nil {
		return ControlledImportResult{}, err
	}

	if operation.State == operationStateSucceeded {
		return completedControlledImport(operation, plan)
	}

	lease, err := coordinator.control.ClaimImportOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledImportResult{}, fmt.Errorf("claim controlled import: %w", err)
	}

	importContext, cancelImport := context.WithCancel(ctx)
	leaseState := &renewedImportLease{lease: lease}
	renewalErrors := make(chan error, 1)
	renewalDone := make(chan struct{})

	go coordinator.renewLease(
		importContext,
		cancelImport,
		operation,
		leaseState,
		renewalErrors,
		renewalDone,
	)

	epochKey, err := coordinator.control.GrantImportEpochKey(
		importContext,
		operation,
		leaseState.current(),
	)
	if err != nil {
		return ControlledImportResult{}, failControlledImport(
			cancelImport,
			renewalDone,
			renewalErrors,
			fmt.Errorf("grant controlled import key: %w", err),
		)
	}
	defer clear(epochKey[:])

	startedAt := time.Now()

	imported, err := coordinator.importer.Execute(
		importContext,
		plan,
		epochKey,
		requested.StagingDirectory,
	)
	if err != nil {
		return ControlledImportResult{}, failControlledImport(cancelImport, renewalDone, renewalErrors, err)
	}

	staged, err := coordinator.control.StageRecovery(importContext, imported.Recovery)
	if err != nil {
		return ControlledImportResult{}, failControlledImport(cancelImport, renewalDone, renewalErrors, err)
	}

	telemetryWarning := coordinator.reportFinalProgress(
		importContext,
		operation,
		leaseState.current(),
		imported,
		time.Since(startedAt),
	)

	published, publicationErr := coordinator.control.PublishImport(importContext, PublishImportRequest{
		Operation: operation, Lease: leaseState.current(), StagedRecovery: staged,
		Result: imported, ExpectedObjectRevision: requested.ExpectedObjectRevision,
	})

	cancelImport()
	<-renewalDone

	if publicationErr != nil {
		return ControlledImportResult{}, errors.Join(
			publicationErr,
			receiveRenewalError(renewalErrors),
		)
	}

	return ControlledImportResult{
		Operation: operation, Plan: plan, Import: imported,
		StagedRecovery: staged, Publication: published, TelemetryWarning: telemetryWarning,
	}, nil
}

func completedControlledImport(
	operation ImportOperation,
	plan ImportPlan,
) (ControlledImportResult, error) {
	if operation.PublishedObjectID != plan.ObjectID ||
		operation.PublishedGeneration != plan.Generation ||
		operation.PublishedDestinationDriverID != plan.DestinationDriverID ||
		!strings.HasPrefix(
			operation.PublishedSidecarStorageKey,
			plan.DestinationPrefix+"/manifests/",
		) {
		return ControlledImportResult{}, fmt.Errorf(
			"%w: completed import publication differs from persisted plan",
			ErrControlPlaneResponse,
		)
	}

	return ControlledImportResult{
		Operation: operation,
		Plan:      plan,
		Publication: PublishedImport{
			OperationID: operation.ID, ObjectID: operation.PublishedObjectID,
			Generation:     operation.PublishedGeneration,
			ManifestSHA256: operation.PublishedManifestSHA256, State: publicationStatePublished,
		},
		AlreadyPublished: true,
	}, nil
}

func (coordinator *ControlledImporter) loadOrCreatePlan(
	ctx context.Context,
	requested ControlledImportRequest,
	operation ImportOperation,
) (ImportPlan, error) {
	plan, err := ReadImportPlan(requested.PlanFile)
	if err == nil {
		if identityErr := validateControlledImportPlan(plan, requested, operation); identityErr != nil {
			return ImportPlan{}, identityErr
		}

		return plan, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return ImportPlan{}, err
	}

	namespaceID, err := parseCryptoIdentifier(operation.NamespaceID)
	if err != nil {
		return ImportPlan{}, err
	}

	plan, err = coordinator.importer.PlanImport(ctx, ImportPlanRequest{
		NamespaceID: namespaceID, ObjectID: requested.ObjectID, Generation: requested.Generation,
		RootVersion: operation.RootVersion, KeyEpoch: operation.KeyEpoch,
		SourceKey: requested.SourceKey, DestinationDriverID: requested.DestinationDriverID,
		DestinationPrefix: requested.DestinationPrefix,
	})
	if err != nil {
		return ImportPlan{}, fmt.Errorf("plan controlled import: %w", err)
	}

	if err := validateControlledImportPlan(plan, requested, operation); err != nil {
		return ImportPlan{}, err
	}

	if err := WriteImportPlan(requested.PlanFile, plan); err != nil {
		return ImportPlan{}, err
	}

	return plan, nil
}

func (coordinator *ControlledImporter) reportFinalProgress(
	ctx context.Context,
	operation ImportOperation,
	lease OperationLease,
	imported ImportResult,
	active time.Duration,
) string {
	sample, err := finalImportProgress(imported, active)
	if err != nil {
		return err.Error()
	}

	if _, err := coordinator.control.ReportProgress(ctx, operation, lease, sample); err != nil {
		return err.Error()
	}

	return ""
}

func finalImportProgress(imported ImportResult, active time.Duration) (ProgressSample, error) {
	recovery, err := imported.Recovery.MarshalCanonical()
	if err != nil {
		return ProgressSample{}, fmt.Errorf("marshal import recovery for progress: %w", err)
	}

	written := uint64(len(recovery))
	for _, pack := range imported.Manifest.Packs {
		if pack.CiphertextSize > math.MaxUint64-written {
			return ProgressSample{}, fmt.Errorf("%w: import wire bytes overflow", ErrInvalidConfiguration)
		}

		written += pack.CiphertextSize
	}

	plaintext := imported.Manifest.PlaintextSize
	if written > math.MaxUint64-plaintext {
		return ProgressSample{}, fmt.Errorf("%w: import read bytes overflow", ErrInvalidConfiguration)
	}

	activeNanoseconds := max(active.Nanoseconds(), int64(1))

	sample := ProgressSample{
		Sequence: 1, WireBytesRead: plaintext + written, WireBytesWritten: written,
		UsefulBytesVerified: plaintext, ActiveNanoseconds: uint64(activeNanoseconds),
	}
	if !signedProgressCounters(sample) {
		return ProgressSample{}, fmt.Errorf("%w: import progress exceeds signed range", ErrInvalidConfiguration)
	}

	return sample, nil
}

func validateControlledImport(
	coordinator *ControlledImporter,
	requested ControlledImportRequest,
) error {
	if coordinator == nil || coordinator.control == nil || coordinator.importer == nil {
		return fmt.Errorf("%w: controlled importer is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validPlanString(requested.ObjectID, 2_048) || requested.Generation == 0 ||
		!validPlanString(requested.SourceKey, maximumProviderKeyBytes) ||
		!validControlString(requested.DestinationDriverID, 256) ||
		!validDestinationPrefix(requested.DestinationPrefix) ||
		!validControlString(requested.IdempotencyKey, 256) ||
		requested.ExpectedObjectRevision == 0 || requested.PlanFile == "" {
		return fmt.Errorf("%w: invalid controlled import request", ErrInvalidConfiguration)
	}

	if requested.UsefulBytesTotal != nil && *requested.UsefulBytesTotal > math.MaxInt64 {
		return fmt.Errorf("%w: import size exceeds signed range", ErrInvalidConfiguration)
	}

	if err := validateStagingDirectory(requested.StagingDirectory); err != nil {
		return fmt.Errorf("%w: invalid controlled import staging: %w", ErrInvalidConfiguration, err)
	}

	return nil
}

func validateControlledImportPlan(
	plan ImportPlan,
	requested ControlledImportRequest,
	operation ImportOperation,
) error {
	if plan.NamespaceID != operation.NamespaceID || plan.ObjectID != requested.ObjectID ||
		plan.Generation != requested.Generation || plan.RootVersion != operation.RootVersion ||
		plan.KeyEpoch != operation.KeyEpoch || plan.Source.Key != requested.SourceKey ||
		plan.DestinationDriverID != requested.DestinationDriverID ||
		plan.DestinationPrefix != requested.DestinationPrefix {
		return fmt.Errorf("%w: persisted import plan identity changed", ErrInvalidImportPlan)
	}

	if requested.UsefulBytesTotal != nil && plan.Source.SizeBytes != *requested.UsefulBytesTotal {
		return fmt.Errorf("%w: persisted import source size changed", ErrInvalidImportPlan)
	}

	return nil
}

func failControlledImport(
	cancel context.CancelFunc,
	done <-chan struct{},
	renewalErrors <-chan error,
	err error,
) error {
	cancel()
	<-done

	return errors.Join(err, receiveRenewalError(renewalErrors))
}

type renewedImportLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedImportLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedImportLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledImporter) renewLease(
	ctx context.Context,
	cancelImport context.CancelFunc,
	operation ImportOperation,
	state *renewedImportLease,
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
			renewed, err := coordinator.control.ClaimImportOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrImportLeaseLost, err):
				default:
				}

				cancelImport()

				return
			}

			state.replace(renewed)
		}
	}
}
