package sdk

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/dravengarden/carrack/provider"
)

var (
	// ErrInvalidQuarantineJanitor indicates missing control-plane, Stat, or delete capabilities.
	ErrInvalidQuarantineJanitor = errors.New("invalid Carrack quarantine janitor")
	// ErrQuarantineProviderStat indicates that final provider identity could not be observed.
	ErrQuarantineProviderStat = errors.New("carrack quarantine provider stat failed")
	// ErrQuarantineIdentityChanged indicates that provider identity no longer matches the tombstone.
	ErrQuarantineIdentityChanged = errors.New("carrack quarantined provider identity changed")
	// ErrQuarantineProviderDelete indicates that an authorized provider delete failed.
	ErrQuarantineProviderDelete = errors.New("carrack quarantine provider delete failed")
)

// QuarantineDeleteProvider supports the final immutable identity check and idempotent delete.
type QuarantineDeleteProvider interface {
	provider.Reader
	provider.Deleter
}

// QuarantineJanitor deletes only exact provider objects authorized by expired tombstones.
type QuarantineJanitor struct {
	control      *ControlClient
	providers    map[string]QuarantineDeleteProvider
	leaseSeconds uint64
}

// QuarantineSweepResult summarizes one tombstone operation's terminal cleanup state.
type QuarantineSweepResult struct {
	OperationID    string `json:"operation_id"    yaml:"operation_id"`
	ObjectsDeleted uint64 `json:"objects_deleted" yaml:"objects_deleted"`
	AlreadyAbsent  uint64 `json:"already_absent"  yaml:"already_absent"`
	State          string `json:"state"           yaml:"state"`
}

// NewQuarantineJanitor copies an explicit driver-to-Stat-and-delete capability map.
func NewQuarantineJanitor(
	control *ControlClient,
	providers map[string]QuarantineDeleteProvider,
	leaseSeconds uint64,
) (*QuarantineJanitor, error) {
	if control == nil || len(providers) == 0 || !validDeleteLeaseSeconds(leaseSeconds) {
		return nil, fmt.Errorf("%w: invalid configuration", ErrInvalidQuarantineJanitor)
	}

	copied := make(map[string]QuarantineDeleteProvider, len(providers))
	for driverID, target := range providers {
		if !validControlString(driverID, 256) || target == nil {
			return nil, fmt.Errorf("%w: invalid driver provider", ErrInvalidQuarantineJanitor)
		}

		copied[driverID] = target
	}

	return &QuarantineJanitor{
		control: control, providers: copied, leaseSeconds: leaseSeconds,
	}, nil
}

// Sweep performs Stat, final fenced revalidation, provider deletion, and ledger completion.
func (janitor *QuarantineJanitor) Sweep(
	ctx context.Context,
	operationID string,
) (QuarantineSweepResult, error) {
	if janitor == nil || janitor.control == nil || !validControlHex(operationID, 32) {
		return QuarantineSweepResult{}, fmt.Errorf("%w: invalid sweep", ErrInvalidQuarantineJanitor)
	}

	result := QuarantineSweepResult{OperationID: operationID}

	claim, err := janitor.control.ClaimQuarantineDelete(ctx, operationID, janitor.leaseSeconds)
	if err != nil {
		return result, fmt.Errorf("claim quarantine delete: %w", err)
	}

	switch claim.State {
	case operationStateDeleted:
		applyQuarantineDeleteOutcome(&result, claim.Outcome)
		result.State = operationStateDeleted

		return result, nil
	case quarantineDeleteStateSuperseded:
		result.State = quarantineDeleteStateSuperseded

		return result, nil
	case operationStateClaimed:
		return janitor.deleteClaimedObject(ctx, *claim.Task, result)
	default:
		return result, fmt.Errorf("%w: unsupported claim state", ErrInvalidQuarantineJanitor)
	}
}

func (janitor *QuarantineJanitor) deleteClaimedObject(
	ctx context.Context,
	task QuarantineDeleteTask,
	result QuarantineSweepResult,
) (QuarantineSweepResult, error) {
	target, exists := janitor.providers[task.DriverID]
	if !exists {
		failErr := janitor.control.FailQuarantineDelete(ctx, task, "delete_capability_unavailable")

		return result, errors.Join(
			fmt.Errorf("%w: driver %q", ErrInvalidQuarantineJanitor, task.DriverID),
			failErr,
		)
	}

	observed, statErr := target.Stat(ctx, task.StorageKey)

	alreadyAbsent := errors.Is(statErr, provider.ErrObjectNotFound) || errors.Is(statErr, fs.ErrNotExist)
	if statErr != nil && !alreadyAbsent {
		failErr := janitor.control.FailQuarantineDelete(ctx, task, "provider_stat_failed")

		return result, errors.Join(
			fmt.Errorf("%w: %w", ErrQuarantineProviderStat, statErr),
			failErr,
		)
	}

	if !alreadyAbsent && !quarantineProviderIdentityMatches(task, observed) {
		failErr := janitor.control.FailQuarantineDelete(ctx, task, "provider_identity_changed")

		return result, errors.Join(ErrQuarantineIdentityChanged, failErr)
	}

	revalidated, err := janitor.control.RevalidateQuarantineDelete(ctx, task, janitor.leaseSeconds)
	if err != nil {
		return result, fmt.Errorf("revalidate quarantine delete: %w", err)
	}

	outcome := quarantineDeleteOutcomeAbsent

	if !alreadyAbsent {
		if deleteErr := target.Delete(ctx, revalidated.StorageKey); deleteErr != nil {
			failErr := janitor.control.FailQuarantineDelete(
				ctx,
				revalidated,
				"provider_delete_failed",
			)

			return result, errors.Join(
				fmt.Errorf("%w: %w", ErrQuarantineProviderDelete, deleteErr),
				failErr,
			)
		}

		outcome = quarantineDeleteOutcomeDeleted
	}

	completed, err := janitor.control.CompleteQuarantineDelete(ctx, revalidated, outcome)
	if err != nil {
		return result, fmt.Errorf("complete quarantine delete: %w", err)
	}

	applyQuarantineDeleteOutcome(&result, completed.Outcome)
	result.State = completed.QuarantineState

	return result, nil
}

func quarantineProviderIdentityMatches(task QuarantineDeleteTask, observed provider.Object) bool {
	return observed.Key == task.StorageKey && observed.SizeBytes == task.SizeBytes &&
		optionalProviderIdentityMatches(task.ProviderVersion, observed.Version) &&
		optionalProviderIdentityMatches(task.ETag, observed.ETag)
}

func optionalProviderIdentityMatches(expected *string, observed string) bool {
	if expected == nil {
		return observed == ""
	}

	return *expected == observed
}

func applyQuarantineDeleteOutcome(result *QuarantineSweepResult, outcome string) {
	if outcome == quarantineDeleteOutcomeDeleted {
		result.ObjectsDeleted = 1
	}

	if outcome == quarantineDeleteOutcomeAbsent {
		result.AlreadyAbsent = 1
	}
}
