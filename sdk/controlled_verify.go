package sdk

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrVerifyLeaseLost indicates that provider reads were cancelled after renewal failed.
var ErrVerifyLeaseLost = errors.New("carrack verify write lease was lost")

// ControlledVerifier coordinates one complete fenced driver audit.
type ControlledVerifier struct {
	control         *ControlClient
	verifier        *Verifier
	leaseSeconds    uint64
	renewalInterval time.Duration
}

// ControlledVerifyRequest identifies one idempotent driver audit.
type ControlledVerifyRequest struct {
	NamespaceID    string
	ManifestSHA256 string
	DriverID       string
	IdempotencyKey string
}

// ControlledVerifyResult contains local evidence and its durable completion.
type ControlledVerifyResult struct {
	Operation    VerifyOperation
	Verification VerificationResult
	Completion   CompletedVerify
}

// NewControlledVerifier constructs a verifier with an explicit renewal cadence.
func NewControlledVerifier(
	control *ControlClient,
	verifier *Verifier,
	leaseSeconds uint64,
	renewalInterval time.Duration,
) (*ControlledVerifier, error) {
	if control == nil || verifier == nil || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds || renewalInterval <= 0 ||
		renewalInterval >= time.Duration(leaseSeconds)*time.Second {
		return nil, fmt.Errorf("%w: invalid controlled verify configuration", ErrInvalidConfiguration)
	}

	return &ControlledVerifier{
		control: control, verifier: verifier, leaseSeconds: leaseSeconds,
		renewalInterval: renewalInterval,
	}, nil
}

// Verify pins recovery metadata, maintains its fence, checks every selected
// location, and commits evidence only after the complete audit finishes.
func (coordinator *ControlledVerifier) Verify(
	ctx context.Context,
	requested ControlledVerifyRequest,
) (ControlledVerifyResult, error) {
	if coordinator == nil || coordinator.control == nil || coordinator.verifier == nil {
		return ControlledVerifyResult{}, fmt.Errorf("%w: controlled verifier is not initialized", ErrInvalidConfiguration)
	}

	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlHex(requested.ManifestSHA256, 64) ||
		!validControlString(requested.DriverID, 256) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return ControlledVerifyResult{}, fmt.Errorf("%w: invalid controlled verify request", ErrInvalidConfiguration)
	}

	operation, err := coordinator.control.CreateVerifyOperation(ctx, CreateVerifyOperationRequest(requested))
	if err != nil {
		return ControlledVerifyResult{}, fmt.Errorf("create controlled verify: %w", err)
	}

	lease, err := coordinator.control.ClaimVerifyOperation(ctx, operation, coordinator.leaseSeconds)
	if err != nil {
		return ControlledVerifyResult{}, fmt.Errorf("claim controlled verify: %w", err)
	}

	recovery, err := coordinator.control.FetchVerifyManifest(ctx, operation, lease)
	if err != nil {
		return ControlledVerifyResult{}, fmt.Errorf("fetch controlled verify manifest: %w", err)
	}

	verifyContext, cancelVerify := context.WithCancel(ctx)
	leaseState := &renewedVerifyLease{lease: lease}
	renewalErrors := make(chan error, 1)

	renewalDone := make(chan struct{})
	go coordinator.renewLease(
		verifyContext, cancelVerify, operation, leaseState, renewalErrors, renewalDone,
	)

	verification, verifyErr := coordinator.verifier.Verify(
		verifyContext,
		recovery,
		requested.DriverID,
	)
	if verifyErr != nil {
		cancelVerify()
		<-renewalDone

		return ControlledVerifyResult{}, errors.Join(verifyErr, receiveRenewalError(renewalErrors))
	}

	completion, completionErr := coordinator.control.CompleteVerify(
		verifyContext,
		operation,
		leaseState.current(),
		verification,
	)

	cancelVerify()
	<-renewalDone

	if completionErr != nil {
		return ControlledVerifyResult{}, errors.Join(
			completionErr,
			receiveRenewalError(renewalErrors),
		)
	}

	return ControlledVerifyResult{
		Operation: operation, Verification: verification, Completion: completion,
	}, nil
}

type renewedVerifyLease struct {
	mutex sync.RWMutex
	lease OperationLease
}

func (state *renewedVerifyLease) current() OperationLease {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	return state.lease
}

func (state *renewedVerifyLease) replace(lease OperationLease) {
	state.mutex.Lock()
	state.lease = lease
	state.mutex.Unlock()
}

func (coordinator *ControlledVerifier) renewLease(
	ctx context.Context,
	cancelVerify context.CancelFunc,
	operation VerifyOperation,
	state *renewedVerifyLease,
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
			renewed, err := coordinator.control.ClaimVerifyOperation(
				ctx,
				operation,
				coordinator.leaseSeconds,
			)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				select {
				case renewalErrors <- fmt.Errorf("%w: %w", ErrVerifyLeaseLost, err):
				default:
				}

				cancelVerify()

				return
			}

			state.replace(renewed)
		}
	}
}
