package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"strings"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
)

// VerificationCondition is the stable outcome of checking one physical location.
type VerificationCondition string

// VerificationState summarizes whether every selected location was verified.
type VerificationState string

const (
	// VerificationVerified proves the complete declared bytes match their identity.
	VerificationVerified VerificationCondition = "verified"
	// VerificationMissing means the provider explicitly proved object absence.
	VerificationMissing VerificationCondition = "missing"
	// VerificationCorrupt means the bytes have the wrong length or identity.
	VerificationCorrupt VerificationCondition = "corrupt"
	// VerificationUnavailable means the check was inconclusive.
	VerificationUnavailable VerificationCondition = "unavailable"
	// VerificationHealthy means every selected location verified successfully.
	VerificationHealthy VerificationState = "healthy"
	// VerificationDegraded means at least one selected location is missing or corrupt.
	VerificationDegraded VerificationState = "degraded"
	// VerificationUnverified means some checks were inconclusive.
	VerificationUnverified VerificationState = "unverified"
)

var errInvalidVerifier = errors.New("invalid Carrack verifier")

// VerificationEvidence records a non-secret, machine-readable location check.
type VerificationEvidence struct {
	ExtentSHA256   string                `json:"extent_sha256"             yaml:"extent_sha256"`
	DriverID       string                `json:"driver_id"                 yaml:"driver_id"`
	StorageKey     string                `json:"storage_key"               yaml:"storage_key"`
	Offset         uint64                `json:"offset"                    yaml:"offset"`
	Length         uint64                `json:"length"                    yaml:"length"`
	Condition      VerificationCondition `json:"condition"                 yaml:"condition"`
	ObservedSHA256 string                `json:"observed_sha256,omitempty" yaml:"observed_sha256,omitempty"`
}

// VerificationResult summarizes all locations selected for one recovery manifest.
type VerificationResult struct {
	ManifestSHA256 string                 `json:"manifest_sha256" yaml:"manifest_sha256"`
	State          VerificationState      `json:"state"           yaml:"state"`
	Verified       uint64                 `json:"verified"        yaml:"verified"`
	Missing        uint64                 `json:"missing"         yaml:"missing"`
	Corrupt        uint64                 `json:"corrupt"         yaml:"corrupt"`
	Unavailable    uint64                 `json:"unavailable"     yaml:"unavailable"`
	Evidence       []VerificationEvidence `json:"evidence"        yaml:"evidence"`
}

// Verifier streams complete ciphertext extents through SHA-256 without buffering them.
type Verifier struct {
	readers map[string]provider.Reader
}

// NewVerifier copies the provider reader registry. An empty registry is valid and
// produces unavailable evidence instead of preventing an audit from running.
func NewVerifier(readers map[string]provider.Reader) (*Verifier, error) {
	registered := make(map[string]provider.Reader, len(readers))
	for driverID, reader := range readers {
		if strings.TrimSpace(driverID) == "" || reader == nil {
			return nil, fmt.Errorf("%w: reader identity and implementation are required", errInvalidVerifier)
		}

		registered[driverID] = reader
	}

	return &Verifier{readers: registered}, nil
}

// Verify checks every location, or only the named driver when driverID is non-empty.
func (verifier *Verifier) Verify(ctx context.Context, recovery manifest.RecoveryManifest, driverID string) (VerificationResult, error) {
	if verifier == nil {
		return VerificationResult{}, fmt.Errorf("%w: verifier is required", errInvalidVerifier)
	}

	if err := recovery.Validate(); err != nil {
		return VerificationResult{}, fmt.Errorf("validate recovery manifest: %w", err)
	}

	result := VerificationResult{ManifestSHA256: recovery.ManifestSHA256, Evidence: make([]VerificationEvidence, 0, len(recovery.Locations))}
	for _, location := range recovery.Locations {
		if driverID != "" && location.DriverID != driverID {
			continue
		}

		if err := ctx.Err(); err != nil {
			return VerificationResult{}, fmt.Errorf("verify ciphertext locations: %w", err)
		}

		evidence := verifier.verifyLocation(ctx, location)

		result.Evidence = append(result.Evidence, evidence)
		switch evidence.Condition {
		case VerificationVerified:
			result.Verified++
		case VerificationMissing:
			result.Missing++
		case VerificationCorrupt:
			result.Corrupt++
		case VerificationUnavailable:
			result.Unavailable++
		default:
			return VerificationResult{}, fmt.Errorf(
				"%w: unsupported verification condition %q",
				errInvalidVerifier,
				evidence.Condition,
			)
		}
	}

	result.State = VerificationHealthy
	if result.Missing != 0 || result.Corrupt != 0 {
		result.State = VerificationDegraded
	} else if result.Unavailable != 0 || len(result.Evidence) == 0 {
		result.State = VerificationUnverified
	}

	return result, nil
}

func (verifier *Verifier) verifyLocation(ctx context.Context, location manifest.Location) VerificationEvidence {
	evidence := VerificationEvidence{ExtentSHA256: location.ExtentSHA256, DriverID: location.DriverID, StorageKey: location.StorageKey, Offset: location.Offset, Length: location.Length}

	reader, exists := verifier.readers[location.DriverID]
	if !exists {
		evidence.Condition = VerificationUnavailable
		return evidence
	}

	if location.Length > math.MaxInt64 {
		evidence.Condition = VerificationUnavailable
		return evidence
	}

	stream, err := reader.OpenRange(ctx, location.StorageKey, location.Offset, location.Length)
	if err != nil {
		if errors.Is(err, provider.ErrObjectNotFound) || errors.Is(err, fs.ErrNotExist) {
			evidence.Condition = VerificationMissing
		} else {
			evidence.Condition = VerificationUnavailable
		}

		return evidence
	}

	hash := sha256.New()

	written, readErr := io.CopyN(hash, stream, int64(location.Length))
	if readErr != nil {
		closeErr := stream.Close()

		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			evidence.Condition = VerificationCorrupt
		} else {
			evidence.Condition = VerificationUnavailable
		}

		_ = closeErr

		return evidence
	}

	var extra [1]byte

	extraBytes, extraErr := stream.Read(extra[:])
	closeErr := stream.Close()

	if written != int64(location.Length) || extraBytes != 0 {
		evidence.Condition = VerificationCorrupt
		return evidence
	}

	if (extraErr != nil && !errors.Is(extraErr, io.EOF)) || closeErr != nil {
		evidence.Condition = VerificationUnavailable
		return evidence
	}

	evidence.ObservedSHA256 = hex.EncodeToString(hash.Sum(nil))
	if evidence.ObservedSHA256 != location.ExtentSHA256 {
		evidence.Condition = VerificationCorrupt
		return evidence
	}

	evidence.Condition = VerificationVerified

	return evidence
}
