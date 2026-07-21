package driver

import (
	"errors"
	"fmt"
)

// ErrInvalidCapabilities indicates an incomplete or contradictory declaration.
var ErrInvalidCapabilities = errors.New("invalid Skydriver driver capabilities")

// SupportMode states how one opened driver instance implements a capability.
// Opened instances must resolve server-dependent behavior through probing and
// report one of these effective modes before Skydriver plans payload I/O.
type SupportMode string

const (
	// SupportNative means the provider implements the capability directly.
	SupportNative SupportMode = "native"
	// SupportEmulated means the driver preserves the complete capability with a
	// local or provider-neutral implementation, potentially at additional cost.
	SupportEmulated SupportMode = "emulated"
	// SupportUnavailable means the capability cannot be used by this instance.
	SupportUnavailable SupportMode = "unavailable"
)

// Available reports whether the capability can be used without weakening its
// documented semantics.
func (mode SupportMode) Available() bool {
	return mode == SupportNative || mode == SupportEmulated
}

func (mode SupportMode) validate(name string) error {
	switch mode {
	case SupportNative, SupportEmulated, SupportUnavailable:
		return nil
	default:
		return fmt.Errorf("%w: %s has unknown support mode %q", ErrInvalidCapabilities, name, mode)
	}
}

// PartOrdering states which resumable upload part schedules a driver accepts.
type PartOrdering string

const (
	// PartOrderingNone means resumable part upload is unavailable.
	PartOrderingNone PartOrdering = "none"
	// PartOrderingSequential requires parts to be submitted in ascending order.
	PartOrderingSequential PartOrdering = "sequential"
	// PartOrderingArbitrary permits independent, out-of-order part completion.
	PartOrderingArbitrary PartOrdering = "arbitrary"
)

func (ordering PartOrdering) validate() error {
	switch ordering {
	case PartOrderingNone, PartOrderingSequential, PartOrderingArbitrary:
		return nil
	default:
		return fmt.Errorf("%w: unknown part ordering %q", ErrInvalidCapabilities, ordering)
	}
}

// ReadCapabilities describes complete and range reads from immutable objects.
type ReadCapabilities struct {
	// Complete states whether the driver can stream one complete pinned object.
	Complete SupportMode `json:"complete"`
	// Range states whether the driver can prove and return an exact byte range.
	Range SupportMode `json:"range"`
	// MaxParallelRanges is the safe per-object range request concurrency. It is
	// zero when Range is unavailable and positive otherwise.
	MaxParallelRanges uint32 `json:"max_parallel_ranges"`
	// MaximumRangeBytes is the provider or driver hard limit for one exact range
	// response. Zero means no smaller limit than MaximumObjectBytes. It must be
	// zero when range reads are unavailable.
	MaximumRangeBytes uint64 `json:"maximum_range_bytes,omitempty"`
}

// WriteCapabilities describes complete-object publication and resumable parts.
type WriteCapabilities struct {
	// Complete states whether one call can atomically publish a complete object.
	Complete SupportMode `json:"complete"`
	// Resume states whether an upload session and completed parts survive a
	// client restart and can be authoritatively queried before resuming.
	Resume SupportMode `json:"resume"`
	// ParallelParts states whether more than one part may be in flight for the
	// same final object. It is independent from resumability.
	ParallelParts SupportMode `json:"parallel_parts"`
	// PartOrdering constrains the order in which resumable parts may complete.
	PartOrdering PartOrdering `json:"part_ordering"`
	// MaxParallelParts is zero without resumable writes, one for sequential
	// sessions, and greater than one only for parallel multipart sessions.
	MaxParallelParts uint32 `json:"max_parallel_parts"`
	// MinimumNonFinalPartBytes is the hard minimum for every part except the
	// final part. It is positive for resumable writes and zero otherwise.
	MinimumNonFinalPartBytes uint64 `json:"minimum_non_final_part_bytes,omitempty"`
	// MaximumPartBytes is the hard encoded payload limit for one part. It is
	// positive for resumable writes and zero otherwise.
	MaximumPartBytes uint64 `json:"maximum_part_bytes,omitempty"`
	// MaximumParts is the maximum number of provider parts in one completed
	// object. It is positive for resumable writes and zero otherwise.
	MaximumParts uint32 `json:"maximum_parts,omitempty"`
	// UploadSessionTTLSeconds is zero for sessions without a provider deadline.
	UploadSessionTTLSeconds uint64 `json:"upload_session_ttl_seconds,omitempty"`
}

// ChecksumAlgorithm is a provider-verified complete-object checksum name.
type ChecksumAlgorithm string

// IntegrityCapabilities describes provider-side upload verification.
type IntegrityCapabilities struct {
	// StrongUploadChecksum states whether the provider verifies a caller-supplied
	// complete-object cryptographic checksum before publishing the object.
	StrongUploadChecksum SupportMode `json:"strong_upload_checksum"`
	// Algorithms lists the exact provider-verified algorithms when strong
	// checksum support is available.
	Algorithms []ChecksumAlgorithm `json:"algorithms,omitempty"`
	// RequiresReadback is true when Skydriver must read the completed object in
	// full to preserve publication correctness.
	RequiresReadback bool `json:"requires_readback"`
}

// Capabilities describes one opened driver instance. Every support field must
// be explicit; the zero value is invalid so a new driver cannot accidentally
// omit documentation for a feature.
type Capabilities struct {
	Read  ReadCapabilities  `json:"read"`
	Write WriteCapabilities `json:"write"`

	Delete         SupportMode `json:"delete"`
	Inventory      SupportMode `json:"inventory"`
	ServerSideCopy SupportMode `json:"server_side_copy"`

	Integrity IntegrityCapabilities `json:"integrity"`

	// MaximumObjectBytes is the hard complete-object limit. Zero means that the
	// provider exposes no smaller limit than Skydriver's protocol limit.
	MaximumObjectBytes uint64 `json:"maximum_object_bytes,omitempty"`
	// PreferredPartBytes is a transfer tuning hint and never changes file or
	// object identity. Zero means that the planner selects a safe default.
	PreferredPartBytes uint64 `json:"preferred_part_bytes,omitempty"`
	// SafeConcurrency is the maximum aggregate request concurrency for this
	// opened instance and credential scope.
	SafeConcurrency uint32 `json:"safe_concurrency"`
}

// Validate rejects contradictory, incomplete, or correctness-weakening
// capability declarations.
func (capabilities Capabilities) Validate() error {
	if err := capabilities.validateModes(); err != nil {
		return err
	}

	if err := capabilities.validateReads(); err != nil {
		return err
	}

	if err := capabilities.validateWrites(); err != nil {
		return err
	}

	if err := capabilities.validateIntegrity(); err != nil {
		return err
	}

	if capabilities.SafeConcurrency == 0 {
		return fmt.Errorf("%w: safe concurrency must be positive", ErrInvalidCapabilities)
	}

	if !capabilities.Read.Complete.Available() && !capabilities.Write.Complete.Available() {
		return fmt.Errorf("%w: at least one complete-object direction is required", ErrInvalidCapabilities)
	}

	return nil
}

func (capabilities Capabilities) validateModes() error {
	modes := []struct {
		name string
		mode SupportMode
	}{
		{name: "complete read", mode: capabilities.Read.Complete},
		{name: "range read", mode: capabilities.Read.Range},
		{name: "complete write", mode: capabilities.Write.Complete},
		{name: "resumable write", mode: capabilities.Write.Resume},
		{name: "parallel parts", mode: capabilities.Write.ParallelParts},
		{name: "delete", mode: capabilities.Delete},
		{name: "inventory", mode: capabilities.Inventory},
		{name: "server-side copy", mode: capabilities.ServerSideCopy},
		{name: "strong upload checksum", mode: capabilities.Integrity.StrongUploadChecksum},
	}

	for _, candidate := range modes {
		if err := candidate.mode.validate(candidate.name); err != nil {
			return err
		}
	}

	return nil
}

func (capabilities Capabilities) validateReads() error {
	if capabilities.Read.Range.Available() && !capabilities.Read.Complete.Available() {
		return fmt.Errorf("%w: range read requires complete read", ErrInvalidCapabilities)
	}

	if capabilities.Read.Range.Available() && capabilities.Read.MaxParallelRanges == 0 {
		return fmt.Errorf("%w: range read requires positive concurrency", ErrInvalidCapabilities)
	}

	if !capabilities.Read.Range.Available() && capabilities.Read.MaxParallelRanges != 0 {
		return fmt.Errorf("%w: unavailable range read cannot declare concurrency", ErrInvalidCapabilities)
	}

	if !capabilities.Read.Range.Available() && capabilities.Read.MaximumRangeBytes != 0 {
		return fmt.Errorf("%w: unavailable range read cannot declare a size limit", ErrInvalidCapabilities)
	}

	return nil
}

func (capabilities Capabilities) validateWrites() error {
	if err := capabilities.Write.PartOrdering.validate(); err != nil {
		return err
	}

	if !capabilities.Write.Complete.Available() {
		if capabilities.Write.Resume.Available() || capabilities.Write.ParallelParts.Available() {
			return fmt.Errorf("%w: write acceleration requires complete write", ErrInvalidCapabilities)
		}

		if capabilities.Write.PartOrdering != PartOrderingNone || capabilities.Write.hasPartLimits() {
			return fmt.Errorf("%w: unavailable writes cannot declare parts", ErrInvalidCapabilities)
		}

		return nil
	}

	if !capabilities.Write.Resume.Available() {
		if capabilities.Write.ParallelParts.Available() || capabilities.Write.PartOrdering != PartOrderingNone ||
			capabilities.Write.hasPartLimits() || capabilities.Write.UploadSessionTTLSeconds != 0 ||
			capabilities.PreferredPartBytes != 0 {
			return fmt.Errorf("%w: non-resumable writes cannot declare upload sessions", ErrInvalidCapabilities)
		}

		return nil
	}

	if err := capabilities.validateResumablePartLimits(); err != nil {
		return err
	}

	return capabilities.Write.validatePartConcurrency()
}

func (capabilities Capabilities) validateResumablePartLimits() error {
	writes := capabilities.Write
	if writes.PartOrdering == PartOrderingNone || writes.MaxParallelParts == 0 ||
		writes.MinimumNonFinalPartBytes == 0 || writes.MaximumPartBytes == 0 || writes.MaximumParts == 0 {
		return fmt.Errorf("%w: resumable write requires ordering, concurrency, and part limits", ErrInvalidCapabilities)
	}

	if writes.MinimumNonFinalPartBytes > writes.MaximumPartBytes {
		return fmt.Errorf("%w: minimum non-final part exceeds maximum part size", ErrInvalidCapabilities)
	}

	if capabilities.MaximumObjectBytes != 0 && writes.MinimumNonFinalPartBytes > capabilities.MaximumObjectBytes {
		return fmt.Errorf("%w: minimum non-final part exceeds maximum object size", ErrInvalidCapabilities)
	}

	if capabilities.PreferredPartBytes != 0 &&
		(capabilities.PreferredPartBytes < writes.MinimumNonFinalPartBytes ||
			capabilities.PreferredPartBytes > writes.MaximumPartBytes) {
		return fmt.Errorf("%w: preferred part size is outside hard part limits", ErrInvalidCapabilities)
	}

	return nil
}

func (capabilities WriteCapabilities) validatePartConcurrency() error {
	if capabilities.ParallelParts.Available() {
		if capabilities.PartOrdering != PartOrderingArbitrary || capabilities.MaxParallelParts < 2 {
			return fmt.Errorf("%w: parallel writes require arbitrary ordering and concurrency above one", ErrInvalidCapabilities)
		}

		return nil
	}

	if capabilities.PartOrdering != PartOrderingSequential || capabilities.MaxParallelParts != 1 {
		return fmt.Errorf("%w: sequential resumable writes require concurrency one", ErrInvalidCapabilities)
	}

	return nil
}

func (capabilities WriteCapabilities) hasPartLimits() bool {
	return capabilities.MaxParallelParts != 0 || capabilities.MinimumNonFinalPartBytes != 0 ||
		capabilities.MaximumPartBytes != 0 || capabilities.MaximumParts != 0
}

func (capabilities Capabilities) validateIntegrity() error {
	strongChecksum := capabilities.Integrity.StrongUploadChecksum.Available()
	if strongChecksum && len(capabilities.Integrity.Algorithms) == 0 {
		return fmt.Errorf("%w: strong upload checksum requires an algorithm", ErrInvalidCapabilities)
	}

	if !strongChecksum && len(capabilities.Integrity.Algorithms) != 0 {
		return fmt.Errorf("%w: unavailable strong checksum cannot list algorithms", ErrInvalidCapabilities)
	}

	if capabilities.Write.Complete.Available() && !strongChecksum && !capabilities.Integrity.RequiresReadback {
		return fmt.Errorf("%w: writes without strong checksum require full readback", ErrInvalidCapabilities)
	}

	if capabilities.Integrity.RequiresReadback && !capabilities.Read.Complete.Available() {
		return fmt.Errorf("%w: mandatory upload readback requires complete read support", ErrInvalidCapabilities)
	}

	if !capabilities.Write.Complete.Available() && capabilities.Integrity.RequiresReadback {
		return fmt.Errorf("%w: read-only driver cannot require upload readback", ErrInvalidCapabilities)
	}

	return nil
}
