package driver

import (
	"errors"
	"fmt"
)

// ErrRequiredCapability indicates that correctness policy forbids degradation.
var ErrRequiredCapability = errors.New("required Skydriver driver capability unavailable")

// Feature identifies one optional transfer acceleration evaluated before I/O.
type Feature string

const (
	// FeatureRangeRead requests exact partial-object downloads.
	FeatureRangeRead Feature = "range_read"
	// FeatureParallelRangeRead requests concurrent ranges from one object.
	FeatureParallelRangeRead Feature = "parallel_range_read"
	// FeatureResumableWrite requests durable provider upload sessions.
	FeatureResumableWrite Feature = "resumable_write"
	// FeatureParallelWrite requests concurrent parts for one final object.
	FeatureParallelWrite Feature = "parallel_write"
	// FeatureStrongUploadChecksum requests provider-side cryptographic proof.
	FeatureStrongUploadChecksum Feature = "strong_upload_checksum"
)

// RequirementLevel controls whether a missing feature warns or aborts.
type RequirementLevel string

const (
	// RequirementPreferred permits a documented warning and fallback.
	RequirementPreferred RequirementLevel = "preferred"
	// RequirementRequired rejects a driver that lacks the feature.
	RequirementRequired RequirementLevel = "required"
)

// Requirement asks the planner to evaluate one feature before payload I/O.
type Requirement struct {
	Feature Feature          `json:"feature"`
	Level   RequirementLevel `json:"level"`
}

// WarningCode is a stable machine-readable degradation identifier.
type WarningCode string

const (
	// WarningRangeReadUnavailable reports sequential whole-object fallback.
	WarningRangeReadUnavailable WarningCode = "driver.range_read_unavailable"
	// WarningParallelRangeReadUnavailable reports per-object read concurrency one.
	WarningParallelRangeReadUnavailable WarningCode = "driver.parallel_range_read_unavailable"
	// WarningResumableWriteUnavailable reports current-file restart fallback.
	WarningResumableWriteUnavailable WarningCode = "driver.resumable_write_unavailable"
	// WarningParallelWriteUnavailable reports sequential per-object upload.
	WarningParallelWriteUnavailable WarningCode = "driver.parallel_write_unavailable"
	// WarningStrongUploadChecksumUnavailable reports mandatory full readback.
	WarningStrongUploadChecksumUnavailable WarningCode = "driver.strong_upload_checksum_unavailable"
)

// Replacement describes another driver instance that satisfies a missing
// preferred feature.
type Replacement struct {
	DriverID   string `json:"driver_id"`
	DriverKind Kind   `json:"driver_kind"`
	Reason     string `json:"reason"`
}

// Warning describes one correctness-preserving transfer degradation. It is
// emitted once per operation before payload I/O and is safe for AI consumers.
type Warning struct {
	Code              WarningCode   `json:"code"`
	Severity          string        `json:"severity"`
	DriverID          string        `json:"driver_id"`
	DriverKind        Kind          `json:"driver_kind"`
	Feature           Feature       `json:"feature"`
	CorrectnessImpact string        `json:"correctness_impact"`
	PerformanceImpact string        `json:"performance_impact"`
	Fallback          string        `json:"fallback"`
	Replacements      []Replacement `json:"replacements"`
}

// Assessment is the deterministic capability result for one selected driver.
type Assessment struct {
	Warnings []Warning `json:"warnings"`
}

// Assess validates all descriptors, rejects unavailable required features, and
// returns deterministic warnings and replacement suggestions for unavailable
// preferred features. It performs no provider or payload I/O.
func Assess(
	selected Descriptor,
	requirements []Requirement,
	alternatives []Descriptor,
) (Assessment, error) {
	if err := selected.Validate(); err != nil {
		return Assessment{}, err
	}

	for _, alternative := range alternatives {
		if err := alternative.Validate(); err != nil {
			return Assessment{}, fmt.Errorf("validate alternative %q: %w", alternative.ID, err)
		}
	}

	warnings := make([]Warning, 0, len(requirements))
	seen := make(map[Feature]struct{}, len(requirements))

	for _, requirement := range requirements {
		if err := requirement.validate(); err != nil {
			return Assessment{}, err
		}

		if _, exists := seen[requirement.Feature]; exists {
			return Assessment{}, fmt.Errorf("%w: duplicate requirement %q", ErrInvalidCapabilities, requirement.Feature)
		}

		seen[requirement.Feature] = struct{}{}
		if selected.Capabilities.support(requirement.Feature).Available() {
			continue
		}

		if requirement.Level == RequirementRequired {
			return Assessment{}, fmt.Errorf(
				"%w: driver %q lacks %s",
				ErrRequiredCapability,
				selected.ID,
				requirement.Feature,
			)
		}

		warning, err := newWarning(selected, requirement.Feature, alternatives)
		if err != nil {
			return Assessment{}, err
		}

		warnings = append(warnings, warning)
	}

	return Assessment{Warnings: warnings}, nil
}

func (requirement Requirement) validate() error {
	if err := requirement.Feature.validate(); err != nil {
		return err
	}

	switch requirement.Level {
	case RequirementPreferred, RequirementRequired:
		return nil
	default:
		return fmt.Errorf("%w: unknown requirement level %q", ErrInvalidCapabilities, requirement.Level)
	}
}

func (feature Feature) validate() error {
	switch feature {
	case FeatureRangeRead,
		FeatureParallelRangeRead,
		FeatureResumableWrite,
		FeatureParallelWrite,
		FeatureStrongUploadChecksum:
		return nil
	default:
		return fmt.Errorf("%w: unknown feature %q", ErrInvalidCapabilities, feature)
	}
}

func (capabilities Capabilities) support(feature Feature) SupportMode {
	switch feature {
	case FeatureRangeRead:
		return capabilities.Read.Range
	case FeatureParallelRangeRead:
		if capabilities.Read.Range.Available() && capabilities.Read.MaxParallelRanges > 1 {
			return capabilities.Read.Range
		}

		return SupportUnavailable
	case FeatureResumableWrite:
		return capabilities.Write.Resume
	case FeatureParallelWrite:
		return capabilities.Write.ParallelParts
	case FeatureStrongUploadChecksum:
		return capabilities.Integrity.StrongUploadChecksum
	default:
		return SupportUnavailable
	}
}

func newWarning(selected Descriptor, feature Feature, alternatives []Descriptor) (Warning, error) {
	details, err := warningDetails(feature)
	if err != nil {
		return Warning{}, err
	}

	replacements := make([]Replacement, 0, len(alternatives))
	for _, alternative := range alternatives {
		if alternative.ID == selected.ID || !alternative.Capabilities.support(feature).Available() {
			continue
		}

		replacements = append(replacements, Replacement{
			DriverID:   alternative.ID,
			DriverKind: alternative.Kind,
			Reason:     fmt.Sprintf("supports %s", feature),
		})
	}

	return Warning{
		Code:              details.code,
		Severity:          "warning",
		DriverID:          selected.ID,
		DriverKind:        selected.Kind,
		Feature:           feature,
		CorrectnessImpact: "unchanged",
		PerformanceImpact: details.performanceImpact,
		Fallback:          details.fallback,
		Replacements:      replacements,
	}, nil
}

type warningDetail struct {
	code              WarningCode
	performanceImpact string
	fallback          string
}

func warningDetails(feature Feature) (warningDetail, error) {
	switch feature {
	case FeatureRangeRead:
		return warningDetail{
			code:              WarningRangeReadUnavailable,
			performanceImpact: "the current file must be downloaded as one sequential object",
			fallback:          "sequential_full_object_download",
		}, nil
	case FeatureParallelRangeRead:
		return warningDetail{
			code:              WarningParallelRangeReadUnavailable,
			performanceImpact: "one large file cannot use concurrent byte-range requests",
			fallback:          "single_range_download",
		}, nil
	case FeatureResumableWrite:
		return warningDetail{
			code:              WarningResumableWriteUnavailable,
			performanceImpact: "the current file restarts after an interrupted upload",
			fallback:          "restart_current_file",
		}, nil
	case FeatureParallelWrite:
		return warningDetail{
			code:              WarningParallelWriteUnavailable,
			performanceImpact: "one large file uploads sequentially while file-level concurrency remains available",
			fallback:          "sequential_single_file_upload",
		}, nil
	case FeatureStrongUploadChecksum:
		return warningDetail{
			code:              WarningStrongUploadChecksumUnavailable,
			performanceImpact: "publication requires one complete provider readback",
			fallback:          "complete_readback_verification",
		}, nil
	default:
		return warningDetail{}, fmt.Errorf("%w: unknown feature %q", ErrInvalidCapabilities, feature)
	}
}
