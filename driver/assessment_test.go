package driver

import (
	"errors"
	"reflect"
	"testing"
)

func degradedDescriptor() Descriptor {
	capabilities := fullCapabilities()
	capabilities.Read.Range = SupportUnavailable
	capabilities.Read.MaxParallelRanges = 0
	capabilities.Read.MaximumRangeBytes = 0
	capabilities.Write.Resume = SupportUnavailable
	capabilities.Write.ParallelParts = SupportUnavailable
	capabilities.Write.PartOrdering = PartOrderingNone
	capabilities.Write.MaxParallelParts = 0
	capabilities.Write.MinimumNonFinalPartBytes = 0
	capabilities.Write.MaximumPartBytes = 0
	capabilities.Write.MaximumParts = 0
	capabilities.Write.UploadSessionTTLSeconds = 0
	capabilities.PreferredPartBytes = 0
	capabilities.Integrity.StrongUploadChecksum = SupportUnavailable
	capabilities.Integrity.Algorithms = nil
	capabilities.Integrity.RequiresReadback = true

	return Descriptor{
		ID:           "webdav-main",
		Kind:         "webdav/v1",
		Summary:      "sequential complete-object WebDAV driver",
		Capabilities: capabilities,
	}
}

func TestAssessmentWarnsBeforeCorrectnessPreservingFallbacks(t *testing.T) {
	t.Parallel()

	selected := degradedDescriptor()
	alternative := fullDescriptor("r2-main", "r2/v1")
	requirements := []Requirement{
		{Feature: FeatureRangeRead, Level: RequirementPreferred},
		{Feature: FeatureResumableWrite, Level: RequirementPreferred},
		{Feature: FeatureParallelWrite, Level: RequirementPreferred},
		{Feature: FeatureStrongUploadChecksum, Level: RequirementPreferred},
	}

	assessment, err := Assess(selected, requirements, []Descriptor{alternative})
	if err != nil {
		t.Fatalf("assess degraded driver: %v", err)
	}

	warningCodes := make([]WarningCode, 0, len(assessment.Warnings))
	for _, warning := range assessment.Warnings {
		if warning.CorrectnessImpact != "unchanged" || warning.Severity != "warning" {
			t.Fatalf("warning weakened correctness: %+v", warning)
		}

		if len(warning.Replacements) != 1 || warning.Replacements[0].DriverID != alternative.ID {
			t.Fatalf("warning omitted replacement: %+v", warning)
		}

		warningCodes = append(warningCodes, warning.Code)
	}

	expectedCodes := []WarningCode{
		WarningRangeReadUnavailable,
		WarningResumableWriteUnavailable,
		WarningParallelWriteUnavailable,
		WarningStrongUploadChecksumUnavailable,
	}
	if !reflect.DeepEqual(warningCodes, expectedCodes) {
		t.Fatalf("unexpected warning order: got %v want %v", warningCodes, expectedCodes)
	}
}

func TestAssessmentRejectsMissingRequiredCapability(t *testing.T) {
	t.Parallel()

	_, err := Assess(degradedDescriptor(), []Requirement{{
		Feature: FeatureResumableWrite,
		Level:   RequirementRequired,
	}}, nil)
	if !errors.Is(err, ErrRequiredCapability) {
		t.Fatalf("expected required-capability error, got %v", err)
	}
}

func TestAssessmentRejectsDuplicateAndUnknownRequirements(t *testing.T) {
	t.Parallel()

	selected := degradedDescriptor()
	tests := map[string][]Requirement{
		"duplicate": {
			{Feature: FeatureRangeRead, Level: RequirementPreferred},
			{Feature: FeatureRangeRead, Level: RequirementRequired},
		},
		"unknown feature": {{Feature: "unknown", Level: RequirementPreferred}},
		"unknown level":   {{Feature: FeatureRangeRead, Level: "unknown"}},
	}

	for name, requirements := range tests {
		if _, err := Assess(selected, requirements, nil); !errors.Is(err, ErrInvalidCapabilities) {
			t.Errorf("%s returned %v, expected invalid capabilities", name, err)
		}
	}
}

func TestAssessmentDoesNotWarnForAvailableFeature(t *testing.T) {
	t.Parallel()

	assessment, err := Assess(fullDescriptor("s3-main", "s3/v1"), []Requirement{{
		Feature: FeatureParallelRangeRead,
		Level:   RequirementPreferred,
	}}, nil)
	if err != nil {
		t.Fatalf("assess full driver: %v", err)
	}

	if len(assessment.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", assessment.Warnings)
	}
}
