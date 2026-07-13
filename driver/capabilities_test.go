package driver

import (
	"errors"
	"testing"
)

const testChecksumSHA256 ChecksumAlgorithm = "sha256"

func fullCapabilities() Capabilities {
	return Capabilities{
		Read: ReadCapabilities{
			Complete:          SupportNative,
			Range:             SupportNative,
			MaxParallelRanges: 8,
			MaximumRangeBytes: 64 << 20,
		},
		Write: WriteCapabilities{
			Complete:                 SupportNative,
			Resume:                   SupportNative,
			ParallelParts:            SupportNative,
			PartOrdering:             PartOrderingArbitrary,
			MaxParallelParts:         8,
			MinimumNonFinalPartBytes: 5 << 20,
			MaximumPartBytes:         5 << 30,
			MaximumParts:             10_000,
			UploadSessionTTLSeconds:  3600,
		},
		Delete:         SupportNative,
		Inventory:      SupportNative,
		ServerSideCopy: SupportNative,
		Integrity: IntegrityCapabilities{
			StrongUploadChecksum: SupportNative,
			Algorithms:           []ChecksumAlgorithm{testChecksumSHA256},
		},
		MaximumObjectBytes: 1 << 40,
		PreferredPartBytes: 8 << 20,
		SafeConcurrency:    16,
	}
}

func readOnlyCapabilities() Capabilities {
	return Capabilities{
		Read: ReadCapabilities{
			Complete:          SupportNative,
			Range:             SupportUnavailable,
			MaxParallelRanges: 0,
		},
		Write: WriteCapabilities{
			Complete:         SupportUnavailable,
			Resume:           SupportUnavailable,
			ParallelParts:    SupportUnavailable,
			PartOrdering:     PartOrderingNone,
			MaxParallelParts: 0,
		},
		Delete:         SupportUnavailable,
		Inventory:      SupportUnavailable,
		ServerSideCopy: SupportUnavailable,
		Integrity: IntegrityCapabilities{
			StrongUploadChecksum: SupportUnavailable,
			RequiresReadback:     false,
		},
		SafeConcurrency: 1,
	}
}

func TestCapabilitiesAcceptCompleteObjectDrivers(t *testing.T) {
	t.Parallel()

	for name, capabilities := range map[string]Capabilities{
		"full":      fullCapabilities(),
		"read-only": readOnlyCapabilities(),
	} {
		if err := capabilities.Validate(); err != nil {
			t.Errorf("%s capabilities failed validation: %v", name, err)
		}
	}
}

func TestCapabilitiesRejectContradictions(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Capabilities){
		"zero value": func(capabilities *Capabilities) {
			*capabilities = Capabilities{}
		},
		"range without complete read": func(capabilities *Capabilities) {
			capabilities.Read.Complete = SupportUnavailable
		},
		"range without concurrency": func(capabilities *Capabilities) {
			capabilities.Read.MaxParallelRanges = 0
		},
		"range limit without range": func(capabilities *Capabilities) {
			capabilities.Read.Range = SupportUnavailable
			capabilities.Read.MaxParallelRanges = 0
		},
		"resume without complete write": func(capabilities *Capabilities) {
			capabilities.Write.Complete = SupportUnavailable
		},
		"parallel without arbitrary ordering": func(capabilities *Capabilities) {
			capabilities.Write.PartOrdering = PartOrderingSequential
		},
		"parallel without concurrency": func(capabilities *Capabilities) {
			capabilities.Write.MaxParallelParts = 1
		},
		"resume without part count": func(capabilities *Capabilities) {
			capabilities.Write.MaximumParts = 0
		},
		"minimum part above maximum": func(capabilities *Capabilities) {
			capabilities.Write.MinimumNonFinalPartBytes = capabilities.Write.MaximumPartBytes + 1
		},
		"preferred part outside limits": func(capabilities *Capabilities) {
			capabilities.PreferredPartBytes = capabilities.Write.MinimumNonFinalPartBytes - 1
		},
		"strong checksum without algorithm": func(capabilities *Capabilities) {
			capabilities.Integrity.Algorithms = nil
		},
		"missing checksum without readback": func(capabilities *Capabilities) {
			capabilities.Integrity.StrongUploadChecksum = SupportUnavailable
			capabilities.Integrity.Algorithms = nil
			capabilities.Integrity.RequiresReadback = false
		},
		"readback without complete read": func(capabilities *Capabilities) {
			capabilities.Integrity.StrongUploadChecksum = SupportUnavailable
			capabilities.Integrity.Algorithms = nil
			capabilities.Integrity.RequiresReadback = true
			capabilities.Read.Complete = SupportUnavailable
			capabilities.Read.Range = SupportUnavailable
			capabilities.Read.MaxParallelRanges = 0
			capabilities.Read.MaximumRangeBytes = 0
		},
		"zero aggregate concurrency": func(capabilities *Capabilities) {
			capabilities.SafeConcurrency = 0
		},
	}

	for name, mutate := range tests {
		capabilities := fullCapabilities()
		mutate(&capabilities)

		if err := capabilities.Validate(); !errors.Is(err, ErrInvalidCapabilities) {
			t.Errorf("%s returned %v, expected invalid capabilities", name, err)
		}
	}
}

func TestSequentialResumableWriteIsIndependentFromParallelWrite(t *testing.T) {
	t.Parallel()

	capabilities := fullCapabilities()
	capabilities.Write.ParallelParts = SupportUnavailable
	capabilities.Write.PartOrdering = PartOrderingSequential
	capabilities.Write.MaxParallelParts = 1

	if err := capabilities.Validate(); err != nil {
		t.Fatalf("validate sequential resumable write: %v", err)
	}

	if !capabilities.Write.Resume.Available() || capabilities.Write.ParallelParts.Available() {
		t.Fatalf("unexpected sequential capabilities: %+v", capabilities.Write)
	}
}
