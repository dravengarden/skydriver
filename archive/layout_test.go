package archive_test

import (
	"errors"
	"testing"

	"github.com/dravengarden/carrack/archive"
)

func TestDefaultLayout(t *testing.T) {
	t.Parallel()

	layout := archive.DefaultLayout()
	if err := layout.Validate(); err != nil {
		t.Fatalf("default layout must be valid: %v", err)
	}

	if layout.PhysicalBlockBytes != 64<<20 {
		t.Fatalf("default physical block must be 64 MiB, got %d bytes", layout.PhysicalBlockBytes)
	}
}

func TestLayoutRejectsMisalignedFrames(t *testing.T) {
	t.Parallel()

	layout := archive.Layout{PhysicalBlockBytes: 10, CryptoFrameBytes: 4, LogicalPackBytes: 20}
	err := layout.Validate()

	if !errors.Is(err, archive.ErrInvalidLayout) {
		t.Fatalf("expected ErrInvalidLayout, got %v", err)
	}
}

func TestLayoutPlansFinalPartialBlock(t *testing.T) {
	t.Parallel()

	layout := archive.Layout{PhysicalBlockBytes: 8, CryptoFrameBytes: 2, LogicalPackBytes: 16}

	spans, err := layout.Plan(18)
	if err != nil {
		t.Fatalf("plan object: %v", err)
	}

	if len(spans) != 3 {
		t.Fatalf("expected three spans, got %d", len(spans))
	}

	last := spans[2]
	if last.Ordinal != 2 || last.Offset != 16 || last.Size != 2 {
		t.Fatalf("unexpected final span: %+v", last)
	}
}
