package archive_test

import (
	"errors"
	"reflect"
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

func TestPlanPacksAndExtentsPreservesFrameBoundaries(t *testing.T) {
	t.Parallel()

	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}

	packs, err := layout.PlanPacks(35)
	if err != nil {
		t.Fatalf("plan packs: %v", err)
	}

	if !reflect.DeepEqual(packs, []archive.PackSpan{
		{Ordinal: 0, Offset: 0, Size: 16},
		{Ordinal: 1, Offset: 16, Size: 16},
		{Ordinal: 2, Offset: 32, Size: 3},
	}) {
		t.Fatalf("unexpected pack plan: %+v", packs)
	}

	extents, err := layout.PlanExtents(packs[2].Size)
	if err != nil {
		t.Fatalf("plan final pack extents: %v", err)
	}

	if !reflect.DeepEqual(extents, []archive.ExtentSpan{
		{
			Ordinal:         0,
			PlaintextOffset: 0,
			PlaintextSize:   3,
			FirstFrame:      0,
			FrameCount:      2,
		},
	}) {
		t.Fatalf("unexpected extent plan: %+v", extents)
	}
}

func TestPlanExtentsRejectsEmptyAndOversizedPack(t *testing.T) {
	t.Parallel()

	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}

	for _, size := range []uint64{0, 17} {
		if _, err := layout.PlanExtents(size); !errors.Is(err, archive.ErrInvalidLayout) {
			t.Errorf("pack size %d: expected ErrInvalidLayout, got %v", size, err)
		}
	}
}

func TestLayoutTargetsNeverReservePaddingSlots(t *testing.T) {
	t.Parallel()

	layout := archive.Layout{
		PhysicalBlockBytes: 64,
		CryptoFrameBytes:   8,
		LogicalPackBytes:   256,
	}

	for _, objectSize := range []uint64{1, 63, 64, 65, 255, 256, 257, 1_003} {
		packs, err := layout.PlanPacks(objectSize)
		if err != nil {
			t.Fatalf("object %d: plan packs: %v", objectSize, err)
		}

		covered := uint64(0)
		for _, pack := range packs {
			if pack.Offset != covered {
				t.Fatalf("object %d: pack %d starts at %d after %d bytes", objectSize, pack.Ordinal, pack.Offset, covered)
			}

			extents, extentErr := layout.PlanExtents(pack.Size)
			if extentErr != nil {
				t.Fatalf("object %d pack %d: plan extents: %v", objectSize, pack.Ordinal, extentErr)
			}

			packCovered := uint64(0)
			for _, extent := range extents {
				if extent.PlaintextOffset != packCovered {
					t.Fatalf(
						"object %d pack %d: extent %d starts at %d after %d bytes",
						objectSize,
						pack.Ordinal,
						extent.Ordinal,
						extent.PlaintextOffset,
						packCovered,
					)
				}

				packCovered += extent.PlaintextSize
			}

			if packCovered != pack.Size {
				t.Fatalf("object %d pack %d: extents cover %d of %d bytes", objectSize, pack.Ordinal, packCovered, pack.Size)
			}

			covered += pack.Size
		}

		if covered != objectSize {
			t.Fatalf("object %d: packs cover %d bytes", objectSize, covered)
		}
	}
}
