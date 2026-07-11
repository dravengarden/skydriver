// Package archive defines Carrack's provider-neutral physical archive layout.
package archive

import (
	"errors"
	"fmt"
)

const (
	mebibyte = uint64(1 << 20)
	gibibyte = uint64(1 << 30)
)

// ErrInvalidLayout indicates an internally inconsistent archive layout.
var ErrInvalidLayout = errors.New("invalid archive layout")

// Layout controls physical block, encryption frame, and logical pack sizes.
type Layout struct {
	PhysicalBlockBytes uint64 `json:"physical_block_bytes" yaml:"physical_block_bytes"`
	CryptoFrameBytes   uint64 `json:"crypto_frame_bytes"   yaml:"crypto_frame_bytes"`
	LogicalPackBytes   uint64 `json:"logical_pack_bytes"   yaml:"logical_pack_bytes"`
}

// BlockSpan identifies one plaintext range in a logical object.
type BlockSpan struct {
	Ordinal uint64 `json:"ordinal" yaml:"ordinal"`
	Offset  uint64 `json:"offset"  yaml:"offset"`
	Size    uint64 `json:"size"    yaml:"size"`
}

// PackSpan identifies one independently keyed plaintext range.
type PackSpan struct {
	Ordinal uint64 `json:"ordinal" yaml:"ordinal"`
	Offset  uint64 `json:"offset"  yaml:"offset"`
	Size    uint64 `json:"size"    yaml:"size"`
}

// ExtentSpan identifies one independently transferable group of whole crypto
// frames inside a pack.
type ExtentSpan struct {
	Ordinal         uint64 `json:"ordinal"          yaml:"ordinal"`
	PlaintextOffset uint64 `json:"plaintext_offset" yaml:"plaintext_offset"`
	PlaintextSize   uint64 `json:"plaintext_size"   yaml:"plaintext_size"`
	FirstFrame      uint64 `json:"first_frame"      yaml:"first_frame"`
	FrameCount      uint64 `json:"frame_count"      yaml:"frame_count"`
}

// DefaultLayout returns the initial Carrack storage profile.
func DefaultLayout() Layout {
	return Layout{
		PhysicalBlockBytes: 64 * mebibyte,
		CryptoFrameBytes:   8 * mebibyte,
		LogicalPackBytes:   8 * gibibyte,
	}
}

// Validate checks relationships required for streaming encryption and packing.
func (layout Layout) Validate() error {
	if layout.PhysicalBlockBytes == 0 {
		return fmt.Errorf("%w: physical block size must be positive", ErrInvalidLayout)
	}

	if layout.CryptoFrameBytes == 0 {
		return fmt.Errorf("%w: crypto frame size must be positive", ErrInvalidLayout)
	}

	if layout.LogicalPackBytes == 0 {
		return fmt.Errorf("%w: logical pack size must be positive", ErrInvalidLayout)
	}

	if layout.PhysicalBlockBytes%layout.CryptoFrameBytes != 0 {
		return fmt.Errorf("%w: physical block size must be divisible by crypto frame size", ErrInvalidLayout)
	}

	if layout.LogicalPackBytes%layout.PhysicalBlockBytes != 0 {
		return fmt.Errorf("%w: logical pack size must be divisible by physical block size", ErrInvalidLayout)
	}

	return nil
}

// Plan divides a plaintext object into ordered physical block spans.
func (layout Layout) Plan(objectSize uint64) ([]BlockSpan, error) {
	if err := layout.Validate(); err != nil {
		return nil, err
	}

	if objectSize == 0 {
		return []BlockSpan{}, nil
	}

	blockCount := 1 + (objectSize-1)/layout.PhysicalBlockBytes
	spans := make([]BlockSpan, blockCount)

	for ordinal := range blockCount {
		offset := ordinal * layout.PhysicalBlockBytes
		size := min(layout.PhysicalBlockBytes, objectSize-offset)
		spans[ordinal] = BlockSpan{Ordinal: ordinal, Offset: offset, Size: size}
	}

	return spans, nil
}

// PlanPacks divides an object into ordered independently keyed pack ranges.
func (layout Layout) PlanPacks(objectSize uint64) ([]PackSpan, error) {
	if err := layout.Validate(); err != nil {
		return nil, err
	}

	if objectSize == 0 {
		return []PackSpan{}, nil
	}

	packCount := 1 + (objectSize-1)/layout.LogicalPackBytes
	packs := make([]PackSpan, packCount)

	for ordinal := range packCount {
		offset := ordinal * layout.LogicalPackBytes
		size := min(layout.LogicalPackBytes, objectSize-offset)
		packs[ordinal] = PackSpan{Ordinal: ordinal, Offset: offset, Size: size}
	}

	return packs, nil
}

// PlanExtents divides one pack into physical leaves without splitting a crypto
// frame. The final extent may contain a partial final frame.
func (layout Layout) PlanExtents(packSize uint64) ([]ExtentSpan, error) {
	if err := layout.Validate(); err != nil {
		return nil, err
	}

	if packSize == 0 || packSize > layout.LogicalPackBytes {
		return nil, fmt.Errorf("%w: pack size is out of range", ErrInvalidLayout)
	}

	extentCount := 1 + (packSize-1)/layout.PhysicalBlockBytes
	extents := make([]ExtentSpan, extentCount)
	framesPerExtent := layout.PhysicalBlockBytes / layout.CryptoFrameBytes

	for ordinal := range extentCount {
		offset := ordinal * layout.PhysicalBlockBytes
		size := min(layout.PhysicalBlockBytes, packSize-offset)
		frameCount := 1 + (size-1)/layout.CryptoFrameBytes
		extents[ordinal] = ExtentSpan{
			Ordinal:         ordinal,
			PlaintextOffset: offset,
			PlaintextSize:   size,
			FirstFrame:      ordinal * framesPerExtent,
			FrameCount:      frameCount,
		}
	}

	return extents, nil
}
