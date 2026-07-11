package archive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
)

const (
	// BundlePlanSchemaVersion is the persisted pre-transfer membership format.
	BundlePlanSchemaVersion = "carrack.bundle-plan.v1"
	maximumBundlePlanBytes  = 64 << 20
)

// BundleFile describes one file before canonical offsets are assigned.
type BundleFile struct {
	Path string
	Size uint64
}

// BundleMember fixes one canonical file identity before transfer starts.
type BundleMember struct {
	Path   string `json:"path"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
}

// BundlePlan persists canonical ordering and exact gapless offsets. Readers and
// file hashes are intentionally not serialized here.
type BundlePlan struct {
	SchemaVersion string         `json:"schema_version"`
	DataBytes     uint64         `json:"data_bytes"`
	Members       []BundleMember `json:"members"`
}

// PlanBundle fixes canonical member ordering and gapless offsets.
func PlanBundle(files []BundleFile) (BundlePlan, error) {
	if files == nil {
		return BundlePlan{}, fmt.Errorf("%w: member array is required", ErrInvalidBundle)
	}

	ordered := slices.Clone(files)
	slices.SortFunc(ordered, func(left, right BundleFile) int {
		return strings.Compare(left.Path, right.Path)
	})

	plan := BundlePlan{
		SchemaVersion: BundlePlanSchemaVersion,
		Members:       make([]BundleMember, len(ordered)),
	}
	for ordinal, member := range ordered {
		plan.Members[ordinal] = BundleMember{
			Path:   member.Path,
			Offset: plan.DataBytes,
			Size:   member.Size,
		}

		if member.Size > math.MaxUint64-plan.DataBytes {
			return BundlePlan{}, fmt.Errorf("%w: member data size overflows", ErrInvalidBundle)
		}

		plan.DataBytes += member.Size
	}

	if err := plan.Validate(); err != nil {
		return BundlePlan{}, err
	}

	return plan, nil
}

// Validate proves that a persisted plan is canonical and contains no gaps.
func (plan BundlePlan) Validate() error {
	if plan.SchemaVersion != BundlePlanSchemaVersion || plan.Members == nil {
		return fmt.Errorf("%w: unsupported bundle-plan schema or null members", ErrInvalidBundle)
	}

	expectedOffset := uint64(0)
	previousPath := ""

	for ordinal, member := range plan.Members {
		if !validBundlePath(member.Path) || (ordinal > 0 && member.Path <= previousPath) {
			return fmt.Errorf("%w: member %d path is unsafe, duplicate, or unordered", ErrInvalidBundle, ordinal)
		}

		if member.Offset != expectedOffset || member.Size > math.MaxUint64-expectedOffset {
			return fmt.Errorf("%w: member %d introduces a gap or overflow", ErrInvalidBundle, ordinal)
		}

		expectedOffset += member.Size
		previousPath = member.Path
	}

	if expectedOffset != plan.DataBytes {
		return fmt.Errorf("%w: members cover %d bytes, expected %d", ErrInvalidBundle, expectedOffset, plan.DataBytes)
	}

	return nil
}

// MarshalCanonical returns stable persisted plan JSON.
func (plan BundlePlan) MarshalCanonical() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal Carrack bundle plan: %w", err)
	}

	if len(encoded) > maximumBundlePlanBytes {
		return nil, fmt.Errorf("%w: bundle plan exceeds %d bytes", ErrInvalidBundle, maximumBundlePlanBytes)
	}

	return encoded, nil
}

// ParseBundlePlan strictly decodes a persisted plan.
func ParseBundlePlan(encoded []byte) (BundlePlan, error) {
	if len(encoded) == 0 || len(encoded) > maximumBundlePlanBytes {
		return BundlePlan{}, fmt.Errorf("%w: encoded bundle plan size is out of range", ErrInvalidBundle)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var plan BundlePlan
	if err := decoder.Decode(&plan); err != nil {
		return BundlePlan{}, fmt.Errorf("%w: decode bundle plan: %w", ErrInvalidBundle, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BundlePlan{}, fmt.Errorf("%w: trailing bundle-plan JSON", ErrInvalidBundle)
	}

	if err := plan.Validate(); err != nil {
		return BundlePlan{}, err
	}

	return plan, nil
}

// WritePlannedBundle consumes exactly the members and sizes fixed by a plan.
// Missing, extra, short, or long sources are rejected.
func WritePlannedBundle(
	ctx context.Context,
	destination io.Writer,
	plan BundlePlan,
	readers map[string]io.Reader,
) (BundleResult, error) {
	if err := plan.Validate(); err != nil {
		return BundleResult{}, err
	}

	if len(readers) != len(plan.Members) {
		return BundleResult{}, fmt.Errorf("%w: reader set differs from persisted membership", ErrInvalidBundle)
	}

	sources := make([]BundleSource, len(plan.Members))
	for ordinal, member := range plan.Members {
		reader, exists := readers[member.Path]
		if !exists || reader == nil {
			return BundleResult{}, fmt.Errorf("%w: reader for %q is missing", ErrInvalidBundle, member.Path)
		}

		sources[ordinal] = BundleSource{Path: member.Path, Size: member.Size, Reader: reader}
	}

	return WriteBundle(ctx, destination, sources)
}
