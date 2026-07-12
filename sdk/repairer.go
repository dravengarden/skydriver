package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

// ErrRepairIntegrity indicates reconstructed bytes failed exact destination readback.
var ErrRepairIntegrity = errors.New("carrack repaired object integrity check failed")

// Repairer reconstructs missing immutable objects without changing recovery metadata.
type Repairer struct {
	fetcher            *transfer.Fetcher
	destinations       map[string]provider.ReadWriter
	maximumObjectBytes uint64
}

// RepairResult contains only independently verified provider writes.
type RepairResult struct {
	ManifestSHA256    string            `json:"manifest_sha256"     yaml:"manifest_sha256"`
	ProviderObjects   []provider.Object `json:"provider_objects"    yaml:"provider_objects"`
	ObjectsRepaired   uint64            `json:"objects_repaired"    yaml:"objects_repaired"`
	ExtentsRepaired   uint64            `json:"extents_repaired"    yaml:"extents_repaired"`
	CiphertextBytes   uint64            `json:"ciphertext_bytes"    yaml:"ciphertext_bytes"`
	ReplicaRetryCount uint64            `json:"replica_retry_count" yaml:"replica_retry_count"`
}

// NewRepairer validates explicit source readers, destinations, and bounds.
func NewRepairer(
	readers map[string]provider.Reader,
	destinations map[string]provider.ReadWriter,
	maximumExtentBytes,
	maximumObjectBytes uint64,
) (*Repairer, error) {
	fetcher, err := transfer.NewFetcher(readers, maximumExtentBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: construct repair fetcher: %w", ErrInvalidRepair, err)
	}

	if len(destinations) == 0 || maximumObjectBytes == 0 || maximumObjectBytes > math.MaxInt64 {
		return nil, fmt.Errorf("%w: destinations and object bound are required", ErrInvalidRepair)
	}

	registered := make(map[string]provider.ReadWriter, len(destinations))
	for driverID, destination := range destinations {
		if !validControlString(driverID, 256) || destination == nil {
			return nil, fmt.Errorf("%w: invalid repair destination", ErrInvalidRepair)
		}

		registered[driverID] = destination
	}

	return &Repairer{
		fetcher: fetcher, destinations: registered, maximumObjectBytes: maximumObjectBytes,
	}, nil
}

// Repair reconstructs each complete target object through a bounded staging file.
func (repairer *Repairer) Repair(
	ctx context.Context,
	plan RepairPlan,
	stagingDirectory string,
) (RepairResult, error) {
	if repairer == nil || repairer.fetcher == nil || len(repairer.destinations) == 0 {
		return RepairResult{}, fmt.Errorf("%w: repairer is not initialized", ErrInvalidRepair)
	}

	if !validControlHex(plan.ManifestSHA256, 64) || len(plan.Objects) == 0 {
		return RepairResult{}, fmt.Errorf("%w: repair plan is empty or malformed", ErrInvalidRepair)
	}

	if err := validateStagingDirectory(stagingDirectory); err != nil {
		return RepairResult{}, fmt.Errorf("%w: staging directory: %w", ErrInvalidRepair, err)
	}

	result := RepairResult{
		ManifestSHA256:  plan.ManifestSHA256,
		ProviderObjects: make([]provider.Object, 0, len(plan.Objects)),
	}
	for index, object := range plan.Objects {
		repaired, statistics, err := repairer.repairObject(ctx, object, stagingDirectory)
		if err != nil {
			return RepairResult{}, fmt.Errorf("repair provider object %d: %w", index, err)
		}

		result.ProviderObjects = append(result.ProviderObjects, repaired)
		result.ObjectsRepaired++
		result.ExtentsRepaired += statistics.extents
		result.CiphertextBytes += statistics.bytes
		result.ReplicaRetryCount += statistics.retries
	}

	return result, nil
}

type repairStatistics struct {
	extents uint64
	bytes   uint64
	retries uint64
}

func (repairer *Repairer) repairObject(
	ctx context.Context,
	object RepairObject,
	stagingDirectory string,
) (_ provider.Object, _ repairStatistics, returnErr error) {
	destination, exists := repairer.destinations[object.DriverID]
	if !exists || object.Length == 0 || object.Length > repairer.maximumObjectBytes || len(object.Extents) == 0 {
		return provider.Object{}, repairStatistics{}, fmt.Errorf("%w: invalid repair object", ErrInvalidRepair)
	}

	temporary, createErr := os.CreateTemp(stagingDirectory, ".carrack-repair-object-*")
	if createErr != nil {
		return provider.Object{}, repairStatistics{}, fmt.Errorf("create repair staging file: %w", createErr)
	}

	path := temporary.Name()
	defer func() {
		returnErr = errors.Join(returnErr, temporary.Close(), os.Remove(path))
	}()

	hasher := sha256.New()
	statistics := repairStatistics{}

	expectedOffset := uint64(0)
	for _, extent := range object.Extents {
		if expectedOffset > object.Length || extent.Offset != expectedOffset ||
			extent.Length > object.Length-expectedOffset {
			return provider.Object{}, repairStatistics{}, fmt.Errorf("%w: repair extent layout changed", ErrInvalidRepair)
		}

		converted, err := repairTransferExtent(extent)
		if err != nil {
			return provider.Object{}, repairStatistics{}, err
		}

		verified, err := repairer.fetcher.Fetch(ctx, converted)
		if err != nil {
			return provider.Object{}, repairStatistics{}, fmt.Errorf("fetch repair extent: %w", err)
		}

		if err := writeReplicationExtent(temporary, hasher, verified.Data); err != nil {
			return provider.Object{}, repairStatistics{}, err
		}

		expectedOffset += extent.Length
		statistics.extents++
		statistics.bytes += extent.Length
		statistics.retries += verified.Attempts - 1
	}

	if expectedOffset != object.Length {
		return provider.Object{}, repairStatistics{}, fmt.Errorf("%w: repaired object length changed", ErrRepairIntegrity)
	}

	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return provider.Object{}, repairStatistics{}, fmt.Errorf("rewind repair staging file: %w", err)
	}

	digest := hasher.Sum(nil)

	uploaded, err := publishRepairObject(ctx, destination, temporary, object, digest)
	if err != nil {
		return provider.Object{}, repairStatistics{}, err
	}

	return uploaded, statistics, nil
}

func publishRepairObject(
	ctx context.Context,
	destination provider.ReadWriter,
	body io.Reader,
	object RepairObject,
	digest []byte,
) (provider.Object, error) {
	uploaded, err := destination.Put(ctx, object.StorageKey, body, provider.PutOptions{
		SizeBytes: object.Length, SHA256: hex.EncodeToString(digest),
	})
	if err != nil {
		return provider.Object{}, fmt.Errorf("upload repaired object: %w", err)
	}

	if uploaded.Key != object.StorageKey || uploaded.SizeBytes != object.Length {
		return provider.Object{}, fmt.Errorf("%w: repaired object identity changed", ErrRepairIntegrity)
	}

	if object.ProviderVersion != "" && uploaded.Version != object.ProviderVersion {
		return provider.Object{}, fmt.Errorf(
			"%w: provider version changed from %q to %q",
			ErrRepairRequiresRelocation,
			object.ProviderVersion,
			uploaded.Version,
		)
	}

	if verifyErr := verifyProviderObject(
		ctx,
		destination,
		object.StorageKey,
		object.Length,
		digest,
		ErrRepairIntegrity,
	); verifyErr != nil {
		return provider.Object{}, verifyErr
	}

	observed, err := destination.Stat(ctx, object.StorageKey)
	if err != nil {
		return provider.Object{}, fmt.Errorf("stat repaired object after readback: %w", err)
	}

	if observed.Key != object.StorageKey || observed.SizeBytes != object.Length ||
		(uploaded.Version != "" && observed.Version != uploaded.Version) ||
		(uploaded.ETag != "" && observed.ETag != "" && observed.ETag != uploaded.ETag) {
		return provider.Object{}, fmt.Errorf("%w: repaired object metadata changed", ErrRepairIntegrity)
	}

	if object.ProviderVersion != "" && observed.Version != object.ProviderVersion {
		return provider.Object{}, fmt.Errorf(
			"%w: observed provider version changed from %q to %q",
			ErrRepairRequiresRelocation,
			object.ProviderVersion,
			observed.Version,
		)
	}

	return observed, nil
}

func repairTransferExtent(extent RepairExtent) (transfer.Extent, error) {
	locations := make([]manifest.Location, len(extent.Sources))
	copy(locations, extent.Sources)

	return makeTransferExtent(manifest.Extent{
		CiphertextSHA256: extent.ExtentSHA256,
		CiphertextSize:   extent.Length,
	}, locations)
}
