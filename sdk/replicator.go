package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

var (
	// ErrInvalidReplication indicates missing dependencies or unsafe copy parameters.
	ErrInvalidReplication = errors.New("invalid Carrack ciphertext replication")
	// ErrReplicationIntegrity indicates that copied bytes failed destination readback.
	ErrReplicationIntegrity = errors.New("carrack replication destination integrity check failed")
)

// ReplicatorOptions bounds source extent memory and destination object grouping.
type ReplicatorOptions struct {
	MaximumExtentBytes         uint64
	ProviderObjectTargetBytes  uint64
	MaximumProviderObjectBytes uint64
}

// ReplicatorOptionsFromCapabilities combines an explicit source-memory bound
// with destination placement policy advertised by an opened driver.
func ReplicatorOptionsFromCapabilities(
	maximumExtentBytes uint64,
	capabilities provider.Capabilities,
) ReplicatorOptions {
	return ReplicatorOptions{
		MaximumExtentBytes:         maximumExtentBytes,
		ProviderObjectTargetBytes:  capabilities.PreferredObjectBytes,
		MaximumProviderObjectBytes: capabilities.MaximumObjectBytes,
	}
}

// Replicator performs provider-neutral location-only ciphertext copies.
type Replicator struct {
	fetcher             *transfer.Fetcher
	destination         provider.ReadWriter
	providerObjectBytes uint64
	maximumObjectBytes  uint64
}

// ReplicationRequest identifies one immutable recovery manifest and destination.
type ReplicationRequest struct {
	Recovery            manifest.RecoveryManifest
	DestinationDriverID string
	DestinationPrefix   string
	StagingDirectory    string
}

// ReplicationResult contains verified metadata that is safe for a later fenced publication.
type ReplicationResult struct {
	Recovery          manifest.RecoveryManifest
	Locations         []manifest.Location
	ProviderObjects   []provider.Object
	RecoveryKey       string
	RecoveryObject    provider.Object
	VerifiedExtents   uint64
	CiphertextBytes   uint64
	ReplicaRetryCount uint64
}

// RecoverySidecar is a verified provider copy of one recovery manifest.
type RecoverySidecar struct {
	Recovery manifest.RecoveryManifest
	Key      string
	Object   provider.Object
}

// NewReplicator validates source readers, a readable destination, and explicit bounds.
func NewReplicator(
	readers map[string]provider.Reader,
	destination provider.ReadWriter,
	options ReplicatorOptions,
) (*Replicator, error) {
	if destination == nil {
		return nil, fmt.Errorf("%w: readable destination is required", ErrInvalidReplication)
	}

	fetcher, err := transfer.NewFetcher(readers, options.MaximumExtentBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: construct source fetcher: %w", ErrInvalidReplication, err)
	}

	targetBytes, err := providerObjectTarget(
		options.ProviderObjectTargetBytes,
		options.MaximumProviderObjectBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidReplication, err)
	}

	return &Replicator{
		fetcher: fetcher, destination: destination,
		providerObjectBytes: targetBytes, maximumObjectBytes: options.MaximumProviderObjectBytes,
	}, nil
}

// Replicate copies and independently verifies every ciphertext extent before
// writing a content-addressed recovery sidecar. It never publishes metadata or
// deletes a source location.
func (replicator *Replicator) Replicate(
	ctx context.Context,
	request ReplicationRequest,
) (ReplicationResult, error) {
	if replicator == nil || replicator.fetcher == nil || replicator.destination == nil {
		return ReplicationResult{}, fmt.Errorf("%w: replicator is not initialized", ErrInvalidReplication)
	}

	if err := validateReplicationRequest(request); err != nil {
		return ReplicationResult{}, err
	}

	groups, err := replicator.planGroups(request.Recovery)
	if err != nil {
		return ReplicationResult{}, err
	}

	candidates := make([]manifest.Location, 0)
	objects := make([]provider.Object, 0, len(groups))
	statistics := replicationStatistics{}

	for groupIndex, group := range groups {
		copied, groupErr := replicator.replicateGroup(
			ctx,
			request,
			group,
		)
		if groupErr != nil {
			return ReplicationResult{}, fmt.Errorf("replicate provider object group %d: %w", groupIndex, groupErr)
		}

		candidates = append(candidates, copied.locations...)
		objects = append(objects, copied.object)

		if statisticsErr := statistics.add(copied.statistics); statisticsErr != nil {
			return ReplicationResult{}, statisticsErr
		}
	}

	merged, added := mergeReplicationLocations(request.Recovery.Locations, candidates)

	updatedRecovery, err := manifest.NewRecoveryManifest(request.Recovery.Manifest, merged)
	if err != nil {
		return ReplicationResult{}, fmt.Errorf("construct replicated recovery manifest: %w", err)
	}

	recoveryKey, recoveryObject, err := writeRecoverySidecar(
		ctx,
		replicator.destination,
		request.DestinationPrefix,
		updatedRecovery,
		replicator.maximumObjectBytes,
		ErrInvalidReplication,
		ErrReplicationIntegrity,
	)
	if err != nil {
		return ReplicationResult{}, fmt.Errorf("write replicated recovery sidecar: %w", err)
	}

	return ReplicationResult{
		Recovery: updatedRecovery, Locations: added, ProviderObjects: objects,
		RecoveryKey: recoveryKey, RecoveryObject: recoveryObject,
		VerifiedExtents: statistics.extents, CiphertextBytes: statistics.ciphertextBytes,
		ReplicaRetryCount: statistics.replicaRetries,
	}, nil
}

// WriteRecoverySidecar writes and reads back a content-addressed recovery
// manifest without copying payload bytes or publishing control-plane metadata.
func (replicator *Replicator) WriteRecoverySidecar(
	ctx context.Context,
	prefix string,
	recovery manifest.RecoveryManifest,
) (RecoverySidecar, error) {
	if replicator == nil || replicator.destination == nil {
		return RecoverySidecar{}, fmt.Errorf("%w: replicator is not initialized", ErrInvalidReplication)
	}

	if !validDestinationPrefix(prefix) {
		return RecoverySidecar{}, fmt.Errorf("%w: invalid recovery destination prefix", ErrInvalidReplication)
	}

	if err := recovery.Validate(); err != nil {
		return RecoverySidecar{}, fmt.Errorf("%w: invalid recovery sidecar: %w", ErrInvalidReplication, err)
	}

	key, object, err := writeRecoverySidecar(
		ctx,
		replicator.destination,
		prefix,
		recovery,
		replicator.maximumObjectBytes,
		ErrInvalidReplication,
		ErrReplicationIntegrity,
	)
	if err != nil {
		return RecoverySidecar{}, fmt.Errorf("write recovery sidecar: %w", err)
	}

	return RecoverySidecar{Recovery: recovery, Key: key, Object: object}, nil
}

type replicationExtent struct {
	manifest manifest.Extent
	transfer transfer.Extent
}

type replicationGroup struct {
	extents         []replicationExtent
	ciphertextBytes uint64
}

type replicatedGroup struct {
	locations  []manifest.Location
	object     provider.Object
	statistics replicationStatistics
}

func (replicator *Replicator) planGroups(recovery manifest.RecoveryManifest) ([]replicationGroup, error) {
	locations := indexRestoreLocations(recovery.Locations)
	groups := make([]replicationGroup, 0)

	for _, pack := range recovery.Manifest.Packs {
		current := replicationGroup{extents: make([]replicationExtent, 0)}

		for _, extent := range pack.Extents {
			if replicator.maximumObjectBytes > 0 && extent.CiphertextSize > replicator.maximumObjectBytes {
				return nil, fmt.Errorf(
					"%w: extent %s has %d bytes, destination maximum is %d",
					ErrInvalidReplication,
					extent.CiphertextSHA256,
					extent.CiphertextSize,
					replicator.maximumObjectBytes,
				)
			}

			if len(current.extents) > 0 &&
				(current.ciphertextBytes >= replicator.providerObjectBytes ||
					extent.CiphertextSize > replicator.providerObjectBytes-current.ciphertextBytes) {
				groups = append(groups, current)
				current = replicationGroup{extents: make([]replicationExtent, 0)}
			}

			if extent.CiphertextSize > math.MaxUint64-current.ciphertextBytes {
				return nil, fmt.Errorf("%w: destination object size overflows", ErrInvalidReplication)
			}

			converted, err := makeTransferExtent(extent, locations[extent.CiphertextSHA256])
			if err != nil {
				return nil, fmt.Errorf("%w: convert extent %s: %w", ErrInvalidReplication, extent.CiphertextSHA256, err)
			}

			current.extents = append(current.extents, replicationExtent{manifest: extent, transfer: converted})
			current.ciphertextBytes += extent.CiphertextSize
		}

		if len(current.extents) > 0 {
			groups = append(groups, current)
		}
	}

	return groups, nil
}

func (replicator *Replicator) replicateGroup(
	ctx context.Context,
	request ReplicationRequest,
	group replicationGroup,
) (_ replicatedGroup, returnErr error) {
	temporary, err := os.CreateTemp(request.StagingDirectory, ".carrack-replication-object-*")
	if err != nil {
		return replicatedGroup{}, fmt.Errorf("create replication staging file: %w", err)
	}

	temporaryPath := temporary.Name()

	defer func() {
		closeErr := temporary.Close()
		removeErr := os.Remove(temporaryPath)

		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}

		returnErr = errors.Join(returnErr, closeErr, removeErr)
	}()

	objectHash := sha256.New()
	locations := make([]manifest.Location, 0, len(group.extents))
	statistics := replicationStatistics{}
	objectOffset := uint64(0)

	for _, planned := range group.extents {
		verified, fetchErr := replicator.fetcher.Fetch(ctx, planned.transfer)
		if fetchErr != nil {
			return replicatedGroup{}, fmt.Errorf(
				"fetch extent %s: %w",
				planned.manifest.CiphertextSHA256,
				fetchErr,
			)
		}

		if writeErr := writeReplicationExtent(temporary, objectHash, verified.Data); writeErr != nil {
			return replicatedGroup{}, writeErr
		}

		locations = append(locations, manifest.Location{
			ExtentSHA256: planned.manifest.CiphertextSHA256,
			DriverID:     request.DestinationDriverID,
			Offset:       objectOffset,
			Length:       planned.manifest.CiphertextSize,
		})
		objectOffset += planned.manifest.CiphertextSize

		statistics.extents++
		statistics.ciphertextBytes += planned.manifest.CiphertextSize
		statistics.replicaRetries += verified.Attempts - 1
	}

	if objectOffset != group.ciphertextBytes {
		return replicatedGroup{}, fmt.Errorf(
			"%w: staged object has %d bytes, expected %d",
			ErrReplicationIntegrity,
			objectOffset,
			group.ciphertextBytes,
		)
	}

	if _, seekErr := temporary.Seek(0, io.SeekStart); seekErr != nil {
		return replicatedGroup{}, fmt.Errorf("rewind replication staging file: %w", seekErr)
	}

	digest := hex.EncodeToString(objectHash.Sum(nil))

	storageKey := providerObjectStorageKey(request.DestinationPrefix, digest)
	if !validPlanString(storageKey, maximumProviderKeyBytes) {
		return replicatedGroup{}, fmt.Errorf(
			"%w: destination storage key exceeds protocol bounds",
			ErrInvalidReplication,
		)
	}

	uploaded, err := replicator.destination.Put(ctx, storageKey, temporary, provider.PutOptions{
		SizeBytes: group.ciphertextBytes,
		SHA256:    digest,
	})
	if err != nil {
		return replicatedGroup{}, fmt.Errorf("upload replicated object %q: %w", storageKey, err)
	}

	if uploaded.SizeBytes != group.ciphertextBytes {
		return replicatedGroup{}, fmt.Errorf(
			"%w: uploaded object has %d bytes, expected %d",
			ErrReplicationIntegrity,
			uploaded.SizeBytes,
			group.ciphertextBytes,
		)
	}

	if err := verifyProviderObject(
		ctx,
		replicator.destination,
		storageKey,
		group.ciphertextBytes,
		objectHash.Sum(nil),
		ErrReplicationIntegrity,
	); err != nil {
		return replicatedGroup{}, err
	}

	for index := range locations {
		locations[index].StorageKey = storageKey
		locations[index].ProviderVersion = uploaded.Version
	}

	return replicatedGroup{locations: locations, object: uploaded, statistics: statistics}, nil
}

func validateReplicationRequest(request ReplicationRequest) error {
	if err := request.Recovery.Validate(); err != nil {
		return fmt.Errorf("%w: recovery manifest: %w", ErrInvalidReplication, err)
	}

	if !validPlanString(request.DestinationDriverID, 256) ||
		!validDestinationPrefix(request.DestinationPrefix) {
		return fmt.Errorf("%w: destination driver and canonical prefix are required", ErrInvalidReplication)
	}

	if err := validateStagingDirectory(request.StagingDirectory); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidReplication, err)
	}

	return nil
}

func writeReplicationExtent(destination io.Writer, objectHash hash.Hash, data []byte) error {
	written, err := io.MultiWriter(destination, objectHash).Write(data)
	if err != nil {
		return fmt.Errorf("write replication staging extent: %w", err)
	}

	if written != len(data) {
		return fmt.Errorf(
			"%w: staged extent wrote %d of %d bytes",
			ErrReplicationIntegrity,
			written,
			len(data),
		)
	}

	return nil
}

type replicationStatistics struct {
	extents         uint64
	ciphertextBytes uint64
	replicaRetries  uint64
}

func (statistics *replicationStatistics) add(other replicationStatistics) error {
	if other.extents > math.MaxUint64-statistics.extents ||
		other.ciphertextBytes > math.MaxUint64-statistics.ciphertextBytes ||
		other.replicaRetries > math.MaxUint64-statistics.replicaRetries {
		return fmt.Errorf("%w: replication statistics overflow", ErrInvalidReplication)
	}

	statistics.extents += other.extents
	statistics.ciphertextBytes += other.ciphertextBytes
	statistics.replicaRetries += other.replicaRetries

	return nil
}

type replicationLocationIdentity struct {
	extentDigest string
	driverID     string
	storageKey   string
	offset       uint64
	length       uint64
}

func mergeReplicationLocations(
	existing,
	candidates []manifest.Location,
) (merged, added []manifest.Location) {
	merged = make([]manifest.Location, 0, len(existing)+len(candidates))
	merged = append(merged, existing...)
	added = make([]manifest.Location, 0, len(candidates))
	identities := make(map[replicationLocationIdentity]struct{}, len(existing)+len(candidates))

	for _, location := range existing {
		identities[replicationLocationKey(location)] = struct{}{}
	}

	for _, location := range candidates {
		identity := replicationLocationKey(location)
		if _, duplicate := identities[identity]; duplicate {
			continue
		}

		identities[identity] = struct{}{}

		merged = append(merged, location)
		added = append(added, location)
	}

	return merged, added
}

func replicationLocationKey(location manifest.Location) replicationLocationIdentity {
	return replicationLocationIdentity{
		extentDigest: location.ExtentSHA256,
		driverID:     location.DriverID,
		storageKey:   location.StorageKey,
		offset:       location.Offset,
		length:       location.Length,
	}
}
