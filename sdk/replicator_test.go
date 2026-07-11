package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type corruptingReader struct {
	reader provider.Reader
}

func (reader corruptingReader) Stat(ctx context.Context, key string) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader corruptingReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	stream, err := reader.reader.OpenRange(ctx, key, offset, length)
	if err != nil {
		return nil, err
	}

	data, readErr := io.ReadAll(stream)

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}

	if len(data) > 0 {
		data[0] ^= 1
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

type sidecarCorruptingArchive struct {
	*memoryArchive
}

func (archiveStore *sidecarCorruptingArchive) Put(
	ctx context.Context,
	key string,
	body io.Reader,
	options provider.PutOptions,
) (provider.Object, error) {
	object, err := archiveStore.memoryArchive.Put(ctx, key, body, options)
	if err != nil || !strings.Contains(key, "/manifests/") {
		return object, err
	}

	archiveStore.mutex.Lock()
	archiveStore.objects[key][0] ^= 1
	archiveStore.mutex.Unlock()

	return object, nil
}

func TestReplicatorCopiesVerifiedCiphertextWithReplicaFallback(t *testing.T) {
	t.Parallel()

	fixture := newReplicationFixture(t)
	recovery := withCorruptReplicationLocations(t, fixture.recovery)
	destination := newMemoryArchive()
	replicator := newTestReplicator(t, map[string]provider.Reader{
		"corrupt": corruptingReader{reader: fixture.source},
		"source":  fixture.source,
	}, destination, 200, 1<<20)
	stagingDirectory := t.TempDir()

	before, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal source recovery manifest: %v", err)
	}

	result, err := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: recovery, DestinationDriverID: "destination",
		DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
	})
	if err != nil {
		t.Fatalf("replicate ciphertext archive: %v", err)
	}

	extentCount, ciphertextBytes := replicationManifestTotals(recovery.Manifest)
	if result.VerifiedExtents != extentCount || result.CiphertextBytes != ciphertextBytes ||
		result.ReplicaRetryCount != extentCount {
		t.Fatalf("unexpected replication statistics: %+v", result)
	}

	if len(result.Locations) != int(extentCount) || len(result.ProviderObjects) != len(recovery.Manifest.Packs) {
		t.Fatalf(
			"unexpected replication shape: locations=%d objects=%d packs=%d",
			len(result.Locations),
			len(result.ProviderObjects),
			len(recovery.Manifest.Packs),
		)
	}

	assertGaplessProviderLocations(t, destination, result.Locations)
	assertReplicatedLocationDigests(t, destination, result.Locations)
	assertReplicationSidecar(t, destination, result)
	assertDirectoryEmpty(t, stagingDirectory)

	after, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("remarshal source recovery manifest: %v", err)
	}

	if !bytes.Equal(before, after) {
		t.Fatal("replication mutated the source recovery manifest")
	}

	if len(result.Recovery.Locations) != len(recovery.Locations)+len(result.Locations) {
		t.Fatal("replicated recovery did not preserve every source location")
	}
}

func TestReplicatorReplayConvergesWithoutDuplicateLocations(t *testing.T) {
	t.Parallel()

	fixture := newReplicationFixture(t)
	destination := newMemoryArchive()
	replicator := newTestReplicator(
		t,
		map[string]provider.Reader{"source": fixture.source},
		destination,
		200,
		1<<20,
	)
	stagingDirectory := t.TempDir()

	first, err := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: fixture.recovery, DestinationDriverID: "destination",
		DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
	})
	if err != nil {
		t.Fatalf("execute first ciphertext replication: %v", err)
	}

	second, err := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: first.Recovery, DestinationDriverID: "destination",
		DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
	})
	if err != nil {
		t.Fatalf("replay ciphertext replication: %v", err)
	}

	if len(second.Locations) != 0 {
		t.Fatalf("replay added %d duplicate locations", len(second.Locations))
	}

	firstEncoded, err := first.Recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal first replicated recovery: %v", err)
	}

	secondEncoded, err := second.Recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal replayed recovery: %v", err)
	}

	if !bytes.Equal(firstEncoded, secondEncoded) || first.RecoveryKey != second.RecoveryKey {
		t.Fatal("replayed replication changed content-addressed recovery identity")
	}

	assertDirectoryEmpty(t, stagingDirectory)
}

func TestReplicatorRejectsCorruptPayloadAndSidecarReadback(t *testing.T) {
	t.Parallel()

	fixture := newReplicationFixture(t)

	tests := []struct {
		name        string
		destination provider.ReadWriter
	}{
		{name: "payload", destination: &memoryArchive{objects: make(map[string][]byte), corruptPut: true}},
		{name: "sidecar", destination: &sidecarCorruptingArchive{memoryArchive: newMemoryArchive()}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stagingDirectory := t.TempDir()
			replicator := newTestReplicator(
				t,
				map[string]provider.Reader{"source": fixture.source},
				test.destination,
				200,
				1<<20,
			)

			_, err := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
				Recovery: fixture.recovery, DestinationDriverID: "destination",
				DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
			})
			if !errors.Is(err, sdk.ErrReplicationIntegrity) {
				t.Fatalf("corrupt destination was not rejected: %v", err)
			}

			assertDirectoryEmpty(t, stagingDirectory)
		})
	}
}

func TestReplicatorValidatesBoundsAndCancellationBeforePublication(t *testing.T) {
	t.Parallel()

	fixture := newReplicationFixture(t)
	destination := newMemoryArchive()
	stagingDirectory := t.TempDir()

	tooSmall := newTestReplicator(
		t,
		map[string]provider.Reader{"source": fixture.source},
		destination,
		70,
		70,
	)

	_, err := tooSmall.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: fixture.recovery, DestinationDriverID: "destination",
		DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
	})
	if !errors.Is(err, sdk.ErrInvalidReplication) {
		t.Fatalf("destination maximum did not reject an oversized extent: %v", err)
	}

	sidecarBounded := newTestReplicator(
		t,
		map[string]provider.Reader{"source": fixture.source},
		destination,
		100,
		100,
	)

	_, err = sidecarBounded.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: fixture.recovery, DestinationDriverID: "destination",
		DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
	})
	if !errors.Is(err, sdk.ErrInvalidReplication) {
		t.Fatalf("destination maximum did not reject an oversized recovery sidecar: %v", err)
	}

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	replicator := newTestReplicator(
		t,
		map[string]provider.Reader{"source": fixture.source},
		destination,
		200,
		1<<20,
	)

	for _, prefix := range []string{"", "/absolute", "../escape", `unsafe\path`, strings.Repeat("x", 4_000)} {
		_, requestErr := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
			Recovery: fixture.recovery, DestinationDriverID: "destination",
			DestinationPrefix: prefix, StagingDirectory: stagingDirectory,
		})
		if !errors.Is(requestErr, sdk.ErrInvalidReplication) {
			t.Fatalf("unsafe destination prefix %q returned %v", prefix, requestErr)
		}
	}

	_, err = replicator.Replicate(cancelledContext, sdk.ReplicationRequest{
		Recovery: fixture.recovery, DestinationDriverID: "destination",
		DestinationPrefix: "replica", StagingDirectory: stagingDirectory,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled replication returned unexpected error: %v", err)
	}

	assertDirectoryEmpty(t, stagingDirectory)
}

func TestNewReplicatorRejectsMissingDependenciesAndBounds(t *testing.T) {
	t.Parallel()

	destination := newMemoryArchive()
	validOptions := sdk.ReplicatorOptions{MaximumExtentBytes: 1}

	capabilityOptions := sdk.ReplicatorOptionsFromCapabilities(7, provider.Capabilities{
		PreferredObjectBytes: 11,
		MaximumObjectBytes:   13,
	})
	if capabilityOptions.MaximumExtentBytes != 7 ||
		capabilityOptions.ProviderObjectTargetBytes != 11 ||
		capabilityOptions.MaximumProviderObjectBytes != 13 {
		t.Fatalf("unexpected capability-derived replication options: %+v", capabilityOptions)
	}

	if _, err := sdk.NewReplicator(nil, destination, validOptions); !errors.Is(err, sdk.ErrInvalidReplication) {
		t.Fatalf("missing source readers returned unexpected error: %v", err)
	}

	if _, err := sdk.NewReplicator(
		map[string]provider.Reader{"source": destination},
		nil,
		validOptions,
	); !errors.Is(err, sdk.ErrInvalidReplication) {
		t.Fatalf("missing destination returned unexpected error: %v", err)
	}

	if _, err := sdk.NewReplicator(
		map[string]provider.Reader{"source": destination},
		destination,
		sdk.ReplicatorOptions{},
	); !errors.Is(err, sdk.ErrInvalidReplication) {
		t.Fatalf("missing extent bound returned unexpected error: %v", err)
	}
}

func newReplicationFixture(t *testing.T) struct {
	recovery manifest.RecoveryManifest
	source   *memoryArchive
} {
	t.Helper()

	plaintext := []byte("a deterministic thirty-five byte value")
	input := &mutableMemorySource{data: plaintext, version: "source-v1"}
	source := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}

	importer, err := sdk.NewImporter(input, source, layout)
	if err != nil {
		t.Fatalf("construct replication fixture importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID: importIdentifier(), ObjectID: "replication-object", Generation: 1,
		RootVersion: 1, KeyEpoch: 7, SourceKey: "source",
		DestinationDriverID: "source", DestinationPrefix: "source-archive",
	})
	if err != nil {
		t.Fatalf("plan replication fixture import: %v", err)
	}

	result, err := importer.Execute(
		context.Background(),
		plan,
		importEpochKey(t, importIdentifier()),
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("execute replication fixture import: %v", err)
	}

	return struct {
		recovery manifest.RecoveryManifest
		source   *memoryArchive
	}{recovery: result.Recovery, source: source}
}

func newTestReplicator(
	t *testing.T,
	readers map[string]provider.Reader,
	destination provider.ReadWriter,
	targetObjectBytes,
	maximumObjectBytes uint64,
) *sdk.Replicator {
	t.Helper()

	replicator, err := sdk.NewReplicator(readers, destination, sdk.ReplicatorOptions{
		MaximumExtentBytes:         1 << 20,
		ProviderObjectTargetBytes:  targetObjectBytes,
		MaximumProviderObjectBytes: maximumObjectBytes,
	})
	if err != nil {
		t.Fatalf("construct test replicator: %v", err)
	}

	return replicator
}

func withCorruptReplicationLocations(
	t *testing.T,
	recovery manifest.RecoveryManifest,
) manifest.RecoveryManifest {
	t.Helper()

	locations := make([]manifest.Location, 0, len(recovery.Locations)*2)
	for _, location := range recovery.Locations {
		corrupt := location
		corrupt.DriverID = "corrupt"
		locations = append(locations, corrupt, location)
	}

	updated, err := manifest.NewRecoveryManifest(recovery.Manifest, locations)
	if err != nil {
		t.Fatalf("construct fallback replication recovery: %v", err)
	}

	return updated
}

func replicationManifestTotals(content manifest.Manifest) (uint64, uint64) {
	var extents uint64

	var ciphertextBytes uint64

	for _, pack := range content.Packs {
		for _, extent := range pack.Extents {
			extents++
			ciphertextBytes += extent.CiphertextSize
		}
	}

	return extents, ciphertextBytes
}

func assertReplicatedLocationDigests(
	t *testing.T,
	destination provider.Reader,
	locations []manifest.Location,
) {
	t.Helper()

	for _, location := range locations {
		stream, err := destination.OpenRange(
			context.Background(),
			location.StorageKey,
			location.Offset,
			location.Length,
		)
		if err != nil {
			t.Fatalf("open replicated destination range: %v", err)
		}

		data, readErr := io.ReadAll(stream)

		closeErr := stream.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read replicated destination range: %v", errors.Join(readErr, closeErr))
		}

		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != location.ExtentSHA256 {
			t.Fatalf("replicated location %q has the wrong digest", location.StorageKey)
		}
	}
}

func assertReplicationSidecar(
	t *testing.T,
	destination *memoryArchive,
	result sdk.ReplicationResult,
) {
	t.Helper()

	encoded := destination.object(result.RecoveryKey)

	parsed, err := manifest.ParseRecovery(encoded)
	if err != nil {
		t.Fatalf("parse replicated recovery sidecar: %v", err)
	}

	expected, err := result.Recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal replicated recovery result: %v", err)
	}

	if !bytes.Equal(encoded, expected) || parsed.ManifestSHA256 != result.Recovery.ManifestSHA256 {
		t.Fatal("destination recovery sidecar differs from the verified result")
	}

	digest := sha256.Sum256(encoded)
	if !strings.Contains(result.RecoveryKey, result.Recovery.ManifestSHA256) ||
		!strings.HasSuffix(result.RecoveryKey, hex.EncodeToString(digest[:])+".json") {
		t.Fatalf("recovery sidecar key is not content-addressed: %q", result.RecoveryKey)
	}
}
