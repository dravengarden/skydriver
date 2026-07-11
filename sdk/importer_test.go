package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var (
	errMemoryObjectMissing      = errors.New("memory object is missing")
	errMemoryObjectTooLarge     = errors.New("memory object exceeds address space")
	errMemoryUploadHashMismatch = errors.New("memory upload hash mismatch")
)

type mutableMemorySource struct {
	mutex   sync.RWMutex
	data    []byte
	version string
}

func (source *mutableMemorySource) Stat(
	_ context.Context,
	key string,
) (provider.Object, error) {
	source.mutex.RLock()
	defer source.mutex.RUnlock()

	return provider.Object{Key: key, SizeBytes: uint64(len(source.data)), Version: source.version}, nil
}

func (source *mutableMemorySource) OpenRange(
	_ context.Context,
	_ string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	source.mutex.RLock()
	defer source.mutex.RUnlock()

	if offset > uint64(len(source.data)) || length > uint64(len(source.data))-offset {
		return nil, io.ErrUnexpectedEOF
	}

	start := int(offset)
	end := int(offset + length)
	selected := bytes.Clone(source.data[start:end])

	return io.NopCloser(bytes.NewReader(selected)), nil
}

type memoryArchive struct {
	mutex      sync.RWMutex
	objects    map[string][]byte
	corruptPut bool
}

func newMemoryArchive() *memoryArchive {
	return &memoryArchive{objects: make(map[string][]byte)}
}

func (archiveStore *memoryArchive) Stat(
	_ context.Context,
	key string,
) (provider.Object, error) {
	archiveStore.mutex.RLock()
	defer archiveStore.mutex.RUnlock()

	value, exists := archiveStore.objects[key]
	if !exists {
		return provider.Object{}, errMemoryObjectMissing
	}

	return provider.Object{
		Key:       key,
		SizeBytes: uint64(len(value)),
		Version:   "memory-v1",
	}, nil
}

func (archiveStore *memoryArchive) OpenRange(
	_ context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	archiveStore.mutex.RLock()
	defer archiveStore.mutex.RUnlock()

	value, exists := archiveStore.objects[key]
	if !exists {
		return nil, errMemoryObjectMissing
	}

	if offset > uint64(len(value)) || length > uint64(len(value))-offset {
		return nil, io.ErrUnexpectedEOF
	}

	start := int(offset)
	end := int(offset + length)

	return io.NopCloser(bytes.NewReader(bytes.Clone(value[start:end]))), nil
}

func (archiveStore *memoryArchive) Put(
	_ context.Context,
	key string,
	body io.Reader,
	options provider.PutOptions,
) (provider.Object, error) {
	if options.SizeBytes > uint64(^uint(0)>>1)-1 {
		return provider.Object{}, errMemoryObjectTooLarge
	}

	value, err := io.ReadAll(io.LimitReader(body, int64(options.SizeBytes)+1))
	if err != nil {
		return provider.Object{}, fmt.Errorf("read memory upload: %w", err)
	}

	if uint64(len(value)) != options.SizeBytes {
		return provider.Object{}, io.ErrUnexpectedEOF
	}

	digest := sha256.Sum256(value)
	if options.SHA256 != hex.EncodeToString(digest[:]) {
		return provider.Object{}, errMemoryUploadHashMismatch
	}

	if archiveStore.corruptPut && len(value) > 0 {
		value[0] ^= 1
	}

	archiveStore.mutex.Lock()
	archiveStore.objects[key] = bytes.Clone(value)
	archiveStore.mutex.Unlock()

	return provider.Object{Key: key, SizeBytes: uint64(len(value)), Version: "memory-v1"}, nil
}

func TestImporterProducesReconstructablePortableArchive(t *testing.T) {
	t.Parallel()

	plaintext := []byte("a deterministic thirty-five byte value")
	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	destination := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}

	importer, err := sdk.NewImporter(source, destination, layout)
	if err != nil {
		t.Fatalf("construct importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID:         importIdentifier(),
		ObjectID:            "object-1",
		Generation:          1,
		RootVersion:         1,
		KeyEpoch:            7,
		SourceKey:           "source",
		DestinationDriverID: "memory-primary",
		DestinationPrefix:   "archive",
	})
	if err != nil {
		t.Fatalf("plan import: %v", err)
	}

	epochKey := importEpochKey(t, importIdentifier())
	stagingDirectory := t.TempDir()

	result, err := importer.Execute(context.Background(), plan, epochKey, stagingDirectory)
	if err != nil {
		t.Fatalf("execute import: %v", err)
	}

	expectedPlaintextHash := sha256.Sum256(plaintext)
	if result.Manifest.PlaintextSHA256 != hex.EncodeToString(expectedPlaintextHash[:]) {
		t.Fatalf("plaintext hash mismatch: %s", result.Manifest.PlaintextSHA256)
	}

	if len(result.Manifest.Packs) != 3 || len(result.Recovery.Locations) != 5 {
		t.Fatalf("unexpected import shape: packs=%d locations=%d", len(result.Manifest.Packs), len(result.Recovery.Locations))
	}

	providerObjects := make(map[string]struct{})
	for _, location := range result.Recovery.Locations {
		providerObjects[location.StorageKey] = struct{}{}
	}

	if len(providerObjects) != 3 {
		t.Fatalf("expected one exact provider object per tiny test pack, got %d", len(providerObjects))
	}

	assertGaplessProviderLocations(t, destination, result.Recovery.Locations)

	recoveryBytes := destination.object(result.RecoveryKey)

	parsedRecovery, err := manifest.ParseRecovery(recoveryBytes)
	if err != nil {
		t.Fatalf("parse uploaded recovery sidecar: %v", err)
	}

	if parsedRecovery.ManifestSHA256 != result.Recovery.ManifestSHA256 {
		t.Fatal("uploaded recovery sidecar changed manifest identity")
	}

	restored := restoreMemoryArchive(t, destination, result, epochKey)
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored plaintext mismatch: got %q want %q", restored, plaintext)
	}

	assertDirectoryEmpty(t, stagingDirectory)

	second, err := importer.Execute(context.Background(), plan, epochKey, stagingDirectory)
	if err != nil {
		t.Fatalf("repeat identical import: %v", err)
	}

	firstRecovery, err := result.Recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal first recovery manifest: %v", err)
	}

	secondRecovery, err := second.Recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal repeated recovery manifest: %v", err)
	}

	if !bytes.Equal(firstRecovery, secondRecovery) {
		t.Fatal("repeating a persisted plan changed ciphertext recovery identity")
	}
}

func TestImporterProviderObjectsUseExactRangesWithoutPadding(t *testing.T) {
	t.Parallel()

	plaintext := []byte("a deterministic thirty-five byte value")
	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	destination := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}

	importer, err := sdk.NewImporterWithOptions(source, destination, layout, sdk.ImporterOptions{
		ProviderObjectTargetBytes:  100,
		MaximumProviderObjectBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("construct bounded importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID:         importIdentifier(),
		ObjectID:            "object-exact-ranges",
		Generation:          1,
		RootVersion:         1,
		KeyEpoch:            7,
		SourceKey:           "source",
		DestinationDriverID: "memory-primary",
		DestinationPrefix:   "archive",
	})
	if err != nil {
		t.Fatalf("plan bounded import: %v", err)
	}

	result, err := importer.Execute(
		context.Background(),
		plan,
		importEpochKey(t, importIdentifier()),
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("execute bounded import: %v", err)
	}

	usedBytes := make(map[string]uint64)
	for _, location := range result.Recovery.Locations {
		usedBytes[location.StorageKey] = max(
			usedBytes[location.StorageKey],
			location.Offset+location.Length,
		)
	}

	if len(usedBytes) != 5 {
		t.Fatalf("100-byte target should keep five test extents separate, got %d objects", len(usedBytes))
	}

	for storageKey, expectedBytes := range usedBytes {
		actualBytes := uint64(len(destination.object(storageKey)))
		if actualBytes != expectedBytes || actualBytes > 100 {
			t.Fatalf(
				"provider object %q has %d bytes, referenced exact length is %d",
				storageKey,
				actualBytes,
				expectedBytes,
			)
		}
	}
}

func TestImporterRejectsExtentAboveDriverObjectMaximum(t *testing.T) {
	t.Parallel()

	plaintext := []byte("12345678")
	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	destination := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   8,
	}

	importer, err := sdk.NewImporterWithOptions(source, destination, layout, sdk.ImporterOptions{
		ProviderObjectTargetBytes:  71,
		MaximumProviderObjectBytes: 71,
	})
	if err != nil {
		t.Fatalf("construct maximum-bounded importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID:         importIdentifier(),
		ObjectID:            "object-too-small-driver-limit",
		Generation:          1,
		RootVersion:         1,
		KeyEpoch:            7,
		SourceKey:           "source",
		DestinationDriverID: "memory-primary",
		DestinationPrefix:   "archive",
	})
	if err != nil {
		t.Fatalf("plan maximum-bounded import: %v", err)
	}

	_, err = importer.Execute(
		context.Background(),
		plan,
		importEpochKey(t, importIdentifier()),
		t.TempDir(),
	)
	if !errors.Is(err, sdk.ErrInvalidConfiguration) {
		t.Fatalf("expected driver maximum rejection, got %v", err)
	}
}

func TestImporterRejectsChangedSourceAndCorruptDestination(t *testing.T) {
	t.Parallel()

	plaintext := []byte("source bytes larger than one extent")
	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	destination := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}

	importer, err := sdk.NewImporter(source, destination, layout)
	if err != nil {
		t.Fatalf("construct importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID:         importIdentifier(),
		ObjectID:            "object-1",
		Generation:          1,
		RootVersion:         1,
		KeyEpoch:            7,
		SourceKey:           "source",
		DestinationDriverID: "memory-primary",
		DestinationPrefix:   "archive",
	})
	if err != nil {
		t.Fatalf("plan import: %v", err)
	}

	source.mutex.Lock()
	source.version = "source-v2"
	source.mutex.Unlock()

	_, err = importer.Execute(
		context.Background(),
		plan,
		importEpochKey(t, importIdentifier()),
		t.TempDir(),
	)
	if !errors.Is(err, sdk.ErrImportSourceChanged) {
		t.Fatalf("expected source change rejection, got %v", err)
	}

	source.mutex.Lock()
	source.version = "source-v1"
	source.mutex.Unlock()

	destination.corruptPut = true
	stagingDirectory := t.TempDir()

	_, err = importer.Execute(
		context.Background(),
		plan,
		importEpochKey(t, importIdentifier()),
		stagingDirectory,
	)
	if !errors.Is(err, sdk.ErrImportIntegrity) {
		t.Fatalf("expected corrupt destination rejection, got %v", err)
	}

	assertDirectoryEmpty(t, stagingDirectory)
}

func (archiveStore *memoryArchive) object(key string) []byte {
	archiveStore.mutex.RLock()
	defer archiveStore.mutex.RUnlock()

	return bytes.Clone(archiveStore.objects[key])
}

func assertGaplessProviderLocations(
	t *testing.T,
	destination *memoryArchive,
	locations []manifest.Location,
) {
	t.Helper()

	byStorageKey := make(map[string][]manifest.Location)
	for _, location := range locations {
		byStorageKey[location.StorageKey] = append(byStorageKey[location.StorageKey], location)
	}

	for storageKey, objectLocations := range byStorageKey {
		sort.Slice(objectLocations, func(left, right int) bool {
			return objectLocations[left].Offset < objectLocations[right].Offset
		})

		var expectedOffset uint64
		for _, location := range objectLocations {
			if location.Offset != expectedOffset {
				t.Fatalf(
					"provider object %q has a gap: location starts at %d, expected %d",
					storageKey,
					location.Offset,
					expectedOffset,
				)
			}

			expectedOffset += location.Length
		}

		actualBytes := uint64(len(destination.object(storageKey)))
		if actualBytes != expectedOffset {
			t.Fatalf(
				"provider object %q has %d bytes, exact referenced length is %d",
				storageKey,
				actualBytes,
				expectedOffset,
			)
		}
	}
}

func restoreMemoryArchive(
	t *testing.T,
	destination *memoryArchive,
	result sdk.ImportResult,
	epochKey cryptostream.EpochKey,
) []byte {
	t.Helper()

	var plaintext bytes.Buffer

	locations := make(map[string]manifest.Location, len(result.Recovery.Locations))
	for _, location := range result.Recovery.Locations {
		locations[location.ExtentSHA256] = location
	}

	for _, pack := range result.Manifest.Packs {
		packID := decodeTestIdentifier(t, pack.PackID)

		packKey, err := cryptostream.DerivePackKey(epochKey, packID)
		if err != nil {
			t.Fatalf("derive restore pack key: %v", err)
		}

		packCipher, err := cryptostream.NewCipher(packKey, cryptostream.Descriptor{
			Suite:          result.Manifest.Crypto.Suite,
			RootVersion:    result.Manifest.Crypto.RootVersion,
			NamespaceID:    decodeTestIdentifier(t, result.Manifest.NamespaceID),
			EpochID:        result.Manifest.Crypto.KeyEpoch,
			PackID:         packID,
			FrameBytes:     result.Manifest.Layout.CryptoFrameBytes,
			PlaintextBytes: pack.PlaintextSize,
		})
		if err != nil {
			t.Fatalf("construct restore cipher: %v", err)
		}

		for _, extent := range pack.Extents {
			location := locations[extent.CiphertextSHA256]

			providerObject := destination.object(location.StorageKey)
			if location.Offset > uint64(len(providerObject)) ||
				location.Length > uint64(len(providerObject))-location.Offset {
				t.Fatalf("location range exceeds provider object: %+v", location)
			}

			ciphertext := providerObject[location.Offset : location.Offset+location.Length]
			if _, err := packCipher.OpenFrames(
				context.Background(),
				&plaintext,
				bytes.NewReader(ciphertext),
				extent.FirstFrame,
				extent.FrameCount,
			); err != nil {
				t.Fatalf("open restored extent: %v", err)
			}
		}
	}

	return plaintext.Bytes()
}

func importEpochKey(
	t *testing.T,
	namespaceID cryptostream.Identifier,
) cryptostream.EpochKey {
	t.Helper()

	var root cryptostream.RootKey
	for index := range root {
		root[index] = byte(index + 1)
	}

	epochKey, err := cryptostream.DeriveEpochKey(root, cryptostream.EpochContext{
		NamespaceID: namespaceID,
		EpochID:     7,
	})
	if err != nil {
		t.Fatalf("derive import epoch key: %v", err)
	}

	return epochKey
}

func decodeTestIdentifier(t *testing.T, value string) cryptostream.Identifier {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test identifier: %v", err)
	}

	var identifier cryptostream.Identifier
	copy(identifier[:], decoded)

	return identifier
}

func assertDirectoryEmpty(t *testing.T, directory string) {
	t.Helper()

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read staging directory: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("staging directory retained %d files", len(entries))
	}
}
