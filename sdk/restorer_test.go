package sdk_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errInjectedRestoreRead = errors.New("injected restore read failure")

type failingRestoreReader struct {
	reader    provider.Reader
	mutex     sync.Mutex
	remaining int
}

func (reader *failingRestoreReader) Stat(ctx context.Context, key string) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader *failingRestoreReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()

	if reader.remaining == 0 {
		return nil, errInjectedRestoreRead
	}

	reader.remaining--

	return reader.reader.OpenRange(ctx, key, offset, length)
}

func TestRestorerResumesVerifiedExtentsAndPublishesAtomically(t *testing.T) {
	t.Parallel()

	plaintext := []byte("restore must resume exact authenticated extents")
	archiveStore, imported, epochKey := importRestoreFixture(t, plaintext)
	destination := filepath.Join(t.TempDir(), "restored.bin")

	interrupted, err := sdk.NewRestorer(map[string]provider.Reader{
		"memory-primary": &failingRestoreReader{reader: archiveStore, remaining: 1},
	}, 128)
	if err != nil {
		t.Fatalf("construct interrupted restorer: %v", err)
	}

	if _, restoreErr := interrupted.Restore(context.Background(), imported.Recovery, epochKey, destination); restoreErr == nil {
		t.Fatal("interrupted restore unexpectedly succeeded")
	}

	if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("interrupted restore published destination: %v", statErr)
	}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{"memory-primary": archiveStore}, 128)
	if err != nil {
		t.Fatalf("construct restorer: %v", err)
	}

	result, err := restorer.Restore(context.Background(), imported.Recovery, epochKey, destination)
	if err != nil {
		t.Fatalf("resume restore: %v", err)
	}

	if result.ResumedExtents != 1 || result.FetchedExtents == 0 {
		t.Fatalf("unexpected resume counts: %+v", result)
	}

	restored, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read restored destination: %v", err)
	}

	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("restored plaintext mismatch: got %q want %q", restored, plaintext)
	}

	for _, suffix := range []string{".carrack-restore.part", ".carrack-restore.json"} {
		if _, err := os.Stat(destination + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("successful restore retained %s: %v", suffix, err)
		}
	}
}

func TestRestorerRejectsWrongKeyWithoutPublishing(t *testing.T) {
	t.Parallel()

	archiveStore, imported, _ := importRestoreFixture(t, []byte("authenticated plaintext"))
	destination := filepath.Join(t.TempDir(), "restored.bin")

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{"memory-primary": archiveStore}, 128)
	if err != nil {
		t.Fatalf("construct restorer: %v", err)
	}

	var wrongKey cryptostream.EpochKey

	wrongKey[0] = 1
	if _, err := restorer.Restore(context.Background(), imported.Recovery, wrongKey, destination); err == nil {
		t.Fatal("restore with wrong key unexpectedly succeeded")
	}

	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-key restore published destination: %v", err)
	}
}

func importRestoreFixture(
	t *testing.T,
	plaintext []byte,
) (*memoryArchive, sdk.ImportResult, cryptostream.EpochKey) {
	t.Helper()

	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	archiveStore := newMemoryArchive()
	layout := archive.Layout{PhysicalBlockBytes: 8, CryptoFrameBytes: 2, LogicalPackBytes: 16}

	importer, err := sdk.NewImporter(source, archiveStore, layout)
	if err != nil {
		t.Fatalf("construct importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID: importIdentifier(), ObjectID: "restore-object", Generation: 1,
		RootVersion: 1, KeyEpoch: 7, SourceKey: "source",
		DestinationDriverID: "memory-primary", DestinationPrefix: "archive",
	})
	if err != nil {
		t.Fatalf("plan import: %v", err)
	}

	epochKey := importEpochKey(t, decodeTestIdentifier(t, plan.NamespaceID))

	result, err := importer.Execute(context.Background(), plan, epochKey, t.TempDir())
	if err != nil {
		t.Fatalf("execute import: %v", err)
	}

	return archiveStore, result, epochKey
}
