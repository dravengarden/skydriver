package sdk_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

func TestCompactorCreatesSmallerImmutableReplacement(t *testing.T) {
	t.Parallel()

	plaintext := []byte("three deliberately small source packs")
	sourcePlaintext := &mutableMemorySource{data: plaintext, version: "plaintext-v1"}
	sourceArchive := newMemoryArchive()
	sourceLayout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   4,
		LogicalPackBytes:   16,
	}

	sourceImporter, err := sdk.NewImporter(sourcePlaintext, sourceArchive, sourceLayout)
	if err != nil {
		t.Fatalf("construct source importer: %v", err)
	}

	sourcePlan, err := sourceImporter.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID: importIdentifier(), ObjectID: "compact-object", Generation: 1,
		RootVersion: 1, KeyEpoch: 7, SourceKey: "source",
		DestinationDriverID: "source-archive", DestinationPrefix: "source",
	})
	if err != nil {
		t.Fatalf("plan source archive: %v", err)
	}

	sourceKey := importEpochKey(t, importIdentifier())

	source, err := sourceImporter.Execute(context.Background(), sourcePlan, sourceKey, t.TempDir())
	if err != nil {
		t.Fatalf("write source archive: %v", err)
	}

	if len(source.Manifest.Packs) < 2 {
		t.Fatalf("source fixture did not create multiple packs: %d", len(source.Manifest.Packs))
	}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{
		"source-archive": sourceArchive,
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct compact restorer: %v", err)
	}

	targetArchive := newMemoryArchive()
	targetLayout := archive.Layout{
		PhysicalBlockBytes: 64,
		CryptoFrameBytes:   4,
		LogicalPackBytes:   64,
	}

	compactor, err := sdk.NewCompactor(restorer, targetArchive, targetLayout, sdk.ImporterOptions{})
	if err != nil {
		t.Fatalf("construct compactor: %v", err)
	}

	workspace := t.TempDir()
	plaintextPath := filepath.Join(workspace, "compact.plaintext")
	planFile := filepath.Join(workspace, "compact.json")
	targetKey := importEpochKey(t, importIdentifier())

	result, err := compactor.Execute(context.Background(), sdk.CompactExecutionRequest{
		SourceRecovery: source.Recovery, SourceEpochKey: sourceKey, TargetEpochKey: targetKey,
		ObjectID: "compact-object", TargetGeneration: 2, TargetRootVersion: 1,
		TargetKeyEpoch: 7, DestinationDriverID: "target-archive",
		DestinationPrefix: "target", PlaintextPath: plaintextPath,
		PlanFile: planFile, StagingDirectory: workspace,
	})
	if err != nil {
		t.Fatalf("execute compaction: %v", err)
	}

	if len(result.Import.Manifest.Packs) != 1 ||
		len(result.Import.Manifest.Packs) >= len(source.Manifest.Packs) ||
		result.Import.Manifest.PlaintextSHA256 != source.Manifest.PlaintextSHA256 ||
		result.Import.Manifest.Generation != 2 {
		t.Fatalf("unexpected replacement shape: %+v", result.Import.Manifest)
	}

	restored := restoreMemoryArchive(t, targetArchive, result.Import, targetKey)
	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("replacement plaintext differs: got %q want %q", restored, plaintext)
	}

	if _, err := os.Stat(planFile); err != nil {
		t.Fatalf("compact plan was not persisted: %v", err)
	}

	if _, err := os.Stat(plaintextPath); err != nil {
		t.Fatalf("raw compactor unexpectedly removed plaintext bridge: %v", err)
	}
}
