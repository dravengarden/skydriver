package journal

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/driver"
)

func TestDownloadResumesOnlyMissingVerifiedBlocks(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("range-resume-"), 17)
	object := putTestObject(t, environment.handle, "objects/source.bin", payload)
	destination := filepath.Join(t.TempDir(), "download.bin")

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 23},
	)
	if err != nil {
		t.Fatalf("prepare download: %v", err)
	}

	failing := &failRangeReader{
		RangeReader: environment.handle.RangeReader,
		failOffset:  prepared.Download.Blocks[1].Offset,
		calls:       make(map[uint64]int),
	}
	failingHandle := environment.handle
	failingHandle.RangeReader = failing

	if _, runErr := environment.engine.RunDownload(
		context.Background(),
		prepared.ID,
		failingHandle,
	); runErr == nil {
		t.Fatal("first download unexpectedly succeeded")
	}

	interrupted, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect interrupted download: %v", err)
	}

	if interrupted.Status != StatusTransferring || len(interrupted.VerifiedBlocks) != 1 ||
		interrupted.VerifiedBlocks[0].Number != 1 {
		t.Fatalf("unexpected interrupted progress: %+v", interrupted)
	}

	counting := &failRangeReader{
		RangeReader: environment.handle.RangeReader,
		failOffset:  math.MaxUint64,
		calls:       make(map[uint64]int),
	}
	resumeHandle := environment.handle
	resumeHandle.RangeReader = counting

	result, err := environment.engine.RunDownload(context.Background(), prepared.ID, resumeHandle)
	if err != nil {
		t.Fatalf("resume download: %v", err)
	}

	if counting.callCount(prepared.Download.Blocks[0].Offset) != 0 {
		t.Fatal("resume downloaded already verified block 1 again")
	}

	for _, block := range prepared.Download.Blocks[1:] {
		if counting.callCount(block.Offset) != 1 {
			t.Fatalf("block %d downloaded %d times during resume", block.Number, counting.callCount(block.Offset))
		}
	}

	if result.Destination != destination || !bytes.Equal(readFile(t, destination), payload) {
		t.Fatalf("published download differs: %+v", result)
	}

	if _, statErr := os.Lstat(prepared.Download.StagingPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("staging remains after publication: %v", statErr)
	}

	replayed, err := environment.engine.RunDownload(context.Background(), prepared.ID, environment.handle)
	if err != nil || replayed != result {
		t.Fatalf("replay completed download: result=%+v error=%v", replayed, err)
	}
}

func TestDownloadReplacesCorruptReceiptedStagingBlock(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("repair-staging-"), 11)
	object := putTestObject(t, environment.handle, "objects/repair.bin", payload)
	destination := filepath.Join(t.TempDir(), "repair.bin")

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 19},
	)
	if err != nil {
		t.Fatalf("prepare download: %v", err)
	}

	failing := &failRangeReader{
		RangeReader: environment.handle.RangeReader,
		failOffset:  prepared.Download.Blocks[1].Offset,
		calls:       make(map[uint64]int),
	}
	failingHandle := environment.handle
	failingHandle.RangeReader = failing

	if _, runErr := environment.engine.RunDownload(
		context.Background(),
		prepared.ID,
		failingHandle,
	); runErr == nil {
		t.Fatal("first download unexpectedly succeeded")
	}

	staging, err := os.OpenFile(prepared.Download.StagingPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open staging for corruption: %v", err)
	}

	if _, writeErr := staging.WriteAt([]byte{0xff}, 0); writeErr != nil {
		_ = staging.Close()

		t.Fatalf("corrupt staging: %v", writeErr)
	}

	if closeErr := staging.Close(); closeErr != nil {
		t.Fatalf("close corrupted staging: %v", closeErr)
	}

	counting := &failRangeReader{
		RangeReader: environment.handle.RangeReader,
		failOffset:  math.MaxUint64,
		calls:       make(map[uint64]int),
	}
	resumeHandle := environment.handle
	resumeHandle.RangeReader = counting

	if _, err := environment.engine.RunDownload(context.Background(), prepared.ID, resumeHandle); err != nil {
		t.Fatalf("repair and resume download: %v", err)
	}

	if counting.callCount(0) != 1 {
		t.Fatalf("corrupt receipted block downloaded %d times, want one", counting.callCount(0))
	}

	if !bytes.Equal(readFile(t, destination), payload) {
		t.Fatal("repaired download differs")
	}
}

func TestDownloadWarnsAndFallsBackToSequentialRead(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("sequential-"), 9)
	object := putTestObject(t, environment.handle, "objects/sequential.bin", payload)
	destination := filepath.Join(t.TempDir(), "sequential.bin")
	sequentialHandle := environment.handle
	sequentialHandle.Descriptor.Capabilities.Read.Range = driver.SupportUnavailable
	sequentialHandle.Descriptor.Capabilities.Read.MaxParallelRanges = 0
	sequentialHandle.Descriptor.Capabilities.Read.MaximumRangeBytes = 0
	sequentialHandle.RangeReader = nil

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		sequentialHandle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 13},
	)
	if err != nil {
		t.Fatalf("prepare sequential download: %v", err)
	}

	warnings := prepared.Download.Warnings
	if len(warnings) != 2 || warnings[0].Code != driver.WarningRangeReadUnavailable ||
		warnings[1].Code != driver.WarningParallelRangeReadUnavailable {
		t.Fatalf("unexpected fallback warnings: %+v", warnings)
	}

	if _, err := environment.engine.RunDownload(context.Background(), prepared.ID, sequentialHandle); err != nil {
		t.Fatalf("run sequential download: %v", err)
	}

	if !bytes.Equal(readFile(t, destination), payload) {
		t.Fatal("sequential fallback download differs")
	}
}

func TestDownloadInvalidatesAllReceiptsAfterCompleteHashFailure(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("complete-proof-"), 9)
	object := putTestObject(t, environment.handle, "objects/complete-proof.bin", payload)
	destination := filepath.Join(t.TempDir(), "complete-proof.bin")

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 17},
	)
	if err != nil {
		t.Fatalf("prepare download: %v", err)
	}

	corrupting := &corruptRangeReader{
		RangeReader:   environment.handle.RangeReader,
		corruptOffset: prepared.Download.Blocks[1].Offset,
	}
	corruptingHandle := environment.handle
	corruptingHandle.RangeReader = corrupting

	_, err = environment.engine.RunDownload(context.Background(), prepared.ID, corruptingHandle)
	if !errors.Is(err, ErrTransferIntegrity) {
		t.Fatalf("got %v, want complete integrity failure", err)
	}

	interrupted, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect rejected complete proof: %v", err)
	}

	if interrupted.Status != StatusVerifying || len(interrupted.VerifiedBlocks) != 0 {
		t.Fatalf("untrusted receipts survived complete proof failure: %+v", interrupted)
	}

	counting := &failRangeReader{
		RangeReader: environment.handle.RangeReader,
		failOffset:  math.MaxUint64,
		calls:       make(map[uint64]int),
	}
	resumeHandle := environment.handle
	resumeHandle.RangeReader = counting

	if _, err := environment.engine.RunDownload(context.Background(), prepared.ID, resumeHandle); err != nil {
		t.Fatalf("retry after rejected complete proof: %v", err)
	}

	for _, block := range prepared.Download.Blocks {
		if counting.callCount(block.Offset) != 1 {
			t.Fatalf("block %d retried %d times, want one", block.Number, counting.callCount(block.Offset))
		}
	}

	if !bytes.Equal(readFile(t, destination), payload) {
		t.Fatal("download after complete-proof retry differs")
	}
}

func TestDownloadNeverOverwritesDifferentDestination(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := []byte("provider bytes")
	object := putTestObject(t, environment.handle, "objects/no-overwrite.bin", payload)
	destination := filepath.Join(t.TempDir(), "no-overwrite.bin")

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 4},
	)
	if err != nil {
		t.Fatalf("prepare download: %v", err)
	}

	existing := []byte("keep this destination")
	if writeErr := os.WriteFile(destination, existing, 0o600); writeErr != nil {
		t.Fatalf("write competing destination: %v", writeErr)
	}

	_, err = environment.engine.RunDownload(context.Background(), prepared.ID, environment.handle)
	if !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("got %v, want destination conflict", err)
	}

	if !bytes.Equal(readFile(t, destination), existing) {
		t.Fatal("different destination was overwritten")
	}
}

func TestDownloadRecoversAlreadyPublishedDestination(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := []byte("published before terminal journal revision")
	object := putTestObject(t, environment.handle, "objects/published.bin", payload)
	destination := filepath.Join(t.TempDir(), "published.bin")

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 7},
	)
	if err != nil {
		t.Fatalf("prepare download: %v", err)
	}

	if writeErr := os.WriteFile(destination, payload, 0o600); writeErr != nil {
		t.Fatalf("simulate published destination: %v", writeErr)
	}

	result, err := environment.engine.RunDownload(context.Background(), prepared.ID, environment.handle)
	if err != nil {
		t.Fatalf("recover published destination: %v", err)
	}

	if result.Destination != destination || !bytes.Equal(readFile(t, destination), payload) {
		t.Fatalf("unexpected recovered result: %+v", result)
	}

	snapshot, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect recovered download: %v", err)
	}

	if snapshot.Status != StatusComplete {
		t.Fatalf("got status %q, want complete", snapshot.Status)
	}
}

func TestAbortDownloadRemovesOnlyStaging(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("abort-download"), 8)
	object := putTestObject(t, environment.handle, "objects/abort-download.bin", payload)
	destination := filepath.Join(t.TempDir(), "abort-download.bin")

	prepared, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(payload),
		destination,
		DownloadOptions{BlockBytes: 17},
	)
	if err != nil {
		t.Fatalf("prepare download: %v", err)
	}

	failing := &failRangeReader{
		RangeReader: environment.handle.RangeReader,
		failOffset:  prepared.Download.Blocks[1].Offset,
		calls:       make(map[uint64]int),
	}
	failingHandle := environment.handle
	failingHandle.RangeReader = failing

	if _, runErr := environment.engine.RunDownload(
		context.Background(),
		prepared.ID,
		failingHandle,
	); runErr == nil {
		t.Fatal("first download unexpectedly succeeded")
	}

	if abortErr := environment.engine.AbortDownload(prepared.ID); abortErr != nil {
		t.Fatalf("abort download: %v", abortErr)
	}

	if _, statErr := os.Lstat(prepared.Download.StagingPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("staging remains after abort: %v", statErr)
	}

	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("final destination exists after abort: %v", statErr)
	}

	snapshot, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect aborted download: %v", err)
	}

	if snapshot.Status != StatusAborted {
		t.Fatalf("got status %q, want aborted", snapshot.Status)
	}
}
