package journal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/skydriver/driver"
)

func TestUploadPublishesOneCompleteObject(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, EngineOptions{MaxConcurrency: 4})
	payload := bytes.Repeat([]byte("complete-object-"), 23)
	source := NewBytesSource("test-upload", payload)

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		source,
		"objects/release.bin",
		UploadOptions{PartBytes: 31},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	object, err := environment.engine.RunUpload(
		context.Background(),
		prepared.ID,
		environment.handle,
		source,
	)
	if err != nil {
		t.Fatalf("run upload: %v", err)
	}

	if object.Locator.StorageKey != "objects/release.bin" || object.SizeBytes != uint64(len(payload)) {
		t.Fatalf("unexpected object: %+v", object)
	}

	if actual := readFile(t, filepath.Join(environment.providerRoot, "objects", "release.bin")); !bytes.Equal(actual, payload) {
		t.Fatalf("provider object differs: got %d bytes", len(actual))
	}

	objects, cursor, err := environment.handle.Inventory.List(context.Background(), "", 10)
	if err != nil {
		t.Fatalf("list provider objects: %v", err)
	}

	if cursor != "" || len(objects) != 1 || objects[0] != object {
		t.Fatalf("inventory does not contain exactly the complete object: cursor=%q objects=%+v", cursor, objects)
	}

	completed, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect completed upload: %v", err)
	}

	if completed.Status != StatusComplete || completed.Object == nil || *completed.Object != object {
		t.Fatalf("upload journal is not complete: %+v", completed)
	}

	if len(completed.CompletedParts) != len(prepared.Upload.Parts) {
		t.Fatalf("got %d completed parts, want %d", len(completed.CompletedParts), len(prepared.Upload.Parts))
	}

	replayed, err := environment.engine.RunUpload(
		context.Background(),
		prepared.ID,
		environment.handle,
		source,
	)
	if err != nil || replayed != object {
		t.Fatalf("replay completed upload: object=%+v error=%v", replayed, err)
	}
}

func TestUploadResumesOnlyMissingProviderParts(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("resume-me"), 19)
	source := NewBytesSource("resume-source", payload)

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		source,
		"objects/resumed.bin",
		UploadOptions{PartBytes: 17},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	failing := &failPartWriter{
		ResumableWriter: environment.handle.ResumableWriter,
		failNumber:      2,
		calls:           make(map[uint32]int),
	}
	failingHandle := environment.handle
	failingHandle.ResumableWriter = failing

	if _, runErr := environment.engine.RunUpload(
		context.Background(),
		prepared.ID,
		failingHandle,
		source,
	); runErr == nil {
		t.Fatal("first upload unexpectedly succeeded")
	}

	interrupted, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect interrupted upload: %v", err)
	}

	if interrupted.Status != StatusTransferring || len(interrupted.CompletedParts) != 1 ||
		interrupted.CompletedParts[0].Number != 1 {
		t.Fatalf("unexpected interrupted progress: %+v", interrupted)
	}

	counting := &failPartWriter{
		ResumableWriter: environment.handle.ResumableWriter,
		calls:           make(map[uint32]int),
	}
	resumeHandle := environment.handle
	resumeHandle.ResumableWriter = counting

	object, err := environment.engine.RunUpload(context.Background(), prepared.ID, resumeHandle, source)
	if err != nil {
		t.Fatalf("resume upload: %v", err)
	}

	if counting.callCount(1) != 0 {
		t.Fatal("resume uploaded provider-authoritative part 1 again")
	}

	for _, part := range prepared.Upload.Parts[1:] {
		if counting.callCount(part.Number) != 1 {
			t.Fatalf("part %d uploaded %d times during resume", part.Number, counting.callCount(part.Number))
		}
	}

	if actual := readFile(t, filepath.Join(environment.providerRoot, object.Locator.StorageKey)); !bytes.Equal(actual, payload) {
		t.Fatal("resumed provider object differs")
	}
}

func TestUploadRecoversLostCompleteResponseWithoutListParts(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("lost-response"), 13)
	source := NewBytesSource("lost-complete", payload)

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		source,
		"objects/lost-complete.bin",
		UploadOptions{PartBytes: 19},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	lostWriter := &lostCompleteWriter{ResumableWriter: environment.handle.ResumableWriter}
	lostHandle := environment.handle
	lostHandle.ResumableWriter = lostWriter

	if _, runErr := environment.engine.RunUpload(
		context.Background(),
		prepared.ID,
		lostHandle,
		source,
	); runErr == nil {
		t.Fatal("lost completion response unexpectedly succeeded")
	}

	interrupted, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect lost completion: %v", err)
	}

	if interrupted.Status != StatusVerifying || interrupted.UploadSession == nil {
		t.Fatalf("completion manifest was not durable before provider completion: %+v", interrupted)
	}

	object, err := environment.engine.RunUpload(
		context.Background(),
		prepared.ID,
		environment.handle,
		source,
	)
	if err != nil {
		t.Fatalf("recover lost completion response: %v", err)
	}

	if actual := readFile(t, filepath.Join(environment.providerRoot, object.Locator.StorageKey)); !bytes.Equal(actual, payload) {
		t.Fatal("recovered completed object differs")
	}
}

func TestUploadRejectsChangedFileSourceBeforeProviderIO(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())

	sourcePath := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(sourcePath, []byte("first immutable bytes"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	source, err := NewFileSource(sourcePath)
	if err != nil {
		t.Fatalf("create file source: %v", err)
	}

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		source,
		"objects/changed.bin",
		UploadOptions{PartBytes: 5},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	if writeErr := os.WriteFile(sourcePath, []byte("second different data"), 0o600); writeErr != nil {
		t.Fatalf("change source: %v", writeErr)
	}

	_, err = environment.engine.RunUpload(context.Background(), prepared.ID, environment.handle, source)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("got %v, want ErrSourceChanged", err)
	}

	if _, statErr := environment.handle.Reader.Stat(context.Background(), "objects/changed.bin"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("provider object exists after changed-source rejection: %v", statErr)
	}
}

func TestCompleteUploadFallbackRecoversLostPutResponse(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	payload := bytes.Repeat([]byte("complete-fallback-"), 7)
	source := NewBytesSource("complete-fallback", payload)
	handle := completeOnlyHandle(environment.handle, true)

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		handle,
		source,
		"objects/complete-fallback.bin",
		UploadOptions{PartBytes: 11},
	)
	if err != nil {
		t.Fatalf("prepare complete upload: %v", err)
	}

	if len(prepared.Upload.Warnings) != 3 ||
		prepared.Upload.Warnings[0].Code != driver.WarningResumableWriteUnavailable ||
		prepared.Upload.Warnings[1].Code != driver.WarningParallelWriteUnavailable ||
		prepared.Upload.Warnings[2].Code != driver.WarningStrongUploadChecksumUnavailable {
		t.Fatalf("unexpected complete-write warnings: %+v", prepared.Upload.Warnings)
	}

	lostWriter := &lostPutWriter{Writer: handle.Writer}
	lostHandle := handle
	lostHandle.Writer = lostWriter

	if _, runErr := environment.engine.RunUpload(
		context.Background(),
		prepared.ID,
		lostHandle,
		source,
	); !errors.Is(runErr, errInjectedPut) {
		t.Fatalf("got %v, want injected lost response", runErr)
	}

	interrupted, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect interrupted complete write: %v", err)
	}

	if interrupted.Status != StatusTransferring {
		t.Fatalf("got status %q, want transferring", interrupted.Status)
	}

	object, err := environment.engine.RunUpload(context.Background(), prepared.ID, handle, source)
	if err != nil {
		t.Fatalf("recover complete write: %v", err)
	}

	if actual := readFile(t, filepath.Join(environment.providerRoot, object.Locator.StorageKey)); !bytes.Equal(actual, payload) {
		t.Fatal("recovered complete-write object differs")
	}
}

func TestAbortPreparedUploadIsIdempotent(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	source := NewBytesSource("abort", []byte("not uploaded"))

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		source,
		"objects/abort.bin",
		UploadOptions{PartBytes: 4},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	for range 2 {
		if abortErr := environment.engine.AbortUpload(
			context.Background(),
			prepared.ID,
			environment.handle,
		); abortErr != nil {
			t.Fatalf("abort upload: %v", abortErr)
		}
	}

	snapshot, err := environment.engine.Inspect(prepared.ID)
	if err != nil {
		t.Fatalf("inspect aborted upload: %v", err)
	}

	if snapshot.Status != StatusAborted {
		t.Fatalf("got status %q, want aborted", snapshot.Status)
	}

	if _, err := environment.engine.RunUpload(context.Background(), prepared.ID, environment.handle, source); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("run aborted upload: got %v, want conflict", err)
	}
}

func TestEmptyObjectUploadAndDownload(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())
	source := NewBytesSource("empty", nil)

	upload, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		source,
		"objects/empty.bin",
		UploadOptions{},
	)
	if err != nil {
		t.Fatalf("prepare empty upload: %v", err)
	}

	object, err := environment.engine.RunUpload(
		context.Background(),
		upload.ID,
		environment.handle,
		source,
	)
	if err != nil {
		t.Fatalf("run empty upload: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "empty.bin")

	download, err := environment.engine.PrepareDownload(
		context.Background(),
		environment.handle,
		object,
		checksumOf(nil),
		destination,
		DownloadOptions{},
	)
	if err != nil {
		t.Fatalf("prepare empty download: %v", err)
	}

	if _, err := environment.engine.RunDownload(
		context.Background(),
		download.ID,
		environment.handle,
	); err != nil {
		t.Fatalf("run empty download: %v", err)
	}

	if actual := readFile(t, destination); len(actual) != 0 {
		t.Fatalf("empty destination has %d bytes", len(actual))
	}
}

var _ driver.ResumableWriter = (*failPartWriter)(nil)
