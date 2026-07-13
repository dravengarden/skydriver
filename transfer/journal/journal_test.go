package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/driver/localfs"
)

var (
	errInjectedPart     = errors.New("injected part failure")
	errInjectedComplete = errors.New("injected lost completion response")
	errInjectedPut      = errors.New("injected lost complete-write response")
	errInjectedRange    = errors.New("injected range failure")
)

type testEnvironment struct {
	engine       *Engine
	store        *Store
	handle       driver.Handle
	journalRoot  string
	providerRoot string
}

func newTestEnvironment(t *testing.T, options EngineOptions) testEnvironment {
	t.Helper()

	journalRoot := filepath.Join(t.TempDir(), "journals")

	store, err := NewStore(journalRoot)
	if err != nil {
		t.Fatalf("create journal store: %v", err)
	}

	engine, err := NewEngine(store, options)
	if err != nil {
		t.Fatalf("create journal engine: %v", err)
	}

	providerRoot := filepath.Join(t.TempDir(), "provider")
	if mkdirErr := os.Mkdir(providerRoot, 0o700); mkdirErr != nil {
		t.Fatalf("create provider root: %v", mkdirErr)
	}

	handle, err := localfs.Open("test-local", providerRoot)
	if err != nil {
		t.Fatalf("open local filesystem driver: %v", err)
	}

	return testEnvironment{
		engine:       engine,
		store:        store,
		handle:       handle,
		journalRoot:  journalRoot,
		providerRoot: providerRoot,
	}
}

func checksumOf(payload []byte) string {
	digest := sha256.Sum256(payload)

	return hex.EncodeToString(digest[:])
}

func putTestObject(t *testing.T, handle driver.Handle, storageKey string, payload []byte) driver.Object {
	t.Helper()

	object, err := handle.Writer.Put(context.Background(), driver.PutRequest{
		StorageKey: storageKey,
		Body:       bytes.NewReader(payload),
		SizeBytes:  uint64(len(payload)),
		Checksum:   checksumOf(payload),
	})
	if err != nil {
		t.Fatalf("put test object: %v", err)
	}

	return object
}

func readFile(t *testing.T, filePath string) []byte {
	t.Helper()

	payload, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read %q: %v", filePath, err)
	}

	return payload
}

type failPartWriter struct {
	driver.ResumableWriter

	mutex      sync.Mutex
	failNumber uint32
	failed     bool
	calls      map[uint32]int
}

func (writer *failPartWriter) PutPart(
	ctx context.Context,
	request driver.PutPartRequest,
) (driver.UploadedPart, error) {
	writer.mutex.Lock()
	writer.calls[request.Part.Number]++

	shouldFail := request.Part.Number == writer.failNumber && !writer.failed
	if shouldFail {
		writer.failed = true
	}
	writer.mutex.Unlock()

	if shouldFail {
		return driver.UploadedPart{}, fmt.Errorf("%w: part %d", errInjectedPart, request.Part.Number)
	}

	return writer.ResumableWriter.PutPart(ctx, request)
}

func (writer *failPartWriter) callCount(number uint32) int {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	return writer.calls[number]
}

type lostCompleteWriter struct {
	driver.ResumableWriter

	mutex sync.Mutex
	lost  bool
}

type lostPutWriter struct {
	driver.Writer

	mutex sync.Mutex
	lost  bool
}

func (writer *lostPutWriter) Put(
	ctx context.Context,
	request driver.PutRequest,
) (driver.Object, error) {
	object, err := writer.Writer.Put(ctx, request)
	if err != nil {
		return driver.Object{}, err
	}

	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	if !writer.lost {
		writer.lost = true

		return driver.Object{}, errInjectedPut
	}

	return object, nil
}

func (writer *lostCompleteWriter) CompleteUpload(
	ctx context.Context,
	request driver.CompleteUploadRequest,
) (driver.Object, error) {
	object, err := writer.ResumableWriter.CompleteUpload(ctx, request)
	if err != nil {
		return driver.Object{}, err
	}

	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	if !writer.lost {
		writer.lost = true

		return driver.Object{}, errInjectedComplete
	}

	return object, nil
}

type failRangeReader struct {
	driver.RangeReader

	mutex      sync.Mutex
	failOffset uint64
	failed     bool
	calls      map[uint64]int
}

type corruptRangeReader struct {
	driver.RangeReader

	corruptOffset uint64
}

func (reader *corruptRangeReader) OpenRange(
	ctx context.Context,
	object driver.Object,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	stream, err := reader.RangeReader.OpenRange(ctx, object, offset, length)
	if err != nil {
		return nil, err
	}

	payload, readErr := io.ReadAll(stream)

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}

	if offset == reader.corruptOffset && len(payload) != 0 {
		payload[0] ^= 0xff
	}

	return io.NopCloser(bytes.NewReader(payload)), nil
}

func (reader *failRangeReader) OpenRange(
	ctx context.Context,
	object driver.Object,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	reader.mutex.Lock()
	reader.calls[offset]++

	shouldFail := offset == reader.failOffset && !reader.failed
	if shouldFail {
		reader.failed = true
	}
	reader.mutex.Unlock()

	if shouldFail {
		return nil, fmt.Errorf("%w at %d", errInjectedRange, offset)
	}

	return reader.RangeReader.OpenRange(ctx, object, offset, length)
}

func (reader *failRangeReader) callCount(offset uint64) int {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()

	return reader.calls[offset]
}

func testEngineOptions() EngineOptions {
	return EngineOptions{MaxConcurrency: 1, LeaseDuration: time.Minute}
}

func completeOnlyHandle(handle driver.Handle, requiresReadback bool) driver.Handle {
	handle.Descriptor.Capabilities.Write.Resume = driver.SupportUnavailable
	handle.Descriptor.Capabilities.Write.ParallelParts = driver.SupportUnavailable
	handle.Descriptor.Capabilities.Write.PartOrdering = driver.PartOrderingNone
	handle.Descriptor.Capabilities.Write.MaxParallelParts = 0
	handle.Descriptor.Capabilities.Write.MinimumNonFinalPartBytes = 0
	handle.Descriptor.Capabilities.Write.MaximumPartBytes = 0
	handle.Descriptor.Capabilities.Write.MaximumParts = 0
	handle.Descriptor.Capabilities.PreferredPartBytes = 0
	handle.ResumableWriter = nil

	if requiresReadback {
		handle.Descriptor.Capabilities.Integrity.StrongUploadChecksum = driver.SupportUnavailable
		handle.Descriptor.Capabilities.Integrity.Algorithms = nil
		handle.Descriptor.Capabilities.Integrity.RequiresReadback = true
	}

	return handle
}
