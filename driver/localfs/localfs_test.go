package localfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dravengarden/carrack/driver"
)

func TestOpenDeclaresExactCapabilities(t *testing.T) {
	t.Parallel()

	handle, err := Open("local-test", t.TempDir())
	if err != nil {
		t.Fatalf("open handle: %v", err)
	}

	if err := handle.Validate(); err != nil {
		t.Fatalf("validate handle: %v", err)
	}

	capabilities := handle.Descriptor.Capabilities
	if handle.Descriptor.Kind != Kind || capabilities.Read.Range != driver.SupportNative {
		t.Fatalf("unexpected read capabilities: %+v", capabilities.Read)
	}

	if capabilities.Write.Resume != driver.SupportEmulated ||
		capabilities.Write.ParallelParts != driver.SupportEmulated ||
		capabilities.Write.PartOrdering != driver.PartOrderingArbitrary {
		t.Fatalf("unexpected write capabilities: %+v", capabilities.Write)
	}

	if capabilities.ServerSideCopy != driver.SupportUnavailable {
		t.Fatalf("server-side copy unexpectedly available: %q", capabilities.ServerSideCopy)
	}

	if capabilities.Integrity.RequiresReadback ||
		!slices.Equal(capabilities.Integrity.Algorithms, []driver.ChecksumAlgorithm{"sha256"}) {
		t.Fatalf("unexpected integrity capabilities: %+v", capabilities.Integrity)
	}
}

func TestCompleteObjectLifecycle(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)
	ctx := context.Background()
	payload := []byte("complete immutable payload")

	object := mustPut(t, client, "objects/alpha", payload)
	if actual := mustReadFile(t, filepath.Join(rootPath, "objects", "alpha")); !bytes.Equal(actual, payload) {
		t.Fatalf("published bytes differ: %q", actual)
	}

	retried := mustPut(t, client, "objects/alpha", payload)
	if retried != object {
		t.Fatalf("idempotent retry returned different object: %+v != %+v", retried, object)
	}

	_, err := client.Put(ctx, driver.PutRequest{
		StorageKey: "objects/alpha",
		Body:       bytes.NewReader([]byte("different")),
		SizeBytes:  uint64(len("different")),
		Checksum:   checksum([]byte("different")),
	})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("conflicting immutable write error = %v, want ErrIntegrity", err)
	}

	stat, err := client.Stat(ctx, object.Locator.StorageKey)
	if err != nil {
		t.Fatalf("stat object: %v", err)
	}

	if stat != object {
		t.Fatalf("stat returned different identity: %+v != %+v", stat, object)
	}

	stream, err := client.Open(ctx, object)
	if err != nil {
		t.Fatalf("open complete object: %v", err)
	}

	if actual := mustReadAll(t, stream); !bytes.Equal(actual, payload) {
		t.Fatalf("complete read differs: %q", actual)
	}

	rangeStream, err := client.OpenRange(ctx, object, 9, 9)
	if err != nil {
		t.Fatalf("open exact range: %v", err)
	}

	if actual := mustReadAll(t, rangeStream); string(actual) != "immutable" {
		t.Fatalf("range read = %q, want immutable", actual)
	}

	if err := client.Delete(ctx, object); err != nil {
		t.Fatalf("delete exact object: %v", err)
	}

	if err := client.Delete(ctx, object); err != nil {
		t.Fatalf("repeat delete: %v", err)
	}

	if _, err := os.Stat(filepath.Join(rootPath, "objects", "alpha")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted final object stat error = %v, want not exist", err)
	}
}

func TestPutSupportsEmptyFilesAndRejectsBodyLengthMismatch(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)
	ctx := context.Background()

	empty := mustPut(t, client, "objects/empty", nil)
	if empty.SizeBytes != 0 || empty.Locator.ETag != checksum(nil) {
		t.Fatalf("unexpected empty object: %+v", empty)
	}

	tests := []struct {
		name        string
		storageKey  string
		body        []byte
		sizeBytes   uint64
		declaredSum string
	}{
		{name: "short", storageKey: "objects/short", body: []byte("abc"), sizeBytes: 4, declaredSum: checksum([]byte("abcx"))},
		{name: "long", storageKey: "objects/long", body: []byte("abcd"), sizeBytes: 3, declaredSum: checksum([]byte("abc"))},
		{name: "checksum", storageKey: "objects/checksum", body: []byte("abc"), sizeBytes: 3, declaredSum: checksum([]byte("abd"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := client.Put(ctx, driver.PutRequest{
				StorageKey: test.storageKey,
				Body:       bytes.NewReader(test.body),
				SizeBytes:  test.sizeBytes,
				Checksum:   test.declaredSum,
			})
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("put mismatch error = %v, want ErrIntegrity", err)
			}

			if _, err := os.Stat(filepath.Join(rootPath, filepath.FromSlash(test.storageKey))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("partial final object exists, stat error = %v", err)
			}
		})
	}
}

func TestInventoryIsBoundedStableAndExcludesInternalState(t *testing.T) {
	t.Parallel()

	client := mustClient(t, t.TempDir())
	ctx := context.Background()

	mustPut(t, client, "objects/c", []byte("c"))
	mustPut(t, client, "objects/a", []byte("a"))
	mustPut(t, client, "objects/b", []byte("b"))

	session, err := client.BeginUpload(ctx, driver.BeginUploadRequest{
		StorageKey: "objects/pending",
		SizeBytes:  1,
		Checksum:   checksum([]byte("p")),
	})
	if err != nil {
		t.Fatalf("begin pending upload: %v", err)
	}

	first, cursor, err := client.List(ctx, "", 2)
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}

	if keys := objectKeys(first); !slices.Equal(keys, []string{"objects/a", "objects/b"}) {
		t.Fatalf("first page keys = %v", keys)
	}

	second, next, err := client.List(ctx, cursor, 2)
	if err != nil {
		t.Fatalf("list second page: %v", err)
	}

	if keys := objectKeys(second); !slices.Equal(keys, []string{"objects/c"}) || next != "" {
		t.Fatalf("second page = %v, next = %q", keys, next)
	}

	if err := client.AbortUpload(ctx, session); err != nil {
		t.Fatalf("abort pending upload: %v", err)
	}
}

func TestPinnedReadsRejectChangedObjects(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)
	object := mustPut(t, client, "objects/change", []byte("original"))

	if err := os.WriteFile(filepath.Join(rootPath, "objects", "change"), []byte("modified"), 0o600); err != nil {
		t.Fatalf("mutate object: %v", err)
	}

	if _, err := client.Open(context.Background(), object); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("open changed object error = %v, want ErrIntegrity", err)
	}

	if _, err := client.OpenRange(context.Background(), object, 0, 1); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("range changed object error = %v, want ErrIntegrity", err)
	}

	if err := client.Delete(context.Background(), object); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("delete changed object error = %v, want ErrIntegrity", err)
	}

	if actual := mustReadFile(t, filepath.Join(rootPath, "objects", "change")); string(actual) != "modified" {
		t.Fatalf("conditional delete changed bytes: %q", actual)
	}
}

func TestKeysAndFinalSymlinksAreRejected(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)

	for _, storageKey := range []string{"../escape", "/absolute", ".carrack/object", "objects/.carrack-upload-x"} {
		_, err := client.Put(context.Background(), driver.PutRequest{
			StorageKey: storageKey,
			Body:       bytes.NewReader(nil),
			SizeBytes:  0,
			Checksum:   checksum(nil),
		})
		if !errors.Is(err, ErrInvalidObject) {
			t.Fatalf("key %q error = %v, want ErrInvalidObject", storageKey, err)
		}
	}

	if err := os.MkdirAll(filepath.Join(rootPath, "objects"), 0o700); err != nil {
		t.Fatalf("create objects directory: %v", err)
	}

	if err := os.WriteFile(filepath.Join(rootPath, "target"), []byte("target"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}

	if err := os.Symlink("../target", filepath.Join(rootPath, "objects", "link")); err != nil {
		t.Fatalf("create object symlink: %v", err)
	}

	if _, err := client.Stat(context.Background(), "objects/link"); !errors.Is(err, ErrInvalidObject) {
		t.Fatalf("stat symlink error = %v, want ErrInvalidObject", err)
	}
}

func mustClient(t *testing.T, rootPath string) *Client {
	t.Helper()

	client, err := NewClient(rootPath)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	return client
}

func mustPut(t *testing.T, client *Client, storageKey string, payload []byte) driver.Object {
	t.Helper()

	object, err := client.Put(context.Background(), driver.PutRequest{
		StorageKey: storageKey,
		Body:       bytes.NewReader(payload),
		SizeBytes:  uint64(len(payload)),
		Checksum:   checksum(payload),
	})
	if err != nil {
		t.Fatalf("put %q: %v", storageKey, err)
	}

	return object
}

func mustReadAll(t *testing.T, stream io.ReadCloser) []byte {
	t.Helper()

	payload, readErr := io.ReadAll(stream)

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read and close stream: %v", errors.Join(readErr, closeErr))
	}

	return payload
}

func mustReadFile(t *testing.T, filePath string) []byte {
	t.Helper()

	payload, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read %q: %v", filePath, err)
	}

	return payload
}

func checksum(payload []byte) string {
	digest := sha256.Sum256(payload)

	return hex.EncodeToString(digest[:])
}

func objectKeys(objects []driver.Object) []string {
	keys := make([]string, 0, len(objects))
	for _, object := range objects {
		keys = append(keys, object.Locator.StorageKey)
	}

	return keys
}
