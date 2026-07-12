package localfs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
)

func TestFactoryOpensRootedReadWriter(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()

	configuration, err := json.Marshal(localfs.DriverConfig{Root: rootPath})
	if err != nil {
		t.Fatalf("encode local filesystem configuration: %v", err)
	}

	registry, err := provider.NewRegistry(localfs.Factory{})
	if err != nil {
		t.Fatalf("construct local filesystem registry: %v", err)
	}

	handle, err := registry.Open(context.Background(), provider.DriverSpec{
		ID: "local-main", Kind: localfs.DriverKind, Config: configuration,
	}, provider.Dependencies{})
	if err != nil {
		t.Fatalf("open local filesystem driver: %v", err)
	}

	if handle.Reader == nil || handle.Writer == nil || handle.Deleter == nil ||
		handle.Inventory == nil ||
		!handle.Capabilities.RangeRead || !handle.Capabilities.StreamingWrite ||
		!handle.Capabilities.Delete || !handle.Capabilities.Inventory {
		t.Fatalf("unexpected local filesystem capabilities: %+v", handle.Capabilities)
	}
}

func TestClientListsBoundedStableInventoryPages(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)

	const objectCount = 70

	for index := range objectCount {
		key := fmt.Sprintf("owned/objects/%03d.bin", index)

		payload := fmt.Appendf(nil, "inventory object %03d", index)
		if _, err := client.Put(context.Background(), key, bytes.NewReader(payload), putOptions(payload)); err != nil {
			t.Fatalf("put inventory fixture %q: %v", key, err)
		}
	}

	outside := []byte("outside inventory prefix")
	if _, err := client.Put(
		context.Background(),
		"other/object.bin",
		bytes.NewReader(outside),
		putOptions(outside),
	); err != nil {
		t.Fatalf("put outside inventory fixture: %v", err)
	}

	first, err := client.List(context.Background(), "owned", "")
	if err != nil {
		t.Fatalf("list first inventory page: %v", err)
	}

	if len(first.Objects) != 64 || first.NextCursor != "owned/objects/063.bin" {
		t.Fatalf("unexpected first inventory page: count=%d cursor=%q", len(first.Objects), first.NextCursor)
	}

	second, err := client.List(context.Background(), "owned", first.NextCursor)
	if err != nil {
		t.Fatalf("list second inventory page: %v", err)
	}

	if len(second.Objects) != objectCount-len(first.Objects) || second.NextCursor != "" {
		t.Fatalf("unexpected final inventory page: count=%d cursor=%q", len(second.Objects), second.NextCursor)
	}

	objects := slices.Concat(first.Objects, second.Objects)
	for index, object := range objects {
		expectedKey := fmt.Sprintf("owned/objects/%03d.bin", index)
		if object.Key != expectedKey || object.SizeBytes == 0 || object.ETag == "" || object.Version == "" {
			t.Errorf("unexpected inventory object %d: %+v", index, object)
		}
	}

	empty, err := client.List(context.Background(), "missing", "")
	if err != nil {
		t.Fatalf("list absent inventory prefix: %v", err)
	}

	if len(empty.Objects) != 0 || empty.NextCursor != "" {
		t.Fatalf("absent prefix returned inventory: %+v", empty)
	}

	if _, err := client.List(context.Background(), "owned", "other/object.bin"); !errors.Is(err, localfs.ErrInvalidObject) {
		t.Fatalf("outside inventory cursor was not rejected: %v", err)
	}
}

func TestClientInventoryConvergesAfterMidScanMutation(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)

	const initialObjectCount = 65

	for index := range initialObjectCount {
		key := fmt.Sprintf("owned/objects/%03d.bin", index)
		payload := fmt.Appendf(nil, "inventory object %03d", index)

		if _, err := client.Put(context.Background(), key, bytes.NewReader(payload), putOptions(payload)); err != nil {
			t.Fatalf("put inventory fixture %q: %v", key, err)
		}
	}

	first, err := client.List(context.Background(), "owned", "")
	if err != nil {
		t.Fatalf("list first inventory page: %v", err)
	}

	if len(first.Objects) != 64 || first.NextCursor != "owned/objects/063.bin" {
		t.Fatalf("unexpected first inventory page: count=%d cursor=%q", len(first.Objects), first.NextCursor)
	}

	insertedKey := "owned/objects/000a.bin"
	insertedPayload := []byte("inserted before the active cursor")

	if _, putErr := client.Put(
		context.Background(),
		insertedKey,
		bytes.NewReader(insertedPayload),
		putOptions(insertedPayload),
	); putErr != nil {
		t.Fatalf("insert object before inventory cursor: %v", putErr)
	}

	removedKey := "owned/objects/064.bin"

	if deleteErr := client.Delete(context.Background(), removedKey); deleteErr != nil {
		t.Fatalf("remove object after inventory cursor: %v", deleteErr)
	}

	second, err := client.List(context.Background(), "owned", first.NextCursor)
	if err != nil {
		t.Fatalf("list inventory page after provider mutation: %v", err)
	}

	if len(second.Objects) != 0 || second.NextCursor != "" {
		t.Fatalf("mutated terminal inventory page changed: %+v", second)
	}

	staleKeys := inventoryObjectKeys(slices.Concat(first.Objects, second.Objects))
	if slices.Contains(staleKeys, insertedKey) {
		t.Fatalf("mid-scan insertion before cursor appeared in stale report: %v", staleKeys)
	}

	freshKeys := make([]string, 0, initialObjectCount)
	cursor := ""

	for {
		page, listErr := client.List(context.Background(), "owned", cursor)
		if listErr != nil {
			t.Fatalf("repeat inventory after provider mutation: %v", listErr)
		}

		freshKeys = append(freshKeys, inventoryObjectKeys(page.Objects)...)
		if page.NextCursor == "" {
			break
		}

		cursor = page.NextCursor
	}

	if len(freshKeys) != initialObjectCount || !slices.IsSorted(freshKeys) ||
		!slices.Contains(freshKeys, insertedKey) || slices.Contains(freshKeys, removedKey) {
		t.Fatalf("fresh inventory did not converge after mutation: %v", freshKeys)
	}
}

func inventoryObjectKeys(objects []provider.Object) []string {
	keys := make([]string, len(objects))
	for index, object := range objects {
		keys[index] = object.Key
	}

	return keys
}

func TestClientDeleteIsIdempotentAndRejectsDirectories(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)
	key := "packs/delete/object.bin"
	payload := []byte("delete this immutable object")

	if _, err := client.Put(context.Background(), key, bytes.NewReader(payload), putOptions(payload)); err != nil {
		t.Fatalf("put delete fixture: %v", err)
	}

	if err := client.Delete(context.Background(), key); err != nil {
		t.Fatalf("delete local filesystem object: %v", err)
	}

	if err := client.Delete(context.Background(), key); err != nil {
		t.Fatalf("replay local filesystem delete: %v", err)
	}

	if _, err := os.Stat(filepath.Join(rootPath, filepath.FromSlash(key))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("deleted object remains visible: %v", err)
	}

	if err := client.Delete(context.Background(), "packs/delete"); !errors.Is(err, localfs.ErrInvalidObject) {
		t.Fatalf("directory delete was not rejected: %v", err)
	}
}

func TestFactoryRejectsUnknownConfigurationAndRelativeRoot(t *testing.T) {
	t.Parallel()

	factory := localfs.Factory{}
	for _, specification := range []provider.DriverSpec{
		{ID: "unknown", Kind: localfs.DriverKind, Config: json.RawMessage(`{"root":"/tmp","extra":true}`)},
		{ID: "relative", Kind: localfs.DriverKind, Config: json.RawMessage(`{"root":"relative"}`)},
	} {
		if _, err := factory.Open(context.Background(), specification, provider.Dependencies{}); err == nil {
			t.Fatalf("invalid configuration was accepted: %s", specification.Config)
		}
	}
}

func TestClientPutsStatsAndReadsExactRange(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)
	payload := []byte("immutable local filesystem ciphertext")
	digest := sha256.Sum256(payload)
	options := provider.PutOptions{
		SizeBytes: uint64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
	}

	uploaded, err := client.Put(
		context.Background(),
		"packs/sha256/object.bin",
		bytes.NewReader(payload),
		options,
	)
	if err != nil {
		t.Fatalf("put local filesystem object: %v", err)
	}

	if uploaded.SizeBytes != uint64(len(payload)) || uploaded.ETag != options.SHA256 ||
		uploaded.Version != "sha256:"+options.SHA256 {
		t.Fatalf("unexpected uploaded object: %+v", uploaded)
	}

	information, err := os.Stat(filepath.Join(rootPath, "packs", "sha256", "object.bin"))
	if err != nil {
		t.Fatalf("stat stored local filesystem object: %v", err)
	}

	if information.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected stored object mode: %o", information.Mode().Perm())
	}

	stated, err := client.Stat(context.Background(), "packs/sha256/object.bin")
	if err != nil {
		t.Fatalf("stat local filesystem object: %v", err)
	}

	if stated != uploaded {
		t.Fatalf("stat identity differs from upload: stat=%+v upload=%+v", stated, uploaded)
	}

	stream, err := client.OpenRange(context.Background(), "packs/sha256/object.bin", 10, 12)
	if err != nil {
		t.Fatalf("open local filesystem range: %v", err)
	}

	selected, readErr := io.ReadAll(stream)

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read local filesystem range: %v", errors.Join(readErr, closeErr))
	}

	if !bytes.Equal(selected, payload[10:22]) {
		t.Fatalf("range is %q, expected %q", selected, payload[10:22])
	}
}

func TestClientPutIsContentIdempotent(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)
	key := "packs/object.bin"
	payload := []byte("first immutable object")
	options := putOptions(payload)

	first, err := client.Put(context.Background(), key, bytes.NewReader(payload), options)
	if err != nil {
		t.Fatalf("put first local filesystem object: %v", err)
	}

	replayed, err := client.Put(context.Background(), key, bytes.NewReader(payload), options)
	if err != nil {
		t.Fatalf("replay local filesystem object: %v", err)
	}

	if replayed != first {
		t.Fatalf("replayed object identity changed: first=%+v replayed=%+v", first, replayed)
	}

	replacement := []byte("other immutable bytes")
	if _, putErr := client.Put(
		context.Background(),
		key,
		bytes.NewReader(replacement),
		putOptions(replacement),
	); !errors.Is(putErr, localfs.ErrIntegrity) {
		t.Fatalf("conflicting immutable object was not rejected: %v", putErr)
	}

	stored, err := os.ReadFile(filepath.Join(rootPath, filepath.FromSlash(key)))
	if err != nil {
		t.Fatalf("read immutable destination after conflict: %v", err)
	}

	if !bytes.Equal(stored, payload) {
		t.Fatalf("immutable destination changed to %q", stored)
	}
}

func TestClientRejectsInvalidUploadBodiesWithoutPublishing(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)
	payload := []byte("declared bytes")

	tests := []struct {
		name    string
		key     string
		body    []byte
		options provider.PutOptions
	}{
		{
			name: "short", key: "objects/short",
			body: payload, options: provider.PutOptions{
				SizeBytes: uint64(len(payload) + 1), SHA256: putOptions(payload).SHA256,
			},
		},
		{
			name: "long", key: "objects/long",
			body: append(bytes.Clone(payload), '!'), options: putOptions(payload),
		},
		{
			name: "wrong digest", key: "objects/digest",
			body: payload, options: provider.PutOptions{
				SizeBytes: uint64(len(payload)), SHA256: strings.Repeat("0", sha256.Size*2),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := client.Put(
				context.Background(),
				test.key,
				bytes.NewReader(test.body),
				test.options,
			); !errors.Is(err, localfs.ErrIntegrity) {
				t.Fatalf("invalid upload body was not rejected: %v", err)
			}

			if _, err := os.Stat(filepath.Join(rootPath, filepath.FromSlash(test.key))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid upload was published: %v", err)
			}
		})
	}
}

func TestClientConfinesKeysAndSymlinksToRoot(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()

	outsidePath := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsidePath, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	if err := os.Symlink(outsidePath, filepath.Join(rootPath, "escape")); err != nil {
		t.Fatalf("create escaping symlink: %v", err)
	}

	client := newClient(t, rootPath)
	if _, err := client.Stat(context.Background(), "escape/secret"); !errors.Is(err, localfs.ErrInvalidObject) {
		t.Fatalf("escaping read symlink was not rejected: %v", err)
	}

	payload := []byte("must stay rooted")
	if _, err := client.Put(
		context.Background(),
		"escape/new",
		bytes.NewReader(payload),
		putOptions(payload),
	); !errors.Is(err, localfs.ErrInvalidObject) {
		t.Fatalf("escaping write symlink was not rejected: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outsidePath, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escaping write created an outside file: %v", err)
	}

	for _, key := range []string{"", ".", "../secret", "/absolute", "a//b", "a/./b", `a\b`} {
		if _, err := client.Stat(context.Background(), key); !errors.Is(err, localfs.ErrInvalidObject) {
			t.Fatalf("unsafe key %q was not rejected: %v", key, err)
		}
	}
}

func TestClientRangeAndUploadHonorCancellation(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := newClient(t, rootPath)
	payload := []byte("cancelled local object")

	key := "object"
	if _, err := client.Put(context.Background(), key, bytes.NewReader(payload), putOptions(payload)); err != nil {
		t.Fatalf("seed local filesystem object: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	stream, err := client.OpenRange(ctx, key, 0, uint64(len(payload)))
	if err != nil {
		t.Fatalf("open cancellable local filesystem range: %v", err)
	}

	cancel()

	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled range returned unexpected error: %v", err)
	}

	if err := stream.Close(); err != nil {
		t.Fatalf("close cancelled local filesystem range: %v", err)
	}

	cancelledContext, cancelUpload := context.WithCancel(context.Background())
	cancelUpload()

	if _, err := client.Put(
		cancelledContext,
		"cancelled",
		bytes.NewReader(payload),
		putOptions(payload),
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled upload returned unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(rootPath, "cancelled")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled upload was published: %v", err)
	}
}

func newClient(t *testing.T, rootPath string) *localfs.Client {
	t.Helper()

	client, err := localfs.NewClient(rootPath)
	if err != nil {
		t.Fatalf("construct local filesystem client: %v", err)
	}

	return client
}

func putOptions(payload []byte) provider.PutOptions {
	digest := sha256.Sum256(payload)

	return provider.PutOptions{
		SizeBytes: uint64(len(payload)), SHA256: hex.EncodeToString(digest[:]),
	}
}
