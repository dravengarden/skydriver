package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/sdk"
)

const (
	testVFSDeleteTaskID      = "d0000000000000000000000000000001"
	testVFSDeleteIncarnation = "e0000000000000000000000000000001"
)

func TestVFSPutJanitorDeletesOnlyAfterStatAndFenceRotation(t *testing.T) {
	t.Parallel()

	fixture := newVFSPutDeleteFixture(t, false)

	server := httptest.NewServer(fixture)
	defer server.Close()

	control := newTestVFSControl(t, server.URL)
	defer control.Clear()

	registry := driver.NewRegistry()
	if err := registry.Register(localfs.Kind, localfs.Factory); err != nil {
		t.Fatalf("register localfs: %v", err)
	}

	janitor, err := sdk.NewVFSPutJanitor(control, registry, 30*time.Second)
	if err != nil {
		t.Fatalf("construct janitor: %v", err)
	}

	result, err := janitor.SweepOne(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if result.Outcome != "deleted" || fixture.completed != "deleted" || fixture.fence != 2 {
		t.Fatalf("unexpected result %#v, completion %q, fence %d", result, fixture.completed, fixture.fence)
	}

	handle, err := localfs.Open(testVFSDriverID, fixture.root)
	if err != nil {
		t.Fatalf("reopen localfs: %v", err)
	}

	if _, err := handle.Reader.Stat(context.Background(), testVFSStorageKey); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("deleted object Stat error = %v", err)
	}
}

func TestVFSPutJanitorRejectsChangedProviderIdentity(t *testing.T) {
	t.Parallel()

	fixture := newVFSPutDeleteFixture(t, true)

	server := httptest.NewServer(fixture)
	defer server.Close()

	control := newTestVFSControl(t, server.URL)
	defer control.Clear()

	registry := driver.NewRegistry()
	if err := registry.Register(localfs.Kind, localfs.Factory); err != nil {
		t.Fatalf("register localfs: %v", err)
	}

	janitor, err := sdk.NewVFSPutJanitor(control, registry, 30*time.Second)
	if err != nil {
		t.Fatalf("construct janitor: %v", err)
	}

	if _, err := janitor.SweepOne(context.Background()); !errors.Is(err, sdk.ErrVFSPutDeleteIdentityChanged) {
		t.Fatalf("sweep error = %v", err)
	}

	if fixture.failed != "provider_identity_changed" || fixture.fence != 1 || fixture.completed != "" {
		t.Fatalf("failure = %q, fence = %d, completion = %q", fixture.failed, fixture.fence, fixture.completed)
	}
}

type vfsPutDeleteFixture struct {
	t         *testing.T
	root      string
	object    driver.Object
	fence     uint64
	failed    string
	completed string
}

func newVFSPutDeleteFixture(t *testing.T, changedIdentity bool) *vfsPutDeleteFixture {
	t.Helper()

	root := t.TempDir()

	handle, err := localfs.Open(testVFSDriverID, root)
	if err != nil {
		t.Fatalf("open localfs: %v", err)
	}

	payload := []byte("unpublished complete object")
	digest := sha256.Sum256(payload)

	object, err := handle.Writer.Put(context.Background(), driver.PutRequest{
		StorageKey: testVFSStorageKey, Body: bytes.NewReader(payload), SizeBytes: uint64(len(payload)),
		Checksum: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatalf("put local object: %v", err)
	}

	if changedIdentity {
		object.Locator.ETag = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}

	return &vfsPutDeleteFixture{t: t, root: root, object: object, fence: 1}
}

func (fixture *vfsPutDeleteFixture) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	fixture.t.Helper()

	switch request.URL.Path {
	case "/api/v2/put-deletes/claim":
		writeTestJSON(fixture.t, response, map[string]any{"state": "claimed", "task": fixture.task()})
	case "/api/v2/put-deletes/" + testVFSDeleteTaskID + "/driver-grant":
		writeTestJSON(fixture.t, response, map[string]any{
			"schema": "carrack.vfs.put-delete-driver-grant.v1", "task_id": testVFSDeleteTaskID,
			"driver_id": testVFSDriverID, "driver_kind": localfs.Kind, "driver_revision": 1,
			"config": map[string]any{"root": fixture.root}, "credential": nil, "expires_at": 4_102_444_800,
		})
	case "/api/v2/put-deletes/" + testVFSDeleteTaskID + "/revalidate":
		fixture.fence++
		writeTestJSON(fixture.t, response, fixture.task())
	case "/api/v2/put-deletes/" + testVFSDeleteTaskID + "/complete":
		var body struct {
			Incarnation  string `json:"incarnation"`
			FencingToken uint64 `json:"fencing_token"`
			Outcome      string `json:"outcome"`
		}
		decodeTestJSON(fixture.t, request.Body, &body)
		fixture.completed = body.Outcome
		task := fixture.task()
		task.State, task.Incarnation, task.LeaseExpiresAt = "deleted", nil, nil
		task.CompletionOutcome = &fixture.completed
		writeTestJSON(fixture.t, response, task)
	case "/api/v2/put-deletes/" + testVFSDeleteTaskID + "/fail":
		var body struct {
			Incarnation  string `json:"incarnation"`
			FencingToken uint64 `json:"fencing_token"`
			ErrorCode    string `json:"error_code"`
		}
		decodeTestJSON(fixture.t, request.Body, &body)
		fixture.failed = body.ErrorCode
		task := fixture.task()
		task.State, task.Incarnation, task.LeaseExpiresAt = "failed", nil, nil
		writeTestJSON(fixture.t, response, task)
	default:
		http.NotFound(response, request)
	}
}

func (fixture *vfsPutDeleteFixture) task() sdk.VFSPutDeleteTask {
	incarnation, lease := testVFSDeleteIncarnation, uint64(4_102_444_800)
	nativeID, version, etag := fixture.object.Locator.NativeID, fixture.object.Locator.Version, fixture.object.Locator.ETag

	return sdk.VFSPutDeleteTask{
		Schema: "carrack.vfs.put-delete-task.v1", TaskID: testVFSDeleteTaskID,
		FilesystemID: testVFSFilesystemID, DirectoryID: testVFSDirectoryID,
		DriverID: testVFSDriverID, DriverRevision: 1, StorageKey: testVFSStorageKey,
		NativeID: &nativeID, ProviderVersion: &version, ETag: &etag,
		SizeBytes:     fixture.object.SizeBytes,
		EncodedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DeleteAfter:   1, Incarnation: &incarnation, FencingToken: fixture.fence,
		LeaseExpiresAt: &lease, AttemptCount: 1, State: "claimed",
	}
}

func newTestVFSControl(t *testing.T, endpoint string) *sdk.VFSControlClient {
	t.Helper()

	encoded := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

	token, err := sdk.ParseVFSToken(encoded)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	control, err := sdk.NewVFSControlClient(endpoint, token, http.DefaultClient)
	token.Clear()

	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	return control
}
