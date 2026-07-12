package sdk_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

func TestGCJanitorRevalidatesDeletesAndCompletes(t *testing.T) {
	t.Parallel()

	fixture := newGCJanitorFixture(t, nil)

	result, err := fixture.janitor.Sweep(context.Background(), fixture.operationID)
	if err != nil {
		t.Fatalf("sweep GC: %v", err)
	}

	if result.State != "succeeded" || result.ObjectsDeleted != 1 || result.LocationsDeleted != 2 {
		t.Fatalf("unexpected GC sweep result: %+v", result)
	}

	if fixture.deleter.callCount() != 1 || fixture.deleter.lastKey() != "retired/object" {
		t.Fatalf("unexpected GC provider deletes: calls=%d key=%q", fixture.deleter.callCount(), fixture.deleter.lastKey())
	}
}

func TestGCJanitorReportsProviderFailure(t *testing.T) {
	t.Parallel()

	fixture := newGCJanitorFixture(t, errTestProviderUnavailable)

	_, err := fixture.janitor.Sweep(context.Background(), fixture.operationID)
	if !errors.Is(err, sdk.ErrGCProviderDelete) || !fixture.failureReported() {
		t.Fatalf("GC provider failure was not durable: err=%v reported=%v", err, fixture.failureReported())
	}
}

type gcJanitorFixture struct {
	janitor     *sdk.GCJanitor
	deleter     *recordingDeleter
	server      *httptest.Server
	operationID string

	mutex     sync.Mutex
	completed bool
	failure   bool
}

func newGCJanitorFixture(t *testing.T, deleteErr error) *gcJanitorFixture {
	t.Helper()

	const operationID = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"

	fixture := &gcJanitorFixture{
		deleter: &recordingDeleter{err: deleteErr}, operationID: operationID,
	}
	token, encodedToken := testClientToken(t)
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/gc/" + operationID + "/deletes/claim":
			fixture.mutex.Lock()
			completed := fixture.completed
			fixture.mutex.Unlock()

			if completed {
				writeJSON(t, response, map[string]any{"state": "succeeded", "task": nil})

				return
			}

			writeJSON(t, response, map[string]any{
				"state": "claimed", "task": gcDeleteTaskJSON(operationID, 1),
			})
		case "/api/v1/gc/deletes/revalidate":
			writeJSON(t, response, gcDeleteTaskJSON(operationID, 2))
		case "/api/v1/gc/deletes/complete":
			fixture.mutex.Lock()
			fixture.completed = true
			fixture.mutex.Unlock()
			writeJSON(t, response, map[string]any{
				"task_id": operationID + "/retired-location", "operation_id": operationID,
				"locations_deleted": 2, "task_state": "deleted", "gc_state": "succeeded",
			})
		case "/api/v1/gc/deletes/fail":
			fixture.mutex.Lock()
			fixture.failure = true
			fixture.mutex.Unlock()

			incarnation := "0123456789abcdef0123456789abcdef"
			writeJSON(t, response, map[string]any{
				"task_id": operationID + "/retired-location", "operation_id": operationID,
				"incarnation": incarnation, "fencing_token": 2, "state": "failed",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(fixture.server.Close)

	control, err := sdk.NewControlClient(fixture.server.URL, token, fixture.server.Client())
	if err != nil {
		t.Fatalf("construct GC janitor control client: %v", err)
	}

	fixture.janitor, err = sdk.NewGCJanitor(
		control,
		map[string]provider.Deleter{"archive": fixture.deleter},
		60,
	)
	if err != nil {
		t.Fatalf("construct GC janitor: %v", err)
	}

	return fixture
}

func gcDeleteTaskJSON(operationID string, fence uint64) map[string]any {
	return map[string]any{
		"task_id": operationID + "/retired-location", "operation_id": operationID,
		"driver_id": "archive", "storage_key": "retired/object",
		"expected_location_count": 2, "owner_client_id": "janitor-client",
		"incarnation": "0123456789abcdef0123456789abcdef", "fencing_token": fence,
		"lease_expires_at": 100, "attempt_count": 1, "state": "claimed",
	}
}

func (fixture *gcJanitorFixture) failureReported() bool {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()

	return fixture.failure
}
