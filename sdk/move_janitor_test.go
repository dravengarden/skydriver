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

var errTestProviderUnavailable = errors.New("test provider unavailable")

func TestMoveJanitorRevalidatesDeletesAndCompletes(t *testing.T) {
	t.Parallel()

	fixture := newMoveJanitorFixture(t, false, nil)

	result, err := fixture.janitor.SweepMove(context.Background(), fixture.operationID)
	if err != nil {
		t.Fatalf("sweep move: %v", err)
	}

	if result.State != "succeeded" || result.ObjectsDeleted != 1 || result.LocationsDeleted != 2 {
		t.Fatalf("unexpected move sweep result: %+v", result)
	}

	if fixture.deleter.callCount() != 1 || fixture.deleter.lastKey() != "source/object" {
		t.Fatalf("unexpected provider deletes: calls=%d key=%q", fixture.deleter.callCount(), fixture.deleter.lastKey())
	}
}

func TestMoveJanitorRecoversAfterLostCompletionResponse(t *testing.T) {
	t.Parallel()

	fixture := newMoveJanitorFixture(t, true, nil)

	_, firstErr := fixture.janitor.SweepMove(context.Background(), fixture.operationID)
	if !errors.Is(firstErr, sdk.ErrControlPlaneResponse) {
		t.Fatalf("expected lost completion response, got %v", firstErr)
	}

	result, err := fixture.janitor.SweepMove(context.Background(), fixture.operationID)
	if err != nil {
		t.Fatalf("resume completed move: %v", err)
	}

	if result.State != "succeeded" || fixture.deleter.callCount() != 1 {
		t.Fatalf("lost response repeated provider delete: result=%+v calls=%d", result, fixture.deleter.callCount())
	}
}

func TestMoveJanitorReportsProviderFailure(t *testing.T) {
	t.Parallel()

	fixture := newMoveJanitorFixture(t, false, errTestProviderUnavailable)

	_, err := fixture.janitor.SweepMove(context.Background(), fixture.operationID)
	if !errors.Is(err, sdk.ErrMoveProviderDelete) || !fixture.failureReported() {
		t.Fatalf("provider failure was not durably reported: err=%v reported=%v", err, fixture.failureReported())
	}
}

type moveJanitorFixture struct {
	janitor     *sdk.MoveJanitor
	deleter     *recordingDeleter
	server      *httptest.Server
	operationID string

	mutex          sync.Mutex
	completed      bool
	failure        bool
	loseCompletion bool
}

func newMoveJanitorFixture(
	t *testing.T,
	loseCompletion bool,
	deleteErr error,
) *moveJanitorFixture {
	t.Helper()

	const operationID = "606162636465666768696a6b6c6d6e6f"

	fixture := &moveJanitorFixture{
		deleter: &recordingDeleter{err: deleteErr}, operationID: operationID,
		loseCompletion: loseCompletion,
	}
	token, encodedToken := testClientToken(t)
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/moves/" + operationID + "/deletes/claim":
			fixture.mutex.Lock()
			completed := fixture.completed
			fixture.mutex.Unlock()

			if completed {
				writeJSON(t, response, map[string]any{"state": "succeeded", "task": nil})

				return
			}

			writeJSON(t, response, map[string]any{
				"state": "claimed",
				"task":  moveDeleteTaskJSON(operationID, 1),
			})
		case "/api/v1/moves/deletes/revalidate":
			writeJSON(t, response, moveDeleteTaskJSON(operationID, 2))
		case "/api/v1/moves/deletes/complete":
			fixture.mutex.Lock()
			fixture.completed = true
			lose := fixture.loseCompletion
			fixture.loseCompletion = false
			fixture.mutex.Unlock()

			if lose {
				http.Error(response, "lost response", http.StatusInternalServerError)

				return
			}

			writeJSON(t, response, map[string]any{
				"task_id":      operationID + "/source-location",
				"operation_id": operationID, "locations_deleted": 2,
				"task_state": "deleted", "move_state": "succeeded",
			})
		case "/api/v1/moves/deletes/fail":
			fixture.mutex.Lock()
			fixture.failure = true
			fixture.mutex.Unlock()

			incarnation := "0123456789abcdef0123456789abcdef"
			writeJSON(t, response, map[string]any{
				"task_id": operationID + "/source-location", "operation_id": operationID,
				"incarnation": incarnation, "fencing_token": 2, "state": "failed",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(fixture.server.Close)

	control, err := sdk.NewControlClient(fixture.server.URL, token, fixture.server.Client())
	if err != nil {
		t.Fatalf("construct janitor control client: %v", err)
	}

	fixture.janitor, err = sdk.NewMoveJanitor(
		control,
		map[string]provider.Deleter{"source": fixture.deleter},
		60,
	)
	if err != nil {
		t.Fatalf("construct move janitor: %v", err)
	}

	return fixture
}

func moveDeleteTaskJSON(operationID string, fence uint64) map[string]any {
	return map[string]any{
		"task_id": operationID + "/source-location", "operation_id": operationID,
		"driver_id": "source", "storage_key": "source/object",
		"expected_location_count": 2, "owner_client_id": "janitor-client",
		"incarnation":   "0123456789abcdef0123456789abcdef",
		"fencing_token": fence, "lease_expires_at": 100,
		"attempt_count": 1, "state": "claimed",
	}
}

func (fixture *moveJanitorFixture) failureReported() bool {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()

	return fixture.failure
}

type recordingDeleter struct {
	mutex       sync.Mutex
	keys        []string
	err         error
	crashScript *janitorCrashScript
}

func (deleter *recordingDeleter) Delete(_ context.Context, key string) error {
	deleter.mutex.Lock()
	script := deleter.crashScript
	deleter.mutex.Unlock()

	if script != nil {
		if err := script.hit(crashBeforeProviderDelete); err != nil {
			return err
		}
	}

	deleter.mutex.Lock()
	deleter.keys = append(deleter.keys, key)
	deleteErr := deleter.err
	deleter.mutex.Unlock()

	if script == nil {
		return deleteErr
	}

	return errors.Join(deleteErr, script.hit(crashAfterProviderDelete))
}

func (deleter *recordingDeleter) setCrashScript(script *janitorCrashScript) {
	deleter.mutex.Lock()
	defer deleter.mutex.Unlock()

	deleter.crashScript = script
}

func (deleter *recordingDeleter) callCount() int {
	deleter.mutex.Lock()
	defer deleter.mutex.Unlock()

	return len(deleter.keys)
}

func (deleter *recordingDeleter) lastKey() string {
	deleter.mutex.Lock()
	defer deleter.mutex.Unlock()

	if len(deleter.keys) == 0 {
		return ""
	}

	return deleter.keys[len(deleter.keys)-1]
}
