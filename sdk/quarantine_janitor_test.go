package sdk_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errUnexpectedQuarantineRangeRead = errors.New("unexpected quarantine range read")

func TestQuarantineJanitorStatsRevalidatesDeletesAndCompletes(t *testing.T) {
	t.Parallel()

	fixture := newQuarantineJanitorFixture(t, provider.Object{
		Key: "archive/orphan", SizeBytes: 19, Version: "orphan-v1", ETag: "orphan-etag",
	}, nil)

	result, err := fixture.janitor.Sweep(context.Background(), fixture.operationID)
	if err != nil {
		t.Fatalf("sweep quarantine: %v", err)
	}

	if result.State != "deleted" || result.ObjectsDeleted != 1 || result.AlreadyAbsent != 0 {
		t.Fatalf("unexpected quarantine sweep result: %+v", result)
	}

	if fixture.target.deleteCount() != 1 || fixture.target.lastDeletedKey() != "archive/orphan" {
		t.Fatalf("unexpected quarantine delete: calls=%d key=%q", fixture.target.deleteCount(), fixture.target.lastDeletedKey())
	}

	resumed, err := fixture.janitor.Sweep(context.Background(), fixture.operationID)
	if err != nil || resumed.ObjectsDeleted != 1 || fixture.target.deleteCount() != 1 {
		t.Fatalf("terminal quarantine task repeated delete: result=%+v err=%v calls=%d", resumed, err, fixture.target.deleteCount())
	}
}

func TestQuarantineJanitorCompletesAlreadyAbsentObjectWithoutDelete(t *testing.T) {
	t.Parallel()

	fixture := newQuarantineJanitorFixture(t, provider.Object{}, provider.ErrObjectNotFound)

	result, err := fixture.janitor.Sweep(context.Background(), fixture.operationID)
	if err != nil {
		t.Fatalf("sweep absent quarantine: %v", err)
	}

	if result.State != "deleted" || result.AlreadyAbsent != 1 || fixture.target.deleteCount() != 0 {
		t.Fatalf("absent object was not resolved idempotently: result=%+v deletes=%d", result, fixture.target.deleteCount())
	}
}

func TestQuarantineJanitorRejectsChangedProviderIdentity(t *testing.T) {
	t.Parallel()

	fixture := newQuarantineJanitorFixture(t, provider.Object{
		Key: "archive/orphan", SizeBytes: 20, Version: "orphan-v2", ETag: "changed",
	}, nil)

	_, err := fixture.janitor.Sweep(context.Background(), fixture.operationID)
	if !errors.Is(err, sdk.ErrQuarantineIdentityChanged) || !fixture.failureReported() ||
		fixture.target.deleteCount() != 0 {
		t.Fatalf("changed quarantine identity was not fenced: err=%v failure=%v deletes=%d", err, fixture.failureReported(), fixture.target.deleteCount())
	}
}

type quarantineJanitorFixture struct {
	janitor     *sdk.QuarantineJanitor
	target      *quarantineTestProvider
	operationID string

	mutex     sync.Mutex
	completed bool
	outcome   string
	failure   bool
}

func newQuarantineJanitorFixture(
	t *testing.T,
	object provider.Object,
	statErr error,
) *quarantineJanitorFixture {
	t.Helper()

	const operationID = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"

	fixture := &quarantineJanitorFixture{
		target:      &quarantineTestProvider{object: object, statErr: statErr},
		operationID: operationID,
	}
	token, encodedToken := testClientToken(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/quarantine-actions/" + operationID + "/deletes/claim":
			fixture.mutex.Lock()
			completed := fixture.completed
			outcome := fixture.outcome
			fixture.mutex.Unlock()

			if completed {
				writeJSON(t, response, map[string]any{
					"state": "deleted", "task": nil, "outcome": outcome,
				})

				return
			}

			writeJSON(t, response, map[string]any{
				"state": "claimed", "task": quarantineDeleteTaskJSON(operationID, 1),
			})
		case "/api/v1/quarantine-deletes/revalidate":
			writeJSON(t, response, quarantineDeleteTaskJSON(operationID, 2))
		case "/api/v1/quarantine-deletes/complete":
			var body struct {
				Outcome string `json:"outcome"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode quarantine completion: %v", err)
			}

			fixture.mutex.Lock()
			fixture.completed = true
			fixture.outcome = body.Outcome
			fixture.mutex.Unlock()
			writeJSON(t, response, map[string]any{
				"task_id": operationID + "/quarantine-delete", "operation_id": operationID,
				"quarantine_revision": 5, "task_state": "deleted",
				"quarantine_state": "deleted", "outcome": body.Outcome,
			})
		case "/api/v1/quarantine-deletes/fail":
			var body struct {
				FencingToken uint64 `json:"fencing_token"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode quarantine failure: %v", err)
			}

			fixture.mutex.Lock()
			fixture.failure = true
			fixture.mutex.Unlock()

			incarnation := "0123456789abcdef0123456789abcdef"
			writeJSON(t, response, map[string]any{
				"task_id": operationID + "/quarantine-delete", "operation_id": operationID,
				"incarnation": incarnation, "fencing_token": body.FencingToken,
				"state": "failed",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct quarantine control client: %v", err)
	}

	fixture.janitor, err = sdk.NewQuarantineJanitor(
		control,
		map[string]sdk.QuarantineDeleteProvider{"archive": fixture.target},
		60,
	)
	if err != nil {
		t.Fatalf("construct quarantine janitor: %v", err)
	}

	return fixture
}

func quarantineDeleteTaskJSON(operationID string, fence uint64) map[string]any {
	return map[string]any{
		"task_id": operationID + "/quarantine-delete", "operation_id": operationID,
		"driver_id": "archive", "driver_revision": 3, "storage_key": "archive/orphan",
		"expected_revision": 4, "provider_version": "orphan-v1", "etag": "orphan-etag",
		"size_bytes": 19, "delete_after": 100, "owner_client_id": "janitor-client",
		"incarnation": "0123456789abcdef0123456789abcdef", "fencing_token": fence,
		"lease_expires_at": 200, "attempt_count": 1, "state": "claimed",
	}
}

func (fixture *quarantineJanitorFixture) failureReported() bool {
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()

	return fixture.failure
}

type quarantineTestProvider struct {
	mutex   sync.Mutex
	object  provider.Object
	statErr error
	deleted []string
}

func (target *quarantineTestProvider) Stat(context.Context, string) (provider.Object, error) {
	return target.object, target.statErr
}

func (*quarantineTestProvider) OpenRange(context.Context, string, uint64, uint64) (io.ReadCloser, error) {
	return nil, errUnexpectedQuarantineRangeRead
}

func (target *quarantineTestProvider) Delete(_ context.Context, key string) error {
	target.mutex.Lock()
	defer target.mutex.Unlock()

	target.deleted = append(target.deleted, key)

	return nil
}

func (target *quarantineTestProvider) deleteCount() int {
	target.mutex.Lock()
	defer target.mutex.Unlock()

	return len(target.deleted)
}

func (target *quarantineTestProvider) lastDeletedKey() string {
	target.mutex.Lock()
	defer target.mutex.Unlock()

	if len(target.deleted) == 0 {
		return ""
	}

	return target.deleted[len(target.deleted)-1]
}
