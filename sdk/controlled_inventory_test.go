package sdk_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errUnexpectedInventoryRequest = errors.New("unexpected inventory request")

type twoPageInventory struct {
	mutex sync.Mutex
	calls int
}

func (inventory *twoPageInventory) List(
	_ context.Context,
	prefix,
	cursor string,
) (provider.InventoryPage, error) {
	inventory.mutex.Lock()
	defer inventory.mutex.Unlock()

	inventory.calls++

	if prefix != "archive" {
		return provider.InventoryPage{}, fmt.Errorf("%w: prefix %q", errUnexpectedInventoryRequest, prefix)
	}

	switch inventory.calls {
	case 1:
		if cursor != "" {
			return provider.InventoryPage{}, fmt.Errorf("%w: first cursor %q", errUnexpectedInventoryRequest, cursor)
		}

		return provider.InventoryPage{
			Objects: []provider.Object{{
				Key: "archive/objects/known", SizeBytes: 11, ETag: "known-etag", Version: "known-v1",
			}},
			NextCursor: "archive/objects/known",
		}, nil
	case 2:
		if cursor != "archive/objects/known" {
			return provider.InventoryPage{}, fmt.Errorf("%w: second cursor %q", errUnexpectedInventoryRequest, cursor)
		}

		return provider.InventoryPage{Objects: []provider.Object{{
			Key: "archive/objects/unknown", SizeBytes: 13, ETag: "unknown-etag",
		}}}, nil
	default:
		return provider.InventoryPage{}, fmt.Errorf("%w: call %d", errUnexpectedInventoryRequest, inventory.calls)
	}
}

func TestControlledInventoryReportsEveryPageBeforeCompletion(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)

	const (
		operationID = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
		incarnation = "0123456789abcdef0123456789abcdef"
		namespaceID = "202122232425262728292a2b2c2d2e2f"
	)

	pageHashes := []string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	reportDigest := sha256.Sum256([]byte(pageHashes[0] + pageHashes[1]))
	reportSHA256 := hex.EncodeToString(reportDigest[:])

	var pageCalls int

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/inventory-reconciliations":
			value = sdk.InventoryOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: "reconcile",
				State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, DriverID: "local-main",
				DriverRevision: 3, Prefix: "archive", QuarantineGraceSeconds: 86_400,
				CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/inventory-reconciliations/" + operationID + "/pages":
			var body struct {
				Sequence   uint64 `json:"sequence"`
				Cursor     string `json:"cursor"`
				NextCursor string `json:"next_cursor"`
				Objects    []struct {
					StorageKey string `json:"storage_key"`
				} `json:"objects"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode inventory page: %v", err)
			}

			pageCalls++
			if body.Sequence != uint64(pageCalls) || len(body.Objects) != 1 {
				t.Errorf("unexpected inventory page %d: %+v", pageCalls, body)
			}

			if pageCalls == 1 && (body.Cursor != "" || body.NextCursor != "archive/objects/known") {
				t.Errorf("unexpected first inventory cursor chain: %+v", body)
			}

			if pageCalls == 2 && (body.Cursor != "archive/objects/known" || body.NextCursor != "") {
				t.Errorf("unexpected final inventory cursor chain: %+v", body)
			}

			value = sdk.InventoryPageReceipt{
				OperationID: operationID, Sequence: body.Sequence,
				ReportSHA256: pageHashes[pageCalls-1], ObjectCount: 1,
				NextCursor: body.NextCursor,
			}
		case "/api/v1/inventory-reconciliations/" + operationID + "/complete":
			var body struct {
				LastSequence uint64 `json:"last_sequence"`
				ReportSHA256 string `json:"report_sha256"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode inventory completion: %v", err)
			}

			if body.LastSequence != 2 || body.ReportSHA256 != reportSHA256 || pageCalls != 2 {
				t.Errorf("unexpected inventory completion: pages=%d body=%+v", pageCalls, body)
			}

			value = sdk.CompletedInventory{
				OperationID: operationID, State: "succeeded", ReportSHA256: reportSHA256,
				Pages: 2, Objects: 2, Known: 1, Quarantined: 1, Missing: 2,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode controlled inventory response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	coordinator, err := sdk.NewControlledInventoryReconciler(
		control,
		&twoPageInventory{},
		60,
		30*time.Second,
	)
	if err != nil {
		t.Fatalf("construct controlled inventory: %v", err)
	}

	result, err := coordinator.Reconcile(context.Background(), sdk.ControlledInventoryRequest{
		NamespaceID: namespaceID, DriverID: "local-main", Prefix: "archive",
		IdempotencyKey: "inventory-local-main-archive",
	})
	if err != nil {
		t.Fatalf("run controlled inventory: %v", err)
	}

	if result.Completion.Known != 1 || result.Completion.Quarantined != 1 ||
		result.Completion.Missing != 2 || pageCalls != 2 {
		t.Fatalf("unexpected controlled inventory result: %+v", result)
	}
}
