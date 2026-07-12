package sdk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlledQuarantineCommitsExactTombstoneRevision(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)

	const (
		operationID = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		incarnation = "0123456789abcdef0123456789abcdef"
		namespaceID = "202122232425262728292a2b2c2d2e2f"
	)

	deleteAfter := uint64(1_234)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/quarantine-actions":
			var body struct {
				Action           sdk.QuarantineAction `json:"action"`
				ExpectedRevision uint64               `json:"expected_revision"`
				Reason           string               `json:"reason"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode quarantine operation: %v", err)
			}

			if body.Action != sdk.QuarantineActionTombstone || body.ExpectedRevision != 4 ||
				body.Reason != "reviewed orphan has no recovery ownership" {
				t.Errorf("unexpected quarantine operation request: %+v", body)
			}

			value = sdk.QuarantineActionOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: "gc", State: "planned",
				Phase: "planned", RequestedBy: "client-1", Incarnation: incarnation,
				Revision: 1, Action: sdk.QuarantineActionTombstone, DriverID: "local-main",
				DriverRevision: 2, StorageKey: "archive/objects/orphan", ExpectedRevision: 4,
				ProviderVersion: "orphan-v1", ETag: "orphan-etag", SizeBytes: 13,
				Reason: "reviewed orphan has no recovery ownership", GraceSeconds: 90,
				CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 3,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/quarantine-actions/" + operationID + "/complete":
			var body struct {
				FencingToken uint64 `json:"fencing_token"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode quarantine completion: %v", err)
			}

			if body.FencingToken != 3 {
				t.Errorf("unexpected quarantine fence: %+v", body)
			}

			value = sdk.CompletedQuarantineAction{
				OperationID: operationID, Action: sdk.QuarantineActionTombstone,
				State: "succeeded", QuarantineState: "tombstoned",
				QuarantineRevision: 5, DeleteAfter: &deleteAfter,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode quarantine response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	reviewer, err := sdk.NewControlledQuarantineReviewer(control, 60)
	if err != nil {
		t.Fatalf("construct quarantine reviewer: %v", err)
	}

	result, err := reviewer.Act(context.Background(), sdk.ControlledQuarantineRequest{
		NamespaceID: namespaceID, Action: sdk.QuarantineActionTombstone,
		DriverID: "local-main", StorageKey: "archive/objects/orphan", ExpectedRevision: 4,
		Reason: "reviewed orphan has no recovery ownership", IdempotencyKey: "tombstone-orphan-v4",
	})
	if err != nil {
		t.Fatalf("run controlled quarantine action: %v", err)
	}

	if result.Completion.QuarantineState != "tombstoned" ||
		result.Completion.QuarantineRevision != 5 || result.Completion.DeleteAfter == nil {
		t.Fatalf("unexpected quarantine action result: %+v", result)
	}
}
