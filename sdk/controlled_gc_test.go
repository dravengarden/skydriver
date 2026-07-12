package sdk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlledGarbageCollectorMarksPolicyCandidates(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)

	const (
		namespaceID = "202122232425262728292a2b2c2d2e2f"
		operationID = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
		incarnation = "0123456789abcdef0123456789abcdef"
		leaseID     = "operation/a0a1a2a3a4a5a6a7a8a9aaabacadaeaf/write"
	)

	graceUntil := uint64(1_000)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/gc/epochs":
			assertJSONBody(t, request, map[string]any{
				"namespace_id": namespaceID, "idempotency_key": "gc-retired-generation-1",
			})
			value = sdk.GCOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: "gc", State: "planned",
				Phase: "planned", RequestedBy: "client-1", Incarnation: incarnation,
				Revision: 1, CutoffAt: 100, GraceSeconds: 60, GCState: "marking",
				CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			assertJSONBody(t, request, map[string]any{"lease_seconds": float64(60)})

			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: leaseID, OwnerClientID: "client-1",
				Incarnation: incarnation, FencingToken: 1, ExpiresAt: 200,
				OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/gc/" + operationID + "/mark":
			assertJSONBody(t, request, map[string]any{
				"lease_id": leaseID, "incarnation": incarnation, "fencing_token": float64(1),
			})

			value = sdk.GCMark{
				OperationID: operationID, CandidatesMarked: 3, ObjectsMarked: 2,
				GraceUntil: &graceUntil, State: "grace",
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode GC response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct GC control client: %v", err)
	}

	collector, err := sdk.NewControlledGarbageCollector(control, 60)
	if err != nil {
		t.Fatalf("construct controlled garbage collector: %v", err)
	}

	result, err := collector.Mark(context.Background(), sdk.ControlledGCRequest{
		NamespaceID: namespaceID, IdempotencyKey: "gc-retired-generation-1",
	})
	if err != nil {
		t.Fatalf("mark controlled GC: %v", err)
	}

	if result.Operation.ID != operationID || result.Mark.CandidatesMarked != 3 ||
		result.Mark.ObjectsMarked != 2 || result.Mark.GraceUntil == nil ||
		*result.Mark.GraceUntil != graceUntil {
		t.Fatalf("unexpected controlled GC result: %+v", result)
	}
}
