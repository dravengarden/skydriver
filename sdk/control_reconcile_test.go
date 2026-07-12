package sdk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientPinsReconciliationSnapshot(t *testing.T) {
	recovery := controlRecoveryManifest(t)
	token, encodedToken := testClientToken(t)

	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/reconciliations":
			value = sdk.ReconcileOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "reconcile", State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: 1,
				VersionID: "version-1", ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 3, MinimumAvailableReplicas: 2, CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/reconciliations/" + operationID + "/snapshot":
			value = sdk.ReconcileSnapshot{
				Recovery: recovery, RecoveryRevision: 3, MinimumAvailableReplicas: 2,
				Locations: []sdk.IndexedLocation{{
					ID: "location-1", ExtentSHA256: recovery.Locations[0].ExtentSHA256,
					DriverID:   recovery.Locations[0].DriverID,
					StorageKey: recovery.Locations[0].StorageKey,
					Length:     recovery.Locations[0].Length, State: "available",
				}},
			}
		case "/api/v1/reconciliations/" + operationID + "/complete":
			value = sdk.CompletedReconcile{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", Degraded: 1,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode reconcile response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	operation, err := client.CreateReconcileOperation(context.Background(), sdk.CreateReconcileOperationRequest{
		NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
		IdempotencyKey: "reconcile-version-1",
	})
	if err != nil {
		t.Fatalf("create reconcile operation: %v", err)
	}

	lease, err := client.ClaimReconcileOperation(context.Background(), operation, 60)
	if err != nil {
		t.Fatalf("claim reconcile operation: %v", err)
	}

	snapshot, err := client.FetchReconcileSnapshot(context.Background(), operation, lease)
	if err != nil {
		t.Fatalf("fetch reconcile snapshot: %v", err)
	}

	if snapshot.RecoveryRevision != 3 || len(snapshot.Locations) != 1 {
		t.Fatalf("unexpected reconcile snapshot: %+v", snapshot)
	}

	result, err := (sdk.Reconciler{}).Reconcile(
		snapshot.Recovery,
		snapshot.Locations,
		snapshot.MinimumAvailableReplicas,
	)
	if err != nil {
		t.Fatalf("reconcile snapshot: %v", err)
	}

	completed, err := client.CompleteReconcile(context.Background(), operation, lease, result)
	if err != nil {
		t.Fatalf("complete reconcile operation: %v", err)
	}

	if completed.Degraded != 1 {
		t.Fatalf("unexpected reconcile completion: %+v", completed)
	}
}
