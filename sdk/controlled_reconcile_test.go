package sdk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlledReconcilerCommitsPinnedMetadataReport(t *testing.T) {
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
				RecoveryRevision: 1, MinimumAvailableReplicas: 2, CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/reconciliations/" + operationID + "/snapshot":
			value = sdk.ReconcileSnapshot{
				Recovery: recovery, RecoveryRevision: 1, MinimumAvailableReplicas: 2,
				Locations: []sdk.IndexedLocation{{
					ID: "location-1", ExtentSHA256: recovery.Locations[0].ExtentSHA256,
					DriverID:   recovery.Locations[0].DriverID,
					StorageKey: recovery.Locations[0].StorageKey,
					Length:     recovery.Locations[0].Length, State: "available",
				}},
			}
		case "/api/v1/reconciliations/" + operationID + "/complete":
			var body struct {
				Evidence []sdk.ReconciliationEvidence `json:"evidence"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode reconcile completion: %v", err)
			}

			if len(body.Evidence) != 1 || body.Evidence[0].Condition != sdk.ReconciliationDegraded {
				t.Errorf("unexpected reconciliation evidence: %+v", body.Evidence)
			}

			value = sdk.CompletedReconcile{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", Degraded: 1,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode controlled reconcile response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	coordinator, err := sdk.NewControlledReconciler(control, 60, time.Second)
	if err != nil {
		t.Fatalf("construct controlled reconciler: %v", err)
	}

	result, err := coordinator.Reconcile(context.Background(), sdk.ControlledReconcileRequest{
		NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
		IdempotencyKey: "reconcile-version-1",
	})
	if err != nil {
		t.Fatalf("run controlled reconcile: %v", err)
	}

	if result.Reconciliation.Degraded != 1 || result.Completion.Degraded != 1 {
		t.Fatalf("unexpected controlled reconciliation: %+v", result)
	}
}
