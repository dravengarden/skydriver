package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestReconcileRunCommandCommitsPinnedMetadataReport(t *testing.T) {
	base, _, _ := cliRestoreFixture(t, []byte("ok"))

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{base.Locations[0]})
	if err != nil {
		t.Fatalf("construct reconciliation recovery: %v", err)
	}

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/reconciliations":
			value = sdk.ReconcileOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "reconcile", State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: 1,
				VersionID: "version-1", ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 1, MinimumAvailableReplicas: 2, CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 1,
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
			value = sdk.CompletedReconcile{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", Degraded: 1,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode reconciliation response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv(controlTokenEnvironment, token)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{
		"reconcile", "run", "--control-url", server.URL,
		"--namespace", recovery.Manifest.NamespaceID,
		"--manifest", recovery.ManifestSHA256,
		"--idempotency-key", "cli-reconcile-version-1", "--format", "json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run reconcile command: %v", err)
	}

	var result struct {
		Completion sdk.CompletedReconcile `json:"completion"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode reconciliation output: %v", err)
	}

	if result.Completion.State != "succeeded" || result.Completion.Degraded != 1 {
		t.Fatalf("unexpected reconciliation result: %+v", result)
	}
}
