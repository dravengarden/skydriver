package sdk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientCreatesAndClaimsPinnedVerification(t *testing.T) {
	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
		manifest    = "1111111111111111111111111111111111111111111111111111111111111111"
	)

	token, encodedToken := testClientToken(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/health":
			_, _ = response.Write([]byte(`{"service":"carrack-control-plane","transfer_mode":"direct","mode":"active","incarnation":"0123456789abcdef0123456789abcdef","revision":1,"external_maintenance":false,"mutations_allowed":true}`))
		case "/api/v1/verifications":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode create body: %v", err)
			}

			if body["driver_id"] != "local-main" || body["manifest_sha256"] != manifest {
				t.Errorf("unexpected create body: %#v", body)
			}

			if err := json.NewEncoder(response).Encode(sdk.VerifyOperation{
				ID: operationID, NamespaceID: "202122232425262728292a2b2c2d2e2f",
				Kind: "verify", State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: 18,
				VersionID: "version-1", ManifestSHA256: manifest, RecoveryRevision: 3,
				DriverID: "local-main", CreatedAt: 1, UpdatedAt: 1,
			}); err != nil {
				t.Errorf("encode operation response: %v", err)
			}
		case "/api/v1/operations/" + operationID + "/claim":
			if err := json.NewEncoder(response).Encode(sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}); err != nil {
				t.Errorf("encode lease response: %v", err)
			}
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	operation, err := client.CreateVerifyOperation(context.Background(), sdk.CreateVerifyOperationRequest{
		NamespaceID: "202122232425262728292a2b2c2d2e2f", ManifestSHA256: manifest,
		DriverID: "local-main", IdempotencyKey: "verify-version-1-local-main",
	})
	if err != nil {
		t.Fatalf("create verify operation: %v", err)
	}

	lease, err := client.ClaimVerifyOperation(context.Background(), operation, 60)
	if err != nil {
		t.Fatalf("claim verify operation: %v", err)
	}

	if lease.FencingToken != 1 || operation.RecoveryRevision != 3 {
		t.Fatalf("unexpected pinned verification: operation=%+v lease=%+v", operation, lease)
	}
}
