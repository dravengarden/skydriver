package sdk_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientPinsRestoreAndClaimsReadLease(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)
	recovery := controlRecoveryManifest(t)
	manifestID := recovery.ManifestSHA256

	const (
		namespaceID = "202122232425262728292a2b2c2d2e2f"
		operationID = "303132333435363738393a3b3c3d3e3f"
		incarnation = "404142434445464748494a4b4c4d4e4f"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/restores":
			assertJSONBody(t, request, map[string]any{
				"namespace_id": namespaceID, "manifest_sha256": manifestID, "idempotency_key": "restore-local-1",
			})
			_, _ = response.Write([]byte(`{"id":"` + operationID + `","namespace_id":"` + namespaceID +
				`","kind":"restore","state":"planned","phase":"planned","requested_by":"client-1",` +
				`"incarnation":"` + incarnation + `","revision":1,"useful_bytes_total":2,` +
				`"version_id":"version-1","object_id":"object-1","generation":1,"manifest_sha256":"` +
				manifestID + `","created_at":1,"updated_at":1}`))
		case "/api/v1/restores/" + operationID + "/claim":
			assertJSONBody(t, request, map[string]any{"lease_seconds": float64(60)})

			_, _ = response.Write([]byte(`{"operation_id":"` + operationID +
				`","lease_id":"operation/` + operationID + `/read","owner_client_id":"client-1",` +
				`"incarnation":"` + incarnation + `","fencing_token":1,"expires_at":100,` +
				`"operation_revision":2,"operation_state":"running","version_id":"version-1",` +
				`"manifest_sha256":"` + manifestID + `"}`))
		case "/api/v1/restores/" + operationID + "/manifest":
			assertJSONBody(t, request, map[string]any{
				"lease_id":      "operation/" + operationID + "/read",
				"incarnation":   incarnation,
				"fencing_token": float64(1),
			})

			encoded, err := recovery.MarshalCanonical()
			if err != nil {
				t.Errorf("marshal recovery response: %v", err)

				return
			}

			_, _ = response.Write(encoded)
		case "/api/v1/restores/" + operationID + "/complete":
			assertJSONBody(t, request, map[string]any{
				"lease_id":         "operation/" + operationID + "/read",
				"incarnation":      incarnation,
				"fencing_token":    float64(1),
				"manifest_sha256":  manifestID,
				"plaintext_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"plaintext_bytes":  float64(2),
			})

			_, _ = response.Write([]byte(`{"operation_id":"` + operationID +
				`","manifest_sha256":"` + manifestID + `","state":"succeeded"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	operation, err := client.CreateRestoreOperation(context.Background(), sdk.CreateRestoreOperationRequest{
		NamespaceID: namespaceID, ManifestSHA256: manifestID, IdempotencyKey: "restore-local-1",
	})
	if err != nil {
		t.Fatalf("create restore operation: %v", err)
	}

	lease, err := client.ClaimRestoreOperation(context.Background(), operation, 60)
	if err != nil {
		t.Fatalf("claim restore operation: %v", err)
	}

	if lease.VersionID != operation.VersionID || lease.ManifestSHA256 != operation.ManifestSHA256 {
		t.Fatalf("restore pin changed across lease: operation=%+v lease=%+v", operation, lease)
	}

	fetched, err := client.FetchRestoreManifest(context.Background(), operation, lease)
	if err != nil {
		t.Fatalf("fetch restore manifest: %v", err)
	}

	if fetched.ManifestSHA256 != operation.ManifestSHA256 {
		t.Fatalf("fetched restore manifest changed: %+v", fetched)
	}

	completed, err := client.CompleteRestoreOperation(
		context.Background(),
		operation,
		lease,
		sdk.RestoreResult{ManifestSHA256: manifestID, PlaintextBytes: 2},
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	)
	if err != nil {
		t.Fatalf("complete restore operation: %v", err)
	}

	if completed.State != "succeeded" {
		t.Fatalf("unexpected restore completion: %+v", completed)
	}
}
