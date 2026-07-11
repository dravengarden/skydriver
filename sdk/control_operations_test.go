package sdk_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientPublishesImportUnderExactFence(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)
	recovery := controlRecoveryManifest(t)
	manifestSHA256 := recovery.ManifestSHA256

	const (
		operationID    = "303132333435363738393a3b3c3d3e3f"
		incarnation    = "0123456789abcdef0123456789abcdef"
		clientID       = "client-1"
		leaseID        = "operation/303132333435363738393a3b3c3d3e3f/write"
		recoverySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken ||
			request.Header.Get("Content-Type") != "application/json" {
			http.Error(response, "invalid request metadata", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/operations":
			assertJSONBody(t, request, map[string]any{
				"namespace_id":       recovery.Manifest.NamespaceID,
				"idempotency_key":    "source-version-1",
				"useful_bytes_total": float64(2),
			})

			_, _ = response.Write([]byte(`{"id":"` + operationID +
				`","namespace_id":"` + recovery.Manifest.NamespaceID +
				`","kind":"import","state":"planned","phase":"planned",` +
				`"requested_by":"` + clientID + `","incarnation":"` + incarnation +
				`","revision":1,"useful_bytes_total":2,"created_at":1,"updated_at":1}`))
		case "/api/v1/operations/" + operationID + "/claim":
			assertJSONBody(t, request, map[string]any{"lease_seconds": float64(60)})

			_, _ = response.Write([]byte(`{"operation_id":"` + operationID +
				`","lease_id":"` + leaseID + `","owner_client_id":"` + clientID +
				`","incarnation":"` + incarnation +
				`","fencing_token":7,"expires_at":100,"operation_revision":2,` +
				`"operation_state":"running"}`))
		case "/api/v1/imports/publish":
			assertJSONBody(t, request, map[string]any{
				"operation_id":             operationID,
				"lease_id":                 leaseID,
				"incarnation":              incarnation,
				"fencing_token":            float64(7),
				"manifest_sha256":          manifestSHA256,
				"recovery_sha256":          recoverySHA256,
				"r2_key":                   "manifests/test.json",
				"r2_version":               "r2-version-1",
				"sidecar_driver_id":        "aliyun-main",
				"sidecar_storage_key":      "recovery/test.json",
				"expected_object_revision": float64(1),
			})

			_, _ = response.Write([]byte(`{"operation_id":"` + operationID +
				`","object_id":"` + recovery.Manifest.ObjectID +
				`","generation":1,"manifest_sha256":"` + manifestSHA256 +
				`","state":"published"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	total := uint64(2)

	operation, err := client.CreateImportOperation(context.Background(), sdk.CreateImportOperationRequest{
		NamespaceID:      recovery.Manifest.NamespaceID,
		IdempotencyKey:   "source-version-1",
		UsefulBytesTotal: &total,
	})
	if err != nil {
		t.Fatalf("create import operation: %v", err)
	}

	lease, err := client.ClaimImportOperation(context.Background(), operation, 60)
	if err != nil {
		t.Fatalf("claim import operation: %v", err)
	}

	published, err := client.PublishImport(context.Background(), sdk.PublishImportRequest{
		Operation: operation,
		Lease:     lease,
		StagedRecovery: sdk.StagedRecovery{
			ManifestSHA256: manifestSHA256,
			RecoverySHA256: recoverySHA256,
			NamespaceID:    recovery.Manifest.NamespaceID,
			ObjectID:       recovery.Manifest.ObjectID,
			Generation:     recovery.Manifest.Generation,
			R2Key:          "manifests/test.json",
			R2Version:      "r2-version-1",
		},
		Result: sdk.ImportResult{
			Manifest:            recovery.Manifest,
			Recovery:            recovery,
			DestinationDriverID: "aliyun-main",
			RecoveryKey:         "recovery/test.json",
			RecoveryObject:      provider.Object{Key: "recovery/test.json"},
		},
		ExpectedObjectRevision: 1,
	})
	if err != nil {
		t.Fatalf("publish import: %v", err)
	}

	if published.State != "published" || published.ManifestSHA256 != manifestSHA256 {
		t.Fatalf("unexpected publication: %+v", published)
	}
}

func TestControlClientRejectsMismatchedPublicationBeforeNetwork(t *testing.T) {
	token, _ := testClientToken(t)
	requests := 0

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	_, err = client.PublishImport(context.Background(), sdk.PublishImportRequest{})
	if !errors.Is(err, sdk.ErrInvalidControlPlane) {
		t.Fatalf("expected local publication rejection, got %v", err)
	}

	if requests != 0 {
		t.Fatalf("invalid publication made %d network requests", requests)
	}
}

func assertJSONBody(t *testing.T, request *http.Request, expected map[string]any) {
	t.Helper()

	var actual map[string]any
	if err := json.NewDecoder(request.Body).Decode(&actual); err != nil {
		t.Errorf("decode request body: %v", err)

		return
	}

	if len(actual) != len(expected) {
		t.Errorf("request fields differ: got %+v, expected %+v", actual, expected)
	}

	for key, expectedValue := range expected {
		if actual[key] != expectedValue {
			t.Errorf("request field %q: got %#v, expected %#v", key, actual[key], expectedValue)
		}
	}
}
