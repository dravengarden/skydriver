package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientPublishesCopyUnderPinnedRecoveryFence(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)
	source := controlRecoveryManifest(t)
	destinationLocation := manifest.Location{
		ExtentSHA256:    source.Manifest.Packs[0].Extents[0].CiphertextSHA256,
		DriverID:        "local-mirror",
		StorageKey:      "copies/object",
		ProviderVersion: "destination-v1",
		Offset:          0,
		Length:          18,
	}

	updated, err := manifest.NewRecoveryManifest(
		source.Manifest,
		append(append([]manifest.Location{}, source.Locations...), destinationLocation),
	)
	if err != nil {
		t.Fatalf("construct copied recovery: %v", err)
	}

	sourceEncoded := mustMarshalRecovery(t, source)
	updatedEncoded := mustMarshalRecovery(t, updated)
	sourceRecoverySHA256 := testDigest(sourceEncoded)
	updatedRecoverySHA256 := testDigest(updatedEncoded)

	const (
		operationID = "303132333435363738393a3b3c3d3e3f"
		incarnation = "0123456789abcdef0123456789abcdef"
		clientID    = "client-1"
		leaseID     = "operation/303132333435363738393a3b3c3d3e3f/write"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken ||
			request.Header.Get("Content-Type") != "application/json" {
			http.Error(response, "invalid request metadata", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/copies":
			assertJSONBody(t, request, map[string]any{
				"namespace_id":          source.Manifest.NamespaceID,
				"manifest_sha256":       source.ManifestSHA256,
				"destination_driver_id": "local-mirror",
				"idempotency_key":       "copy-local-v1",
			})

			_, _ = response.Write([]byte(`{"id":"` + operationID +
				`","namespace_id":"` + source.Manifest.NamespaceID +
				`","kind":"copy","state":"planned","phase":"planned",` +
				`"requested_by":"` + clientID + `","incarnation":"` + incarnation +
				`","revision":1,"useful_bytes_total":18,"version_id":"version-1",` +
				`"object_id":"` + source.Manifest.ObjectID + `","generation":1,` +
				`"manifest_sha256":"` + source.ManifestSHA256 +
				`","source_recovery_sha256":"` + sourceRecoverySHA256 +
				`","source_recovery_revision":3,"destination_driver_id":"local-mirror",` +
				`"created_at":1,"updated_at":1}`))
		case "/api/v1/operations/" + operationID + "/claim":
			assertJSONBody(t, request, map[string]any{"lease_seconds": float64(60)})

			_, _ = response.Write([]byte(`{"operation_id":"` + operationID +
				`","lease_id":"` + leaseID + `","owner_client_id":"` + clientID +
				`","incarnation":"` + incarnation +
				`","fencing_token":7,"expires_at":100,"operation_revision":2,` +
				`"operation_state":"running"}`))
		case "/api/v1/copies/" + operationID + "/manifest":
			assertJSONBody(t, request, map[string]any{
				"lease_id":      leaseID,
				"incarnation":   incarnation,
				"fencing_token": float64(7),
			})

			_, _ = response.Write(sourceEncoded)
		case "/api/v1/operations/" + operationID + "/progress":
			assertJSONBody(t, request, map[string]any{
				"lease_id":              leaseID,
				"incarnation":           incarnation,
				"fencing_token":         float64(7),
				"attempt":               float64(7),
				"sequence":              float64(1),
				"wire_bytes_read":       float64(18),
				"wire_bytes_written":    float64(18),
				"useful_bytes_verified": float64(18),
				"active_nanoseconds":    float64(1_000),
				"retry_count":           float64(0),
				"throttle_count":        float64(0),
			})

			_, _ = response.Write([]byte(`{"component_id":"` + operationID +
				`/copy","attempt":7,"sequence":1,"wire_bytes_read":18,` +
				`"wire_bytes_written":18,"useful_bytes_verified":18,` +
				`"active_nanoseconds":1000,"retry_count":0,"throttle_count":0,` +
				`"observed_at":2,"disposition":"current"}`))
		case "/api/v1/recovery-manifests/stage":
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Errorf("read staged recovery: %v", readErr)
			}

			if !bytes.Equal(body, updatedEncoded) {
				t.Error("staged recovery bytes changed")
			}

			_, _ = response.Write([]byte(`{"manifest_sha256":"` + source.ManifestSHA256 +
				`","recovery_sha256":"` + updatedRecoverySHA256 +
				`","namespace_id":"` + source.Manifest.NamespaceID + `","object_id":"` +
				source.Manifest.ObjectID + `","generation":1,"r2_key":"manifests/copied.json",` +
				`"r2_version":"r2-copy-v1","bytes":` + strconv.Itoa(len(updatedEncoded)) + `}`))
		case "/api/v1/copies/publish":
			assertJSONBody(t, request, map[string]any{
				"operation_id":        operationID,
				"lease_id":            leaseID,
				"incarnation":         incarnation,
				"fencing_token":       float64(7),
				"manifest_sha256":     source.ManifestSHA256,
				"recovery_sha256":     updatedRecoverySHA256,
				"r2_key":              "manifests/copied.json",
				"r2_version":          "r2-copy-v1",
				"sidecar_driver_id":   "local-mirror",
				"sidecar_storage_key": "copies/recovery.json",
			})

			_, _ = response.Write([]byte(`{"operation_id":"` + operationID +
				`","manifest_sha256":"` + source.ManifestSHA256 +
				`","recovery_sha256":"` + updatedRecoverySHA256 +
				`","destination_driver_id":"local-mirror","locations_added":1,` +
				`"recovery_revision":4,"state":"published"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	operation, err := client.CreateCopyOperation(context.Background(), sdk.CreateCopyOperationRequest{
		NamespaceID: source.Manifest.NamespaceID, ManifestSHA256: source.ManifestSHA256,
		DestinationDriverID: "local-mirror", IdempotencyKey: "copy-local-v1",
	})
	if err != nil {
		t.Fatalf("create copy operation: %v", err)
	}

	lease, err := client.ClaimCopyOperation(context.Background(), operation, 60)
	if err != nil {
		t.Fatalf("claim copy operation: %v", err)
	}

	fetched, err := client.FetchCopyManifest(context.Background(), operation, lease)
	if err != nil {
		t.Fatalf("fetch copy manifest: %v", err)
	}

	if testDigest(mustMarshalRecovery(t, fetched)) != sourceRecoverySHA256 {
		t.Fatal("fetched copy recovery changed")
	}

	if _, progressErr := client.ReportCopyProgress(context.Background(), operation, lease, sdk.ProgressSample{
		Sequence: 1, WireBytesRead: 18, WireBytesWritten: 18,
		UsefulBytesVerified: 18, ActiveNanoseconds: 1_000,
	}); progressErr != nil {
		t.Fatalf("report copy progress: %v", progressErr)
	}

	staged, err := client.StageRecovery(context.Background(), updated)
	if err != nil {
		t.Fatalf("stage copied recovery: %v", err)
	}

	published, err := client.PublishCopy(context.Background(), sdk.PublishCopyRequest{
		Operation: operation, Lease: lease, StagedRecovery: staged,
		Result: sdk.ReplicationResult{
			Recovery: updated, Locations: []manifest.Location{destinationLocation},
			RecoveryKey:    "copies/recovery.json",
			RecoveryObject: provider.Object{Key: "copies/recovery.json"},
		},
	})
	if err != nil {
		t.Fatalf("publish copy: %v", err)
	}

	if published.RecoveryRevision != 4 || published.LocationsAdded != 1 {
		t.Fatalf("unexpected published copy: %+v", published)
	}
}

func TestControlClientRejectsMismatchedCopyPublicationBeforeNetwork(t *testing.T) {
	t.Parallel()

	token, _ := testClientToken(t)

	var requests int

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	_, err = client.PublishCopy(context.Background(), sdk.PublishCopyRequest{})
	if !errors.Is(err, sdk.ErrInvalidControlPlane) {
		t.Fatalf("expected local copy publication rejection, got %v", err)
	}

	if requests != 0 {
		t.Fatalf("invalid copy publication made %d network requests", requests)
	}
}

func mustMarshalRecovery(t *testing.T, recovery manifest.RecoveryManifest) []byte {
	t.Helper()

	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal recovery: %v", err)
	}

	return encoded
}

func testDigest(data []byte) string {
	digest := sha256.Sum256(data)

	return hex.EncodeToString(digest[:])
}
