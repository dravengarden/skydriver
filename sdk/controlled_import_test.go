package sdk_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlledImporterPersistsPlanRenewsFenceAndPublishes(t *testing.T) {
	t.Parallel()

	result, claimCount, err := runControlledImport(t, false)
	if err != nil {
		t.Fatalf("controlled import failed: %v", err)
	}

	if result.Publication.State != "published" || result.TelemetryWarning != "" ||
		result.Import.Manifest.PlaintextSize == 0 {
		t.Fatalf("unexpected controlled import result: %+v", result)
	}

	if claimCount < 2 {
		t.Fatalf("import completed without a lease renewal: claims=%d", claimCount)
	}
}

func TestControlledImporterCancelsProviderIOAfterFenceLoss(t *testing.T) {
	t.Parallel()

	_, _, err := runControlledImport(t, true)
	if !errors.Is(err, sdk.ErrImportLeaseLost) {
		t.Fatalf("expected import lease loss, got %v", err)
	}
}

func TestControlledImporterConvergesAfterLostPublicationResponse(t *testing.T) {
	t.Parallel()

	plaintext := []byte("already published import")
	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	destination := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   4,
		LogicalPackBytes:   16,
	}

	importer, err := sdk.NewImporter(source, destination, layout)
	if err != nil {
		t.Fatalf("construct replay importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID: importIdentifier(), ObjectID: "object-1", Generation: 1,
		RootVersion: 1, KeyEpoch: 7, SourceKey: "source",
		DestinationDriverID: "memory-primary", DestinationPrefix: "archive",
	})
	if err != nil {
		t.Fatalf("plan replay import: %v", err)
	}

	planFile := filepath.Join(t.TempDir(), "import-plan.json")
	if writeErr := sdk.WriteImportPlan(planFile, plan); writeErr != nil {
		t.Fatalf("persist replay import plan: %v", writeErr)
	}

	token, encodedToken := testClientToken(t)
	manifestSHA256 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	requests := atomic.Int64{}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)

		if request.Header.Get("Authorization") != "Bearer "+encodedToken ||
			request.URL.Path != "/api/v1/operations" {
			http.Error(response, "unexpected replay request", http.StatusBadRequest)

			return
		}

		writeJSON(t, response, map[string]any{
			"id":           "707172737475767778797a7b7c7d7e7f",
			"namespace_id": controlledImportNamespace(),
			"kind":         "import", "state": "succeeded", "phase": "succeeded",
			"requested_by": "controlled-import-client",
			"incarnation":  "0123456789abcdef0123456789abcdef", "revision": 5,
			"useful_bytes_total": len(plaintext), "root_version": 1, "key_epoch": 7,
			"published_object_id": "object-1", "published_generation": 1,
			"published_manifest_sha256":       manifestSHA256,
			"published_destination_driver_id": "memory-primary",
			"published_sidecar_storage_key":   "archive/manifests/aa/sidecar.json",
			"created_at":                      1, "updated_at": 2,
		})
	}))
	defer server.Close()

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct replay control client: %v", err)
	}

	coordinator, err := sdk.NewControlledImporter(control, importer, 15, time.Second)
	if err != nil {
		t.Fatalf("construct replay coordinator: %v", err)
	}

	total := uint64(len(plaintext))

	result, err := coordinator.Import(context.Background(), sdk.ControlledImportRequest{
		NamespaceID: controlledImportNamespace(), ObjectID: "object-1", Generation: 1,
		SourceKey: "source", DestinationDriverID: "memory-primary",
		DestinationPrefix: "archive", IdempotencyKey: "controlled-import-v1",
		UsefulBytesTotal: &total, ExpectedObjectRevision: 1,
		StagingDirectory: t.TempDir(), PlanFile: planFile,
	})
	if err != nil {
		t.Fatalf("converge completed import: %v", err)
	}

	if !result.AlreadyPublished || result.Publication.ManifestSHA256 != manifestSHA256 ||
		requests.Load() != 1 {
		t.Fatalf("completed import performed extra work: requests=%d result=%+v", requests.Load(), result)
	}
}

func runControlledImport(
	t *testing.T,
	failRenewal bool,
) (sdk.ControlledImportResult, int64, error) {
	t.Helper()

	plaintext := []byte("controlled import payload")
	providerGate := make(chan struct{})
	source := &gatedCopyReader{
		Reader: &mutableMemorySource{data: plaintext, version: "source-v1"},
		gate:   providerGate,
	}
	destination := newMemoryArchive()
	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   4,
		LogicalPackBytes:   16,
	}

	importer, err := sdk.NewImporter(source, destination, layout)
	if err != nil {
		t.Fatalf("construct controlled test importer: %v", err)
	}

	token, encodedToken := testClientToken(t)
	epochKey := importEpochKey(t, importIdentifier())

	const (
		operationID = "606162636465666768696a6b6c6d6e6f"
		incarnation = "0123456789abcdef0123456789abcdef"
		clientID    = "controlled-import-client"
		leaseID     = "operation/606162636465666768696a6b6c6d6e6f/write"
	)

	var (
		claims      atomic.Int64
		releaseGate sync.Once
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/operations":
			writeJSON(t, response, map[string]any{
				"id": operationID, "namespace_id": controlledImportNamespace(),
				"kind": "import", "state": "planned", "phase": "planned",
				"requested_by": clientID, "incarnation": incarnation, "revision": 1,
				"useful_bytes_total": len(plaintext), "root_version": 1, "key_epoch": 7,
				"created_at": 1, "updated_at": 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			claim := claims.Add(1)

			if claim > 1 && failRenewal {
				http.Error(response, "import fence lost", http.StatusConflict)

				return
			}

			if claim > 1 {
				releaseGate.Do(func() { close(providerGate) })
			}

			writeJSON(t, response, map[string]any{
				"operation_id": operationID, "lease_id": leaseID,
				"owner_client_id": clientID, "incarnation": incarnation,
				"fencing_token": 7, "expires_at": 1 << 40, "operation_revision": 2,
				"operation_state": "running",
			})
		case "/api/v1/imports/" + operationID + "/key":
			writeJSON(t, response, map[string]any{
				"operation_id": operationID, "root_version": 1, "key_epoch": 7,
				"epoch_key": base64.RawURLEncoding.EncodeToString(epochKey[:]),
			})
		case "/api/v1/recovery-manifests/stage":
			var recovery manifest.RecoveryManifest
			if decodeErr := json.NewDecoder(request.Body).Decode(&recovery); decodeErr != nil {
				t.Errorf("decode controlled import recovery: %v", decodeErr)

				return
			}

			encoded := mustMarshalRecovery(t, recovery)
			writeJSON(t, response, map[string]any{
				"manifest_sha256": recovery.ManifestSHA256,
				"recovery_sha256": testDigest(encoded),
				"namespace_id":    recovery.Manifest.NamespaceID, "object_id": recovery.Manifest.ObjectID,
				"generation": recovery.Manifest.Generation,
				"r2_key":     "manifests/controlled-import.json", "r2_version": "import-v1",
				"bytes": len(encoded),
			})
		case "/api/v1/operations/" + operationID + "/progress":
			var sample struct {
				Sequence            uint64 `json:"sequence"`
				WireBytesRead       uint64 `json:"wire_bytes_read"`
				WireBytesWritten    uint64 `json:"wire_bytes_written"`
				UsefulBytesVerified uint64 `json:"useful_bytes_verified"`
				ActiveNanoseconds   uint64 `json:"active_nanoseconds"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&sample); decodeErr != nil {
				t.Errorf("decode controlled import progress: %v", decodeErr)

				return
			}

			writeJSON(t, response, map[string]any{
				"component_id": operationID + "/transfer", "attempt": 7,
				"sequence": sample.Sequence, "wire_bytes_read": sample.WireBytesRead,
				"wire_bytes_written":    sample.WireBytesWritten,
				"useful_bytes_verified": sample.UsefulBytesVerified,
				"active_nanoseconds":    sample.ActiveNanoseconds,
				"retry_count":           0, "throttle_count": 0, "observed_at": 2,
				"disposition": "current",
			})
		case "/api/v1/imports/publish":
			var publication struct {
				ManifestSHA256 string `json:"manifest_sha256"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&publication); decodeErr != nil {
				t.Errorf("decode controlled import publication: %v", decodeErr)

				return
			}

			writeJSON(t, response, map[string]any{
				"operation_id": operationID, "object_id": "object-1", "generation": 1,
				"manifest_sha256": publication.ManifestSHA256, "state": "published",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct controlled import client: %v", err)
	}

	coordinator, err := sdk.NewControlledImporter(control, importer, 15, time.Millisecond)
	if err != nil {
		t.Fatalf("construct controlled importer: %v", err)
	}

	total := uint64(len(plaintext))
	planFile := filepath.Join(t.TempDir(), "import-plan.json")

	result, importErr := coordinator.Import(context.Background(), sdk.ControlledImportRequest{
		NamespaceID: controlledImportNamespace(), ObjectID: "object-1", Generation: 1,
		SourceKey: "source", DestinationDriverID: "memory-primary",
		DestinationPrefix: "archive", IdempotencyKey: "controlled-import-v1",
		UsefulBytesTotal: &total, ExpectedObjectRevision: 1,
		StagingDirectory: t.TempDir(), PlanFile: planFile,
	})
	if importErr == nil {
		if _, readErr := sdk.ReadImportPlan(planFile); readErr != nil {
			t.Fatalf("read persisted controlled import plan: %v", readErr)
		}
	}

	return result, claims.Load(), importErr
}

func controlledImportNamespace() string {
	identifier := importIdentifier()

	return hex.EncodeToString(identifier[:])
}
