package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestReconcileInventoryCommandReportsLocalObjects(t *testing.T) {
	rootPath := t.TempDir()

	objectPath := filepath.Join(rootPath, "archive", "objects", "unknown")
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		t.Fatalf("create inventory fixture directory: %v", err)
	}

	if err := os.WriteFile(objectPath, []byte("unknown provider object"), 0o600); err != nil {
		t.Fatalf("write inventory fixture: %v", err)
	}

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))

	const (
		operationID = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
		incarnation = "0123456789abcdef0123456789abcdef"
		namespaceID = "202122232425262728292a2b2c2d2e2f"
		pageHash    = "1111111111111111111111111111111111111111111111111111111111111111"
	)

	reportDigest := sha256.Sum256([]byte(pageHash))
	reportHash := hex.EncodeToString(reportDigest[:])
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/inventory-reconciliations":
			value = sdk.InventoryOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: "reconcile",
				State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, DriverID: "local-main",
				DriverRevision: 1, Prefix: "archive", QuarantineGraceSeconds: 86_400,
				CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/inventory-reconciliations/" + operationID + "/pages":
			var body struct {
				Sequence uint64 `json:"sequence"`
				Objects  []struct {
					StorageKey string `json:"storage_key"`
				} `json:"objects"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode CLI inventory page: %v", err)
			}

			if body.Sequence != 1 || len(body.Objects) != 1 ||
				body.Objects[0].StorageKey != "archive/objects/unknown" {
				t.Errorf("unexpected CLI inventory page: %+v", body)
			}

			value = sdk.InventoryPageReceipt{
				OperationID: operationID, Sequence: 1, ReportSHA256: pageHash, ObjectCount: 1,
			}
		case "/api/v1/inventory-reconciliations/" + operationID + "/complete":
			var body struct {
				ReportSHA256 string `json:"report_sha256"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode CLI inventory completion: %v", err)
			}

			if body.ReportSHA256 != reportHash {
				t.Errorf("unexpected CLI inventory report hash: %q", body.ReportSHA256)
			}

			value = sdk.CompletedInventory{
				OperationID: operationID, State: "succeeded", ReportSHA256: reportHash,
				Pages: 1, Objects: 1, Quarantined: 1,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode CLI inventory response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv(controlTokenEnvironment, token)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{
		"reconcile", "inventory", "--control-url", server.URL,
		"--namespace", namespaceID, "--local-driver-id", "local-main",
		"--local-root", rootPath, "--prefix", "archive",
		"--idempotency-key", "cli-inventory-local-main-archive", "--format", "json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run inventory reconcile command: %v", err)
	}

	if !strings.Contains(stdout.String(), `"quarantined": 1`) {
		t.Fatalf("unexpected inventory reconciliation output: %s", stdout.String())
	}
}
