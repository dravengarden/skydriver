package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestRepairRunCommandRebuildsAndCommitsLocalObject(t *testing.T) {
	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
		targetID    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		sourceID    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	base, _, ciphertext := cliRestoreFixture(t, []byte("ok"))
	extent := base.Locations[0]

	recovery, recoveryErr := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{
		{
			ExtentSHA256: extent.ExtentSHA256, DriverID: "target-local",
			StorageKey: "payload.bin", Length: extent.Length,
		},
		{
			ExtentSHA256: extent.ExtentSHA256, DriverID: "source-local",
			StorageKey: "payload.bin", Length: extent.Length,
		},
	})
	if recoveryErr != nil {
		t.Fatalf("construct CLI repair recovery: %v", recoveryErr)
	}

	sourceRoot := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(sourceRoot, "payload.bin"), ciphertext, 0o600); writeErr != nil {
		t.Fatalf("write CLI repair source: %v", writeErr)
	}

	targetRoot := t.TempDir()
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		switch request.URL.Path {
		case "/api/v1/repairs":
			writeCLIJSON(t, response, sdk.RepairOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "copy", State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(ciphertext)),
				VersionID: "version-1", ObjectID: recovery.Manifest.ObjectID,
				Generation: recovery.Manifest.Generation, ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 4, TargetDriverID: "target-local", ExpectedObjectCount: 1,
				ExpectedTargetCount: 1, CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/repairs/" + operationID + "/snapshot":
			writeCLIJSON(t, response, sdk.RepairSnapshot{
				Recovery: recovery, RecoveryRevision: 4, TargetDriverID: "target-local",
				TargetLocationIDs: []string{targetID},
				Locations: []sdk.IndexedLocation{
					{
						ID: targetID, ExtentSHA256: extent.ExtentSHA256, DriverID: "target-local",
						StorageKey: "payload.bin", Length: extent.Length, State: "missing",
					},
					{
						ID: sourceID, ExtentSHA256: extent.ExtentSHA256, DriverID: "source-local",
						StorageKey: "payload.bin", Length: extent.Length, State: "available",
					},
				},
			})
		case "/api/v1/repairs/" + operationID + "/complete":
			var completion struct {
				Objects []struct {
					StorageKey string `json:"storage_key"`
					SizeBytes  uint64 `json:"size_bytes"`
				} `json:"objects"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&completion); decodeErr != nil {
				t.Errorf("decode CLI repair completion: %v", decodeErr)
			}

			if len(completion.Objects) != 1 || completion.Objects[0].StorageKey != "payload.bin" ||
				completion.Objects[0].SizeBytes != uint64(len(ciphertext)) {
				t.Errorf("unexpected CLI repair completion: %+v", completion)
			}

			writeCLIJSON(t, response, sdk.CompletedRepair{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", ObjectsRepaired: 1, LocationsRepaired: 1,
				CiphertextBytes: uint64(len(ciphertext)), RecoveryRevision: 4,
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)
	t.Setenv(controlTokenEnvironment, token)

	var stdout bytes.Buffer
	if runErr := Run(context.Background(), []string{
		"repair", "run", "--control-url", control.URL,
		"--namespace", recovery.Manifest.NamespaceID,
		"--manifest", recovery.ManifestSHA256,
		"--source-local-driver-id", "source-local", "--source-local-root", sourceRoot,
		"--destination-local-driver-id", "target-local", "--destination-local-root", targetRoot,
		"--idempotency-key", "cli-repair-target-v1", "--staging-directory", t.TempDir(),
		"--format", "json",
	}, &stdout, &bytes.Buffer{}); runErr != nil {
		t.Fatalf("run repair command: %v", runErr)
	}

	var result repairRunResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode repair command output: %v", err)
	}

	repaired, readErr := os.ReadFile(filepath.Join(targetRoot, "payload.bin"))
	if readErr != nil {
		t.Fatalf("read CLI repaired object: %v", readErr)
	}

	if result.State != "succeeded" || result.LocationsRepaired != 1 ||
		!bytes.Equal(repaired, ciphertext) {
		t.Fatalf("unexpected CLI repair result: result=%+v bytes=%x", result, repaired)
	}
}
