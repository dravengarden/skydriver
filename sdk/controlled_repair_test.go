package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlledRepairerRebuildsAndCommitsPinnedObject(t *testing.T) {
	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
		targetID    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		sourceID    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	payload := bytes.Repeat([]byte{'c'}, 18)
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])
	recovery := verificationRecovery(t, digestHex, []manifest.Location{
		{DriverID: "target", StorageKey: "objects/target", Length: uint64(len(payload))},
		{DriverID: "source", StorageKey: "objects/source", Length: uint64(len(payload))},
	})
	token, encodedToken := testClientToken(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/repairs":
			value = sdk.RepairOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "copy", State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(payload)),
				VersionID: "version-1", ObjectID: recovery.Manifest.ObjectID,
				Generation: recovery.Manifest.Generation, ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 3, TargetDriverID: "target", ExpectedObjectCount: 1,
				ExpectedTargetCount: 1, CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/repairs/" + operationID + "/snapshot":
			value = sdk.RepairSnapshot{
				Recovery: recovery, RecoveryRevision: 3, TargetDriverID: "target",
				TargetLocationIDs: []string{targetID},
				Locations: []sdk.IndexedLocation{
					{
						ID: targetID, ExtentSHA256: digestHex, DriverID: "target",
						StorageKey: "objects/target", Length: uint64(len(payload)), State: "missing",
					},
					{
						ID: sourceID, ExtentSHA256: digestHex, DriverID: "source",
						StorageKey: "objects/source", Length: uint64(len(payload)), State: "available",
					},
				},
			}
		case "/api/v1/repairs/" + operationID + "/complete":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode repair completion: %v", err)
			}

			objects, ok := body["objects"].([]any)
			if !ok || len(objects) != 1 {
				t.Errorf("unexpected repair completion: %#v", body)
			}

			value = sdk.CompletedRepair{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", ObjectsRepaired: 1, LocationsRepaired: 1,
				CiphertextBytes: uint64(len(payload)), RecoveryRevision: 3,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode controlled repair response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	destinationRoot := t.TempDir()

	destination, err := localfs.NewClient(destinationRoot)
	if err != nil {
		t.Fatalf("open repair destination: %v", err)
	}

	repairer, err := sdk.NewRepairer(
		map[string]provider.Reader{"source": verificationReader{data: payload}},
		map[string]provider.ReadWriter{"target": destination},
		uint64(len(payload)),
		uint64(len(payload)),
	)
	if err != nil {
		t.Fatalf("construct repairer: %v", err)
	}

	coordinator, err := sdk.NewControlledRepairer(control, repairer, 60, time.Second)
	if err != nil {
		t.Fatalf("construct controlled repairer: %v", err)
	}

	result, err := coordinator.Repair(context.Background(), sdk.ControlledRepairRequest{
		NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
		TargetDriverID: "target", IdempotencyKey: "repair-target-v1",
		StagingDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("run controlled repair: %v", err)
	}

	repaired, err := os.ReadFile(filepath.Join(destinationRoot, "objects", "target"))
	if err != nil {
		t.Fatalf("read repaired provider object: %v", err)
	}

	if !bytes.Equal(repaired, payload) || result.Completion.LocationsRepaired != 1 {
		t.Fatalf("unexpected controlled repair: result=%+v bytes=%x", result, repaired)
	}
}
