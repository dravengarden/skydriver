package sdk_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientPinsExactRepairTargets(t *testing.T) {
	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
		targetID    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		sourceID    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	base := controlRecoveryManifest(t)
	extent := base.Locations[0]

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{
		{
			ExtentSHA256: extent.ExtentSHA256, DriverID: "target",
			StorageKey: "target/object", Length: extent.Length,
		},
		{
			ExtentSHA256: extent.ExtentSHA256, DriverID: "source",
			StorageKey: "source/object", Length: extent.Length,
		},
	})
	if err != nil {
		t.Fatalf("construct repair recovery: %v", err)
	}

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
			var body map[string]any
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode repair create body: %v", decodeErr)
			}

			if body["target_driver_id"] != "target" || body["manifest_sha256"] != recovery.ManifestSHA256 {
				t.Errorf("unexpected repair create body: %#v", body)
			}

			value = sdk.RepairOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "copy", State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: extent.Length,
				VersionID: "version-1", ObjectID: recovery.Manifest.ObjectID,
				Generation: recovery.Manifest.Generation, ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 3, TargetDriverID: "target", ExpectedObjectCount: 1,
				ExpectedTargetCount: 1,
				CreatedAt:           1, UpdatedAt: 1,
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
						ID: targetID, ExtentSHA256: extent.ExtentSHA256, DriverID: "target",
						StorageKey: "target/object", Length: extent.Length, State: "missing",
					},
					{
						ID: sourceID, ExtentSHA256: extent.ExtentSHA256, DriverID: "source",
						StorageKey: "source/object", Length: extent.Length, State: "available",
					},
				},
			}
		case "/api/v1/repairs/" + operationID + "/complete":
			value = sdk.CompletedRepair{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", ObjectsRepaired: 1, LocationsRepaired: 1,
				CiphertextBytes: extent.Length, RecoveryRevision: 3,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if encodeErr := json.NewEncoder(response).Encode(value); encodeErr != nil {
			t.Errorf("encode repair response: %v", encodeErr)
		}
	}))
	t.Cleanup(server.Close)

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	operation, err := client.CreateRepairOperation(context.Background(), sdk.CreateRepairOperationRequest{
		NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
		TargetDriverID: "target", IdempotencyKey: "repair-target-version-1",
	})
	if err != nil {
		t.Fatalf("create repair operation: %v", err)
	}

	lease, err := client.ClaimRepairOperation(context.Background(), operation, 60)
	if err != nil {
		t.Fatalf("claim repair operation: %v", err)
	}

	snapshot, err := client.FetchRepairSnapshot(context.Background(), operation, lease)
	if err != nil {
		t.Fatalf("fetch repair snapshot: %v", err)
	}

	plan, err := (sdk.RepairPlanner{}).PlanMissing(
		snapshot.Recovery,
		snapshot.Locations,
		snapshot.TargetLocationIDs,
	)
	if err != nil {
		t.Fatalf("plan controlled repair: %v", err)
	}

	if len(plan.Objects) != 1 || !strings.HasSuffix(plan.Objects[0].StorageKey, "/object") {
		t.Fatalf("unexpected controlled repair plan: %+v", plan)
	}

	result := sdk.RepairResult{
		ManifestSHA256: recovery.ManifestSHA256,
		ProviderObjects: []provider.Object{{
			Key: "target/object", SizeBytes: extent.Length,
			ETag: "repaired-etag", Version: "repaired-version",
		}},
		ObjectsRepaired: 1, ExtentsRepaired: 1, CiphertextBytes: extent.Length,
	}

	completed, err := client.CompleteRepair(context.Background(), operation, lease, plan, result)
	if err != nil {
		t.Fatalf("complete repair operation: %v", err)
	}

	if completed.RecoveryRevision != operation.RecoveryRevision || completed.LocationsRepaired != 1 {
		t.Fatalf("unexpected repair completion: %+v", completed)
	}
}
