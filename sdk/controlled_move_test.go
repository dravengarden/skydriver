package sdk_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlledMoverPublishesThenTombstonesSource(t *testing.T) {
	t.Parallel()

	result, claimCount, err := runControlledMove(t, false)
	if err != nil {
		t.Fatalf("controlled move failed: %v", err)
	}

	if result.DestinationPublication.State != "destination_published" ||
		result.SourceTombstone.State != "source_delete_pending" ||
		result.Replication.CiphertextBytes == 0 {
		t.Fatalf("unexpected controlled move result: %+v", result)
	}

	for _, location := range result.FinalSidecar.Recovery.Locations {
		if location.DriverID == result.Operation.SourceDriverID {
			t.Fatalf("final recovery retained source location: %+v", location)
		}
	}

	if claimCount < 2 {
		t.Fatalf("move completed without a lease renewal: claims=%d", claimCount)
	}
}

func TestControlledMoverCancelsProviderIOAfterFenceLoss(t *testing.T) {
	t.Parallel()

	_, _, err := runControlledMove(t, true)
	if !errors.Is(err, sdk.ErrMoveLeaseLost) {
		t.Fatalf("expected move lease loss, got %v", err)
	}
}

func runControlledMove(
	t *testing.T,
	failRenewal bool,
) (sdk.ControlledMoveResult, int64, error) {
	t.Helper()

	fixture := newReplicationFixture(t)
	destination := newMemoryArchive()
	providerGate := make(chan struct{})
	gatedSource := &gatedCopyReader{Reader: fixture.source, gate: providerGate}
	replicator := newTestReplicator(
		t,
		map[string]provider.Reader{"source": gatedSource},
		destination,
		24,
		1<<20,
	)

	token, encodedToken := testClientToken(t)
	sourceEncoded := mustMarshalRecovery(t, fixture.recovery)
	sourceRecoverySHA256 := testDigest(sourceEncoded)
	extentCount, ciphertextBytes := replicationManifestTotals(fixture.recovery.Manifest)
	sourceLocationCount := uint64(0)

	for _, location := range fixture.recovery.Locations {
		if location.DriverID == "source" {
			sourceLocationCount++
		}
	}

	const (
		operationID = "505152535455565758595a5b5c5d5e5f"
		incarnation = "0123456789abcdef0123456789abcdef"
		clientID    = "controlled-move-client"
		leaseID     = "operation/505152535455565758595a5b5c5d5e5f/write"
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
		case "/api/v1/moves":
			writeJSON(t, response, map[string]any{
				"id": operationID, "namespace_id": fixture.recovery.Manifest.NamespaceID,
				"kind": "move", "state": "planned", "phase": "planned",
				"requested_by": clientID, "incarnation": incarnation, "revision": 1,
				"useful_bytes_total": ciphertextBytes, "version_id": "version-1",
				"object_id":                fixture.recovery.Manifest.ObjectID,
				"generation":               fixture.recovery.Manifest.Generation,
				"manifest_sha256":          fixture.recovery.ManifestSHA256,
				"source_recovery_sha256":   sourceRecoverySHA256,
				"source_recovery_revision": 1, "source_driver_id": "source",
				"destination_driver_id":      "destination",
				"source_location_count":      sourceLocationCount,
				"minimum_available_replicas": 1, "grace_seconds": 86400,
				"move_state": "copying", "created_at": 1, "updated_at": 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			claim := claims.Add(1)

			if claim > 1 && failRenewal {
				http.Error(response, "move fence lost", http.StatusConflict)
				return
			}

			if claim > 1 {
				releaseGate.Do(func() { close(providerGate) })
			}

			writeJSON(t, response, map[string]any{
				"operation_id": operationID, "lease_id": leaseID,
				"owner_client_id": clientID, "incarnation": incarnation,
				"fencing_token": 9, "expires_at": 100, "operation_revision": 2,
				"operation_state": "running",
			})
		case "/api/v1/moves/" + operationID + "/manifest":
			_, _ = response.Write(sourceEncoded)
		case "/api/v1/recovery-manifests/stage":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read move recovery: %v", err)
				return
			}

			parsed, err := manifest.ParseRecovery(body)
			if err != nil {
				t.Errorf("parse move recovery: %v", err)
				return
			}

			writeJSON(t, response, map[string]any{
				"manifest_sha256": parsed.ManifestSHA256,
				"recovery_sha256": testDigest(body),
				"namespace_id":    parsed.Manifest.NamespaceID,
				"object_id":       parsed.Manifest.ObjectID,
				"generation":      parsed.Manifest.Generation,
				"r2_key":          "manifests/controlled-move/" + testDigest(body) + ".json",
				"r2_version":      "move-v1", "bytes": len(body),
			})
		case "/api/v1/moves/publish-destination":
			var published struct {
				RecoverySHA256 string `json:"recovery_sha256"`
			}
			if err := json.NewDecoder(request.Body).Decode(&published); err != nil {
				t.Errorf("decode move publication: %v", err)
				return
			}

			writeJSON(t, response, map[string]any{
				"operation_id":          operationID,
				"manifest_sha256":       fixture.recovery.ManifestSHA256,
				"recovery_sha256":       published.RecoverySHA256,
				"destination_driver_id": "destination",
				"locations_added":       extentCount, "recovery_revision": 2,
				"state": "destination_published",
			})
		case "/api/v1/moves/tombstone-source":
			var tombstone struct {
				RecoverySHA256 string `json:"recovery_sha256"`
			}
			if err := json.NewDecoder(request.Body).Decode(&tombstone); err != nil {
				t.Errorf("decode move tombstone: %v", err)
				return
			}

			writeJSON(t, response, map[string]any{
				"operation_id":                operationID,
				"manifest_sha256":             fixture.recovery.ManifestSHA256,
				"recovery_sha256":             tombstone.RecoverySHA256,
				"source_driver_id":            "source",
				"source_locations_tombstoned": sourceLocationCount,
				"recovery_revision":           3, "grace_until": 90000,
				"state": "source_delete_pending",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct move control client: %v", err)
	}

	coordinator, err := sdk.NewControlledMover(control, replicator, 15, time.Millisecond)
	if err != nil {
		t.Fatalf("construct controlled mover: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, moveErr := coordinator.Move(ctx, sdk.ControlledMoveRequest{
		NamespaceID:    fixture.recovery.Manifest.NamespaceID,
		ManifestSHA256: fixture.recovery.ManifestSHA256,
		SourceDriverID: "source", DestinationDriverID: "destination",
		DestinationPrefix: "controlled-move", IdempotencyKey: "controlled-move-v1",
		StagingDirectory: t.TempDir(),
	})

	return result, claims.Load(), moveErr
}
