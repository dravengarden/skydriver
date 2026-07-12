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

func TestControlledReplicatorRenewsFenceDuringProviderIO(t *testing.T) {
	t.Parallel()

	result, claimCount, err := runControlledCopy(t, false)
	if err != nil {
		t.Fatalf("controlled copy failed: %v", err)
	}

	if result.Publication.State != "published" || result.Replication.CiphertextBytes == 0 {
		t.Fatalf("unexpected controlled copy result: %+v", result)
	}

	if claimCount < 2 {
		t.Fatalf("copy completed without a lease renewal: claims=%d", claimCount)
	}
}

func TestControlledReplicatorCancelsProviderIOAfterFenceLoss(t *testing.T) {
	t.Parallel()

	_, _, err := runControlledCopy(t, true)
	if !errors.Is(err, sdk.ErrCopyLeaseLost) {
		t.Fatalf("expected copy lease loss, got %v", err)
	}
}

func runControlledCopy(
	t *testing.T,
	failRenewal bool,
) (sdk.ControlledCopyResult, int64, error) {
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
	_, ciphertextBytes := replicationManifestTotals(fixture.recovery.Manifest)
	extentCount, _ := replicationManifestTotals(fixture.recovery.Manifest)

	const (
		operationID = "303132333435363738393a3b3c3d3e3f"
		incarnation = "0123456789abcdef0123456789abcdef"
		clientID    = "controlled-copy-client"
		leaseID     = "operation/303132333435363738393a3b3c3d3e3f/write"
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
		case "/api/v1/copies":
			writeJSON(t, response, map[string]any{
				"id": operationID, "namespace_id": fixture.recovery.Manifest.NamespaceID,
				"kind": "copy", "state": "planned", "phase": "planned",
				"requested_by": clientID, "incarnation": incarnation, "revision": 1,
				"useful_bytes_total": ciphertextBytes, "version_id": "version-1",
				"object_id":                fixture.recovery.Manifest.ObjectID,
				"generation":               fixture.recovery.Manifest.Generation,
				"manifest_sha256":          fixture.recovery.ManifestSHA256,
				"source_recovery_sha256":   sourceRecoverySHA256,
				"source_recovery_revision": 1, "destination_driver_id": "destination",
				"created_at": 1, "updated_at": 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			claim := claims.Add(1)

			if claim > 1 && failRenewal {
				http.Error(response, "copy fence lost", http.StatusConflict)

				return
			}

			if claim > 1 {
				releaseGate.Do(func() { close(providerGate) })
			}

			writeJSON(t, response, map[string]any{
				"operation_id": operationID, "lease_id": leaseID,
				"owner_client_id": clientID, "incarnation": incarnation,
				"fencing_token": 7, "expires_at": 100, "operation_revision": 2,
				"operation_state": "running",
			})
		case "/api/v1/copies/" + operationID + "/manifest":
			_, _ = response.Write(sourceEncoded)
		case "/api/v1/recovery-manifests/stage":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read copied recovery: %v", err)

				return
			}

			parsed, err := manifest.ParseRecovery(body)
			if err != nil {
				t.Errorf("parse copied recovery: %v", err)

				return
			}

			writeJSON(t, response, map[string]any{
				"manifest_sha256": parsed.ManifestSHA256,
				"recovery_sha256": testDigest(body),
				"namespace_id":    parsed.Manifest.NamespaceID,
				"object_id":       parsed.Manifest.ObjectID,
				"generation":      parsed.Manifest.Generation,
				"r2_key":          "manifests/controlled-copy.json", "r2_version": "copy-v1",
				"bytes": len(body),
			})
		case "/api/v1/copies/publish":
			var published struct {
				RecoverySHA256 string `json:"recovery_sha256"`
			}
			if err := json.NewDecoder(request.Body).Decode(&published); err != nil {
				t.Errorf("decode copy publication: %v", err)

				return
			}

			writeJSON(t, response, map[string]any{
				"operation_id":          operationID,
				"manifest_sha256":       fixture.recovery.ManifestSHA256,
				"recovery_sha256":       published.RecoverySHA256,
				"destination_driver_id": "destination",
				"locations_added":       extentCount, "recovery_revision": 2,
				"state": "published",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct copy control client: %v", err)
	}

	coordinator, err := sdk.NewControlledReplicator(control, replicator, 15, time.Millisecond)
	if err != nil {
		t.Fatalf("construct controlled replicator: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, copyErr := coordinator.Copy(ctx, sdk.ControlledCopyRequest{
		NamespaceID:         fixture.recovery.Manifest.NamespaceID,
		ManifestSHA256:      fixture.recovery.ManifestSHA256,
		DestinationDriverID: "destination", DestinationPrefix: "controlled-copy",
		IdempotencyKey: "controlled-copy-v1", StagingDirectory: t.TempDir(),
	})

	return result, claims.Load(), copyErr
}

type gatedCopyReader struct {
	provider.Reader

	once sync.Once
	gate <-chan struct{}
}

func (reader *gatedCopyReader) OpenRange(
	ctx context.Context,
	key string,
	offset uint64,
	length uint64,
) (io.ReadCloser, error) {
	wait := false

	reader.once.Do(func() { wait = true })

	if wait {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-reader.gate:
		}
	}

	return reader.Reader.OpenRange(ctx, key, offset, length)
}

func writeJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()

	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("encode HTTP response: %v", err)
	}
}
