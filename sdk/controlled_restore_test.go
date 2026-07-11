package sdk_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type delayedRestoreReader struct {
	reader provider.Reader
	delay  time.Duration
}

func (reader delayedRestoreReader) Stat(ctx context.Context, key string) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader delayedRestoreReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	timer := time.NewTimer(reader.delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return reader.reader.OpenRange(ctx, key, offset, length)
	}
}

func TestControlledRestorerRenewsLeaseDuringProviderIO(t *testing.T) {
	t.Parallel()
	runControlledRestore(t, false, false, false)
}

func TestControlledRestorerCancelsProviderIOAfterLeaseLoss(t *testing.T) {
	t.Parallel()
	runControlledRestore(t, true, false, false)
}

func TestControlledRestorerClosesTerminalIntegrityFailure(t *testing.T) {
	t.Parallel()
	runControlledRestore(t, false, true, false)
}

func TestControlledRestorerObtainsEpochKeyFromControlPlane(t *testing.T) {
	t.Parallel()
	runControlledRestore(t, false, false, true)
}

func runControlledRestore(t *testing.T, failRenewal, wrongKey, useKeyGrant bool) {
	t.Helper()

	plaintext := []byte("a controlled restore remains leased throughout provider reads")
	archiveStore, imported, epochKey := importRestoreFixture(t, plaintext)
	token, encodedToken := testClientToken(t)

	var claims atomic.Uint64

	var failures atomic.Uint64

	var progressReports atomic.Uint64

	const (
		operationID = "303132333435363738393a3b3c3d3e3f"
		incarnation = "404142434445464748494a4b4c4d4e4f"
		clientID    = "client-1"
		versionID   = "version-1"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/restores":
			writeTestJSON(t, response, sdk.RestoreOperation{
				ID: operationID, NamespaceID: imported.Manifest.NamespaceID, Kind: "restore",
				State: "planned", Phase: "planned", RequestedBy: clientID, Incarnation: incarnation,
				Revision: 1, UsefulBytesTotal: uint64(len(plaintext)), VersionID: versionID,
				ObjectID: imported.Manifest.ObjectID, Generation: imported.Manifest.Generation,
				ManifestSHA256: imported.Recovery.ManifestSHA256, CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/restores/" + operationID + "/claim":
			claim := claims.Add(1)
			if failRenewal && claim > 1 {
				http.Error(response, "lease lost", http.StatusConflict)

				return
			}

			writeTestJSON(t, response, sdk.RestoreReadLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/read",
				OwnerClientID: clientID, Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
				VersionID: versionID, ManifestSHA256: imported.Recovery.ManifestSHA256,
			})
		case "/api/v1/restores/" + operationID + "/manifest":
			writeTestJSON(t, response, imported.Recovery)
		case "/api/v1/restores/" + operationID + "/key":
			writeTestJSON(t, response, map[string]any{
				"operation_id": operationID, "manifest_sha256": imported.Recovery.ManifestSHA256,
				"root_version": imported.Manifest.Crypto.RootVersion,
				"key_epoch":    imported.Manifest.Crypto.KeyEpoch,
				"epoch_key":    base64.RawURLEncoding.EncodeToString(epochKey[:]),
			})
		case "/api/v1/restores/" + operationID + "/complete":
			writeTestJSON(t, response, sdk.CompletedRestore{
				OperationID: operationID, ManifestSHA256: imported.Recovery.ManifestSHA256,
				State: "succeeded",
			})
		case "/api/v1/restores/" + operationID + "/fail":
			failures.Add(1)
			writeTestJSON(t, response, sdk.CompletedRestore{
				OperationID: operationID, ManifestSHA256: imported.Recovery.ManifestSHA256,
				State: "failed",
			})
		case "/api/v1/operations/" + operationID + "/progress":
			progressReports.Add(1)

			var sample struct {
				Sequence            uint64 `json:"sequence"`
				WireBytesRead       uint64 `json:"wire_bytes_read"`
				UsefulBytesVerified uint64 `json:"useful_bytes_verified"`
				ActiveNanoseconds   uint64 `json:"active_nanoseconds"`
			}
			if err := json.NewDecoder(request.Body).Decode(&sample); err != nil {
				t.Errorf("decode progress sample: %v", err)

				return
			}

			writeTestJSON(t, response, sdk.ProgressSnapshot{
				ComponentID: operationID + "/restore", Attempt: 1,
				Sequence: sample.Sequence, WireBytesRead: sample.WireBytesRead,
				UsefulBytesVerified: sample.UsefulBytesVerified,
				ActiveNanoseconds:   sample.ActiveNanoseconds, Disposition: "current",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{
		"memory-primary": delayedRestoreReader{reader: archiveStore, delay: 20 * time.Millisecond},
	}, 128)
	if err != nil {
		t.Fatalf("construct local restorer: %v", err)
	}

	coordinator, err := sdk.NewControlledRestorer(control, restorer, 15, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("construct controlled restorer: %v", err)
	}

	destination := filepath.Join(t.TempDir(), "restored.bin")

	requestedEpochKey := epochKey
	if wrongKey {
		requestedEpochKey[0] ^= 1
	} else if useKeyGrant {
		clear(requestedEpochKey[:])
	}

	result, err := coordinator.Restore(context.Background(), sdk.ControlledRestoreRequest{
		NamespaceID: imported.Manifest.NamespaceID, ManifestSHA256: imported.Recovery.ManifestSHA256,
		IdempotencyKey: "controlled-restore-1", EpochKey: requestedEpochKey,
		Destination: destination,
	})
	if failRenewal {
		if !errors.Is(err, sdk.ErrRestoreLeaseLost) {
			t.Fatalf("restore did not report lease loss: %v", err)
		}

		if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("lease-lost restore published destination: %v", statErr)
		}

		return
	}

	if wrongKey {
		if err == nil || failures.Load() != 1 {
			t.Fatalf("terminal integrity failure was not closed: err=%v failures=%d", err, failures.Load())
		}

		if _, statErr := os.Stat(destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("integrity-failed restore published destination: %v", statErr)
		}

		return
	}

	if err != nil {
		t.Fatalf("execute controlled restore: %v", err)
	}

	if claims.Load() < 2 {
		t.Fatalf("restore completed without renewal: claims=%d", claims.Load())
	}

	if result.Completion.State != "succeeded" || result.Restore.PlaintextBytes != uint64(len(plaintext)) {
		t.Fatalf("unexpected controlled restore result: %+v", result)
	}

	if progressReports.Load() == 0 || result.TelemetryWarning != "" {
		t.Fatalf("restore telemetry was not accepted: reports=%d warning=%q", progressReports.Load(), result.TelemetryWarning)
	}
}

func writeTestJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()

	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}
