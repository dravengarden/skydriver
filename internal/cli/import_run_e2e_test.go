package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

//nolint:maintidx // The end-to-end test intentionally keeps one complete protocol trace visible.
func TestImportRunCommandEncryptsAndPublishesLocalSource(t *testing.T) {
	const (
		operationID = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	plaintext := []byte("local controlled import")
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	stagingDirectory := t.TempDir()
	planFile := filepath.Join(t.TempDir(), "import-plan.json")

	if err := os.WriteFile(filepath.Join(sourceRoot, "payload.bin"), plaintext, 0o600); err != nil {
		t.Fatalf("write local import source: %v", err)
	}

	var (
		stageCount    atomic.Uint64
		progressCount atomic.Uint64
		keyGrantCount atomic.Uint64
		published     atomic.Bool
		publishedSHA  atomic.Value
	)

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	epochKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		switch request.URL.Path {
		case "/api/v1/operations":
			total := uint64(len(plaintext))
			if published.Load() {
				writeCLIJSON(t, response, sdk.ImportOperation{
					ID: operationID, NamespaceID: "202122232425262728292a2b2c2d2e2f",
					Kind: importCommandName, State: "succeeded", Phase: "succeeded",
					RequestedBy: "cli-client", Incarnation: incarnation, Revision: 5,
					UsefulBytesTotal: &total, RootVersion: 1, KeyEpoch: 7,
					PublishedObjectID: "object-1", PublishedGeneration: 1,
					PublishedManifestSHA256:      publishedSHA.Load().(string),
					PublishedDestinationDriverID: "local-destination",
					PublishedSidecarStorageKey:   "imported/manifests/replayed.json",
					CreatedAt:                    1, UpdatedAt: 2,
				})

				return
			}

			writeCLIJSON(t, response, sdk.ImportOperation{
				ID: operationID, NamespaceID: "202122232425262728292a2b2c2d2e2f",
				Kind: importCommandName, State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: &total,
				RootVersion: 1, KeyEpoch: 7, CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 7,
				ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/imports/" + operationID + "/key":
			keyGrantCount.Add(1)
			writeCLIJSON(t, response, map[string]any{
				"operation_id": operationID, "root_version": 1, "key_epoch": 7,
				"epoch_key": epochKey,
			})
		case "/api/v1/recovery-manifests/stage":
			var recovery manifest.RecoveryManifest
			if decodeErr := json.NewDecoder(request.Body).Decode(&recovery); decodeErr != nil {
				t.Errorf("decode local import recovery: %v", decodeErr)

				return
			}

			if recovery.Manifest.ObjectID != "object-1" || recovery.Manifest.Crypto.RootVersion != 1 ||
				recovery.Manifest.Crypto.KeyEpoch != 7 || len(recovery.Locations) == 0 {
				t.Errorf("unexpected local import recovery: %+v", recovery)

				return
			}

			encoded, encodeErr := recovery.MarshalCanonical()
			if encodeErr != nil {
				t.Errorf("marshal local import recovery: %v", encodeErr)

				return
			}

			digest := sha256.Sum256(encoded)

			stageCount.Add(1)
			writeCLIJSON(t, response, sdk.StagedRecovery{
				ManifestSHA256: recovery.ManifestSHA256,
				RecoverySHA256: hex.EncodeToString(digest[:]),
				NamespaceID:    recovery.Manifest.NamespaceID, ObjectID: recovery.Manifest.ObjectID,
				Generation: recovery.Manifest.Generation,
				R2Key:      "import/staged/" + hex.EncodeToString(digest[:]),
				R2Version:  "import-v1", Bytes: uint64(len(encoded)),
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
				t.Errorf("decode local import progress: %v", decodeErr)

				return
			}

			progressCount.Add(1)
			writeCLIJSON(t, response, sdk.ProgressSnapshot{
				ComponentID: operationID + "/transfer", Attempt: 7,
				Sequence: sample.Sequence, WireBytesRead: sample.WireBytesRead,
				WireBytesWritten:    sample.WireBytesWritten,
				UsefulBytesVerified: sample.UsefulBytesVerified,
				ActiveNanoseconds:   sample.ActiveNanoseconds,
				ObservedAt:          2, Disposition: "current",
			})
		case "/api/v1/imports/publish":
			var body struct {
				ManifestSHA256 string `json:"manifest_sha256"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode local import publication: %v", decodeErr)

				return
			}

			publishedSHA.Store(body.ManifestSHA256)
			published.Store(true)

			writeCLIJSON(t, response, sdk.PublishedImport{
				OperationID: operationID, ObjectID: "object-1", Generation: 1,
				ManifestSHA256: body.ManifestSHA256, State: "published",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)
	t.Setenv(controlTokenEnvironment, token)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	arguments := []string{
		importCommandName, runCommandName,
		"--control-url", control.URL,
		"--namespace", "202122232425262728292a2b2c2d2e2f",
		"--object-id", "object-1",
		"--source-local-driver-id", "local-source",
		"--source-local-root", sourceRoot,
		"--source-key", "payload.bin",
		"--destination-local-driver-id", "local-destination",
		"--destination-local-root", destinationRoot,
		"--destination-prefix", "imported",
		"--staging-directory", stagingDirectory,
		"--plan-file", planFile,
		"--format", outputFormatJSON,
	}

	err := Run(context.Background(), arguments, &stdout, &stderr)
	if err != nil {
		t.Fatalf("execute local import: %v; stderr=%s", err, stderr.String())
	}

	if _, statErr := os.Stat(filepath.Join(sourceRoot, "payload.bin")); statErr != nil {
		t.Fatalf("import run removed its source: %v", statErr)
	}

	plan, err := sdk.ReadImportPlan(planFile)
	if err != nil {
		t.Fatalf("read local import plan: %v", err)
	}

	if plan.RootVersion != 1 || plan.KeyEpoch != 7 || plan.Source.SizeBytes != uint64(len(plaintext)) {
		t.Fatalf("unexpected persisted local import plan: %+v", plan)
	}

	destinationFiles := 0

	if walkErr := filepath.WalkDir(destinationRoot, func(_ string, entry fs.DirEntry, entryErr error) error {
		if entryErr == nil && entry.Type().IsRegular() {
			destinationFiles++
		}

		return entryErr
	}); walkErr != nil {
		t.Fatalf("inspect local import destination: %v", walkErr)
	}

	if destinationFiles < 2 || stageCount.Load() != 1 || progressCount.Load() != 1 ||
		keyGrantCount.Load() != 1 {
		t.Fatalf(
			"import output is incomplete: files=%d stages=%d progress=%d keys=%d",
			destinationFiles,
			stageCount.Load(),
			progressCount.Load(),
			keyGrantCount.Load(),
		)
	}

	if !strings.Contains(stdout.String(), `"state": "published"`) ||
		!strings.Contains(stdout.String(), `"object_id": "object-1"`) ||
		!strings.Contains(stdout.String(), `"telemetry_warning": ""`) ||
		!strings.Contains(stdout.String(), `"already_published": false`) {
		t.Fatalf("unexpected import run output: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()

	if replayErr := Run(context.Background(), arguments, &stdout, &stderr); replayErr != nil {
		t.Fatalf("replay completed local import: %v; stderr=%s", replayErr, stderr.String())
	}

	if stageCount.Load() != 1 || progressCount.Load() != 1 || keyGrantCount.Load() != 1 ||
		!strings.Contains(stdout.String(), `"already_published": true`) {
		t.Fatalf(
			"completed import replay repeated side effects: stages=%d progress=%d keys=%d output=%s",
			stageCount.Load(),
			progressCount.Load(),
			keyGrantCount.Load(),
			stdout.String(),
		)
	}
}

func TestImportRunIdempotencyKeyPinsEveryIdentity(t *testing.T) {
	t.Parallel()

	flags := importRunFlags{
		namespaceID: "namespace", objectID: "object", generation: 1,
		sourceDriverID: "source", sourceKey: "payload",
		destinationDriverID: "destination", destinationPrefix: "prefix",
		expectedObjectRevision: 1,
	}
	source := provider.Object{SizeBytes: 2, ETag: "etag", Version: "version"}

	base := importRunIdempotencyKey(flags, source)
	if base != importRunIdempotencyKey(flags, source) {
		t.Fatal("import run idempotency key is not stable")
	}

	changedFlags := []importRunFlags{flags, flags, flags, flags, flags, flags, flags, flags}
	changedFlags[0].namespaceID = "other"
	changedFlags[1].objectID = "other"
	changedFlags[2].generation = 2
	changedFlags[3].sourceDriverID = "other"
	changedFlags[4].sourceKey = "other"
	changedFlags[5].destinationDriverID = "other"
	changedFlags[6].destinationPrefix = "other"
	changedFlags[7].expectedObjectRevision = 2

	for _, changed := range changedFlags {
		if importRunIdempotencyKey(changed, source) == base {
			t.Fatal("import run idempotency identity omitted a flag")
		}
	}

	for _, changed := range []provider.Object{
		{SizeBytes: 3, ETag: "etag", Version: "version"},
		{SizeBytes: 2, ETag: "other", Version: "version"},
		{SizeBytes: 2, ETag: "etag", Version: "other"},
	} {
		if importRunIdempotencyKey(flags, changed) == base {
			t.Fatal("import run idempotency identity omitted source state")
		}
	}
}
