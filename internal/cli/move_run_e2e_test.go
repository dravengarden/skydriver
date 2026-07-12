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
	"github.com/dravengarden/carrack/sdk"
)

func TestMoveRunCommandReplicatesAndTombstonesLocalSource(t *testing.T) {
	const (
		operationID = "808182838485868788898a8b8c8d8e8f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	baseRecovery, _, ciphertext := cliRestoreFixture(t, []byte("ok"))

	sourceRecovery, err := manifest.NewRecoveryManifest(baseRecovery.Manifest, []manifest.Location{{
		ExtentSHA256: baseRecovery.Manifest.Packs[0].Extents[0].CiphertextSHA256,
		DriverID:     "local-source", StorageKey: "payload.bin", Length: uint64(len(ciphertext)),
	}})
	if err != nil {
		t.Fatalf("construct local move recovery: %v", err)
	}

	sourceEncoded, err := sourceRecovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal local move recovery: %v", err)
	}

	sourceDigest := sha256.Sum256(sourceEncoded)

	manifestDigest, err := sourceRecovery.Manifest.Digest()
	if err != nil {
		t.Fatalf("digest local move manifest: %v", err)
	}

	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()

	stagingDirectory := t.TempDir()

	if writeErr := os.WriteFile(filepath.Join(sourceRoot, "payload.bin"), ciphertext, 0o600); writeErr != nil {
		t.Fatalf("write local move source: %v", writeErr)
	}

	var stageCount atomic.Uint64

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		switch request.URL.Path {
		case "/api/v1/moves":
			writeCLIJSON(t, response, sdk.MoveOperation{
				ID: operationID, NamespaceID: sourceRecovery.Manifest.NamespaceID,
				Kind: moveCommandName, State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(ciphertext)),
				VersionID: "version-1", ObjectID: sourceRecovery.Manifest.ObjectID,
				Generation: sourceRecovery.Manifest.Generation, ManifestSHA256: manifestDigest,
				SourceRecoverySHA256:   hex.EncodeToString(sourceDigest[:]),
				SourceRecoveryRevision: 1, SourceDriverID: "local-source",
				DestinationDriverID: "local-destination", SourceLocationCount: 1,
				MinimumAvailableReplicas: 1, GraceSeconds: 60, MoveState: "copying",
				CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 7,
				ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/moves/" + operationID + "/manifest":
			_, _ = response.Write(sourceEncoded)
		case "/api/v1/recovery-manifests/stage":
			var recovery manifest.RecoveryManifest
			if decodeErr := json.NewDecoder(request.Body).Decode(&recovery); decodeErr != nil {
				t.Errorf("decode staged move recovery: %v", decodeErr)

				return
			}

			encoded, encodeErr := recovery.MarshalCanonical()
			if encodeErr != nil {
				t.Errorf("marshal staged move recovery: %v", encodeErr)

				return
			}

			digest := sha256.Sum256(encoded)
			sequence := stageCount.Add(1)
			writeCLIJSON(t, response, sdk.StagedRecovery{
				ManifestSHA256: recovery.ManifestSHA256,
				RecoverySHA256: hex.EncodeToString(digest[:]),
				NamespaceID:    recovery.Manifest.NamespaceID, ObjectID: recovery.Manifest.ObjectID,
				Generation: recovery.Manifest.Generation,
				R2Key:      "move/staged/" + hex.EncodeToString(digest[:]),
				R2Version:  "r2-v" + string(rune('0'+sequence)), Bytes: uint64(len(encoded)),
			})
		case "/api/v1/moves/publish-destination":
			var body struct {
				RecoverySHA256 string `json:"recovery_sha256"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode move destination publication: %v", decodeErr)

				return
			}

			writeCLIJSON(t, response, sdk.PublishedMoveDestination{
				OperationID: operationID, ManifestSHA256: manifestDigest,
				RecoverySHA256: body.RecoverySHA256, DestinationDriverID: "local-destination",
				LocationsAdded: 1, RecoveryRevision: 2, State: "destination_published",
			})
		case "/api/v1/moves/tombstone-source":
			var body struct {
				RecoverySHA256 string `json:"recovery_sha256"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode move source tombstone: %v", decodeErr)

				return
			}

			writeCLIJSON(t, response, sdk.TombstonedMoveSource{
				OperationID: operationID, ManifestSHA256: manifestDigest,
				RecoverySHA256: body.RecoverySHA256, SourceDriverID: "local-source",
				SourceLocationsTombstoned: 1, RecoveryRevision: 3,
				GraceUntil: 1000, State: "source_delete_pending",
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

	err = Run(context.Background(), []string{
		moveCommandName, "run",
		"--control-url", control.URL,
		"--namespace", sourceRecovery.Manifest.NamespaceID,
		"--manifest", manifestDigest,
		"--source-local-driver-id", "local-source",
		"--source-local-root", sourceRoot,
		"--destination-local-driver-id", "local-destination",
		"--destination-local-root", destinationRoot,
		"--destination-prefix", "moved",
		"--staging-directory", stagingDirectory,
		"--format", outputFormatJSON,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("execute local move: %v; stderr=%s", err, stderr.String())
	}

	if _, statErr := os.Stat(filepath.Join(sourceRoot, "payload.bin")); statErr != nil {
		t.Fatalf("move run physically deleted source before grace: %v", statErr)
	}

	destinationFiles := 0

	if walkErr := filepath.WalkDir(destinationRoot, func(_ string, entry fs.DirEntry, entryErr error) error {
		if entryErr == nil && entry.Type().IsRegular() {
			destinationFiles++
		}

		return entryErr
	}); walkErr != nil {
		t.Fatalf("inspect local move destination: %v", walkErr)
	}

	if destinationFiles < 3 || stageCount.Load() != 2 {
		t.Fatalf("move output is incomplete: files=%d stages=%d", destinationFiles, stageCount.Load())
	}

	if !strings.Contains(stdout.String(), `"state": "source_delete_pending"`) ||
		!strings.Contains(stdout.String(), `"locations_added": 1`) {
		t.Fatalf("unexpected move run output: %s", stdout.String())
	}
}

func TestMoveRunIdempotencyKeyPinsEveryIdentity(t *testing.T) {
	t.Parallel()

	base := moveRunIdempotencyKey("namespace", "manifest", "source", "destination", "prefix")
	if base != moveRunIdempotencyKey("namespace", "manifest", "source", "destination", "prefix") {
		t.Fatal("move run idempotency key is not stable")
	}

	for _, changed := range []string{
		moveRunIdempotencyKey("other", "manifest", "source", "destination", "prefix"),
		moveRunIdempotencyKey("namespace", "other", "source", "destination", "prefix"),
		moveRunIdempotencyKey("namespace", "manifest", "other", "destination", "prefix"),
		moveRunIdempotencyKey("namespace", "manifest", "source", "other", "prefix"),
		moveRunIdempotencyKey("namespace", "manifest", "source", "destination", "other"),
	} {
		if changed == base {
			t.Fatal("move run idempotency identity omitted an input")
		}
	}
}
