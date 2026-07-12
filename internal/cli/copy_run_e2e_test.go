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

func TestCopyRunCommandReplicatesAndPreservesLocalSource(t *testing.T) {
	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	baseRecovery, _, ciphertext := cliRestoreFixture(t, []byte("ok"))

	sourceRecovery, err := manifest.NewRecoveryManifest(baseRecovery.Manifest, []manifest.Location{{
		ExtentSHA256: baseRecovery.Manifest.Packs[0].Extents[0].CiphertextSHA256,
		DriverID:     "local-source", StorageKey: "payload.bin", Length: uint64(len(ciphertext)),
	}})
	if err != nil {
		t.Fatalf("construct local copy recovery: %v", err)
	}

	sourceEncoded, err := sourceRecovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal local copy recovery: %v", err)
	}

	sourceDigest := sha256.Sum256(sourceEncoded)

	manifestDigest, err := sourceRecovery.Manifest.Digest()
	if err != nil {
		t.Fatalf("digest local copy manifest: %v", err)
	}

	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	stagingDirectory := t.TempDir()

	if writeErr := os.WriteFile(filepath.Join(sourceRoot, "payload.bin"), ciphertext, 0o600); writeErr != nil {
		t.Fatalf("write local copy source: %v", writeErr)
	}

	var stageCount atomic.Uint64

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		switch request.URL.Path {
		case "/api/v1/copies":
			writeCLIJSON(t, response, sdk.CopyOperation{
				ID: operationID, NamespaceID: sourceRecovery.Manifest.NamespaceID,
				Kind: copyCommandName, State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(ciphertext)),
				VersionID: "version-1", ObjectID: sourceRecovery.Manifest.ObjectID,
				Generation: sourceRecovery.Manifest.Generation, ManifestSHA256: manifestDigest,
				SourceRecoverySHA256:   hex.EncodeToString(sourceDigest[:]),
				SourceRecoveryRevision: 1, DestinationDriverID: "local-destination",
				CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 7,
				ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/copies/" + operationID + "/manifest":
			_, _ = response.Write(sourceEncoded)
		case "/api/v1/recovery-manifests/stage":
			var recovery manifest.RecoveryManifest
			if decodeErr := json.NewDecoder(request.Body).Decode(&recovery); decodeErr != nil {
				t.Errorf("decode staged copy recovery: %v", decodeErr)

				return
			}

			encoded, encodeErr := recovery.MarshalCanonical()
			if encodeErr != nil {
				t.Errorf("marshal staged copy recovery: %v", encodeErr)

				return
			}

			digest := sha256.Sum256(encoded)

			stageCount.Add(1)
			writeCLIJSON(t, response, sdk.StagedRecovery{
				ManifestSHA256: recovery.ManifestSHA256,
				RecoverySHA256: hex.EncodeToString(digest[:]),
				NamespaceID:    recovery.Manifest.NamespaceID, ObjectID: recovery.Manifest.ObjectID,
				Generation: recovery.Manifest.Generation,
				R2Key:      "copy/staged/" + hex.EncodeToString(digest[:]),
				R2Version:  "copy-v1", Bytes: uint64(len(encoded)),
			})
		case "/api/v1/copies/publish":
			var body struct {
				RecoverySHA256 string `json:"recovery_sha256"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode copy publication: %v", decodeErr)

				return
			}

			writeCLIJSON(t, response, sdk.PublishedCopy{
				OperationID: operationID, ManifestSHA256: manifestDigest,
				RecoverySHA256: body.RecoverySHA256, DestinationDriverID: "local-destination",
				LocationsAdded: 1, RecoveryRevision: 2, State: "published",
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
		copyCommandName, runCommandName,
		"--control-url", control.URL,
		"--namespace", sourceRecovery.Manifest.NamespaceID,
		"--manifest", manifestDigest,
		"--source-local-driver-id", "local-source",
		"--source-local-root", sourceRoot,
		"--destination-local-driver-id", "local-destination",
		"--destination-local-root", destinationRoot,
		"--destination-prefix", "copied",
		"--staging-directory", stagingDirectory,
		"--format", outputFormatJSON,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("execute local copy: %v; stderr=%s", err, stderr.String())
	}

	if _, statErr := os.Stat(filepath.Join(sourceRoot, "payload.bin")); statErr != nil {
		t.Fatalf("copy run removed its source: %v", statErr)
	}

	destinationFiles := 0

	if walkErr := filepath.WalkDir(destinationRoot, func(_ string, entry fs.DirEntry, entryErr error) error {
		if entryErr == nil && entry.Type().IsRegular() {
			destinationFiles++
		}

		return entryErr
	}); walkErr != nil {
		t.Fatalf("inspect local copy destination: %v", walkErr)
	}

	if destinationFiles < 2 || stageCount.Load() != 1 {
		t.Fatalf("copy output is incomplete: files=%d stages=%d", destinationFiles, stageCount.Load())
	}

	if !strings.Contains(stdout.String(), `"state": "published"`) ||
		!strings.Contains(stdout.String(), `"locations_added": 1`) {
		t.Fatalf("unexpected copy run output: %s", stdout.String())
	}
}

func TestCopyRunIdempotencyKeyPinsEveryIdentity(t *testing.T) {
	t.Parallel()

	base := copyRunIdempotencyKey("namespace", "manifest", "source", "destination", "prefix")
	if base != copyRunIdempotencyKey("namespace", "manifest", "source", "destination", "prefix") {
		t.Fatal("copy run idempotency key is not stable")
	}

	for _, changed := range []string{
		copyRunIdempotencyKey("other", "manifest", "source", "destination", "prefix"),
		copyRunIdempotencyKey("namespace", "other", "source", "destination", "prefix"),
		copyRunIdempotencyKey("namespace", "manifest", "other", "destination", "prefix"),
		copyRunIdempotencyKey("namespace", "manifest", "source", "other", "prefix"),
		copyRunIdempotencyKey("namespace", "manifest", "source", "destination", "other"),
	} {
		if changed == base {
			t.Fatal("copy run idempotency identity omitted an input")
		}
	}
}
