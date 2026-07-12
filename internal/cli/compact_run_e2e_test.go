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
	"sync/atomic"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

//nolint:maintidx // The complete decrypt, repack, stage, CAS, and replay trace is intentional.
func TestCompactRunCommandPublishesSmallerGeneration(t *testing.T) {
	const (
		operationID = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		incarnation = "0123456789abcdef0123456789abcdef"
		namespaceID = "202122232425262728292a2b2c2d2e2f"
	)

	plaintext := []byte("local compaction combines several immutable source packs")
	plaintextRoot := t.TempDir()
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()

	stagingDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(plaintextRoot, "payload.bin"), plaintext, 0o600); err != nil {
		t.Fatalf("write compact plaintext fixture: %v", err)
	}

	plaintextReader, err := localfs.NewClient(plaintextRoot)
	if err != nil {
		t.Fatalf("open compact plaintext fixture: %v", err)
	}

	sourceArchive, err := localfs.NewClient(sourceRoot)
	if err != nil {
		t.Fatalf("open compact source archive: %v", err)
	}

	sourceLayout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   4,
		LogicalPackBytes:   16,
	}

	sourceImporter, err := sdk.NewImporter(plaintextReader, sourceArchive, sourceLayout)
	if err != nil {
		t.Fatalf("construct compact source importer: %v", err)
	}

	var identifier cryptostream.Identifier
	for index := range identifier {
		identifier[index] = byte(0x20 + index)
	}

	sourcePlan, err := sourceImporter.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID: identifier, ObjectID: "compact-object", Generation: 1,
		RootVersion: 1, KeyEpoch: 7, SourceKey: "payload.bin",
		DestinationDriverID: "local-source", DestinationPrefix: "source",
	})
	if err != nil {
		t.Fatalf("plan compact source: %v", err)
	}

	var (
		sourceKey cryptostream.EpochKey
		targetKey cryptostream.EpochKey
	)

	for index := range sourceKey {
		sourceKey[index] = byte(index + 1)
		targetKey[index] = byte(index + 33)
	}

	source, err := sourceImporter.Execute(context.Background(), sourcePlan, sourceKey, t.TempDir())
	if err != nil {
		t.Fatalf("write compact source: %v", err)
	}

	if len(source.Manifest.Packs) < 2 {
		t.Fatalf("compact fixture has only %d source pack(s)", len(source.Manifest.Packs))
	}

	sourceEncoded, err := source.Recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal compact source recovery: %v", err)
	}

	sourceRecoveryDigest := sha256.Sum256(sourceEncoded)

	var (
		published     atomic.Bool
		stageCount    atomic.Uint64
		progressCount atomic.Uint64
		keyGrantCount atomic.Uint64
		targetValue   atomic.Value
		publishedSHA  atomic.Value
		publishedKey  atomic.Value
	)

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		switch request.URL.Path {
		case "/api/v1/compactions":
			operation := sdk.CompactOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: compactCommandName,
				State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(plaintext)),
				VersionID: "compact-version-1", ObjectID: "compact-object",
				SourceGeneration: 1, SourceManifestSHA256: source.Recovery.ManifestSHA256,
				SourceRecoverySHA256:   hex.EncodeToString(sourceRecoveryDigest[:]),
				SourceRecoveryRevision: 1, SourcePlaintextSHA256: source.Manifest.PlaintextSHA256,
				SourcePackCount: uint64(len(source.Manifest.Packs)), SourceRootVersion: 1,
				SourceKeyEpoch: 7, ExpectedObjectRevision: 3, TargetGeneration: 2,
				TargetRootVersion: 1, TargetKeyEpoch: 8,
				DestinationDriverID: "local-destination", CreatedAt: 1, UpdatedAt: 1,
			}
			if published.Load() {
				operation.State = "succeeded"
				operation.Phase = "succeeded"
				operation.Revision = 5
				operation.PublishedManifestSHA256 = publishedSHA.Load().(string)
				operation.PublishedSidecarStorageKey = publishedKey.Load().(string)
			}

			writeCLIJSON(t, response, operation)
		case "/api/v1/operations/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 7,
				ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/compactions/" + operationID + "/manifest":
			_, _ = response.Write(sourceEncoded)
		case "/api/v1/compactions/" + operationID + "/source-key":
			keyGrantCount.Add(1)
			writeCLIJSON(t, response, map[string]any{
				"operation_id": operationID, "purpose": "source", "root_version": 1,
				"key_epoch": 7, "epoch_key": base64.RawURLEncoding.EncodeToString(sourceKey[:]),
			})
		case "/api/v1/compactions/" + operationID + "/target-key":
			keyGrantCount.Add(1)
			writeCLIJSON(t, response, map[string]any{
				"operation_id": operationID, "purpose": "target", "root_version": 1,
				"key_epoch": 8, "epoch_key": base64.RawURLEncoding.EncodeToString(targetKey[:]),
			})
		case "/api/v1/recovery-manifests/stage":
			var recovery manifest.RecoveryManifest
			if decodeErr := json.NewDecoder(request.Body).Decode(&recovery); decodeErr != nil {
				t.Errorf("decode compact target recovery: %v", decodeErr)

				return
			}

			if recovery.Manifest.Generation != 2 || len(recovery.Manifest.Packs) != 1 ||
				recovery.Manifest.PlaintextSHA256 != source.Manifest.PlaintextSHA256 {
				t.Errorf("invalid compact target: %+v", recovery.Manifest)

				return
			}

			encoded, encodeErr := recovery.MarshalCanonical()
			if encodeErr != nil {
				t.Errorf("marshal compact target: %v", encodeErr)

				return
			}

			digest := sha256.Sum256(encoded)

			targetValue.Store(recovery)
			stageCount.Add(1)
			writeCLIJSON(t, response, sdk.StagedRecovery{
				ManifestSHA256: recovery.ManifestSHA256,
				RecoverySHA256: hex.EncodeToString(digest[:]), NamespaceID: namespaceID,
				ObjectID: "compact-object", Generation: 2,
				R2Key:     "compact/staged/" + hex.EncodeToString(digest[:]),
				R2Version: "compact-v1", Bytes: uint64(len(encoded)),
			})
		case "/api/v1/operations/" + operationID + "/progress":
			var sample struct {
				Sequence            uint64 `json:"sequence"`
				WireBytesRead       uint64 `json:"wire_bytes_read"`
				WireBytesWritten    uint64 `json:"wire_bytes_written"`
				UsefulBytesVerified uint64 `json:"useful_bytes_verified"`
				ActiveNanoseconds   uint64 `json:"active_nanoseconds"`
				RetryCount          uint64 `json:"retry_count"`
				ThrottleCount       uint64 `json:"throttle_count"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&sample); decodeErr != nil {
				t.Errorf("decode compact progress: %v", decodeErr)

				return
			}

			progressCount.Add(1)
			writeCLIJSON(t, response, sdk.ProgressSnapshot{
				ComponentID: operationID + "/compact", Attempt: 7,
				Sequence: sample.Sequence, WireBytesRead: sample.WireBytesRead,
				WireBytesWritten:    sample.WireBytesWritten,
				UsefulBytesVerified: sample.UsefulBytesVerified,
				ActiveNanoseconds:   sample.ActiveNanoseconds, RetryCount: sample.RetryCount,
				ThrottleCount: sample.ThrottleCount, ObservedAt: 2, Disposition: "current",
			})
		case "/api/v1/compactions/publish":
			var body struct {
				ManifestSHA256    string `json:"manifest_sha256"`
				SidecarStorageKey string `json:"sidecar_storage_key"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode compact publication: %v", decodeErr)

				return
			}

			publishedSHA.Store(body.ManifestSHA256)
			publishedKey.Store(body.SidecarStorageKey)
			published.Store(true)
			writeCLIJSON(t, response, sdk.PublishedImport{
				OperationID: operationID, ObjectID: "compact-object", Generation: 2,
				ManifestSHA256: body.ManifestSHA256, State: "published",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)
	t.Setenv(controlTokenEnvironment, token)

	arguments := []string{
		compactCommandName, runCommandName,
		"--control-url", control.URL,
		"--namespace", namespaceID,
		"--manifest", source.Recovery.ManifestSHA256,
		"--source-local-driver-id", "local-source",
		"--source-local-root", sourceRoot,
		"--destination-local-driver-id", "local-destination",
		"--destination-local-root", destinationRoot,
		"--destination-prefix", "compacted",
		"--idempotency-key", "compact-local-v1",
		"--staging-directory", stagingDirectory,
		"--maximum-extent-bytes", "1048576",
		"--format", outputFormatJSON,
	}

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	if runErr := Run(context.Background(), arguments, &stdout, &stderr); runErr != nil {
		t.Fatalf("execute local compact: %v; stderr=%s", runErr, stderr.String())
	}

	if stageCount.Load() != 1 || progressCount.Load() != 1 || keyGrantCount.Load() != 2 ||
		!strings.Contains(stdout.String(), `"packs_before":`) ||
		!strings.Contains(stdout.String(), `"packs_after": 1`) ||
		!strings.Contains(stdout.String(), `"already_published": false`) {
		t.Fatalf(
			"compact output incomplete: stages=%d progress=%d keys=%d output=%s",
			stageCount.Load(), progressCount.Load(), keyGrantCount.Load(), stdout.String(),
		)
	}

	target := targetValue.Load().(manifest.RecoveryManifest)

	destinationArchive, err := localfs.NewClient(destinationRoot)
	if err != nil {
		t.Fatalf("open compact destination: %v", err)
	}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{
		"local-destination": destinationArchive,
	}, 1<<30)
	if err != nil {
		t.Fatalf("construct target restorer: %v", err)
	}

	restoredPath := filepath.Join(t.TempDir(), "restored.bin")
	if _, restoreErr := restorer.Restore(
		context.Background(),
		target,
		targetKey,
		restoredPath,
	); restoreErr != nil {
		t.Fatalf("restore compact target: %v", restoreErr)
	}

	restored, err := os.ReadFile(restoredPath)
	if err != nil || !bytes.Equal(restored, plaintext) {
		t.Fatalf("compact target plaintext differs: %q, err=%v", restored, err)
	}

	workspace, err := compactWorkspace(stagingDirectory, "compact-local-v1")
	if err != nil {
		t.Fatalf("resolve compact workspace: %v", err)
	}

	if _, err := os.Stat(workspace.plaintext); !os.IsNotExist(err) {
		t.Fatalf("published compact retained plaintext bridge: %v", err)
	}

	if _, err := sdk.ReadImportPlan(workspace.plan); err != nil {
		t.Fatalf("published compact lost its non-secret plan: %v", err)
	}

	stdout.Reset()
	stderr.Reset()

	if err := Run(context.Background(), arguments, &stdout, &stderr); err != nil {
		t.Fatalf("replay completed compact: %v; stderr=%s", err, stderr.String())
	}

	if stageCount.Load() != 1 || progressCount.Load() != 1 || keyGrantCount.Load() != 2 ||
		!strings.Contains(stdout.String(), `"already_published": true`) {
		t.Fatalf("compact replay repeated side effects: %s", stdout.String())
	}
}
