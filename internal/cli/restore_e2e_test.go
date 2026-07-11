package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	"github.com/dravengarden/carrack/sdk"
)

func TestRestoreCommandEndToEnd(t *testing.T) {
	plaintext := []byte("ok")
	recovery, epochKey, ciphertext := cliRestoreFixture(t, plaintext)
	operationID := "303132333435363738393a3b3c3d3e3f"
	incarnation := "505152535455565758595a5b5c5d5e5f"

	var keyGrants atomic.Uint64

	var progressReports atomic.Uint64

	aliyun := newFakeAliyunRestore(t, ciphertext)
	aliyunServer := httptest.NewServer(aliyun)
	aliyun.url = aliyunServer.URL
	t.Cleanup(aliyunServer.Close)

	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/restores":
			writeCLIJSON(t, response, sdk.RestoreOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID, Kind: "restore",
				State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1,
				UsefulBytesTotal: uint64(len(plaintext)), VersionID: "version-1",
				ObjectID: recovery.Manifest.ObjectID, Generation: recovery.Manifest.Generation,
				ManifestSHA256: recovery.ManifestSHA256, CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/restores/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.RestoreReadLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/read",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
				VersionID: "version-1", ManifestSHA256: recovery.ManifestSHA256,
			})
		case "/api/v1/restores/" + operationID + "/manifest":
			writeCLIJSON(t, response, recovery)
		case "/api/v1/restores/" + operationID + "/key":
			keyGrants.Add(1)
			writeCLIJSON(t, response, map[string]any{
				"operation_id": operationID, "manifest_sha256": recovery.ManifestSHA256,
				"root_version": recovery.Manifest.Crypto.RootVersion,
				"key_epoch":    recovery.Manifest.Crypto.KeyEpoch,
				"epoch_key":    base64.RawURLEncoding.EncodeToString(epochKey[:]),
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
				t.Errorf("decode CLI progress: %v", err)

				return
			}

			writeCLIJSON(t, response, sdk.ProgressSnapshot{
				ComponentID: operationID + "/restore", Attempt: 1,
				Sequence: sample.Sequence, WireBytesRead: sample.WireBytesRead,
				UsefulBytesVerified: sample.UsefulBytesVerified,
				ActiveNanoseconds:   sample.ActiveNanoseconds, Disposition: "current",
			})
		case "/api/v1/restores/" + operationID + "/complete":
			writeCLIJSON(t, response, sdk.CompletedRestore{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)

	t.Setenv(controlTokenEnvironment, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	t.Setenv(epochKeyEnvironment, "")
	t.Setenv(aliyunTokenEnvironment, "access-token")
	t.Setenv(aliyunRefreshEnvironment, "")

	destination := filepath.Join(t.TempDir(), "restored.bin")

	var stdout bytes.Buffer

	var stderr bytes.Buffer

	err := Run(context.Background(), []string{
		"restore", destination,
		"--control-url", control.URL,
		"--namespace", recovery.Manifest.NamespaceID,
		"--manifest", recovery.ManifestSHA256,
		"--driver-id", "aliyun-main",
		"--aliyun-api-base-url", aliyunServer.URL,
		"--format", "json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("execute restore command: %v; stderr=%s", err, stderr.String())
	}

	restored, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read CLI restore output: %v", err)
	}

	if !bytes.Equal(restored, plaintext) {
		t.Fatalf("CLI restored %q, want %q", restored, plaintext)
	}

	if keyGrants.Load() != 1 || progressReports.Load() == 0 || !strings.Contains(stdout.String(), `"state": "succeeded"`) {
		t.Fatalf("CLI did not complete full control protocol: grants=%d progress=%d output=%s", keyGrants.Load(), progressReports.Load(), stdout.String())
	}
}

type fakeAliyunRestore struct {
	testing    *testing.T
	url        string
	ciphertext []byte
}

func newFakeAliyunRestore(t *testing.T, ciphertext []byte) *fakeAliyunRestore {
	t.Helper()

	return &fakeAliyunRestore{testing: t, ciphertext: ciphertext}
}

func (server *fakeAliyunRestore) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	server.testing.Helper()

	if strings.HasPrefix(request.URL.Path, "/adrive/") && request.Header.Get("Authorization") != "Bearer access-token" {
		server.testing.Errorf("Aliyun request omitted access token: %s", request.URL.Path)
	}

	switch request.URL.Path {
	case "/adrive/v1.0/user/getDriveInfo":
		writeCLIJSON(server.testing, response, map[string]string{"resource_drive_id": "drive-1"})
	case "/adrive/v1.0/openFile/list":
		writeCLIJSON(server.testing, response, map[string]any{
			"items": []map[string]any{{
				"file_id": "file-1", "name": "payload.bin", "size": len(server.ciphertext),
				"content_hash": "sha1", "type": "file",
			}},
			"next_marker": "",
		})
	case "/adrive/v1.0/openFile/getDownloadUrl":
		writeCLIJSON(server.testing, response, map[string]string{"url": server.url + "/download"})
	case "/download":
		expectedRange := fmt.Sprintf("bytes=0-%d", len(server.ciphertext)-1)
		if request.Header.Get("Range") != expectedRange {
			server.testing.Errorf("download range is %q, want %q", request.Header.Get("Range"), expectedRange)
		}

		response.WriteHeader(http.StatusPartialContent)
		_, _ = response.Write(server.ciphertext)
	default:
		http.NotFound(response, request)
	}
}

func cliRestoreFixture(
	t *testing.T,
	plaintext []byte,
) (manifest.RecoveryManifest, cryptostream.EpochKey, []byte) {
	t.Helper()

	var (
		namespaceID cryptostream.Identifier
		packID      cryptostream.Identifier
	)

	for index := range namespaceID {
		namespaceID[index] = byte(0x20 + index)
		packID[index] = byte(0x40 + index)
	}

	var epochKey cryptostream.EpochKey

	for index := range epochKey {
		epochKey[index] = byte(index + 1)
	}

	descriptor := cryptostream.Descriptor{
		Suite: cryptostream.SuiteAES128GCMHKDFSHA256V1, RootVersion: 1,
		NamespaceID: namespaceID, EpochID: 7, PackID: packID,
		FrameBytes: 2, PlaintextBytes: uint64(len(plaintext)),
	}

	packKey, err := cryptostream.DerivePackKey(epochKey, packID)
	if err != nil {
		t.Fatalf("derive CLI fixture pack key: %v", err)
	}

	packCipher, err := cryptostream.NewCipher(packKey, descriptor)
	if err != nil {
		t.Fatalf("construct CLI fixture cipher: %v", err)
	}

	var encrypted bytes.Buffer

	if _, sealErr := packCipher.SealFrames(context.Background(), &encrypted, bytes.NewReader(plaintext), 0, 1); sealErr != nil {
		t.Fatalf("encrypt CLI fixture: %v", sealErr)
	}

	ciphertext := encrypted.Bytes()
	plaintextDigest := sha256.Sum256(plaintext)
	ciphertextDigest := sha256.Sum256(ciphertext)
	digestHex := hex.EncodeToString(ciphertextDigest[:])

	content := manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion, NamespaceID: hex.EncodeToString(namespaceID[:]),
		ObjectID: "cli-object", Generation: 1, PlaintextSize: uint64(len(plaintext)),
		PlaintextSHA256: hex.EncodeToString(plaintextDigest[:]),
		Layout:          archive.Layout{PhysicalBlockBytes: 2, CryptoFrameBytes: 2, LogicalPackBytes: 2},
		Crypto:          manifest.Crypto{Suite: descriptor.Suite, RootVersion: 1, KeyEpoch: 7},
		Packs: []manifest.Pack{{
			Ordinal: 0, PackID: hex.EncodeToString(packID[:]), PlaintextSize: uint64(len(plaintext)),
			CiphertextSize: uint64(len(ciphertext)), CiphertextSHA256: digestHex,
			Extents: []manifest.Extent{{
				Ordinal: 0, FrameCount: 1, CiphertextSize: uint64(len(ciphertext)),
				CiphertextSHA256: digestHex,
			}},
		}},
	}

	recovery, err := manifest.NewRecoveryManifest(content, []manifest.Location{{
		ExtentSHA256: digestHex, DriverID: "aliyun-main", StorageKey: "payload.bin",
		Length: uint64(len(ciphertext)),
	}})
	if err != nil {
		t.Fatalf("construct CLI recovery manifest: %v", err)
	}

	return recovery, epochKey, bytes.Clone(ciphertext)
}

func writeCLIJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Errorf("encode CLI test response: %v", err)
	}
}
