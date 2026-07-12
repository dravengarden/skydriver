package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestVerifyCommandStreamsLocalCiphertextEvidence(t *testing.T) {
	base, _, ciphertext := cliRestoreFixture(t, []byte("ok"))

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{{
		ExtentSHA256: base.Manifest.Packs[0].Extents[0].CiphertextSHA256,
		DriverID:     "local-archive", StorageKey: "payload.bin", Length: uint64(len(ciphertext)),
	}})
	if err != nil {
		t.Fatalf("construct verification recovery: %v", err)
	}

	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal verification recovery: %v", err)
	}

	root := t.TempDir()

	manifestPath := filepath.Join(t.TempDir(), "recovery.json")
	if err := os.WriteFile(filepath.Join(root, "payload.bin"), ciphertext, 0o600); err != nil {
		t.Fatalf("write local ciphertext: %v", err)
	}

	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatalf("write recovery manifest: %v", err)
	}

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"verify", manifestPath, "--local-driver-id", "local-archive", "--local-root", root, "--format", "json"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run verification command: %v", err)
	}

	var result sdk.VerificationResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode verification output: %v", err)
	}

	if result.State != sdk.VerificationHealthy || result.Verified != 1 || len(result.Evidence) != 1 {
		t.Fatalf("unexpected verification result: %+v", result)
	}
}

func TestVerifyRunCommandCommitsFencedLocalEvidence(t *testing.T) {
	base, _, ciphertext := cliRestoreFixture(t, []byte("ok"))

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{{
		ExtentSHA256: base.Manifest.Packs[0].Extents[0].CiphertextSHA256,
		DriverID:     "local-archive", StorageKey: "payload.bin", Length: uint64(len(ciphertext)),
	}})
	if err != nil {
		t.Fatalf("construct controlled verification recovery: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload.bin"), ciphertext, 0o600); err != nil {
		t.Fatalf("write controlled verification ciphertext: %v", err)
	}

	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/verifications":
			value = sdk.VerifyOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "verify", State: "planned", Phase: "planned", RequestedBy: "cli-client",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(ciphertext)),
				VersionID: "version-1", ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 1, DriverID: "local-archive", CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/verifications/" + operationID + "/manifest":
			value = recovery
		case "/api/v1/verifications/" + operationID + "/complete":
			value = sdk.CompletedVerify{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", Verified: 1,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode controlled verification response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv(controlTokenEnvironment, token)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{
		"verify", "run", "--control-url", server.URL,
		"--namespace", recovery.Manifest.NamespaceID,
		"--manifest", recovery.ManifestSHA256,
		"--local-driver-id", "local-archive", "--local-root", root,
		"--idempotency-key", "cli-verify-local-archive-1", "--format", "json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run controlled verification command: %v", err)
	}

	var result struct {
		Completion sdk.CompletedVerify `json:"completion"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode controlled verification output: %v", err)
	}

	if result.Completion.State != "succeeded" || result.Completion.Verified != 1 {
		t.Fatalf("unexpected controlled verification result: %+v", result)
	}
}
