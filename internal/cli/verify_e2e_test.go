package cli

import (
	"bytes"
	"context"
	"encoding/json"
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
