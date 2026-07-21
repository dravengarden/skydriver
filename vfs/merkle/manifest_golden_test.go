package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type blockManifestGoldenVectors struct {
	Schema    string                      `json:"schema"`
	Manifests []blockManifestGoldenVector `json:"manifests"`
}

type blockManifestGoldenVector struct {
	Name        string `json:"name"`
	ManifestHex string `json:"manifest_hex"`
	SHA256      string `json:"sha256"`
	SizeBytes   uint64 `json:"size_bytes"`
	BlockBytes  uint64 `json:"block_bytes"`
	BlockCount  uint64 `json:"block_count"`
	FileRoot    Digest `json:"file_root"`
}

func TestSharedBlockManifestGoldenVectors(t *testing.T) {
	t.Parallel()

	encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vfs-block-manifest-v1.json"))
	if err != nil {
		t.Fatalf("read block-manifest vectors: %v", err)
	}

	var vectors blockManifestGoldenVectors
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatalf("decode block-manifest vectors: %v", err)
	}

	if vectors.Schema != "skydriver.vfs-block-manifest.golden.v1" {
		t.Fatalf("unexpected schema %q", vectors.Schema)
	}

	for _, vector := range vectors.Manifests {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			manifest, err := hex.DecodeString(vector.ManifestHex)
			if err != nil {
				t.Fatalf("decode manifest: %v", err)
			}

			if actual := sha256.Sum256(manifest); hex.EncodeToString(actual[:]) != vector.SHA256 {
				t.Fatalf("manifest SHA-256 differs: %x", actual)
			}

			tree, err := ParseFileBlockManifest(manifest)
			if err != nil {
				t.Fatalf("parse manifest: %v", err)
			}

			if tree.SizeBytes != vector.SizeBytes || tree.BlockBytes != vector.BlockBytes ||
				uint64(len(tree.Blocks)) != vector.BlockCount || tree.Root != vector.FileRoot {
				t.Fatalf("manifest identity differs: %+v", tree)
			}

			remarshaled, err := MarshalFileBlockManifest(tree)
			if err != nil {
				t.Fatalf("remarshal manifest: %v", err)
			}

			if hex.EncodeToString(remarshaled) != vector.ManifestHex {
				t.Fatal("manifest encoding is not canonical")
			}
		})
	}
}
