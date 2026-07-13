package merkle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const goldenSchema = "carrack.vfs-merkle.golden.v1"

type goldenVectors struct {
	Schema      string                  `json:"schema"`
	Files       []goldenFileVector      `json:"files"`
	Directories []goldenDirectoryVector `json:"directories"`
}

type goldenFileVector struct {
	Name       string   `json:"name"`
	PayloadHex string   `json:"payload_hex"`
	Expected   FileTree `json:"expected"`
}

type goldenDirectoryVector struct {
	Name     string           `json:"name"`
	Entries  []DirectoryEntry `json:"entries"`
	Expected DirectoryTree    `json:"expected"`
}

func TestSharedGoldenVectors(t *testing.T) {
	t.Parallel()

	vectors := loadGoldenVectors(t)
	if vectors.Schema != goldenSchema {
		t.Fatalf("got schema %q, want %q", vectors.Schema, goldenSchema)
	}

	for _, vector := range vectors.Files {
		t.Run("file/"+vector.Name, func(t *testing.T) {
			t.Parallel()

			payload, err := hex.DecodeString(vector.PayloadHex)
			if err != nil || hex.EncodeToString(payload) != vector.PayloadHex {
				t.Fatalf("decode canonical payload: %v", err)
			}

			actual, err := BuildFileBytes(payload, vector.Expected.BlockBytes)
			if err != nil {
				t.Fatalf("build file vector: %v", err)
			}

			if !equalFileTrees(actual, vector.Expected) {
				t.Fatalf("file vector differs:\nactual:   %+v\nexpected: %+v", actual, vector.Expected)
			}
		})
	}

	for _, vector := range vectors.Directories {
		t.Run("directory/"+vector.Name, func(t *testing.T) {
			t.Parallel()

			actual, err := BuildDirectory(vector.Entries)
			if err != nil {
				t.Fatalf("build directory vector: %v", err)
			}

			if !equalDirectoryTrees(actual, vector.Expected) {
				t.Fatalf("directory vector differs:\nactual:   %+v\nexpected: %+v", actual, vector.Expected)
			}
		})
	}
}

func loadGoldenVectors(t *testing.T) goldenVectors {
	t.Helper()

	filePath := filepath.Join("..", "..", "testdata", "vfs-merkle-v1.json")

	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read shared Merkle vectors: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var vectors goldenVectors
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatalf("decode shared Merkle vectors: %v", err)
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("decode trailing shared Merkle data: %v", err)
	}

	return vectors
}

func equalFileTrees(left, right FileTree) bool {
	return left.SizeBytes == right.SizeBytes && left.BlockBytes == right.BlockBytes &&
		left.TreeDigest == right.TreeDigest && left.Root == right.Root && slices.Equal(left.Blocks, right.Blocks)
}

func equalDirectoryTrees(left, right DirectoryTree) bool {
	return left.TreeDigest == right.TreeDigest && left.Root == right.Root && slices.Equal(left.Entries, right.Entries)
}
