package merkle

import (
	"bytes"
	"testing"
)

func TestFileBlockManifestRoundTrip(t *testing.T) {
	t.Parallel()

	tree, err := BuildFileBytes([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 4)
	if err != nil {
		t.Fatalf("build file: %v", err)
	}

	encoded, err := MarshalFileBlockManifest(tree)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	parsed, err := ParseFileBlockManifest(encoded)
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	if parsed.Root != tree.Root || parsed.TreeDigest != tree.TreeDigest ||
		!bytes.Equal(encoded[:len(blockManifestDomain)+1], append([]byte(blockManifestDomain), 0)) {
		t.Fatalf("round trip differs: parsed=%+v tree=%+v", parsed, tree)
	}
}

func TestFileBlockManifestRejectsCorruptionAndTrailingBytes(t *testing.T) {
	t.Parallel()

	tree, err := BuildFileBytes([]byte("abc"), 4)
	if err != nil {
		t.Fatalf("build file: %v", err)
	}

	encoded, err := MarshalFileBlockManifest(tree)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	tests := map[string][]byte{
		"short":        encoded[:len(encoded)-1],
		"trailing":     append(bytes.Clone(encoded), 0),
		"wrong domain": append([]byte{'x'}, encoded[1:]...),
		"wrong leaf": func() []byte {
			changed := bytes.Clone(encoded)
			changed[len(blockManifestDomain)+1+3*8] ^= 1

			return changed
		}(),
		"wrong root": func() []byte {
			changed := bytes.Clone(encoded)
			changed[len(changed)-1] ^= 1

			return changed
		}(),
	}

	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseFileBlockManifest(candidate); err == nil {
				t.Fatal("expected malformed manifest rejection")
			}
		})
	}
}

func TestEmptyFileBlockManifestIsCanonical(t *testing.T) {
	t.Parallel()

	tree, err := BuildFileBytes(nil, 4)
	if err != nil {
		t.Fatalf("build empty file: %v", err)
	}

	encoded, err := MarshalFileBlockManifest(tree)
	if err != nil {
		t.Fatalf("marshal empty manifest: %v", err)
	}

	parsed, err := ParseFileBlockManifest(encoded)
	if err != nil {
		t.Fatalf("parse empty manifest: %v", err)
	}

	if parsed.Root != tree.Root || len(parsed.Blocks) != 0 {
		t.Fatalf("empty manifest differs: %+v", parsed)
	}
}
