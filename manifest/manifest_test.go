package manifest_test

import (
	"errors"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/manifest"
)

const blockHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestManifestValidatesContiguousBlocks(t *testing.T) {
	t.Parallel()

	value := validManifest()

	if err := value.Validate(); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
}

func TestManifestRejectsBlockGap(t *testing.T) {
	t.Parallel()

	value := validManifest()
	value.Blocks[1].PlaintextOffset = 9

	err := value.Validate()

	if !errors.Is(err, manifest.ErrInvalidManifest) {
		t.Fatalf("expected ErrInvalidManifest, got %v", err)
	}
}

func validManifest() manifest.Manifest {
	return manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		ObjectID:      "object-1",
		SourceURI:     "s3://example/source",
		PlaintextSize: 10,
		Layout: archive.Layout{
			PhysicalBlockBytes: 8,
			CryptoFrameBytes:   2,
			LogicalPackBytes:   16,
		},
		Blocks: []manifest.Block{
			{
				Ordinal:          0,
				PlaintextOffset:  0,
				PlaintextSize:    8,
				CiphertextSize:   9,
				CiphertextSHA256: blockHash,
				StorageKey:       "blocks/01/23/0123",
			},
			{
				Ordinal:          1,
				PlaintextOffset:  8,
				PlaintextSize:    2,
				CiphertextSize:   3,
				CiphertextSHA256: blockHash,
				StorageKey:       "blocks/01/23/0123-copy",
			},
		},
	}
}
