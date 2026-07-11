// Package manifest defines Carrack's versioned archive index format.
package manifest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/dravengarden/carrack/archive"
)

// SchemaVersion is the only manifest version understood by this package.
const SchemaVersion = "carrack.manifest.v1"

// ErrInvalidManifest indicates a malformed or internally inconsistent manifest.
var ErrInvalidManifest = errors.New("invalid Carrack manifest")

// Manifest maps one immutable logical object to content-addressed blocks.
type Manifest struct {
	SchemaVersion   string         `json:"schema_version"`
	ObjectID        string         `json:"object_id"`
	SourceURI       string         `json:"source_uri"`
	PlaintextSize   uint64         `json:"plaintext_size"`
	PlaintextSHA256 string         `json:"plaintext_sha256,omitempty"`
	Layout          archive.Layout `json:"layout"`
	Blocks          []Block        `json:"blocks"`
}

// Block describes one encrypted physical block and its plaintext position.
type Block struct {
	Ordinal          uint64 `json:"ordinal"`
	PlaintextOffset  uint64 `json:"plaintext_offset"`
	PlaintextSize    uint64 `json:"plaintext_size"`
	CiphertextSize   uint64 `json:"ciphertext_size"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	StorageKey       string `json:"storage_key"`
}

// Validate checks the manifest's canonical form, ordering, and coverage.
func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version %q", ErrInvalidManifest, manifest.SchemaVersion)
	}

	if manifest.ObjectID == "" {
		return fmt.Errorf("%w: object ID is required", ErrInvalidManifest)
	}

	if manifest.SourceURI == "" {
		return fmt.Errorf("%w: source URI is required", ErrInvalidManifest)
	}

	if err := manifest.Layout.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}

	if manifest.PlaintextSHA256 != "" && !validSHA256(manifest.PlaintextSHA256) {
		return fmt.Errorf("%w: plaintext SHA-256 must be 64 lowercase hexadecimal characters", ErrInvalidManifest)
	}

	expectedOffset := uint64(0)

	for index, block := range manifest.Blocks {
		if err := validateBlock(block, uint64(index), expectedOffset, manifest.Layout.PhysicalBlockBytes); err != nil {
			return err
		}

		expectedOffset += block.PlaintextSize
	}

	if expectedOffset != manifest.PlaintextSize {
		return fmt.Errorf(
			"%w: blocks cover %d plaintext bytes, expected %d",
			ErrInvalidManifest,
			expectedOffset,
			manifest.PlaintextSize,
		)
	}

	return nil
}

func validateBlock(block Block, expectedOrdinal, expectedOffset, maximumSize uint64) error {
	if block.Ordinal != expectedOrdinal {
		return fmt.Errorf("%w: block ordinal %d must be %d", ErrInvalidManifest, block.Ordinal, expectedOrdinal)
	}

	if block.PlaintextOffset != expectedOffset {
		return fmt.Errorf("%w: block %d plaintext offset must be %d", ErrInvalidManifest, block.Ordinal, expectedOffset)
	}

	if block.PlaintextSize == 0 || block.PlaintextSize > maximumSize {
		return fmt.Errorf("%w: block %d plaintext size is out of range", ErrInvalidManifest, block.Ordinal)
	}

	if block.CiphertextSize == 0 {
		return fmt.Errorf("%w: block %d ciphertext size must be positive", ErrInvalidManifest, block.Ordinal)
	}

	if !validSHA256(block.CiphertextSHA256) {
		return fmt.Errorf("%w: block %d has a non-canonical SHA-256", ErrInvalidManifest, block.Ordinal)
	}

	if block.StorageKey == "" {
		return fmt.Errorf("%w: block %d storage key is required", ErrInvalidManifest, block.Ordinal)
	}

	return nil
}

func validSHA256(value string) bool {
	if len(value) != hex.EncodedLen(32) || value != strings.ToLower(value) {
		return false
	}

	decoded, err := hex.DecodeString(value)

	return err == nil && len(decoded) == 32
}
