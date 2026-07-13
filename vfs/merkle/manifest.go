package merkle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

const blockManifestDomain = "carrack.vfs.block-manifest.v1"

// MarshalFileBlockManifest encodes one already validated FileTree into the
// canonical V1 block-manifest binary format. The manifest contains plaintext
// verification leaf digests and the resulting file root, never payload bytes,
// encryption keys, filenames, paths, or provider identities.
func MarshalFileBlockManifest(tree FileTree) ([]byte, error) {
	validated, err := RootFromFileBlocks(tree.SizeBytes, tree.BlockBytes, tree.Blocks)
	if err != nil {
		return nil, fmt.Errorf("marshal VFS block manifest: %w", err)
	}

	if validated.Root != tree.Root || validated.TreeDigest != tree.TreeDigest {
		return nil, fmt.Errorf("%w: file tree identity differs", ErrInvalidFile)
	}

	manifestBytes, err := blockManifestSize(uint64(len(tree.Blocks)))
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, 0, manifestBytes)
	encoded = append(encoded, blockManifestDomain...)
	encoded = append(encoded, 0)
	encoded = binary.BigEndian.AppendUint64(encoded, tree.SizeBytes)
	encoded = binary.BigEndian.AppendUint64(encoded, tree.BlockBytes)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(len(tree.Blocks)))

	for _, block := range tree.Blocks {
		encoded = append(encoded, block.Digest[:]...)
	}

	encoded = append(encoded, tree.Root[:]...)

	return encoded, nil
}

// ParseFileBlockManifest decodes, validates, and recomputes one canonical V1
// block manifest. It rejects unknown domains, noncanonical layout, zero leaf
// digests, a mismatching embedded root, short input, and trailing bytes.
func ParseFileBlockManifest(encoded []byte) (FileTree, error) {
	prefix := append([]byte(blockManifestDomain), 0)

	minimumBytes, err := blockManifestSize(0)
	if err != nil {
		return FileTree{}, err
	}

	if len(encoded) < minimumBytes || !bytes.Equal(encoded[:len(prefix)], prefix) {
		return FileTree{}, fmt.Errorf("%w: block manifest domain or length differs", ErrInvalidFile)
	}

	offset := len(prefix)
	sizeBytes := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	blockBytes := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	blockCount := binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8

	expectedBytes, err := blockManifestSize(blockCount)
	if err != nil || len(encoded) != expectedBytes {
		return FileTree{}, fmt.Errorf("%w: block manifest length differs", ErrInvalidFile)
	}

	if blockBytes == 0 || blockCount != expectedBlockCount(sizeBytes, blockBytes) {
		return FileTree{}, fmt.Errorf("%w: block manifest layout differs", ErrInvalidFile)
	}

	blocks := make([]FileBlock, 0, blockCount)
	for index := range blockCount {
		var digest Digest
		copy(digest[:], encoded[offset:offset+digestBytes])
		offset += digestBytes

		if digest.IsZero() {
			return FileTree{}, fmt.Errorf("%w: block %d digest is zero", ErrInvalidFile, index)
		}

		blockOffset := index * blockBytes
		blocks = append(blocks, FileBlock{
			Index:     index,
			Offset:    blockOffset,
			SizeBytes: min(blockBytes, sizeBytes-blockOffset),
			Digest:    digest,
		})
	}

	var embeddedRoot Digest
	copy(embeddedRoot[:], encoded[offset:offset+digestBytes])

	computed, err := RootFromFileBlocks(sizeBytes, blockBytes, blocks)
	if err != nil {
		return FileTree{}, fmt.Errorf("parse VFS block manifest: %w", err)
	}

	if embeddedRoot != computed.Root {
		return FileTree{}, fmt.Errorf("%w: block manifest root differs", ErrIntegrity)
	}

	return computed, nil
}

func blockManifestSize(blockCount uint64) (int, error) {
	if blockCount > MaximumFileBlocks {
		return 0, fmt.Errorf("%w: block manifest count exceeds limit", ErrInvalidFile)
	}

	const fixedBytes = len(blockManifestDomain) + 1 + 3*8 + digestBytes

	payloadBytes, overflow := blockCount*uint64(digestBytes), false
	if blockCount != 0 && payloadBytes/blockCount != digestBytes {
		overflow = true
	}

	totalBytes := uint64(fixedBytes) + payloadBytes
	if overflow || totalBytes > math.MaxInt {
		return 0, fmt.Errorf("%w: block manifest length overflows", ErrInvalidFile)
	}

	return int(totalBytes), nil
}
