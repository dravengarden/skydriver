package merkle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	fileLeafDomain  = "skydriver.vfs.file.leaf.v1"
	fileEmptyDomain = "skydriver.vfs.file.empty.v1"
	fileNodeDomain  = "skydriver.vfs.file.node.v1"
	fileRootDomain  = "skydriver.vfs.file.root.v1"

	// MaximumFileBlocks bounds retained verification metadata and tree work.
	MaximumFileBlocks = uint64(1_000_000)
)

// FileBlock is one exact plaintext verification range and leaf digest. Blocks
// are integrity and transfer units, never independently addressable VFS data.
type FileBlock struct {
	Index     uint64 `json:"index"`
	Offset    uint64 `json:"offset"`
	SizeBytes uint64 `json:"size_bytes"`
	Digest    Digest `json:"digest"`
}

// FileTree commits to exact file length, canonical block layout, every leaf,
// and the complete root. Returned Blocks are in ascending gapless order.
type FileTree struct {
	SizeBytes  uint64      `json:"size_bytes"`
	BlockBytes uint64      `json:"block_bytes"`
	Blocks     []FileBlock `json:"blocks"`
	TreeDigest Digest      `json:"tree_digest"`
	Root       Digest      `json:"root"`
}

// BuildFile consumes exactly sizeBytes, hashes canonical blocks, rejects short
// or trailing input, and checks ctx throughout streaming I/O. The reader is not
// closed. Empty files are valid and still require an empty reader.
func BuildFile(
	ctx context.Context,
	reader io.Reader,
	sizeBytes,
	blockBytes uint64,
) (FileTree, error) {
	if ctx == nil || reader == nil {
		return FileTree{}, fmt.Errorf("%w: context and reader are required", ErrInvalidFile)
	}

	if err := validateFileLayout(sizeBytes, blockBytes); err != nil {
		return FileTree{}, err
	}

	blocks := make([]FileBlock, 0, expectedBlockCount(sizeBytes, blockBytes))
	checkedReader := &contextReader{cancellation: ctx.Err, reader: reader}

	for offset, index := uint64(0), uint64(0); offset < sizeBytes; index++ {
		length := min(blockBytes, sizeBytes-offset)

		digest, err := hashReaderBlock(checkedReader, index, length)
		if err != nil {
			return FileTree{}, err
		}

		blocks = append(blocks, FileBlock{
			Index:     index,
			Offset:    offset,
			SizeBytes: length,
			Digest:    digest,
		})
		offset += length
	}

	if err := requireReaderEOF(checkedReader); err != nil {
		return FileTree{}, err
	}

	return RootFromFileBlocks(sizeBytes, blockBytes, blocks)
}

// BuildFileBytes computes a canonical tree over an owned byte slice.
func BuildFileBytes(payload []byte, blockBytes uint64) (FileTree, error) {
	return BuildFile(context.Background(), bytes.NewReader(payload), uint64(len(payload)), blockBytes)
}

// HashFileBlock computes one canonical leaf digest for independently verified
// plaintext bytes. The ordinal is zero-based.
func HashFileBlock(index uint64, payload []byte) Digest {
	hasher := newDomainHasher(fileLeafDomain)
	writeUint64(hasher, index)
	writeUint64(hasher, uint64(len(payload)))
	writeHash(hasher, payload)

	return finishDigest(hasher)
}

// RootFromFileBlocks validates canonical block metadata and derives the tree
// and file root without re-reading payload bytes.
func RootFromFileBlocks(
	sizeBytes,
	blockBytes uint64,
	blocks []FileBlock,
) (FileTree, error) {
	if err := validateFileLayout(sizeBytes, blockBytes); err != nil {
		return FileTree{}, err
	}

	expectedBlocks := expectedBlockCount(sizeBytes, blockBytes)
	if uint64(len(blocks)) != expectedBlocks {
		return FileTree{}, fmt.Errorf("%w: block count differs from canonical layout", ErrInvalidFile)
	}

	leaves := make([]Digest, len(blocks))
	for index, block := range blocks {
		expectedOffset := uint64(index) * blockBytes
		expectedLength := min(blockBytes, sizeBytes-expectedOffset)

		if block.Index != uint64(index) || block.Offset != expectedOffset ||
			block.SizeBytes != expectedLength || block.Digest.IsZero() {
			return FileTree{}, fmt.Errorf("%w: block %d is not canonical", ErrInvalidFile, index)
		}

		leaves[index] = block.Digest
	}

	treeDigest := hashEmpty(fileEmptyDomain)
	if len(leaves) != 0 {
		treeDigest = buildCanonicalTree(fileNodeDomain, leaves, 0)
	}

	rootHasher := newDomainHasher(fileRootDomain)
	writeUint64(rootHasher, blockBytes)
	writeUint64(rootHasher, sizeBytes)
	writeUint64(rootHasher, uint64(len(blocks)))
	writeHash(rootHasher, treeDigest[:])

	return FileTree{
		SizeBytes:  sizeBytes,
		BlockBytes: blockBytes,
		Blocks:     append([]FileBlock(nil), blocks...),
		TreeDigest: treeDigest,
		Root:       finishDigest(rootHasher),
	}, nil
}

func validateFileLayout(sizeBytes, blockBytes uint64) error {
	if blockBytes == 0 {
		return fmt.Errorf("%w: verification block size must be positive", ErrInvalidFile)
	}

	if sizeBytes > math.MaxInt64 || blockBytes > math.MaxInt64 {
		return fmt.Errorf("%w: file or block exceeds streaming limit", ErrInvalidFile)
	}

	if expectedBlockCount(sizeBytes, blockBytes) > MaximumFileBlocks {
		return fmt.Errorf("%w: file exceeds maximum verification block count", ErrInvalidFile)
	}

	return nil
}

func expectedBlockCount(sizeBytes, blockBytes uint64) uint64 {
	if sizeBytes == 0 {
		return 0
	}

	return 1 + (sizeBytes-1)/blockBytes
}

func hashReaderBlock(reader io.Reader, index, length uint64) (Digest, error) {
	hasher := newDomainHasher(fileLeafDomain)
	writeUint64(hasher, index)
	writeUint64(hasher, length)

	written, err := io.CopyN(hasher, reader, int64(length)) //nolint:gosec // Layout validation bounds length.
	if err != nil || written != int64(length) {             //nolint:gosec // Layout validation bounds length.
		return Digest{}, fmt.Errorf(
			"%w: block %d ended after %d of %d bytes: %w",
			ErrIntegrity,
			index,
			written,
			length,
			err,
		)
	}

	return finishDigest(hasher), nil
}

func requireReaderEOF(reader io.Reader) error {
	var extra [1]byte

	readBytes, err := reader.Read(extra[:])
	if readBytes != 0 || err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: file contains bytes beyond declared length: %w", ErrIntegrity, err)
	}

	return nil
}

type contextReader struct {
	cancellation func() error
	reader       io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.cancellation(); err != nil {
		return 0, fmt.Errorf("hash VFS file: %w", err)
	}

	readBytes, err := reader.reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		return readBytes, fmt.Errorf("read VFS file: %w", err)
	}

	return readBytes, err //nolint:wrapcheck // io.Reader consumers require the exact io.EOF sentinel.
}
