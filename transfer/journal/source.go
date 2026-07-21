package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// SourceMetadata is cheap replay identity captured before and after Skydriver
// hashes a source. Version must change whenever the implementation knows bytes
// may have changed; SHA-256 verification remains authoritative.
type SourceMetadata struct {
	Kind      string
	Reference string
	Version   string
	SizeBytes uint64
}

// ReplayableSource provides exact ranges from stable caller-owned bytes.
// Implementations must allow independent concurrent ranges. One-shot streams
// must first be spooled to a protected file by a higher-level Skydriver API.
type ReplayableSource interface {
	Metadata(ctx context.Context) (SourceMetadata, error)
	OpenRange(ctx context.Context, offset, length uint64) (io.ReadCloser, error)
}

// FileSource is a replayable regular local file. The path must be canonical and
// absolute; the final path component may not be a symlink. Skydriver rehashes the
// complete source during preparation and every resumed execution.
type FileSource struct {
	filePath string
}

// NewFileSource validates path syntax. File existence and immutable identity
// are revalidated on every Metadata and OpenRange call.
func NewFileSource(filePath string) (*FileSource, error) {
	if !canonicalAbsolutePath(filePath) {
		return nil, fmt.Errorf("%w: source path must be canonical and absolute", ErrInvalidPlan)
	}

	return &FileSource{filePath: filePath}, nil
}

// Metadata returns regular-file size and modification identity without hashing.
func (source *FileSource) Metadata(ctx context.Context) (SourceMetadata, error) {
	if source == nil || source.filePath == "" {
		return SourceMetadata{}, fmt.Errorf("%w: file source is not initialized", ErrInvalidPlan)
	}

	if err := ctx.Err(); err != nil {
		return SourceMetadata{}, fmt.Errorf("inspect upload source: %w", err)
	}

	information, err := os.Lstat(source.filePath)
	if err != nil {
		return SourceMetadata{}, fmt.Errorf("inspect upload source: %w", err)
	}

	if !information.Mode().IsRegular() || information.Mode()&fs.ModeSymlink != 0 || information.Size() < 0 {
		return SourceMetadata{}, fmt.Errorf("%w: source must be a regular non-symlink file", ErrInvalidPlan)
	}

	return SourceMetadata{
		Kind:      "local-file/v1",
		Reference: source.filePath,
		Version:   fmt.Sprintf("size:%d;mtime:%d", information.Size(), information.ModTime().UnixNano()),
		SizeBytes: uint64(information.Size()), //nolint:gosec // Negative file sizes are rejected above.
	}, nil
}

// OpenRange opens one exact range from the current regular file. The transfer
// engine validates length, range SHA-256, complete SHA-256, and source metadata.
func (source *FileSource) OpenRange(
	ctx context.Context,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	metadata, err := source.Metadata(ctx)
	if err != nil {
		return nil, err
	}

	if offset > metadata.SizeBytes || length > metadata.SizeBytes-offset {
		return nil, fmt.Errorf("%w: source range exceeds current file", ErrInvalidPlan)
	}

	file, err := os.Open(source.filePath)
	if err != nil {
		return nil, fmt.Errorf("open upload source: %w", err)
	}

	information, inspectErr := file.Stat()
	if inspectErr != nil || !information.Mode().IsRegular() || information.Size() != checkedInt64(metadata.SizeBytes) {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: source changed while being opened", ErrSourceChanged),
			inspectErr,
			closeErr,
		)
	}

	return &fileRange{
		cancellation: ctx.Err,
		file:         file,
		reader:       io.NewSectionReader(file, checkedInt64(offset), checkedInt64(length)),
	}, nil
}

// BytesSource owns an immutable copy of caller-provided bytes. It supports the
// same concurrent exact-range contract as FileSource but is resumable across a
// process restart only when the caller reconstructs the same reference/bytes.
type BytesSource struct {
	reference string
	payload   []byte
	checksum  string
}

// NewBytesSource copies payload. A blank reference is replaced with a
// content-derived opaque reference safe to persist in a journal.
func NewBytesSource(reference string, payload []byte) *BytesSource {
	owned := bytes.Clone(payload)
	digest := sha256.Sum256(owned)
	checksum := hex.EncodeToString(digest[:])

	if strings.TrimSpace(reference) == "" {
		reference = "sha256:" + checksum
	}

	return &BytesSource{reference: reference, payload: owned, checksum: checksum}
}

// Metadata returns immutable in-memory identity.
func (source *BytesSource) Metadata(ctx context.Context) (SourceMetadata, error) {
	if source == nil {
		return SourceMetadata{}, fmt.Errorf("%w: bytes source is not initialized", ErrInvalidPlan)
	}

	if err := ctx.Err(); err != nil {
		return SourceMetadata{}, fmt.Errorf("inspect bytes source: %w", err)
	}

	return SourceMetadata{
		Kind:      "bytes/v1",
		Reference: source.reference,
		Version:   "sha256:" + source.checksum,
		SizeBytes: uint64(len(source.payload)),
	}, nil
}

// OpenRange returns an independent reader over the owned immutable bytes.
func (source *BytesSource) OpenRange(
	ctx context.Context,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if _, err := source.Metadata(ctx); err != nil {
		return nil, err
	}

	sizeBytes := uint64(len(source.payload))
	if offset > sizeBytes || length > sizeBytes-offset {
		return nil, fmt.Errorf("%w: bytes source range exceeds payload", ErrInvalidPlan)
	}

	return io.NopCloser(bytes.NewReader(source.payload[offset : offset+length])), nil
}

func inspectSource(
	ctx context.Context,
	source ReplayableSource,
	partBytes uint64,
) (SourceIdentity, []PlannedPart, error) {
	if source == nil {
		return SourceIdentity{}, nil, fmt.Errorf("%w: replayable source is required", ErrInvalidPlan)
	}

	before, err := source.Metadata(ctx)
	if err != nil {
		return SourceIdentity{}, nil, fmt.Errorf("inspect source before hashing: %w", err)
	}

	parts, checksum, err := hashSourceRanges(ctx, source, before.SizeBytes, partBytes)
	if err != nil {
		return SourceIdentity{}, nil, err
	}

	after, err := source.Metadata(ctx)
	if err != nil {
		return SourceIdentity{}, nil, fmt.Errorf("inspect source after hashing: %w", err)
	}

	if before != after {
		return SourceIdentity{}, nil, ErrSourceChanged
	}

	identity := SourceIdentity{
		Kind:      before.Kind,
		Reference: before.Reference,
		Version:   before.Version,
		SizeBytes: before.SizeBytes,
		Checksum:  checksum,
	}

	if err := identity.validate(); err != nil {
		return SourceIdentity{}, nil, err
	}

	return identity, parts, nil
}

func hashSourceRanges(
	ctx context.Context,
	source ReplayableSource,
	sizeBytes,
	partBytes uint64,
) ([]PlannedPart, string, error) {
	if sizeBytes == 0 {
		return []PlannedPart{}, digestBytes(nil), nil
	}

	if partBytes == 0 {
		return nil, "", fmt.Errorf("%w: part size must be positive", ErrInvalidPlan)
	}

	parts := make([]PlannedPart, 0)
	completeHasher := sha256.New()

	for offset, number := uint64(0), uint32(1); offset < sizeBytes; number++ {
		length := min(partBytes, sizeBytes-offset)

		stream, err := source.OpenRange(ctx, offset, length)
		if err != nil {
			return nil, "", fmt.Errorf("open source part %d: %w", number, err)
		}

		partHasher := sha256.New()

		written, copyErr := io.CopyN(
			io.MultiWriter(completeHasher, partHasher),
			stream,
			checkedInt64(length),
		)
		if copyErr == nil && written == checkedInt64(length) {
			copyErr = requireEOF(stream)
		}

		closeErr := stream.Close()
		if copyErr != nil || closeErr != nil {
			return nil, "", fmt.Errorf(
				"%w: hash source part %d: %w",
				ErrTransferIntegrity,
				number,
				errors.Join(copyErr, closeErr),
			)
		}

		parts = append(parts, PlannedPart{
			Number:   number,
			Offset:   offset,
			Length:   length,
			Checksum: hex.EncodeToString(partHasher.Sum(nil)),
		})
		offset += length
	}

	return parts, hex.EncodeToString(completeHasher.Sum(nil)), nil
}

type fileRange struct {
	cancellation func() error
	file         *os.File
	reader       *io.SectionReader
}

func (stream *fileRange) Read(buffer []byte) (int, error) {
	if err := stream.cancellation(); err != nil {
		return 0, fmt.Errorf("read upload source: %w", err)
	}

	readBytes, err := stream.reader.Read(buffer)
	if err == nil {
		return readBytes, nil
	}

	if errors.Is(err, io.EOF) {
		return readBytes, io.EOF
	}

	return readBytes, fmt.Errorf("read upload source: %w", err)
}

func (stream *fileRange) Close() error {
	if err := stream.file.Close(); err != nil {
		return fmt.Errorf("close upload source: %w", err)
	}

	return nil
}

func requireEOF(reader io.Reader) error {
	var extra [1]byte

	extraBytes, err := io.ReadFull(reader, extra[:])
	if extraBytes != 0 || err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: source range contains trailing bytes: %w", ErrTransferIntegrity, err)
	}

	return nil
}

func checkedInt64(value uint64) int64 {
	return int64(value) //nolint:gosec // Planners reject object and range sizes above math.MaxInt64.
}
