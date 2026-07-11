package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"slices"
	"strings"
)

const (
	// BundleSchemaVersion is Carrack's canonical gapless small-file container.
	BundleSchemaVersion = "carrack.bundle.v1"
	// BundleFooterBytes is the exact encoded V1 footer size.
	BundleFooterBytes = uint64(56)

	maximumBundleIndexBytes = 64 << 20
	maximumBundlePathBytes  = 4_096
	bundleCopyBufferBytes   = 1 << 20
	bundleFooterMagic       = "CRKBNDL1"
)

var (
	// ErrInvalidBundle indicates malformed metadata, unsafe paths, gaps, or
	// source lengths that differ from their immutable plan.
	ErrInvalidBundle = errors.New("invalid Carrack bundle")
	// ErrBundleIntegrity indicates that stored file bytes do not match the
	// bundle index.
	ErrBundleIntegrity = errors.New("carrack bundle integrity check failed")
)

// BundleSource is one exact source stream consumed by WriteBundle.
type BundleSource struct {
	Path   string
	Size   uint64
	Reader io.Reader
}

// BundleEntry maps one file to an exact contiguous range in the data region.
type BundleEntry struct {
	Path   string `json:"path"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

// BundleIndex is stored immediately after the gapless data region.
type BundleIndex struct {
	SchemaVersion string        `json:"schema_version"`
	DataBytes     uint64        `json:"data_bytes"`
	Entries       []BundleEntry `json:"entries"`
}

// BundleResult describes the exact bytes emitted by WriteBundle.
type BundleResult struct {
	Index      BundleIndex
	IndexBytes uint64
	TotalBytes uint64
}

type bundleFooter struct {
	indexOffset uint64
	indexLength uint64
	digest      [sha256.Size]byte
}

// WriteBundle concatenates sources without alignment or zero padding, then
// appends a canonical index and fixed metadata footer.
func WriteBundle(
	ctx context.Context,
	destination io.Writer,
	sources []BundleSource,
) (BundleResult, error) {
	if destination == nil || sources == nil {
		return BundleResult{}, fmt.Errorf("%w: destination and source array are required", ErrInvalidBundle)
	}

	ordered, err := validateBundleSources(sources)
	if err != nil {
		return BundleResult{}, err
	}

	index, err := writeBundleData(ctx, destination, ordered)
	if err != nil {
		return BundleResult{}, err
	}

	encoded, err := index.MarshalCanonical()
	if err != nil {
		return BundleResult{}, err
	}

	footer, err := encodeBundleFooter(index.DataBytes, encoded)
	if err != nil {
		return BundleResult{}, err
	}

	if err := writeBundleBytes(destination, encoded); err != nil {
		return BundleResult{}, fmt.Errorf("write Carrack bundle index: %w", err)
	}

	if err := writeBundleBytes(destination, footer); err != nil {
		return BundleResult{}, fmt.Errorf("write Carrack bundle footer: %w", err)
	}

	indexBytes := uint64(len(encoded))

	totalBytes, overflow := addBundleSizes(index.DataBytes, indexBytes, BundleFooterBytes)
	if overflow {
		return BundleResult{}, fmt.Errorf("%w: total size overflows uint64", ErrInvalidBundle)
	}

	return BundleResult{Index: index, IndexBytes: indexBytes, TotalBytes: totalBytes}, nil
}

// MarshalCanonical returns the stable bundle-index JSON representation.
func (index BundleIndex) MarshalCanonical() ([]byte, error) {
	if err := index.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("marshal Carrack bundle index: %w", err)
	}

	if len(encoded) > maximumBundleIndexBytes {
		return nil, fmt.Errorf("%w: index exceeds %d bytes", ErrInvalidBundle, maximumBundleIndexBytes)
	}

	return encoded, nil
}

// Validate proves that entries are canonical and cover the data region
// contiguously with zero padding bytes between files.
func (index BundleIndex) Validate() error {
	if index.SchemaVersion != BundleSchemaVersion || index.Entries == nil {
		return fmt.Errorf("%w: unsupported schema or null entries", ErrInvalidBundle)
	}

	expectedOffset := uint64(0)
	previousPath := ""

	for ordinal, entry := range index.Entries {
		if !validBundlePath(entry.Path) || (ordinal > 0 && entry.Path <= previousPath) {
			return fmt.Errorf("%w: entry %d path is unsafe, duplicate, or unordered", ErrInvalidBundle, ordinal)
		}

		if entry.Offset != expectedOffset || !validBundleDigest(entry.SHA256) {
			return fmt.Errorf("%w: entry %d introduces a gap or invalid identity", ErrInvalidBundle, ordinal)
		}

		if entry.Size > math.MaxUint64-expectedOffset {
			return fmt.Errorf("%w: entry %d range overflows", ErrInvalidBundle, ordinal)
		}

		expectedOffset += entry.Size
		previousPath = entry.Path
	}

	if index.DataBytes != expectedOffset {
		return fmt.Errorf(
			"%w: entries cover %d bytes, data region declares %d",
			ErrInvalidBundle,
			expectedOffset,
			index.DataBytes,
		)
	}

	return nil
}

// ReadBundleIndex authenticates and strictly parses the index at a bundle's
// footer. Payload bytes are not read.
func ReadBundleIndex(source io.ReaderAt, totalBytes uint64) (BundleIndex, error) {
	if source == nil || totalBytes < BundleFooterBytes || totalBytes > math.MaxInt64 {
		return BundleIndex{}, fmt.Errorf("%w: bundle size is out of range", ErrInvalidBundle)
	}

	footer := make([]byte, BundleFooterBytes)
	if err := readBundleAt(source, footer, totalBytes-BundleFooterBytes); err != nil {
		return BundleIndex{}, fmt.Errorf("read Carrack bundle footer: %w", err)
	}

	decodedFooter, err := decodeBundleFooter(footer, totalBytes)
	if err != nil {
		return BundleIndex{}, err
	}

	encoded := make([]byte, decodedFooter.indexLength)
	if readErr := readBundleAt(source, encoded, decodedFooter.indexOffset); readErr != nil {
		return BundleIndex{}, fmt.Errorf("read Carrack bundle index: %w", readErr)
	}

	actualDigest := sha256.Sum256(encoded)
	if actualDigest != decodedFooter.digest {
		return BundleIndex{}, fmt.Errorf("%w: index SHA-256 mismatch", ErrBundleIntegrity)
	}

	index, err := parseBundleIndex(encoded)
	if err != nil {
		return BundleIndex{}, err
	}

	if index.DataBytes != decodedFooter.indexOffset {
		return BundleIndex{}, fmt.Errorf("%w: footer and index data lengths differ", ErrInvalidBundle)
	}

	return index, nil
}

// ExtractBundleEntry copies and verifies one indexed file without reading
// unrelated data-region bytes.
func ExtractBundleEntry(
	ctx context.Context,
	destination io.Writer,
	source io.ReaderAt,
	index BundleIndex,
	filePath string,
) (BundleEntry, error) {
	if destination == nil || source == nil {
		return BundleEntry{}, fmt.Errorf("%w: destination and source are required", ErrInvalidBundle)
	}

	if err := index.Validate(); err != nil {
		return BundleEntry{}, err
	}

	position, found := slices.BinarySearchFunc(index.Entries, filePath, func(entry BundleEntry, target string) int {
		return strings.Compare(entry.Path, target)
	})
	if !found {
		return BundleEntry{}, fmt.Errorf("%w: path %q is not indexed", ErrInvalidBundle, filePath)
	}

	entry := index.Entries[position]

	offset, err := bundleInt64(entry.Offset)
	if err != nil {
		return BundleEntry{}, err
	}

	size, err := bundleInt64(entry.Size)
	if err != nil || size > math.MaxInt64-offset {
		return BundleEntry{}, fmt.Errorf("%w: entry range exceeds signed reader limits", ErrInvalidBundle)
	}

	section := io.NewSectionReader(source, offset, size)
	hasher := sha256.New()

	written, err := copyBundleExact(ctx, io.MultiWriter(destination, hasher), section, entry.Size)
	if err != nil {
		return BundleEntry{}, fmt.Errorf("extract Carrack bundle entry %q: %w", filePath, err)
	}

	if written != entry.Size || hex.EncodeToString(hasher.Sum(nil)) != entry.SHA256 {
		return BundleEntry{}, fmt.Errorf("%w: entry %q SHA-256 mismatch", ErrBundleIntegrity, filePath)
	}

	return entry, nil
}

func validateBundleSources(sources []BundleSource) ([]BundleSource, error) {
	ordered := slices.Clone(sources)
	slices.SortFunc(ordered, func(left, right BundleSource) int {
		return strings.Compare(left.Path, right.Path)
	})

	for index, source := range ordered {
		if source.Reader == nil || !validBundlePath(source.Path) {
			return nil, fmt.Errorf("%w: source %d has an unsafe path or nil reader", ErrInvalidBundle, index)
		}

		if index > 0 && source.Path == ordered[index-1].Path {
			return nil, fmt.Errorf("%w: duplicate source path %q", ErrInvalidBundle, source.Path)
		}
	}

	return ordered, nil
}

func writeBundleData(
	ctx context.Context,
	destination io.Writer,
	sources []BundleSource,
) (BundleIndex, error) {
	index := BundleIndex{
		SchemaVersion: BundleSchemaVersion,
		Entries:       make([]BundleEntry, 0, len(sources)),
	}

	for ordinal, source := range sources {
		hasher := sha256.New()

		written, err := copyBundleExact(ctx, io.MultiWriter(destination, hasher), source.Reader, source.Size)
		if err != nil {
			return BundleIndex{}, fmt.Errorf("write Carrack bundle source %d %q: %w", ordinal, source.Path, err)
		}

		if err := requireBundleExhausted(source.Reader); err != nil {
			return BundleIndex{}, fmt.Errorf("validate Carrack bundle source %d %q: %w", ordinal, source.Path, err)
		}

		index.Entries = append(index.Entries, BundleEntry{
			Path:   source.Path,
			Offset: index.DataBytes,
			Size:   written,
			SHA256: hex.EncodeToString(hasher.Sum(nil)),
		})

		if written > math.MaxUint64-index.DataBytes {
			return BundleIndex{}, fmt.Errorf("%w: data size overflows uint64", ErrInvalidBundle)
		}

		index.DataBytes += written
	}

	return index, nil
}

func copyBundleExact(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
	expected uint64,
) (uint64, error) {
	buffer := make([]byte, bundleCopyBufferBytes)
	written := uint64(0)

	for written < expected {
		if err := ctx.Err(); err != nil {
			return written, fmt.Errorf("copy Carrack bundle source: %w", err)
		}

		remaining := expected - written
		readLimit := min(uint64(len(buffer)), remaining)

		readBytes, readErr := source.Read(buffer[:readLimit])
		if readBytes > 0 {
			if uint64(readBytes) > remaining {
				return written, fmt.Errorf("%w: reader exceeded requested range", ErrInvalidBundle)
			}

			if err := writeBundleBytes(destination, buffer[:readBytes]); err != nil {
				return written, err
			}

			written += uint64(readBytes)
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) && written == expected {
				break
			}

			return written, fmt.Errorf("%w: source ended after %d of %d bytes: %w", ErrInvalidBundle, written, expected, readErr)
		}

		if readBytes == 0 {
			return written, io.ErrNoProgress
		}
	}

	return written, nil
}

func requireBundleExhausted(source io.Reader) error {
	var extra [1]byte

	readBytes, err := source.Read(extra[:])
	if readBytes != 0 {
		return fmt.Errorf("%w: source contains bytes beyond its declared size", ErrInvalidBundle)
	}

	if err == nil {
		return io.ErrNoProgress
	}

	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("read beyond Carrack bundle source: %w", err)
	}

	return nil
}

func encodeBundleFooter(indexOffset uint64, encodedIndex []byte) ([]byte, error) {
	indexLength := uint64(len(encodedIndex))

	footerOffset, overflow := addBundleSizes(indexOffset, indexLength)
	if overflow || footerOffset > math.MaxUint64-BundleFooterBytes {
		return nil, fmt.Errorf("%w: footer position overflows uint64", ErrInvalidBundle)
	}

	digest := sha256.Sum256(encodedIndex)
	footer := make([]byte, BundleFooterBytes)
	copy(footer[:8], bundleFooterMagic)
	binary.BigEndian.PutUint64(footer[8:16], indexOffset)
	binary.BigEndian.PutUint64(footer[16:24], indexLength)
	copy(footer[24:], digest[:])

	return footer, nil
}

func decodeBundleFooter(footer []byte, totalBytes uint64) (bundleFooter, error) {
	var decoded bundleFooter

	if len(footer) != int(BundleFooterBytes) || string(footer[:8]) != bundleFooterMagic {
		return bundleFooter{}, fmt.Errorf("%w: invalid footer magic or length", ErrInvalidBundle)
	}

	decoded.indexOffset = binary.BigEndian.Uint64(footer[8:16])
	decoded.indexLength = binary.BigEndian.Uint64(footer[16:24])
	copy(decoded.digest[:], footer[24:])

	if decoded.indexLength == 0 || decoded.indexLength > maximumBundleIndexBytes {
		return bundleFooter{}, fmt.Errorf("%w: index length is out of range", ErrInvalidBundle)
	}

	footerOffset, overflow := addBundleSizes(decoded.indexOffset, decoded.indexLength)
	if overflow || footerOffset != totalBytes-BundleFooterBytes {
		return bundleFooter{}, fmt.Errorf("%w: index and footer are not contiguous", ErrInvalidBundle)
	}

	return decoded, nil
}

func parseBundleIndex(encoded []byte) (BundleIndex, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var index BundleIndex
	if err := decoder.Decode(&index); err != nil {
		return BundleIndex{}, fmt.Errorf("%w: decode index: %w", ErrInvalidBundle, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return BundleIndex{}, fmt.Errorf("%w: trailing index JSON", ErrInvalidBundle)
	}

	if err := index.Validate(); err != nil {
		return BundleIndex{}, err
	}

	return index, nil
}

func validBundlePath(value string) bool {
	return value != "" && len(value) <= maximumBundlePathBytes && value == strings.TrimSpace(value) &&
		!strings.ContainsRune(value, '\x00') && !strings.ContainsRune(value, '\\') &&
		!strings.HasPrefix(value, "/") && path.Clean(value) == value && value != "." && value != ".." &&
		!strings.HasPrefix(value, "../")
}

func validBundleDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}

	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}

func readBundleAt(source io.ReaderAt, destination []byte, offset uint64) error {
	if offset > math.MaxInt64 || uint64(len(destination)) > math.MaxInt64-offset {
		return fmt.Errorf("%w: read range exceeds signed limits", ErrInvalidBundle)
	}

	readBytes, err := source.ReadAt(destination, int64(offset))
	if readBytes != len(destination) {
		return errors.Join(io.ErrUnexpectedEOF, err)
	}

	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read Carrack bundle range: %w", err)
	}

	return nil
}

func writeBundleBytes(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if err != nil {
			return fmt.Errorf("write Carrack bundle bytes: %w", err)
		}

		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}

		value = value[written:]
	}

	return nil
}

func addBundleSizes(values ...uint64) (uint64, bool) {
	total := uint64(0)
	for _, value := range values {
		if value > math.MaxUint64-total {
			return 0, true
		}

		total += value
	}

	return total, false
}

func bundleInt64(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%w: value exceeds signed reader limits", ErrInvalidBundle)
	}

	return int64(value), nil
}
