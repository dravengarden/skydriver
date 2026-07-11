package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

var (
	// ErrInvalidRestore indicates an invalid restore dependency or destination.
	ErrInvalidRestore = errors.New("invalid Carrack restore")
	// ErrRestoreIntegrity indicates that authenticated chunks did not produce the pinned plaintext.
	ErrRestoreIntegrity = errors.New("carrack restore plaintext integrity check failed")
)

// Restorer downloads, authenticates, and atomically publishes local plaintext.
type Restorer struct {
	fetcher *transfer.Fetcher
}

// RestoreResult describes a completely verified local publication.
type RestoreResult struct {
	ManifestSHA256 string
	Destination    string
	PlaintextBytes uint64
	ResumedExtents uint64
	FetchedExtents uint64
}

// RestoreProgress contains cumulative local and provider counters.
type RestoreProgress struct {
	WireBytesRead       uint64
	UsefulBytesVerified uint64
	ActiveNanoseconds   uint64
	RetryCount          uint64
}

// RestoreProgressObserver receives one cumulative sample per verified extent.
type RestoreProgressObserver func(RestoreProgress)

type restoreJournal struct {
	SchemaVersion  string                  `json:"schema_version"`
	ManifestSHA256 string                  `json:"manifest_sha256"`
	PlaintextSize  uint64                  `json:"plaintext_size"`
	Completed      map[string]restoredSpan `json:"completed"`
}

type restoredSpan struct {
	Offset          uint64 `json:"offset"`
	Length          uint64 `json:"length"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
}

const restoreJournalVersion = "carrack.restore-journal.v1"

// NewRestorer constructs a bounded-memory restore client.
func NewRestorer(readers map[string]provider.Reader, maximumExtentBytes uint64) (*Restorer, error) {
	fetcher, err := transfer.NewFetcher(readers, maximumExtentBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRestore, err)
	}

	return &Restorer{fetcher: fetcher}, nil
}

// Restore pins the supplied immutable recovery manifest and atomically replaces
// destination only after every ciphertext, frame, and plaintext identity passes.
func (restorer *Restorer) Restore(
	ctx context.Context,
	recovery manifest.RecoveryManifest,
	epochKey cryptostream.EpochKey,
	destination string,
) (RestoreResult, error) {
	return restorer.RestoreWithProgress(ctx, recovery, epochKey, destination, nil)
}

// RestoreWithProgress performs Restore and observes cumulative verified extents.
//
//nolint:cyclop,funlen,gocognit,gocyclo // The ordered verification and publication protocol is intentionally explicit.
func (restorer *Restorer) RestoreWithProgress(
	ctx context.Context,
	recovery manifest.RecoveryManifest,
	epochKey cryptostream.EpochKey,
	destination string,
	observer RestoreProgressObserver,
) (RestoreResult, error) {
	if restorer == nil || restorer.fetcher == nil || destination == "" {
		return RestoreResult{}, fmt.Errorf("%w: restorer and destination are required", ErrInvalidRestore)
	}

	if err := recovery.Validate(); err != nil {
		return RestoreResult{}, fmt.Errorf("%w: %w", ErrInvalidRestore, err)
	}

	destination, err := filepath.Abs(destination)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("%w: resolve destination: %w", ErrInvalidRestore, err)
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(destination), 0o750); mkdirErr != nil {
		return RestoreResult{}, fmt.Errorf("create restore directory: %w", mkdirErr)
	}

	plaintextSize, err := restoreFileOffset(recovery.Manifest.PlaintextSize)
	if err != nil {
		return RestoreResult{}, err
	}

	partPath := destination + ".carrack-restore.part"
	journalPath := destination + ".carrack-restore.json"

	journal, err := loadRestoreJournal(journalPath, recovery)
	if err != nil {
		return RestoreResult{}, err
	}

	// #nosec G304 -- both paths are derived from the caller-selected restore destination.
	output, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return RestoreResult{}, fmt.Errorf("open restore staging file: %w", err)
	}

	defer func() {
		closeErr := output.Close()
		_ = closeErr
	}()

	if truncateErr := output.Truncate(plaintextSize); truncateErr != nil {
		return RestoreResult{}, fmt.Errorf("size restore staging file: %w", truncateErr)
	}

	locations := indexRestoreLocations(recovery.Locations)

	namespaceID, err := parseCryptoIdentifier(recovery.Manifest.NamespaceID)
	if err != nil {
		return RestoreResult{}, err
	}

	result := RestoreResult{ManifestSHA256: recovery.ManifestSHA256, Destination: destination, PlaintextBytes: recovery.Manifest.PlaintextSize}
	started := time.Now()
	progress := RestoreProgress{}

	for _, pack := range recovery.Manifest.Packs {
		packID, parseErr := parseCryptoIdentifier(pack.PackID)
		if parseErr != nil {
			return RestoreResult{}, parseErr
		}

		packKey, deriveErr := cryptostream.DerivePackKey(epochKey, packID)
		if deriveErr != nil {
			return RestoreResult{}, fmt.Errorf("derive restore pack %d key: %w", pack.Ordinal, deriveErr)
		}

		packCipher, cipherErr := cryptostream.NewCipher(packKey, cryptostream.Descriptor{
			Suite: recovery.Manifest.Crypto.Suite, RootVersion: recovery.Manifest.Crypto.RootVersion,
			NamespaceID: namespaceID, EpochID: recovery.Manifest.Crypto.KeyEpoch, PackID: packID,
			FrameBytes: recovery.Manifest.Layout.CryptoFrameBytes, PlaintextBytes: pack.PlaintextSize,
		})
		if cipherErr != nil {
			return RestoreResult{}, fmt.Errorf("construct restore pack %d cipher: %w", pack.Ordinal, cipherErr)
		}

		for _, extent := range pack.Extents {
			plaintextOffset := pack.PlaintextOffset + extent.FirstFrame*recovery.Manifest.Layout.CryptoFrameBytes

			plaintextLength := extent.FrameCount * recovery.Manifest.Layout.CryptoFrameBytes
			if remaining := pack.PlaintextSize - extent.FirstFrame*recovery.Manifest.Layout.CryptoFrameBytes; plaintextLength > remaining {
				plaintextLength = remaining
			}

			if span, ok := journal.Completed[extent.CiphertextSHA256]; ok && span.Offset == plaintextOffset && span.Length == plaintextLength && verifyLocalSpan(output, span) {
				result.ResumedExtents++
				progress.UsefulBytesVerified += plaintextLength
				observeRestoreProgress(observer, &progress, started)

				continue
			}

			transferExtent, conversionErr := makeTransferExtent(extent, locations[extent.CiphertextSHA256])
			if conversionErr != nil {
				return RestoreResult{}, conversionErr
			}

			verified, fetchErr := restorer.fetcher.Fetch(ctx, transferExtent)
			if fetchErr != nil {
				return RestoreResult{}, fmt.Errorf("fetch restore pack %d extent %d: %w", pack.Ordinal, extent.Ordinal, fetchErr)
			}

			fileOffset, offsetErr := restoreFileOffset(plaintextOffset)
			if offsetErr != nil {
				return RestoreResult{}, offsetErr
			}

			writer := io.NewOffsetWriter(output, fileOffset)

			opened, openErr := packCipher.OpenFrames(ctx, writer, bytes.NewReader(verified.Data), extent.FirstFrame, extent.FrameCount)
			if openErr != nil {
				return RestoreResult{}, fmt.Errorf("decrypt restore pack %d extent %d: %w", pack.Ordinal, extent.Ordinal, openErr)
			}

			span := restoredSpan{Offset: plaintextOffset, Length: opened.PlaintextBytes, PlaintextSHA256: hex.EncodeToString(opened.PlaintextSHA256[:])}

			journal.Completed[extent.CiphertextSHA256] = span
			if journalErr := persistRestoreJournal(journalPath, journal); journalErr != nil {
				return RestoreResult{}, journalErr
			}

			result.FetchedExtents++
			progress.WireBytesRead += uint64(len(verified.Data))
			progress.UsefulBytesVerified += opened.PlaintextBytes
			progress.RetryCount += verified.Attempts - 1
			observeRestoreProgress(observer, &progress, started)
		}
	}

	if syncErr := output.Sync(); syncErr != nil {
		return RestoreResult{}, fmt.Errorf("sync restore staging file: %w", syncErr)
	}

	actualDigest, err := hashLocalFile(output)
	if err != nil {
		return RestoreResult{}, err
	}

	if actualDigest != recovery.Manifest.PlaintextSHA256 {
		return RestoreResult{}, fmt.Errorf("%w: got %s want %s", ErrRestoreIntegrity, actualDigest, recovery.Manifest.PlaintextSHA256)
	}

	if err := output.Close(); err != nil {
		return RestoreResult{}, fmt.Errorf("close restore staging file: %w", err)
	}

	if err := os.Rename(partPath, destination); err != nil {
		return RestoreResult{}, fmt.Errorf("publish restored file: %w", err)
	}

	if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return RestoreResult{}, fmt.Errorf("remove restore journal: %w", err)
	}

	return result, nil
}

func observeRestoreProgress(
	observer RestoreProgressObserver,
	progress *RestoreProgress,
	started time.Time,
) {
	if observer == nil {
		return
	}

	progress.ActiveNanoseconds = activeNanoseconds(started)
	observer(*progress)
}

func activeNanoseconds(started time.Time) uint64 {
	elapsed := time.Since(started)
	if elapsed <= 0 {
		return 0
	}

	// #nosec G115 -- a positive time.Duration always fits uint64.
	return uint64(elapsed.Nanoseconds())
}

func loadRestoreJournal(path string, recovery manifest.RecoveryManifest) (restoreJournal, error) {
	journal := restoreJournal{SchemaVersion: restoreJournalVersion, ManifestSHA256: recovery.ManifestSHA256, PlaintextSize: recovery.Manifest.PlaintextSize, Completed: make(map[string]restoredSpan)}
	// #nosec G304 -- the journal path is derived from the caller-selected restore destination.
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal, nil
	}

	if err != nil {
		return restoreJournal{}, fmt.Errorf("read restore journal: %w", err)
	}

	if err := json.Unmarshal(encoded, &journal); err != nil {
		return restoreJournal{}, fmt.Errorf("decode restore journal: %w", err)
	}

	if journal.SchemaVersion != restoreJournalVersion || journal.ManifestSHA256 != recovery.ManifestSHA256 || journal.PlaintextSize != recovery.Manifest.PlaintextSize || journal.Completed == nil {
		return restoreJournal{}, fmt.Errorf("%w: restore journal does not match pinned manifest", ErrInvalidRestore)
	}

	return journal, nil
}

func persistRestoreJournal(path string, journal restoreJournal) error {
	encoded, err := json.Marshal(journal)
	if err != nil {
		return fmt.Errorf("encode restore journal: %w", err)
	}

	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return fmt.Errorf("write restore journal: %w", err)
	}

	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish restore journal: %w", err)
	}

	return nil
}

func indexRestoreLocations(locations []manifest.Location) map[string][]manifest.Location {
	indexed := make(map[string][]manifest.Location)
	for _, location := range locations {
		indexed[location.ExtentSHA256] = append(indexed[location.ExtentSHA256], location)
	}

	return indexed
}

func makeTransferExtent(extent manifest.Extent, locations []manifest.Location) (transfer.Extent, error) {
	decoded, err := hex.DecodeString(extent.CiphertextSHA256)
	if err != nil {
		return transfer.Extent{}, fmt.Errorf("decode extent digest: %w", err)
	}

	var digest transfer.Digest
	copy(digest[:], decoded)

	converted := make([]transfer.Location, 0, len(locations))
	for _, location := range locations {
		converted = append(converted, transfer.Location{DriverID: location.DriverID, Key: location.StorageKey, Offset: location.Offset, Length: location.Length})
	}

	return transfer.Extent{ID: digest, CiphertextBytes: extent.CiphertextSize, Locations: converted}, nil
}

func verifyLocalSpan(file *os.File, span restoredSpan) bool {
	offset, offsetErr := restoreFileOffset(span.Offset)

	length, lengthErr := restoreFileOffset(span.Length)
	if offsetErr != nil || lengthErr != nil {
		return false
	}

	hasher := sha256.New()
	if _, err := io.CopyN(hasher, io.NewSectionReader(file, offset, length), length); err != nil {
		return false
	}

	return hex.EncodeToString(hasher.Sum(nil)) == span.PlaintextSHA256
}

func restoreFileOffset(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%w: local file offset exceeds int64", ErrInvalidRestore)
	}

	// #nosec G115 -- the upper bound is checked immediately above.
	return int64(value), nil
}

func hashLocalFile(file *os.File) (string, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(file, 0, 1<<63-1)); err != nil {
		return "", fmt.Errorf("hash restored plaintext: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
