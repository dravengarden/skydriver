package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/dravengarden/carrack/provider"
)

var (
	// ErrInvalidFetcher indicates missing readers or unsafe memory bounds.
	ErrInvalidFetcher = errors.New("invalid Carrack extent fetcher")
	// ErrExtentTooLarge indicates an extent exceeding the configured bound.
	ErrExtentTooLarge = errors.New("carrack transfer extent exceeds memory bound")
	// ErrIntegrity indicates bytes that do not match the requested identity.
	ErrIntegrity = errors.New("carrack ciphertext integrity check failed")
	// ErrAllSourcesFailed indicates that every location failed validation.
	ErrAllSourcesFailed = errors.New("all Carrack ciphertext sources failed")
)

// Fetcher retrieves exact ciphertext bytes with ordered replica fallback.
type Fetcher struct {
	readers            map[string]provider.Reader
	maximumExtentBytes uint64
}

// VerifiedExtent owns ciphertext bytes that matched the requested SHA-256.
type VerifiedExtent struct {
	ID       Digest
	Data     []byte
	Location Location
}

// NewFetcher copies its reader registry and applies an explicit memory bound.
func NewFetcher(readers map[string]provider.Reader, maximumExtentBytes uint64) (*Fetcher, error) {
	if len(readers) == 0 {
		return nil, fmt.Errorf("%w: at least one reader is required", ErrInvalidFetcher)
	}

	if maximumExtentBytes == 0 {
		return nil, fmt.Errorf("%w: maximum extent size must be positive", ErrInvalidFetcher)
	}

	registered := make(map[string]provider.Reader, len(readers))
	for driverID, reader := range readers {
		if driverID == "" || reader == nil {
			return nil, fmt.Errorf("%w: reader identity and implementation are required", ErrInvalidFetcher)
		}

		registered[driverID] = reader
	}

	return &Fetcher{readers: registered, maximumExtentBytes: maximumExtentBytes}, nil
}

// Fetch tries locations in plan order until exact length and hash verification
// succeed. Source selection policy can reorder Locations without changing this
// fetch or any crypto implementation.
func (fetcher *Fetcher) Fetch(ctx context.Context, extent Extent) (VerifiedExtent, error) {
	if fetcher == nil {
		return VerifiedExtent{}, fmt.Errorf("%w: fetcher is required", ErrInvalidFetcher)
	}

	if err := extent.Validate(); err != nil {
		return VerifiedExtent{}, err
	}

	if extent.CiphertextBytes > fetcher.maximumExtentBytes {
		return VerifiedExtent{}, fmt.Errorf(
			"%w: %d bytes exceeds %d",
			ErrExtentTooLarge,
			extent.CiphertextBytes,
			fetcher.maximumExtentBytes,
		)
	}

	maximumInt := uint64(^uint(0) >> 1)
	if extent.CiphertextBytes > maximumInt {
		return VerifiedExtent{}, fmt.Errorf("%w: extent does not fit memory address space", ErrExtentTooLarge)
	}

	buffer := make([]byte, int(extent.CiphertextBytes))
	attemptErrors := make([]error, 0, len(extent.Locations))

	for index, location := range extent.Locations {
		if err := ctx.Err(); err != nil {
			return VerifiedExtent{}, fmt.Errorf("fetch ciphertext extent: %w", err)
		}

		reader, exists := fetcher.readers[location.DriverID]
		if !exists {
			attemptErrors = append(
				attemptErrors,
				fmt.Errorf("source %d driver %q: %w", index, location.DriverID, ErrNoReplica),
			)

			continue
		}

		if err := readLocation(ctx, reader, location, buffer); err != nil {
			attemptErrors = append(attemptErrors, fmt.Errorf("source %d read: %w", index, err))

			continue
		}

		if actual := DigestBytes(buffer); actual != extent.ID {
			attemptErrors = append(attemptErrors, fmt.Errorf("source %d: %w", index, ErrIntegrity))

			continue
		}

		return VerifiedExtent{ID: extent.ID, Data: buffer, Location: location}, nil
	}

	return VerifiedExtent{}, fmt.Errorf("%w: %w", ErrAllSourcesFailed, errors.Join(attemptErrors...))
}

func readLocation(
	ctx context.Context,
	reader provider.Reader,
	location Location,
	destination []byte,
) error {
	stream, err := reader.OpenRange(ctx, location.Key, location.Offset, location.Length)
	if err != nil {
		return fmt.Errorf("open provider range: %w", err)
	}

	_, readErr := io.ReadFull(stream, destination)
	if readErr != nil {
		return errors.Join(fmt.Errorf("read provider range: %w", readErr), stream.Close())
	}

	var extra [1]byte

	extraBytes, extraErr := stream.Read(extra[:])
	closeErr := stream.Close()

	if extraBytes != 0 {
		return errors.Join(fmt.Errorf("%w: provider range exceeded declared length", ErrIntegrity), closeErr)
	}

	if extraErr != nil && !errors.Is(extraErr, io.EOF) {
		return errors.Join(fmt.Errorf("finish provider range: %w", extraErr), closeErr)
	}

	if closeErr != nil {
		return fmt.Errorf("close provider range: %w", closeErr)
	}

	return nil
}
