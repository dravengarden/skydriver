// Package transfer fetches and stores opaque ciphertext extents. It does not
// import or interpret Carrack's encryption format.
package transfer

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

const digestBytes = sha256.Size

var (
	// ErrInvalidExtent indicates inconsistent ciphertext metadata.
	ErrInvalidExtent = errors.New("invalid Carrack transfer extent")
	// ErrNoReplica indicates that an extent has no usable physical location.
	ErrNoReplica = errors.New("carrack transfer extent has no replica")
)

// Digest is a SHA-256 identity for exact ciphertext bytes.
type Digest [digestBytes]byte

// Location maps one ciphertext extent to a provider object range.
type Location struct {
	DriverID string
	Key      string
	Offset   uint64
	Length   uint64
}

// Extent is one immutable, provider-neutral ciphertext transfer unit.
type Extent struct {
	ID              Digest
	CiphertextBytes uint64
	Locations       []Location
}

// DigestBytes calculates the identity of opaque ciphertext bytes.
func DigestBytes(ciphertext []byte) Digest {
	return sha256.Sum256(ciphertext)
}

// Validate checks provider-neutral extent metadata.
func (extent Extent) Validate() error {
	if allZero(extent.ID[:]) {
		return fmt.Errorf("%w: digest must not be zero", ErrInvalidExtent)
	}

	if extent.CiphertextBytes == 0 {
		return fmt.Errorf("%w: ciphertext size must be positive", ErrInvalidExtent)
	}

	if len(extent.Locations) == 0 {
		return ErrNoReplica
	}

	for index, location := range extent.Locations {
		if err := location.validate(extent.CiphertextBytes); err != nil {
			return fmt.Errorf("%w: location %d: %w", ErrInvalidExtent, index, err)
		}
	}

	return nil
}

func (location Location) validate(expectedBytes uint64) error {
	if strings.TrimSpace(location.DriverID) == "" {
		return fmt.Errorf("%w: driver ID is required", ErrInvalidExtent)
	}

	if strings.TrimSpace(location.Key) == "" {
		return fmt.Errorf("%w: storage key is required", ErrInvalidExtent)
	}

	if location.Length != expectedBytes {
		return fmt.Errorf(
			"%w: range length %d must equal extent size %d",
			ErrInvalidExtent,
			location.Length,
			expectedBytes,
		)
	}

	return nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, element := range value {
		combined |= element
	}

	return combined == 0
}
