// Package cryptostream implements Carrack's provider-neutral encryption
// format. It has no storage, network, control-plane, or driver dependencies.
package cryptostream

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// SuiteAES128GCMHKDFSHA256V1 is Carrack's initial immutable crypto suite.
	SuiteAES128GCMHKDFSHA256V1 = "carrack-aes128gcm-hkdfsha256-v1"

	rootKeyBytes    = 32
	epochKeyBytes   = 32
	packKeyBytes    = 16
	identifierBytes = 16
)

const (
	epochKeyInfo = "carrack/epoch-key/v1"
	packKeyInfo  = "carrack/pack-key/v1"
)

var (
	// ErrInvalidKeyContext indicates a missing key or all-zero identifier.
	ErrInvalidKeyContext = errors.New("invalid Carrack key context")
	// ErrKeyDerivation indicates an HKDF failure.
	ErrKeyDerivation = errors.New("carrack key derivation failed")
)

// RootKey is one control-plane root seed version.
type RootKey [rootKeyBytes]byte

// EpochKey grants one client access to a namespace key epoch.
type EpochKey [epochKeyBytes]byte

// PackKey encrypts frames belonging to one immutable logical pack.
type PackKey [packKeyBytes]byte

// Identifier is a random, stable 128-bit Carrack object identifier.
type Identifier [identifierBytes]byte

// EpochContext identifies one namespace key epoch.
type EpochContext struct {
	NamespaceID Identifier
	EpochID     uint64
}

// DeriveEpochKey derives one namespace epoch key from a root seed.
func DeriveEpochKey(rootKey RootKey, context EpochContext) (EpochKey, error) {
	if allZero(rootKey[:]) {
		return EpochKey{}, fmt.Errorf("%w: root key must not be zero", ErrInvalidKeyContext)
	}

	if allZero(context.NamespaceID[:]) {
		return EpochKey{}, fmt.Errorf("%w: namespace ID must not be zero", ErrInvalidKeyContext)
	}

	var salt [identifierBytes + 8]byte
	copy(salt[:identifierBytes], context.NamespaceID[:])
	binary.BigEndian.PutUint64(salt[identifierBytes:], context.EpochID)

	derived, err := hkdf.Key(sha256.New, rootKey[:], salt[:], epochKeyInfo, epochKeyBytes)
	if err != nil {
		return EpochKey{}, fmt.Errorf("%w: epoch key: %w", ErrKeyDerivation, err)
	}

	return EpochKey(derived), nil
}

// DerivePackKey derives one pack key from an authorized epoch key.
func DerivePackKey(epochKey EpochKey, packID Identifier) (PackKey, error) {
	if allZero(epochKey[:]) {
		return PackKey{}, fmt.Errorf("%w: epoch key must not be zero", ErrInvalidKeyContext)
	}

	if allZero(packID[:]) {
		return PackKey{}, fmt.Errorf("%w: pack ID must not be zero", ErrInvalidKeyContext)
	}

	derived, err := hkdf.Key(sha256.New, epochKey[:], packID[:], packKeyInfo, packKeyBytes)
	if err != nil {
		return PackKey{}, fmt.Errorf("%w: pack key: %w", ErrKeyDerivation, err)
	}

	return PackKey(derived), nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, element := range value {
		combined |= element
	}

	return combined == 0
}
