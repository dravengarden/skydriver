package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

const (
	digestBytes     = sha256.Size
	identifierBytes = 16
)

var (
	// ErrInvalidDigest indicates a non-canonical SHA-256 value.
	ErrInvalidDigest = errors.New("invalid Skydriver VFS V2 digest")
	// ErrInvalidIdentifier indicates a zero or non-canonical 128-bit VFS ID.
	ErrInvalidIdentifier = errors.New("invalid Skydriver VFS V2 identifier")
	// ErrInvalidFile indicates a contradictory or unsafe file tree request.
	ErrInvalidFile = errors.New("invalid Skydriver VFS V2 file tree")
	// ErrInvalidDirectory indicates a contradictory or non-canonical directory.
	ErrInvalidDirectory = errors.New("invalid Skydriver VFS V2 directory tree")
	// ErrIntegrity indicates bytes that disagree with declared length or root.
	ErrIntegrity = errors.New("skydriver VFS V2 Merkle integrity mismatch")
)

// Digest is one raw SHA-256 value. String and text encoding use exactly 64
// lowercase hexadecimal characters.
type Digest [digestBytes]byte //nolint:recvcheck // Text unmarshaling necessarily uses a pointer receiver.

// ParseDigest decodes one canonical lowercase SHA-256 string.
func ParseDigest(encoded string) (Digest, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != digestBytes || hex.EncodeToString(decoded) != encoded {
		return Digest{}, fmt.Errorf("%w: expected 64 lowercase hexadecimal characters", ErrInvalidDigest)
	}

	return Digest(decoded), nil
}

// String returns canonical lowercase hexadecimal SHA-256.
func (digest Digest) String() string {
	return hex.EncodeToString(digest[:])
}

// MarshalText implements encoding.TextMarshaler.
func (digest Digest) MarshalText() ([]byte, error) {
	return []byte(digest.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler and rejects non-canonical
// hexadecimal input.
func (digest *Digest) UnmarshalText(encoded []byte) error {
	if digest == nil {
		return fmt.Errorf("%w: nil digest destination", ErrInvalidDigest)
	}

	parsed, err := ParseDigest(string(encoded))
	if err != nil {
		return err
	}

	*digest = parsed

	return nil
}

// IsZero reports whether a required digest was omitted.
func (digest Digest) IsZero() bool {
	return digest == Digest{}
}

// Identifier is one opaque nonzero 128-bit VFS identity. ID generation and
// display syntax are control-plane concerns; Merkle encoding hashes raw bytes.
type Identifier [identifierBytes]byte //nolint:recvcheck // Text unmarshaling necessarily uses a pointer receiver.

// ParseIdentifier decodes one canonical lowercase 128-bit hexadecimal ID.
func ParseIdentifier(encoded string) (Identifier, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != identifierBytes || hex.EncodeToString(decoded) != encoded {
		return Identifier{}, fmt.Errorf("%w: expected 32 lowercase hexadecimal characters", ErrInvalidIdentifier)
	}

	identifier := Identifier(decoded)
	if identifier.IsZero() {
		return Identifier{}, fmt.Errorf("%w: zero is reserved", ErrInvalidIdentifier)
	}

	return identifier, nil
}

// String returns canonical lowercase hexadecimal.
func (identifier Identifier) String() string {
	return hex.EncodeToString(identifier[:])
}

// MarshalText implements encoding.TextMarshaler.
func (identifier Identifier) MarshalText() ([]byte, error) {
	return []byte(identifier.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (identifier *Identifier) UnmarshalText(encoded []byte) error {
	if identifier == nil {
		return fmt.Errorf("%w: nil identifier destination", ErrInvalidIdentifier)
	}

	parsed, err := ParseIdentifier(string(encoded))
	if err != nil {
		return err
	}

	*identifier = parsed

	return nil
}

// IsZero reports whether an identifier was omitted.
func (identifier Identifier) IsZero() bool {
	return identifier == Identifier{}
}

func newDomainHasher(domain string) hash.Hash {
	hasher := sha256.New()
	writeHash(hasher, []byte(domain))
	writeHash(hasher, []byte{0})

	return hasher
}

func writeHash(hasher hash.Hash, payload []byte) {
	if _, err := hasher.Write(payload); err != nil {
		panic(fmt.Sprintf("SHA-256 write failed: %v", err))
	}
}

func writeUint32(hasher hash.Hash, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	writeHash(hasher, encoded[:])
}

func writeUint64(hasher hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	writeHash(hasher, encoded[:])
}

func finishDigest(hasher hash.Hash) Digest {
	return Digest(hasher.Sum(nil))
}

func hashEmpty(domain string) Digest {
	return finishDigest(newDomainHasher(domain))
}

func hashBinaryNode(domain string, firstLeaf, leafCount uint64, left, right Digest) Digest {
	hasher := newDomainHasher(domain)
	writeUint64(hasher, firstLeaf)
	writeUint64(hasher, leafCount)
	writeHash(hasher, left[:])
	writeHash(hasher, right[:])

	return finishDigest(hasher)
}

func buildCanonicalTree(domain string, leaves []Digest, firstLeaf uint64) Digest {
	if len(leaves) == 1 {
		return leaves[0]
	}

	leftCount := largestPowerOfTwoPrefix(len(leaves))
	left := buildCanonicalTree(domain, leaves[:leftCount], firstLeaf)
	right := buildCanonicalTree(
		domain,
		leaves[leftCount:],
		firstLeaf+uint64(leftCount), //nolint:gosec // Callers cap leaves at one million.
	)

	return hashBinaryNode(domain, firstLeaf, uint64(len(leaves)), left, right)
}

func largestPowerOfTwoPrefix(count int) int {
	prefix := 1
	for prefix <= (count-1)/2 {
		prefix *= 2
	}

	return prefix
}
