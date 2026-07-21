// Package cryptofile implements Skydriver VFS complete-file encryption.
//
// It is provider-free: verification blocks, multipart parts, ranges, and
// storage drivers remain outside this package. One immutable file version uses
// one derived key and independent authenticated frames whose concatenation is
// the complete encoded provider object.
package cryptofile

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/dravengarden/skydriver/vfs/merkle"
)

const (
	// Suite is the first Skydriver VFS complete-file encryption format.
	Suite = "carrack-vfs-aes256gcm-hkdfsha256-v1"

	directoryKeyBytes = 32
	fileKeyBytes      = 32
	nonceBytes        = 12
	frameTagBytes     = uint64(16)
	fileKeyInfo       = "carrack.vfs.file-key.v1"
	frameAADDomain    = "carrack.vfs.file-frame.v1"
)

var (
	// ErrInvalidDescriptor indicates an incomplete or unsafe immutable file context.
	ErrInvalidDescriptor = errors.New("invalid Skydriver VFS crypto descriptor")
	// ErrInvalidKey indicates missing directory key material.
	ErrInvalidKey = errors.New("invalid Skydriver VFS directory key")
	// ErrInvalidFrame indicates a frame with an impossible ordinal or length.
	ErrInvalidFrame = errors.New("invalid Skydriver VFS crypto frame")
	// ErrAuthentication indicates that an encoded frame failed AES-GCM authentication.
	ErrAuthentication = errors.New("carrack VFS frame authentication failed")
	// ErrStreamLength indicates short or trailing transform input.
	ErrStreamLength = errors.New("invalid Skydriver VFS crypto stream length")
)

// DirectoryKey is one authorized 256-bit directory epoch secret.
type DirectoryKey [directoryKeyBytes]byte

// Clear overwrites this directory secret after deriving its immutable file cipher.
func (key *DirectoryKey) Clear() {
	if key != nil {
		clear(key[:])
	}
}

// Descriptor is the immutable public context authenticated by every frame.
type Descriptor struct {
	Suite          string
	DirectoryID    merkle.Identifier
	VersionID      merkle.Identifier
	KeyEpoch       uint64
	FrameBytes     uint64
	PlaintextBytes uint64
}

// TransformResult records the exact complete encoded-object identity.
type TransformResult struct {
	PlaintextBytes uint64
	EncodedBytes   uint64
	EncodedSHA256  [sha256.Size]byte
}

// Cipher is immutable and safe for concurrent independent frame operations.
type Cipher struct {
	descriptor Descriptor
	aead       cipher.AEAD
	frameCount uint64
	aadPrefix  []byte
}

// New derives the immutable file-version key and constructs its AES-256-GCM cipher.
func New(directoryKey DirectoryKey, descriptor Descriptor) (*Cipher, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	fileKey, err := deriveFileKey(directoryKey, descriptor)
	if err != nil {
		return nil, err
	}
	defer clear(fileKey[:])

	block, err := aes.NewCipher(fileKey[:])
	if err != nil {
		return nil, fmt.Errorf("construct Skydriver VFS AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("construct Skydriver VFS AES-GCM: %w", err)
	}

	if aead.NonceSize() != nonceBytes || aead.Overhead() != int(frameTagBytes) {
		return nil, fmt.Errorf("%w: unexpected AES-GCM dimensions", ErrInvalidDescriptor)
	}

	return &Cipher{
		descriptor: descriptor,
		aead:       aead,
		frameCount: descriptor.FrameCount(),
		aadPrefix:  descriptor.aadPrefix(),
	}, nil
}

// Validate checks the complete immutable encryption context.
func (descriptor Descriptor) Validate() error {
	if descriptor.Suite != Suite {
		return fmt.Errorf("%w: unsupported suite %q", ErrInvalidDescriptor, descriptor.Suite)
	}

	if descriptor.DirectoryID.IsZero() || descriptor.VersionID.IsZero() {
		return fmt.Errorf("%w: directory and version IDs are required", ErrInvalidDescriptor)
	}

	if descriptor.KeyEpoch == 0 || descriptor.FrameBytes == 0 {
		return fmt.Errorf("%w: key epoch and frame size must be positive", ErrInvalidDescriptor)
	}

	if descriptor.PlaintextBytes > math.MaxInt64 || descriptor.FrameBytes > math.MaxInt64 {
		return fmt.Errorf("%w: file or frame exceeds streaming limits", ErrInvalidDescriptor)
	}

	if descriptor.FrameCount() > math.MaxUint32 {
		return fmt.Errorf("%w: frame count exceeds nonce policy", ErrInvalidDescriptor)
	}

	return nil
}

// FrameCount returns the number of independently authenticated frames.
func (descriptor Descriptor) FrameCount() uint64 {
	if descriptor.PlaintextBytes == 0 || descriptor.FrameBytes == 0 {
		return 0
	}

	return 1 + (descriptor.PlaintextBytes-1)/descriptor.FrameBytes
}

// EncodedBytes returns the exact concatenated ciphertext and tag length.
func (descriptor Descriptor) EncodedBytes() (uint64, error) {
	if err := descriptor.Validate(); err != nil {
		return 0, err
	}

	frames := descriptor.FrameCount()
	if frames > (math.MaxUint64-descriptor.PlaintextBytes)/frameTagBytes {
		return 0, fmt.Errorf("%w: encoded length overflows", ErrInvalidDescriptor)
	}

	return descriptor.PlaintextBytes + frames*frameTagBytes, nil
}

// Descriptor returns this cipher's immutable public context.
func (fileCipher *Cipher) Descriptor() Descriptor {
	if fileCipher == nil {
		return Descriptor{}
	}

	return fileCipher.descriptor
}

// Seal encrypts exactly one complete plaintext file with bounded memory.
func (fileCipher *Cipher) Seal(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
) (TransformResult, error) {
	if fileCipher == nil || ctx == nil || destination == nil || source == nil {
		return TransformResult{}, fmt.Errorf("%w: cipher, context, source, and destination are required", ErrInvalidDescriptor)
	}

	encodedBytes, err := fileCipher.descriptor.EncodedBytes()
	if err != nil {
		return TransformResult{}, err
	}

	frameCapacity, err := safeFrameCapacity(fileCipher.descriptor.FrameBytes, frameTagBytes)
	if err != nil {
		return TransformResult{}, err
	}

	plaintextBuffer := make([]byte, frameCapacity-int(frameTagBytes))
	encodedBuffer := make([]byte, 0, frameCapacity)
	hasher := sha256.New()
	result := TransformResult{EncodedBytes: encodedBytes}

	for ordinal := range fileCipher.frameCount {
		if err := ctx.Err(); err != nil {
			return TransformResult{}, fmt.Errorf("seal Skydriver VFS file: %w", err)
		}

		plaintextBytes := fileCipher.plaintextFrameBytes(ordinal)
		plaintextBytes64 := uint64(plaintextBytes) //nolint:gosec // Frame bounds prove a nonnegative conversion.
		plaintext := plaintextBuffer[:plaintextBytes]

		if _, err := io.ReadFull(source, plaintext); err != nil {
			return TransformResult{}, fmt.Errorf("%w: read frame %d: %w", ErrStreamLength, ordinal, err)
		}

		nonce := frameNonce(ordinal)

		encoded := fileCipher.aead.Seal(
			encodedBuffer[:0],
			nonce[:],
			plaintext,
			fileCipher.frameAAD(ordinal, plaintextBytes64),
		)
		if err := writeFull(io.MultiWriter(destination, hasher), encoded); err != nil {
			return TransformResult{}, fmt.Errorf("write encoded frame %d: %w", ordinal, err)
		}

		result.PlaintextBytes += plaintextBytes64
	}

	if err := requireEOF(source); err != nil {
		return TransformResult{}, err
	}

	copy(result.EncodedSHA256[:], hasher.Sum(nil))

	return result, nil
}

// Open authenticates and decrypts exactly one complete encoded file.
func (fileCipher *Cipher) Open(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
) (TransformResult, error) {
	if fileCipher == nil || ctx == nil || destination == nil || source == nil {
		return TransformResult{}, fmt.Errorf("%w: cipher, context, source, and destination are required", ErrInvalidDescriptor)
	}

	encodedBytes, err := fileCipher.descriptor.EncodedBytes()
	if err != nil {
		return TransformResult{}, err
	}

	frameCapacity, err := safeFrameCapacity(fileCipher.descriptor.FrameBytes, frameTagBytes)
	if err != nil {
		return TransformResult{}, err
	}

	encodedBuffer := make([]byte, frameCapacity)
	plaintextBuffer := make([]byte, 0, frameCapacity-int(frameTagBytes))
	hasher := sha256.New()
	result := TransformResult{EncodedBytes: encodedBytes}

	for ordinal := range fileCipher.frameCount {
		if err := ctx.Err(); err != nil {
			return TransformResult{}, fmt.Errorf("open Skydriver VFS file: %w", err)
		}

		plaintextBytes := fileCipher.plaintextFrameBytes(ordinal)
		plaintextBytes64 := uint64(plaintextBytes) //nolint:gosec // Frame bounds prove a nonnegative conversion.
		encodedLength := plaintextBytes + int(frameTagBytes)
		encoded := encodedBuffer[:encodedLength]

		if _, err := io.ReadFull(source, encoded); err != nil {
			return TransformResult{}, fmt.Errorf("%w: read frame %d: %w", ErrStreamLength, ordinal, err)
		}

		_, _ = hasher.Write(encoded)

		nonce := frameNonce(ordinal)

		plaintext, err := fileCipher.aead.Open(
			plaintextBuffer[:0],
			nonce[:],
			encoded,
			fileCipher.frameAAD(ordinal, plaintextBytes64),
		)
		if err != nil {
			return TransformResult{}, fmt.Errorf("%w: frame %d", ErrAuthentication, ordinal)
		}

		if err := writeFull(destination, plaintext); err != nil {
			return TransformResult{}, fmt.Errorf("write plaintext frame %d: %w", ordinal, err)
		}

		result.PlaintextBytes += plaintextBytes64
	}

	if err := requireEOF(source); err != nil {
		return TransformResult{}, err
	}

	copy(result.EncodedSHA256[:], hasher.Sum(nil))

	return result, nil
}

func deriveFileKey(directoryKey DirectoryKey, descriptor Descriptor) ([fileKeyBytes]byte, error) {
	if allZero(directoryKey[:]) {
		return [fileKeyBytes]byte{}, fmt.Errorf("%w: key must not be zero", ErrInvalidKey)
	}

	salt := make([]byte, 0, len(descriptor.DirectoryID)+len(descriptor.VersionID))
	salt = append(salt, descriptor.DirectoryID[:]...)
	salt = append(salt, descriptor.VersionID[:]...)

	derived, err := hkdf.Key(sha256.New, directoryKey[:], salt, fileKeyInfo, fileKeyBytes)
	if err != nil {
		return [fileKeyBytes]byte{}, fmt.Errorf("derive Skydriver VFS file key: %w", err)
	}

	return [fileKeyBytes]byte(derived), nil
}

func (descriptor Descriptor) aadPrefix() []byte {
	prefix := make([]byte, 0, len(frameAADDomain)+1+16+16+24)
	prefix = append(prefix, frameAADDomain...)
	prefix = append(prefix, 0)
	prefix = append(prefix, descriptor.DirectoryID[:]...)
	prefix = append(prefix, descriptor.VersionID[:]...)
	prefix = binary.BigEndian.AppendUint64(prefix, descriptor.KeyEpoch)
	prefix = binary.BigEndian.AppendUint64(prefix, descriptor.FrameBytes)
	prefix = binary.BigEndian.AppendUint64(prefix, descriptor.PlaintextBytes)

	return prefix
}

func (fileCipher *Cipher) frameAAD(ordinal, plaintextBytes uint64) []byte {
	aad := make([]byte, len(fileCipher.aadPrefix), len(fileCipher.aadPrefix)+16)
	copy(aad, fileCipher.aadPrefix)
	aad = binary.BigEndian.AppendUint64(aad, ordinal)
	aad = binary.BigEndian.AppendUint64(aad, plaintextBytes)

	return aad
}

func (fileCipher *Cipher) plaintextFrameBytes(ordinal uint64) int {
	offset := ordinal * fileCipher.descriptor.FrameBytes
	length := min(fileCipher.descriptor.FrameBytes, fileCipher.descriptor.PlaintextBytes-offset)

	return int(length) //nolint:gosec // Descriptor validation and allocation checks bound this frame.
}

func frameNonce(ordinal uint64) [nonceBytes]byte {
	var nonce [nonceBytes]byte
	binary.BigEndian.PutUint64(nonce[nonceBytes-8:], ordinal)

	return nonce
}

func safeFrameCapacity(frameBytes, overhead uint64) (int, error) {
	if frameBytes > uint64(math.MaxInt) || overhead > uint64(math.MaxInt)-frameBytes {
		return 0, fmt.Errorf("%w: frame allocation exceeds address space", ErrInvalidDescriptor)
	}

	return int(frameBytes + overhead), nil //nolint:gosec // The address-space checks above prove conversion safety.
}

func requireEOF(source io.Reader) error {
	var extra [1]byte

	readBytes, err := source.Read(extra[:])
	if readBytes != 0 || err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: input contains trailing bytes: %w", ErrStreamLength, err)
	}

	return nil
}

func writeFull(destination io.Writer, value []byte) error {
	for len(value) != 0 {
		written, err := destination.Write(value)
		if err != nil {
			return fmt.Errorf("write complete buffer: %w", err)
		}

		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}

		value = value[written:]
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
