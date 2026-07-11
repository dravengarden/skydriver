package cryptostream

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// DefaultFrameBytes is the V1 authenticated plaintext frame size.
	DefaultFrameBytes = uint64(8 << 20)
	frameTagBytes     = uint64(16)
	nonceBytes        = 12
	aadDomain         = "carrack/frame/v1"
)

var (
	// ErrInvalidDescriptor indicates inconsistent immutable pack metadata.
	ErrInvalidDescriptor = errors.New("invalid Carrack crypto descriptor")
	// ErrInvalidFrame indicates a frame with the wrong ordinal or length.
	ErrInvalidFrame = errors.New("invalid Carrack crypto frame")
	// ErrFrameAuthentication indicates that ciphertext authentication failed.
	ErrFrameAuthentication = errors.New("carrack crypto frame authentication failed")
)

// Descriptor contains the immutable context authenticated by every frame.
type Descriptor struct {
	Suite          string
	RootVersion    uint32
	NamespaceID    Identifier
	EpochID        uint64
	PackID         Identifier
	FrameBytes     uint64
	PlaintextBytes uint64
}

// Cipher encrypts and decrypts independent frames for one logical pack. A
// Cipher is immutable and safe for concurrent use.
type Cipher struct {
	descriptor Descriptor
	aead       cipher.AEAD
	frameCount uint64
	aadPrefix  []byte
}

// NewCipher validates a pack descriptor and constructs its AES-GCM context.
func NewCipher(packKey PackKey, descriptor Descriptor) (*Cipher, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(packKey[:])
	if err != nil {
		return nil, fmt.Errorf("construct Carrack AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("construct Carrack AES-GCM: %w", err)
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

// Descriptor returns the immutable public context for this pack.
func (packCipher *Cipher) Descriptor() Descriptor {
	if packCipher == nil {
		return Descriptor{}
	}

	return packCipher.descriptor
}

// Validate checks the versioned pack encryption context.
func (descriptor Descriptor) Validate() error {
	if descriptor.Suite != SuiteAES128GCMHKDFSHA256V1 {
		return fmt.Errorf("%w: unsupported suite %q", ErrInvalidDescriptor, descriptor.Suite)
	}

	if descriptor.RootVersion == 0 {
		return fmt.Errorf("%w: root version must be positive", ErrInvalidDescriptor)
	}

	if allZero(descriptor.NamespaceID[:]) {
		return fmt.Errorf("%w: namespace ID must not be zero", ErrInvalidDescriptor)
	}

	if allZero(descriptor.PackID[:]) {
		return fmt.Errorf("%w: pack ID must not be zero", ErrInvalidDescriptor)
	}

	if descriptor.FrameBytes == 0 {
		return fmt.Errorf("%w: frame size must be positive", ErrInvalidDescriptor)
	}

	return nil
}

// FrameCount returns the number of authenticated frames in the pack.
func (descriptor Descriptor) FrameCount() uint64 {
	if descriptor.PlaintextBytes == 0 || descriptor.FrameBytes == 0 {
		return 0
	}

	return 1 + (descriptor.PlaintextBytes-1)/descriptor.FrameBytes
}

// CiphertextBytes returns the exact framed ciphertext size.
func (descriptor Descriptor) CiphertextBytes() (uint64, error) {
	if err := descriptor.Validate(); err != nil {
		return 0, err
	}

	frameCount := descriptor.FrameCount()
	if frameCount > (^uint64(0)-descriptor.PlaintextBytes)/frameTagBytes {
		return 0, fmt.Errorf("%w: ciphertext size overflows uint64", ErrInvalidDescriptor)
	}

	return descriptor.PlaintextBytes + frameCount*frameTagBytes, nil
}

// CiphertextSpan returns the exact byte range occupied by a contiguous group
// of complete authenticated frames. Extent and manifest code can use it
// without constructing a Cipher or possessing key material.
func (descriptor Descriptor) CiphertextSpan(
	firstFrame,
	frameCount uint64,
) (offset, length uint64, err error) {
	if err := descriptor.Validate(); err != nil {
		return 0, 0, err
	}

	totalFrames := descriptor.FrameCount()
	if frameCount == 0 || firstFrame >= totalFrames || frameCount > totalFrames-firstFrame {
		return 0, 0, fmt.Errorf(
			"%w: frame span [%d, %d) exceeds count %d",
			ErrInvalidFrame,
			firstFrame,
			firstFrame+frameCount,
			totalFrames,
		)
	}

	fullCiphertextFrameBytes := descriptor.FrameBytes + frameTagBytes
	if fullCiphertextFrameBytes < descriptor.FrameBytes ||
		firstFrame > ^uint64(0)/fullCiphertextFrameBytes {
		return 0, 0, fmt.Errorf("%w: ciphertext frame offset overflows uint64", ErrInvalidDescriptor)
	}

	offset = firstFrame * fullCiphertextFrameBytes
	if frameCount > ^uint64(0)/fullCiphertextFrameBytes {
		return 0, 0, fmt.Errorf("%w: ciphertext frame length overflows uint64", ErrInvalidDescriptor)
	}

	length = frameCount * fullCiphertextFrameBytes

	lastFrame := firstFrame + frameCount
	if lastFrame == totalFrames {
		lastPlaintextBytes := descriptor.PlaintextBytes - (totalFrames-1)*descriptor.FrameBytes
		length -= descriptor.FrameBytes - lastPlaintextBytes
	}

	return offset, length, nil
}

// SealFrame encrypts one exact plaintext frame.
func (packCipher *Cipher) SealFrame(destination, plaintext []byte, ordinal uint64) ([]byte, error) {
	expectedBytes, err := packCipher.plaintextFrameBytes(ordinal)
	if err != nil {
		return nil, err
	}

	if uint64(len(plaintext)) != expectedBytes {
		return nil, fmt.Errorf(
			"%w: plaintext frame %d has %d bytes, expected %d",
			ErrInvalidFrame,
			ordinal,
			len(plaintext),
			expectedBytes,
		)
	}

	nonce := frameNonce(ordinal)
	aad := packCipher.frameAAD(ordinal, expectedBytes)

	return packCipher.aead.Seal(destination, nonce[:], plaintext, aad), nil
}

// OpenFrame authenticates and decrypts one exact ciphertext frame.
func (packCipher *Cipher) OpenFrame(destination, ciphertext []byte, ordinal uint64) ([]byte, error) {
	plaintextBytes, err := packCipher.plaintextFrameBytes(ordinal)
	if err != nil {
		return nil, err
	}

	expectedBytes := plaintextBytes + frameTagBytes
	if uint64(len(ciphertext)) != expectedBytes {
		return nil, fmt.Errorf(
			"%w: ciphertext frame %d has %d bytes, expected %d",
			ErrInvalidFrame,
			ordinal,
			len(ciphertext),
			expectedBytes,
		)
	}

	nonce := frameNonce(ordinal)
	aad := packCipher.frameAAD(ordinal, plaintextBytes)

	plaintext, err := packCipher.aead.Open(destination, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: frame %d: %w", ErrFrameAuthentication, ordinal, err)
	}

	return plaintext, nil
}

func (packCipher *Cipher) plaintextFrameBytes(ordinal uint64) (uint64, error) {
	if ordinal >= packCipher.frameCount {
		return 0, fmt.Errorf(
			"%w: frame ordinal %d exceeds count %d",
			ErrInvalidFrame,
			ordinal,
			packCipher.frameCount,
		)
	}

	offset := ordinal * packCipher.descriptor.FrameBytes

	return min(packCipher.descriptor.FrameBytes, packCipher.descriptor.PlaintextBytes-offset), nil
}

func (descriptor Descriptor) aadPrefix() []byte {
	prefix := make([]byte, 0, len(aadDomain)+4+identifierBytes+8+identifierBytes+16)
	prefix = append(prefix, aadDomain...)
	prefix = binary.BigEndian.AppendUint32(prefix, descriptor.RootVersion)
	prefix = append(prefix, descriptor.NamespaceID[:]...)
	prefix = binary.BigEndian.AppendUint64(prefix, descriptor.EpochID)
	prefix = append(prefix, descriptor.PackID[:]...)
	prefix = binary.BigEndian.AppendUint64(prefix, descriptor.FrameBytes)
	prefix = binary.BigEndian.AppendUint64(prefix, descriptor.PlaintextBytes)

	return prefix
}

func (packCipher *Cipher) frameAAD(ordinal, plaintextBytes uint64) []byte {
	aad := make([]byte, len(packCipher.aadPrefix), len(packCipher.aadPrefix)+16)
	copy(aad, packCipher.aadPrefix)
	aad = binary.BigEndian.AppendUint64(aad, ordinal)
	aad = binary.BigEndian.AppendUint64(aad, plaintextBytes)

	return aad
}

func frameNonce(ordinal uint64) [nonceBytes]byte {
	var nonce [nonceBytes]byte
	binary.BigEndian.PutUint64(nonce[nonceBytes-8:], ordinal)

	return nonce
}
