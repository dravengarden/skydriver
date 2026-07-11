package cryptostream

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidStream indicates a missing endpoint or unsafe frame allocation.
	ErrInvalidStream = errors.New("invalid Carrack crypto stream")
	// ErrStreamLength indicates that an input ended early or contained extra data.
	ErrStreamLength = errors.New("invalid Carrack crypto stream length")
)

// StreamDigest is the SHA-256 identity of one exact stream.
type StreamDigest [sha256.Size]byte

// TransformResult records exact bytes and hashes consumed and produced by a
// contiguous frame transform.
type TransformResult struct {
	PlaintextBytes   uint64
	CiphertextBytes  uint64
	PlaintextSHA256  StreamDigest
	CiphertextSHA256 StreamDigest
}

// SealFrames encrypts an exact plaintext input containing one contiguous frame
// span. Memory is bounded by one plaintext and one ciphertext frame.
func (packCipher *Cipher) SealFrames(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
	firstFrame,
	frameCount uint64,
) (TransformResult, error) {
	if packCipher == nil || destination == nil || source == nil {
		return TransformResult{}, fmt.Errorf("%w: cipher, source, and destination are required", ErrInvalidStream)
	}

	_, expectedCiphertextBytes, err := packCipher.descriptor.CiphertextSpan(firstFrame, frameCount)
	if err != nil {
		return TransformResult{}, err
	}

	frameCapacity, err := safeFrameCapacity(packCipher.descriptor.FrameBytes, frameTagBytes)
	if err != nil {
		return TransformResult{}, err
	}

	plaintextBuffer := make([]byte, frameCapacity-int(frameTagBytes))
	ciphertextBuffer := make([]byte, 0, frameCapacity)
	plaintextHash := sha256.New()
	ciphertextHash := sha256.New()
	result := TransformResult{CiphertextBytes: expectedCiphertextBytes}

	for ordinal := firstFrame; ordinal < firstFrame+frameCount; ordinal++ {
		if err := ctx.Err(); err != nil {
			return TransformResult{}, fmt.Errorf("seal Carrack frames: %w", err)
		}

		frameBytes, err := packCipher.plaintextFrameBytes(ordinal)
		if err != nil {
			return TransformResult{}, err
		}

		frameLength, err := safeInt(frameBytes)
		if err != nil {
			return TransformResult{}, err
		}

		plaintext := plaintextBuffer[:frameLength]
		if _, readErr := io.ReadFull(source, plaintext); readErr != nil {
			return TransformResult{}, fmt.Errorf(
				"%w: read plaintext frame %d: %w",
				ErrStreamLength,
				ordinal,
				readErr,
			)
		}

		_, _ = plaintextHash.Write(plaintext)
		result.PlaintextBytes += frameBytes

		ciphertext, err := packCipher.SealFrame(ciphertextBuffer[:0], plaintext, ordinal)
		if err != nil {
			return TransformResult{}, err
		}

		_, _ = ciphertextHash.Write(ciphertext)
		if err := writeFull(destination, ciphertext); err != nil {
			return TransformResult{}, fmt.Errorf("write ciphertext frame %d: %w", ordinal, err)
		}
	}

	if err := requireExhausted(source); err != nil {
		return TransformResult{}, err
	}

	copy(result.PlaintextSHA256[:], plaintextHash.Sum(nil))
	copy(result.CiphertextSHA256[:], ciphertextHash.Sum(nil))

	return result, nil
}

// OpenFrames authenticates and decrypts an exact ciphertext input containing
// one contiguous frame span. No plaintext after a failed frame is produced.
func (packCipher *Cipher) OpenFrames(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
	firstFrame,
	frameCount uint64,
) (TransformResult, error) {
	if packCipher == nil || destination == nil || source == nil {
		return TransformResult{}, fmt.Errorf("%w: cipher, source, and destination are required", ErrInvalidStream)
	}

	_, expectedCiphertextBytes, err := packCipher.descriptor.CiphertextSpan(firstFrame, frameCount)
	if err != nil {
		return TransformResult{}, err
	}

	frameCapacity, err := safeFrameCapacity(packCipher.descriptor.FrameBytes, frameTagBytes)
	if err != nil {
		return TransformResult{}, err
	}

	ciphertextBuffer := make([]byte, frameCapacity)
	plaintextBuffer := make([]byte, 0, frameCapacity-int(frameTagBytes))
	plaintextHash := sha256.New()
	ciphertextHash := sha256.New()
	result := TransformResult{CiphertextBytes: expectedCiphertextBytes}

	for ordinal := firstFrame; ordinal < firstFrame+frameCount; ordinal++ {
		if err := ctx.Err(); err != nil {
			return TransformResult{}, fmt.Errorf("open Carrack frames: %w", err)
		}

		plaintextBytes, err := packCipher.plaintextFrameBytes(ordinal)
		if err != nil {
			return TransformResult{}, err
		}

		ciphertextBytes := plaintextBytes + frameTagBytes

		ciphertextLength, err := safeInt(ciphertextBytes)
		if err != nil {
			return TransformResult{}, err
		}

		ciphertext := ciphertextBuffer[:ciphertextLength]
		if _, readErr := io.ReadFull(source, ciphertext); readErr != nil {
			return TransformResult{}, fmt.Errorf(
				"%w: read ciphertext frame %d: %w",
				ErrStreamLength,
				ordinal,
				readErr,
			)
		}

		_, _ = ciphertextHash.Write(ciphertext)

		plaintext, err := packCipher.OpenFrame(plaintextBuffer[:0], ciphertext, ordinal)
		if err != nil {
			return TransformResult{}, err
		}

		_, _ = plaintextHash.Write(plaintext)
		if err := writeFull(destination, plaintext); err != nil {
			return TransformResult{}, fmt.Errorf("write plaintext frame %d: %w", ordinal, err)
		}

		result.PlaintextBytes += plaintextBytes
	}

	if err := requireExhausted(source); err != nil {
		return TransformResult{}, err
	}

	copy(result.PlaintextSHA256[:], plaintextHash.Sum(nil))
	copy(result.CiphertextSHA256[:], ciphertextHash.Sum(nil))

	return result, nil
}

func safeFrameCapacity(frameBytes, overhead uint64) (int, error) {
	maximumInt := uint64(^uint(0) >> 1)
	if frameBytes > maximumInt || overhead > maximumInt-frameBytes {
		return 0, fmt.Errorf("%w: frame allocation exceeds address space", ErrInvalidStream)
	}

	return safeInt(frameBytes + overhead)
}

func safeInt(value uint64) (int, error) {
	maximumInt := uint64(^uint(0) >> 1)
	if value > maximumInt {
		return 0, fmt.Errorf("%w: value exceeds address space", ErrInvalidStream)
	}

	return int(value), nil
}

func writeFull(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if err != nil {
			return fmt.Errorf("write stream: %w", err)
		}

		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}

		value = value[written:]
	}

	return nil
}

func requireExhausted(source io.Reader) error {
	var extra [1]byte

	readBytes, err := source.Read(extra[:])
	if readBytes != 0 {
		return fmt.Errorf("%w: input contains trailing bytes", ErrStreamLength)
	}

	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("finish Carrack crypto input: %w", err)
	}

	return nil
}
