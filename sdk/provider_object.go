package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"path"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
)

const (
	verificationBufferBytes = 1 << 20
	maximumProviderKeyBytes = 4_096
)

func providerObjectTarget(targetBytes, maximumBytes uint64) (uint64, error) {
	if targetBytes == 0 {
		targetBytes = defaultProviderObjectBytes
	}

	if maximumBytes > 0 {
		targetBytes = min(targetBytes, maximumBytes)
	}

	if targetBytes == 0 || targetBytes > math.MaxInt64 || maximumBytes > math.MaxInt64 {
		return 0, fmt.Errorf("%w: provider object target is out of range", ErrInvalidConfiguration)
	}

	return targetBytes, nil
}

func verifyProviderObject(
	ctx context.Context,
	reader provider.Reader,
	key string,
	expectedBytes uint64,
	expectedDigest []byte,
	integrityError error,
) error {
	expectedLength, err := safeProviderObjectLength(expectedBytes, integrityError)
	if err != nil {
		return fmt.Errorf("verify destination %q: %w", key, err)
	}

	stream, err := reader.OpenRange(ctx, key, 0, expectedBytes)
	if err != nil {
		return fmt.Errorf("verify destination %q: open range: %w", key, err)
	}

	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(
		hasher,
		io.LimitReader(stream, expectedLength+1),
		make([]byte, verificationBufferBytes),
	)

	closeErr := stream.Close()
	if copyErr != nil || closeErr != nil {
		return fmt.Errorf("verify destination %q: read: %w", key, errors.Join(copyErr, closeErr))
	}

	if written != expectedLength {
		return fmt.Errorf(
			"%w: destination %q returned %d bytes, expected %d",
			integrityError,
			key,
			written,
			expectedBytes,
		)
	}

	if !equalDigest(hasher.Sum(nil), expectedDigest) {
		return fmt.Errorf("%w: destination %q SHA-256 mismatch", integrityError, key)
	}

	return nil
}

func writeRecoverySidecar(
	ctx context.Context,
	destination provider.ReadWriter,
	prefix string,
	recovery manifest.RecoveryManifest,
	maximumBytes uint64,
	boundaryError,
	integrityError error,
) (string, provider.Object, error) {
	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		return "", provider.Object{}, fmt.Errorf("marshal recovery sidecar: %w", err)
	}

	digest := sha256.Sum256(encoded)
	digestHex := hex.EncodeToString(digest[:])

	encodedBytes := uint64(len(encoded))
	if maximumBytes > 0 && encodedBytes > maximumBytes {
		return "", provider.Object{}, fmt.Errorf(
			"%w: recovery sidecar has %d bytes, destination maximum is %d",
			boundaryError,
			encodedBytes,
			maximumBytes,
		)
	}

	storageKey := recoverySidecarStorageKey(prefix, recovery.ManifestSHA256, digestHex)
	if !validPlanString(storageKey, maximumProviderKeyBytes) {
		return "", provider.Object{}, fmt.Errorf("%w: recovery sidecar key exceeds protocol bounds", boundaryError)
	}

	uploaded, err := destination.Put(
		ctx,
		storageKey,
		bytes.NewReader(encoded),
		provider.PutOptions{SizeBytes: encodedBytes, SHA256: digestHex},
	)
	if err != nil {
		return "", provider.Object{}, fmt.Errorf("upload recovery sidecar %q: %w", storageKey, err)
	}

	if uploaded.SizeBytes != encodedBytes {
		return "", provider.Object{}, fmt.Errorf("%w: recovery sidecar size changed", integrityError)
	}

	if err := verifyProviderObject(
		ctx,
		destination,
		storageKey,
		encodedBytes,
		digest[:],
		integrityError,
	); err != nil {
		return "", provider.Object{}, err
	}

	return storageKey, uploaded, nil
}

func safeProviderObjectLength(value uint64, integrityError error) (int64, error) {
	if value >= math.MaxInt64 {
		return 0, fmt.Errorf("%w: object exceeds signed stream range", integrityError)
	}

	return int64(value), nil
}

func providerObjectStorageKey(prefix, digest string) string {
	return path.Join(prefix, "objects", digest[:2], digest)
}

func recoverySidecarStorageKey(prefix, manifestDigest, recoveryDigest string) string {
	return path.Join(prefix, "manifests", manifestDigest[:2], manifestDigest, recoveryDigest+".json")
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}

	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}

	return difference == 0
}
