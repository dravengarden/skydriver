package cryptofile_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/dravengarden/skydriver/vfs/cryptofile"
	"github.com/dravengarden/skydriver/vfs/merkle"
)

func TestCompleteFileRoundTripAndIdentity(t *testing.T) {
	t.Parallel()

	payload := []byte("complete Skydriver files use independent authenticated frames")
	descriptor := testDescriptor(uint64(len(payload)))

	fileCipher, err := cryptofile.New(testKey(), descriptor)
	if err != nil {
		t.Fatalf("construct VFS cipher: %v", err)
	}

	var encoded bytes.Buffer

	sealed, err := fileCipher.Seal(context.Background(), &encoded, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("seal VFS file: %v", err)
	}

	expectedBytes, err := descriptor.EncodedBytes()
	if err != nil {
		t.Fatalf("compute encoded bytes: %v", err)
	}

	digest := sha256.Sum256(encoded.Bytes())
	if sealed.PlaintextBytes != uint64(len(payload)) || sealed.EncodedBytes != expectedBytes ||
		sealed.EncodedSHA256 != digest {
		t.Fatalf("unexpected seal result: %+v", sealed)
	}

	var opened bytes.Buffer

	openResult, err := fileCipher.Open(context.Background(), &opened, bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatalf("open VFS file: %v", err)
	}

	if !bytes.Equal(opened.Bytes(), payload) || openResult != sealed {
		t.Fatalf("round trip differs: result=%+v payload=%q", openResult, opened.Bytes())
	}
}

func TestFileContextAndCiphertextAreAuthenticated(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("x"), 19)
	descriptor := testDescriptor(uint64(len(payload)))

	fileCipher, err := cryptofile.New(testKey(), descriptor)
	if err != nil {
		t.Fatalf("construct VFS cipher: %v", err)
	}

	var encoded bytes.Buffer
	if _, sealErr := fileCipher.Seal(context.Background(), &encoded, bytes.NewReader(payload)); sealErr != nil {
		t.Fatalf("seal VFS file: %v", sealErr)
	}

	tampered := bytes.Clone(encoded.Bytes())

	tampered[len(tampered)/2] ^= 1
	if _, openErr := fileCipher.Open(context.Background(), &bytes.Buffer{}, bytes.NewReader(tampered)); !errors.Is(openErr, cryptofile.ErrAuthentication) {
		t.Fatalf("tampered ciphertext was not rejected: %v", openErr)
	}

	changed := descriptor
	changed.VersionID = merkle.Identifier{3, 1}

	changedCipher, err := cryptofile.New(testKey(), changed)
	if err != nil {
		t.Fatalf("construct changed VFS cipher: %v", err)
	}

	if _, openErr := changedCipher.Open(context.Background(), &bytes.Buffer{}, bytes.NewReader(encoded.Bytes())); !errors.Is(openErr, cryptofile.ErrAuthentication) {
		t.Fatalf("changed version identity was not rejected: %v", openErr)
	}
}

func TestEmptyFileHasCanonicalEmptyEncoding(t *testing.T) {
	t.Parallel()

	descriptor := testDescriptor(0)

	fileCipher, err := cryptofile.New(testKey(), descriptor)
	if err != nil {
		t.Fatalf("construct empty VFS cipher: %v", err)
	}

	var encoded bytes.Buffer

	result, err := fileCipher.Seal(context.Background(), &encoded, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("seal empty VFS file: %v", err)
	}

	if result.EncodedBytes != 0 || encoded.Len() != 0 || result.EncodedSHA256 != sha256.Sum256(nil) {
		t.Fatalf("unexpected empty encoding: %+v %x", result, encoded.Bytes())
	}
}

func testKey() cryptofile.DirectoryKey {
	var key cryptofile.DirectoryKey
	for index := range key {
		key[index] = byte(index + 1)
	}

	return key
}

func testDescriptor(sizeBytes uint64) cryptofile.Descriptor {
	return cryptofile.Descriptor{
		Suite:          cryptofile.Suite,
		DirectoryID:    merkle.Identifier{1, 1},
		VersionID:      merkle.Identifier{2, 1},
		KeyEpoch:       7,
		FrameBytes:     8,
		PlaintextBytes: sizeBytes,
	}
}
