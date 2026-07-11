package cryptostream_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/dravengarden/carrack/cryptostream"
)

func TestFrameStreamsRoundTripPartialSpanWithExactHashes(t *testing.T) {
	t.Parallel()

	plaintext := []byte("nineteen-byte-value")
	descriptor := cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    identifier(0x20),
		EpochID:        7,
		PackID:         identifier(0x40),
		FrameBytes:     8,
		PlaintextBytes: uint64(len(plaintext)),
	}
	packCipher := integrationTestCipher(t, descriptor)

	var ciphertext bytes.Buffer

	sealed, err := packCipher.SealFrames(
		context.Background(),
		&ciphertext,
		bytes.NewReader(plaintext[16:]),
		2,
		1,
	)
	if err != nil {
		t.Fatalf("seal partial frame span: %v", err)
	}

	if sealed.PlaintextBytes != 3 || sealed.CiphertextBytes != 19 {
		t.Fatalf("unexpected sealed dimensions: %+v", sealed)
	}

	if sealed.PlaintextSHA256 != cryptostream.StreamDigest(sha256.Sum256(plaintext[16:])) {
		t.Fatal("sealed plaintext hash mismatch")
	}

	if sealed.CiphertextSHA256 != cryptostream.StreamDigest(sha256.Sum256(ciphertext.Bytes())) {
		t.Fatal("sealed ciphertext hash mismatch")
	}

	var opened bytes.Buffer

	decrypted, err := packCipher.OpenFrames(
		context.Background(),
		&opened,
		bytes.NewReader(ciphertext.Bytes()),
		2,
		1,
	)
	if err != nil {
		t.Fatalf("open partial frame span: %v", err)
	}

	if !bytes.Equal(opened.Bytes(), plaintext[16:]) || decrypted != sealed {
		t.Fatalf("stream round trip mismatch: opened %q result %+v", opened.Bytes(), decrypted)
	}
}

func TestFrameStreamsRejectShortAndTrailingInputs(t *testing.T) {
	t.Parallel()

	packCipher := newTestCipher(t, 8, 4)

	for _, plaintext := range [][]byte{[]byte("1234567"), []byte("123456789")} {
		_, err := packCipher.SealFrames(
			context.Background(),
			io.Discard,
			bytes.NewReader(plaintext),
			0,
			2,
		)
		if !errors.Is(err, cryptostream.ErrStreamLength) {
			t.Errorf("input length %d: expected ErrStreamLength, got %v", len(plaintext), err)
		}
	}
}

func TestFrameStreamsHonorCancellationBeforeProducingData(t *testing.T) {
	t.Parallel()

	packCipher := newTestCipher(t, 8, 4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var destination bytes.Buffer

	_, err := packCipher.SealFrames(ctx, &destination, bytes.NewReader([]byte("12345678")), 0, 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}

	if destination.Len() != 0 {
		t.Fatalf("cancelled stream wrote %d bytes", destination.Len())
	}
}
