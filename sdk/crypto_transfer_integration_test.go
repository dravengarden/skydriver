package sdk_test

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"

	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

type replicaReader struct {
	objects map[string][]byte
}

func (reader replicaReader) Stat(_ context.Context, key string) (provider.Object, error) {
	data := reader.objects[key]

	return provider.Object{Key: key, SizeBytes: uint64(len(data))}, nil
}

func (reader replicaReader) OpenRange(
	_ context.Context,
	key string,
	offset, length uint64,
) (io.ReadCloser, error) {
	data := reader.objects[key]

	return io.NopCloser(bytes.NewReader(data[offset : offset+length])), nil
}

func TestMultiSourceTransferAndCryptoAreOrthogonal(t *testing.T) {
	t.Parallel()

	plaintext := []byte("provider selection cannot affect Carrack crypto")
	descriptor := integrationDescriptor(uint64(len(plaintext)), 7)
	packCipher := integrationCipher(t, descriptor)
	ciphertext := sealPack(t, packCipher, descriptor, plaintext)

	corrupt := append([]byte(nil), ciphertext...)
	corrupt[len(corrupt)/2] ^= 1

	healthyObject := append([]byte("prefix"), ciphertext...)
	healthyObject = append(healthyObject, []byte("suffix")...)

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"corrupt-drive": replicaReader{objects: map[string][]byte{"leaf": corrupt}},
		"healthy-r2":    replicaReader{objects: map[string][]byte{"packed": healthyObject}},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct multi-source fetcher: %v", err)
	}

	verified, err := fetcher.Fetch(context.Background(), transfer.Extent{
		ID:              transfer.DigestBytes(ciphertext),
		CiphertextBytes: uint64(len(ciphertext)),
		Locations: []transfer.Location{
			{DriverID: "corrupt-drive", Key: "leaf", Length: uint64(len(ciphertext))},
			{
				DriverID: "healthy-r2",
				Key:      "packed",
				Offset:   uint64(len("prefix")),
				Length:   uint64(len(ciphertext)),
			},
		},
	})
	if err != nil {
		t.Fatalf("fetch verified ciphertext: %v", err)
	}

	if verified.Location.DriverID != "healthy-r2" {
		t.Fatalf("expected healthy replica, got %q", verified.Location.DriverID)
	}

	opened := openPack(t, packCipher, descriptor, verified.Data)
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}
}

func TestTransferAcceptsOpaqueNonCarrackCiphertext(t *testing.T) {
	t.Parallel()

	opaque := []byte("transfer does not parse encryption formats")

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"source": replicaReader{objects: map[string][]byte{"opaque": opaque}},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct opaque fetcher: %v", err)
	}

	verified, err := fetcher.Fetch(context.Background(), transfer.Extent{
		ID:              transfer.DigestBytes(opaque),
		CiphertextBytes: uint64(len(opaque)),
		Locations: []transfer.Location{
			{DriverID: "source", Key: "opaque", Length: uint64(len(opaque))},
		},
	})
	if err != nil {
		t.Fatalf("fetch opaque extent: %v", err)
	}

	if !bytes.Equal(verified.Data, opaque) {
		t.Fatalf("opaque bytes changed: got %q want %q", verified.Data, opaque)
	}
}

func TestConcurrentTransferPipelineDecryptsOutOfOrderExtents(t *testing.T) {
	t.Parallel()

	plaintext := []byte("parallel transfer remains independent from parallel decryption")
	descriptor := integrationDescriptor(uint64(len(plaintext)), 8)
	packCipher := integrationCipher(t, descriptor)

	extents := make([]transfer.Extent, descriptor.FrameCount())

	objects := make(map[string][]byte, descriptor.FrameCount())
	for ordinal := range descriptor.FrameCount() {
		offset := ordinal * descriptor.FrameBytes
		frameBytes := min(descriptor.FrameBytes, descriptor.PlaintextBytes-offset)

		ciphertext, err := packCipher.SealFrame(nil, plaintext[offset:offset+frameBytes], ordinal)
		if err != nil {
			t.Fatalf("seal concurrent frame %d: %v", ordinal, err)
		}

		key := string(rune('a' + ordinal))
		objects[key] = ciphertext
		extents[ordinal] = transfer.Extent{
			ID:              transfer.DigestBytes(ciphertext),
			CiphertextBytes: uint64(len(ciphertext)),
			Locations: []transfer.Location{
				{DriverID: "source", Key: key, Length: uint64(len(ciphertext))},
			},
		}
	}

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"source": replicaReader{objects: objects},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct concurrent fetcher: %v", err)
	}

	opened := make([]byte, len(plaintext))

	var completed atomic.Uint64

	err = fetcher.FetchBatch(context.Background(), extents, 4, func(
		_ context.Context,
		ordinal int,
		verified transfer.VerifiedExtent,
	) error {
		frameOrdinal := uint64(ordinal)

		frame, openErr := packCipher.OpenFrame(nil, verified.Data, frameOrdinal)
		if openErr != nil {
			return openErr
		}

		offset := frameOrdinal * descriptor.FrameBytes
		copy(opened[offset:offset+uint64(len(frame))], frame)
		completed.Add(1)

		return nil
	})
	if err != nil {
		t.Fatalf("run concurrent transfer pipeline: %v", err)
	}

	if completed.Load() != descriptor.FrameCount() || !bytes.Equal(opened, plaintext) {
		t.Fatalf("concurrent plaintext mismatch: got %q want %q", opened, plaintext)
	}
}

func integrationCipher(t *testing.T, descriptor cryptostream.Descriptor) *cryptostream.Cipher {
	t.Helper()

	var rootKey cryptostream.RootKey
	for index := range rootKey {
		rootKey[index] = byte(index + 1)
	}

	epochKey, err := cryptostream.DeriveEpochKey(rootKey, cryptostream.EpochContext{
		NamespaceID: descriptor.NamespaceID,
		EpochID:     descriptor.EpochID,
	})
	if err != nil {
		t.Fatalf("derive integration epoch key: %v", err)
	}

	packKey, err := cryptostream.DerivePackKey(epochKey, descriptor.PackID)
	if err != nil {
		t.Fatalf("derive integration pack key: %v", err)
	}

	packCipher, err := cryptostream.NewCipher(packKey, descriptor)
	if err != nil {
		t.Fatalf("construct integration cipher: %v", err)
	}

	return packCipher
}

func integrationDescriptor(plaintextBytes, frameBytes uint64) cryptostream.Descriptor {
	return cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    integrationIdentifier(0x20),
		EpochID:        7,
		PackID:         integrationIdentifier(0x40),
		FrameBytes:     frameBytes,
		PlaintextBytes: plaintextBytes,
	}
}

func integrationIdentifier(start byte) cryptostream.Identifier {
	var value cryptostream.Identifier
	for index := range value {
		value[index] = start + byte(index)
	}

	return value
}

func sealPack(
	t *testing.T,
	packCipher *cryptostream.Cipher,
	descriptor cryptostream.Descriptor,
	plaintext []byte,
) []byte {
	t.Helper()

	ciphertext := make([]byte, 0, len(plaintext)+int(descriptor.FrameCount())*16)
	for ordinal := range descriptor.FrameCount() {
		offset := ordinal * descriptor.FrameBytes
		frameBytes := min(descriptor.FrameBytes, descriptor.PlaintextBytes-offset)
		frame := plaintext[offset : offset+frameBytes]

		var err error

		ciphertext, err = packCipher.SealFrame(ciphertext, frame, ordinal)
		if err != nil {
			t.Fatalf("seal integration frame %d: %v", ordinal, err)
		}
	}

	return ciphertext
}

func openPack(
	t *testing.T,
	packCipher *cryptostream.Cipher,
	descriptor cryptostream.Descriptor,
	ciphertext []byte,
) []byte {
	t.Helper()

	plaintext := make([]byte, 0, descriptor.PlaintextBytes)
	ciphertextOffset := uint64(0)

	for ordinal := range descriptor.FrameCount() {
		plaintextOffset := ordinal * descriptor.FrameBytes
		plaintextBytes := min(descriptor.FrameBytes, descriptor.PlaintextBytes-plaintextOffset)
		ciphertextBytes := plaintextBytes + 16
		frame := ciphertext[ciphertextOffset : ciphertextOffset+ciphertextBytes]

		var err error

		plaintext, err = packCipher.OpenFrame(plaintext, frame, ordinal)
		if err != nil {
			t.Fatalf("open integration frame %d: %v", ordinal, err)
		}

		ciphertextOffset += ciphertextBytes
	}

	return plaintext
}
