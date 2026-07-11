package cryptostream_test

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/cryptostream"
)

func TestFramesRoundTripIncludingPartialFinalFrame(t *testing.T) {
	t.Parallel()

	packCipher := newTestCipher(t, 10, 4)
	frames := [][]byte{[]byte("abcd"), []byte("efgh"), []byte("ij")}

	for ordinal, plaintext := range frames {
		ciphertext, err := packCipher.SealFrame(nil, plaintext, uint64(ordinal))
		if err != nil {
			t.Fatalf("seal frame %d: %v", ordinal, err)
		}

		opened, err := packCipher.OpenFrame(nil, ciphertext, uint64(ordinal))
		if err != nil {
			t.Fatalf("open frame %d: %v", ordinal, err)
		}

		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("frame %d mismatch: got %q want %q", ordinal, opened, plaintext)
		}
	}
}

func TestFramesRejectTamperingWrongOrdinalAndContext(t *testing.T) {
	t.Parallel()

	packCipher := newTestCipher(t, 8, 4)

	ciphertext, err := packCipher.SealFrame(nil, []byte("abcd"), 0)
	if err != nil {
		t.Fatalf("seal frame: %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0x80

	if _, err := packCipher.OpenFrame(nil, tampered, 0); !errors.Is(err, cryptostream.ErrFrameAuthentication) {
		t.Fatalf("expected tamper authentication error, got %v", err)
	}

	if _, err := packCipher.OpenFrame(nil, ciphertext, 1); !errors.Is(err, cryptostream.ErrFrameAuthentication) {
		t.Fatalf("expected ordinal authentication error, got %v", err)
	}

	differentContext := newTestCipherWithPack(t, 8, 4, identifier(0x70))
	if _, err := differentContext.OpenFrame(nil, ciphertext, 0); !errors.Is(err, cryptostream.ErrFrameAuthentication) {
		t.Fatalf("expected context authentication error, got %v", err)
	}
}

func TestFramesRejectIncorrectLengthsAndOrdinals(t *testing.T) {
	t.Parallel()

	packCipher := newTestCipher(t, 5, 4)

	if _, err := packCipher.SealFrame(nil, []byte("short"), 0); !errors.Is(err, cryptostream.ErrInvalidFrame) {
		t.Fatalf("expected invalid plaintext length, got %v", err)
	}

	if _, err := packCipher.SealFrame(nil, []byte("x"), 2); !errors.Is(err, cryptostream.ErrInvalidFrame) {
		t.Fatalf("expected invalid ordinal, got %v", err)
	}
}

func TestDescriptorRejectsInvalidContextsAndOverflow(t *testing.T) {
	t.Parallel()

	valid := cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    identifier(0x20),
		EpochID:        7,
		PackID:         identifier(0x40),
		FrameBytes:     8,
		PlaintextBytes: 16,
	}

	invalidDescriptors := []cryptostream.Descriptor{
		func() cryptostream.Descriptor { value := valid; value.Suite = "unknown"; return value }(),
		func() cryptostream.Descriptor { value := valid; value.RootVersion = 0; return value }(),
		func() cryptostream.Descriptor {
			value := valid
			value.NamespaceID = cryptostream.Identifier{}

			return value
		}(),
		func() cryptostream.Descriptor { value := valid; value.PackID = cryptostream.Identifier{}; return value }(),
		func() cryptostream.Descriptor { value := valid; value.FrameBytes = 0; return value }(),
	}

	for index, descriptor := range invalidDescriptors {
		if err := descriptor.Validate(); !errors.Is(err, cryptostream.ErrInvalidDescriptor) {
			t.Errorf("descriptor %d: expected validation error, got %v", index, err)
		}
	}

	overflow := valid
	overflow.FrameBytes = 1
	overflow.PlaintextBytes = math.MaxUint64

	if _, err := overflow.CiphertextBytes(); !errors.Is(err, cryptostream.ErrInvalidDescriptor) {
		t.Fatalf("expected ciphertext overflow error, got %v", err)
	}
}

func TestDescriptorCalculatesCiphertextSpans(t *testing.T) {
	t.Parallel()

	descriptor := cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    identifier(0x20),
		EpochID:        7,
		PackID:         identifier(0x40),
		FrameBytes:     8,
		PlaintextBytes: 19,
	}

	firstOffset, firstLength, err := descriptor.CiphertextSpan(0, 2)
	if err != nil {
		t.Fatalf("calculate first ciphertext span: %v", err)
	}

	if firstOffset != 0 || firstLength != 48 {
		t.Fatalf("first ciphertext span = (%d, %d), want (0, 48)", firstOffset, firstLength)
	}

	lastOffset, lastLength, err := descriptor.CiphertextSpan(2, 1)
	if err != nil {
		t.Fatalf("calculate last ciphertext span: %v", err)
	}

	if lastOffset != 48 || lastLength != 19 {
		t.Fatalf("last ciphertext span = (%d, %d), want (48, 19)", lastOffset, lastLength)
	}
}

func TestDescriptorNeverPadsPartialFinalFrame(t *testing.T) {
	t.Parallel()

	const frameBytes = uint64(4 << 20)
	for _, plaintextBytes := range []uint64{
		1,
		frameBytes - 1,
		frameBytes,
		frameBytes + 1,
		3*frameBytes + 17,
	} {
		descriptor := cryptostream.Descriptor{
			Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
			RootVersion:    1,
			NamespaceID:    identifier(0x20),
			EpochID:        7,
			PackID:         identifier(0x40),
			FrameBytes:     frameBytes,
			PlaintextBytes: plaintextBytes,
		}

		ciphertextBytes, err := descriptor.CiphertextBytes()
		if err != nil {
			t.Fatalf("plaintext %d: calculate ciphertext bytes: %v", plaintextBytes, err)
		}

		expected := plaintextBytes + 16*descriptor.FrameCount()
		if ciphertextBytes != expected {
			t.Fatalf(
				"plaintext %d: ciphertext has %d bytes, expected exact payload plus tags %d",
				plaintextBytes,
				ciphertextBytes,
				expected,
			)
		}
	}
}

func TestDescriptorRejectsInvalidCiphertextSpan(t *testing.T) {
	t.Parallel()

	descriptor := cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    identifier(0x20),
		EpochID:        7,
		PackID:         identifier(0x40),
		FrameBytes:     8,
		PlaintextBytes: 19,
	}

	for _, span := range []struct {
		first uint64
		count uint64
	}{
		{first: 0, count: 0},
		{first: descriptor.FrameCount(), count: 1},
		{first: 0, count: descriptor.FrameCount() + 1},
	} {
		_, _, err := descriptor.CiphertextSpan(span.first, span.count)
		if !errors.Is(err, cryptostream.ErrInvalidFrame) {
			t.Fatalf("span (%d, %d): expected ErrInvalidFrame, got %v", span.first, span.count, err)
		}
	}
}

func TestEveryDescriptorFieldAuthenticatesFrames(t *testing.T) {
	t.Parallel()

	base := cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    identifier(0x20),
		EpochID:        7,
		PackID:         identifier(0x40),
		FrameBytes:     4,
		PlaintextBytes: 8,
	}

	packCipher := integrationTestCipher(t, base)

	ciphertext, err := packCipher.SealFrame(nil, []byte("abcd"), 0)
	if err != nil {
		t.Fatalf("seal base frame: %v", err)
	}

	mutations := []cryptostream.Descriptor{
		func() cryptostream.Descriptor { value := base; value.RootVersion++; return value }(),
		func() cryptostream.Descriptor { value := base; value.NamespaceID[0] ^= 1; return value }(),
		func() cryptostream.Descriptor { value := base; value.EpochID++; return value }(),
		func() cryptostream.Descriptor { value := base; value.PackID[0] ^= 1; return value }(),
		func() cryptostream.Descriptor { value := base; value.FrameBytes = 8; return value }(),
		func() cryptostream.Descriptor { value := base; value.PlaintextBytes = 9; return value }(),
	}

	for index, descriptor := range mutations {
		mutatedCipher := integrationTestCipher(t, descriptor)

		_, openErr := mutatedCipher.OpenFrame(nil, ciphertext, 0)
		if !errors.Is(openErr, cryptostream.ErrFrameAuthentication) &&
			!errors.Is(openErr, cryptostream.ErrInvalidFrame) {
			t.Errorf("mutation %d: expected authenticated rejection, got %v", index, openErr)
		}
	}
}

func TestCipherSupportsConcurrentFrames(t *testing.T) {
	t.Parallel()

	const frameCount = 64

	var waitGroup sync.WaitGroup

	packCipher := newTestCipher(t, frameCount*32, 32)

	for ordinal := range uint64(frameCount) {
		waitGroup.Go(func() {
			plaintext := bytes.Repeat([]byte{byte(ordinal)}, 32)

			ciphertext, err := packCipher.SealFrame(nil, plaintext, ordinal)
			if err != nil {
				t.Errorf("seal frame %d: %v", ordinal, err)

				return
			}

			opened, err := packCipher.OpenFrame(nil, ciphertext, ordinal)
			if err != nil {
				t.Errorf("open frame %d: %v", ordinal, err)

				return
			}

			if !bytes.Equal(opened, plaintext) {
				t.Errorf("frame %d round trip mismatch", ordinal)
			}
		})
	}

	waitGroup.Wait()
}

func FuzzFrameRoundTrip(fuzz *testing.F) {
	fuzz.Add([]byte("carrack"))
	fuzz.Add([]byte{})

	fuzz.Fuzz(func(t *testing.T, plaintext []byte) {
		if len(plaintext) > 1<<20 {
			t.Skip()
		}

		frameBytes := max(1, len(plaintext))

		packCipher := newTestCipher(t, uint64(len(plaintext)), uint64(frameBytes))
		if len(plaintext) == 0 {
			if _, err := packCipher.SealFrame(nil, nil, 0); !errors.Is(err, cryptostream.ErrInvalidFrame) {
				t.Fatalf("expected empty pack to reject frame: %v", err)
			}

			return
		}

		ciphertext, err := packCipher.SealFrame(nil, plaintext, 0)
		if err != nil {
			t.Fatalf("seal frame: %v", err)
		}

		opened, err := packCipher.OpenFrame(nil, ciphertext, 0)
		if err != nil {
			t.Fatalf("open frame: %v", err)
		}

		if !bytes.Equal(opened, plaintext) {
			t.Fatal("round trip mismatch")
		}
	})
}

func FuzzFrameRejectsBitFlips(fuzz *testing.F) {
	fuzz.Add([]byte("carrack"), uint64(0))
	fuzz.Add([]byte{0}, uint64(16))

	fuzz.Fuzz(func(t *testing.T, plaintext []byte, selected uint64) {
		if len(plaintext) == 0 || len(plaintext) > 1<<20 {
			t.Skip()
		}

		packCipher := newTestCipher(t, uint64(len(plaintext)), uint64(len(plaintext)))

		ciphertext, err := packCipher.SealFrame(nil, plaintext, 0)
		if err != nil {
			t.Fatalf("seal frame: %v", err)
		}

		position := selected % uint64(len(ciphertext))
		ciphertext[position] ^= 1

		if _, openErr := packCipher.OpenFrame(nil, ciphertext, 0); !errors.Is(openErr, cryptostream.ErrFrameAuthentication) {
			t.Fatalf("expected authentication failure, got %v", openErr)
		}
	})
}

func BenchmarkSealFrame8MiB(benchmark *testing.B) {
	packCipher := newTestCipher(benchmark, cryptostream.DefaultFrameBytes, cryptostream.DefaultFrameBytes)
	plaintext := make([]byte, cryptostream.DefaultFrameBytes)
	destination := make([]byte, 0, cryptostream.DefaultFrameBytes+16)

	benchmark.SetBytes(int64(len(plaintext)))
	benchmark.ReportAllocs()

	for benchmark.Loop() {
		if _, err := packCipher.SealFrame(destination[:0], plaintext, 0); err != nil {
			benchmark.Fatalf("seal frame: %v", err)
		}
	}
}

func BenchmarkOpenFrame8MiB(benchmark *testing.B) {
	packCipher := newTestCipher(benchmark, cryptostream.DefaultFrameBytes, cryptostream.DefaultFrameBytes)
	plaintext := make([]byte, cryptostream.DefaultFrameBytes)

	ciphertext, err := packCipher.SealFrame(nil, plaintext, 0)
	if err != nil {
		benchmark.Fatalf("prepare ciphertext: %v", err)
	}

	destination := make([]byte, 0, cryptostream.DefaultFrameBytes)

	benchmark.SetBytes(int64(len(plaintext)))
	benchmark.ReportAllocs()

	for benchmark.Loop() {
		if _, openErr := packCipher.OpenFrame(destination[:0], ciphertext, 0); openErr != nil {
			benchmark.Fatalf("open frame: %v", openErr)
		}
	}
}

func newTestCipher(tb testing.TB, plaintextBytes, frameBytes uint64) *cryptostream.Cipher {
	tb.Helper()

	return newTestCipherWithPack(tb, plaintextBytes, frameBytes, identifier(0x40))
}

func newTestCipherWithPack(
	tb testing.TB,
	plaintextBytes uint64,
	frameBytes uint64,
	packID cryptostream.Identifier,
) *cryptostream.Cipher {
	tb.Helper()

	epochKey, err := cryptostream.DeriveEpochKey(sequentialRootKey(), cryptostream.EpochContext{
		NamespaceID: identifier(0x20),
		EpochID:     7,
	})
	if err != nil {
		tb.Fatalf("derive epoch key: %v", err)
	}

	packKey, err := cryptostream.DerivePackKey(epochKey, packID)
	if err != nil {
		tb.Fatalf("derive pack key: %v", err)
	}

	packCipher, err := cryptostream.NewCipher(packKey, cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    1,
		NamespaceID:    identifier(0x20),
		EpochID:        7,
		PackID:         packID,
		FrameBytes:     frameBytes,
		PlaintextBytes: plaintextBytes,
	})
	if err != nil {
		tb.Fatalf("construct pack cipher: %v", err)
	}

	return packCipher
}

func integrationTestCipher(tb testing.TB, descriptor cryptostream.Descriptor) *cryptostream.Cipher {
	tb.Helper()

	epochKey, err := cryptostream.DeriveEpochKey(sequentialRootKey(), cryptostream.EpochContext{
		NamespaceID: descriptor.NamespaceID,
		EpochID:     descriptor.EpochID,
	})
	if err != nil {
		tb.Fatalf("derive descriptor epoch key: %v", err)
	}

	packKey, err := cryptostream.DerivePackKey(epochKey, descriptor.PackID)
	if err != nil {
		tb.Fatalf("derive descriptor pack key: %v", err)
	}

	packCipher, err := cryptostream.NewCipher(packKey, descriptor)
	if err != nil {
		tb.Fatalf("construct descriptor cipher: %v", err)
	}

	return packCipher
}
