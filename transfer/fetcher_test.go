package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

var errSourceFailure = errors.New("source failure")

type memoryReader struct {
	objects map[string][]byte
	failure error
}

func (reader memoryReader) Stat(_ context.Context, key string) (provider.Object, error) {
	data, exists := reader.objects[key]
	if !exists {
		return provider.Object{}, errSourceFailure
	}

	return provider.Object{Key: key, SizeBytes: uint64(len(data))}, nil
}

func (reader memoryReader) OpenRange(
	_ context.Context,
	key string,
	offset, length uint64,
) (io.ReadCloser, error) {
	if reader.failure != nil {
		return nil, reader.failure
	}

	data, exists := reader.objects[key]
	if !exists || offset > uint64(len(data)) || length > uint64(len(data))-offset {
		return nil, errSourceFailure
	}

	return io.NopCloser(bytes.NewReader(data[offset : offset+length])), nil
}

func TestFetcherFallsBackFromCorruptReplica(t *testing.T) {
	t.Parallel()

	expected := []byte("verified ciphertext")
	corrupt := append([]byte(nil), expected...)
	corrupt[0] ^= 1

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"slow-corrupt": memoryReader{objects: map[string][]byte{"pack": corrupt}},
		"healthy":      memoryReader{objects: map[string][]byte{"pack": expected}},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct fetcher: %v", err)
	}

	verified, err := fetcher.Fetch(context.Background(), transfer.Extent{
		ID:              transfer.DigestBytes(expected),
		CiphertextBytes: uint64(len(expected)),
		Locations: []transfer.Location{
			{DriverID: "slow-corrupt", Key: "pack", Length: uint64(len(expected))},
			{DriverID: "healthy", Key: "pack", Length: uint64(len(expected))},
		},
	})
	if err != nil {
		t.Fatalf("fetch extent: %v", err)
	}

	if !bytes.Equal(verified.Data, expected) || verified.Location.DriverID != "healthy" {
		t.Fatalf("unexpected verified extent: %+v", verified)
	}
}

func TestFetcherFallsBackFromUnavailableReplica(t *testing.T) {
	t.Parallel()

	expected := []byte("opaque bytes")

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"failed":  memoryReader{failure: errSourceFailure},
		"healthy": memoryReader{objects: map[string][]byte{"pack": expected}},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct fetcher: %v", err)
	}

	verified, err := fetcher.Fetch(context.Background(), transfer.Extent{
		ID:              transfer.DigestBytes(expected),
		CiphertextBytes: uint64(len(expected)),
		Locations: []transfer.Location{
			{DriverID: "failed", Key: "pack", Length: uint64(len(expected))},
			{DriverID: "healthy", Key: "pack", Length: uint64(len(expected))},
		},
	})
	if err != nil {
		t.Fatalf("fetch extent: %v", err)
	}

	if !bytes.Equal(verified.Data, expected) {
		t.Fatalf("unexpected bytes %q", verified.Data)
	}
}

func TestFetcherReportsAllSourceFailures(t *testing.T) {
	t.Parallel()

	expected := []byte("expected")

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"failed": memoryReader{failure: errSourceFailure},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct fetcher: %v", err)
	}

	_, err = fetcher.Fetch(context.Background(), transfer.Extent{
		ID:              transfer.DigestBytes(expected),
		CiphertextBytes: uint64(len(expected)),
		Locations: []transfer.Location{
			{DriverID: "missing", Key: "pack", Length: uint64(len(expected))},
			{DriverID: "failed", Key: "pack", Length: uint64(len(expected))},
		},
	})
	if !errors.Is(err, transfer.ErrAllSourcesFailed) {
		t.Fatalf("expected aggregate failure, got %v", err)
	}
}

func TestFetcherEnforcesMemoryBound(t *testing.T) {
	t.Parallel()

	expected := []byte("too large")

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"source": memoryReader{objects: map[string][]byte{"pack": expected}},
	}, 4)
	if err != nil {
		t.Fatalf("construct fetcher: %v", err)
	}

	_, err = fetcher.Fetch(context.Background(), transfer.Extent{
		ID:              transfer.DigestBytes(expected),
		CiphertextBytes: uint64(len(expected)),
		Locations: []transfer.Location{
			{DriverID: "source", Key: "pack", Length: uint64(len(expected))},
		},
	})
	if !errors.Is(err, transfer.ErrExtentTooLarge) {
		t.Fatalf("expected memory-bound error, got %v", err)
	}
}

func TestFetcherStopsBeforeIOWhenContextIsCancelled(t *testing.T) {
	t.Parallel()

	expected := []byte("cancelled")

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"source": memoryReader{objects: map[string][]byte{"pack": expected}},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct fetcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = fetcher.Fetch(ctx, transfer.Extent{
		ID:              transfer.DigestBytes(expected),
		CiphertextBytes: uint64(len(expected)),
		Locations: []transfer.Location{
			{DriverID: "source", Key: "pack", Length: uint64(len(expected))},
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func FuzzDigestIsContentSensitive(fuzz *testing.F) {
	fuzz.Add([]byte("carrack"))
	fuzz.Add([]byte{})

	fuzz.Fuzz(func(t *testing.T, value []byte) {
		first := transfer.DigestBytes(value)

		second := transfer.DigestBytes(append([]byte(nil), value...))
		if first != second {
			t.Fatal("equal ciphertext produced different digests")
		}

		if len(value) > 0 {
			changed := append([]byte(nil), value...)
			changed[0] ^= 1

			if transfer.DigestBytes(changed) == first {
				t.Fatal("changed ciphertext produced identical digest")
			}
		}
	})
}
