package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

var errConsumerStopped = errors.New("consumer stopped")

type concurrencyReader struct {
	active    *atomic.Int32
	maximum   *atomic.Int32
	data      []byte
	readDelay time.Duration
}

func (reader concurrencyReader) Stat(_ context.Context, key string) (provider.Object, error) {
	return provider.Object{Key: key, SizeBytes: uint64(len(reader.data))}, nil
}

func (reader concurrencyReader) OpenRange(
	ctx context.Context,
	_ string,
	_, _ uint64,
) (io.ReadCloser, error) {
	active := reader.active.Add(1)
	defer reader.active.Add(-1)

	for {
		maximum := reader.maximum.Load()
		if active <= maximum || reader.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}

	timer := time.NewTimer(reader.readDelay)
	defer timer.Stop()

	select {
	case <-timer.C:
		return io.NopCloser(bytes.NewReader(reader.data)), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestFetchBatchBoundsConcurrencyAndPreservesOrdinals(t *testing.T) {
	t.Parallel()

	const (
		extentCount = 12
		concurrency = 3
	)

	data := []byte("ciphertext")

	var (
		active  atomic.Int32
		maximum atomic.Int32
	)

	reader := concurrencyReader{
		active:    &active,
		maximum:   &maximum,
		data:      data,
		readDelay: 5 * time.Millisecond,
	}

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{"source": reader}, 1<<20)
	if err != nil {
		t.Fatalf("construct batch fetcher: %v", err)
	}

	extents := make([]transfer.Extent, extentCount)
	for index := range extents {
		extents[index] = transfer.Extent{
			ID:              transfer.DigestBytes(data),
			CiphertextBytes: uint64(len(data)),
			Locations: []transfer.Location{
				{DriverID: "source", Key: "pack", Length: uint64(len(data))},
			},
		}
	}

	seen := make([]atomic.Int32, extentCount)

	err = fetcher.FetchBatch(context.Background(), extents, concurrency, func(
		_ context.Context,
		ordinal int,
		verified transfer.VerifiedExtent,
	) error {
		if !bytes.Equal(verified.Data, data) {
			t.Errorf("extent %d data mismatch", ordinal)
		}

		seen[ordinal].Add(1)

		return nil
	})
	if err != nil {
		t.Fatalf("fetch batch: %v", err)
	}

	if maximum.Load() > concurrency {
		t.Fatalf("observed concurrency %d exceeds %d", maximum.Load(), concurrency)
	}

	if maximum.Load() < 2 {
		t.Fatalf("expected concurrent work, observed maximum %d", maximum.Load())
	}

	for ordinal := range seen {
		if seen[ordinal].Load() != 1 {
			t.Errorf("extent %d consumed %d times", ordinal, seen[ordinal].Load())
		}
	}
}

func TestFetchBatchCancelsOnConsumerFailure(t *testing.T) {
	t.Parallel()

	data := []byte("ciphertext")

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"source": memoryReader{objects: map[string][]byte{"pack": data}},
	}, 1<<20)
	if err != nil {
		t.Fatalf("construct batch fetcher: %v", err)
	}

	extent := transfer.Extent{
		ID:              transfer.DigestBytes(data),
		CiphertextBytes: uint64(len(data)),
		Locations: []transfer.Location{
			{DriverID: "source", Key: "pack", Length: uint64(len(data))},
		},
	}

	err = fetcher.FetchBatch(context.Background(), []transfer.Extent{extent, extent}, 2, func(
		_ context.Context,
		_ int,
		_ transfer.VerifiedExtent,
	) error {
		return errConsumerStopped
	})
	if !errors.Is(err, transfer.ErrBatchFailed) || !errors.Is(err, errConsumerStopped) {
		t.Fatalf("expected wrapped consumer failure, got %v", err)
	}
}

func TestFetchBatchValidatesConfiguration(t *testing.T) {
	t.Parallel()

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{
		"source": memoryReader{objects: map[string][]byte{}},
	}, 1)
	if err != nil {
		t.Fatalf("construct batch fetcher: %v", err)
	}

	if err := fetcher.FetchBatch(context.Background(), nil, 0, func(context.Context, int, transfer.VerifiedExtent) error {
		return nil
	}); !errors.Is(err, transfer.ErrInvalidBatch) {
		t.Fatalf("expected concurrency validation error, got %v", err)
	}

	if err := fetcher.FetchBatch(context.Background(), nil, 1, nil); !errors.Is(err, transfer.ErrInvalidBatch) {
		t.Fatalf("expected consumer validation error, got %v", err)
	}
}
