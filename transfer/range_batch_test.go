package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/transfer"
)

type recordedRange struct {
	key    string
	offset uint64
	length uint64
}

type recordingRangeReader struct {
	mutex   sync.Mutex
	objects map[string][]byte
	calls   []recordedRange
}

func (reader *recordingRangeReader) Stat(_ context.Context, key string) (provider.Object, error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()

	data, exists := reader.objects[key]
	if !exists {
		return provider.Object{}, errSourceFailure
	}

	return provider.Object{Key: key, SizeBytes: uint64(len(data))}, nil
}

func (reader *recordingRangeReader) OpenRange(
	_ context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()

	data, exists := reader.objects[key]
	if !exists || offset > uint64(len(data)) || length > uint64(len(data))-offset {
		return nil, errSourceFailure
	}

	reader.calls = append(reader.calls, recordedRange{key: key, offset: offset, length: length})
	selected := bytes.Clone(data[offset : offset+length])

	return io.NopCloser(bytes.NewReader(selected)), nil
}

func (reader *recordingRangeReader) recordedCalls() []recordedRange {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()

	return append([]recordedRange(nil), reader.calls...)
}

func TestFetchBatchCoalescesExactContiguousPrimaryRanges(t *testing.T) {
	t.Parallel()

	object := []byte("--abcdefghijkl--")
	reader := &recordingRangeReader{objects: map[string][]byte{"object": object}}
	extents := contiguousExtents("primary", "object", object, 2, []uint64{3, 4, 5})

	fetcher, err := transfer.NewFetcherWithOptions(
		map[string]provider.Reader{"primary": reader},
		transfer.FetcherOptions{MaximumExtentBytes: 5, MaximumRangeBytes: 12},
	)
	if err != nil {
		t.Fatalf("construct range fetcher: %v", err)
	}

	received := make([][]byte, len(extents))

	err = fetcher.FetchBatch(context.Background(), extents, 1, func(
		_ context.Context,
		ordinal int,
		verified transfer.VerifiedExtent,
	) error {
		received[ordinal] = bytes.Clone(verified.Data)

		return nil
	})
	if err != nil {
		t.Fatalf("fetch coalesced batch: %v", err)
	}

	if calls := reader.recordedCalls(); len(calls) != 1 || calls[0] != (recordedRange{
		key:    "object",
		offset: 2,
		length: 12,
	}) {
		t.Fatalf("unexpected physical reads: %+v", calls)
	}

	for ordinal, extent := range extents {
		location := extent.Locations[0]

		expected := object[location.Offset : location.Offset+location.Length]
		if !bytes.Equal(received[ordinal], expected) {
			t.Fatalf("extent %d mismatch: got %q want %q", ordinal, received[ordinal], expected)
		}
	}
}

func TestFetchBatchSplitsAtConfiguredRangeBound(t *testing.T) {
	t.Parallel()

	object := []byte("abcdefghijkl")
	reader := &recordingRangeReader{objects: map[string][]byte{"object": object}}
	extents := contiguousExtents("primary", "object", object, 0, []uint64{3, 4, 5})

	fetcher, err := transfer.NewFetcherWithOptions(
		map[string]provider.Reader{"primary": reader},
		transfer.FetcherOptions{MaximumExtentBytes: 5, MaximumRangeBytes: 7},
	)
	if err != nil {
		t.Fatalf("construct bounded range fetcher: %v", err)
	}

	err = fetcher.FetchBatch(context.Background(), extents, 1, func(
		_ context.Context,
		_ int,
		_ transfer.VerifiedExtent,
	) error {
		return nil
	})
	if err != nil {
		t.Fatalf("fetch bounded range batch: %v", err)
	}

	calls := reader.recordedCalls()

	expected := []recordedRange{
		{key: "object", offset: 0, length: 7},
		{key: "object", offset: 7, length: 5},
	}
	if len(calls) != len(expected) {
		t.Fatalf("unexpected physical read count: got %+v want %+v", calls, expected)
	}

	for index := range expected {
		if calls[index] != expected[index] {
			t.Fatalf("physical read %d mismatch: got %+v want %+v", index, calls[index], expected[index])
		}
	}
}

func TestFetchBatchDoesNotBridgePhysicalGapsOrStorageKeys(t *testing.T) {
	t.Parallel()

	reader := &recordingRangeReader{objects: map[string][]byte{
		"first":  []byte("abc-def"),
		"second": []byte("ghi"),
	}}
	extents := []transfer.Extent{
		rangeExtent("primary", "first", reader.objects["first"], 0, 3),
		rangeExtent("primary", "first", reader.objects["first"], 4, 3),
		rangeExtent("primary", "second", reader.objects["second"], 0, 3),
	}

	fetcher, err := transfer.NewFetcherWithOptions(
		map[string]provider.Reader{"primary": reader},
		transfer.FetcherOptions{MaximumExtentBytes: 3, MaximumRangeBytes: 9},
	)
	if err != nil {
		t.Fatalf("construct discontinuous range fetcher: %v", err)
	}

	err = fetcher.FetchBatch(context.Background(), extents, 1, func(
		context.Context,
		int,
		transfer.VerifiedExtent,
	) error {
		return nil
	})
	if err != nil {
		t.Fatalf("fetch discontinuous batch: %v", err)
	}

	if calls := reader.recordedCalls(); len(calls) != len(extents) {
		t.Fatalf("discontinuous locations were coalesced: %+v", calls)
	}
}

func TestFetchBatchFallsBackAfterCoalescedIntegrityFailure(t *testing.T) {
	t.Parallel()

	healthyObject := []byte("abcdefghijkl")
	corruptObject := bytes.Clone(healthyObject)
	corruptObject[4] ^= 1

	primary := &recordingRangeReader{objects: map[string][]byte{"object": corruptObject}}
	healthy := &recordingRangeReader{objects: map[string][]byte{"object": healthyObject}}

	extents := contiguousExtents("primary", "object", healthyObject, 0, []uint64{4, 4, 4})
	for index := range extents {
		location := extents[index].Locations[0]
		extents[index].Locations = append(extents[index].Locations, transfer.Location{
			DriverID: "healthy",
			Key:      location.Key,
			Offset:   location.Offset,
			Length:   location.Length,
		})
	}

	fetcher, err := transfer.NewFetcherWithOptions(
		map[string]provider.Reader{"primary": primary, "healthy": healthy},
		transfer.FetcherOptions{MaximumExtentBytes: 4, MaximumRangeBytes: 12},
	)
	if err != nil {
		t.Fatalf("construct fallback range fetcher: %v", err)
	}

	err = fetcher.FetchBatch(context.Background(), extents, 1, func(
		_ context.Context,
		ordinal int,
		verified transfer.VerifiedExtent,
	) error {
		expectedDriver := "primary"
		if ordinal == 1 {
			expectedDriver = "healthy"
		}

		if verified.Location.DriverID != expectedDriver {
			t.Errorf("extent %d used unexpected replica: %+v", ordinal, verified.Location)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("fetch fallback range batch: %v", err)
	}

	if calls := healthy.recordedCalls(); len(calls) != 1 || calls[0].offset != 4 || calls[0].length != 4 {
		t.Fatalf("expected one exact healthy fallback read, got %+v", calls)
	}
}

func TestFetcherRejectsUnsafeRangeConfigurationAndOverflow(t *testing.T) {
	t.Parallel()

	reader := &recordingRangeReader{objects: map[string][]byte{"object": {1}}}

	_, err := transfer.NewFetcherWithOptions(
		map[string]provider.Reader{"primary": reader},
		transfer.FetcherOptions{MaximumExtentBytes: 8, MaximumRangeBytes: 4},
	)
	if !errors.Is(err, transfer.ErrInvalidFetcher) {
		t.Fatalf("expected invalid range bound, got %v", err)
	}

	fetcher, err := transfer.NewFetcher(map[string]provider.Reader{"primary": reader}, 8)
	if err != nil {
		t.Fatalf("construct overflow test fetcher: %v", err)
	}

	overflow := transfer.Extent{
		ID:              transfer.DigestBytes([]byte{1}),
		CiphertextBytes: 1,
		Locations: []transfer.Location{{
			DriverID: "primary",
			Key:      "object",
			Offset:   math.MaxUint64,
			Length:   1,
		}},
	}

	err = fetcher.FetchBatch(context.Background(), []transfer.Extent{overflow}, 1, func(
		context.Context,
		int,
		transfer.VerifiedExtent,
	) error {
		return nil
	})
	if !errors.Is(err, transfer.ErrInvalidExtent) {
		t.Fatalf("expected overflowing range rejection, got %v", err)
	}

	if calls := reader.recordedCalls(); len(calls) != 0 {
		t.Fatalf("overflowing metadata performed I/O: %+v", calls)
	}
}

func contiguousExtents(
	driverID,
	key string,
	object []byte,
	start uint64,
	lengths []uint64,
) []transfer.Extent {
	extents := make([]transfer.Extent, 0, len(lengths))
	offset := start

	for _, length := range lengths {
		extents = append(extents, rangeExtent(driverID, key, object, offset, length))
		offset += length
	}

	return extents
}

func rangeExtent(driverID, key string, object []byte, offset, length uint64) transfer.Extent {
	return transfer.Extent{
		ID:              transfer.DigestBytes(object[offset : offset+length]),
		CiphertextBytes: length,
		Locations: []transfer.Location{{
			DriverID: driverID,
			Key:      key,
			Offset:   offset,
			Length:   length,
		}},
	}
}
