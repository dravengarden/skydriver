package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	// ErrInvalidBatch indicates invalid concurrency or a missing consumer.
	ErrInvalidBatch = errors.New("invalid Carrack transfer batch")
	// ErrBatchFailed indicates that fetching or consuming one extent failed.
	ErrBatchFailed = errors.New("carrack transfer batch failed")
)

// Consumer receives verified extents concurrently. The ordinal is the
// extent's position in the submitted batch; completion order is unspecified.
type Consumer func(ctx context.Context, ordinal int, extent VerifiedExtent) error

type batchJob struct {
	extents []batchExtent
	bytes   uint64
}

type batchExtent struct {
	ordinal int
	extent  Extent
}

// FetchBatch fetches a bounded number of extents concurrently and invokes the
// consumer as each one verifies. Adjacent primary locations in the same
// provider object share one exact range request. Peak ciphertext memory is
// bounded by concurrency multiplied by the Fetcher's maximum range size.
func (fetcher *Fetcher) FetchBatch(
	ctx context.Context,
	extents []Extent,
	concurrency uint32,
	consumer Consumer,
) error {
	if fetcher == nil {
		return fmt.Errorf("%w: fetcher is required", ErrInvalidFetcher)
	}

	if concurrency == 0 {
		return fmt.Errorf("%w: concurrency must be positive", ErrInvalidBatch)
	}

	if consumer == nil {
		return fmt.Errorf("%w: consumer is required", ErrInvalidBatch)
	}

	if len(extents) == 0 {
		return nil
	}

	jobs, err := fetcher.planBatch(extents)
	if err != nil {
		return err
	}

	return fetcher.runBatch(ctx, jobs, min(int(concurrency), len(jobs)), consumer)
}

func (fetcher *Fetcher) runBatch(
	ctx context.Context,
	jobs []batchJob,
	workerCount int,
	consumer Consumer,
) error {
	batchContext, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	jobQueue := make(chan batchJob)

	var workers sync.WaitGroup

	workers.Go(func() {
		defer close(jobQueue)

		for _, job := range jobs {
			select {
			case jobQueue <- job:
			case <-batchContext.Done():
				return
			}
		}
	})

	for range workerCount {
		workers.Go(func() {
			for job := range jobQueue {
				verifiedExtents, err := fetcher.fetchBatchJob(batchContext, job)
				if err != nil {
					cancel(fmt.Errorf(
						"%w: extent %d fetch: %w",
						ErrBatchFailed,
						job.extents[0].ordinal,
						err,
					))

					return
				}

				for index, verified := range verifiedExtents {
					ordinal := job.extents[index].ordinal
					if err := consumer(batchContext, ordinal, verified); err != nil {
						cancel(fmt.Errorf("%w: extent %d consume: %w", ErrBatchFailed, ordinal, err))

						return
					}
				}
			}
		})
	}

	workers.Wait()

	cause := context.Cause(batchContext)
	if cause == nil {
		return nil
	}

	return fmt.Errorf("fetch ciphertext batch: %w", cause)
}

func (fetcher *Fetcher) planBatch(extents []Extent) ([]batchJob, error) {
	jobs := make([]batchJob, 0, len(extents))
	current := batchJob{extents: make([]batchExtent, 0)}

	for ordinal, extent := range extents {
		if err := extent.Validate(); err != nil {
			return nil, fmt.Errorf("plan ciphertext batch extent %d: %w", ordinal, err)
		}

		if extent.CiphertextBytes > fetcher.maximumExtentBytes {
			return nil, fmt.Errorf(
				"%w: extent %d has %d bytes, maximum is %d",
				ErrExtentTooLarge,
				ordinal,
				extent.CiphertextBytes,
				fetcher.maximumExtentBytes,
			)
		}

		if len(current.extents) > 0 && !fetcher.canCoalesce(current, extent) {
			jobs = append(jobs, current)
			current = batchJob{extents: make([]batchExtent, 0)}
		}

		current.extents = append(current.extents, batchExtent{ordinal: ordinal, extent: extent})
		current.bytes += extent.CiphertextBytes
	}

	if len(current.extents) > 0 {
		jobs = append(jobs, current)
	}

	return jobs, nil
}

func (fetcher *Fetcher) canCoalesce(current batchJob, next Extent) bool {
	if next.CiphertextBytes > fetcher.maximumRangeBytes-current.bytes {
		return false
	}

	previous := current.extents[len(current.extents)-1].extent.Locations[0]
	nextLocation := next.Locations[0]

	return previous.DriverID == nextLocation.DriverID &&
		previous.Key == nextLocation.Key &&
		previous.Offset+previous.Length == nextLocation.Offset
}

func (fetcher *Fetcher) fetchBatchJob(ctx context.Context, job batchJob) ([]VerifiedExtent, error) {
	if len(job.extents) == 1 {
		verified, err := fetcher.Fetch(ctx, job.extents[0].extent)
		if err != nil {
			return nil, err
		}

		return []VerifiedExtent{verified}, nil
	}

	verified, rangeErr := fetcher.fetchPrimaryRange(ctx, job)
	if rangeErr == nil {
		return verified, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, errors.Join(rangeErr, err)
	}

	verified = make([]VerifiedExtent, 0, len(job.extents))
	for _, item := range job.extents {
		extent, err := fetcher.Fetch(ctx, item.extent)
		if err != nil {
			return nil, errors.Join(
				fmt.Errorf("coalesced primary range: %w", rangeErr),
				fmt.Errorf("fallback extent %d: %w", item.ordinal, err),
			)
		}

		verified = append(verified, extent)
	}

	return verified, nil
}

func (fetcher *Fetcher) fetchPrimaryRange(ctx context.Context, job batchJob) ([]VerifiedExtent, error) {
	firstLocation := job.extents[0].extent.Locations[0]

	reader, exists := fetcher.readers[firstLocation.DriverID]
	if !exists {
		return nil, fmt.Errorf("driver %q: %w", firstLocation.DriverID, ErrNoReplica)
	}

	stream, err := reader.OpenRange(ctx, firstLocation.Key, firstLocation.Offset, job.bytes)
	if err != nil {
		return nil, fmt.Errorf("open coalesced provider range: %w", err)
	}

	verified := make([]VerifiedExtent, 0, len(job.extents))
	for _, item := range job.extents {
		data := make([]byte, item.extent.CiphertextBytes)
		if _, readErr := io.ReadFull(stream, data); readErr != nil {
			return nil, errors.Join(fmt.Errorf("read coalesced provider range: %w", readErr), stream.Close())
		}

		location := item.extent.Locations[0]
		verified = append(verified, VerifiedExtent{
			ID:       item.extent.ID,
			Data:     data,
			Location: location,
		})
	}

	var extra [1]byte

	extraBytes, extraErr := stream.Read(extra[:])
	closeErr := stream.Close()

	if extraBytes != 0 {
		return nil, errors.Join(fmt.Errorf("%w: coalesced provider range exceeded declared length", ErrIntegrity), closeErr)
	}

	if extraErr != nil && !errors.Is(extraErr, io.EOF) {
		return nil, errors.Join(fmt.Errorf("finish coalesced provider range: %w", extraErr), closeErr)
	}

	if closeErr != nil {
		return nil, fmt.Errorf("close coalesced provider range: %w", closeErr)
	}

	for index, extent := range verified {
		if actual := DigestBytes(extent.Data); actual != extent.ID {
			return nil, fmt.Errorf("extent %d: %w", job.extents[index].ordinal, ErrIntegrity)
		}
	}

	return verified, nil
}
