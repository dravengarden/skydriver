package transfer

import (
	"context"
	"errors"
	"fmt"
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
	ordinal int
	extent  Extent
}

// FetchBatch fetches a bounded number of extents concurrently and invokes the
// consumer as each one verifies. Its peak ciphertext buffer is bounded by
// concurrency multiplied by the Fetcher's maximum extent size.
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

	workerCount := min(int(concurrency), len(extents))

	batchContext, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	jobs := make(chan batchJob)

	var workers sync.WaitGroup

	workers.Go(func() {
		defer close(jobs)

		for ordinal, extent := range extents {
			select {
			case jobs <- batchJob{ordinal: ordinal, extent: extent}:
			case <-batchContext.Done():
				return
			}
		}
	})

	for range workerCount {
		workers.Go(func() {
			for job := range jobs {
				verified, err := fetcher.Fetch(batchContext, job.extent)
				if err != nil {
					cancel(fmt.Errorf("%w: extent %d fetch: %w", ErrBatchFailed, job.ordinal, err))

					return
				}

				if err := consumer(batchContext, job.ordinal, verified); err != nil {
					cancel(fmt.Errorf("%w: extent %d consume: %w", ErrBatchFailed, job.ordinal, err))

					return
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
