package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/dravengarden/skydriver/driver"
)

// DownloadResult identifies one atomically published verified local file.
type DownloadResult struct {
	Destination string
	Object      driver.Object
	SizeBytes   uint64
	Checksum    string
}

// RunDownload claims or resumes a prepared download. Exact range support uses
// parallel missing-block recovery; otherwise the current file restarts as one
// sequential complete read. Final success always requires complete SHA-256 and
// no-replace publication of a regular sibling staging file.
func (engine *Engine) RunDownload(
	ctx context.Context,
	journalID string,
	handle driver.Handle,
) (DownloadResult, error) {
	if err := engine.validate(); err != nil {
		return DownloadResult{}, err
	}

	run, err := engine.acquire(journalID, DirectionDownload)
	if err != nil {
		return DownloadResult{}, err
	}

	plan := run.loaded.plan.record.Download
	if plan == nil {
		return DownloadResult{}, fmt.Errorf("%w: download plan is missing", ErrJournalCorrupt)
	}

	if run.loaded.state.record.Status == StatusAborted {
		return DownloadResult{}, fmt.Errorf("%w: download is aborted", ErrJournalConflict)
	}

	if run.loaded.state.record.Status == StatusComplete {
		if err := verifyPublishedDestination(*plan); err != nil {
			return DownloadResult{}, err
		}

		return downloadResult(*plan), nil
	}

	result, runErr := run.executeDownload(ctx, handle, *plan)
	if runErr != nil {
		releaseErr := run.release()

		return DownloadResult{}, errors.Join(runErr, releaseErr)
	}

	return result, nil
}

func (run *execution) executeDownload(
	ctx context.Context,
	handle driver.Handle,
	plan DownloadPlan,
) (DownloadResult, error) {
	if err := validateCurrentHandle(handle, plan.Driver); err != nil {
		return DownloadResult{}, err
	}

	if found, err := existingDestinationMatches(plan); err != nil {
		return DownloadResult{}, err
	} else if found {
		if err := removeStagingIfPresent(plan.StagingPath); err != nil {
			return DownloadResult{}, err
		}

		if err := run.finishRecoveredDownload(plan.Object); err != nil {
			return DownloadResult{}, err
		}

		return downloadResult(plan), nil
	}

	staging, err := openDownloadStaging(plan, run.loaded.downloadReceipts)
	if err != nil {
		return DownloadResult{}, err
	}

	transferErr := run.transferDownload(ctx, handle, plan, staging)
	if transferErr != nil {
		closeErr := staging.Close()

		return DownloadResult{}, errors.Join(transferErr, closeErr)
	}

	if err := transitionToVerifying(run); err != nil {
		closeErr := staging.Close()

		return DownloadResult{}, errors.Join(err, closeErr)
	}

	if err := verifyStagingFile(ctx, staging, plan); err != nil {
		invalidateErr := run.invalidateDownloadReceipts(err)
		closeErr := staging.Close()

		return DownloadResult{}, errors.Join(err, invalidateErr, closeErr)
	}

	if err := staging.Sync(); err != nil {
		closeErr := staging.Close()

		return DownloadResult{}, errors.Join(fmt.Errorf("sync verified download staging: %w", err), closeErr)
	}

	if err := staging.Close(); err != nil {
		return DownloadResult{}, fmt.Errorf("close verified download staging: %w", err)
	}

	if err := transitionToPublishing(run); err != nil {
		return DownloadResult{}, err
	}

	if err := publishDownload(plan); err != nil {
		return DownloadResult{}, err
	}

	if err := run.complete(plan.Object); err != nil {
		return DownloadResult{}, err
	}

	return downloadResult(plan), nil
}

func (run *execution) invalidateDownloadReceipts(verificationErr error) error {
	if !errors.Is(verificationErr, ErrTransferIntegrity) {
		return nil
	}

	if err := run.engine.store.clearDownloadReceipts(run.journalID); err != nil {
		return fmt.Errorf("invalidate failed download proof: %w", err)
	}

	run.loaded.downloadReceipts = nil

	return nil
}

func (run *execution) transferDownload(
	ctx context.Context,
	handle driver.Handle,
	plan DownloadPlan,
	staging *os.File,
) error {
	if handle.Descriptor.Capabilities.Read.Range.Available() {
		return run.transferMissingBlocks(ctx, handle, plan, staging)
	}

	return transferSequentialDownload(ctx, handle.Reader, plan, staging)
}

func (run *execution) transferMissingBlocks(
	ctx context.Context,
	handle driver.Handle,
	plan DownloadPlan,
	staging *os.File,
) error {
	if handle.RangeReader == nil {
		return fmt.Errorf("%w: range capability lacks range reader", ErrInvalidPlan)
	}

	missing, err := missingDownloadBlocks(plan, run.loaded.downloadReceipts, staging)
	if err != nil {
		return err
	}

	if len(missing) == 0 {
		return nil
	}

	workerCount := run.engine.concurrency(handle.Descriptor.Capabilities.Read.MaxParallelRanges)

	transferContext, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	jobs := make(chan PlannedBlock)

	var journalMutex sync.Mutex

	var workers sync.WaitGroup

	workers.Go(func() {
		defer close(jobs)

		for _, block := range missing {
			select {
			case jobs <- block:
			case <-transferContext.Done():
				return
			}
		}
	})

	for range workerCount {
		workers.Go(func() {
			for block := range jobs {
				if err := run.downloadOneBlock(
					transferContext,
					handle.RangeReader,
					plan,
					staging,
					block,
					&journalMutex,
				); err != nil {
					cancel(err)

					return
				}
			}
		})
	}

	workers.Wait()

	if cause := context.Cause(transferContext); cause != nil {
		return fmt.Errorf("download missing blocks: %w", cause)
	}

	return nil
}

func (run *execution) downloadOneBlock(
	ctx context.Context,
	reader driver.RangeReader,
	plan DownloadPlan,
	staging *os.File,
	block PlannedBlock,
	journalMutex *sync.Mutex,
) error {
	stream, err := reader.OpenRange(ctx, plan.Object, block.Offset, block.Length)
	if err != nil {
		return fmt.Errorf("open download block %d: %w", block.Number, err)
	}

	hasher := sha256.New()
	destination := io.NewOffsetWriter(staging, checkedInt64(block.Offset))

	written, readErr := io.CopyN(
		io.MultiWriter(destination, hasher),
		stream,
		checkedInt64(block.Length),
	)
	if readErr == nil && written == checkedInt64(block.Length) {
		readErr = requireEOF(stream)
	}

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf(
			"%w: read download block %d: %w",
			ErrTransferIntegrity,
			block.Number,
			errors.Join(readErr, closeErr),
		)
	}

	receipt := downloadBlockReceipt{
		Schema:     schema,
		PlanDigest: run.loaded.plan.digest,
		Block: VerifiedBlock{
			Number:   block.Number,
			Offset:   block.Offset,
			Length:   block.Length,
			Checksum: hex.EncodeToString(hasher.Sum(nil)),
		},
	}

	journalMutex.Lock()
	defer journalMutex.Unlock()

	if err := staging.Sync(); err != nil {
		return fmt.Errorf("sync download block %d: %w", block.Number, err)
	}

	if err := run.engine.store.putDownloadReceipt(run.journalID, run.loaded.plan.digest, receipt); err != nil {
		return err
	}

	return run.heartbeat()
}

func transferSequentialDownload(
	ctx context.Context,
	reader driver.Reader,
	plan DownloadPlan,
	staging *os.File,
) error {
	if reader == nil {
		return fmt.Errorf("%w: complete reader is missing", ErrInvalidPlan)
	}

	if err := staging.Truncate(0); err != nil {
		return fmt.Errorf("truncate sequential download staging: %w", err)
	}

	if _, err := staging.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind sequential download staging: %w", err)
	}

	stream, err := reader.Open(ctx, plan.Object)
	if err != nil {
		return fmt.Errorf("open complete download object: %w", err)
	}

	hasher := sha256.New()

	written, readErr := io.CopyN(
		io.MultiWriter(staging, hasher),
		stream,
		checkedInt64(plan.Object.SizeBytes),
	)
	if readErr == nil && written == checkedInt64(plan.Object.SizeBytes) {
		readErr = requireEOF(stream)
	}

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("%w: read complete object: %w", ErrTransferIntegrity, errors.Join(readErr, closeErr))
	}

	if hex.EncodeToString(hasher.Sum(nil)) != plan.Checksum {
		return fmt.Errorf("%w: sequential download checksum differs", ErrTransferIntegrity)
	}

	if err := staging.Truncate(checkedInt64(plan.Object.SizeBytes)); err != nil {
		return fmt.Errorf("truncate complete download staging: %w", err)
	}

	return nil
}

func openDownloadStaging(
	plan DownloadPlan,
	receipts []downloadBlockReceipt,
) (*os.File, error) {
	information, err := os.Lstat(plan.StagingPath)
	if errors.Is(err, fs.ErrNotExist) {
		file, createErr := os.OpenFile(plan.StagingPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, privateFileMode)
		if createErr != nil {
			return nil, fmt.Errorf("create download staging: %w", createErr)
		}

		if truncateErr := file.Truncate(checkedInt64(plan.Object.SizeBytes)); truncateErr != nil {
			closeErr := file.Close()

			return nil, errors.Join(fmt.Errorf("size download staging: %w", truncateErr), closeErr)
		}

		if syncErr := file.Sync(); syncErr != nil {
			closeErr := file.Close()

			return nil, errors.Join(fmt.Errorf("persist download staging: %w", syncErr), closeErr)
		}

		if syncErr := syncParentDirectory(filepath.Dir(plan.StagingPath)); syncErr != nil {
			closeErr := file.Close()

			return nil, errors.Join(fmt.Errorf("persist download staging name: %w", syncErr), closeErr)
		}

		return file, nil
	}

	if err != nil {
		return nil, fmt.Errorf("inspect download staging: %w", err)
	}

	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 || information.Size() < 0 {
		return nil, fmt.Errorf("%w: download staging is not a private regular file", ErrTransferIntegrity)
	}

	file, err := os.OpenFile(plan.StagingPath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open download staging: %w", err)
	}

	openedInformation, inspectErr := file.Stat()
	if inspectErr != nil || !openedInformation.Mode().IsRegular() || !os.SameFile(information, openedInformation) {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: download staging changed while opening", ErrTransferIntegrity),
			inspectErr,
			closeErr,
		)
	}

	if uint64(information.Size()) != plan.Object.SizeBytes { //nolint:gosec // Negative sizes are rejected above.
		if len(receipts) != 0 {
			closeErr := file.Close()

			return nil, errors.Join(
				fmt.Errorf("%w: sized staging disagrees with durable receipts", ErrTransferIntegrity),
				closeErr,
			)
		}

		if err := file.Truncate(checkedInt64(plan.Object.SizeBytes)); err != nil {
			closeErr := file.Close()

			return nil, errors.Join(fmt.Errorf("resize download staging: %w", err), closeErr)
		}
	}

	return file, nil
}

func missingDownloadBlocks(
	plan DownloadPlan,
	receipts []downloadBlockReceipt,
	staging *os.File,
) ([]PlannedBlock, error) {
	planned := make(map[uint32]PlannedBlock, len(plan.Blocks))
	for _, block := range plan.Blocks {
		planned[block.Number] = block
	}

	verified := make(map[uint32]struct{}, len(receipts))
	for _, receipt := range receipts {
		block, exists := planned[receipt.Block.Number]
		if !exists || block.Offset != receipt.Block.Offset || block.Length != receipt.Block.Length {
			return nil, fmt.Errorf("%w: download receipt does not match plan", ErrJournalCorrupt)
		}

		checksum, err := hashFileRange(staging, block.Offset, block.Length)
		if err != nil {
			return nil, err
		}

		if checksum == receipt.Block.Checksum {
			verified[block.Number] = struct{}{}
		}
	}

	missing := make([]PlannedBlock, 0, len(plan.Blocks)-len(verified))
	for _, block := range plan.Blocks {
		if _, exists := verified[block.Number]; !exists {
			missing = append(missing, block)
		}
	}

	return missing, nil
}

func hashFileRange(file *os.File, offset, length uint64) (string, error) {
	hasher := sha256.New()
	reader := io.NewSectionReader(file, checkedInt64(offset), checkedInt64(length))

	written, err := io.CopyN(hasher, reader, checkedInt64(length))
	if err != nil || written != checkedInt64(length) {
		return "", fmt.Errorf("%w: hash staged download range: %w", ErrTransferIntegrity, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func verifyStagingFile(ctx context.Context, file *os.File, plan DownloadPlan) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify download staging: %w", err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind download staging: %w", err)
	}

	hasher := sha256.New()

	written, err := io.CopyN(hasher, file, checkedInt64(plan.Object.SizeBytes))
	if err != nil || written != checkedInt64(plan.Object.SizeBytes) {
		return fmt.Errorf("%w: hash complete download staging: %w", ErrTransferIntegrity, err)
	}

	if err := requireEOF(file); err != nil {
		return err
	}

	if hex.EncodeToString(hasher.Sum(nil)) != plan.Checksum {
		return fmt.Errorf("%w: complete download checksum differs", ErrTransferIntegrity)
	}

	return nil
}

func publishDownload(plan DownloadPlan) error {
	parent := filepath.Dir(plan.Destination)

	root, err := os.OpenRoot(parent)
	if err != nil {
		return fmt.Errorf("open download destination parent: %w", err)
	}

	stagingName := filepath.Base(plan.StagingPath)
	destinationName := filepath.Base(plan.Destination)

	linkErr := root.Link(stagingName, destinationName)
	if linkErr != nil && !errors.Is(linkErr, fs.ErrExist) {
		closeErr := root.Close()

		return errors.Join(fmt.Errorf("publish verified download: %w", linkErr), closeErr)
	}

	if errors.Is(linkErr, fs.ErrExist) {
		matches, verifyErr := existingDestinationMatches(plan)
		if verifyErr != nil || !matches {
			closeErr := root.Close()

			return errors.Join(verifyErr, closeErr)
		}
	}

	linkSyncErr := syncOSDirectory(root)
	if linkSyncErr != nil {
		closeErr := root.Close()

		return errors.Join(fmt.Errorf("persist verified download link: %w", linkSyncErr), closeErr)
	}

	removeErr := root.Remove(stagingName)
	removeSyncErr := syncOSDirectory(root)

	closeErr := root.Close()
	if removeErr != nil || removeSyncErr != nil || closeErr != nil {
		return errors.Join(
			fmt.Errorf("finalize verified download: %w", errors.Join(removeErr, removeSyncErr)),
			closeErr,
		)
	}

	return nil
}

func existingDestinationMatches(plan DownloadPlan) (bool, error) {
	information, err := os.Lstat(plan.Destination)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("inspect download destination: %w", err)
	}

	if !information.Mode().IsRegular() || information.Size() < 0 ||
		uint64(information.Size()) != plan.Object.SizeBytes { //nolint:gosec // Negative sizes are rejected first.
		return false, fmt.Errorf("%w: destination contains a different file", ErrJournalConflict)
	}

	file, err := os.Open(plan.Destination)
	if err != nil {
		return false, fmt.Errorf("open download destination: %w", err)
	}

	openedInformation, inspectErr := file.Stat()
	if inspectErr != nil || !openedInformation.Mode().IsRegular() || !os.SameFile(information, openedInformation) {
		closeErr := file.Close()

		return false, errors.Join(
			fmt.Errorf("%w: destination changed while opening", ErrJournalConflict),
			inspectErr,
			closeErr,
		)
	}

	checksum, hashErr := hashFileRange(file, 0, plan.Object.SizeBytes)

	closeErr := file.Close()
	if hashErr != nil || closeErr != nil {
		return false, errors.Join(hashErr, closeErr)
	}

	if checksum != plan.Checksum {
		return false, fmt.Errorf("%w: destination checksum differs", ErrJournalConflict)
	}

	return true, nil
}

func verifyPublishedDestination(plan DownloadPlan) error {
	found, err := existingDestinationMatches(plan)
	if err != nil {
		return err
	}

	if !found {
		return fmt.Errorf("%w: completed destination is missing", ErrTransferIntegrity)
	}

	return nil
}

func removeStagingIfPresent(stagingPath string) error {
	err := os.Remove(stagingPath)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	return fmt.Errorf("remove recovered download staging: %w", err)
}

func (run *execution) finishRecoveredDownload(object driver.Object) error {
	if err := transitionToVerifying(run); err != nil {
		return err
	}

	if err := transitionToPublishing(run); err != nil {
		return err
	}

	return run.complete(object)
}

func transitionToVerifying(run *execution) error {
	switch run.loaded.state.record.Status {
	case StatusTransferring:
		return run.append(StatusVerifying, leaseRetained, nil)
	case StatusVerifying, StatusPublishing:
		return nil
	case StatusPrepared, StatusComplete, StatusAborted:
		return fmt.Errorf("%w: cannot verify download from %q", ErrJournalConflict, run.loaded.state.record.Status)
	}

	return fmt.Errorf("%w: unknown download state", ErrJournalCorrupt)
}

func transitionToPublishing(run *execution) error {
	switch run.loaded.state.record.Status {
	case StatusVerifying:
		return run.append(StatusPublishing, leaseRetained, nil)
	case StatusPublishing:
		return nil
	case StatusPrepared, StatusTransferring, StatusComplete, StatusAborted:
		return fmt.Errorf("%w: cannot publish download from %q", ErrJournalConflict, run.loaded.state.record.Status)
	}

	return fmt.Errorf("%w: unknown download state", ErrJournalCorrupt)
}

func syncOSDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open destination directory for sync: %w", err)
	}

	syncErr := directory.Sync()

	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync destination directory: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func syncParentDirectory(parent string) error {
	root, err := os.OpenRoot(parent)
	if err != nil {
		return fmt.Errorf("open parent directory for sync: %w", err)
	}

	syncErr := syncOSDirectory(root)
	closeErr := root.Close()

	return errors.Join(syncErr, closeErr)
}

func downloadResult(plan DownloadPlan) DownloadResult {
	return DownloadResult{
		Destination: plan.Destination,
		Object:      plan.Object,
		SizeBytes:   plan.Object.SizeBytes,
		Checksum:    plan.Checksum,
	}
}
