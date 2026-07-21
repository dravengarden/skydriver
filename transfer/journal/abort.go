package journal

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/dravengarden/skydriver/driver"
)

// AbortUpload seals the journal as aborted after asking the matching driver to
// discard active staging. Once the durable completion manifest enters the
// verifying state, completion is the only safe recovery: Skydriver replays it
// instead of risking an aborted journal for an object whose success response
// was lost. It never deletes an already completed object; a terminal complete
// journal is an idempotent success.
func (engine *Engine) AbortUpload(
	ctx context.Context,
	journalID string,
	handle driver.Handle,
) error {
	if err := engine.validate(); err != nil {
		return err
	}

	run, err := engine.acquire(journalID, DirectionUpload)
	if err != nil {
		return err
	}

	status := run.loaded.state.record.Status
	if status == StatusComplete || status == StatusAborted {
		return nil
	}

	plan := run.loaded.plan.record.Upload
	if plan == nil {
		return fmt.Errorf("%w: upload plan is missing", ErrJournalCorrupt)
	}

	if err := validateCurrentHandle(handle, plan.Driver); err != nil {
		releaseErr := run.release()

		return errors.Join(err, releaseErr)
	}

	if status == StatusVerifying {
		if !plan.Driver.Capabilities.Write.Resume.Available() {
			if run.loaded.state.record.Object == nil {
				releaseErr := run.release()

				return errors.Join(
					fmt.Errorf("%w: verified complete upload lacks its object", ErrJournalCorrupt),
					releaseErr,
				)
			}

			return run.complete(*run.loaded.state.record.Object)
		}

		if run.loaded.state.record.UploadSession == nil {
			releaseErr := run.release()

			return errors.Join(
				fmt.Errorf("%w: committed resumable upload lacks a session", ErrJournalCorrupt),
				releaseErr,
			)
		}

		_, completionErr := run.completeResumableUpload(
			ctx,
			handle,
			*plan,
			*run.loaded.state.record.UploadSession,
			run.loaded.state.record.CompletionParts,
		)
		if completionErr != nil {
			releaseErr := run.release()

			return errors.Join(
				fmt.Errorf("finish committed upload before abort: %w", completionErr),
				releaseErr,
			)
		}

		return nil
	}

	if session := run.loaded.state.record.UploadSession; session != nil {
		if handle.ResumableWriter == nil {
			releaseErr := run.release()

			return errors.Join(
				fmt.Errorf("%w: upload session lacks resumable driver", ErrInvalidPlan),
				releaseErr,
			)
		}

		if err := handle.ResumableWriter.AbortUpload(ctx, *session); err != nil {
			releaseErr := run.release()

			return errors.Join(fmt.Errorf("abort provider upload: %w", err), releaseErr)
		}
	}

	return run.append(StatusAborted, leaseReleased, nil)
}

// AbortDownload removes only the protected staging file and marks the journal
// aborted. If verified bytes were already published before a lost journal
// update, Skydriver completes the journal instead. It never removes or modifies
// the final destination path.
func (engine *Engine) AbortDownload(journalID string) error {
	if err := engine.validate(); err != nil {
		return err
	}

	run, err := engine.acquire(journalID, DirectionDownload)
	if err != nil {
		return err
	}

	status := run.loaded.state.record.Status
	if status == StatusComplete || status == StatusAborted {
		return nil
	}

	plan := run.loaded.plan.record.Download
	if plan == nil {
		return fmt.Errorf("%w: download plan is missing", ErrJournalCorrupt)
	}

	if published, publishedErr := existingDestinationMatches(*plan); publishedErr != nil &&
		!errors.Is(publishedErr, ErrJournalConflict) {
		releaseErr := run.release()

		return errors.Join(publishedErr, releaseErr)
	} else if published {
		if removeErr := removeStagingIfPresent(plan.StagingPath); removeErr != nil {
			releaseErr := run.release()

			return errors.Join(removeErr, releaseErr)
		}

		return run.finishRecoveredDownload(plan.Object)
	}

	removeErr := os.Remove(plan.StagingPath)
	if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
		releaseErr := run.release()

		return errors.Join(fmt.Errorf("remove download staging: %w", removeErr), releaseErr)
	}

	return run.append(StatusAborted, leaseReleased, nil)
}
