package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/dravengarden/carrack/driver"
)

// RunUpload claims or resumes a prepared upload. It rehashes the complete
// source before provider I/O, treats ListParts as authoritative, transfers only
// missing valid parts, completes exactly one object, performs mandatory
// readback when declared, and commits a terminal optimistic journal revision.
func (engine *Engine) RunUpload(
	ctx context.Context,
	journalID string,
	handle driver.Handle,
	source ReplayableSource,
) (driver.Object, error) {
	if err := engine.validate(); err != nil {
		return driver.Object{}, err
	}

	if source == nil {
		return driver.Object{}, fmt.Errorf("%w: replayable source is required", ErrInvalidPlan)
	}

	run, err := engine.acquire(journalID, DirectionUpload)
	if err != nil {
		return driver.Object{}, err
	}

	if run.loaded.state.record.Status == StatusComplete {
		return *run.loaded.state.record.Object, nil
	}

	if run.loaded.state.record.Status == StatusAborted {
		return driver.Object{}, fmt.Errorf("%w: upload is aborted", ErrJournalConflict)
	}

	object, runErr := run.executeUpload(ctx, handle, source)
	if runErr != nil {
		releaseErr := run.release()

		return driver.Object{}, errors.Join(runErr, releaseErr)
	}

	return object, nil
}

func (run *execution) executeUpload(
	ctx context.Context,
	handle driver.Handle,
	source ReplayableSource,
) (driver.Object, error) {
	plan := run.loaded.plan.record.Upload
	if plan == nil {
		return driver.Object{}, fmt.Errorf("%w: upload plan is missing", ErrJournalCorrupt)
	}

	if err := validateCurrentHandle(handle, plan.Driver); err != nil {
		return driver.Object{}, err
	}

	identity, parts, err := inspectSource(ctx, source, plan.PartBytes)
	if err != nil {
		return driver.Object{}, err
	}

	if !sameSourceIdentity(identity, plan.Source) || !sameParts(parts, plan.Parts) {
		return driver.Object{}, ErrSourceChanged
	}

	if handle.Descriptor.Capabilities.Write.Resume.Available() {
		return run.executeResumableUpload(ctx, handle, source, *plan)
	}

	return run.executeCompleteUpload(ctx, handle, source, *plan)
}

func (run *execution) executeCompleteUpload(
	ctx context.Context,
	handle driver.Handle,
	source ReplayableSource,
	plan UploadPlan,
) (driver.Object, error) {
	if run.loaded.state.record.Status == StatusVerifying {
		object := run.loaded.state.record.Object
		if object == nil {
			return driver.Object{}, fmt.Errorf("%w: verified complete upload lacks its object", ErrJournalCorrupt)
		}

		if err := validateUploadResult(*object, plan); err != nil {
			return driver.Object{}, err
		}

		if err := verifyReadbackIfRequired(ctx, handle, *object, plan.Checksum); err != nil {
			return driver.Object{}, err
		}

		if err := run.complete(*object); err != nil {
			return driver.Object{}, err
		}

		return *object, nil
	}

	stream, err := source.OpenRange(ctx, 0, plan.SizeBytes)
	if err != nil {
		return driver.Object{}, fmt.Errorf("open complete upload source: %w", err)
	}

	object, putErr := handle.Writer.Put(ctx, driver.PutRequest{
		StorageKey: plan.StorageKey,
		Body:       stream,
		SizeBytes:  plan.SizeBytes,
		Checksum:   plan.Checksum,
	})

	closeErr := stream.Close()
	if putErr != nil || closeErr != nil {
		return driver.Object{}, errors.Join(putErr, closeErr)
	}

	if err := validateUploadResult(object, plan); err != nil {
		return driver.Object{}, err
	}

	if err := verifyReadbackIfRequired(ctx, handle, object, plan.Checksum); err != nil {
		return driver.Object{}, err
	}

	if err := run.append(StatusVerifying, leaseRetained, func(next *stateRecord) {
		next.Object = cloneObject(&object)
	}); err != nil {
		return driver.Object{}, err
	}

	if err := run.complete(object); err != nil {
		return driver.Object{}, err
	}

	return object, nil
}

func (run *execution) executeResumableUpload(
	ctx context.Context,
	handle driver.Handle,
	source ReplayableSource,
	plan UploadPlan,
) (driver.Object, error) {
	session, err := run.ensureUploadSession(ctx, handle.ResumableWriter, plan)
	if err != nil {
		return driver.Object{}, err
	}

	if run.loaded.state.record.Status == StatusVerifying {
		return run.completeResumableUpload(ctx, handle, plan, session, run.loaded.state.record.CompletionParts)
	}

	authoritative, err := handle.ResumableWriter.ListParts(ctx, session)
	if err != nil {
		return driver.Object{}, fmt.Errorf("list authoritative upload parts: %w", err)
	}

	present, err := reconcileUploadParts(plan.Parts, authoritative)
	if err != nil {
		return driver.Object{}, err
	}

	for _, part := range plan.Parts {
		if _, exists := present[part.Number]; !exists {
			continue
		}

		if recordErr := run.recordUploadPart(part); recordErr != nil {
			return driver.Object{}, recordErr
		}
	}

	missing := missingUploadParts(plan.Parts, present)
	if uploadErr := run.uploadMissingParts(ctx, handle, source, session, missing); uploadErr != nil {
		return driver.Object{}, uploadErr
	}

	authoritative, err = handle.ResumableWriter.ListParts(ctx, session)
	if err != nil {
		return driver.Object{}, fmt.Errorf("relist authoritative upload parts: %w", err)
	}

	ordered, err := orderedCompletionParts(plan.Parts, authoritative)
	if err != nil {
		return driver.Object{}, err
	}

	if appendErr := run.append(StatusVerifying, leaseRetained, func(next *stateRecord) {
		next.CompletionParts = slices.Clone(ordered)
	}); appendErr != nil {
		return driver.Object{}, appendErr
	}

	return run.completeResumableUpload(ctx, handle, plan, session, ordered)
}

func (run *execution) completeResumableUpload(
	ctx context.Context,
	handle driver.Handle,
	plan UploadPlan,
	session driver.UploadSession,
	parts []driver.UploadedPart,
) (driver.Object, error) {
	ordered, err := orderedCompletionParts(plan.Parts, parts)
	if err != nil {
		return driver.Object{}, fmt.Errorf("validate durable completion manifest: %w", err)
	}

	object, err := handle.ResumableWriter.CompleteUpload(ctx, driver.CompleteUploadRequest{
		Session:   session,
		Parts:     ordered,
		SizeBytes: plan.SizeBytes,
		Checksum:  plan.Checksum,
	})
	if err != nil {
		return driver.Object{}, fmt.Errorf("complete provider upload: %w", err)
	}

	if err := validateUploadResult(object, plan); err != nil {
		return driver.Object{}, err
	}

	if err := verifyReadbackIfRequired(ctx, handle, object, plan.Checksum); err != nil {
		return driver.Object{}, err
	}

	if err := run.complete(object); err != nil {
		return driver.Object{}, err
	}

	return object, nil
}

func (run *execution) ensureUploadSession(
	ctx context.Context,
	writer driver.ResumableWriter,
	plan UploadPlan,
) (driver.UploadSession, error) {
	if writer == nil {
		return driver.UploadSession{}, fmt.Errorf("%w: resumable driver interface is missing", ErrInvalidPlan)
	}

	if existing := run.loaded.state.record.UploadSession; existing != nil {
		return *cloneUploadSession(existing), nil
	}

	session, err := writer.BeginUpload(ctx, driver.BeginUploadRequest{
		StorageKey: plan.StorageKey,
		SizeBytes:  plan.SizeBytes,
		Checksum:   plan.Checksum,
	})
	if err != nil {
		return driver.UploadSession{}, fmt.Errorf("begin provider upload: %w", err)
	}

	if strings.TrimSpace(session.ID) == "" {
		return driver.UploadSession{}, fmt.Errorf("%w: provider returned an empty upload session", ErrTransferIntegrity)
	}

	if err := run.append(StatusTransferring, leaseRetained, func(next *stateRecord) {
		next.UploadSession = cloneUploadSession(&session)
	}); err != nil {
		return driver.UploadSession{}, err
	}

	return session, nil
}

func (run *execution) uploadMissingParts(
	ctx context.Context,
	handle driver.Handle,
	source ReplayableSource,
	session driver.UploadSession,
	parts []PlannedPart,
) error {
	if len(parts) == 0 {
		return nil
	}

	workerCount := run.engine.concurrency(handle.Descriptor.Capabilities.Write.MaxParallelParts)
	if !handle.Descriptor.Capabilities.Write.ParallelParts.Available() {
		workerCount = 1
	}

	transferContext, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	jobs := make(chan PlannedPart)

	var journalMutex sync.Mutex

	var workers sync.WaitGroup

	workers.Go(func() {
		defer close(jobs)

		for _, part := range parts {
			select {
			case jobs <- part:
			case <-transferContext.Done():
				return
			}
		}
	})

	for range workerCount {
		workers.Go(func() {
			for part := range jobs {
				if err := run.uploadOnePart(transferContext, handle, source, session, part, &journalMutex); err != nil {
					cancel(err)

					return
				}
			}
		})
	}

	workers.Wait()

	if cause := context.Cause(transferContext); cause != nil {
		return fmt.Errorf("upload missing parts: %w", cause)
	}

	return nil
}

func (run *execution) uploadOnePart(
	ctx context.Context,
	handle driver.Handle,
	source ReplayableSource,
	session driver.UploadSession,
	part PlannedPart,
	journalMutex *sync.Mutex,
) error {
	stream, err := source.OpenRange(ctx, part.Offset, part.Length)
	if err != nil {
		return fmt.Errorf("open upload part %d: %w", part.Number, err)
	}

	uploaded, putErr := handle.ResumableWriter.PutPart(ctx, driver.PutPartRequest{
		Session: session,
		Part: driver.UploadedPart{
			Number:   part.Number,
			Offset:   part.Offset,
			Length:   part.Length,
			Checksum: part.Checksum,
		},
		Body: stream,
	})

	closeErr := stream.Close()
	if putErr != nil || closeErr != nil {
		return fmt.Errorf("put upload part %d: %w", part.Number, errors.Join(putErr, closeErr))
	}

	if !uploadedMatchesPlan(uploaded, part) {
		return fmt.Errorf("%w: provider part %d differs from plan", ErrTransferIntegrity, part.Number)
	}

	journalMutex.Lock()
	defer journalMutex.Unlock()

	if err := run.recordUploadPart(part); err != nil {
		return err
	}

	return run.heartbeat()
}

func (run *execution) recordUploadPart(part PlannedPart) error {
	receipt := uploadPartReceipt{
		Schema:     schema,
		PlanDigest: run.loaded.plan.digest,
		Part:       part,
	}

	return run.engine.store.putUploadReceipt(run.journalID, run.loaded.plan.digest, receipt)
}

func (run *execution) complete(object driver.Object) error {
	return run.append(StatusComplete, leaseReleased, func(next *stateRecord) {
		next.Object = cloneObject(&object)
	})
}

func reconcileUploadParts(
	planned []PlannedPart,
	authoritative []driver.UploadedPart,
) (map[uint32]driver.UploadedPart, error) {
	plans := make(map[uint32]PlannedPart, len(planned))
	for _, part := range planned {
		plans[part.Number] = part
	}

	present := make(map[uint32]driver.UploadedPart, len(authoritative))
	for _, part := range authoritative {
		plannedPart, exists := plans[part.Number]
		if !exists || !uploadedMatchesPlan(part, plannedPart) {
			return nil, fmt.Errorf("%w: provider contains an unknown or conflicting part", ErrTransferIntegrity)
		}

		if _, duplicate := present[part.Number]; duplicate {
			return nil, fmt.Errorf("%w: provider returned duplicate part number", ErrTransferIntegrity)
		}

		present[part.Number] = part
	}

	return present, nil
}

func missingUploadParts(
	planned []PlannedPart,
	present map[uint32]driver.UploadedPart,
) []PlannedPart {
	missing := make([]PlannedPart, 0, len(planned)-len(present))
	for _, part := range planned {
		if _, exists := present[part.Number]; !exists {
			missing = append(missing, part)
		}
	}

	return missing
}

func orderedCompletionParts(
	planned []PlannedPart,
	authoritative []driver.UploadedPart,
) ([]driver.UploadedPart, error) {
	present, err := reconcileUploadParts(planned, authoritative)
	if err != nil {
		return nil, err
	}

	if len(present) != len(planned) {
		return nil, fmt.Errorf("%w: provider upload is missing planned parts", ErrTransferIntegrity)
	}

	ordered := make([]driver.UploadedPart, 0, len(planned))
	for _, part := range planned {
		ordered = append(ordered, present[part.Number])
	}

	return ordered, nil
}

func uploadedMatchesPlan(uploaded driver.UploadedPart, planned PlannedPart) bool {
	return uploaded.Number == planned.Number && uploaded.Offset == planned.Offset &&
		uploaded.Length == planned.Length && uploaded.Checksum == planned.Checksum
}

func validateUploadResult(object driver.Object, plan UploadPlan) error {
	if object.Locator.StorageKey != plan.StorageKey || object.SizeBytes != plan.SizeBytes {
		return fmt.Errorf("%w: completed provider object differs from plan", ErrTransferIntegrity)
	}

	return nil
}

func verifyReadbackIfRequired(
	ctx context.Context,
	handle driver.Handle,
	object driver.Object,
	checksum string,
) error {
	if !handle.Descriptor.Capabilities.Integrity.RequiresReadback {
		return nil
	}

	if handle.Reader == nil {
		return fmt.Errorf("%w: mandatory readback lacks a complete reader", ErrInvalidPlan)
	}

	stream, err := handle.Reader.Open(ctx, object)
	if err != nil {
		return fmt.Errorf("%w: open mandatory upload readback: %w", ErrTransferIntegrity, err)
	}

	hasher := sha256.New()

	written, readErr := io.CopyN(hasher, stream, checkedInt64(object.SizeBytes))
	if readErr == nil && written == checkedInt64(object.SizeBytes) {
		readErr = requireEOF(stream)
	}

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("%w: read completed object: %w", ErrTransferIntegrity, errors.Join(readErr, closeErr))
	}

	if hex.EncodeToString(hasher.Sum(nil)) != checksum {
		return fmt.Errorf("%w: completed object readback checksum differs", ErrTransferIntegrity)
	}

	return nil
}

func validateCurrentHandle(handle driver.Handle, planned driver.Descriptor) error {
	if err := handle.Validate(); err != nil {
		return fmt.Errorf("validate current driver handle: %w", err)
	}

	if !reflect.DeepEqual(handle.Descriptor, planned) {
		return fmt.Errorf("%w: effective driver descriptor changed; prepare a new transfer", ErrInvalidPlan)
	}

	return nil
}
