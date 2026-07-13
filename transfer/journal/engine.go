package journal

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dravengarden/carrack/driver"
)

const (
	defaultConcurrency = uint32(8)
	maximumConcurrency = uint32(1024)
	defaultPartBytes   = uint64(64 << 20)
	defaultBlockBytes  = uint64(16 << 20)
	maximumPlanPieces  = uint32(100_000)
	defaultLease       = 5 * time.Minute
)

// EngineOptions bounds local transfer concurrency and optimistic executor
// leases. A zero field selects a conservative default.
type EngineOptions struct {
	MaxConcurrency uint32
	LeaseDuration  time.Duration
}

// UploadOptions selects transfer acceleration policy. Preferred features emit
// structured warnings when unavailable; Require fields turn the corresponding
// missing feature into a pre-I/O hard error.
type UploadOptions struct {
	PartBytes             uint64
	RequireResumable      bool
	RequireParallel       bool
	RequireStrongChecksum bool
	Alternatives          []driver.Descriptor
}

// DownloadOptions selects range planning and acceleration policy. A driver
// without preferred range support falls back to a verified sequential complete
// read; required range behavior fails before payload I/O.
type DownloadOptions struct {
	BlockBytes      uint64
	RequireRange    bool
	RequireParallel bool
	Alternatives    []driver.Descriptor
}

// Engine prepares and resumes complete-object transfers using one Store.
// Payload concurrency is bounded by EngineOptions and each current driver
// descriptor. Control-plane calls are deliberately outside this type.
type Engine struct {
	store          *Store
	maxConcurrency uint32
	leaseDuration  time.Duration
	now            func() time.Time
}

// NewEngine validates local execution bounds.
func NewEngine(store *Store, options EngineOptions) (*Engine, error) {
	if store == nil || store.rootPath == "" {
		return nil, fmt.Errorf("%w: journal store is required", ErrInvalidStore)
	}

	maxConcurrency := options.MaxConcurrency
	if maxConcurrency == 0 {
		maxConcurrency = defaultConcurrency
	}

	if maxConcurrency > maximumConcurrency {
		return nil, fmt.Errorf("%w: maximum concurrency exceeds %d", ErrInvalidPlan, maximumConcurrency)
	}

	leaseDuration := options.LeaseDuration
	if leaseDuration == 0 {
		leaseDuration = defaultLease
	}

	if leaseDuration < time.Second {
		return nil, fmt.Errorf("%w: lease duration must be at least one second", ErrInvalidPlan)
	}

	return &Engine{
		store:          store,
		maxConcurrency: maxConcurrency,
		leaseDuration:  leaseDuration,
		now:            time.Now,
	}, nil
}

// PrepareUpload hashes the complete replayable source, fixes every part range,
// evaluates driver degradation, and durably publishes a prepared journal before
// any provider payload call.
func (engine *Engine) PrepareUpload(
	ctx context.Context,
	handle driver.Handle,
	source ReplayableSource,
	storageKey string,
	options UploadOptions,
) (Snapshot, error) {
	if err := engine.validate(); err != nil {
		return Snapshot{}, err
	}

	if err := handle.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("validate upload driver: %w", err)
	}

	if handle.Writer == nil {
		return Snapshot{}, fmt.Errorf("%w: selected driver cannot write complete objects", ErrInvalidPlan)
	}

	if strings.TrimSpace(storageKey) == "" {
		return Snapshot{}, fmt.Errorf("%w: destination storage key is required", ErrInvalidPlan)
	}

	if source == nil {
		return Snapshot{}, fmt.Errorf("%w: replayable source is required", ErrInvalidPlan)
	}

	metadata, err := source.Metadata(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("inspect upload source metadata: %w", err)
	}

	partBytes, err := choosePartBytes(metadata.SizeBytes, handle.Descriptor.Capabilities, options.PartBytes)
	if err != nil {
		return Snapshot{}, err
	}

	identity, parts, err := inspectSource(ctx, source, partBytes)
	if err != nil {
		return Snapshot{}, err
	}

	assessment, err := driver.Assess(
		handle.Descriptor,
		uploadRequirements(options),
		options.Alternatives,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("assess upload driver: %w", err)
	}

	journalID, err := randomIdentity()
	if err != nil {
		return Snapshot{}, err
	}

	plan := planRecord{
		Schema:    schema,
		ID:        journalID,
		Direction: DirectionUpload,
		CreatedAt: engine.now().Unix(),
		Upload: &UploadPlan{
			Driver:     handle.Descriptor,
			Source:     identity,
			StorageKey: storageKey,
			SizeBytes:  identity.SizeBytes,
			Checksum:   identity.Checksum,
			PartBytes:  partBytes,
			Parts:      parts,
			Warnings:   assessment.Warnings,
		},
	}

	createdPlan, createdState, err := engine.store.create(plan)
	if err != nil {
		return Snapshot{}, err
	}

	return snapshotFromRecords(createdPlan, createdState, nil, nil), nil
}

// PrepareDownload pins the current driver object, evaluates range degradation,
// and chooses a protected sibling staging file. It performs no payload I/O.
func (engine *Engine) PrepareDownload(
	ctx context.Context,
	handle driver.Handle,
	object driver.Object,
	checksum,
	destination string,
	options DownloadOptions,
) (Snapshot, error) {
	if err := engine.validate(); err != nil {
		return Snapshot{}, err
	}

	if err := handle.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("validate download driver: %w", err)
	}

	if handle.Reader == nil {
		return Snapshot{}, fmt.Errorf("%w: selected driver cannot read complete objects", ErrInvalidPlan)
	}

	if err := validateSHA256(checksum); err != nil {
		return Snapshot{}, err
	}

	if err := validateDownloadDestination(destination); err != nil {
		return Snapshot{}, err
	}

	actual, err := handle.Reader.Stat(ctx, object.Locator.StorageKey)
	if err != nil {
		return Snapshot{}, fmt.Errorf("stat pinned download object: %w", err)
	}

	if actual != object {
		return Snapshot{}, fmt.Errorf("%w: current driver object differs from pinned identity", ErrTransferIntegrity)
	}

	blockBytes, err := chooseBlockBytes(object.SizeBytes, handle.Descriptor.Capabilities, options.BlockBytes)
	if err != nil {
		return Snapshot{}, err
	}

	blocks, err := buildBlocks(object.SizeBytes, blockBytes)
	if err != nil {
		return Snapshot{}, err
	}

	assessment, err := driver.Assess(
		handle.Descriptor,
		downloadRequirements(options),
		options.Alternatives,
	)
	if err != nil {
		return Snapshot{}, fmt.Errorf("assess download driver: %w", err)
	}

	journalID, err := randomIdentity()
	if err != nil {
		return Snapshot{}, err
	}

	stagingPath := filepath.Join(
		filepath.Dir(destination),
		"."+filepath.Base(destination)+".carrack-"+journalID+".partial",
	)
	plan := planRecord{
		Schema:    schema,
		ID:        journalID,
		Direction: DirectionDownload,
		CreatedAt: engine.now().Unix(),
		Download: &DownloadPlan{
			Driver:      handle.Descriptor,
			Object:      object,
			Checksum:    checksum,
			Destination: destination,
			StagingPath: stagingPath,
			BlockBytes:  blockBytes,
			Blocks:      blocks,
			Warnings:    assessment.Warnings,
		},
	}

	createdPlan, createdState, err := engine.store.create(plan)
	if err != nil {
		return Snapshot{}, err
	}

	return snapshotFromRecords(createdPlan, createdState, nil, nil), nil
}

// Inspect reloads and validates a journal without claiming execution.
func (engine *Engine) Inspect(journalID string) (Snapshot, error) {
	if err := engine.validate(); err != nil {
		return Snapshot{}, err
	}

	return engine.store.Load(journalID)
}

func (engine *Engine) validate() error {
	if engine == nil || engine.store == nil || engine.maxConcurrency == 0 ||
		engine.leaseDuration <= 0 || engine.now == nil {
		return fmt.Errorf("%w: engine is not initialized", ErrInvalidStore)
	}

	return nil
}

func choosePartBytes(sizeBytes uint64, capabilities driver.Capabilities, requested uint64) (uint64, error) {
	if capabilities.MaximumObjectBytes != 0 && sizeBytes > capabilities.MaximumObjectBytes {
		return 0, fmt.Errorf("%w: source exceeds driver complete-object limit", ErrInvalidPlan)
	}

	if sizeBytes > math.MaxInt64 {
		return 0, fmt.Errorf("%w: source exceeds local journal I/O limit", ErrInvalidPlan)
	}

	if sizeBytes == 0 {
		return 0, nil
	}

	partBytes := requested
	if partBytes == 0 {
		partBytes = capabilities.PreferredPartBytes
	}

	if partBytes == 0 {
		partBytes = defaultPartBytes
	}

	if capabilities.Write.Resume.Available() {
		if requested != 0 && (requested < capabilities.Write.MinimumNonFinalPartBytes ||
			requested > capabilities.Write.MaximumPartBytes) {
			return 0, fmt.Errorf("%w: requested part size is outside driver limits", ErrInvalidPlan)
		}

		partBytes = max(partBytes, capabilities.Write.MinimumNonFinalPartBytes)
		partBytes = min(partBytes, capabilities.Write.MaximumPartBytes)
	}

	maximumParts := maximumPlanPieces
	if capabilities.Write.Resume.Available() {
		maximumParts = min(maximumParts, capabilities.Write.MaximumParts)
	}

	minimumForCount := divideRoundUp(sizeBytes, uint64(maximumParts))

	partBytes = max(partBytes, minimumForCount)
	if capabilities.Write.Resume.Available() && partBytes > capabilities.Write.MaximumPartBytes {
		return 0, fmt.Errorf("%w: object cannot fit within driver maximum part count", ErrInvalidPlan)
	}

	return partBytes, nil
}

func chooseBlockBytes(sizeBytes uint64, capabilities driver.Capabilities, requested uint64) (uint64, error) {
	if sizeBytes > math.MaxInt64 {
		return 0, fmt.Errorf("%w: object exceeds local journal I/O limit", ErrInvalidPlan)
	}

	if sizeBytes == 0 {
		return 0, nil
	}

	blockBytes := requested
	if blockBytes == 0 {
		blockBytes = defaultBlockBytes
	}

	maximumRange := capabilities.Read.MaximumRangeBytes
	if capabilities.Read.Range.Available() && maximumRange != 0 {
		if requested > maximumRange {
			return 0, fmt.Errorf("%w: requested block exceeds driver range limit", ErrInvalidPlan)
		}

		blockBytes = min(blockBytes, maximumRange)
	}

	minimumForCount := divideRoundUp(sizeBytes, uint64(maximumPlanPieces))

	blockBytes = max(blockBytes, minimumForCount)
	if capabilities.Read.Range.Available() && maximumRange != 0 && blockBytes > maximumRange {
		return 0, fmt.Errorf("%w: object cannot fit journal blocks within range limit", ErrInvalidPlan)
	}

	return blockBytes, nil
}

func buildBlocks(sizeBytes, blockBytes uint64) ([]PlannedBlock, error) {
	if sizeBytes == 0 {
		return []PlannedBlock{}, nil
	}

	if blockBytes == 0 {
		return nil, fmt.Errorf("%w: block size must be positive", ErrInvalidPlan)
	}

	blocks := make([]PlannedBlock, 0)

	for offset, number := uint64(0), uint32(1); offset < sizeBytes; number++ {
		length := min(blockBytes, sizeBytes-offset)
		blocks = append(blocks, PlannedBlock{Number: number, Offset: offset, Length: length})
		offset += length
	}

	if len(blocks) > int(maximumPlanPieces) {
		return nil, fmt.Errorf("%w: download exceeds maximum journal block count", ErrInvalidPlan)
	}

	return blocks, nil
}

func uploadRequirements(options UploadOptions) []driver.Requirement {
	resumeLevel := driver.RequirementPreferred
	if options.RequireResumable {
		resumeLevel = driver.RequirementRequired
	}

	parallelLevel := driver.RequirementPreferred
	if options.RequireParallel {
		parallelLevel = driver.RequirementRequired
	}

	checksumLevel := driver.RequirementPreferred
	if options.RequireStrongChecksum {
		checksumLevel = driver.RequirementRequired
	}

	return []driver.Requirement{
		{Feature: driver.FeatureResumableWrite, Level: resumeLevel},
		{Feature: driver.FeatureParallelWrite, Level: parallelLevel},
		{Feature: driver.FeatureStrongUploadChecksum, Level: checksumLevel},
	}
}

func downloadRequirements(options DownloadOptions) []driver.Requirement {
	rangeLevel := driver.RequirementPreferred
	if options.RequireRange {
		rangeLevel = driver.RequirementRequired
	}

	parallelLevel := driver.RequirementPreferred
	if options.RequireParallel {
		parallelLevel = driver.RequirementRequired
	}

	return []driver.Requirement{
		{Feature: driver.FeatureRangeRead, Level: rangeLevel},
		{Feature: driver.FeatureParallelRangeRead, Level: parallelLevel},
	}
}

func validateDownloadDestination(destination string) error {
	if !canonicalAbsolutePath(destination) || filepath.Base(destination) == "." || filepath.Base(destination) == string(os.PathSeparator) {
		return fmt.Errorf("%w: destination must be a canonical absolute file path", ErrInvalidPlan)
	}

	parent := filepath.Dir(destination)

	information, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("%w: inspect destination parent: %w", ErrInvalidPlan, err)
	}

	if !information.IsDir() || information.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: destination parent must be a real directory", ErrInvalidPlan)
	}

	return nil
}

func divideRoundUp(value, divisor uint64) uint64 {
	quotient := value / divisor
	if value%divisor != 0 {
		quotient++
	}

	return quotient
}

type execution struct {
	engine    *Engine
	journalID string
	owner     string
	loaded    loadedJournal
}

type leaseDisposition uint8

const (
	leaseReleased leaseDisposition = iota
	leaseRetained
)

func (engine *Engine) acquire(journalID string, direction Direction) (*execution, error) {
	loaded, err := engine.store.loadRecords(journalID)
	if err != nil {
		return nil, err
	}

	if loaded.plan.record.Direction != direction {
		return nil, fmt.Errorf("%w: journal direction is %q", ErrInvalidPlan, loaded.plan.record.Direction)
	}

	if loaded.state.record.Status == StatusComplete || loaded.state.record.Status == StatusAborted {
		return &execution{engine: engine, journalID: journalID, loaded: loaded}, nil
	}

	now := engine.now()
	if lease := loaded.state.record.Lease; lease != nil && lease.ExpiresAt > now.Unix() {
		return nil, ErrJournalBusy
	}

	owner, err := randomIdentity()
	if err != nil {
		return nil, err
	}

	run := &execution{engine: engine, journalID: journalID, owner: owner, loaded: loaded}

	status := loaded.state.record.Status
	if status == StatusPrepared {
		status = StatusTransferring
	}

	if err := run.append(status, leaseRetained, func(next *stateRecord) {
		next.ExecutorFence++
	}); err != nil {
		return nil, err
	}

	return run, nil
}

func (run *execution) append(
	status Status,
	lease leaseDisposition,
	mutate func(*stateRecord),
) error {
	current := run.loaded.state
	next := current.record
	next.Revision++
	next.PreviousStateDigest = current.digest
	next.Status = status
	next.UpdatedAt = run.engine.now().Unix()
	next.UploadSession = cloneUploadSession(current.record.UploadSession)
	next.CompletionParts = slices.Clone(current.record.CompletionParts)
	next.Object = cloneObject(current.record.Object)

	if mutate != nil {
		mutate(&next)
	}

	if lease == leaseRetained {
		next.Lease = &executorLease{
			Owner:     run.owner,
			Fence:     next.ExecutorFence,
			ExpiresAt: run.engine.now().Add(run.engine.leaseDuration).Unix(),
		}
	} else {
		next.Lease = nil
	}

	appended, err := run.engine.store.appendState(run.journalID, current, next)
	if err != nil {
		return err
	}

	run.loaded.state = appended

	return nil
}

func (run *execution) heartbeat() error {
	return run.append(run.loaded.state.record.Status, leaseRetained, nil)
}

func (run *execution) release() error {
	status := run.loaded.state.record.Status
	if status == StatusComplete || status == StatusAborted || run.owner == "" {
		return nil
	}

	return run.append(status, leaseReleased, nil)
}

func sameSourceIdentity(left, right SourceIdentity) bool {
	return left == right
}

func sameParts(left, right []PlannedPart) bool {
	return slices.Equal(left, right)
}

func (engine *Engine) concurrency(driverLimit uint32) uint32 {
	return min(engine.maxConcurrency, driverLimit)
}
