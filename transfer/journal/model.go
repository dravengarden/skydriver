package journal

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dravengarden/carrack/driver"
)

const schema = "carrack.transfer-journal/v1"

var (
	// ErrInvalidStore indicates an unsafe root or uninitialized journal store.
	ErrInvalidStore = errors.New("invalid Carrack transfer journal store")
	// ErrInvalidPlan indicates incomplete, contradictory, or unsafe immutable
	// transfer planning data.
	ErrInvalidPlan = errors.New("invalid Carrack complete-object transfer plan")
	// ErrJournalNotFound indicates that no complete journal has the supplied ID.
	ErrJournalNotFound = errors.New("carrack transfer journal not found")
	// ErrJournalConflict indicates an optimistic revision or immutable receipt
	// collision. Callers must reload the journal before retrying.
	ErrJournalConflict = errors.New("carrack transfer journal revision conflict")
	// ErrJournalCorrupt indicates a malformed, truncated, hash-mismatched, or
	// non-contiguous journal record.
	ErrJournalCorrupt = errors.New("carrack transfer journal is corrupt")
	// ErrJournalBusy indicates an unexpired executor lease held by another run.
	ErrJournalBusy = errors.New("carrack transfer journal has an active executor")
	// ErrSourceChanged indicates that a replayable upload source no longer has
	// the immutable identity fixed by its journal.
	ErrSourceChanged = errors.New("carrack transfer source changed")
	// ErrTransferIntegrity indicates payload bytes that fail exact length or
	// SHA-256 verification.
	ErrTransferIntegrity = errors.New("carrack complete-object transfer integrity mismatch")
)

// Direction identifies the payload flow represented by one journal.
type Direction string

const (
	// DirectionUpload transfers one replayable source into one driver object.
	DirectionUpload Direction = "upload"
	// DirectionDownload transfers one pinned driver object into one local file.
	DirectionDownload Direction = "download"
)

// Status is the monotonic high-level journal state.
type Status string

const (
	// StatusPrepared means immutable planning is durable but payload I/O has not
	// been claimed by an executor.
	StatusPrepared Status = "prepared"
	// StatusTransferring means payload parts or blocks may be in flight.
	StatusTransferring Status = "transferring"
	// StatusVerifying means all planned payload pieces exist and complete-object
	// verification or provider completion is in progress.
	StatusVerifying Status = "verifying"
	// StatusPublishing means a verified download is being atomically exposed at
	// its final local path.
	StatusPublishing Status = "publishing"
	// StatusComplete is terminal and contains a verified result.
	StatusComplete Status = "complete"
	// StatusAborted is terminal and never contains a successful result.
	StatusAborted Status = "aborted"
)

// SourceIdentity pins a replayable upload source without storing payload bytes
// or credentials. Reference may be a local path or caller-owned opaque label;
// Version is source-specific, while Checksum always uses lowercase SHA-256.
type SourceIdentity struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
	Version   string `json:"version"`
	SizeBytes uint64 `json:"size_bytes"`
	Checksum  string `json:"checksum"`
}

// PlannedPart is one exact upload range. It is durable transfer metadata only
// and never a VFS object identity.
type PlannedPart struct {
	Number   uint32 `json:"number"`
	Offset   uint64 `json:"offset"`
	Length   uint64 `json:"length"`
	Checksum string `json:"checksum"`
}

// PlannedBlock is one exact download staging range. Its receipt checksum
// protects local recovery state; the final complete checksum remains decisive.
type PlannedBlock struct {
	Number uint32 `json:"number"`
	Offset uint64 `json:"offset"`
	Length uint64 `json:"length"`
}

// UploadPlan fixes every input required to resume and complete one immutable
// provider object without another control-plane call on the payload hot path.
type UploadPlan struct {
	Driver     driver.Descriptor `json:"driver"`
	Source     SourceIdentity    `json:"source"`
	StorageKey string            `json:"storage_key"`
	SizeBytes  uint64            `json:"size_bytes"`
	Checksum   string            `json:"checksum"`
	PartBytes  uint64            `json:"part_bytes"`
	Parts      []PlannedPart     `json:"parts"`
	Warnings   []driver.Warning  `json:"warnings"`
}

// DownloadPlan pins one immutable provider object and a fresh canonical local
// destination. BlockBytes is an acceleration choice and does not change the
// final checksum or complete-file publication semantics.
type DownloadPlan struct {
	Driver      driver.Descriptor `json:"driver"`
	Object      driver.Object     `json:"object"`
	Checksum    string            `json:"checksum"`
	Destination string            `json:"destination"`
	StagingPath string            `json:"staging_path"`
	BlockBytes  uint64            `json:"block_bytes"`
	Blocks      []PlannedBlock    `json:"blocks"`
	Warnings    []driver.Warning  `json:"warnings"`
}

type planRecord struct {
	Schema    string        `json:"schema"`
	ID        string        `json:"id"`
	Direction Direction     `json:"direction"`
	CreatedAt int64         `json:"created_at"`
	Upload    *UploadPlan   `json:"upload,omitempty"`
	Download  *DownloadPlan `json:"download,omitempty"`
}

type executorLease struct {
	Owner     string `json:"owner"`
	Fence     uint64 `json:"fence"`
	ExpiresAt int64  `json:"expires_at"`
}

type stateRecord struct {
	Schema              string                `json:"schema"`
	Revision            uint64                `json:"revision"`
	PlanDigest          string                `json:"plan_digest"`
	PreviousStateDigest string                `json:"previous_state_digest,omitempty"`
	Status              Status                `json:"status"`
	ExecutorFence       uint64                `json:"executor_fence"`
	Lease               *executorLease        `json:"lease,omitempty"`
	UploadSession       *driver.UploadSession `json:"upload_session,omitempty"`
	CompletionParts     []driver.UploadedPart `json:"completion_parts,omitempty"`
	Object              *driver.Object        `json:"object,omitempty"`
	UpdatedAt           int64                 `json:"updated_at"`
}

type uploadPartReceipt struct {
	Schema     string      `json:"schema"`
	PlanDigest string      `json:"plan_digest"`
	Part       PlannedPart `json:"part"`
}

// VerifiedBlock records one durable exact range in a download staging file.
type VerifiedBlock struct {
	Number   uint32 `json:"number"`
	Offset   uint64 `json:"offset"`
	Length   uint64 `json:"length"`
	Checksum string `json:"checksum"`
}

type downloadBlockReceipt struct {
	Schema     string        `json:"schema"`
	PlanDigest string        `json:"plan_digest"`
	Block      VerifiedBlock `json:"block"`
}

// Snapshot is an authenticated-internal view of immutable planning data,
// optimistic state, and durable progress receipts. Returned slices are owned by
// the caller and may be inspected safely by CLIs or recovery tooling.
type Snapshot struct {
	ID             string
	Direction      Direction
	Status         Status
	Revision       uint64
	Upload         *UploadPlan
	Download       *DownloadPlan
	UploadSession  *driver.UploadSession
	Object         *driver.Object
	CompletedParts []PlannedPart
	VerifiedBlocks []VerifiedBlock
}

func (plan planRecord) validate() error {
	if plan.Schema != schema || validateIdentity(plan.ID) != nil || plan.CreatedAt <= 0 {
		return fmt.Errorf("%w: invalid plan envelope identity", ErrInvalidPlan)
	}

	switch plan.Direction {
	case DirectionUpload:
		if plan.Upload == nil || plan.Download != nil {
			return fmt.Errorf("%w: upload plan union is invalid", ErrInvalidPlan)
		}

		return plan.Upload.validate()
	case DirectionDownload:
		if plan.Download == nil || plan.Upload != nil {
			return fmt.Errorf("%w: download plan union is invalid", ErrInvalidPlan)
		}

		return plan.Download.validate()
	default:
		return fmt.Errorf("%w: unknown direction %q", ErrInvalidPlan, plan.Direction)
	}
}

func (plan UploadPlan) validate() error {
	if err := plan.Driver.Validate(); err != nil {
		return fmt.Errorf("%w: upload driver: %w", ErrInvalidPlan, err)
	}

	if strings.TrimSpace(plan.StorageKey) == "" || plan.SizeBytes != plan.Source.SizeBytes ||
		plan.Checksum != plan.Source.Checksum {
		return fmt.Errorf("%w: upload source and object identity disagree", ErrInvalidPlan)
	}

	if err := plan.Source.validate(); err != nil {
		return err
	}

	if err := validateSHA256(plan.Checksum); err != nil {
		return err
	}

	capabilities := plan.Driver.Capabilities
	if capabilities.MaximumObjectBytes != 0 && plan.SizeBytes > capabilities.MaximumObjectBytes {
		return fmt.Errorf("%w: upload exceeds driver object limit", ErrInvalidPlan)
	}

	if plan.SizeBytes != 0 && capabilities.Write.Resume.Available() &&
		(plan.PartBytes < capabilities.Write.MinimumNonFinalPartBytes ||
			plan.PartBytes > capabilities.Write.MaximumPartBytes ||
			uint64(len(plan.Parts)) > uint64(capabilities.Write.MaximumParts)) {
		return fmt.Errorf("%w: upload layout exceeds driver part limits", ErrInvalidPlan)
	}

	return validateParts(plan.SizeBytes, plan.PartBytes, plan.Parts)
}

func (identity SourceIdentity) validate() error {
	if strings.TrimSpace(identity.Kind) == "" || strings.TrimSpace(identity.Reference) == "" ||
		strings.TrimSpace(identity.Version) == "" {
		return fmt.Errorf("%w: source identity fields are required", ErrInvalidPlan)
	}

	return validateSHA256(identity.Checksum)
}

func (plan DownloadPlan) validate() error {
	if err := plan.Driver.Validate(); err != nil {
		return fmt.Errorf("%w: download driver: %w", ErrInvalidPlan, err)
	}

	if strings.TrimSpace(plan.Object.Locator.StorageKey) == "" {
		return fmt.Errorf("%w: download object identity is required", ErrInvalidPlan)
	}

	if err := validateSHA256(plan.Checksum); err != nil {
		return err
	}

	capabilities := plan.Driver.Capabilities
	if capabilities.MaximumObjectBytes != 0 && plan.Object.SizeBytes > capabilities.MaximumObjectBytes {
		return fmt.Errorf("%w: download exceeds driver object limit", ErrInvalidPlan)
	}

	if capabilities.Read.Range.Available() && capabilities.Read.MaximumRangeBytes != 0 &&
		plan.BlockBytes > capabilities.Read.MaximumRangeBytes {
		return fmt.Errorf("%w: download block exceeds driver range limit", ErrInvalidPlan)
	}

	if !canonicalAbsolutePath(plan.Destination) || !canonicalAbsolutePath(plan.StagingPath) ||
		filepath.Dir(plan.Destination) != filepath.Dir(plan.StagingPath) || plan.Destination == plan.StagingPath {
		return fmt.Errorf("%w: download paths must be distinct canonical siblings", ErrInvalidPlan)
	}

	return validateBlocks(plan.Object.SizeBytes, plan.BlockBytes, plan.Blocks)
}

func validateParts(sizeBytes, partBytes uint64, parts []PlannedPart) error {
	if sizeBytes == 0 {
		if partBytes != 0 || len(parts) != 0 {
			return fmt.Errorf("%w: empty upload cannot contain parts", ErrInvalidPlan)
		}

		return nil
	}

	if partBytes == 0 || len(parts) == 0 {
		return fmt.Errorf("%w: non-empty upload requires a part layout", ErrInvalidPlan)
	}

	if len(parts) > int(maximumPlanPieces) {
		return fmt.Errorf("%w: upload exceeds maximum journal part count", ErrInvalidPlan)
	}

	nextOffset := uint64(0)
	for index, part := range parts {
		expectedLength := min(partBytes, sizeBytes-nextOffset)
		if part.Number != uint32(index+1) || part.Offset != nextOffset || part.Length != expectedLength {
			return fmt.Errorf("%w: upload parts are not canonical and gapless", ErrInvalidPlan)
		}

		if err := validateSHA256(part.Checksum); err != nil {
			return err
		}

		nextOffset += part.Length
	}

	if nextOffset != sizeBytes {
		return fmt.Errorf("%w: upload parts do not cover the complete object", ErrInvalidPlan)
	}

	return nil
}

func validateBlocks(sizeBytes, blockBytes uint64, blocks []PlannedBlock) error {
	if sizeBytes == 0 {
		if blockBytes != 0 || len(blocks) != 0 {
			return fmt.Errorf("%w: empty download cannot contain blocks", ErrInvalidPlan)
		}

		return nil
	}

	if blockBytes == 0 || len(blocks) == 0 {
		return fmt.Errorf("%w: non-empty download requires a block layout", ErrInvalidPlan)
	}

	if len(blocks) > int(maximumPlanPieces) {
		return fmt.Errorf("%w: download exceeds maximum journal block count", ErrInvalidPlan)
	}

	nextOffset := uint64(0)
	for index, block := range blocks {
		expectedLength := min(blockBytes, sizeBytes-nextOffset)
		if block.Number != uint32(index+1) || block.Offset != nextOffset || block.Length != expectedLength {
			return fmt.Errorf("%w: download blocks are not canonical and gapless", ErrInvalidPlan)
		}

		nextOffset += block.Length
	}

	if nextOffset != sizeBytes {
		return fmt.Errorf("%w: download blocks do not cover the complete object", ErrInvalidPlan)
	}

	return nil
}

func (state stateRecord) validate(planDigest string, previous stateEnvelope) error {
	if state.Schema != schema || state.PlanDigest != planDigest || state.Revision == 0 || state.UpdatedAt <= 0 {
		return fmt.Errorf("%w: invalid state identity", ErrJournalCorrupt)
	}

	if err := state.validateChain(previous); err != nil {
		return err
	}

	if err := state.Status.validate(); err != nil {
		return err
	}

	if err := state.validateLease(); err != nil {
		return err
	}

	return state.validateTerminalContents()
}

func (state stateRecord) validateChain(previous stateEnvelope) error {
	if state.Revision == 1 {
		if state.PreviousStateDigest != "" || state.Status != StatusPrepared {
			return fmt.Errorf("%w: invalid initial state", ErrJournalCorrupt)
		}
	} else if state.Revision != previous.record.Revision+1 || state.PreviousStateDigest != previous.digest {
		return fmt.Errorf("%w: state hash chain is discontinuous", ErrJournalCorrupt)
	}

	if state.Revision > 1 {
		if err := validateStatusTransition(previous.record.Status, state.Status); err != nil {
			return fmt.Errorf("%w: persisted state transition is invalid: %w", ErrJournalCorrupt, err)
		}
	}

	return nil
}

func (state stateRecord) validateLease() error {
	if state.Lease != nil && (state.Lease.Owner == "" || state.Lease.Fence == 0 ||
		state.Lease.Fence != state.ExecutorFence || state.Lease.ExpiresAt <= 0) {
		return fmt.Errorf("%w: executor lease is invalid", ErrJournalCorrupt)
	}

	if (state.Status == StatusComplete || state.Status == StatusAborted) && state.Lease != nil {
		return fmt.Errorf("%w: terminal state retains an executor lease", ErrJournalCorrupt)
	}

	return nil
}

func (state stateRecord) validateTerminalContents() error {
	if state.Status == StatusComplete && state.Object == nil {
		return fmt.Errorf("%w: complete state lacks an object", ErrJournalCorrupt)
	}

	if state.Status == StatusAborted && state.Object != nil {
		return fmt.Errorf("%w: aborted state contains an object", ErrJournalCorrupt)
	}

	return nil
}

func validateStatusTransition(previous, next Status) error {
	allowed := map[Status][]Status{
		StatusPrepared:     {StatusTransferring, StatusAborted},
		StatusTransferring: {StatusTransferring, StatusVerifying, StatusAborted},
		StatusVerifying:    {StatusVerifying, StatusPublishing, StatusComplete, StatusAborted},
		StatusPublishing:   {StatusPublishing, StatusComplete, StatusAborted},
		StatusComplete:     nil,
		StatusAborted:      nil,
	}

	if slices.Contains(allowed[previous], next) {
		return nil
	}

	return fmt.Errorf("%w: invalid state transition %q to %q", ErrJournalConflict, previous, next)
}

func (status Status) validate() error {
	if slices.Contains(
		[]Status{StatusPrepared, StatusTransferring, StatusVerifying, StatusPublishing, StatusComplete, StatusAborted},
		status,
	) {
		return nil
	}

	return fmt.Errorf("%w: unknown status %q", ErrJournalCorrupt, status)
}

func validateSHA256(checksum string) error {
	digest, err := hex.DecodeString(checksum)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != checksum {
		return fmt.Errorf("%w: SHA-256 must be 64 lowercase hexadecimal characters", ErrInvalidPlan)
	}

	return nil
}

func validateIdentity(identity string) error {
	decoded, err := hex.DecodeString(identity)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != identity {
		return fmt.Errorf("%w: journal ID must be 32 lowercase hexadecimal characters", ErrInvalidPlan)
	}

	return nil
}

func canonicalAbsolutePath(filePath string) bool {
	return filePath != "" && filepath.IsAbs(filePath) && filepath.Clean(filePath) == filePath
}
