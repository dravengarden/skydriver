package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
)

// ErrInvalidCompact indicates an unsafe source, target, or workspace identity.
var ErrInvalidCompact = errors.New("invalid Carrack compaction")

const compactPlaintextKey = "plaintext"

// Compactor decrypts one immutable generation and repacks it through a new importer.
type Compactor struct {
	restorer        *Restorer
	destination     provider.ReadWriter
	targetLayout    archive.Layout
	importerOptions ImporterOptions
}

// CompactExecutionRequest supplies the already pinned source and target identities.
type CompactExecutionRequest struct {
	SourceRecovery      manifest.RecoveryManifest
	SourceEpochKey      cryptostream.EpochKey
	TargetEpochKey      cryptostream.EpochKey
	ObjectID            string
	TargetGeneration    uint64
	TargetRootVersion   uint32
	TargetKeyEpoch      uint64
	DestinationDriverID string
	DestinationPrefix   string
	PlaintextPath       string
	PlanFile            string
	StagingDirectory    string
}

// CompactExecutionResult contains the verified plaintext bridge and replacement archive.
type CompactExecutionResult struct {
	Restore         RestoreResult
	RestoreProgress RestoreProgress
	Plan            ImportPlan
	Import          ImportResult
}

// NewCompactor constructs a provider-neutral decrypt-and-repack data path.
func NewCompactor(
	restorer *Restorer,
	destination provider.ReadWriter,
	targetLayout archive.Layout,
	options ImporterOptions,
) (*Compactor, error) {
	if restorer == nil || destination == nil {
		return nil, fmt.Errorf("%w: restorer and destination are required", ErrInvalidCompact)
	}

	if err := targetLayout.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCompact, err)
	}

	if _, err := providerObjectTarget(
		options.ProviderObjectTargetBytes,
		options.MaximumProviderObjectBytes,
	); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCompact, err)
	}

	return &Compactor{
		restorer: restorer, destination: destination, targetLayout: targetLayout,
		importerOptions: options,
	}, nil
}

// Execute restores verified plaintext into the explicit workspace, persists all
// new random pack IDs, then encrypts and verifies the smaller replacement.
func (compactor *Compactor) Execute(
	ctx context.Context,
	requested CompactExecutionRequest,
) (CompactExecutionResult, error) {
	if err := validateCompactExecution(compactor, requested); err != nil {
		return CompactExecutionResult{}, err
	}

	var restoreProgress RestoreProgress

	restored, err := compactor.restorer.RestoreWithProgress(
		ctx,
		requested.SourceRecovery,
		requested.SourceEpochKey,
		requested.PlaintextPath,
		func(progress RestoreProgress) { restoreProgress = progress },
	)
	if err != nil {
		return CompactExecutionResult{}, fmt.Errorf("restore compact source: %w", err)
	}

	source, err := newCompactPlaintextReader(requested.PlaintextPath)
	if err != nil {
		return CompactExecutionResult{}, err
	}

	importer, err := NewImporterWithOptions(
		source,
		compactor.destination,
		compactor.targetLayout,
		compactor.importerOptions,
	)
	if err != nil {
		return CompactExecutionResult{}, fmt.Errorf("construct compact importer: %w", err)
	}

	plan, err := compactor.loadOrCreatePlan(ctx, importer, source.object, requested)
	if err != nil {
		return CompactExecutionResult{}, err
	}

	if len(plan.Packs) == 0 || len(plan.Packs) >= len(requested.SourceRecovery.Manifest.Packs) {
		return CompactExecutionResult{}, fmt.Errorf(
			"%w: target layout does not reduce the source pack count",
			ErrInvalidCompact,
		)
	}

	imported, err := importer.Execute(
		ctx,
		plan,
		requested.TargetEpochKey,
		requested.StagingDirectory,
	)
	if err != nil {
		return CompactExecutionResult{}, fmt.Errorf("write compact replacement: %w", err)
	}

	if imported.Manifest.PlaintextSHA256 != requested.SourceRecovery.Manifest.PlaintextSHA256 ||
		imported.Manifest.PlaintextSize != requested.SourceRecovery.Manifest.PlaintextSize ||
		len(imported.Manifest.Packs) >= len(requested.SourceRecovery.Manifest.Packs) {
		return CompactExecutionResult{}, fmt.Errorf(
			"%w: compact replacement changed plaintext or did not reduce packs",
			ErrInvalidCompact,
		)
	}

	return CompactExecutionResult{
		Restore: restored, RestoreProgress: restoreProgress, Plan: plan, Import: imported,
	}, nil
}

func (compactor *Compactor) loadOrCreatePlan(
	ctx context.Context,
	importer *Importer,
	source provider.Object,
	requested CompactExecutionRequest,
) (ImportPlan, error) {
	plan, err := ReadImportPlan(requested.PlanFile)
	if err == nil {
		if validationErr := validateCompactPlan(
			plan,
			source,
			requested,
			compactor.targetLayout,
		); validationErr != nil {
			return ImportPlan{}, validationErr
		}

		return plan, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return ImportPlan{}, err
	}

	namespaceID, err := parseCryptoIdentifier(requested.SourceRecovery.Manifest.NamespaceID)
	if err != nil {
		return ImportPlan{}, err
	}

	plan, err = importer.PlanImport(ctx, ImportPlanRequest{
		NamespaceID: namespaceID, ObjectID: requested.ObjectID,
		Generation: requested.TargetGeneration, RootVersion: requested.TargetRootVersion,
		KeyEpoch: requested.TargetKeyEpoch, SourceKey: compactPlaintextKey,
		DestinationDriverID: requested.DestinationDriverID,
		DestinationPrefix:   requested.DestinationPrefix,
	})
	if err != nil {
		return ImportPlan{}, fmt.Errorf("plan compact replacement: %w", err)
	}

	if err := validateCompactPlan(plan, source, requested, compactor.targetLayout); err != nil {
		return ImportPlan{}, err
	}

	if err := WriteImportPlan(requested.PlanFile, plan); err != nil {
		return ImportPlan{}, err
	}

	return plan, nil
}

func validateCompactExecution(compactor *Compactor, requested CompactExecutionRequest) error {
	if compactor == nil || compactor.restorer == nil || compactor.destination == nil {
		return fmt.Errorf("%w: compactor is not initialized", ErrInvalidCompact)
	}

	if err := requested.SourceRecovery.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidCompact, err)
	}

	if len(requested.SourceRecovery.Manifest.Packs) < 2 ||
		!validPlanString(requested.ObjectID, 2_048) || requested.TargetGeneration < 2 ||
		requested.TargetRootVersion == 0 || requested.TargetKeyEpoch == 0 ||
		!validControlString(requested.DestinationDriverID, 256) ||
		!validDestinationPrefix(requested.DestinationPrefix) || requested.PlanFile == "" ||
		requested.PlaintextPath == "" {
		return fmt.Errorf("%w: invalid replacement identity", ErrInvalidCompact)
	}

	if err := validateStagingDirectory(requested.StagingDirectory); err != nil {
		return fmt.Errorf("%w: invalid staging directory: %w", ErrInvalidCompact, err)
	}

	for _, candidate := range []string{requested.PlaintextPath, requested.PlanFile} {
		absolute, err := filepath.Abs(candidate)
		if err != nil || absolute != candidate || filepath.Dir(absolute) != requested.StagingDirectory {
			return fmt.Errorf("%w: workspace files must be canonical staging children", ErrInvalidCompact)
		}
	}

	return nil
}

func validateCompactPlan(
	plan ImportPlan,
	source provider.Object,
	requested CompactExecutionRequest,
	layout archive.Layout,
) error {
	if err := plan.Validate(); err != nil {
		return err
	}

	if plan.NamespaceID != requested.SourceRecovery.Manifest.NamespaceID ||
		plan.ObjectID != requested.ObjectID || plan.Generation != requested.TargetGeneration ||
		plan.RootVersion != requested.TargetRootVersion || plan.KeyEpoch != requested.TargetKeyEpoch ||
		plan.Source != PlannedSource(source) || plan.Source.Key != compactPlaintextKey ||
		plan.DestinationDriverID != requested.DestinationDriverID ||
		plan.DestinationPrefix != requested.DestinationPrefix || plan.Layout != layout {
		return fmt.Errorf("%w: persisted compact plan identity changed", ErrInvalidImportPlan)
	}

	return nil
}

type compactPlaintextReader struct {
	path   string
	object provider.Object
}

func newCompactPlaintextReader(path string) (*compactPlaintextReader, error) {
	object, err := compactPlaintextObject(path)
	if err != nil {
		return nil, err
	}

	return &compactPlaintextReader{path: path, object: object}, nil
}

func (reader *compactPlaintextReader) Stat(ctx context.Context, key string) (provider.Object, error) {
	if err := ctx.Err(); err != nil {
		return provider.Object{}, fmt.Errorf("inspect compact plaintext: %w", err)
	}

	if key != compactPlaintextKey {
		return provider.Object{}, fmt.Errorf("%w: unknown compact plaintext key", ErrInvalidCompact)
	}

	return compactPlaintextObject(reader.path)
}

func (reader *compactPlaintextReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("open compact plaintext range: %w", err)
	}

	if key != compactPlaintextKey || length == 0 || offset > reader.object.SizeBytes ||
		length > reader.object.SizeBytes-offset {
		return nil, fmt.Errorf("%w: invalid compact plaintext range", ErrInvalidCompact)
	}

	file, err := os.Open(reader.path) // #nosec G304 -- path is an explicit canonical workspace child.
	if err != nil {
		return nil, fmt.Errorf("open compact plaintext: %w", err)
	}

	section := io.NewSectionReader(file, int64(offset), int64(length)) // #nosec G115 -- file sizes are bounded by os.File offsets.

	return &sectionReadCloser{Reader: section, file: file}, nil
}

type sectionReadCloser struct {
	io.Reader

	file *os.File
}

func (reader *sectionReadCloser) Close() error {
	if err := reader.file.Close(); err != nil {
		return fmt.Errorf("close compact plaintext range: %w", err)
	}

	return nil
}

func compactPlaintextObject(path string) (provider.Object, error) {
	file, err := os.Open(path) // #nosec G304 -- path is an explicit canonical workspace child.
	if err != nil {
		return provider.Object{}, fmt.Errorf("open compact plaintext: %w", err)
	}

	information, err := file.Stat()
	if err != nil || !information.Mode().IsRegular() || information.Size() <= 0 {
		closeErr := file.Close()

		return provider.Object{}, errors.Join(
			fmt.Errorf("%w: compact plaintext must be a non-empty regular file", ErrInvalidCompact),
			closeErr,
		)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		closeErr := file.Close()

		return provider.Object{}, errors.Join(fmt.Errorf("hash compact plaintext: %w", err), closeErr)
	}

	if err := file.Close(); err != nil {
		return provider.Object{}, fmt.Errorf("close compact plaintext: %w", err)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))
	// #nosec G115 -- a positive os.FileInfo size is an int64 and therefore fits uint64.
	sizeBytes := uint64(information.Size())

	return provider.Object{
		Key: compactPlaintextKey, SizeBytes: sizeBytes, ETag: digest,
		Version: digest,
	}, nil
}
