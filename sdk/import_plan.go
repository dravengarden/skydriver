package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/provider"
)

const (
	// ImportPlanSchemaVersion is the crash-resumable V1 import plan format.
	ImportPlanSchemaVersion    = "carrack.import-plan.v1"
	maximumPlanBytes           = 64 << 20
	identifierBytes            = 16
	defaultProviderObjectBytes = uint64(1 << 30)
)

var (
	// ErrInvalidImportPlan indicates unsafe or internally inconsistent work.
	ErrInvalidImportPlan = errors.New("invalid Carrack import plan")
	errTrailingPlanJSON  = errors.New("unexpected trailing import-plan JSON")
)

// ImportPlanRequest supplies immutable identities for planning one import.
type ImportPlanRequest struct {
	NamespaceID         cryptostream.Identifier
	ObjectID            string
	Generation          uint64
	RootVersion         uint32
	KeyEpoch            uint64
	SourceKey           string
	DestinationDriverID string
	DestinationPrefix   string
}

// ImportPlan persists every random pack identity before payload transfer.
type ImportPlan struct {
	SchemaVersion       string         `json:"schema_version"`
	NamespaceID         string         `json:"namespace_id"`
	ObjectID            string         `json:"object_id"`
	Generation          uint64         `json:"generation"`
	RootVersion         uint32         `json:"root_version"`
	KeyEpoch            uint64         `json:"key_epoch"`
	Source              PlannedSource  `json:"source"`
	DestinationDriverID string         `json:"destination_driver_id"`
	DestinationPrefix   string         `json:"destination_prefix"`
	Layout              archive.Layout `json:"layout"`
	Packs               []PlannedPack  `json:"packs"`
}

// PlannedSource pins the provider identity observed before transfer.
type PlannedSource struct {
	Key       string `json:"key"`
	SizeBytes uint64 `json:"size_bytes"`
	ETag      string `json:"etag,omitempty"`
	Version   string `json:"version,omitempty"`
}

// PlannedPack pins one random pack ID to an exact source range.
type PlannedPack struct {
	Ordinal         uint64 `json:"ordinal"`
	PackID          string `json:"pack_id"`
	PlaintextOffset uint64 `json:"plaintext_offset"`
	PlaintextSize   uint64 `json:"plaintext_size"`
}

// Importer executes bounded-memory encrypted imports.
type Importer struct {
	source              provider.Reader
	destination         provider.ReadWriter
	layout              archive.Layout
	providerObjectBytes uint64
	maximumObjectBytes  uint64
}

// ImporterOptions controls provider placement independently from crypto and
// integrity extent sizes. Targets never cause padding.
type ImporterOptions struct {
	ProviderObjectTargetBytes  uint64
	MaximumProviderObjectBytes uint64
}

// ImporterOptionsFromCapabilities translates an opened driver policy without
// coupling archive identity to that driver.
func ImporterOptionsFromCapabilities(capabilities provider.Capabilities) ImporterOptions {
	return ImporterOptions{
		ProviderObjectTargetBytes:  capabilities.PreferredObjectBytes,
		MaximumProviderObjectBytes: capabilities.MaximumObjectBytes,
	}
}

// NewImporter constructs a direct source-to-destination importer.
func NewImporter(
	source provider.Reader,
	destination provider.ReadWriter,
	layout archive.Layout,
) (*Importer, error) {
	return NewImporterWithOptions(source, destination, layout, ImporterOptions{})
}

// NewImporterWithOptions constructs an importer with an exact-length provider
// object grouping policy.
func NewImporterWithOptions(
	source provider.Reader,
	destination provider.ReadWriter,
	layout archive.Layout,
	options ImporterOptions,
) (*Importer, error) {
	if source == nil || destination == nil {
		return nil, fmt.Errorf("%w: source and readable destination are required", ErrInvalidConfiguration)
	}

	if err := layout.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	target, err := providerObjectTarget(
		options.ProviderObjectTargetBytes,
		options.MaximumProviderObjectBytes,
	)
	if err != nil {
		return nil, err
	}

	return &Importer{
		source:              source,
		destination:         destination,
		layout:              layout,
		providerObjectBytes: target,
		maximumObjectBytes:  options.MaximumProviderObjectBytes,
	}, nil
}

// PlanImport pins the source identity and generates all pack IDs before any
// destination write occurs.
func (importer *Importer) PlanImport(
	ctx context.Context,
	request ImportPlanRequest,
) (ImportPlan, error) {
	if importer == nil || importer.source == nil {
		return ImportPlan{}, fmt.Errorf("%w: importer is not initialized", ErrInvalidConfiguration)
	}

	source, err := importer.source.Stat(ctx, request.SourceKey)
	if err != nil {
		return ImportPlan{}, fmt.Errorf("stat import source %q: %w", request.SourceKey, err)
	}

	spans, err := importer.layout.PlanPacks(source.SizeBytes)
	if err != nil {
		return ImportPlan{}, fmt.Errorf("plan import packs: %w", err)
	}

	packs := make([]PlannedPack, len(spans))
	for index, span := range spans {
		packID, err := randomIdentifier()
		if err != nil {
			return ImportPlan{}, err
		}

		packs[index] = PlannedPack{
			Ordinal:         span.Ordinal,
			PackID:          packID,
			PlaintextOffset: span.Offset,
			PlaintextSize:   span.Size,
		}
	}

	plan := ImportPlan{
		SchemaVersion:       ImportPlanSchemaVersion,
		NamespaceID:         hex.EncodeToString(request.NamespaceID[:]),
		ObjectID:            request.ObjectID,
		Generation:          request.Generation,
		RootVersion:         request.RootVersion,
		KeyEpoch:            request.KeyEpoch,
		Source:              PlannedSource(source),
		DestinationDriverID: request.DestinationDriverID,
		DestinationPrefix:   strings.Trim(request.DestinationPrefix, "/"),
		Layout:              importer.layout,
		Packs:               packs,
	}
	if err := plan.Validate(); err != nil {
		return ImportPlan{}, err
	}

	return plan, nil
}

// Validate checks source coverage and all immutable protocol identities.
func (plan ImportPlan) Validate() error {
	if err := validateImportPlanHeader(plan); err != nil {
		return err
	}

	return validatePlannedPacks(plan)
}

func validateImportPlanHeader(plan ImportPlan) error {
	if plan.SchemaVersion != ImportPlanSchemaVersion {
		return invalidImportPlan("unsupported schema version %q", plan.SchemaVersion)
	}

	if !validPlanIdentifier(plan.NamespaceID) {
		return invalidImportPlan("namespace ID must be canonical lowercase hexadecimal")
	}

	if !validPlanString(plan.ObjectID, 2_048) || plan.Generation == 0 {
		return invalidImportPlan("object identity and generation are required")
	}

	if plan.RootVersion == 0 || plan.KeyEpoch == 0 {
		return invalidImportPlan("root version and key epoch must be positive")
	}

	if !validPlanString(plan.Source.Key, 4_096) {
		return invalidImportPlan("source key is required")
	}

	if !validPlanString(plan.DestinationDriverID, 256) || !validDestinationPrefix(plan.DestinationPrefix) {
		return invalidImportPlan("destination driver and prefix are required")
	}

	if err := plan.Layout.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidImportPlan, err)
	}

	if plan.Packs == nil {
		return invalidImportPlan("packs must be an array, not null")
	}

	return nil
}

func validatePlannedPacks(plan ImportPlan) error {
	expectedOffset := uint64(0)
	packIDs := make(map[string]struct{}, len(plan.Packs))

	for index, pack := range plan.Packs {
		if pack.Ordinal != uint64(index) || pack.PlaintextOffset != expectedOffset ||
			pack.PlaintextSize == 0 || pack.PlaintextSize > plan.Layout.LogicalPackBytes ||
			!validPlanIdentifier(pack.PackID) {
			return invalidImportPlan("pack %d is malformed or out of order", index)
		}

		if _, duplicate := packIDs[pack.PackID]; duplicate {
			return invalidImportPlan("pack %d repeats an earlier pack ID", index)
		}

		if pack.PlaintextSize > ^uint64(0)-expectedOffset {
			return invalidImportPlan("pack %d overflows source coverage", index)
		}

		packIDs[pack.PackID] = struct{}{}
		expectedOffset += pack.PlaintextSize
	}

	if expectedOffset != plan.Source.SizeBytes {
		return invalidImportPlan(
			"packs cover %d source bytes, expected %d",
			expectedOffset,
			plan.Source.SizeBytes,
		)
	}

	if plan.Source.SizeBytes == 0 && len(plan.Packs) != 0 {
		return invalidImportPlan("empty source must not contain packs")
	}

	return nil
}

// MarshalCanonical returns the stable import-plan JSON representation.
func (plan ImportPlan) MarshalCanonical() ([]byte, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal Carrack import plan: %w", err)
	}

	return encoded, nil
}

// ParseImportPlan strictly decodes a persisted import plan.
func ParseImportPlan(encoded []byte) (ImportPlan, error) {
	if len(encoded) > maximumPlanBytes {
		return ImportPlan{}, invalidImportPlan("encoded plan exceeds %d bytes", maximumPlanBytes)
	}

	var plan ImportPlan

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&plan); err != nil {
		return ImportPlan{}, fmt.Errorf("%w: decode JSON: %w", ErrInvalidImportPlan, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return ImportPlan{}, fmt.Errorf("%w: %w", ErrInvalidImportPlan, errTrailingPlanJSON)
		}

		return ImportPlan{}, fmt.Errorf("%w: decode trailing JSON: %w", ErrInvalidImportPlan, err)
	}

	if err := plan.Validate(); err != nil {
		return ImportPlan{}, err
	}

	return plan, nil
}

// WriteImportPlan atomically persists a non-secret plan before transfer.
func WriteImportPlan(filePath string, plan ImportPlan) error {
	encoded, err := plan.MarshalCanonical()
	if err != nil {
		return err
	}

	directory := filepath.Dir(filePath)

	temporary, err := os.CreateTemp(directory, ".carrack-import-plan-*")
	if err != nil {
		return fmt.Errorf("create temporary Carrack import plan: %w", err)
	}

	temporaryPath := temporary.Name()
	committed := false

	defer func() {
		if !committed {
			removeErr := os.Remove(temporaryPath)
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return
			}
		}
	}()

	if chmodErr := temporary.Chmod(0o600); chmodErr != nil {
		return errors.Join(fmt.Errorf("secure Carrack import plan: %w", chmodErr), temporary.Close())
	}

	if _, writeErr := temporary.Write(encoded); writeErr != nil {
		return errors.Join(fmt.Errorf("write Carrack import plan: %w", writeErr), temporary.Close())
	}

	if syncFileErr := temporary.Sync(); syncFileErr != nil {
		return errors.Join(fmt.Errorf("sync Carrack import plan: %w", syncFileErr), temporary.Close())
	}

	if closeTemporaryErr := temporary.Close(); closeTemporaryErr != nil {
		return fmt.Errorf("close Carrack import plan: %w", closeTemporaryErr)
	}

	if renameErr := os.Rename(temporaryPath, filePath); renameErr != nil {
		return fmt.Errorf("publish Carrack import plan: %w", renameErr)
	}

	directoryRoot, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open Carrack import-plan root: %w", err)
	}

	directoryHandle, err := directoryRoot.Open(".")
	if err != nil {
		return errors.Join(
			fmt.Errorf("open Carrack import-plan directory: %w", err),
			directoryRoot.Close(),
		)
	}

	syncErr := directoryHandle.Sync()
	closeHandleErr := directoryHandle.Close()
	closeRootErr := directoryRoot.Close()

	if syncErr != nil || closeHandleErr != nil || closeRootErr != nil {
		return fmt.Errorf(
			"sync Carrack import-plan directory: %w",
			errors.Join(syncErr, closeHandleErr, closeRootErr),
		)
	}

	committed = true

	return nil
}

func randomIdentifier() (string, error) {
	var identifier [identifierBytes]byte
	if _, err := rand.Read(identifier[:]); err != nil {
		return "", fmt.Errorf("generate Carrack pack ID: %w", err)
	}

	return hex.EncodeToString(identifier[:]), nil
}

func validPlanIdentifier(value string) bool {
	if len(value) != identifierBytes*2 || value != strings.ToLower(value) {
		return false
	}

	decoded, err := hex.DecodeString(value)

	return err == nil && len(decoded) == identifierBytes && !allZeroBytes(decoded)
}

func validPlanString(value string, maximumBytes int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximumBytes
}

func validDestinationPrefix(value string) bool {
	const digestCharacters = sha256.Size * 2

	return validPlanString(value, maximumProviderKeyBytes) && path.Clean(value) == value &&
		value != "." && value != ".." && !strings.HasPrefix(value, "/") &&
		!strings.HasPrefix(value, "../") && !strings.Contains(value, "\\") &&
		len(recoverySidecarStorageKey(
			value,
			strings.Repeat("0", digestCharacters),
			strings.Repeat("0", digestCharacters),
		)) <= maximumProviderKeyBytes
}

func allZeroBytes(value []byte) bool {
	var combined byte
	for _, element := range value {
		combined |= element
	}

	return combined == 0
}

func invalidImportPlan(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidImportPlan, fmt.Sprintf(format, arguments...))
}
