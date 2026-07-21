package journal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dravengarden/skydriver/driver"
)

const (
	privateFileMode         = fs.FileMode(0o600)
	privateDirectoryMode    = fs.FileMode(0o700)
	maximumRecordBytes      = int64(64 << 20)
	temporaryPrefix         = ".carrack-journal-"
	planFileName            = "plan.json"
	stateDirectoryName      = "state"
	uploadPartsDirectory    = "upload-parts"
	downloadBlocksDirectory = "download-blocks"
)

type recordEnvelope struct {
	Schema  string          `json:"schema"`
	Digest  string          `json:"digest"`
	Payload json.RawMessage `json:"payload"`
}

type planEnvelope struct {
	record planRecord
	digest string
}

type stateEnvelope struct {
	record stateRecord
	digest string
}

type loadedJournal struct {
	plan             planEnvelope
	state            stateEnvelope
	uploadReceipts   []uploadPartReceipt
	downloadReceipts []downloadBlockReceipt
}

// Store owns append-only complete-object transfer journals beneath one private
// local directory. Immutable plans, state revisions, and progress receipts use
// fsync plus no-replace publication; Store never persists payload bytes, keys,
// provider credentials, or encryption secrets.
type Store struct {
	rootPath string
}

// NewStore creates or validates a canonical absolute private directory.
func NewStore(rootPath string) (*Store, error) {
	if !canonicalAbsolutePath(rootPath) {
		return nil, fmt.Errorf("%w: root must be a canonical absolute path", ErrInvalidStore)
	}

	if err := os.MkdirAll(rootPath, privateDirectoryMode); err != nil {
		return nil, fmt.Errorf("%w: create root: %w", ErrInvalidStore, err)
	}

	information, err := os.Lstat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect root: %w", ErrInvalidStore, err)
	}

	if !information.IsDir() || information.Mode()&fs.ModeSymlink != 0 || information.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: root must be a private real directory", ErrInvalidStore)
	}

	return &Store{rootPath: rootPath}, nil
}

// Load validates the plan envelope, complete state hash chain, and every
// progress receipt before returning a caller-owned recovery snapshot.
func (store *Store) Load(journalID string) (Snapshot, error) {
	loaded, err := store.loadRecords(journalID)
	if err != nil {
		return Snapshot{}, err
	}

	return snapshotFromRecords(
		loaded.plan,
		loaded.state,
		loaded.uploadReceipts,
		loaded.downloadReceipts,
	), nil
}

// List validates and returns every durably published journal in stable ID
// order. An unexpected entry or one corrupt journal fails the entire listing;
// incomplete private directories from an interrupted create are ignored.
func (store *Store) List() ([]Snapshot, error) {
	if store == nil || store.rootPath == "" {
		return nil, fmt.Errorf("%w: store is not initialized", ErrInvalidStore)
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open root: %w", ErrInvalidStore, err)
	}

	entries, readErr := fs.ReadDir(root.FS(), ".")

	closeErr := root.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("%w: list root: %w", ErrInvalidStore, errors.Join(readErr, closeErr))
	}

	journalIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()

		temporaryID, temporary := strings.CutPrefix(name, temporaryPrefix)
		if temporary {
			if !safeJournalDirectoryEntry(entry, temporaryID) {
				return nil, fmt.Errorf("%w: malformed temporary entry %q", ErrJournalCorrupt, name)
			}

			continue
		}

		if !safeJournalDirectoryEntry(entry, name) {
			return nil, fmt.Errorf("%w: unexpected store entry %q", ErrJournalCorrupt, name)
		}

		journalIDs = append(journalIDs, name)
	}

	slices.Sort(journalIDs)

	snapshots := make([]Snapshot, 0, len(journalIDs))
	for _, journalID := range journalIDs {
		snapshot, err := store.Load(journalID)
		if err != nil {
			return nil, fmt.Errorf("list journal %s: %w", journalID, err)
		}

		snapshots = append(snapshots, snapshot)
	}

	return snapshots, nil
}

func safeJournalDirectoryEntry(entry fs.DirEntry, journalID string) bool {
	return entry.Type()&fs.ModeSymlink == 0 && entry.IsDir() && validateIdentity(journalID) == nil
}

func (store *Store) create(plan planRecord) (planEnvelope, stateEnvelope, error) {
	if store == nil || store.rootPath == "" {
		return planEnvelope{}, stateEnvelope{}, fmt.Errorf("%w: store is not initialized", ErrInvalidStore)
	}

	if err := plan.validate(); err != nil {
		return planEnvelope{}, stateEnvelope{}, err
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return planEnvelope{}, stateEnvelope{}, fmt.Errorf("%w: open root: %w", ErrInvalidStore, err)
	}

	createdPlan, createdState, createErr := createJournalAt(root, plan)

	closeErr := root.Close()
	if createErr != nil || closeErr != nil {
		return planEnvelope{}, stateEnvelope{}, errors.Join(createErr, closeErr)
	}

	return createdPlan, createdState, nil
}

func (store *Store) loadRecords(journalID string) (loadedJournal, error) {
	if store == nil || store.rootPath == "" {
		return loadedJournal{}, fmt.Errorf("%w: store is not initialized", ErrInvalidStore)
	}

	if err := validateIdentity(journalID); err != nil {
		return loadedJournal{}, err
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return loadedJournal{}, fmt.Errorf("%w: open root: %w", ErrInvalidStore, err)
	}

	loaded, loadErr := loadJournalAt(root, journalID)

	closeErr := root.Close()
	if loadErr != nil || closeErr != nil {
		return loadedJournal{}, errors.Join(loadErr, closeErr)
	}

	return loaded, nil
}

func createJournalAt(root *os.Root, plan planRecord) (planEnvelope, stateEnvelope, error) {
	temporaryDirectory := temporaryPrefix + plan.ID
	if err := root.Mkdir(temporaryDirectory, privateDirectoryMode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return planEnvelope{}, stateEnvelope{}, fmt.Errorf("%w: temporary journal exists", ErrJournalConflict)
		}

		return planEnvelope{}, stateEnvelope{}, fmt.Errorf("%w: create temporary journal: %w", ErrInvalidStore, err)
	}

	createdPlan, createdState, err := initializeTemporaryJournal(root, temporaryDirectory, plan)
	if err != nil {
		removeErr := root.RemoveAll(temporaryDirectory)

		return planEnvelope{}, stateEnvelope{}, errors.Join(err, removeErr)
	}

	if err := root.Rename(temporaryDirectory, plan.ID); err != nil {
		removeErr := root.RemoveAll(temporaryDirectory)

		return planEnvelope{}, stateEnvelope{}, errors.Join(
			fmt.Errorf("%w: publish journal: %w", ErrJournalConflict, err),
			removeErr,
		)
	}

	if err := syncDirectory(root, "."); err != nil {
		return planEnvelope{}, stateEnvelope{}, err
	}

	return createdPlan, createdState, nil
}

func initializeTemporaryJournal(
	root *os.Root,
	directory string,
	plan planRecord,
) (planEnvelope, stateEnvelope, error) {
	for _, child := range []string{stateDirectoryName, uploadPartsDirectory, downloadBlocksDirectory} {
		if err := root.Mkdir(path.Join(directory, child), privateDirectoryMode); err != nil {
			return planEnvelope{}, stateEnvelope{}, fmt.Errorf("%w: create journal directory: %w", ErrInvalidStore, err)
		}
	}

	planDigest, err := writeEnvelopeExclusive(root, path.Join(directory, planFileName), plan)
	if err != nil {
		return planEnvelope{}, stateEnvelope{}, err
	}

	initial := stateRecord{
		Schema:     schema,
		Revision:   1,
		PlanDigest: planDigest,
		Status:     StatusPrepared,
		UpdatedAt:  time.Now().Unix(),
	}

	stateDigest, err := writeEnvelopeExclusive(root, statePath(directory, initial.Revision), initial)
	if err != nil {
		return planEnvelope{}, stateEnvelope{}, err
	}

	for _, child := range []string{stateDirectoryName, uploadPartsDirectory, downloadBlocksDirectory, "."} {
		directoryPath := directory
		if child != "." {
			directoryPath = path.Join(directory, child)
		}

		if err := syncDirectory(root, directoryPath); err != nil {
			return planEnvelope{}, stateEnvelope{}, err
		}
	}

	return planEnvelope{record: plan, digest: planDigest}, stateEnvelope{record: initial, digest: stateDigest}, nil
}

func loadJournalAt(
	root *os.Root,
	journalID string,
) (loadedJournal, error) {
	var plan planRecord

	planDigest, err := readEnvelope(root, path.Join(journalID, planFileName), &plan)
	if errors.Is(err, fs.ErrNotExist) {
		return loadedJournal{}, ErrJournalNotFound
	}

	if err != nil {
		return loadedJournal{}, err
	}

	if validationErr := plan.validate(); validationErr != nil {
		return loadedJournal{}, fmt.Errorf("%w: %w", ErrJournalCorrupt, validationErr)
	}

	loadedPlan := planEnvelope{record: plan, digest: planDigest}

	state, err := loadStateChain(root, journalID, planDigest)
	if err != nil {
		return loadedJournal{}, err
	}

	if stateErr := validateStateForPlan(plan, state.record); stateErr != nil {
		return loadedJournal{}, stateErr
	}

	parts, err := loadUploadReceipts(root, journalID, planDigest)
	if err != nil {
		return loadedJournal{}, err
	}

	blocks, err := loadDownloadReceipts(root, journalID, planDigest)
	if err != nil {
		return loadedJournal{}, err
	}

	if progressErr := validateProgressForPlan(plan, parts, blocks); progressErr != nil {
		return loadedJournal{}, progressErr
	}

	return loadedJournal{
		plan:             loadedPlan,
		state:            state,
		uploadReceipts:   parts,
		downloadReceipts: blocks,
	}, nil
}

func validateStateForPlan(plan planRecord, state stateRecord) error {
	switch plan.Direction {
	case DirectionUpload:
		return validateUploadStateForPlan(plan.Upload, state)
	case DirectionDownload:
		if state.UploadSession != nil || len(state.CompletionParts) != 0 {
			return fmt.Errorf("%w: download contains upload recovery state", ErrJournalCorrupt)
		}

		if state.Status == StatusComplete && (plan.Download == nil || state.Object == nil ||
			*state.Object != plan.Download.Object) {
			return fmt.Errorf("%w: completed download object differs from its plan", ErrJournalCorrupt)
		}

		if state.Status != StatusComplete && state.Object != nil {
			return fmt.Errorf("%w: incomplete download contains a result object", ErrJournalCorrupt)
		}

		return nil
	default:
		return fmt.Errorf("%w: unknown plan direction", ErrJournalCorrupt)
	}
}

func validateUploadStateForPlan(plan *UploadPlan, state stateRecord) error {
	if plan == nil {
		return fmt.Errorf("%w: upload plan is missing", ErrJournalCorrupt)
	}

	if plan.Driver.Capabilities.Write.Resume.Available() {
		if err := validateResumableUploadState(plan, state); err != nil {
			return err
		}
	} else if err := validateCompleteUploadState(state); err != nil {
		return err
	}

	if state.Status == StatusComplete && (state.Object == nil ||
		state.Object.Locator.StorageKey != plan.StorageKey || state.Object.SizeBytes != plan.SizeBytes) {
		return fmt.Errorf("%w: completed upload object differs from its plan", ErrJournalCorrupt)
	}

	return nil
}

func validateCompleteUploadState(state stateRecord) error {
	if state.UploadSession != nil || len(state.CompletionParts) != 0 {
		return fmt.Errorf("%w: complete upload contains resumable state", ErrJournalCorrupt)
	}

	if state.Status == StatusVerifying && state.Object == nil {
		return fmt.Errorf("%w: verified complete upload lacks its object", ErrJournalCorrupt)
	}

	return nil
}

func validateResumableUploadState(plan *UploadPlan, state stateRecord) error {
	committed := state.Status == StatusVerifying || state.Status == StatusComplete
	if !committed && len(state.CompletionParts) != 0 {
		return fmt.Errorf("%w: upload completion manifest appears before commit", ErrJournalCorrupt)
	}

	if !committed {
		return nil
	}

	if state.UploadSession == nil {
		return fmt.Errorf("%w: resumable completion lacks a session", ErrJournalCorrupt)
	}

	ordered, err := orderedCompletionParts(plan.Parts, state.CompletionParts)
	if err != nil {
		return fmt.Errorf("%w: resumable completion manifest is invalid: %w", ErrJournalCorrupt, err)
	}

	if !slices.Equal(ordered, state.CompletionParts) {
		return fmt.Errorf("%w: resumable completion manifest is not canonical", ErrJournalCorrupt)
	}

	return nil
}

func validateProgressForPlan(
	plan planRecord,
	parts []uploadPartReceipt,
	blocks []downloadBlockReceipt,
) error {
	switch plan.Direction {
	case DirectionUpload:
		if len(blocks) != 0 || plan.Upload == nil {
			return fmt.Errorf("%w: upload journal contains invalid progress kind", ErrJournalCorrupt)
		}

		for _, receipt := range parts {
			if receipt.Part.Number > uint32(len(plan.Upload.Parts)) || //nolint:gosec // Plans are capped below uint32.
				receipt.Part != plan.Upload.Parts[receipt.Part.Number-1] {
				return fmt.Errorf("%w: upload receipt does not match immutable plan", ErrJournalCorrupt)
			}
		}

		return nil
	case DirectionDownload:
		if len(parts) != 0 || plan.Download == nil {
			return fmt.Errorf("%w: download journal contains invalid progress kind", ErrJournalCorrupt)
		}

		for _, receipt := range blocks {
			if receipt.Block.Number > uint32(len(plan.Download.Blocks)) { //nolint:gosec // Plans are capped below uint32.
				return fmt.Errorf("%w: download receipt exceeds immutable plan", ErrJournalCorrupt)
			}

			planned := plan.Download.Blocks[receipt.Block.Number-1]
			if receipt.Block.Number != planned.Number || receipt.Block.Offset != planned.Offset ||
				receipt.Block.Length != planned.Length {
				return fmt.Errorf("%w: download receipt does not match immutable plan", ErrJournalCorrupt)
			}
		}

		return nil
	default:
		return fmt.Errorf("%w: unknown progress direction", ErrJournalCorrupt)
	}
}

func loadStateChain(root *os.Root, journalID, planDigest string) (stateEnvelope, error) {
	directory := path.Join(journalID, stateDirectoryName)

	entries, err := fs.ReadDir(root.FS(), directory)
	if err != nil {
		return stateEnvelope{}, fmt.Errorf("%w: read state directory: %w", ErrJournalCorrupt, err)
	}

	if len(entries) == 0 {
		return stateEnvelope{}, fmt.Errorf("%w: state chain is empty", ErrJournalCorrupt)
	}

	previous := stateEnvelope{}

	for index, entry := range entries {
		revision, err := parseRevisionName(entry.Name())
		if err != nil || revision != uint64(index+1) {
			return stateEnvelope{}, fmt.Errorf("%w: state revision filenames are not contiguous", ErrJournalCorrupt)
		}

		var state stateRecord

		digest, err := readEnvelope(root, path.Join(directory, entry.Name()), &state)
		if err != nil {
			return stateEnvelope{}, err
		}

		if err := state.validate(planDigest, previous); err != nil {
			return stateEnvelope{}, err
		}

		previous = stateEnvelope{record: state, digest: digest}
	}

	return previous, nil
}

func loadUploadReceipts(
	root *os.Root,
	journalID,
	planDigest string,
) ([]uploadPartReceipt, error) {
	directory := path.Join(journalID, uploadPartsDirectory)

	entries, err := fs.ReadDir(root.FS(), directory)
	if err != nil {
		return nil, fmt.Errorf("%w: read upload receipts: %w", ErrJournalCorrupt, err)
	}

	receipts := make([]uploadPartReceipt, 0, len(entries))
	for _, entry := range entries {
		number, err := parseNumberName(entry.Name())
		if err != nil {
			return nil, err
		}

		var receipt uploadPartReceipt
		if _, err := readEnvelope(root, path.Join(directory, entry.Name()), &receipt); err != nil {
			return nil, err
		}

		if receipt.Schema != schema || receipt.PlanDigest != planDigest || receipt.Part.Number != number {
			return nil, fmt.Errorf("%w: upload receipt identity is invalid", ErrJournalCorrupt)
		}

		receipts = append(receipts, receipt)
	}

	return receipts, nil
}

func loadDownloadReceipts(
	root *os.Root,
	journalID,
	planDigest string,
) ([]downloadBlockReceipt, error) {
	directory := path.Join(journalID, downloadBlocksDirectory)

	entries, err := fs.ReadDir(root.FS(), directory)
	if err != nil {
		return nil, fmt.Errorf("%w: read download receipts: %w", ErrJournalCorrupt, err)
	}

	receipts := make([]downloadBlockReceipt, 0, len(entries))
	for _, entry := range entries {
		number, err := parseNumberName(entry.Name())
		if err != nil {
			return nil, err
		}

		var receipt downloadBlockReceipt
		if _, err := readEnvelope(root, path.Join(directory, entry.Name()), &receipt); err != nil {
			return nil, err
		}

		if receipt.Schema != schema || receipt.PlanDigest != planDigest || receipt.Block.Number != number ||
			validateSHA256(receipt.Block.Checksum) != nil {
			return nil, fmt.Errorf("%w: download receipt identity is invalid", ErrJournalCorrupt)
		}

		receipts = append(receipts, receipt)
	}

	return receipts, nil
}

func writeEnvelopeExclusive(root *os.Root, storagePath string, value any) (string, error) {
	encoded, digest, err := encodeEnvelope(value)
	if err != nil {
		return "", err
	}

	if int64(len(encoded)) > maximumRecordBytes {
		return "", fmt.Errorf("%w: record %q exceeds maximum size", ErrInvalidStore, storagePath)
	}

	file, err := root.OpenFile(storagePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", ErrJournalConflict
		}

		return "", fmt.Errorf("%w: create record %q: %w", ErrInvalidStore, storagePath, err)
	}

	if _, err := file.Write(encoded); err != nil {
		closeErr := file.Close()

		return "", fmt.Errorf("%w: write record %q: %w", ErrInvalidStore, storagePath, errors.Join(err, closeErr))
	}

	syncErr := file.Sync()

	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return "", fmt.Errorf("%w: persist record %q: %w", ErrInvalidStore, storagePath, errors.Join(syncErr, closeErr))
	}

	return digest, nil
}

func readEnvelope(root *os.Root, storagePath string, destination any) (string, error) {
	linkInformation, err := root.Lstat(storagePath)
	if err != nil {
		return "", fmt.Errorf("%w: inspect record %q: %w", ErrJournalCorrupt, storagePath, err)
	}

	if !linkInformation.Mode().IsRegular() || linkInformation.Size() <= 0 || linkInformation.Size() > maximumRecordBytes {
		return "", fmt.Errorf("%w: record %q has invalid file identity", ErrJournalCorrupt, storagePath)
	}

	file, err := root.Open(storagePath)
	if err != nil {
		return "", fmt.Errorf("%w: open record %q: %w", ErrJournalCorrupt, storagePath, err)
	}

	information, inspectErr := file.Stat()
	if inspectErr != nil || !information.Mode().IsRegular() || !os.SameFile(linkInformation, information) {
		closeErr := file.Close()

		return "", errors.Join(
			fmt.Errorf("%w: record %q has invalid file identity", ErrJournalCorrupt, storagePath),
			inspectErr,
			closeErr,
		)
	}

	encoded, readErr := io.ReadAll(file)

	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return "", fmt.Errorf("%w: read record %q: %w", ErrJournalCorrupt, storagePath, errors.Join(readErr, closeErr))
	}

	var envelope recordEnvelope
	if err := decodeStrictJSON(encoded, &envelope); err != nil {
		return "", fmt.Errorf("%w: decode record %q: %w", ErrJournalCorrupt, storagePath, err)
	}

	if envelope.Schema != schema || digestBytes(envelope.Payload) != envelope.Digest {
		return "", fmt.Errorf("%w: record %q digest differs", ErrJournalCorrupt, storagePath)
	}

	if err := decodeStrictJSON(envelope.Payload, destination); err != nil {
		return "", fmt.Errorf("%w: decode payload %q: %w", ErrJournalCorrupt, storagePath, err)
	}

	return envelope.Digest, nil
}

func encodeEnvelope(value any) ([]byte, string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, "", fmt.Errorf("encode journal payload: %w", err)
	}

	digest := digestBytes(payload)
	envelope := recordEnvelope{Schema: schema, Digest: digest, Payload: payload}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, "", fmt.Errorf("encode journal envelope: %w", err)
	}

	return append(encoded, '\n'), digest, nil
}

func decodeStrictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	var trailing json.RawMessage

	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("decode trailing JSON: %w", err)
	}

	return fmt.Errorf("%w: record contains trailing JSON", ErrJournalCorrupt)
}

func digestBytes(payload []byte) string {
	digest := sha256.Sum256(payload)

	return hex.EncodeToString(digest[:])
}

func randomIdentity() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("create journal identity: %w", err)
	}

	return hex.EncodeToString(randomBytes), nil
}

func statePath(directory string, revision uint64) string {
	return path.Join(directory, stateDirectoryName, fmt.Sprintf("%020d.json", revision))
}

func parseRevisionName(fileName string) (uint64, error) {
	numberText, found := strings.CutSuffix(fileName, ".json")
	if !found || len(numberText) != 20 {
		return 0, fmt.Errorf("%w: state filename is invalid", ErrJournalCorrupt)
	}

	revision, err := strconv.ParseUint(numberText, 10, 64)
	if err != nil || revision == 0 || statePath(".", revision) != path.Join(".", stateDirectoryName, fileName) {
		return 0, fmt.Errorf("%w: state filename is not canonical", ErrJournalCorrupt)
	}

	return revision, nil
}

func parseNumberName(fileName string) (uint32, error) {
	numberText, found := strings.CutSuffix(fileName, ".json")
	if !found || len(numberText) != 10 {
		return 0, fmt.Errorf("%w: progress receipt filename is invalid", ErrJournalCorrupt)
	}

	number, err := strconv.ParseUint(numberText, 10, 32)
	if err != nil || number == 0 || fmt.Sprintf("%010d.json", number) != fileName {
		return 0, fmt.Errorf("%w: progress receipt filename is not canonical", ErrJournalCorrupt)
	}

	return uint32(number), nil
}

func syncDirectory(root *os.Root, directoryPath string) error {
	directory, err := root.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("%w: open directory for sync: %w", ErrInvalidStore, err)
	}

	syncErr := directory.Sync()

	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("%w: sync directory: %w", ErrInvalidStore, errors.Join(syncErr, closeErr))
	}

	return nil
}

func snapshotFromRecords(
	plan planEnvelope,
	state stateEnvelope,
	parts []uploadPartReceipt,
	blocks []downloadBlockReceipt,
) Snapshot {
	snapshot := Snapshot{
		ID:             plan.record.ID,
		CreatedAt:      plan.record.CreatedAt,
		Direction:      plan.record.Direction,
		Status:         state.record.Status,
		Revision:       state.record.Revision,
		Upload:         cloneUploadPlan(plan.record.Upload),
		Download:       cloneDownloadPlan(plan.record.Download),
		UploadSession:  cloneUploadSession(state.record.UploadSession),
		Object:         cloneObject(state.record.Object),
		CompletedParts: make([]PlannedPart, 0, len(parts)),
		VerifiedBlocks: make([]VerifiedBlock, 0, len(blocks)),
	}

	for _, receipt := range parts {
		snapshot.CompletedParts = append(snapshot.CompletedParts, receipt.Part)
	}

	for _, receipt := range blocks {
		snapshot.VerifiedBlocks = append(snapshot.VerifiedBlocks, receipt.Block)
	}

	return snapshot
}

func cloneUploadPlan(plan *UploadPlan) *UploadPlan {
	if plan == nil {
		return nil
	}

	cloned := *plan
	cloned.Parts = slices.Clone(plan.Parts)
	cloned.Warnings = slices.Clone(plan.Warnings)

	return &cloned
}

func cloneDownloadPlan(plan *DownloadPlan) *DownloadPlan {
	if plan == nil {
		return nil
	}

	cloned := *plan
	cloned.Blocks = slices.Clone(plan.Blocks)
	cloned.Warnings = slices.Clone(plan.Warnings)

	return &cloned
}

func cloneUploadSession(session *driver.UploadSession) *driver.UploadSession {
	if session == nil {
		return nil
	}

	cloned := *session
	cloned.Opaque = slices.Clone(session.Opaque)

	return &cloned
}

func cloneObject(object *driver.Object) *driver.Object {
	if object == nil {
		return nil
	}

	cloned := *object

	return &cloned
}
