package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/transfer/journal"
	"github.com/dravengarden/carrack/vfs/cryptofile"
	"github.com/dravengarden/carrack/vfs/merkle"
)

const (
	defaultVFSVerificationBlockBytes = uint64(4 << 20)
	maximumVFSVerificationBlockBytes = uint64(256 << 20)
	vfsPutResultSchema               = "carrack.sdk.vfs-put-result.v1"
)

var (
	// ErrInvalidVFSClient indicates missing control, driver, or private state configuration.
	ErrInvalidVFSClient = errors.New("invalid Carrack VFS client")
	// ErrVFSPutIntegrity indicates that source, staging, provider, or control identities diverged.
	ErrVFSPutIntegrity  = errors.New("carrack VFS Put integrity mismatch")
	errVFSDirectoryPath = errors.New("vfs state directory must be canonical and absolute")
	errVFSDirectoryMode = errors.New("vfs state directory must be private and must not be a symlink")
)

// VFSClientOptions configures private local recovery state. Both directories
// must be canonical absolute paths and inaccessible to group or other users.
type VFSClientOptions struct {
	JournalDirectory string
	StagingDirectory string
	MaxConcurrency   uint32
	LeaseDuration    time.Duration
}

// VFSPutOptions fixes the destination, optimistic precondition, integrity
// layout, transfer requirements, and optional durable recovery journal for one
// file version.
type VFSPutOptions struct {
	DirectoryID            string
	EntryName              string
	ExpectedEntryRevision  uint64
	PreferredDriverID      string
	IdempotencyKey         string
	VerificationBlockBytes uint64
	EncryptionFrameBytes   uint64
	UploadPartBytes        uint64
	RequireResumable       bool
	RequireParallel        bool
	RequireStrongChecksum  bool
	ResumeJournalID        string
}

// VFSPutRecoveryError reports a durable upload journal that can be supplied as
// VFSPutOptions.ResumeJournalID after a transfer or commit failure.
type VFSPutRecoveryError struct {
	JournalID string
	Err       error
}

func (recovery *VFSPutRecoveryError) Error() string {
	if recovery == nil {
		return "carrack VFS Put recovery error"
	}

	return fmt.Sprintf("carrack VFS Put journal %s can be resumed: %v", recovery.JournalID, recovery.Err)
}

// Unwrap exposes the transfer, integrity, or control-plane cause.
func (recovery *VFSPutRecoveryError) Unwrap() error {
	if recovery == nil {
		return nil
	}

	return recovery.Err
}

// VFSPutResult identifies one published immutable file version and its durable
// local transfer journal. Warnings describe correctness-preserving degradation.
type VFSPutResult struct {
	Schema                string           `json:"schema"`
	Receipt               VFSPutReceipt    `json:"receipt"`
	JournalID             string           `json:"journal_id"`
	PlaintextBytes        uint64           `json:"plaintext_bytes"`
	FileRoot              string           `json:"file_root"`
	MetadataRoot          string           `json:"metadata_root"`
	CryptoSuite           string           `json:"crypto_suite"`
	EncryptionFrameBytes  uint64           `json:"encryption_frame_bytes"`
	Warnings              []driver.Warning `json:"warnings"`
	StagingCleanupWarning string           `json:"staging_cleanup_warning,omitempty"`
}

// VFSClient coordinates metadata calls, local transforms, compiled drivers,
// and the durable complete-object transfer journal.
type VFSClient struct {
	control     *VFSControlClient
	drivers     *driver.Registry
	engine      *journal.Engine
	stagingRoot string
}

// NewVFSClient validates and creates private journal and encoded-staging roots.
func NewVFSClient(
	control *VFSControlClient,
	drivers *driver.Registry,
	options VFSClientOptions,
) (*VFSClient, error) {
	if control == nil || control.control == nil || drivers == nil {
		return nil, fmt.Errorf("%w: control client and compiled driver registry are required", ErrInvalidVFSClient)
	}

	if err := ensurePrivateDirectory(options.StagingDirectory); err != nil {
		return nil, fmt.Errorf("%w: staging directory: %w", ErrInvalidVFSClient, err)
	}

	store, err := journal.NewStore(options.JournalDirectory)
	if err != nil {
		return nil, fmt.Errorf("%w: journal directory: %w", ErrInvalidVFSClient, err)
	}

	engine, err := journal.NewEngine(store, journal.EngineOptions{
		MaxConcurrency: options.MaxConcurrency,
		LeaseDuration:  options.LeaseDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: transfer engine: %w", ErrInvalidVFSClient, err)
	}

	return &VFSClient{
		control: control, drivers: drivers, engine: engine, stagingRoot: options.StagingDirectory,
	}, nil
}

// PutFile uploads one canonical local regular file into the VFS.
func (client *VFSClient) PutFile(
	ctx context.Context,
	filePath string,
	options VFSPutOptions,
) (VFSPutResult, error) {
	absolute, err := filepath.Abs(filePath)
	if err != nil {
		return VFSPutResult{}, fmt.Errorf("resolve VFS Put source: %w", err)
	}

	absolute = filepath.Clean(absolute)

	source, err := journal.NewFileSource(absolute)
	if err != nil {
		return VFSPutResult{}, fmt.Errorf("construct VFS file source: %w", err)
	}

	return client.Put(ctx, source, options)
}

// PutBytes copies and uploads one caller-owned in-memory byte sequence. The
// reference is an opaque journal identity; blank selects its SHA-256 identity.
func (client *VFSClient) PutBytes(
	ctx context.Context,
	reference string,
	payload []byte,
	options VFSPutOptions,
) (VFSPutResult, error) {
	return client.Put(ctx, journal.NewBytesSource(reference, payload), options)
}

// Put uploads any replayable exact-range source as one complete provider
// object, verifies its plaintext Merkle identity and encoded SHA-256, then
// conditionally publishes the VFS metadata.
func (client *VFSClient) Put(
	ctx context.Context,
	source journal.ReplayableSource,
	options VFSPutOptions,
) (VFSPutResult, error) {
	if err := client.validatePut(ctx, source, &options); err != nil {
		return VFSPutResult{}, err
	}

	tree, err := buildVFSSourceTree(ctx, source, options.VerificationBlockBytes)
	if err != nil {
		return VFSPutResult{}, err
	}

	blockManifest, err := merkle.MarshalFileBlockManifest(tree)
	if err != nil {
		return VFSPutResult{}, fmt.Errorf("marshal VFS block manifest: %w", err)
	}

	manifestDigest := sha256.Sum256(blockManifest)
	metadataRoot := merkle.EmptyMetadataRoot()

	var preferredDriverID *string

	if options.PreferredDriverID != "" {
		preferred := options.PreferredDriverID
		preferredDriverID = &preferred
	}

	preparation, err := client.control.PreparePut(ctx, PrepareVFSPutRequest{
		DirectoryID:            options.DirectoryID,
		EntryName:              options.EntryName,
		ExpectedEntryRevision:  options.ExpectedEntryRevision,
		PlaintextBytes:         tree.SizeBytes,
		VerificationBlockBytes: tree.BlockBytes,
		VerificationBlockCount: uint64(len(tree.Blocks)),
		FileRoot:               tree.Root.String(),
		MetadataRoot:           metadataRoot.String(),
		BlockManifestSHA256:    hex.EncodeToString(manifestDigest[:]),
		BlockManifestBytes:     uint64(len(blockManifest)),
		EncryptionFrameBytes:   options.EncryptionFrameBytes,
		PreferredDriverID:      preferredDriverID,
		IdempotencyKey:         options.IdempotencyKey,
	})
	if err != nil {
		return VFSPutResult{}, err
	}

	keyGrant, err := client.control.GrantPutKey(ctx, preparation)
	if err != nil {
		return VFSPutResult{}, err
	}
	defer keyGrant.Clear()

	driverGrant, err := client.control.GrantPutDriver(ctx, preparation)
	if err != nil {
		return VFSPutResult{}, err
	}
	defer driverGrant.Clear()

	handle, err := client.drivers.Open(ctx, driverGrant.Instance)
	if err != nil {
		return VFSPutResult{}, fmt.Errorf("open authorized VFS driver: %w", err)
	}

	driverGrant.Clear()

	staged, err := client.ensureEncodedStaging(ctx, source, tree, preparation, keyGrant)
	if err != nil {
		return VFSPutResult{}, err
	}

	manifestStage, err := client.control.StagePutBlockManifest(ctx, preparation, blockManifest)
	if err != nil {
		return VFSPutResult{}, err
	}

	planned, object, err := client.transferEncodedVFSObject(ctx, staged, preparation, handle, options)
	if err != nil {
		return VFSPutResult{}, vfsPutRecoveryError(planned.ID, err)
	}

	if object.SizeBytes != staged.encodedBytes || object.Locator.StorageKey != preparation.StorageKey {
		return VFSPutResult{}, &VFSPutRecoveryError{
			JournalID: planned.ID,
			Err:       fmt.Errorf("%w: provider object identity changed", ErrVFSPutIntegrity),
		}
	}

	verificationMethod := VFSVerificationCompleteReadback
	if handle.Descriptor.Capabilities.Integrity.StrongUploadChecksum.Available() {
		verificationMethod = VFSVerificationProviderChecksum
	}

	receipt, err := client.control.CommitPut(ctx, preparation, CommitVFSPutRequest{
		BlockManifestR2Version: manifestStage.R2Version,
		EncodedBytes:           staged.encodedBytes,
		EncodedSHA256:          staged.encodedSHA256,
		VerificationMethod:     verificationMethod,
		NativeID:               optionalVFSLocator(object.Locator.NativeID),
		ProviderVersion:        optionalVFSLocator(object.Locator.Version),
		ETag:                   optionalVFSLocator(object.Locator.ETag),
	})
	if err != nil {
		return VFSPutResult{}, &VFSPutRecoveryError{JournalID: planned.ID, Err: err}
	}

	result := VFSPutResult{
		Schema: vfsPutResultSchema, Receipt: receipt, JournalID: planned.ID,
		PlaintextBytes: tree.SizeBytes, FileRoot: tree.Root.String(), MetadataRoot: metadataRoot.String(),
		CryptoSuite: preparation.CryptoSuite, EncryptionFrameBytes: preparation.EncryptionFrameBytes,
	}
	if planned.Upload != nil {
		result.Warnings = append([]driver.Warning(nil), planned.Upload.Warnings...)
	}

	if err := removeDurableStaging(staged.path, client.stagingRoot); err != nil {
		result.StagingCleanupWarning = err.Error()
	}

	return result, nil
}

func vfsPutRecoveryError(journalID string, err error) error {
	if journalID == "" {
		return err
	}

	return &VFSPutRecoveryError{JournalID: journalID, Err: err}
}

func (client *VFSClient) transferEncodedVFSObject(
	ctx context.Context,
	staged encodedVFSStaging,
	preparation VFSPutPreparation,
	handle driver.Handle,
	options VFSPutOptions,
) (journal.Snapshot, driver.Object, error) {
	encodedSource, err := journal.NewFileSource(staged.path)
	if err != nil {
		return journal.Snapshot{}, driver.Object{}, fmt.Errorf("construct encoded VFS source: %w", err)
	}

	uploadOptions := journal.UploadOptions{
		PartBytes:             options.UploadPartBytes,
		RequireResumable:      options.RequireResumable,
		RequireParallel:       options.RequireParallel,
		RequireStrongChecksum: options.RequireStrongChecksum,
	}

	planned, err := client.prepareOrResumeVFSUpload(
		ctx,
		handle,
		encodedSource,
		staged,
		preparation,
		options.ResumeJournalID,
		uploadOptions,
	)
	if err != nil {
		return journal.Snapshot{}, driver.Object{}, fmt.Errorf("prepare VFS provider upload: %w", err)
	}

	object, err := client.engine.RunUpload(ctx, planned.ID, handle, encodedSource)
	if err != nil {
		return planned, driver.Object{}, fmt.Errorf("run VFS provider upload: %w", err)
	}

	return planned, object, nil
}

func (client *VFSClient) prepareOrResumeVFSUpload(
	ctx context.Context,
	handle driver.Handle,
	encodedSource journal.ReplayableSource,
	staged encodedVFSStaging,
	preparation VFSPutPreparation,
	resumeJournalID string,
	options journal.UploadOptions,
) (journal.Snapshot, error) {
	if resumeJournalID == "" {
		planned, err := client.engine.PrepareUpload(ctx, handle, encodedSource, preparation.StorageKey, options)
		if err != nil {
			return journal.Snapshot{}, fmt.Errorf("create VFS upload journal: %w", err)
		}

		return planned, nil
	}

	planned, err := client.engine.Inspect(resumeJournalID)
	if err != nil {
		return journal.Snapshot{}, fmt.Errorf("inspect requested VFS upload journal: %w", err)
	}

	if err := validateVFSUploadJournal(planned, staged, preparation, handle, options); err != nil {
		return journal.Snapshot{}, err
	}

	return planned, nil
}

func validateVFSUploadJournal(
	planned journal.Snapshot,
	staged encodedVFSStaging,
	preparation VFSPutPreparation,
	handle driver.Handle,
	options journal.UploadOptions,
) error {
	if planned.Direction != journal.DirectionUpload || planned.Upload == nil || planned.Status == journal.StatusAborted {
		return fmt.Errorf("%w: requested journal is not a viable upload", ErrVFSPutIntegrity)
	}

	upload := planned.Upload
	if upload.StorageKey != preparation.StorageKey || upload.SizeBytes != staged.encodedBytes ||
		upload.Checksum != staged.encodedSHA256 || upload.Source.Reference != staged.path ||
		upload.Source.SizeBytes != staged.encodedBytes || upload.Source.Checksum != staged.encodedSHA256 ||
		!reflect.DeepEqual(upload.Driver, handle.Descriptor) {
		return fmt.Errorf("%w: requested journal belongs to a different VFS object or driver", ErrVFSPutIntegrity)
	}

	if _, err := driver.Assess(upload.Driver, vfsUploadRequirements(options), nil); err != nil {
		return fmt.Errorf("requested journal violates current VFS transfer requirements: %w", err)
	}

	return nil
}

func vfsUploadRequirements(options journal.UploadOptions) []driver.Requirement {
	resume := driver.RequirementPreferred
	if options.RequireResumable {
		resume = driver.RequirementRequired
	}

	parallel := driver.RequirementPreferred
	if options.RequireParallel {
		parallel = driver.RequirementRequired
	}

	checksum := driver.RequirementPreferred
	if options.RequireStrongChecksum {
		checksum = driver.RequirementRequired
	}

	return []driver.Requirement{
		{Feature: driver.FeatureResumableWrite, Level: resume},
		{Feature: driver.FeatureParallelWrite, Level: parallel},
		{Feature: driver.FeatureStrongUploadChecksum, Level: checksum},
	}
}

func (client *VFSClient) validatePut(
	ctx context.Context,
	source journal.ReplayableSource,
	options *VFSPutOptions,
) error {
	if client == nil || client.control == nil || client.drivers == nil || client.engine == nil ||
		ctx == nil || source == nil || options == nil {
		return fmt.Errorf("%w: initialized client, context, source, and options are required", ErrInvalidVFSClient)
	}

	if options.VerificationBlockBytes == 0 {
		options.VerificationBlockBytes = defaultVFSVerificationBlockBytes
	}

	if options.EncryptionFrameBytes == 0 {
		options.EncryptionFrameBytes = options.VerificationBlockBytes
	}

	if options.VerificationBlockBytes > maximumVFSVerificationBlockBytes ||
		options.EncryptionFrameBytes > options.VerificationBlockBytes ||
		options.VerificationBlockBytes%options.EncryptionFrameBytes != 0 {
		return fmt.Errorf("%w: VFS verification block and encryption frame layout is invalid", ErrInvalidVFSClient)
	}

	if !validIdentifier(options.DirectoryID) || !validVFSName(options.EntryName) ||
		!validControlString(options.IdempotencyKey, 256) ||
		options.PreferredDriverID != "" && !validControlString(options.PreferredDriverID, 256) {
		return fmt.Errorf("%w: VFS destination or idempotency identity is invalid", ErrInvalidVFSClient)
	}

	return nil
}

type encodedVFSStaging struct {
	path          string
	encodedBytes  uint64
	encodedSHA256 string
}

func (client *VFSClient) ensureEncodedStaging(
	ctx context.Context,
	source journal.ReplayableSource,
	tree merkle.FileTree,
	preparation VFSPutPreparation,
	keyGrant VFSDirectoryKeyGrant,
) (encodedVFSStaging, error) {
	fileCipher, expectedBytes, err := vfsFileCipher(preparation, tree.SizeBytes, keyGrant)
	if err != nil {
		return encodedVFSStaging{}, err
	}

	finalPath := filepath.Join(client.stagingRoot, preparation.IntentID+".encoded")

	if existing, valid := verifyEncodedStaging(ctx, finalPath, tree, fileCipher, expectedBytes); valid {
		return existing, nil
	}

	if removeErr := removeUnsafeStaging(finalPath); removeErr != nil {
		return encodedVFSStaging{}, removeErr
	}

	return client.createEncodedStaging(ctx, source, tree, fileCipher, expectedBytes, finalPath, preparation.IntentID)
}

func (client *VFSClient) createEncodedStaging(
	ctx context.Context,
	source journal.ReplayableSource,
	tree merkle.FileTree,
	fileCipher *cryptofile.Cipher,
	expectedBytes uint64,
	finalPath,
	intentID string,
) (encodedVFSStaging, error) {
	temporary, err := os.CreateTemp(client.stagingRoot, "."+intentID+"-*.partial")
	if err != nil {
		return encodedVFSStaging{}, fmt.Errorf("create VFS encoded staging: %w", err)
	}

	temporaryPath := temporary.Name()
	removeTemporary := true

	defer func() {
		if removeTemporary {
			removeVFSBestEffort(temporaryPath)
		}
	}()

	encoded, err := writeEncodedVFSStaging(ctx, temporary, source, tree, fileCipher, expectedBytes)
	if err != nil {
		return encodedVFSStaging{}, err
	}

	if err := os.Link(temporaryPath, finalPath); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return encodedVFSStaging{}, fmt.Errorf("publish VFS encoded staging: %w", err)
		}

		if existing, valid := verifyEncodedStaging(ctx, finalPath, tree, fileCipher, expectedBytes); valid {
			return existing, nil
		}

		return encodedVFSStaging{}, fmt.Errorf("%w: concurrent VFS staging differs", ErrVFSPutIntegrity)
	}

	if err := syncVFSDirectory(client.stagingRoot); err != nil {
		return encodedVFSStaging{}, err
	}

	if err := os.Remove(temporaryPath); err != nil {
		return encodedVFSStaging{}, fmt.Errorf("remove linked VFS staging temporary: %w", err)
	}

	removeTemporary = false

	return encodedVFSStaging{
		path: finalPath, encodedBytes: encoded.encodedBytes, encodedSHA256: encoded.encodedSHA256,
	}, nil
}

func writeEncodedVFSStaging(
	ctx context.Context,
	temporary *os.File,
	source journal.ReplayableSource,
	tree merkle.FileTree,
	fileCipher *cryptofile.Cipher,
	expectedBytes uint64,
) (vfsEncodedIdentity, error) {
	before, err := source.Metadata(ctx)
	if err != nil {
		return vfsEncodedIdentity{}, errors.Join(
			fmt.Errorf("inspect VFS source before encoding: %w", err),
			temporary.Close(),
		)
	}

	if before.SizeBytes != tree.SizeBytes {
		return vfsEncodedIdentity{}, errors.Join(journal.ErrSourceChanged, temporary.Close())
	}

	stream, err := source.OpenRange(ctx, 0, tree.SizeBytes)
	if err != nil {
		return vfsEncodedIdentity{}, errors.Join(
			fmt.Errorf("open VFS source for encoding: %w", err),
			temporary.Close(),
		)
	}

	tracker, err := newVFSPlaintextTracker(tree.SizeBytes, tree.BlockBytes)
	if err != nil {
		return vfsEncodedIdentity{}, errors.Join(err, stream.Close(), temporary.Close())
	}

	encoded, transformErr := encodeVFSFile(ctx, temporary, io.TeeReader(stream, tracker), tree.SizeBytes, fileCipher)
	closeSourceErr := stream.Close()
	trackedTree, treeErr := tracker.Finish()
	syncErr := temporary.Sync()
	closeTemporaryErr := temporary.Close()

	after, metadataErr := source.Metadata(ctx)
	if transformErr != nil || closeSourceErr != nil || treeErr != nil || syncErr != nil ||
		closeTemporaryErr != nil || metadataErr != nil {
		return vfsEncodedIdentity{}, errors.Join(
			transformErr, closeSourceErr, treeErr, syncErr, closeTemporaryErr, metadataErr,
		)
	}

	if before != after || trackedTree.Root != tree.Root || trackedTree.TreeDigest != tree.TreeDigest ||
		encoded.encodedBytes != expectedBytes {
		return vfsEncodedIdentity{}, fmt.Errorf("%w: source changed during VFS encoding", ErrVFSPutIntegrity)
	}

	return encoded, nil
}

type vfsEncodedIdentity struct {
	encodedBytes  uint64
	encodedSHA256 string
}

func encodeVFSFile(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
	plaintextBytes uint64,
	fileCipher *cryptofile.Cipher,
) (vfsEncodedIdentity, error) {
	if fileCipher != nil {
		result, err := fileCipher.Seal(ctx, destination, source)
		if err != nil {
			return vfsEncodedIdentity{}, fmt.Errorf("seal VFS file: %w", err)
		}

		return vfsEncodedIdentity{
			encodedBytes: result.EncodedBytes, encodedSHA256: hex.EncodeToString(result.EncodedSHA256[:]),
		}, nil
	}

	hasher := sha256.New()

	written, err := io.CopyN(io.MultiWriter(destination, hasher), source, checkedVFSInt64(plaintextBytes))
	if err != nil || written != checkedVFSInt64(plaintextBytes) {
		return vfsEncodedIdentity{}, fmt.Errorf("%w: plaintext staging ended after %d bytes: %w", ErrVFSPutIntegrity, written, err)
	}

	if err := requireVFSEOF(source); err != nil {
		return vfsEncodedIdentity{}, err
	}

	return vfsEncodedIdentity{
		encodedBytes: plaintextBytes, encodedSHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func verifyEncodedStaging(
	ctx context.Context,
	filePath string,
	expectedTree merkle.FileTree,
	fileCipher *cryptofile.Cipher,
	expectedBytes uint64,
) (encodedVFSStaging, bool) {
	information, err := os.Lstat(filePath)
	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 ||
		information.Size() < 0 {
		return encodedVFSStaging{}, false
	}

	actualBytes := uint64(information.Size()) //nolint:gosec // Negative sizes are rejected above.
	if actualBytes != expectedBytes {
		return encodedVFSStaging{}, false
	}

	// #nosec G304 -- filePath is an intent-derived name inside the validated private staging root.
	file, err := os.Open(filePath)
	if err != nil {
		return encodedVFSStaging{}, false
	}

	tracker, err := newVFSPlaintextTracker(expectedTree.SizeBytes, expectedTree.BlockBytes)
	if err != nil {
		closeVFSBestEffort(file)

		return encodedVFSStaging{}, false
	}

	var identity vfsEncodedIdentity

	if fileCipher != nil {
		result, openErr := fileCipher.Open(ctx, tracker, file)
		if openErr != nil {
			closeVFSBestEffort(file)

			return encodedVFSStaging{}, false
		}

		identity = vfsEncodedIdentity{
			encodedBytes: result.EncodedBytes, encodedSHA256: hex.EncodeToString(result.EncodedSHA256[:]),
		}
	} else {
		hasher := sha256.New()

		written, copyErr := io.Copy(io.MultiWriter(tracker, hasher), file)
		if copyErr != nil {
			closeVFSBestEffort(file)

			return encodedVFSStaging{}, false
		}

		encodedBytes := uint64(written) //nolint:gosec // io.Copy never returns a negative byte count.
		identity = vfsEncodedIdentity{
			encodedBytes: encodedBytes, encodedSHA256: hex.EncodeToString(hasher.Sum(nil)),
		}
	}

	trackedTree, treeErr := tracker.Finish()

	closeErr := file.Close()
	if treeErr != nil || closeErr != nil || identity.encodedBytes != expectedBytes ||
		trackedTree.Root != expectedTree.Root || trackedTree.TreeDigest != expectedTree.TreeDigest {
		return encodedVFSStaging{}, false
	}

	return encodedVFSStaging{
		path: filePath, encodedBytes: identity.encodedBytes, encodedSHA256: identity.encodedSHA256,
	}, true
}

func vfsFileCipher(
	preparation VFSPutPreparation,
	plaintextBytes uint64,
	grant VFSDirectoryKeyGrant,
) (*cryptofile.Cipher, uint64, error) {
	switch preparation.CryptoSuite {
	case VFSPlaintextSuite:
		if grant.Key != nil {
			return nil, 0, fmt.Errorf("%w: plaintext preparation received a key", ErrVFSPutIntegrity)
		}

		return nil, plaintextBytes, nil
	case VFSEncryptedSuite:
		if grant.Key == nil {
			return nil, 0, fmt.Errorf("%w: encrypted preparation omitted its key", ErrVFSPutIntegrity)
		}

		directoryID, err := merkle.ParseIdentifier(preparation.DirectoryID)
		if err != nil {
			return nil, 0, fmt.Errorf("parse VFS directory identity: %w", err)
		}

		versionID, err := merkle.ParseIdentifier(preparation.VersionID)
		if err != nil {
			return nil, 0, fmt.Errorf("parse VFS version identity: %w", err)
		}

		descriptor := cryptofile.Descriptor{
			Suite: preparation.CryptoSuite, DirectoryID: directoryID, VersionID: versionID,
			KeyEpoch: preparation.KeyEpoch, FrameBytes: preparation.EncryptionFrameBytes,
			PlaintextBytes: plaintextBytes,
		}

		fileCipher, err := cryptofile.New(*grant.Key, descriptor)
		if err != nil {
			return nil, 0, fmt.Errorf("construct VFS file cipher: %w", err)
		}

		encodedBytes, err := descriptor.EncodedBytes()
		if err != nil {
			return nil, 0, fmt.Errorf("derive VFS encoded length: %w", err)
		}

		return fileCipher, encodedBytes, nil
	default:
		return nil, 0, fmt.Errorf("%w: unsupported VFS crypto suite %q", ErrVFSPutIntegrity, preparation.CryptoSuite)
	}
}

func buildVFSSourceTree(
	ctx context.Context,
	source journal.ReplayableSource,
	blockBytes uint64,
) (merkle.FileTree, error) {
	before, err := source.Metadata(ctx)
	if err != nil {
		return merkle.FileTree{}, fmt.Errorf("inspect VFS source before hashing: %w", err)
	}

	stream, err := source.OpenRange(ctx, 0, before.SizeBytes)
	if err != nil {
		return merkle.FileTree{}, fmt.Errorf("open VFS source for hashing: %w", err)
	}

	tree, buildErr := merkle.BuildFile(ctx, stream, before.SizeBytes, blockBytes)
	closeErr := stream.Close()

	after, metadataErr := source.Metadata(ctx)
	if buildErr != nil || closeErr != nil || metadataErr != nil {
		return merkle.FileTree{}, errors.Join(buildErr, closeErr, metadataErr)
	}

	if before != after {
		return merkle.FileTree{}, journal.ErrSourceChanged
	}

	return tree, nil
}

type vfsPlaintextTracker struct {
	sizeBytes     uint64
	blockBytes    uint64
	blockCapacity int
	written       uint64
	buffer        []byte
	blocks        []merkle.FileBlock
}

func newVFSPlaintextTracker(sizeBytes, blockBytes uint64) (*vfsPlaintextTracker, error) {
	if blockBytes == 0 || blockBytes > maximumVFSVerificationBlockBytes || blockBytes > math.MaxInt {
		return nil, fmt.Errorf("%w: unsafe VFS verification block size", ErrInvalidVFSClient)
	}

	blockCount := uint64(0)
	if sizeBytes > 0 {
		blockCount = 1 + (sizeBytes-1)/blockBytes
	}

	if blockCount > merkle.MaximumFileBlocks {
		return nil, fmt.Errorf("%w: VFS source exceeds verification block limit", ErrInvalidVFSClient)
	}

	blockCapacity := int(blockBytes)
	blockCountCapacity := int(blockCount)

	return &vfsPlaintextTracker{
		sizeBytes: sizeBytes, blockBytes: blockBytes, blockCapacity: blockCapacity,
		buffer: make([]byte, 0, blockCapacity),
		blocks: make([]merkle.FileBlock, 0, blockCountCapacity),
	}, nil
}

func (tracker *vfsPlaintextTracker) Write(payload []byte) (int, error) {
	if tracker == nil || tracker.written > tracker.sizeBytes || uint64(len(payload)) > tracker.sizeBytes-tracker.written {
		return 0, fmt.Errorf("%w: plaintext exceeds declared length", ErrVFSPutIntegrity)
	}

	originalBytes := len(payload)
	for len(payload) > 0 {
		available := tracker.blockCapacity - len(tracker.buffer)
		copied := min(available, len(payload))
		tracker.buffer = append(tracker.buffer, payload[:copied]...)
		payload = payload[copied:]
		copiedBytes := uint64(copied) //nolint:gosec // copied is a nonnegative slice length.

		tracker.written += copiedBytes
		if uint64(len(tracker.buffer)) == tracker.blockBytes {
			tracker.flushBlock()
		}
	}

	return originalBytes, nil
}

func (tracker *vfsPlaintextTracker) Finish() (merkle.FileTree, error) {
	if tracker == nil || tracker.written != tracker.sizeBytes {
		return merkle.FileTree{}, fmt.Errorf("%w: plaintext length differs", ErrVFSPutIntegrity)
	}

	if len(tracker.buffer) != 0 {
		tracker.flushBlock()
	}

	tree, err := merkle.RootFromFileBlocks(tracker.sizeBytes, tracker.blockBytes, tracker.blocks)
	if err != nil {
		return merkle.FileTree{}, fmt.Errorf("finish VFS plaintext tree: %w", err)
	}

	return tree, nil
}

func (tracker *vfsPlaintextTracker) flushBlock() {
	index := uint64(len(tracker.blocks))
	offset := index * tracker.blockBytes
	tracker.blocks = append(tracker.blocks, merkle.FileBlock{
		Index: index, Offset: offset, SizeBytes: uint64(len(tracker.buffer)),
		Digest: merkle.HashFileBlock(index, tracker.buffer),
	})
	tracker.buffer = tracker.buffer[:0]
}

func ensurePrivateDirectory(directory string) error {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errVFSDirectoryPath
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	information, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect directory: %w", err)
	}

	if !information.IsDir() || information.Mode()&fs.ModeSymlink != 0 || information.Mode().Perm()&0o077 != 0 {
		return errVFSDirectoryMode
	}

	return nil
}

func removeUnsafeStaging(filePath string) error {
	information, err := os.Lstat(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("inspect existing VFS staging: %w", err)
	}

	if !information.Mode().IsRegular() || information.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: existing VFS staging is not a regular file", ErrVFSPutIntegrity)
	}

	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("remove invalid VFS staging: %w", err)
	}

	return nil
}

func removeDurableStaging(filePath, directory string) error {
	if err := os.Remove(filePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove published VFS staging: %w", err)
	}

	return syncVFSDirectory(directory)
}

func syncVFSDirectory(directory string) error {
	// #nosec G304 -- directory is a validated private client-state root.
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open VFS staging directory: %w", err)
	}

	syncErr := handle.Sync()

	closeErr := handle.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync VFS staging directory: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func optionalVFSLocator(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

func requireVFSEOF(reader io.Reader) error {
	var extra [1]byte

	readBytes, err := reader.Read(extra[:])
	if readBytes != 0 || err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: source has trailing bytes: %w", ErrVFSPutIntegrity, err)
	}

	return nil
}

func checkedVFSInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		panic("VFS byte count exceeds validated int64 range")
	}

	return int64(value)
}

func removeVFSBestEffort(filePath string) {
	if err := os.Remove(filePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return
	}
}

func closeVFSBestEffort(closer io.Closer) {
	if err := closer.Close(); err != nil {
		return
	}
}
