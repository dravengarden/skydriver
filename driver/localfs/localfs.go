package localfs

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
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dravengarden/carrack/driver"
)

const (
	// Kind identifies the first Carrack VFS V2 rooted-filesystem contract.
	Kind driver.Kind = "local-filesystem/v2"

	safeConcurrency      = uint32(16)
	maximumObjectBytes   = uint64(math.MaxInt64 - (1 << 20))
	preferredPartBytes   = uint64(64 << 20)
	maximumInventoryPage = uint32(1000)

	privateFileMode      = fs.FileMode(0o600)
	privateDirectoryMode = fs.FileMode(0o700)
	temporaryAttempts    = 8
	randomIdentityBytes  = 16

	internalRoot       = ".carrack"
	uploadsRoot        = internalRoot + "/uploads"
	completedRoot      = internalRoot + "/completed"
	sessionRecordName  = "session.json"
	sessionPartsName   = "parts"
	sessionSealName    = "sealed"
	recordVersion      = uint32(1)
	maximumRecordBytes = int64(16 << 10)

	uploadTemporaryPrefix = ".carrack-upload-"
	deleteTemporaryPrefix = ".carrack-delete-"
	partTemporaryPrefix   = ".carrack-part-"
)

var (
	// ErrInvalidConfiguration indicates an unusable local filesystem root or
	// missing driver identity.
	ErrInvalidConfiguration = errors.New("invalid Carrack V2 local filesystem configuration")
	// ErrInvalidObject indicates an unsafe key, unsupported filesystem entry, or
	// malformed pinned object identity.
	ErrInvalidObject = errors.New("invalid Carrack V2 local filesystem object")
	// ErrInvalidRange indicates an empty, overflowing, or out-of-bounds range.
	ErrInvalidRange = errors.New("invalid Carrack V2 local filesystem range")
	// ErrIntegrity indicates bytes or immutable identity differ from a declared
	// SHA-256 digest, length, or provider version.
	ErrIntegrity = errors.New("carrack V2 local filesystem integrity mismatch")
	// ErrInvalidUpload indicates a malformed or contradictory upload request.
	ErrInvalidUpload = errors.New("invalid Carrack V2 local filesystem upload")
	// ErrUploadNotFound indicates that no active or completed durable session has
	// the supplied opaque session identity.
	ErrUploadNotFound = errors.New("carrack V2 local filesystem upload not found")
	// ErrUploadSealed indicates that completion or abort has made a session
	// immutable; callers must recover completion or begin another session.
	ErrUploadSealed = errors.New("carrack V2 local filesystem upload is sealed")
	// ErrUploadCompleted indicates that ListParts was called after the final
	// object had already been published. CompleteUpload remains replayable.
	ErrUploadCompleted = errors.New("carrack V2 local filesystem upload is complete")

	errInventoryPageFull = errors.New("local filesystem inventory page is full")
)

// Client stores complete immutable Carrack objects beneath one rooted local
// directory. The root is reopened for every operation, so a Client is safe for
// concurrent use and does not retain filesystem descriptors or credentials.
type Client struct {
	rootPath string
}

// Open validates an existing canonical absolute root and returns a fully
// documented V2 handle. Resumable and parallel parts are emulated in local
// staging; range reads and final no-replace publication are native filesystem
// operations. Server-side copy is unavailable and capability assessment will
// recommend complete-object streaming instead.
func Open(driverID, rootPath string) (driver.Handle, error) {
	if strings.TrimSpace(driverID) == "" {
		return driver.Handle{}, fmt.Errorf("%w: driver ID is required", ErrInvalidConfiguration)
	}

	client, err := NewClient(rootPath)
	if err != nil {
		return driver.Handle{}, err
	}

	handle := driver.Handle{
		Descriptor: driver.Descriptor{
			ID:      driverID,
			Kind:    Kind,
			Summary: "rooted local filesystem with atomic complete objects and emulated resumable parts",
			Capabilities: driver.Capabilities{
				Read: driver.ReadCapabilities{
					Complete:          driver.SupportNative,
					Range:             driver.SupportNative,
					MaxParallelRanges: safeConcurrency,
					MaximumRangeBytes: maximumObjectBytes,
				},
				Write: driver.WriteCapabilities{
					Complete:                 driver.SupportNative,
					Resume:                   driver.SupportEmulated,
					ParallelParts:            driver.SupportEmulated,
					PartOrdering:             driver.PartOrderingArbitrary,
					MaxParallelParts:         safeConcurrency,
					MinimumNonFinalPartBytes: 1,
					MaximumPartBytes:         maximumObjectBytes,
					MaximumParts:             math.MaxUint32,
				},
				Delete:         driver.SupportNative,
				Inventory:      driver.SupportNative,
				ServerSideCopy: driver.SupportUnavailable,
				Integrity: driver.IntegrityCapabilities{
					StrongUploadChecksum: driver.SupportEmulated,
					Algorithms:           []driver.ChecksumAlgorithm{"sha256"},
					RequiresReadback:     false,
				},
				MaximumObjectBytes: maximumObjectBytes,
				PreferredPartBytes: preferredPartBytes,
				SafeConcurrency:    safeConcurrency,
			},
		},
		Reader:          client,
		RangeReader:     client,
		Writer:          client,
		ResumableWriter: client,
		Deleter:         client,
		Inventory:       client,
	}

	if err := handle.Validate(); err != nil {
		return driver.Handle{}, fmt.Errorf("open local filesystem driver: %w", err)
	}

	return handle, nil
}

// NewClient validates an existing canonical absolute directory. Callers that
// need planning warnings should prefer Open and retain its descriptor.
func NewClient(rootPath string) (*Client, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, fmt.Errorf("%w: root must be a canonical absolute path", ErrInvalidConfiguration)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open root: %w", ErrInvalidConfiguration, err)
	}

	information, inspectErr := root.Stat(".")

	closeErr := root.Close()
	if inspectErr != nil || closeErr != nil {
		return nil, fmt.Errorf("%w: inspect root: %w", ErrInvalidConfiguration, errors.Join(inspectErr, closeErr))
	}

	if !information.IsDir() {
		return nil, fmt.Errorf("%w: root is not a directory", ErrInvalidConfiguration)
	}

	return &Client{rootPath: rootPath}, nil
}

func (client *Client) openRoot() (*os.Root, error) {
	if client == nil || client.rootPath == "" {
		return nil, fmt.Errorf("%w: client is not initialized", ErrInvalidConfiguration)
	}

	root, err := os.OpenRoot(client.rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: reopen root: %w", ErrInvalidConfiguration, err)
	}

	return root, nil
}

func validateStorageKey(storageKey string) error {
	if storageKey == "." || !fs.ValidPath(storageKey) || strings.Contains(storageKey, "\\") {
		return fmt.Errorf("%w: storage key must be a canonical relative slash path", ErrInvalidObject)
	}

	first, _, _ := strings.Cut(storageKey, "/")
	if first == internalRoot || hasInternalBaseName(storageKey) {
		return fmt.Errorf("%w: storage key uses a reserved local filesystem name", ErrInvalidObject)
	}

	return nil
}

func hasInternalBaseName(storageKey string) bool {
	for segment := range strings.SplitSeq(storageKey, "/") {
		if strings.HasPrefix(segment, uploadTemporaryPrefix) ||
			strings.HasPrefix(segment, deleteTemporaryPrefix) ||
			strings.HasPrefix(segment, partTemporaryPrefix) {
			return true
		}
	}

	return false
}

func validateChecksum(checksum string) ([]byte, error) {
	digest, err := hex.DecodeString(checksum)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != checksum {
		return nil, fmt.Errorf("%w: SHA-256 must be 64 lowercase hexadecimal characters", ErrIntegrity)
	}

	return digest, nil
}

func validateObject(object driver.Object) ([]byte, error) {
	if err := validateStorageKey(object.Locator.StorageKey); err != nil {
		return nil, err
	}

	if object.SizeBytes > maximumObjectBytes {
		return nil, fmt.Errorf("%w: object exceeds local filesystem size limit", ErrInvalidObject)
	}

	digest, err := validateChecksum(object.Locator.ETag)
	if err != nil {
		return nil, err
	}

	version := "sha256:" + object.Locator.ETag
	if object.Locator.Version != version || object.Locator.NativeID != version {
		return nil, fmt.Errorf("%w: local object identity fields disagree", ErrInvalidObject)
	}

	return digest, nil
}

func objectIdentity(storageKey string, sizeBytes uint64, checksum string) driver.Object {
	version := "sha256:" + checksum

	return driver.Object{
		Locator: driver.Locator{
			StorageKey: storageKey,
			NativeID:   version,
			Version:    version,
			ETag:       checksum,
		},
		SizeBytes: sizeBytes,
	}
}

func objectsEqual(left, right driver.Object) bool {
	return left == right
}

func createRandomFile(root *os.Root, parent, prefix string) (string, *os.File, error) {
	for range temporaryAttempts {
		identity, err := randomIdentity()
		if err != nil {
			return "", nil, err
		}

		storageKey := path.Join(parent, prefix+identity)

		file, openErr := root.OpenFile(storageKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
		if openErr == nil {
			return storageKey, file, nil
		}

		if !errors.Is(openErr, fs.ErrExist) {
			return "", nil, fmt.Errorf("%w: create temporary file: %w", ErrInvalidObject, openErr)
		}
	}

	return "", nil, fmt.Errorf("%w: exhaust temporary names", ErrInvalidObject)
}

func randomIdentity() (string, error) {
	randomBytes := make([]byte, randomIdentityBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("create local filesystem random identity: %w", err)
	}

	return hex.EncodeToString(randomBytes), nil
}

func syncDirectoryChain(root *os.Root, parent string) error {
	directories := []string{"."}
	current := ""

	if parent != "." {
		for segment := range strings.SplitSeq(parent, "/") {
			current = path.Join(current, segment)
			directories = append(directories, current)
		}
	}

	for _, directoryPath := range slices.Backward(directories) {
		directory, err := root.Open(directoryPath)
		if err != nil {
			return fmt.Errorf("open local filesystem directory for sync: %w", err)
		}

		syncErr := directory.Sync()

		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return fmt.Errorf("sync local filesystem directory: %w", errors.Join(syncErr, closeErr))
		}
	}

	return nil
}

func writeJSONFile(file *os.File, value any) error {
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(value); err != nil {
		closeErr := file.Close()

		return fmt.Errorf("encode local filesystem record: %w", errors.Join(err, closeErr))
	}

	syncErr := file.Sync()

	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("persist local filesystem record: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func readJSONFile(root *os.Root, storageKey string, destination any) error {
	file, information, err := openRegularAt(root, storageKey)
	if err != nil {
		return fmt.Errorf("open local filesystem record %q: %w", storageKey, err)
	}

	if information.Size() > maximumRecordBytes {
		closeErr := file.Close()

		return errors.Join(
			fmt.Errorf("%w: record %q exceeds size limit", ErrIntegrity, storageKey),
			closeErr,
		)
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	decodeErr := decoder.Decode(destination)
	if decodeErr == nil {
		decodeErr = rejectTrailingJSON(decoder)
	}

	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil {
		return fmt.Errorf("decode local filesystem record %q: %w", storageKey, errors.Join(decodeErr, closeErr))
	}

	return nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing json.RawMessage

	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("record contains invalid trailing JSON: %w", err)
	}

	return fmt.Errorf("%w: record contains trailing JSON", ErrIntegrity)
}

func openRegularAt(root *os.Root, storageKey string) (*os.File, fs.FileInfo, error) {
	linkInformation, err := root.Lstat(storageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: inspect %q: %w", ErrInvalidObject, storageKey, err)
	}

	if !linkInformation.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %q is not a regular file", ErrInvalidObject, storageKey)
	}

	file, err := root.Open(storageKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open %q: %w", ErrInvalidObject, storageKey, err)
	}

	information, inspectErr := file.Stat()
	if inspectErr != nil || !information.Mode().IsRegular() || !os.SameFile(linkInformation, information) {
		closeErr := file.Close()
		if inspectErr != nil {
			return nil, nil, errors.Join(
				fmt.Errorf("%w: inspect opened %q: %w", ErrInvalidObject, storageKey, inspectErr),
				closeErr,
			)
		}

		return nil, nil, errors.Join(
			fmt.Errorf("%w: %q changed while being opened", ErrIntegrity, storageKey),
			closeErr,
		)
	}

	return file, information, nil
}

type contextReader struct {
	cancellation func() error
	reader       io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.cancellation(); err != nil {
		return 0, fmt.Errorf("read local filesystem payload: %w", err)
	}

	readBytes, err := reader.reader.Read(buffer)
	if err == nil {
		return readBytes, nil
	}

	if errors.Is(err, io.EOF) {
		return readBytes, io.EOF
	}

	return readBytes, fmt.Errorf("read local filesystem payload: %w", err)
}

func checkedInt64(value uint64) int64 {
	return int64(value) //nolint:gosec // All callers reject values above maximumObjectBytes.
}

func checkedFileSize(information fs.FileInfo) (uint64, error) {
	if information.Size() < 0 {
		return 0, fmt.Errorf("%w: regular file has negative size", ErrInvalidObject)
	}

	return uint64(information.Size()), nil //nolint:gosec // A negative size is rejected immediately above.
}

func bytesEqual(left, right []byte) bool {
	return bytes.Equal(left, right)
}

var (
	_ driver.Reader          = (*Client)(nil)
	_ driver.RangeReader     = (*Client)(nil)
	_ driver.Writer          = (*Client)(nil)
	_ driver.ResumableWriter = (*Client)(nil)
	_ driver.Deleter         = (*Client)(nil)
	_ driver.Inventory       = (*Client)(nil)
)
