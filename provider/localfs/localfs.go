// Package localfs implements rooted local filesystem payload storage.
package localfs

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
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dravengarden/carrack/provider"
)

const (
	// DriverKind identifies the initial rooted local filesystem contract.
	DriverKind           provider.DriverKind = "local-filesystem/v1"
	safeConcurrency                          = uint32(8)
	maximumObjectBytes                       = uint64(math.MaxInt64)
	uploadFileMode                           = fs.FileMode(0o600)
	uploadDirectoryMode                      = fs.FileMode(0o700)
	temporaryAttempts                        = 4
	temporaryRandomBytes                     = 16
)

var (
	// ErrInvalidConfiguration indicates an unusable local filesystem root.
	ErrInvalidConfiguration = errors.New("invalid Carrack local filesystem configuration")
	// ErrInvalidObject indicates an unsafe key or unsupported filesystem object.
	ErrInvalidObject = errors.New("invalid Carrack local filesystem object")
	// ErrInvalidRange indicates an empty, overflowing, or out-of-bounds read.
	ErrInvalidRange = errors.New("invalid Carrack local filesystem range")
	// ErrIntegrity indicates that immutable object bytes differ from their declaration.
	ErrIntegrity = errors.New("carrack local filesystem integrity mismatch")
)

// DriverConfig contains non-secret local filesystem configuration.
type DriverConfig struct {
	Root string `json:"root"`
}

// Factory opens rooted local filesystem readers and writers.
type Factory struct{}

// Kind returns the versioned local filesystem driver kind.
func (Factory) Kind() provider.DriverKind { return DriverKind }

// Open validates the configured root and creates a local filesystem client.
func (Factory) Open(
	_ context.Context,
	specification provider.DriverSpec,
	_ provider.Dependencies,
) (provider.Handle, error) {
	configuration, err := decodeConfiguration(specification.Config)
	if err != nil {
		return provider.Handle{}, err
	}

	client, err := NewClient(configuration.Root)
	if err != nil {
		return provider.Handle{}, err
	}

	return provider.Handle{
		ID: specification.ID, Kind: DriverKind,
		Capabilities: provider.Capabilities{
			RangeRead: true, StreamingWrite: true,
			MaximumObjectBytes: maximumObjectBytes, PreferredObjectBytes: 1 << 30,
			SafeConcurrency: safeConcurrency,
		},
		Reader: client, Writer: client,
	}, nil
}

// Client reads and atomically writes immutable objects beneath one root.
type Client struct {
	rootPath string
}

// NewClient validates an existing canonical absolute directory without retaining a descriptor.
func NewClient(rootPath string) (*Client, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, fmt.Errorf(
			"%w: root must be a canonical absolute path",
			ErrInvalidConfiguration,
		)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open root: %w", ErrInvalidConfiguration, err)
	}

	if err := root.Close(); err != nil {
		return nil, fmt.Errorf("%w: close root: %w", ErrInvalidConfiguration, err)
	}

	return &Client{rootPath: rootPath}, nil
}

// Stat hashes one regular file to provide a content-derived immutable identity.
func (client *Client) Stat(ctx context.Context, key string) (provider.Object, error) {
	if err := validateKey(key); err != nil {
		return provider.Object{}, err
	}

	root, err := client.openRoot()
	if err != nil {
		return provider.Object{}, err
	}

	object, statErr := statObject(ctx, root, key)

	closeErr := root.Close()
	if statErr != nil || closeErr != nil {
		return provider.Object{}, errors.Join(statErr, closeErr)
	}

	return object, nil
}

// OpenRange opens exactly one bounded range from a regular file.
func (client *Client) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	if length == 0 || offset > maximumObjectBytes || length > maximumObjectBytes {
		return nil, fmt.Errorf("%w: range is empty or exceeds local file limits", ErrInvalidRange)
	}

	root, err := client.openRoot()
	if err != nil {
		return nil, err
	}

	file, openErr := root.Open(key)

	closeRootErr := root.Close()
	if openErr != nil || closeRootErr != nil {
		var closeFileErr error
		if file != nil {
			closeFileErr = file.Close()
		}

		return nil, fmt.Errorf(
			"%w: open %q: %w",
			ErrInvalidObject,
			key,
			errors.Join(openErr, closeRootErr, closeFileErr),
		)
	}

	information, statErr := file.Stat()
	if statErr != nil {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: inspect %q: %w", ErrInvalidObject, key, statErr),
			closeErr,
		)
	}

	if !information.Mode().IsRegular() {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: %q is not a regular file", ErrInvalidObject, key),
			closeErr,
		)
	}

	fileBytes, sizeErr := checkedFileSize(information)
	if sizeErr != nil {
		closeErr := file.Close()

		return nil, errors.Join(sizeErr, closeErr)
	}

	if offset > fileBytes || length > fileBytes-offset {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf(
				"%w: range [%d,%d) exceeds %d-byte object",
				ErrInvalidRange,
				offset,
				offset+length,
				fileBytes,
			),
			closeErr,
		)
	}

	return &rangeReadCloser{
		cancellation: ctx.Err, file: file,
		reader: io.NewSectionReader(file, checkedInt64(offset), checkedInt64(length)),
	}, nil
}

// Put validates and atomically publishes one immutable regular file.
func (client *Client) Put(
	ctx context.Context,
	key string,
	body io.Reader,
	options provider.PutOptions,
) (provider.Object, error) {
	if err := validateKey(key); err != nil {
		return provider.Object{}, err
	}

	expectedDigest, err := validatePut(body, options)
	if err != nil {
		return provider.Object{}, err
	}

	root, err := client.openRoot()
	if err != nil {
		return provider.Object{}, err
	}

	object, putErr := putObject(ctx, root, key, body, options.SizeBytes, expectedDigest)

	closeErr := root.Close()
	if putErr != nil || closeErr != nil {
		return provider.Object{}, errors.Join(putErr, closeErr)
	}

	return object, nil
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

func decodeConfiguration(encoded json.RawMessage) (DriverConfig, error) {
	var configuration DriverConfig

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&configuration); err != nil {
		return DriverConfig{}, fmt.Errorf("decode local filesystem config: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return DriverConfig{}, fmt.Errorf("decode local filesystem config trailing data: %w", err)
	}

	return configuration, nil
}

func validateKey(key string) error {
	if key == "." || !fs.ValidPath(key) || strings.Contains(key, "\\") {
		return fmt.Errorf(
			"%w: object key must be a canonical relative slash path",
			ErrInvalidObject,
		)
	}

	return nil
}

func validatePut(body io.Reader, options provider.PutOptions) ([]byte, error) {
	if body == nil {
		return nil, fmt.Errorf("%w: upload body is required", ErrInvalidObject)
	}

	if options.SizeBytes == 0 || options.SizeBytes > maximumObjectBytes {
		return nil, fmt.Errorf("%w: upload size is empty or exceeds local file limits", ErrInvalidObject)
	}

	digest, err := hex.DecodeString(options.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != options.SHA256 {
		return nil, fmt.Errorf("%w: SHA-256 must be 64 lowercase hexadecimal characters", ErrIntegrity)
	}

	return digest, nil
}

func statObject(ctx context.Context, root *os.Root, key string) (provider.Object, error) {
	file, err := root.Open(key)
	if err != nil {
		return provider.Object{}, fmt.Errorf("%w: open %q: %w", ErrInvalidObject, key, err)
	}

	object, inspectErr := inspectObject(ctx, file, key)

	closeErr := file.Close()
	if inspectErr != nil || closeErr != nil {
		return provider.Object{}, errors.Join(inspectErr, closeErr)
	}

	return object, nil
}

func inspectObject(ctx context.Context, file *os.File, key string) (provider.Object, error) {
	before, err := file.Stat()
	if err != nil {
		return provider.Object{}, fmt.Errorf("%w: inspect %q: %w", ErrInvalidObject, key, err)
	}

	if !before.Mode().IsRegular() {
		return provider.Object{}, fmt.Errorf("%w: %q is not a regular file", ErrInvalidObject, key)
	}

	hasher := sha256.New()

	written, err := io.Copy(hasher, &contextReader{cancellation: ctx.Err, reader: file})
	if err != nil {
		return provider.Object{}, fmt.Errorf("%w: hash %q: %w", ErrInvalidObject, key, err)
	}

	after, err := file.Stat()
	if err != nil {
		return provider.Object{}, fmt.Errorf("%w: reinspect %q: %w", ErrInvalidObject, key, err)
	}

	if written != before.Size() || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, after) {
		return provider.Object{}, fmt.Errorf("%w: %q changed while being hashed", ErrIntegrity, key)
	}

	digest := hex.EncodeToString(hasher.Sum(nil))

	sizeBytes, err := checkedFileSize(before)
	if err != nil {
		return provider.Object{}, err
	}

	return objectIdentity(key, sizeBytes, digest), nil
}

func putObject(
	ctx context.Context,
	root *os.Root,
	key string,
	body io.Reader,
	sizeBytes uint64,
	expectedDigest []byte,
) (provider.Object, error) {
	if _, err := root.Lstat(key); err == nil {
		return verifyExisting(ctx, root, key, sizeBytes, expectedDigest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return provider.Object{}, fmt.Errorf("%w: inspect destination %q: %w", ErrInvalidObject, key, err)
	}

	parent := path.Dir(key)
	if err := root.MkdirAll(parent, uploadDirectoryMode); err != nil {
		return provider.Object{}, fmt.Errorf("%w: create parent for %q: %w", ErrInvalidObject, key, err)
	}

	temporaryKey, temporary, err := createTemporary(root, parent)
	if err != nil {
		return provider.Object{}, err
	}

	if err := writeTemporary(ctx, temporary, body, sizeBytes, expectedDigest); err != nil {
		removeErr := root.Remove(temporaryKey)

		return provider.Object{}, errors.Join(err, removeErr)
	}

	if err := root.Link(temporaryKey, key); err != nil {
		removeErr := root.Remove(temporaryKey)
		if errors.Is(err, fs.ErrExist) {
			existing, verifyErr := verifyExisting(ctx, root, key, sizeBytes, expectedDigest)

			return existing, errors.Join(verifyErr, removeErr)
		}

		return provider.Object{}, fmt.Errorf(
			"%w: publish %q: %w",
			ErrInvalidObject,
			key,
			errors.Join(err, removeErr),
		)
	}

	removeErr := root.Remove(temporaryKey)

	syncErr := syncDirectoryChain(root, parent)
	if removeErr != nil || syncErr != nil {
		return provider.Object{}, fmt.Errorf(
			"%w: finalize %q: %w",
			ErrInvalidObject,
			key,
			errors.Join(removeErr, syncErr),
		)
	}

	digest := hex.EncodeToString(expectedDigest)

	return objectIdentity(key, sizeBytes, digest), nil
}

func createTemporary(root *os.Root, parent string) (string, *os.File, error) {
	for range temporaryAttempts {
		randomBytes := make([]byte, temporaryRandomBytes)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", nil, fmt.Errorf("create local filesystem upload identity: %w", err)
		}

		key := path.Join(parent, ".carrack-upload-"+hex.EncodeToString(randomBytes))

		file, err := root.OpenFile(key, os.O_WRONLY|os.O_CREATE|os.O_EXCL, uploadFileMode)
		if err == nil {
			return key, file, nil
		}

		if !errors.Is(err, fs.ErrExist) {
			return "", nil, fmt.Errorf("%w: create upload temporary file: %w", ErrInvalidObject, err)
		}
	}

	return "", nil, fmt.Errorf("%w: exhaust upload temporary names", ErrInvalidObject)
}

func writeTemporary(
	ctx context.Context,
	file *os.File,
	body io.Reader,
	sizeBytes uint64,
	expectedDigest []byte,
) error {
	hasher := sha256.New()
	reader := &contextReader{cancellation: ctx.Err, reader: body}
	declaredBytes := checkedInt64(sizeBytes)

	written, copyErr := io.CopyN(io.MultiWriter(file, hasher), reader, declaredBytes)
	if copyErr != nil || written != declaredBytes {
		closeErr := file.Close()

		return fmt.Errorf(
			"%w: upload body ended after %d of %d bytes: %w",
			ErrIntegrity,
			written,
			sizeBytes,
			errors.Join(copyErr, closeErr),
		)
	}

	var extra [1]byte

	extraBytes, extraErr := io.ReadFull(reader, extra[:])
	if extraBytes != 0 || extraErr != nil && !errors.Is(extraErr, io.EOF) {
		closeErr := file.Close()

		return errors.Join(
			fmt.Errorf("%w: upload body exceeds declared size or cannot be completed", ErrIntegrity),
			extraErr,
			closeErr,
		)
	}

	if !bytes.Equal(hasher.Sum(nil), expectedDigest) {
		closeErr := file.Close()

		return errors.Join(fmt.Errorf("%w: upload SHA-256 changed", ErrIntegrity), closeErr)
	}

	syncErr := file.Sync()

	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("persist local filesystem upload: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func verifyExisting(
	ctx context.Context,
	root *os.Root,
	key string,
	expectedBytes uint64,
	expectedDigest []byte,
) (provider.Object, error) {
	information, err := root.Lstat(key)
	if err != nil {
		return provider.Object{}, fmt.Errorf("%w: inspect existing %q: %w", ErrInvalidObject, key, err)
	}

	if !information.Mode().IsRegular() {
		return provider.Object{}, fmt.Errorf("%w: existing %q is not a regular file", ErrInvalidObject, key)
	}

	object, err := statObject(ctx, root, key)
	if err != nil {
		return provider.Object{}, err
	}

	if object.SizeBytes != expectedBytes || object.ETag != hex.EncodeToString(expectedDigest) {
		return provider.Object{}, fmt.Errorf("%w: existing object %q differs from upload", ErrIntegrity, key)
	}

	return object, nil
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

func objectIdentity(key string, sizeBytes uint64, digest string) provider.Object {
	return provider.Object{
		Key: key, SizeBytes: sizeBytes,
		ETag: digest, Version: "sha256:" + digest,
	}
}

type contextReader struct {
	cancellation func() error
	reader       io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	return readWithCancellation(reader.cancellation, reader.reader, buffer, "read local filesystem input")
}

type rangeReadCloser struct {
	cancellation func() error
	file         *os.File
	reader       *io.SectionReader
}

func (stream *rangeReadCloser) Read(buffer []byte) (int, error) {
	return readWithCancellation(stream.cancellation, stream.reader, buffer, "read local filesystem range")
}

func (stream *rangeReadCloser) Close() error {
	if err := stream.file.Close(); err != nil {
		return fmt.Errorf("close local filesystem range: %w", err)
	}

	return nil
}

func readWithCancellation(
	cancellation func() error,
	reader io.Reader,
	buffer []byte,
	operation string,
) (int, error) {
	if err := cancellation(); err != nil {
		return 0, fmt.Errorf("%s: %w", operation, err)
	}

	readBytes, err := reader.Read(buffer)
	if err == nil {
		return readBytes, nil
	}

	if errors.Is(err, io.EOF) {
		return readBytes, io.EOF
	}

	return readBytes, fmt.Errorf("%s: %w", operation, err)
}

func checkedFileSize(information fs.FileInfo) (uint64, error) {
	sizeBytes := information.Size()
	if sizeBytes < 0 {
		return 0, fmt.Errorf("%w: regular file has a negative size", ErrInvalidObject)
	}

	return uint64(sizeBytes), nil
}

func checkedInt64(value uint64) int64 {
	return int64(value) //nolint:gosec // Callers validate values against maximumObjectBytes.
}

var (
	_ provider.Reader = (*Client)(nil)
	_ provider.Writer = (*Client)(nil)
)
