package localfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"

	"github.com/dravengarden/carrack/driver"
)

// Stat hashes one complete regular file and returns its content-derived pinned
// identity. It fails if the file changes while being inspected.
func (client *Client) Stat(ctx context.Context, storageKey string) (driver.Object, error) {
	if err := validateStorageKey(storageKey); err != nil {
		return driver.Object{}, err
	}

	file, err := client.openObjectFile(storageKey)
	if err != nil {
		return driver.Object{}, err
	}

	object, _, inspectErr := inspectOpenFile(ctx.Err, file, storageKey)

	closeErr := file.Close()
	if inspectErr != nil || closeErr != nil {
		return driver.Object{}, errors.Join(inspectErr, closeErr)
	}

	return object, nil
}

// Open validates the complete current file against object before returning a
// stream. The stream rechecks length, SHA-256, inode, size, and modification
// time at EOF so a concurrent mutation becomes a visible integrity error.
func (client *Client) Open(ctx context.Context, object driver.Object) (io.ReadCloser, error) {
	expectedDigest, err := validateObject(object)
	if err != nil {
		return nil, err
	}

	file, err := client.openObjectFile(object.Locator.StorageKey)
	if err != nil {
		return nil, err
	}

	actual, information, inspectErr := inspectOpenFile(ctx.Err, file, object.Locator.StorageKey)
	if inspectErr != nil {
		closeErr := file.Close()

		return nil, errors.Join(inspectErr, closeErr)
	}

	if !objectsEqual(actual, object) {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: pinned object changed before complete read", ErrIntegrity),
			closeErr,
		)
	}

	return &completeReadCloser{
		cancellation:   ctx.Err,
		file:           file,
		hasher:         sha256.New(),
		baseline:       information,
		expectedDigest: expectedDigest,
		remaining:      object.SizeBytes,
	}, nil
}

// OpenRange returns exactly length bytes from a pinned complete object. Local
// range I/O is native, but the driver hashes the complete file before the range
// and again at range EOF because a byte range alone cannot prove whole-object
// identity. Callers needing cheaper repeated ranges should use Carrack's signed
// verification-block metadata while retaining final whole-file verification.
func (client *Client) OpenRange(
	ctx context.Context,
	object driver.Object,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if _, err := validateObject(object); err != nil {
		return nil, err
	}

	if length == 0 || offset > object.SizeBytes || length > object.SizeBytes-offset {
		return nil, fmt.Errorf(
			"%w: range [%d,%d) exceeds %d-byte object",
			ErrInvalidRange,
			offset,
			offset+length,
			object.SizeBytes,
		)
	}

	file, err := client.openObjectFile(object.Locator.StorageKey)
	if err != nil {
		return nil, err
	}

	actual, information, inspectErr := inspectOpenFile(ctx.Err, file, object.Locator.StorageKey)
	if inspectErr != nil {
		closeErr := file.Close()

		return nil, errors.Join(inspectErr, closeErr)
	}

	if !objectsEqual(actual, object) {
		closeErr := file.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: pinned object changed before range read", ErrIntegrity),
			closeErr,
		)
	}

	return &rangeReadCloser{
		cancellation: ctx.Err,
		file:         file,
		reader:       io.NewSectionReader(file, checkedInt64(offset), checkedInt64(length)),
		object:       object,
		baseline:     information,
		remaining:    length,
	}, nil
}

func (client *Client) openObjectFile(storageKey string) (*os.File, error) {
	root, err := client.openRoot()
	if err != nil {
		return nil, err
	}

	file, _, openErr := openRegularAt(root, storageKey)

	closeRootErr := root.Close()
	if openErr != nil || closeRootErr != nil {
		if file != nil {
			closeFileErr := file.Close()

			return nil, fmt.Errorf(
				"%w: open %q: %w",
				ErrInvalidObject,
				storageKey,
				errors.Join(openErr, closeRootErr, closeFileErr),
			)
		}

		return nil, fmt.Errorf(
			"%w: open %q: %w",
			ErrInvalidObject,
			storageKey,
			errors.Join(openErr, closeRootErr),
		)
	}

	return file, nil
}

func inspectOpenFile(
	cancellation func() error,
	file *os.File,
	storageKey string,
) (driver.Object, fs.FileInfo, error) {
	before, err := file.Stat()
	if err != nil {
		return driver.Object{}, nil, fmt.Errorf("%w: inspect %q: %w", ErrInvalidObject, storageKey, err)
	}

	if !before.Mode().IsRegular() {
		return driver.Object{}, nil, fmt.Errorf("%w: %q is not a regular file", ErrInvalidObject, storageKey)
	}

	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		return driver.Object{}, nil, fmt.Errorf("%w: rewind %q: %w", ErrInvalidObject, storageKey, seekErr)
	}

	hasher := sha256.New()

	written, copyErr := io.Copy(hasher, &contextReader{cancellation: cancellation, reader: file})
	if copyErr != nil {
		return driver.Object{}, nil, fmt.Errorf("%w: hash %q: %w", ErrInvalidObject, storageKey, copyErr)
	}

	after, err := file.Stat()
	if err != nil {
		return driver.Object{}, nil, fmt.Errorf("%w: reinspect %q: %w", ErrInvalidObject, storageKey, err)
	}

	if written != before.Size() || !sameFileState(before, after) {
		return driver.Object{}, nil, fmt.Errorf("%w: %q changed while being hashed", ErrIntegrity, storageKey)
	}

	sizeBytes, err := checkedFileSize(before)
	if err != nil {
		return driver.Object{}, nil, err
	}

	if sizeBytes > maximumObjectBytes {
		return driver.Object{}, nil, fmt.Errorf("%w: %q exceeds local file limit", ErrInvalidObject, storageKey)
	}

	if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
		return driver.Object{}, nil, fmt.Errorf("%w: rewind hashed %q: %w", ErrInvalidObject, storageKey, seekErr)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	return objectIdentity(storageKey, sizeBytes, checksum), after, nil
}

func sameFileState(before, after fs.FileInfo) bool {
	return before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && os.SameFile(before, after)
}

type completeReadCloser struct {
	cancellation   func() error
	file           *os.File
	hasher         hash.Hash
	baseline       fs.FileInfo
	expectedDigest []byte
	remaining      uint64
	finalized      bool
}

func (stream *completeReadCloser) Read(buffer []byte) (int, error) {
	if stream.finalized {
		return 0, io.EOF
	}

	if err := stream.cancellation(); err != nil {
		return 0, fmt.Errorf("read complete local filesystem object: %w", err)
	}

	if stream.remaining == 0 {
		if err := stream.finalize(); err != nil {
			return 0, err
		}

		return 0, io.EOF
	}

	readBuffer := buffer
	if uint64(len(readBuffer)) > stream.remaining {
		readBuffer = readBuffer[:stream.remaining]
	}

	readBytes, readErr := stream.file.Read(readBuffer)
	if readBytes > 0 {
		if _, err := stream.hasher.Write(readBuffer[:readBytes]); err != nil {
			return readBytes, fmt.Errorf("hash complete local filesystem object: %w", err)
		}

		stream.remaining -= uint64(readBytes)
	}

	if errors.Is(readErr, io.EOF) && stream.remaining != 0 {
		return readBytes, fmt.Errorf("%w: complete object ended early", ErrIntegrity)
	}

	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readBytes, fmt.Errorf("read complete local filesystem object: %w", readErr)
	}

	if stream.remaining == 0 {
		if err := stream.finalize(); err != nil {
			return readBytes, err
		}
	}

	return readBytes, nil
}

func (stream *completeReadCloser) Close() error {
	if err := stream.file.Close(); err != nil {
		return fmt.Errorf("close complete local filesystem object: %w", err)
	}

	return nil
}

func (stream *completeReadCloser) finalize() error {
	var extra [1]byte

	extraBytes, readErr := stream.file.Read(extra[:])
	if extraBytes != 0 || readErr != nil && !errors.Is(readErr, io.EOF) {
		return fmt.Errorf("%w: complete object length changed: %w", ErrIntegrity, readErr)
	}

	after, err := stream.file.Stat()
	if err != nil {
		return fmt.Errorf("%w: reinspect complete object: %w", ErrInvalidObject, err)
	}

	if !sameFileState(stream.baseline, after) || !bytesEqual(stream.hasher.Sum(nil), stream.expectedDigest) {
		return fmt.Errorf("%w: complete object changed while being read", ErrIntegrity)
	}

	stream.finalized = true

	return nil
}

type rangeReadCloser struct {
	cancellation func() error
	file         *os.File
	reader       *io.SectionReader
	object       driver.Object
	baseline     fs.FileInfo
	remaining    uint64
	finalized    bool
}

func (stream *rangeReadCloser) Read(buffer []byte) (int, error) {
	if stream.finalized {
		return 0, io.EOF
	}

	if err := stream.cancellation(); err != nil {
		return 0, fmt.Errorf("read local filesystem range: %w", err)
	}

	readBytes, readErr := stream.reader.Read(buffer)
	stream.remaining -= uint64(readBytes) //nolint:gosec // SectionReader.Read never returns a negative count.

	if errors.Is(readErr, io.EOF) && stream.remaining != 0 {
		return readBytes, fmt.Errorf("%w: range ended early", ErrIntegrity)
	}

	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readBytes, fmt.Errorf("read local filesystem range: %w", readErr)
	}

	if stream.remaining == 0 {
		if err := stream.finalize(); err != nil {
			return readBytes, err
		}
	}

	return readBytes, nil
}

func (stream *rangeReadCloser) Close() error {
	if err := stream.file.Close(); err != nil {
		return fmt.Errorf("close local filesystem range: %w", err)
	}

	return nil
}

func (stream *rangeReadCloser) finalize() error {
	actual, after, err := inspectOpenFile(stream.cancellation, stream.file, stream.object.Locator.StorageKey)
	if err != nil {
		return err
	}

	if !objectsEqual(actual, stream.object) || !sameFileState(stream.baseline, after) {
		return fmt.Errorf("%w: complete object changed while range was read", ErrIntegrity)
	}

	stream.finalized = true

	return nil
}
