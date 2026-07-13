package localfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	"github.com/dravengarden/carrack/driver"
)

// Put validates and atomically publishes one complete immutable regular file.
// Empty files are supported. A retry after a lost response succeeds only when
// the existing StorageKey has the exact declared length and SHA-256; a
// different existing object is never overwritten.
func (client *Client) Put(ctx context.Context, request driver.PutRequest) (driver.Object, error) {
	expectedDigest, err := validateCompleteWrite(request)
	if err != nil {
		return driver.Object{}, err
	}

	root, err := client.openRoot()
	if err != nil {
		return driver.Object{}, err
	}

	object, putErr := putCompleteObject(ctx, root, request, expectedDigest)

	closeErr := root.Close()
	if putErr != nil || closeErr != nil {
		return driver.Object{}, errors.Join(putErr, closeErr)
	}

	return object, nil
}

func validateCompleteWrite(request driver.PutRequest) ([]byte, error) {
	if err := validateStorageKey(request.StorageKey); err != nil {
		return nil, err
	}

	if request.Body == nil {
		return nil, fmt.Errorf("%w: complete upload body is required", ErrInvalidUpload)
	}

	if request.SizeBytes > maximumObjectBytes {
		return nil, fmt.Errorf("%w: complete upload exceeds local file limit", ErrInvalidUpload)
	}

	return validateChecksum(request.Checksum)
}

func putCompleteObject(
	ctx context.Context,
	root *os.Root,
	request driver.PutRequest,
	expectedDigest []byte,
) (driver.Object, error) {
	if _, err := root.Lstat(request.StorageKey); err == nil {
		return verifyExisting(ctx, root, request.StorageKey, request.SizeBytes, request.Checksum)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return driver.Object{}, fmt.Errorf(
			"%w: inspect destination %q: %w",
			ErrInvalidObject,
			request.StorageKey,
			err,
		)
	}

	parent := path.Dir(request.StorageKey)
	if err := root.MkdirAll(parent, privateDirectoryMode); err != nil {
		return driver.Object{}, fmt.Errorf(
			"%w: create parent for %q: %w",
			ErrInvalidObject,
			request.StorageKey,
			err,
		)
	}

	temporaryKey, temporary, err := createRandomFile(root, parent, uploadTemporaryPrefix)
	if err != nil {
		return driver.Object{}, err
	}

	writeErr := writeExactFile(ctx, temporary, request.Body, request.SizeBytes, expectedDigest)
	if writeErr != nil {
		removeErr := root.Remove(temporaryKey)

		return driver.Object{}, errors.Join(writeErr, removeErr)
	}

	return publishTemporary(
		ctx,
		root,
		temporaryKey,
		request.StorageKey,
		request.SizeBytes,
		request.Checksum,
	)
}

func writeExactFile(
	ctx context.Context,
	file *os.File,
	body io.Reader,
	sizeBytes uint64,
	expectedDigest []byte,
) error {
	hasher := sha256.New()
	reader := &contextReader{cancellation: ctx.Err, reader: body}

	written, copyErr := io.CopyN(io.MultiWriter(file, hasher), reader, checkedInt64(sizeBytes))
	if copyErr != nil || written != checkedInt64(sizeBytes) {
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

		return errors.Join(fmt.Errorf("%w: complete upload SHA-256 differs", ErrIntegrity), closeErr)
	}

	syncErr := file.Sync()

	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("persist local filesystem upload: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func publishTemporary(
	ctx context.Context,
	root *os.Root,
	temporaryKey,
	storageKey string,
	sizeBytes uint64,
	checksum string,
) (driver.Object, error) {
	linkErr := root.Link(temporaryKey, storageKey)
	if linkErr != nil {
		removeErr := root.Remove(temporaryKey)
		if errors.Is(linkErr, fs.ErrExist) {
			existing, verifyErr := verifyExisting(ctx, root, storageKey, sizeBytes, checksum)

			return existing, errors.Join(verifyErr, removeErr)
		}

		return driver.Object{}, fmt.Errorf(
			"%w: publish %q: %w",
			ErrInvalidObject,
			storageKey,
			errors.Join(linkErr, removeErr),
		)
	}

	removeErr := root.Remove(temporaryKey)

	syncErr := syncDirectoryChain(root, path.Dir(storageKey))
	if removeErr != nil || syncErr != nil {
		return driver.Object{}, fmt.Errorf(
			"%w: finalize %q: %w",
			ErrInvalidObject,
			storageKey,
			errors.Join(removeErr, syncErr),
		)
	}

	return objectIdentity(storageKey, sizeBytes, checksum), nil
}

func verifyExisting(
	ctx context.Context,
	root *os.Root,
	storageKey string,
	expectedBytes uint64,
	expectedChecksum string,
) (driver.Object, error) {
	object, err := statObjectAt(ctx, root, storageKey)
	if err != nil {
		return driver.Object{}, err
	}

	if object.SizeBytes != expectedBytes || object.Locator.ETag != expectedChecksum {
		return driver.Object{}, fmt.Errorf("%w: existing object %q differs from upload", ErrIntegrity, storageKey)
	}

	return object, nil
}
