package localfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"github.com/dravengarden/skydriver/driver"
)

// Delete idempotently removes only the exact pinned immutable object. The
// driver first hard-links the current inode to a random quarantine name and
// verifies that link before unlinking either name, so a changed destination is
// never knowingly deleted. The control plane must still fence namespace-level
// delete authorization immediately before this call.
func (client *Client) Delete(ctx context.Context, object driver.Object) error {
	if _, err := validateObject(object); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("delete local filesystem object: %w", err)
	}

	root, err := client.openRoot()
	if err != nil {
		return err
	}

	deleteErr := quarantineAndDelete(ctx, root, object)

	closeErr := root.Close()
	if deleteErr != nil || closeErr != nil {
		return errors.Join(deleteErr, closeErr)
	}

	return nil
}

func quarantineAndDelete(ctx context.Context, root *os.Root, object driver.Object) error {
	storageKey := object.Locator.StorageKey
	parent := path.Dir(storageKey)

	for range temporaryAttempts {
		identity, err := randomIdentity()
		if err != nil {
			return err
		}

		quarantineKey := path.Join(parent, deleteTemporaryPrefix+identity)

		linkErr := root.Link(storageKey, quarantineKey)
		if errors.Is(linkErr, fs.ErrNotExist) {
			return nil
		}

		if errors.Is(linkErr, fs.ErrExist) {
			continue
		}

		if linkErr != nil {
			return fmt.Errorf("%w: quarantine delete target %q: %w", ErrInvalidObject, storageKey, linkErr)
		}

		return removeQuarantined(ctx, root, object, quarantineKey)
	}

	return fmt.Errorf("%w: exhaust delete quarantine names", ErrInvalidObject)
}

func removeQuarantined(
	ctx context.Context,
	root *os.Root,
	object driver.Object,
	quarantineKey string,
) error {
	quarantined, statErr := statObjectAt(ctx, root, quarantineKey)
	if statErr != nil || !sameContentIdentity(quarantined, object) {
		removeErr := root.Remove(quarantineKey)
		if statErr != nil {
			return errors.Join(statErr, removeErr)
		}

		return errors.Join(
			fmt.Errorf("%w: delete target changed before quarantine", ErrIntegrity),
			removeErr,
		)
	}

	quarantineInformation, err := root.Lstat(quarantineKey)
	if err != nil {
		return fmt.Errorf("%w: inspect quarantined object: %w", ErrInvalidObject, err)
	}

	currentInformation, currentErr := root.Lstat(object.Locator.StorageKey)
	if currentErr == nil && os.SameFile(quarantineInformation, currentInformation) {
		currentErr = root.Remove(object.Locator.StorageKey)
	}

	if currentErr != nil && !errors.Is(currentErr, fs.ErrNotExist) {
		return fmt.Errorf("%w: unlink current object: %w", ErrInvalidObject, currentErr)
	}

	removeErr := root.Remove(quarantineKey)

	syncErr := syncDirectoryChain(root, path.Dir(object.Locator.StorageKey))
	if removeErr != nil || syncErr != nil {
		return fmt.Errorf(
			"%w: finalize delete of %q: %w",
			ErrInvalidObject,
			object.Locator.StorageKey,
			errors.Join(removeErr, syncErr),
		)
	}

	return nil
}

func statObjectAt(ctx context.Context, root *os.Root, storageKey string) (driver.Object, error) {
	file, _, err := openRegularAt(root, storageKey)
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

func sameContentIdentity(left, right driver.Object) bool {
	return left.SizeBytes == right.SizeBytes &&
		left.Locator.NativeID == right.Locator.NativeID &&
		left.Locator.Version == right.Locator.Version &&
		left.Locator.ETag == right.Locator.ETag
}
