package localfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/dravengarden/skydriver/driver"
)

// List returns at most limit complete objects in strict StorageKey order. The
// cursor is the last StorageKey returned by the prior page. Reserved upload,
// completion-receipt, and crash-temporary files are never exposed. A limit
// above 1000 is rejected so recovery inventory cannot accidentally monopolize
// local hashing or memory.
func (client *Client) List(
	ctx context.Context,
	cursor string,
	limit uint32,
) ([]driver.Object, string, error) {
	if limit == 0 || limit > maximumInventoryPage {
		return nil, "", fmt.Errorf(
			"%w: inventory limit must be between 1 and %d",
			ErrInvalidObject,
			maximumInventoryPage,
		)
	}

	if cursor != "" {
		if err := validateStorageKey(cursor); err != nil {
			return nil, "", err
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, "", fmt.Errorf("list local filesystem objects: %w", err)
	}

	keys, err := client.inventoryKeys(ctx, cursor, limit)
	if err != nil {
		return nil, "", err
	}

	more := len(keys) > int(limit)
	if more {
		keys = keys[:limit]
	}

	objects := make([]driver.Object, 0, len(keys))
	for _, storageKey := range keys {
		object, statErr := client.Stat(ctx, storageKey)
		if statErr != nil {
			return nil, "", fmt.Errorf("inventory local filesystem object %q: %w", storageKey, statErr)
		}

		objects = append(objects, object)
	}

	nextCursor := ""
	if more {
		nextCursor = objects[len(objects)-1].Locator.StorageKey
	}

	return objects, nextCursor, nil
}

func (client *Client) inventoryKeys(
	ctx context.Context,
	cursor string,
	limit uint32,
) ([]string, error) {
	if client == nil || client.rootPath == "" {
		return nil, fmt.Errorf("%w: client is not initialized", ErrInvalidConfiguration)
	}

	keys := make([]string, 0, int(limit)+1)

	walkErr := fs.WalkDir(os.DirFS(client.rootPath), ".", func(storageKey string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%w: walk inventory: %w", ErrInvalidObject, err)
		}

		if err := ctx.Err(); err != nil {
			return fmt.Errorf("walk inventory canceled: %w", err)
		}

		if storageKey == internalRoot && entry.IsDir() {
			return fs.SkipDir
		}

		if storageKey == "." || entry.IsDir() {
			return nil
		}

		if hasInternalBaseName(storageKey) {
			return nil
		}

		if !entry.Type().IsRegular() {
			return fmt.Errorf("%w: inventory object %q is not a regular file", ErrInvalidObject, storageKey)
		}

		if strings.Compare(storageKey, cursor) <= 0 {
			return nil
		}

		keys = append(keys, storageKey)
		if len(keys) > int(limit) {
			return errInventoryPageFull
		}

		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errInventoryPageFull) {
		return nil, fmt.Errorf("list local filesystem objects: %w", walkErr)
	}

	// WalkDir is lexical, but retain an explicit invariant if a different
	// filesystem implementation is introduced later.
	slices.Sort(keys)

	return keys, nil
}
