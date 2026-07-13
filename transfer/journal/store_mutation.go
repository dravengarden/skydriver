package journal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
)

func (store *Store) appendState(
	journalID string,
	expected stateEnvelope,
	next stateRecord,
) (stateEnvelope, error) {
	if store == nil || store.rootPath == "" {
		return stateEnvelope{}, fmt.Errorf("%w: store is not initialized", ErrInvalidStore)
	}

	if err := validateIdentity(journalID); err != nil {
		return stateEnvelope{}, err
	}

	if next.Revision != expected.record.Revision+1 || next.PreviousStateDigest != expected.digest ||
		next.PlanDigest != expected.record.PlanDigest {
		return stateEnvelope{}, fmt.Errorf("%w: next state does not extend expected revision", ErrJournalConflict)
	}

	if err := validateStatusTransition(expected.record.Status, next.Status); err != nil {
		return stateEnvelope{}, err
	}

	if err := next.validate(expected.record.PlanDigest, expected); err != nil {
		return stateEnvelope{}, err
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return stateEnvelope{}, fmt.Errorf("%w: open root: %w", ErrInvalidStore, err)
	}

	appended, appendErr := appendStateAt(root, journalID, expected, next)

	closeErr := root.Close()
	if appendErr != nil || closeErr != nil {
		return stateEnvelope{}, errors.Join(appendErr, closeErr)
	}

	return appended, nil
}

func (store *Store) clearDownloadReceipts(journalID string) error {
	if store == nil || store.rootPath == "" {
		return fmt.Errorf("%w: store is not initialized", ErrInvalidStore)
	}

	if err := validateIdentity(journalID); err != nil {
		return err
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return fmt.Errorf("%w: open root: %w", ErrInvalidStore, err)
	}

	directory := path.Join(journalID, downloadBlocksDirectory)

	entries, clearErr := fs.ReadDir(root.FS(), directory)
	if clearErr == nil {
		for _, entry := range entries {
			if _, parseErr := parseNumberName(entry.Name()); parseErr != nil {
				clearErr = parseErr

				break
			}

			if removeErr := root.Remove(path.Join(directory, entry.Name())); removeErr != nil {
				clearErr = fmt.Errorf("%w: invalidate download receipt: %w", ErrInvalidStore, removeErr)

				break
			}
		}
	}

	if clearErr == nil {
		clearErr = syncDirectory(root, directory)
	}

	closeErr := root.Close()
	if clearErr != nil || closeErr != nil {
		return errors.Join(clearErr, closeErr)
	}

	return nil
}

func appendStateAt(
	root *os.Root,
	journalID string,
	expected stateEnvelope,
	next stateRecord,
) (stateEnvelope, error) {
	current, err := loadStateChain(root, journalID, expected.record.PlanDigest)
	if err != nil {
		return stateEnvelope{}, err
	}

	if current.record.Revision != expected.record.Revision || current.digest != expected.digest {
		return stateEnvelope{}, ErrJournalConflict
	}

	digest, err := writeEnvelopeExclusive(root, statePath(journalID, next.Revision), next)
	if err != nil {
		return stateEnvelope{}, err
	}

	if err := syncDirectory(root, path.Join(journalID, stateDirectoryName)); err != nil {
		return stateEnvelope{}, err
	}

	return stateEnvelope{record: next, digest: digest}, nil
}

func (store *Store) putUploadReceipt(
	journalID,
	planDigest string,
	receipt uploadPartReceipt,
) error {
	return store.putReceipt(
		journalID,
		path.Join(uploadPartsDirectory, progressFileName(receipt.Part.Number)),
		planDigest,
		receipt,
	)
}

func (store *Store) putDownloadReceipt(
	journalID,
	planDigest string,
	receipt downloadBlockReceipt,
) error {
	return store.putReceipt(
		journalID,
		path.Join(downloadBlocksDirectory, progressFileName(receipt.Block.Number)),
		planDigest,
		receipt,
	)
}

func (store *Store) putReceipt(
	journalID,
	relativePath,
	planDigest string,
	value any,
) error {
	if store == nil || store.rootPath == "" {
		return fmt.Errorf("%w: store is not initialized", ErrInvalidStore)
	}

	if err := validateIdentity(journalID); err != nil {
		return err
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return fmt.Errorf("%w: open root: %w", ErrInvalidStore, err)
	}

	receiptErr := putReceiptAt(root, journalID, relativePath, planDigest, value)

	closeErr := root.Close()
	if receiptErr != nil || closeErr != nil {
		return errors.Join(receiptErr, closeErr)
	}

	return nil
}

func putReceiptAt(
	root *os.Root,
	journalID,
	relativePath,
	planDigest string,
	value any,
) error {
	if !receiptMatchesPlan(value, planDigest) {
		return fmt.Errorf("%w: progress receipt does not match plan", ErrJournalCorrupt)
	}

	recordPath := path.Join(journalID, relativePath)

	_, err := writeEnvelopeExclusive(root, recordPath, value)
	if err == nil {
		return syncDirectory(root, path.Dir(recordPath))
	}

	if !errors.Is(err, ErrJournalConflict) {
		return err
	}

	var existing any

	switch value.(type) {
	case uploadPartReceipt:
		existing = &uploadPartReceipt{}
	case downloadBlockReceipt:
		existing = &downloadBlockReceipt{}
	default:
		return fmt.Errorf("%w: unsupported progress receipt", ErrInvalidStore)
	}

	existingDigest, readErr := readEnvelope(root, recordPath, existing)
	if readErr != nil {
		return readErr
	}

	_, expectedDigest, encodeErr := encodeEnvelope(value)
	if encodeErr != nil {
		return encodeErr
	}

	if expectedDigest != existingDigest || !receiptMatchesPlan(existing, planDigest) {
		return ErrJournalConflict
	}

	return nil
}

func receiptMatchesPlan(value any, planDigest string) bool {
	switch receipt := value.(type) {
	case uploadPartReceipt:
		return receipt.Schema == schema && receipt.PlanDigest == planDigest &&
			receipt.Part.Number != 0 && receipt.Part.Length != 0 && validateSHA256(receipt.Part.Checksum) == nil
	case *uploadPartReceipt:
		return receiptMatchesPlan(*receipt, planDigest)
	case downloadBlockReceipt:
		return receipt.Schema == schema && receipt.PlanDigest == planDigest &&
			receipt.Block.Number != 0 && receipt.Block.Length != 0 && validateSHA256(receipt.Block.Checksum) == nil
	case *downloadBlockReceipt:
		return receiptMatchesPlan(*receipt, planDigest)
	default:
		return false
	}
}

func progressFileName(number uint32) string {
	return fmt.Sprintf("%010d.json", number)
}
