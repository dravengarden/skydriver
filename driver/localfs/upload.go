package localfs

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
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

	"github.com/dravengarden/carrack/driver"
)

const (
	partMagic              = "CARRACK-V2-PART\n"
	maximumPartHeaderBytes = uint32(4096)
)

type sessionRecord struct {
	Version    uint32 `json:"version"`
	ID         string `json:"id"`
	StorageKey string `json:"storage_key"`
	Checksum   string `json:"checksum"`
	SizeBytes  uint64 `json:"size_bytes"`
	CreatedAt  int64  `json:"created_at"`
}

type partRecord struct {
	Version uint32              `json:"version"`
	Part    driver.UploadedPart `json:"part"`
}

type completionRecord struct {
	Version     uint32        `json:"version"`
	SessionID   string        `json:"session_id"`
	Object      driver.Object `json:"object"`
	CompletedAt int64         `json:"completed_at"`
}

// BeginUpload durably fixes one final StorageKey, exact encoded length, and
// complete SHA-256 before payload transfer. The returned random session ID is
// the only client-visible resume token and contains no plaintext storage key.
// Sessions have no local provider TTL; Carrack GC may abort abandoned sessions
// according to control-plane policy.
func (client *Client) BeginUpload(
	ctx context.Context,
	request driver.BeginUploadRequest,
) (driver.UploadSession, error) {
	if err := validateBeginUpload(request); err != nil {
		return driver.UploadSession{}, err
	}

	if err := ctx.Err(); err != nil {
		return driver.UploadSession{}, fmt.Errorf("begin local filesystem upload: %w", err)
	}

	root, err := client.openRoot()
	if err != nil {
		return driver.UploadSession{}, err
	}

	session, beginErr := beginUploadAt(root, request)

	closeErr := root.Close()
	if beginErr != nil || closeErr != nil {
		return driver.UploadSession{}, errors.Join(beginErr, closeErr)
	}

	return session, nil
}

// PutPart persists one exact, independently checksummed part. Calls may run in
// arbitrary order and concurrently. The payload is fully written and fsynced
// before a single hard link publishes the numbered part, making identical
// retries idempotent and conflicting retries visible. A part is staging only;
// it is never a VFS object and never appears in inventory.
func (client *Client) PutPart(
	ctx context.Context,
	request driver.PutPartRequest,
) (driver.UploadedPart, error) {
	if request.Body == nil {
		return driver.UploadedPart{}, fmt.Errorf("%w: part body is required", ErrInvalidUpload)
	}

	if err := validateUploadSession(request.Session); err != nil {
		return driver.UploadedPart{}, err
	}

	root, err := client.openRoot()
	if err != nil {
		return driver.UploadedPart{}, err
	}

	part, putErr := putPartAt(ctx, root, request)

	closeErr := root.Close()
	if putErr != nil || closeErr != nil {
		return driver.UploadedPart{}, errors.Join(putErr, closeErr)
	}

	return part, nil
}

// ListParts returns the authoritative durable part set sorted by part number.
// Every staged payload is rehashed before it is reported. A completed session
// returns ErrUploadCompleted; callers should replay CompleteUpload to recover
// the final pinned Object. A sealed but incomplete session remains listable so
// a completion interrupted by a process crash can resume.
func (client *Client) ListParts(
	ctx context.Context,
	session driver.UploadSession,
) ([]driver.UploadedPart, error) {
	if err := validateUploadSession(session); err != nil {
		return nil, err
	}

	root, err := client.openRoot()
	if err != nil {
		return nil, err
	}

	parts, listErr := listPartsAt(ctx, root, session)

	closeErr := root.Close()
	if listErr != nil || closeErr != nil {
		return nil, errors.Join(listErr, closeErr)
	}

	return parts, nil
}

// CompleteUpload seals the session, verifies that request.Parts exactly equals
// ListParts, requires gapless coverage in request order, revalidates every part
// and the complete SHA-256, and atomically publishes one complete regular file.
// Parts are never concatenated into multiple final objects. Replays after a
// lost response return the same Object from a durable completion receipt.
func (client *Client) CompleteUpload(
	ctx context.Context,
	request driver.CompleteUploadRequest,
) (driver.Object, error) {
	if err := validateUploadSession(request.Session); err != nil {
		return driver.Object{}, err
	}

	root, err := client.openRoot()
	if err != nil {
		return driver.Object{}, err
	}

	object, completeErr := completeUploadAt(ctx, root, request)

	closeErr := root.Close()
	if completeErr != nil || closeErr != nil {
		return driver.Object{}, errors.Join(completeErr, closeErr)
	}

	return object, nil
}

// AbortUpload idempotently removes only staging state. It first recognizes a
// final object already published before a lost completion response and records
// that completion instead. It never removes a final StorageKey or completion
// receipt, even when called concurrently with recovery.
func (client *Client) AbortUpload(ctx context.Context, session driver.UploadSession) error {
	if err := validateUploadSession(session); err != nil {
		return err
	}

	root, err := client.openRoot()
	if err != nil {
		return err
	}

	abortErr := abortUploadAt(ctx, root, session)

	closeErr := root.Close()
	if abortErr != nil || closeErr != nil {
		return errors.Join(abortErr, closeErr)
	}

	return nil
}

func validateBeginUpload(request driver.BeginUploadRequest) error {
	if err := validateStorageKey(request.StorageKey); err != nil {
		return err
	}

	if request.SizeBytes > maximumObjectBytes {
		return fmt.Errorf("%w: resumable upload exceeds local file limit", ErrInvalidUpload)
	}

	if _, err := validateChecksum(request.Checksum); err != nil {
		return err
	}

	return nil
}

func beginUploadAt(root *os.Root, request driver.BeginUploadRequest) (driver.UploadSession, error) {
	if err := root.MkdirAll(uploadsRoot, privateDirectoryMode); err != nil {
		return driver.UploadSession{}, fmt.Errorf("%w: create upload root: %w", ErrInvalidUpload, err)
	}

	if err := root.MkdirAll(completedRoot, privateDirectoryMode); err != nil {
		return driver.UploadSession{}, fmt.Errorf("%w: create completion root: %w", ErrInvalidUpload, err)
	}

	for range temporaryAttempts {
		sessionID, err := randomIdentity()
		if err != nil {
			return driver.UploadSession{}, err
		}

		directory := sessionDirectory(sessionID)
		if err := root.Mkdir(directory, privateDirectoryMode); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}

			return driver.UploadSession{}, fmt.Errorf("%w: create upload session: %w", ErrInvalidUpload, err)
		}

		session, createErr := createSessionRecord(root, directory, sessionID, request)
		if createErr != nil {
			removeErr := root.RemoveAll(directory)

			return driver.UploadSession{}, errors.Join(createErr, removeErr)
		}

		return session, nil
	}

	return driver.UploadSession{}, fmt.Errorf("%w: exhaust upload session identities", ErrInvalidUpload)
}

func createSessionRecord(
	root *os.Root,
	directory,
	sessionID string,
	request driver.BeginUploadRequest,
) (driver.UploadSession, error) {
	partsDirectory := path.Join(directory, sessionPartsName)
	if err := root.Mkdir(partsDirectory, privateDirectoryMode); err != nil {
		return driver.UploadSession{}, fmt.Errorf("%w: create session parts: %w", ErrInvalidUpload, err)
	}

	record := sessionRecord{
		Version:    recordVersion,
		ID:         sessionID,
		StorageKey: request.StorageKey,
		Checksum:   request.Checksum,
		SizeBytes:  request.SizeBytes,
		CreatedAt:  time.Now().Unix(),
	}

	recordKey := path.Join(directory, sessionRecordName)

	file, err := root.OpenFile(recordKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil {
		return driver.UploadSession{}, fmt.Errorf("%w: create session record: %w", ErrInvalidUpload, err)
	}

	if err := writeJSONFile(file, record); err != nil {
		return driver.UploadSession{}, err
	}

	if err := syncDirectoryChain(root, directory); err != nil {
		return driver.UploadSession{}, err
	}

	return driver.UploadSession{ID: sessionID}, nil
}

func putPartAt(
	ctx context.Context,
	root *os.Root,
	request driver.PutPartRequest,
) (driver.UploadedPart, error) {
	if completed, err := completionExists(root, request.Session.ID); err != nil {
		return driver.UploadedPart{}, err
	} else if completed {
		return driver.UploadedPart{}, ErrUploadCompleted
	}

	record, err := loadSessionRecord(root, request.Session.ID)
	if err != nil {
		return driver.UploadedPart{}, err
	}

	part, expectedDigest, err := normalizePart(record, request.Part)
	if err != nil {
		return driver.UploadedPart{}, err
	}

	if sealed, sealErr := sessionIsSealed(root, record.ID); sealErr != nil {
		return driver.UploadedPart{}, sealErr
	} else if sealed {
		return driver.UploadedPart{}, ErrUploadSealed
	}

	partsDirectory := sessionPartsDirectory(record.ID)

	temporaryKey, temporary, err := createRandomFile(root, partsDirectory, partTemporaryPrefix)
	if err != nil {
		return driver.UploadedPart{}, err
	}

	writeErr := writePartFile(ctx, temporary, request.Body, part, expectedDigest)
	if writeErr != nil {
		removeErr := root.Remove(temporaryKey)

		return driver.UploadedPart{}, errors.Join(writeErr, removeErr)
	}

	if sealed, sealErr := sessionIsSealed(root, record.ID); sealErr != nil || sealed {
		removeErr := root.Remove(temporaryKey)
		if sealErr != nil {
			return driver.UploadedPart{}, errors.Join(sealErr, removeErr)
		}

		return driver.UploadedPart{}, errors.Join(ErrUploadSealed, removeErr)
	}

	published, err := publishPart(ctx, root, record, temporaryKey, part)
	if err != nil {
		return driver.UploadedPart{}, err
	}

	if sealed, sealErr := sessionIsSealed(root, record.ID); sealErr != nil {
		return driver.UploadedPart{}, sealErr
	} else if sealed {
		return driver.UploadedPart{}, ErrUploadSealed
	}

	return published, nil
}

func writePartFile(
	ctx context.Context,
	file *os.File,
	body io.Reader,
	part driver.UploadedPart,
	expectedDigest []byte,
) error {
	header, err := json.Marshal(partRecord{Version: recordVersion, Part: part})
	if err != nil {
		closeErr := file.Close()

		return fmt.Errorf("encode local filesystem part header: %w", errors.Join(err, closeErr))
	}

	if len(header) > int(maximumPartHeaderBytes) {
		closeErr := file.Close()

		return errors.Join(fmt.Errorf("%w: part header is too large", ErrInvalidUpload), closeErr)
	}

	if _, err := file.WriteString(partMagic); err != nil {
		closeErr := file.Close()

		return fmt.Errorf("write local filesystem part magic: %w", errors.Join(err, closeErr))
	}

	var lengthBuffer [4]byte
	binary.BigEndian.PutUint32(
		lengthBuffer[:],
		uint32(len(header)), //nolint:gosec // The maximum header bound above is uint32.
	)

	if _, err := file.Write(lengthBuffer[:]); err != nil {
		closeErr := file.Close()

		return fmt.Errorf("write local filesystem part header length: %w", errors.Join(err, closeErr))
	}

	if _, err := file.Write(header); err != nil {
		closeErr := file.Close()

		return fmt.Errorf("write local filesystem part header: %w", errors.Join(err, closeErr))
	}

	return writeExactFile(ctx, file, body, part.Length, expectedDigest)
}

func publishPart(
	ctx context.Context,
	root *os.Root,
	record sessionRecord,
	temporaryKey string,
	part driver.UploadedPart,
) (driver.UploadedPart, error) {
	partKey := path.Join(sessionPartsDirectory(record.ID), partFileName(part.Number))
	linkErr := root.Link(temporaryKey, partKey)
	removeErr := root.Remove(temporaryKey)

	if linkErr != nil {
		if errors.Is(linkErr, fs.ErrExist) {
			existing, inspectErr := inspectPartAt(ctx, root, record, partKey)
			if inspectErr == nil && existing != part {
				inspectErr = fmt.Errorf("%w: existing part number has conflicting identity", ErrIntegrity)
			}

			return existing, errors.Join(inspectErr, removeErr)
		}

		return driver.UploadedPart{}, fmt.Errorf(
			"%w: publish part %d: %w",
			ErrInvalidUpload,
			part.Number,
			errors.Join(linkErr, removeErr),
		)
	}

	if removeErr != nil {
		return driver.UploadedPart{}, fmt.Errorf("%w: remove part temporary: %w", ErrInvalidUpload, removeErr)
	}

	if err := syncDirectoryChain(root, sessionPartsDirectory(record.ID)); err != nil {
		return driver.UploadedPart{}, err
	}

	return part, nil
}

func listPartsAt(
	ctx context.Context,
	root *os.Root,
	session driver.UploadSession,
) ([]driver.UploadedPart, error) {
	if completed, err := completionExists(root, session.ID); err != nil {
		return nil, err
	} else if completed {
		return nil, ErrUploadCompleted
	}

	record, err := loadSessionRecord(root, session.ID)
	if err != nil {
		return nil, err
	}

	return listPartsForRecord(ctx, root, record)
}

func listPartsForRecord(
	ctx context.Context,
	root *os.Root,
	record sessionRecord,
) ([]driver.UploadedPart, error) {
	partsDirectory := sessionPartsDirectory(record.ID)

	entries, err := fs.ReadDir(root.FS(), partsDirectory)
	if err != nil {
		return nil, fmt.Errorf("%w: read session parts: %w", ErrInvalidUpload, err)
	}

	parts := make([]driver.UploadedPart, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), partTemporaryPrefix) {
			continue
		}

		partNumber, err := parsePartFileName(entry.Name())
		if err != nil {
			return nil, err
		}

		partKey := path.Join(partsDirectory, entry.Name())

		part, err := inspectPartAt(ctx, root, record, partKey)
		if err != nil {
			return nil, err
		}

		if part.Number != partNumber {
			return nil, fmt.Errorf("%w: part filename and header disagree", ErrIntegrity)
		}

		parts = append(parts, part)
	}

	slices.SortFunc(parts, func(left, right driver.UploadedPart) int {
		return cmp.Compare(left.Number, right.Number)
	})

	return parts, nil
}

func inspectPartAt(
	ctx context.Context,
	root *os.Root,
	record sessionRecord,
	partKey string,
) (driver.UploadedPart, error) {
	opened, err := openPartFile(root, record, partKey)
	if err != nil {
		return driver.UploadedPart{}, err
	}

	hasher := sha256.New()

	written, copyErr := io.CopyN(
		hasher,
		&contextReader{cancellation: ctx.Err, reader: opened.file},
		checkedInt64(opened.part.Length),
	)
	if copyErr == nil && written == checkedInt64(opened.part.Length) {
		copyErr = ensureReaderEOF(opened.file)
	}

	after, statErr := opened.file.Stat()

	closeErr := opened.file.Close()
	if copyErr != nil || statErr != nil || closeErr != nil {
		return driver.UploadedPart{}, fmt.Errorf(
			"%w: inspect staged part %d: %w",
			ErrIntegrity,
			opened.part.Number,
			errors.Join(copyErr, statErr, closeErr),
		)
	}

	if !sameFileState(opened.information, after) || hex.EncodeToString(hasher.Sum(nil)) != opened.part.Checksum {
		return driver.UploadedPart{}, fmt.Errorf("%w: staged part %d changed", ErrIntegrity, opened.part.Number)
	}

	return opened.part, nil
}

type openedPart struct {
	file        *os.File
	part        driver.UploadedPart
	information fs.FileInfo
}

func openPartFile(
	root *os.Root,
	record sessionRecord,
	partKey string,
) (openedPart, error) {
	file, _, err := openRegularAt(root, partKey)
	if err != nil {
		return openedPart{}, fmt.Errorf("%w: open staged part: %w", ErrInvalidUpload, err)
	}

	part, information, inspectErr := readPartHeader(file, record)
	if inspectErr != nil {
		closeErr := file.Close()

		return openedPart{}, errors.Join(inspectErr, closeErr)
	}

	return openedPart{file: file, part: part, information: information}, nil
}

func readPartHeader(file *os.File, record sessionRecord) (driver.UploadedPart, fs.FileInfo, error) {
	information, err := file.Stat()
	if err != nil {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: inspect staged part: %w", ErrInvalidUpload, err)
	}

	if !information.Mode().IsRegular() {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: staged part is not a regular file", ErrInvalidUpload)
	}

	magic := make([]byte, len(partMagic))
	if _, readErr := io.ReadFull(file, magic); readErr != nil {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: read staged part magic: %w", ErrIntegrity, readErr)
	}

	if string(magic) != partMagic {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: staged part magic is invalid", ErrIntegrity)
	}

	var lengthBuffer [4]byte
	if _, readErr := io.ReadFull(file, lengthBuffer[:]); readErr != nil {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: read staged part header length: %w", ErrIntegrity, readErr)
	}

	headerBytes := binary.BigEndian.Uint32(lengthBuffer[:])
	if headerBytes == 0 || headerBytes > maximumPartHeaderBytes {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: staged part header length is invalid", ErrIntegrity)
	}

	header := make([]byte, headerBytes)
	if _, readErr := io.ReadFull(file, header); readErr != nil {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: read staged part header: %w", ErrIntegrity, readErr)
	}

	var stored partRecord
	if decodeErr := decodeStrictJSON(header, &stored); decodeErr != nil {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: decode staged part header: %w", ErrIntegrity, decodeErr)
	}

	if stored.Version != recordVersion {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: staged part record version is invalid", ErrIntegrity)
	}

	part, _, err := normalizePart(record, stored.Part)
	if err != nil || part != stored.Part {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: staged part identity is invalid: %w", ErrIntegrity, err)
	}

	headerLength := uint64(len(partMagic)) + uint64(len(lengthBuffer)) + uint64(headerBytes)

	expectedLength := headerLength + part.Length
	if expectedLength > maximumObjectBytes || information.Size() != checkedInt64(expectedLength) {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: staged part file length differs", ErrIntegrity)
	}

	return part, information, nil
}

func completeUploadAt(
	ctx context.Context,
	root *os.Root,
	request driver.CompleteUploadRequest,
) (driver.Object, error) {
	if object, completed, err := recoverCompleted(ctx, root, request); err != nil || completed {
		return object, err
	}

	record, err := loadSessionRecord(root, request.Session.ID)
	if err != nil {
		return driver.Object{}, err
	}

	if validationErr := validateCompletionRequest(record, request); validationErr != nil {
		return driver.Object{}, validationErr
	}

	if object, published, findErr := findPublishedObject(ctx, root, record); findErr != nil {
		return driver.Object{}, findErr
	} else if published {
		if persistErr := persistCompletion(root, record.ID, object); persistErr != nil {
			return driver.Object{}, persistErr
		}

		if removeErr := removeSession(root, record.ID); removeErr != nil {
			return driver.Object{}, removeErr
		}

		return object, nil
	}

	if sealErr := sealSession(root, record.ID); sealErr != nil {
		return driver.Object{}, sealErr
	}

	authoritative, err := listPartsForRecord(ctx, root, record)
	if err != nil {
		return driver.Object{}, err
	}

	if !samePartSet(authoritative, request.Parts) {
		return driver.Object{}, fmt.Errorf(
			"%w: completion parts differ from authoritative ListParts result",
			ErrIntegrity,
		)
	}

	object, err := assembleAndPublish(ctx, root, record, request.Parts)
	if err != nil {
		return driver.Object{}, err
	}

	if err := persistCompletion(root, record.ID, object); err != nil {
		return driver.Object{}, err
	}

	if err := removeSession(root, record.ID); err != nil {
		return driver.Object{}, err
	}

	return object, nil
}

func validateCompletionRequest(record sessionRecord, request driver.CompleteUploadRequest) error {
	if request.SizeBytes != record.SizeBytes || request.Checksum != record.Checksum {
		return fmt.Errorf("%w: completion identity differs from session", ErrInvalidUpload)
	}

	if _, err := validateChecksum(request.Checksum); err != nil {
		return err
	}

	if request.SizeBytes == 0 {
		if len(request.Parts) != 0 {
			return fmt.Errorf("%w: empty upload cannot contain parts", ErrInvalidUpload)
		}

		return nil
	}

	if len(request.Parts) == 0 {
		return fmt.Errorf("%w: non-empty upload requires parts", ErrInvalidUpload)
	}

	numbers := make(map[uint32]struct{}, len(request.Parts))
	nextOffset := uint64(0)

	for _, candidate := range request.Parts {
		part, _, err := normalizePart(record, candidate)
		if err != nil || part != candidate {
			return fmt.Errorf("%w: completion part identity is invalid: %w", ErrInvalidUpload, err)
		}

		if _, exists := numbers[part.Number]; exists {
			return fmt.Errorf("%w: completion repeats part number %d", ErrInvalidUpload, part.Number)
		}

		if part.Offset != nextOffset {
			return fmt.Errorf("%w: completion parts are not gapless in request order", ErrInvalidUpload)
		}

		numbers[part.Number] = struct{}{}
		nextOffset += part.Length
	}

	if nextOffset != request.SizeBytes {
		return fmt.Errorf("%w: completion parts do not cover exact object length", ErrInvalidUpload)
	}

	return nil
}

func assembleAndPublish(
	ctx context.Context,
	root *os.Root,
	record sessionRecord,
	parts []driver.UploadedPart,
) (driver.Object, error) {
	parent := path.Dir(record.StorageKey)
	if err := root.MkdirAll(parent, privateDirectoryMode); err != nil {
		return driver.Object{}, fmt.Errorf("%w: create final object parent: %w", ErrInvalidObject, err)
	}

	temporaryKey, temporary, err := createRandomFile(root, parent, uploadTemporaryPrefix)
	if err != nil {
		return driver.Object{}, err
	}

	writeErr := assembleParts(ctx, root, record, parts, temporary)
	if writeErr != nil {
		removeErr := root.Remove(temporaryKey)

		return driver.Object{}, errors.Join(writeErr, removeErr)
	}

	return publishTemporary(
		ctx,
		root,
		temporaryKey,
		record.StorageKey,
		record.SizeBytes,
		record.Checksum,
	)
}

func assembleParts(
	ctx context.Context,
	root *os.Root,
	record sessionRecord,
	parts []driver.UploadedPart,
	destination *os.File,
) error {
	completeHasher := sha256.New()
	totalBytes := uint64(0)

	for _, part := range parts {
		partKey := path.Join(sessionPartsDirectory(record.ID), partFileName(part.Number))

		opened, err := openPartFile(root, record, partKey)
		if err != nil {
			closeErr := destination.Close()

			return errors.Join(err, closeErr)
		}

		if opened.part != part {
			closePartErr := opened.file.Close()
			closeDestinationErr := destination.Close()

			return errors.Join(
				fmt.Errorf("%w: staged part changed before assembly", ErrIntegrity),
				closePartErr,
				closeDestinationErr,
			)
		}

		copyErr := copyPart(ctx, destination, completeHasher, opened.file, opened.information, part)

		closePartErr := opened.file.Close()
		if copyErr != nil || closePartErr != nil {
			closeDestinationErr := destination.Close()

			return errors.Join(copyErr, closePartErr, closeDestinationErr)
		}

		totalBytes += part.Length
	}

	if totalBytes != record.SizeBytes || hex.EncodeToString(completeHasher.Sum(nil)) != record.Checksum {
		closeErr := destination.Close()

		return errors.Join(fmt.Errorf("%w: assembled complete object differs", ErrIntegrity), closeErr)
	}

	syncErr := destination.Sync()

	closeErr := destination.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("persist assembled complete object: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func copyPart(
	ctx context.Context,
	destination io.Writer,
	completeHasher io.Writer,
	file *os.File,
	before fs.FileInfo,
	part driver.UploadedPart,
) error {
	partHasher := sha256.New()

	written, copyErr := io.CopyN(
		io.MultiWriter(destination, completeHasher, partHasher),
		&contextReader{cancellation: ctx.Err, reader: file},
		checkedInt64(part.Length),
	)
	if copyErr == nil && written == checkedInt64(part.Length) {
		copyErr = ensureReaderEOF(file)
	}

	after, statErr := file.Stat()
	if copyErr != nil || statErr != nil {
		return fmt.Errorf(
			"%w: assemble part %d: %w",
			ErrIntegrity,
			part.Number,
			errors.Join(copyErr, statErr),
		)
	}

	if !sameFileState(before, after) || hex.EncodeToString(partHasher.Sum(nil)) != part.Checksum {
		return fmt.Errorf("%w: part %d changed during assembly", ErrIntegrity, part.Number)
	}

	return nil
}

func recoverCompleted(
	ctx context.Context,
	root *os.Root,
	request driver.CompleteUploadRequest,
) (driver.Object, bool, error) {
	record, found, err := loadCompletion(root, request.Session.ID)
	if err != nil || !found {
		return driver.Object{}, false, err
	}

	if record.Object.SizeBytes != request.SizeBytes || record.Object.Locator.ETag != request.Checksum {
		return driver.Object{}, false, fmt.Errorf("%w: completion replay differs from receipt", ErrIntegrity)
	}

	actual, err := statObjectAt(ctx, root, record.Object.Locator.StorageKey)
	if err != nil {
		return driver.Object{}, false, err
	}

	if !objectsEqual(actual, record.Object) {
		return driver.Object{}, false, fmt.Errorf("%w: completed object differs from receipt", ErrIntegrity)
	}

	return actual, true, nil
}

func abortUploadAt(ctx context.Context, root *os.Root, session driver.UploadSession) error {
	if completed, err := completionExists(root, session.ID); err != nil || completed {
		return err
	}

	record, err := loadSessionRecord(root, session.ID)
	if errors.Is(err, ErrUploadNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	object, published, err := findPublishedObject(ctx, root, record)
	if err != nil {
		return err
	}

	if published {
		if err := persistCompletion(root, record.ID, object); err != nil {
			return err
		}
	}

	return removeSession(root, record.ID)
}

func findPublishedObject(
	ctx context.Context,
	root *os.Root,
	record sessionRecord,
) (driver.Object, bool, error) {
	object, err := statObjectAt(ctx, root, record.StorageKey)
	if errors.Is(err, fs.ErrNotExist) {
		return driver.Object{}, false, nil
	}

	if err != nil {
		return driver.Object{}, false, err
	}

	if object.SizeBytes != record.SizeBytes || object.Locator.ETag != record.Checksum {
		return driver.Object{}, false, fmt.Errorf(
			"%w: session destination contains a different object",
			ErrIntegrity,
		)
	}

	return object, true, nil
}

func normalizePart(
	record sessionRecord,
	part driver.UploadedPart,
) (driver.UploadedPart, []byte, error) {
	if part.Number == 0 || part.Length == 0 {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: part number and length must be positive", ErrInvalidUpload)
	}

	if part.Offset > record.SizeBytes || part.Length > record.SizeBytes-part.Offset {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: part range exceeds session object", ErrInvalidUpload)
	}

	digest, err := validateChecksum(part.Checksum)
	if err != nil {
		return driver.UploadedPart{}, nil, err
	}

	if part.ETag != "" && part.ETag != part.Checksum {
		return driver.UploadedPart{}, nil, fmt.Errorf("%w: local part ETag must equal SHA-256", ErrInvalidUpload)
	}

	part.ETag = part.Checksum

	return part, digest, nil
}

func validateUploadSession(session driver.UploadSession) error {
	decoded, err := hex.DecodeString(session.ID)
	if err != nil || len(decoded) != randomIdentityBytes || hex.EncodeToString(decoded) != session.ID {
		return fmt.Errorf("%w: session ID must be 32 lowercase hexadecimal characters", ErrInvalidUpload)
	}

	if len(session.Opaque) != 0 || session.ExpiresAt != 0 {
		return fmt.Errorf("%w: local session token contains unsupported fields", ErrInvalidUpload)
	}

	return nil
}

func loadSessionRecord(root *os.Root, sessionID string) (sessionRecord, error) {
	var record sessionRecord

	recordKey := path.Join(sessionDirectory(sessionID), sessionRecordName)
	if err := readJSONFile(root, recordKey, &record); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sessionRecord{}, ErrUploadNotFound
		}

		return sessionRecord{}, fmt.Errorf("%w: load session: %w", ErrInvalidUpload, err)
	}

	if record.Version != recordVersion || record.ID != sessionID || record.CreatedAt <= 0 {
		return sessionRecord{}, fmt.Errorf("%w: session record identity is invalid", ErrIntegrity)
	}

	request := driver.BeginUploadRequest{
		StorageKey: record.StorageKey,
		SizeBytes:  record.SizeBytes,
		Checksum:   record.Checksum,
	}
	if err := validateBeginUpload(request); err != nil {
		return sessionRecord{}, fmt.Errorf("%w: stored session is invalid: %w", ErrIntegrity, err)
	}

	return record, nil
}

func sealSession(root *os.Root, sessionID string) error {
	sealKey := path.Join(sessionDirectory(sessionID), sessionSealName)

	file, err := root.OpenFile(sealKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("%w: seal upload session: %w", ErrInvalidUpload, err)
	}

	if _, err := file.WriteString("sealed\n"); err != nil {
		closeErr := file.Close()

		return fmt.Errorf("%w: write upload seal: %w", ErrInvalidUpload, errors.Join(err, closeErr))
	}

	syncErr := file.Sync()

	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("%w: persist upload seal: %w", ErrInvalidUpload, errors.Join(syncErr, closeErr))
	}

	return syncDirectoryChain(root, sessionDirectory(sessionID))
}

func sessionIsSealed(root *os.Root, sessionID string) (bool, error) {
	_, err := root.Lstat(path.Join(sessionDirectory(sessionID), sessionSealName))
	if err == nil {
		return true, nil
	}

	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	return false, fmt.Errorf("%w: inspect upload seal: %w", ErrInvalidUpload, err)
}

func persistCompletion(root *os.Root, sessionID string, object driver.Object) error {
	record := completionRecord{
		Version:     recordVersion,
		SessionID:   sessionID,
		Object:      object,
		CompletedAt: time.Now().Unix(),
	}

	if err := root.MkdirAll(completedRoot, privateDirectoryMode); err != nil {
		return fmt.Errorf("%w: create completion root: %w", ErrInvalidUpload, err)
	}

	temporaryKey, temporary, err := createRandomFile(root, completedRoot, partTemporaryPrefix)
	if err != nil {
		return err
	}

	if err := writeJSONFile(temporary, record); err != nil {
		removeErr := root.Remove(temporaryKey)

		return errors.Join(err, removeErr)
	}

	receiptKey := completionRecordPath(sessionID)
	linkErr := root.Link(temporaryKey, receiptKey)

	removeErr := root.Remove(temporaryKey)
	if errors.Is(linkErr, fs.ErrExist) {
		existing, found, loadErr := loadCompletion(root, sessionID)
		if loadErr == nil && (!found || !sameCompletion(existing, record)) {
			loadErr = fmt.Errorf("%w: existing completion receipt differs", ErrIntegrity)
		}

		return errors.Join(loadErr, removeErr)
	}

	if linkErr != nil || removeErr != nil {
		return fmt.Errorf("%w: publish completion receipt: %w", ErrInvalidUpload, errors.Join(linkErr, removeErr))
	}

	return syncDirectoryChain(root, completedRoot)
}

func loadCompletion(root *os.Root, sessionID string) (completionRecord, bool, error) {
	var record completionRecord

	if err := readJSONFile(root, completionRecordPath(sessionID), &record); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return completionRecord{}, false, nil
		}

		return completionRecord{}, false, fmt.Errorf("%w: load completion receipt: %w", ErrIntegrity, err)
	}

	if record.Version != recordVersion || record.SessionID != sessionID || record.CompletedAt <= 0 {
		return completionRecord{}, false, fmt.Errorf("%w: completion receipt identity is invalid", ErrIntegrity)
	}

	if _, err := validateObject(record.Object); err != nil {
		return completionRecord{}, false, fmt.Errorf("%w: completion receipt object is invalid: %w", ErrIntegrity, err)
	}

	return record, true, nil
}

func completionExists(root *os.Root, sessionID string) (bool, error) {
	_, found, err := loadCompletion(root, sessionID)

	return found, err
}

func removeSession(root *os.Root, sessionID string) error {
	if err := root.RemoveAll(sessionDirectory(sessionID)); err != nil {
		return fmt.Errorf("%w: remove upload session: %w", ErrInvalidUpload, err)
	}

	if _, err := root.Lstat(uploadsRoot); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: inspect upload root after removal: %w", ErrInvalidUpload, err)
	}

	return syncDirectoryChain(root, uploadsRoot)
}

func sameCompletion(left, right completionRecord) bool {
	return left.Version == right.Version && left.SessionID == right.SessionID && objectsEqual(left.Object, right.Object)
}

func samePartSet(authoritative, requested []driver.UploadedPart) bool {
	if len(authoritative) != len(requested) {
		return false
	}

	requestedByNumber := make(map[uint32]driver.UploadedPart, len(requested))
	for _, part := range requested {
		requestedByNumber[part.Number] = part
	}

	for _, part := range authoritative {
		if requestedByNumber[part.Number] != part {
			return false
		}
	}

	return true
}

func ensureReaderEOF(reader io.Reader) error {
	var extra [1]byte

	extraBytes, err := io.ReadFull(reader, extra[:])
	if extraBytes != 0 || err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("payload contains trailing bytes: %w", err)
	}

	return nil
}

func decodeStrictJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	return rejectTrailingJSON(decoder)
}

func parsePartFileName(fileName string) (uint32, error) {
	numberText, found := strings.CutSuffix(fileName, ".part")
	if !found || len(numberText) != 10 {
		return 0, fmt.Errorf("%w: unexpected entry in upload parts directory", ErrIntegrity)
	}

	number, err := strconv.ParseUint(numberText, 10, 32)
	if err != nil || number == 0 || partFileName(uint32(number)) != fileName {
		return 0, fmt.Errorf("%w: staged part filename is invalid", ErrIntegrity)
	}

	return uint32(number), nil
}

func partFileName(number uint32) string {
	return fmt.Sprintf("%010d.part", number)
}

func sessionDirectory(sessionID string) string {
	return path.Join(uploadsRoot, sessionID)
}

func sessionPartsDirectory(sessionID string) string {
	return path.Join(sessionDirectory(sessionID), sessionPartsName)
}

func completionRecordPath(sessionID string) string {
	return path.Join(completedRoot, sessionID+".json")
}
