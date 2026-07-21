package localfs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/dravengarden/skydriver/driver"
)

func TestResumableUploadSurvivesRestartAndPublishesOneObject(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	firstClient := mustClient(t, rootPath)
	ctx := context.Background()
	payload := []byte("abcdefghij")

	session := mustBeginUpload(t, firstClient, "objects/resumed", payload)
	secondClient := mustClient(t, rootPath)

	second := mustPutPart(t, secondClient, session, 2, 5, payload[5:])
	first := mustPutPart(t, secondClient, session, 1, 0, payload[:5])

	parts, err := secondClient.ListParts(ctx, session)
	if err != nil {
		t.Fatalf("list restarted upload parts: %v", err)
	}

	if !slices.Equal(parts, []driver.UploadedPart{first, second}) {
		t.Fatalf("authoritative parts = %+v", parts)
	}

	object, err := secondClient.CompleteUpload(ctx, driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{first, second},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if err != nil {
		t.Fatalf("complete restarted upload: %v", err)
	}

	if actual := mustReadFile(t, filepath.Join(rootPath, "objects", "resumed")); !bytes.Equal(actual, payload) {
		t.Fatalf("assembled final bytes = %q", actual)
	}

	if _, statErr := os.Stat(filepath.Join(rootPath, filepath.FromSlash(sessionDirectory(session.ID)))); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("completed staging directory stat error = %v, want not exist", statErr)
	}

	objects, cursor, err := secondClient.List(ctx, "", 10)
	if err != nil {
		t.Fatalf("inventory completed upload: %v", err)
	}

	if cursor != "" || !slices.Equal(objectKeys(objects), []string{"objects/resumed"}) {
		t.Fatalf("inventory exposed staging: keys=%v cursor=%q", objectKeys(objects), cursor)
	}

	replayed, err := secondClient.CompleteUpload(ctx, driver.CompleteUploadRequest{
		Session:   session,
		Parts:     nil,
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if err != nil {
		t.Fatalf("replay completed upload: %v", err)
	}

	if replayed != object {
		t.Fatalf("completion replay object = %+v, want %+v", replayed, object)
	}
}

func TestPartsPublishConcurrentlyAndOutOfOrder(t *testing.T) {
	t.Parallel()

	client := mustClient(t, t.TempDir())
	ctx := context.Background()

	const (
		partCount = 24
		partBytes = 1024
	)

	payload := make([]byte, partCount*partBytes)
	for index := range payload {
		payload[index] = byte(index % 251)
	}

	session := mustBeginUpload(t, client, "objects/parallel", payload)
	parts := make([]driver.UploadedPart, partCount)
	errorsByPart := make([]error, partCount)

	var waitGroup sync.WaitGroup
	for index := range partCount {
		waitGroup.Go(func() {
			reversed := partCount - index - 1
			offset := reversed * partBytes
			partPayload := payload[offset : offset+partBytes]
			part, err := client.PutPart(ctx, driver.PutPartRequest{
				Session: session,
				Part: driver.UploadedPart{
					Number:   uint32(reversed + 1),
					Offset:   uint64(offset),
					Length:   uint64(len(partPayload)),
					Checksum: checksum(partPayload),
				},
				Body: bytes.NewReader(partPayload),
			})
			parts[reversed] = part
			errorsByPart[reversed] = err
		})
	}

	waitGroup.Wait()

	for index, err := range errorsByPart {
		if err != nil {
			t.Fatalf("put parallel part %d: %v", index+1, err)
		}
	}

	authoritative, err := client.ListParts(ctx, session)
	if err != nil {
		t.Fatalf("list parallel parts: %v", err)
	}

	if !slices.Equal(authoritative, parts) {
		t.Fatalf("parallel authoritative parts differ")
	}

	object, err := client.CompleteUpload(ctx, driver.CompleteUploadRequest{
		Session:   session,
		Parts:     parts,
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if err != nil {
		t.Fatalf("complete parallel upload: %v", err)
	}

	stream, err := client.Open(ctx, object)
	if err != nil {
		t.Fatalf("open parallel object: %v", err)
	}

	if actual := mustReadAll(t, stream); !bytes.Equal(actual, payload) {
		t.Fatal("parallel final object differs")
	}
}

func TestPartReplayIsIdempotentAndConflictIsVisible(t *testing.T) {
	t.Parallel()

	client := mustClient(t, t.TempDir())
	payload := []byte("part payload")
	session := mustBeginUpload(t, client, "objects/idempotent-part", payload)

	first := mustPutPart(t, client, session, 1, 0, payload)

	replayed := mustPutPart(t, client, session, 1, 0, payload)
	if replayed != first {
		t.Fatalf("part replay = %+v, want %+v", replayed, first)
	}

	_, err := client.PutPart(context.Background(), driver.PutPartRequest{
		Session: session,
		Part: driver.UploadedPart{
			Number:   1,
			Offset:   0,
			Length:   uint64(len(payload)),
			Checksum: checksum([]byte("different!!!")),
		},
		Body: bytes.NewReader([]byte("different!!!")),
	})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("conflicting part replay error = %v, want ErrIntegrity", err)
	}

	parts, err := client.ListParts(context.Background(), session)
	if err != nil {
		t.Fatalf("list after conflict: %v", err)
	}

	if !slices.Equal(parts, []driver.UploadedPart{first}) {
		t.Fatalf("conflict changed authoritative parts: %+v", parts)
	}
}

func TestCompletionRejectsGapsAndAuthoritativeMismatch(t *testing.T) {
	t.Parallel()

	client := mustClient(t, t.TempDir())
	payload := []byte("abcdefgh")
	session := mustBeginUpload(t, client, "objects/coverage", payload)
	first := mustPutPart(t, client, session, 1, 0, payload[:4])
	second := mustPutPart(t, client, session, 2, 4, payload[4:])

	_, err := client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{second, first},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("out-of-order coverage error = %v, want ErrInvalidUpload", err)
	}

	_, err = client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{first},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("incomplete coverage error = %v, want ErrInvalidUpload", err)
	}

	forgedSecond := second
	forgedSecond.ETag = ""

	_, err = client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{first, forgedSecond},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if !errors.Is(err, ErrInvalidUpload) {
		t.Fatalf("non-authoritative ETag error = %v, want ErrInvalidUpload", err)
	}

	if _, err := client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{first, second},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	}); err != nil {
		t.Fatalf("complete after pre-seal validation errors: %v", err)
	}
}

func TestSealedSessionCanRecoverButRejectsNewParts(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)
	payload := []byte("sealed")
	session := mustBeginUpload(t, client, "objects/sealed", payload)
	part := mustPutPart(t, client, session, 1, 0, payload)

	sealPath := filepath.Join(rootPath, filepath.FromSlash(sessionDirectory(session.ID)), sessionSealName)
	if err := os.WriteFile(sealPath, []byte("sealed\n"), 0o600); err != nil {
		t.Fatalf("simulate durable completion seal: %v", err)
	}

	_, err := client.PutPart(context.Background(), driver.PutPartRequest{
		Session: session,
		Part: driver.UploadedPart{
			Number:   2,
			Offset:   0,
			Length:   uint64(len(payload)),
			Checksum: checksum(payload),
		},
		Body: bytes.NewReader(payload),
	})
	if !errors.Is(err, ErrUploadSealed) {
		t.Fatalf("put into sealed session error = %v, want ErrUploadSealed", err)
	}

	if _, err := client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{part},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	}); err != nil {
		t.Fatalf("recover sealed completion: %v", err)
	}
}

func TestCompletionRecoversPublishedObjectBeforeReceipt(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)
	payload := []byte("published before receipt")
	session := mustBeginUpload(t, client, "objects/lost-response", payload)
	part := mustPutPart(t, client, session, 1, 0, payload)

	expected := mustPut(t, client, "objects/lost-response", payload)

	recovered, err := client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{part},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if err != nil {
		t.Fatalf("recover object published before receipt: %v", err)
	}

	if recovered != expected {
		t.Fatalf("recovered object = %+v, want %+v", recovered, expected)
	}

	if _, err := os.Stat(filepath.Join(rootPath, filepath.FromSlash(completionRecordPath(session.ID)))); err != nil {
		t.Fatalf("completion receipt missing: %v", err)
	}
}

func TestCorruptStagedPartIsNeverListedOrCompleted(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	client := mustClient(t, rootPath)
	payload := []byte("corrupt me")
	session := mustBeginUpload(t, client, "objects/corrupt", payload)
	part := mustPutPart(t, client, session, 1, 0, payload)

	partPath := filepath.Join(
		rootPath,
		filepath.FromSlash(sessionPartsDirectory(session.ID)),
		partFileName(part.Number),
	)

	file, err := os.OpenFile(partPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open staged part for corruption: %v", err)
	}

	if _, writeErr := file.WriteAt([]byte("X"), int64(len(partMagic)+4+200)); writeErr == nil {
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("close corrupted part: %v", closeErr)
		}
	} else {
		closeErr := file.Close()
		t.Fatalf("corrupt staged part: %v", errors.Join(writeErr, closeErr))
	}

	if _, listErr := client.ListParts(context.Background(), session); !errors.Is(listErr, ErrIntegrity) {
		t.Fatalf("list corrupted part error = %v, want ErrIntegrity", listErr)
	}

	_, err = client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   session,
		Parts:     []driver.UploadedPart{part},
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("complete corrupted part error = %v, want ErrIntegrity", err)
	}
}

func TestAbortIsIdempotentAndNeverDeletesFinalObject(t *testing.T) {
	t.Parallel()

	client := mustClient(t, t.TempDir())
	payload := []byte("abort payload")
	session := mustBeginUpload(t, client, "objects/abort", payload)
	mustPutPart(t, client, session, 1, 0, payload)

	if err := client.AbortUpload(context.Background(), session); err != nil {
		t.Fatalf("abort active upload: %v", err)
	}

	if err := client.AbortUpload(context.Background(), session); err != nil {
		t.Fatalf("repeat abort: %v", err)
	}

	if _, err := client.ListParts(context.Background(), session); !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("list aborted session error = %v, want ErrUploadNotFound", err)
	}

	publishedSession := mustBeginUpload(t, client, "objects/abort-published", payload)
	mustPutPart(t, client, publishedSession, 1, 0, payload)
	expected := mustPut(t, client, "objects/abort-published", payload)

	if err := client.AbortUpload(context.Background(), publishedSession); err != nil {
		t.Fatalf("abort after final publication: %v", err)
	}

	recovered, err := client.CompleteUpload(context.Background(), driver.CompleteUploadRequest{
		Session:   publishedSession,
		SizeBytes: uint64(len(payload)),
		Checksum:  checksum(payload),
	})
	if err != nil {
		t.Fatalf("recover completion after abort: %v", err)
	}

	if recovered != expected {
		t.Fatalf("abort changed final object: %+v != %+v", recovered, expected)
	}
}

func mustBeginUpload(t *testing.T, client *Client, storageKey string, payload []byte) driver.UploadSession {
	t.Helper()

	session, err := client.BeginUpload(context.Background(), driver.BeginUploadRequest{
		StorageKey: storageKey,
		SizeBytes:  uint64(len(payload)),
		Checksum:   checksum(payload),
	})
	if err != nil {
		t.Fatalf("begin upload %q: %v", storageKey, err)
	}

	return session
}

func mustPutPart(
	t *testing.T,
	client *Client,
	session driver.UploadSession,
	number uint32,
	offset uint64,
	payload []byte,
) driver.UploadedPart {
	t.Helper()

	part, err := client.PutPart(context.Background(), driver.PutPartRequest{
		Session: session,
		Part: driver.UploadedPart{
			Number:   number,
			Offset:   offset,
			Length:   uint64(len(payload)),
			Checksum: checksum(payload),
		},
		Body: bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("put part %d: %v", number, err)
	}

	return part
}
