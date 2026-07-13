package journal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRejectsNonPrivateRoot(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "public-journals")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatalf("create journal root: %v", err)
	}

	if err := os.Chmod(rootPath, 0o755); err != nil {
		t.Fatalf("make journal root public: %v", err)
	}

	if _, err := NewStore(rootPath); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("got %v, want ErrInvalidStore", err)
	}
}

func TestStoreListReturnsValidatedPublishedJournalsAndIgnoresInterruptedCreate(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, EngineOptions{})
	for index, payload := range [][]byte{[]byte("first"), []byte("second")} {
		if _, err := environment.engine.PrepareUpload(
			context.Background(),
			environment.handle,
			NewBytesSource("list-source", payload),
			fmt.Sprintf("objects/list-%d", index),
			UploadOptions{PartBytes: 2},
		); err != nil {
			t.Fatalf("prepare listed upload: %v", err)
		}
	}

	temporaryID := "ffffffffffffffffffffffffffffffff"
	if err := os.Mkdir(
		filepath.Join(environment.journalRoot, temporaryPrefix+temporaryID),
		privateDirectoryMode,
	); err != nil {
		t.Fatalf("create interrupted temporary journal: %v", err)
	}

	snapshots, err := environment.store.List()
	if err != nil {
		t.Fatalf("list journals: %v", err)
	}

	if len(snapshots) != 2 || snapshots[0].ID >= snapshots[1].ID ||
		snapshots[0].CreatedAt <= 0 || snapshots[1].CreatedAt <= 0 {
		t.Fatalf("journals were not complete and ordered: %+v", snapshots)
	}
}

func TestStoreListRejectsUnexpectedEntries(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, EngineOptions{})
	if err := os.WriteFile(filepath.Join(environment.journalRoot, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatalf("create unexpected store entry: %v", err)
	}

	if _, err := environment.store.List(); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("unexpected store entry was not corruption: %v", err)
	}
}

func TestStoreDetectsTamperedPlanEnvelope(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		NewBytesSource("tamper-plan", []byte("payload")),
		"objects/tamper.bin",
		UploadOptions{PartBytes: 3},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	planPath := filepath.Join(environment.journalRoot, prepared.ID, planFileName)
	encoded := readFile(t, planPath)
	digestPrefix := []byte(`"digest":"`)

	digestIndex := bytes.Index(encoded, digestPrefix)
	if digestIndex < 0 {
		t.Fatal("plan envelope lacks digest")
	}

	digestIndex += len(digestPrefix)
	if encoded[digestIndex] == '0' {
		encoded[digestIndex] = '1'
	} else {
		encoded[digestIndex] = '0'
	}

	if err := os.WriteFile(planPath, encoded, 0o600); err != nil {
		t.Fatalf("tamper plan envelope: %v", err)
	}

	if _, err := environment.store.Load(prepared.ID); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("got %v, want ErrJournalCorrupt", err)
	}
}

func TestStoreRejectsSymlinkRecord(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		NewBytesSource("symlink-plan", []byte("payload")),
		"objects/symlink.bin",
		UploadOptions{PartBytes: 3},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	journalPath := filepath.Join(environment.journalRoot, prepared.ID)
	planPath := filepath.Join(journalPath, planFileName)

	backupName := "plan.backup"
	if err := os.Rename(planPath, filepath.Join(journalPath, backupName)); err != nil {
		t.Fatalf("move plan record: %v", err)
	}

	if err := os.Symlink(backupName, planPath); err != nil {
		t.Fatalf("replace plan with symlink: %v", err)
	}

	if _, err := environment.store.Load(prepared.ID); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("got %v, want ErrJournalCorrupt", err)
	}
}

func TestStoreRejectsStaleOptimisticRevision(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		NewBytesSource("cas", []byte("payload")),
		"objects/cas.bin",
		UploadOptions{PartBytes: 3},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	loaded, err := environment.store.loadRecords(prepared.ID)
	if err != nil {
		t.Fatalf("load prepared journal: %v", err)
	}

	next := loaded.state.record
	next.Revision++
	next.PreviousStateDigest = loaded.state.digest
	next.Status = StatusTransferring
	next.UpdatedAt = time.Now().Unix()

	if _, err := environment.store.appendState(prepared.ID, loaded.state, next); err != nil {
		t.Fatalf("append first optimistic revision: %v", err)
	}

	if _, err := environment.store.appendState(prepared.ID, loaded.state, next); !errors.Is(err, ErrJournalConflict) {
		t.Fatalf("got %v, want ErrJournalConflict", err)
	}
}

func TestExecutorLeaseExcludesConcurrentRun(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		NewBytesSource("lease", []byte("payload")),
		"objects/lease.bin",
		UploadOptions{PartBytes: 3},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	first, err := environment.engine.acquire(prepared.ID, DirectionUpload)
	if err != nil {
		t.Fatalf("acquire first executor: %v", err)
	}

	if _, acquireErr := environment.engine.acquire(
		prepared.ID,
		DirectionUpload,
	); !errors.Is(acquireErr, ErrJournalBusy) {
		t.Fatalf("got %v, want ErrJournalBusy", acquireErr)
	}

	if releaseErr := first.release(); releaseErr != nil {
		t.Fatalf("release first executor: %v", releaseErr)
	}

	second, err := environment.engine.acquire(prepared.ID, DirectionUpload)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}

	if releaseErr := second.release(); releaseErr != nil {
		t.Fatalf("release second executor: %v", releaseErr)
	}
}

func TestStoreRejectsReceiptThatDiffersFromPlan(t *testing.T) {
	t.Parallel()

	environment := newTestEnvironment(t, testEngineOptions())

	prepared, err := environment.engine.PrepareUpload(
		context.Background(),
		environment.handle,
		NewBytesSource("receipt", []byte("payload")),
		"objects/receipt.bin",
		UploadOptions{PartBytes: 3},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	loaded, err := environment.store.loadRecords(prepared.ID)
	if err != nil {
		t.Fatalf("load prepared journal: %v", err)
	}

	conflicting := prepared.Upload.Parts[0]
	conflicting.Offset++

	receipt := uploadPartReceipt{Schema: schema, PlanDigest: loaded.plan.digest, Part: conflicting}
	if err := environment.store.putUploadReceipt(prepared.ID, loaded.plan.digest, receipt); err != nil {
		t.Fatalf("write internally valid conflicting receipt: %v", err)
	}

	if _, err := environment.store.Load(prepared.ID); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("got %v, want ErrJournalCorrupt", err)
	}
}
