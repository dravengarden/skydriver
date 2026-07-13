package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	driverlocalfs "github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/transfer/journal"
)

func TestVFSJournalListDiscoversDurableUploadWithoutControlToken(t *testing.T) {
	t.Parallel()

	journalRoot := filepath.Join(t.TempDir(), "journals")

	store, err := journal.NewStore(journalRoot)
	if err != nil {
		t.Fatalf("create journal store: %v", err)
	}

	engine, err := journal.NewEngine(store, journal.EngineOptions{})
	if err != nil {
		t.Fatalf("create journal engine: %v", err)
	}

	providerRoot := filepath.Join(t.TempDir(), "provider")
	if mkdirErr := os.Mkdir(providerRoot, 0o700); mkdirErr != nil {
		t.Fatalf("create provider root: %v", mkdirErr)
	}

	handle, err := driverlocalfs.Open("local-main", providerRoot)
	if err != nil {
		t.Fatalf("open local driver: %v", err)
	}

	planned, err := engine.PrepareUpload(
		context.Background(),
		handle,
		journal.NewBytesSource("hard-crash-release", []byte("payload")),
		"objects/v2/aa/opaque",
		journal.UploadOptions{PartBytes: 3},
	)
	if err != nil {
		t.Fatalf("prepare upload: %v", err)
	}

	var stdout bytes.Buffer
	if err := Run(
		context.Background(),
		[]string{"vfs", "journal", "list", "--journal-directory", journalRoot, "--format", "json"},
		&stdout,
		&bytes.Buffer{},
	); err != nil {
		t.Fatalf("run VFS journal list: %v", err)
	}

	var result vfsJournalListResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode VFS journal list: %v", err)
	}

	if result.Schema != vfsJournalListSchema || len(result.Journals) != 1 ||
		result.Journals[0].JournalID != planned.ID ||
		result.Journals[0].Status != journal.StatusPrepared ||
		result.Journals[0].SourceReference != "hard-crash-release" ||
		result.Journals[0].StorageKey != "objects/v2/aa/opaque" ||
		result.Journals[0].TotalPieces != len(planned.Upload.Parts) {
		t.Fatalf("unexpected VFS journal list: %+v", result)
	}
}

func TestVFSJournalListRejectsCorruptStoreInsteadOfHidingIt(t *testing.T) {
	t.Parallel()

	journalRoot := filepath.Join(t.TempDir(), "journals")
	if _, err := journal.NewStore(journalRoot); err != nil {
		t.Fatalf("create journal store: %v", err)
	}

	if err := os.WriteFile(filepath.Join(journalRoot, "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatalf("create unexpected store entry: %v", err)
	}

	_, err := executeVFSJournalList(journalRoot, func(string) string { return "" })
	if !errors.Is(err, journal.ErrJournalCorrupt) {
		t.Fatalf("corrupt VFS journal store was hidden: %v", err)
	}
}

func TestResolveVFSJournalDirectoryUsesXDGStateHome(t *testing.T) {
	t.Parallel()

	stateHome := t.TempDir()

	resolved, err := resolveVFSJournalDirectory("", func(name string) string {
		if name == "XDG_STATE_HOME" {
			return stateHome
		}

		return ""
	})
	if err != nil {
		t.Fatalf("resolve VFS journal directory: %v", err)
	}

	expected := filepath.Join(stateHome, "carrack", "vfs", "journals")
	if resolved != expected {
		t.Fatalf("resolved %q, want %q", resolved, expected)
	}
}

func TestSingleLineVFSJournalFieldEscapesTableControls(t *testing.T) {
	t.Parallel()

	if actual := singleLineVFSJournalField("a\\b\tc\rd\ne"); actual != "a\\\\b\\tc\\rd\\ne" {
		t.Fatalf("unexpected escaped table field %q", actual)
	}
}
