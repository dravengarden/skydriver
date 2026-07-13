package sdk

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/transfer/journal"
)

func TestValidateVFSUploadJournalRejectsDifferentObjectIdentity(t *testing.T) {
	t.Parallel()

	handle, err := localfs.Open("local-main", t.TempDir())
	if err != nil {
		t.Fatalf("open local driver: %v", err)
	}

	staged := encodedVFSStaging{
		path:          filepath.Join(t.TempDir(), "intent.encoded"),
		encodedBytes:  23,
		encodedSHA256: strings.Repeat("a", 64),
	}
	preparation := VFSPutPreparation{StorageKey: "objects/v2/aa/opaque"}

	newSnapshot := func() journal.Snapshot {
		return journal.Snapshot{
			ID: "10000000000000000000000000000001", Direction: journal.DirectionUpload,
			Status: journal.StatusTransferring,
			Upload: &journal.UploadPlan{
				Driver: handle.Descriptor, StorageKey: preparation.StorageKey,
				SizeBytes: staged.encodedBytes, Checksum: staged.encodedSHA256,
				Source: journal.SourceIdentity{
					Kind: "local-file/v1", Reference: staged.path, Version: "stable",
					SizeBytes: staged.encodedBytes, Checksum: staged.encodedSHA256,
				},
			},
		}
	}

	if err := validateVFSUploadJournal(
		newSnapshot(), staged, preparation, handle, journal.UploadOptions{},
	); err != nil {
		t.Fatalf("matching VFS upload journal was rejected: %v", err)
	}

	cases := map[string]func(*journal.Snapshot){
		"aborted": func(snapshot *journal.Snapshot) {
			snapshot.Status = journal.StatusAborted
		},
		"download": func(snapshot *journal.Snapshot) {
			snapshot.Direction = journal.DirectionDownload
		},
		"driver": func(snapshot *journal.Snapshot) {
			snapshot.Upload.Driver.ID = "other-driver"
		},
		"source": func(snapshot *journal.Snapshot) {
			snapshot.Upload.Source.Reference = staged.path + ".other"
		},
		"storage-key": func(snapshot *journal.Snapshot) {
			snapshot.Upload.StorageKey = "objects/v2/bb/other"
		},
		"checksum": func(snapshot *journal.Snapshot) {
			snapshot.Upload.Checksum = strings.Repeat("b", 64)
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			snapshot := newSnapshot()
			mutate(&snapshot)

			err := validateVFSUploadJournal(snapshot, staged, preparation, handle, journal.UploadOptions{})
			if !errors.Is(err, ErrVFSPutIntegrity) {
				t.Fatalf("different %s journal was not an integrity error: %v", name, err)
			}
		})
	}
}
