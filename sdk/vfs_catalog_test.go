package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/dravengarden/carrack/sdk"
	"github.com/dravengarden/carrack/vfs/merkle"
)

const (
	catalogRootDirectoryID  = "11111111111111111111111111111111"
	catalogChildDirectoryID = "22222222222222222222222222222222"
	catalogFilesystemID     = "33333333333333333333333333333333"
	catalogFileID           = "44444444444444444444444444444444"
	catalogVersionID        = "55555555555555555555555555555555"
	catalogNodeSchema       = "carrack.vfs.catalog-node.v1"
)

func TestVFSCatalogStoreRejectsCorruption(t *testing.T) {
	t.Parallel()

	empty, err := merkle.BuildDirectory(nil)
	if err != nil {
		t.Fatalf("build empty directory: %v", err)
	}

	rootPath := filepath.Join(t.TempDir(), "catalog")

	store, err := sdk.NewVFSCatalogStore(rootPath)
	if err != nil {
		t.Fatalf("open catalog store: %v", err)
	}

	node := sdk.VFSCatalogNode{
		Schema: catalogNodeSchema, DirectoryID: catalogRootDirectoryID,
		DataRoot: empty.Root.String(), Entries: []sdk.VFSCatalogEntry{},
	}

	if saveErr := store.Save(node); saveErr != nil {
		t.Fatalf("save catalog node: %v", saveErr)
	}

	loaded, err := store.Load(catalogRootDirectoryID, empty.Root.String())
	if err != nil {
		t.Fatalf("load catalog node: %v", err)
	}

	if loaded.DirectoryID != catalogRootDirectoryID || loaded.DataRoot != empty.Root.String() {
		t.Fatalf("unexpected loaded node: %#v", loaded)
	}

	missingRoot := hex.EncodeToString(bytes.Repeat([]byte{9}, sha256.Size))
	if _, loadErr := store.Load(catalogRootDirectoryID, missingRoot); !errors.Is(loadErr, sdk.ErrVFSCatalogNodeNotFound) {
		t.Fatalf("expected cache miss, got %v", loadErr)
	}

	storagePath := filepath.Join(
		rootPath,
		"nodes",
		empty.Root.String()[:2],
		catalogRootDirectoryID+"-"+empty.Root.String()+".json",
	)
	if writeErr := os.WriteFile(storagePath, []byte("{}\n"), 0o600); writeErr != nil {
		t.Fatalf("corrupt catalog fixture: %v", writeErr)
	}

	if _, loadErr := store.Load(catalogRootDirectoryID, empty.Root.String()); !errors.Is(loadErr, sdk.ErrVFSCatalogCorrupt) {
		t.Fatalf("expected corrupt catalog, got %v", loadErr)
	}
}

func TestVFSCatalogSyncReusesVerifiedSubtrees(t *testing.T) {
	t.Parallel()

	fixture := newVFSCatalogFixture(t)
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)

	token, err := sdk.ParseVFSToken(fixture.encodedToken)
	if err != nil {
		t.Fatalf("parse VFS token: %v", err)
	}
	defer token.Clear()

	client, err := sdk.NewVFSControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct VFS control client: %v", err)
	}
	defer client.Clear()

	store, err := sdk.NewVFSCatalogStore(filepath.Join(t.TempDir(), "catalog"))
	if err != nil {
		t.Fatalf("open VFS catalog store: %v", err)
	}

	options := sdk.VFSCatalogSyncOptions{PageSize: 1, MaxConcurrency: 2}

	first, err := client.SyncCatalog(context.Background(), catalogRootDirectoryID, store, options)
	if err != nil {
		t.Fatalf("first catalog synchronization: %v", err)
	}

	if first.Directories != 2 || first.Entries != 2 || first.FetchedNodes != 2 || first.ReusedNodes != 0 {
		t.Fatalf("unexpected first catalog result: %#v", first)
	}

	second, err := client.SyncCatalog(context.Background(), catalogRootDirectoryID, store, options)
	if err != nil {
		t.Fatalf("second catalog synchronization: %v", err)
	}

	if second.RootDataRoot != first.RootDataRoot || second.FetchedNodes != 0 || second.ReusedNodes != 2 {
		t.Fatalf("unexpected second catalog result: %#v", second)
	}

	if fixture.rootStarts.Load() != 4 || fixture.rootContinuations.Load() != 1 ||
		fixture.childReads.Load() != 1 {
		t.Fatalf(
			"unexpected metadata calls: root=%d continuation=%d child=%d",
			fixture.rootStarts.Load(),
			fixture.rootContinuations.Load(),
			fixture.childReads.Load(),
		)
	}
}

type vfsCatalogFixture struct {
	encodedToken      string
	rootDirectory     sdk.VFSDirectory
	childDirectory    sdk.VFSDirectory
	rootEntries       []sdk.VFSDirectoryEntry
	rootStarts        atomic.Int64
	rootContinuations atomic.Int64
	childReads        atomic.Int64
}

func newVFSCatalogFixture(t *testing.T) *vfsCatalogFixture {
	t.Helper()

	fileRootBytes := sha256.Sum256([]byte("catalog file"))

	fileRoot, err := merkle.ParseDigest(hex.EncodeToString(fileRootBytes[:]))
	if err != nil {
		t.Fatalf("parse file root: %v", err)
	}

	fileID := mustCatalogIdentifier(t, catalogFileID)
	versionID := mustCatalogIdentifier(t, catalogVersionID)
	childID := mustCatalogIdentifier(t, catalogChildDirectoryID)

	childTree, err := merkle.BuildDirectory(nil)
	if err != nil {
		t.Fatalf("build child tree: %v", err)
	}

	rootTree, err := merkle.BuildDirectory([]merkle.DirectoryEntry{
		{
			Name: "a.txt", Kind: merkle.EntryFile, StableID: fileID, VersionID: versionID,
			SizeBytes: 12, DataRoot: fileRoot, MetadataRoot: merkle.EmptyMetadataRoot(),
		},
		{
			Name: "child", Kind: merkle.EntryDirectory, StableID: childID,
			DataRoot: childTree.Root,
		},
	})
	if err != nil {
		t.Fatalf("build root tree: %v", err)
	}

	fileIDText := catalogFileID
	versionIDText := catalogVersionID
	childIDText := catalogChildDirectoryID
	metadataRoot := merkle.EmptyMetadataRoot().String()
	rootID := catalogRootDirectoryID

	return &vfsCatalogFixture{
		encodedToken: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		rootDirectory: sdk.VFSDirectory{
			ID: catalogRootDirectoryID, FilesystemID: catalogFilesystemID,
			DataRoot: rootTree.Root.String(), CryptoSuite: sdk.VFSPlaintextSuite,
			ActiveKeyEpoch: 1, ACLInherits: false, Revision: 3, ACLRevision: 1,
			PlacementRevision: 1,
		},
		childDirectory: sdk.VFSDirectory{
			ID: catalogChildDirectoryID, FilesystemID: catalogFilesystemID,
			ParentID: &rootID, Name: "child", DataRoot: childTree.Root.String(),
			CryptoSuite: sdk.VFSPlaintextSuite, ActiveKeyEpoch: 1, ACLInherits: true,
			Revision: 1, ACLRevision: 1, PlacementRevision: 1,
		},
		rootEntries: []sdk.VFSDirectoryEntry{
			{
				Name: "a.txt", Kind: "file", FileID: &fileIDText, VersionID: &versionIDText,
				SizeBytes: 12, DataRoot: fileRoot.String(), MetadataRoot: &metadataRoot,
				Revision: 1, UpdatedAt: 1,
			},
			{
				Name: "child", Kind: "directory", ChildDirectoryID: &childIDText,
				DataRoot: childTree.Root.String(), Revision: 1, UpdatedAt: 1,
			},
		},
	}
}

func (fixture *vfsCatalogFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "Bearer "+fixture.encodedToken {
		http.Error(writer, "missing bearer", http.StatusUnauthorized)

		return
	}

	writer.Header().Set("Content-Type", "application/json")

	var page sdk.VFSDirectoryPage

	switch request.URL.Path {
	case "/api/v2/directories/" + catalogRootDirectoryID + "/entries":
		if request.URL.Query().Get("cursor") == "next" {
			fixture.rootContinuations.Add(1)
			page = sdk.VFSDirectoryPage{
				Schema: "carrack.vfs.directory-list.v1", Directory: fixture.rootDirectory,
				Entries: fixture.rootEntries[1:],
			}
		} else {
			fixture.rootStarts.Add(1)
			page = sdk.VFSDirectoryPage{
				Schema: "carrack.vfs.directory-list.v1", Directory: fixture.rootDirectory,
				Entries: fixture.rootEntries[:1], NextCursor: "next",
			}
		}
	case "/api/v2/directories/" + catalogChildDirectoryID + "/entries":
		fixture.childReads.Add(1)
		page = sdk.VFSDirectoryPage{
			Schema: "carrack.vfs.directory-list.v1", Directory: fixture.childDirectory,
			Entries: []sdk.VFSDirectoryEntry{},
		}
	default:
		http.NotFound(writer, request)

		return
	}

	if err := json.NewEncoder(writer).Encode(page); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func mustCatalogIdentifier(t *testing.T, encoded string) merkle.Identifier {
	t.Helper()

	identifier, err := merkle.ParseIdentifier(encoded)
	if err != nil {
		t.Fatalf("parse catalog identifier: %v", err)
	}

	return identifier
}
