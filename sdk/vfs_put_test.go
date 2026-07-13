package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/sdk"
	"github.com/dravengarden/carrack/vfs/cryptofile"
	"github.com/dravengarden/carrack/vfs/merkle"
)

const (
	testVFSDirectoryID  = "10000000000000000000000000000001"
	testVFSFilesystemID = "20000000000000000000000000000002"
	testVFSIntentID     = "30000000000000000000000000000003"
	testVFSFileID       = "40000000000000000000000000000004"
	testVFSVersionID    = "50000000000000000000000000000005"
	testVFSLocationID   = "60000000000000000000000000000006"
	testVFSDriverID     = "local-main"
	testVFSStorageKey   = "objects/v2/7f/opaque-complete-object"
	testVFSManifestKey  = "vfs/blocks/v1/7f/manifest"
)

func TestVFSClientPutBytesPublishesEncryptedAndPlaintextCompleteObjects(t *testing.T) {
	t.Parallel()

	for _, suite := range []string{sdk.VFSEncryptedSuite, sdk.VFSPlaintextSuite} {
		t.Run(suite, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			providerRoot := privateTestDirectory(t, root, "provider")
			journalRoot := privateTestDirectory(t, root, "journals")
			stagingRoot := privateTestDirectory(t, root, "staging")
			payload := []byte("complete Carrack VFS payload across several frames")
			fixture := newVFSPutControlFixture(t, providerRoot, payload, suite)
			server := httptest.NewServer(fixture)
			t.Cleanup(server.Close)

			var token sdk.VFSToken
			for index := range token {
				token[index] = byte(index + 1)
			}

			control, err := sdk.NewVFSControlClient(server.URL, token, server.Client())
			if err != nil {
				t.Fatalf("construct VFS control client: %v", err)
			}

			registry := driver.NewRegistry()
			if registerErr := registry.Register(localfs.Kind, localfs.Factory); registerErr != nil {
				t.Fatalf("register localfs: %v", registerErr)
			}

			client, err := sdk.NewVFSClient(control, registry, sdk.VFSClientOptions{
				JournalDirectory: journalRoot,
				StagingDirectory: stagingRoot,
				MaxConcurrency:   4,
			})
			if err != nil {
				t.Fatalf("construct VFS client: %v", err)
			}

			options := sdk.VFSPutOptions{
				DirectoryID:            testVFSDirectoryID,
				EntryName:              "release.bin",
				PreferredDriverID:      testVFSDriverID,
				IdempotencyKey:         "sdk-vfs-put-complete-object-v1",
				VerificationBlockBytes: 16,
				EncryptionFrameBytes:   8,
				UploadPartBytes:        11,
			}

			first, err := client.PutBytes(context.Background(), "release-payload", payload, options)
			if err != nil {
				t.Fatalf("put VFS bytes: %v", err)
			}

			second, err := client.PutBytes(context.Background(), "release-payload", payload, options)
			if err != nil {
				t.Fatalf("replay VFS bytes: %v", err)
			}

			if !equalVFSReceipt(first.Receipt, second.Receipt) || first.Receipt.State != "committed" ||
				first.Receipt.VersionID != testVFSVersionID || first.Receipt.DriverID != testVFSDriverID ||
				first.PlaintextBytes != uint64(len(payload)) || first.FileRoot == "" ||
				first.JournalID == second.JournalID {
				t.Fatalf("unexpected VFS Put results: first=%+v second=%+v", first, second)
			}

			encoded, err := os.ReadFile(filepath.Join(providerRoot, filepath.FromSlash(testVFSStorageKey)))
			if err != nil {
				t.Fatalf("read provider object: %v", err)
			}

			if suite == sdk.VFSEncryptedSuite && bytes.Contains(encoded, payload) {
				t.Fatal("encrypted provider object exposed plaintext")
			}

			if suite == sdk.VFSPlaintextSuite && !bytes.Equal(encoded, payload) {
				t.Fatal("plaintext provider object differs")
			}

			stagingEntries, err := os.ReadDir(stagingRoot)
			if err != nil {
				t.Fatalf("read staging directory: %v", err)
			}

			if len(stagingEntries) != 0 {
				t.Fatalf("successful Put retained staging files: %v", stagingEntries)
			}

			fixture.assertComplete(t, 2)
		})
	}
}

func TestVFSClientPutResumesDurableJournalAfterLostCommitResponse(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	providerRoot := privateTestDirectory(t, root, "provider")
	journalRoot := privateTestDirectory(t, root, "journals")
	stagingRoot := privateTestDirectory(t, root, "staging")
	payload := []byte("resume this exact encrypted complete object")
	fixture := newVFSPutControlFixture(t, providerRoot, payload, sdk.VFSEncryptedSuite)
	fixture.failCommitOnce = true
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)

	var token sdk.VFSToken
	for index := range token {
		token[index] = byte(index + 1)
	}

	control, err := sdk.NewVFSControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct VFS control client: %v", err)
	}

	registry := driver.NewRegistry()
	if registerErr := registry.Register(localfs.Kind, localfs.Factory); registerErr != nil {
		t.Fatalf("register localfs: %v", registerErr)
	}

	client, err := sdk.NewVFSClient(control, registry, sdk.VFSClientOptions{
		JournalDirectory: journalRoot,
		StagingDirectory: stagingRoot,
		MaxConcurrency:   4,
	})
	if err != nil {
		t.Fatalf("construct VFS client: %v", err)
	}

	options := sdk.VFSPutOptions{
		DirectoryID:            testVFSDirectoryID,
		EntryName:              "resumed-release.bin",
		PreferredDriverID:      testVFSDriverID,
		IdempotencyKey:         "sdk-vfs-put-resume-v1",
		VerificationBlockBytes: 16,
		EncryptionFrameBytes:   8,
		UploadPartBytes:        7,
	}

	if _, putErr := client.PutBytes(context.Background(), "resumable-release", payload, options); putErr == nil {
		t.Fatal("Put unexpectedly accepted the lost commit response")
	} else {
		var recovery *sdk.VFSPutRecoveryError
		if !errors.As(putErr, &recovery) || recovery.JournalID == "" {
			t.Fatalf("Put error omitted its durable recovery journal: %v", putErr)
		}

		options.ResumeJournalID = recovery.JournalID
	}

	journalEntries, err := os.ReadDir(journalRoot)
	if err != nil || len(journalEntries) != 1 {
		t.Fatalf("lost response did not retain exactly one journal: entries=%v err=%v", journalEntries, err)
	}

	resumed, err := client.PutBytes(context.Background(), "resumable-release", payload, options)
	if err != nil {
		t.Fatalf("resume VFS Put: %v", err)
	}

	if resumed.JournalID != options.ResumeJournalID || resumed.Receipt.State != "committed" {
		t.Fatalf("resume used a different journal or receipt: %+v", resumed)
	}

	journalEntries, err = os.ReadDir(journalRoot)
	if err != nil || len(journalEntries) != 1 {
		t.Fatalf("resume allocated another journal: entries=%v err=%v", journalEntries, err)
	}

	stagingEntries, err := os.ReadDir(stagingRoot)
	if err != nil || len(stagingEntries) != 0 {
		t.Fatalf("successful resume retained encoded staging: entries=%v err=%v", stagingEntries, err)
	}

	fixture.assertComplete(t, 2)
}

type vfsPutControlFixture struct {
	t              *testing.T
	providerRoot   string
	payload        []byte
	suite          string
	directoryKey   cryptofile.DirectoryKey
	mutex          sync.Mutex
	prepared       *sdk.PrepareVFSPutRequest
	committed      *sdk.CommitVFSPutRequest
	prepareCalls   int
	keyCalls       int
	driverCalls    int
	manifestCalls  int
	commitCalls    int
	failCommitOnce bool
}

func newVFSPutControlFixture(
	t *testing.T,
	providerRoot string,
	payload []byte,
	suite string,
) *vfsPutControlFixture {
	t.Helper()

	fixture := &vfsPutControlFixture{t: t, providerRoot: providerRoot, payload: bytes.Clone(payload), suite: suite}
	for index := range fixture.directoryKey {
		fixture.directoryKey[index] = byte(0xa0 + index)
	}

	return fixture
}

func (fixture *vfsPutControlFixture) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	fixture.t.Helper()

	if request.Header.Get("Authorization") == "" {
		http.Error(response, "missing bearer", http.StatusUnauthorized)
		return
	}

	switch request.URL.Path {
	case "/api/v2/puts/prepare":
		fixture.servePrepare(response, request)
	case "/api/v2/puts/" + testVFSIntentID + "/key-grant":
		fixture.serveKeyGrant(response)
	case "/api/v2/puts/" + testVFSIntentID + "/driver-grant":
		fixture.serveDriverGrant(response)
	case "/api/v2/puts/" + testVFSIntentID + "/block-manifest":
		fixture.serveManifest(response, request)
	case "/api/v2/puts/" + testVFSIntentID + "/commit":
		fixture.serveCommit(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (fixture *vfsPutControlFixture) servePrepare(response http.ResponseWriter, request *http.Request) {
	var prepared sdk.PrepareVFSPutRequest
	decodeTestJSON(fixture.t, request.Body, &prepared)

	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()

	fixture.prepareCalls++
	if fixture.prepared == nil {
		captured := prepared
		fixture.prepared = &captured
	} else if !equalVFSPrepare(*fixture.prepared, prepared) {
		http.Error(response, "idempotency changed", http.StatusConflict)
		return
	}

	state := "prepared"
	if fixture.committed != nil {
		state = "committed"
	}

	writeTestJSON(fixture.t, response, sdk.VFSPutPreparation{
		Schema: "carrack.vfs.put-preparation.v1", IntentID: testVFSIntentID,
		FilesystemID: testVFSFilesystemID, DirectoryID: prepared.DirectoryID,
		EntryName: prepared.EntryName, ExpectedEntryRevision: prepared.ExpectedEntryRevision,
		FileID: testVFSFileID, VersionID: testVFSVersionID, LocationID: testVFSLocationID,
		DriverID: testVFSDriverID, StorageKey: testVFSStorageKey,
		BlockManifestR2Key: testVFSManifestKey, CryptoSuite: fixture.suite, KeyEpoch: 1,
		EncryptionFrameBytes:  prepared.EncryptionFrameBytes,
		RequiresEncryptionKey: fixture.suite == sdk.VFSEncryptedSuite,
		State:                 state, ExpiresAt: 4_102_444_800,
	})
}

func (fixture *vfsPutControlFixture) serveKeyGrant(response http.ResponseWriter) {
	fixture.mutex.Lock()
	fixture.keyCalls++
	fixture.mutex.Unlock()

	var encodedKey any
	if fixture.suite == sdk.VFSEncryptedSuite {
		encodedKey = base64.RawURLEncoding.EncodeToString(fixture.directoryKey[:])
	}

	writeTestJSON(fixture.t, response, map[string]any{
		"schema": "carrack.vfs.directory-key-grant.v1", "intent_id": testVFSIntentID,
		"directory_id": testVFSDirectoryID, "version_id": testVFSVersionID,
		"crypto_suite": fixture.suite, "key_epoch": 1, "directory_key": encodedKey,
		"expires_at": 4_102_444_800,
	})
}

func (fixture *vfsPutControlFixture) serveDriverGrant(response http.ResponseWriter) {
	fixture.mutex.Lock()
	fixture.driverCalls++
	fixture.mutex.Unlock()

	writeTestJSON(fixture.t, response, map[string]any{
		"schema": "carrack.vfs.driver-grant.v1", "intent_id": testVFSIntentID,
		"driver_id": testVFSDriverID, "driver_kind": localfs.Kind, "driver_revision": 1,
		"config": map[string]any{"root": fixture.providerRoot}, "credential": nil,
		"expires_at": 4_102_444_800,
	})
}

func (fixture *vfsPutControlFixture) serveManifest(response http.ResponseWriter, request *http.Request) {
	encoded, err := io.ReadAll(request.Body)
	if err != nil {
		fixture.t.Fatalf("read block manifest: %v", err)
	}

	tree, err := merkle.ParseFileBlockManifest(encoded)
	if err != nil || fixture.prepared == nil || tree.Root.String() != fixture.prepared.FileRoot {
		http.Error(response, "bad manifest", http.StatusConflict)
		return
	}

	digest := sha256.Sum256(encoded)

	fixture.mutex.Lock()
	fixture.manifestCalls++
	fixture.mutex.Unlock()
	writeTestJSON(fixture.t, response, map[string]any{
		"schema": "carrack.vfs.block-manifest-stage.v1", "intent_id": testVFSIntentID,
		"sha256": hex.EncodeToString(digest[:]), "bytes": len(encoded),
		"r2_key": testVFSManifestKey, "r2_version": "manifest-version-1",
	})
}

func (fixture *vfsPutControlFixture) serveCommit(response http.ResponseWriter, request *http.Request) {
	var committed sdk.CommitVFSPutRequest

	decodeTestJSON(fixture.t, request.Body, &committed)

	encoded, err := os.ReadFile(filepath.Join(fixture.providerRoot, filepath.FromSlash(testVFSStorageKey)))
	if err != nil {
		http.Error(response, "provider object missing", http.StatusConflict)
		return
	}

	digest := sha256.Sum256(encoded)

	if committed.EncodedBytes != uint64(len(encoded)) || committed.EncodedSHA256 != hex.EncodeToString(digest[:]) {
		http.Error(response, "provider identity differs", http.StatusConflict)
		return
	}

	if fixture.suite == sdk.VFSEncryptedSuite {
		directoryID, _ := merkle.ParseIdentifier(testVFSDirectoryID)
		versionID, _ := merkle.ParseIdentifier(testVFSVersionID)
		cipher, cipherErr := cryptofile.New(fixture.directoryKey, cryptofile.Descriptor{
			Suite: fixture.suite, DirectoryID: directoryID, VersionID: versionID, KeyEpoch: 1,
			FrameBytes: fixture.prepared.EncryptionFrameBytes, PlaintextBytes: uint64(len(fixture.payload)),
		})

		var plaintext bytes.Buffer

		if cipherErr != nil {
			fixture.t.Fatalf("construct verification cipher: %v", cipherErr)
		}

		if _, openErr := cipher.Open(request.Context(), &plaintext, bytes.NewReader(encoded)); openErr != nil ||
			!bytes.Equal(plaintext.Bytes(), fixture.payload) {
			http.Error(response, "encrypted object differs", http.StatusConflict)
			return
		}
	}

	fixture.mutex.Lock()

	fixture.commitCalls++
	if fixture.committed == nil {
		captured := committed
		fixture.committed = &captured
	} else if !equalVFSCommit(*fixture.committed, committed) {
		fixture.mutex.Unlock()
		http.Error(response, "commit identity changed", http.StatusConflict)

		return
	}

	lostResponse := fixture.failCommitOnce
	fixture.failCommitOnce = false
	fixture.mutex.Unlock()

	if lostResponse {
		http.Error(response, "commit response lost", http.StatusServiceUnavailable)

		return
	}

	writeTestJSON(fixture.t, response, map[string]any{
		"schema": "carrack.vfs.put-receipt.v1", "intent_id": testVFSIntentID,
		"file_id": testVFSFileID, "version_id": testVFSVersionID, "location_id": testVFSLocationID,
		"driver_id": testVFSDriverID, "storage_key": testVFSStorageKey,
		"block_manifest_r2_version": committed.BlockManifestR2Version,
		"encoded_bytes":             committed.EncodedBytes, "encoded_sha256": committed.EncodedSHA256,
		"verification_method": committed.VerificationMethod, "native_id": committed.NativeID,
		"provider_version": committed.ProviderVersion, "etag": committed.ETag,
		"entry_revision": 1, "catalog_revision_id": 1, "committed_at": 1_750_000_000,
		"state": "committed",
	})
}

func (fixture *vfsPutControlFixture) assertComplete(t *testing.T, calls int) {
	t.Helper()
	fixture.mutex.Lock()
	defer fixture.mutex.Unlock()

	if fixture.prepareCalls != calls || fixture.keyCalls != calls || fixture.driverCalls != calls ||
		fixture.manifestCalls != calls || fixture.commitCalls != calls {
		t.Fatalf(
			"incomplete VFS protocol calls: prepare=%d key=%d driver=%d manifest=%d commit=%d",
			fixture.prepareCalls, fixture.keyCalls, fixture.driverCalls, fixture.manifestCalls, fixture.commitCalls,
		)
	}
}

func equalVFSCommit(left, right sdk.CommitVFSPutRequest) bool {
	return reflect.DeepEqual(left, right)
}

func equalVFSPrepare(left, right sdk.PrepareVFSPutRequest) bool {
	return reflect.DeepEqual(left, right)
}

func equalVFSReceipt(left, right sdk.VFSPutReceipt) bool {
	return reflect.DeepEqual(left, right)
}

func privateTestDirectory(t *testing.T, parent, name string) string {
	t.Helper()

	directory := filepath.Join(parent, name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create private directory: %v", err)
	}

	return directory
}

func decodeTestJSON(t *testing.T, reader io.Reader, destination any) {
	t.Helper()

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode test JSON: %v", err)
	}
}

func ExampleParseVFSToken() {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	token, err := sdk.ParseVFSToken(encoded)
	fmt.Println(err == nil, token[0])
	token.Clear()

	// Output: true 1
}
