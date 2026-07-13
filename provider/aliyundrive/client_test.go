package aliyundrive

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/provider"
)

const testPayload = "carrack!!"

type fakeDrive struct {
	testing *testing.T

	mutex         sync.Mutex
	serverURL     string
	folderCreated bool
	fileCompleted bool
	uploaded      bytes.Buffer
	completedSize int64
}

func (drive *fakeDrive) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	drive.testing.Helper()

	if strings.HasPrefix(request.URL.Path, "/adrive/") && request.Header.Get("Authorization") != "Bearer access-token" {
		drive.testing.Errorf("API request omitted bearer token: %s", request.URL.Path)
	}

	switch request.URL.Path {
	case "/adrive/v1.0/user/getDriveInfo":
		drive.writeJSON(writer, map[string]string{"resource_drive_id": "drive-1"})
	case "/adrive/v1.0/openFile/list":
		drive.list(writer, request)
	case "/adrive/v1.0/openFile/create":
		drive.create(writer, request)
	case "/adrive/v1.0/openFile/complete":
		drive.complete(writer)
	case "/adrive/v1.0/openFile/getDownloadUrl":
		drive.writeJSON(writer, map[string]string{"url": drive.serverURL + "/download"})
	case "/upload/1", "/upload/2", "/upload/3":
		drive.upload(writer, request)
	case "/download":
		drive.download(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (drive *fakeDrive) list(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		ParentFileID string `json:"parent_file_id"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		drive.testing.Errorf("decode list request: %v", err)
	}

	drive.mutex.Lock()
	defer drive.mutex.Unlock()

	items := make([]fileRecord, 0, 1)
	if input.ParentFileID == "root" && drive.folderCreated {
		items = append(items, fileRecord{FileID: "folder-1", Name: "archive", Type: "folder"})
	}

	if input.ParentFileID == "folder-1" && drive.fileCompleted {
		items = append(items, fileRecord{
			FileID:      "file-1",
			Name:        "block.bin",
			Size:        drive.completedSize,
			ContentHash: "sha1-value",
			Type:        "file",
		})
	}

	drive.writeJSON(writer, listResponse{Items: items, NextMarker: ""})
}

func (drive *fakeDrive) create(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Type         string        `json:"type"`
		PartInfoList []partRequest `json:"part_info_list"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		drive.testing.Errorf("decode create request: %v", err)
	}

	if input.Type == "folder" {
		drive.mutex.Lock()
		drive.folderCreated = true
		drive.mutex.Unlock()
		drive.writeJSON(writer, fileRecord{FileID: "folder-1", Type: "folder"})

		return
	}

	parts := make([]partInformation, len(input.PartInfoList))
	for index := range parts {
		parts[index] = partInformation{PartNumber: index + 1, UploadURL: fmt.Sprintf("%s/upload/%d", drive.serverURL, index+1)}
	}

	drive.writeJSON(writer, createFileResponse{FileID: "file-1", UploadID: "upload-1", PartInfoList: parts})
}

func (drive *fakeDrive) upload(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Authorization") != "" {
		drive.testing.Error("signed upload request unexpectedly included bearer token")
	}

	body, err := io.ReadAll(request.Body)
	if err != nil {
		drive.testing.Errorf("read upload request: %v", err)
	}

	drive.mutex.Lock()
	_, _ = drive.uploaded.Write(body)
	drive.mutex.Unlock()
	writer.WriteHeader(http.StatusOK)
}

func (drive *fakeDrive) complete(writer http.ResponseWriter) {
	drive.mutex.Lock()
	drive.fileCompleted = true
	drive.completedSize = int64(drive.uploaded.Len())
	completedSize := drive.completedSize
	drive.mutex.Unlock()
	drive.writeJSON(writer, fileRecord{
		FileID:      "file-1",
		Name:        "block.bin",
		Size:        completedSize,
		ContentHash: "sha1-value",
		Type:        "file",
	})
}

func TestClientUploadsEmptyObject(t *testing.T) {
	t.Parallel()

	drive := &fakeDrive{testing: t}
	server := httptest.NewServer(drive)
	drive.serverURL = server.URL
	t.Cleanup(server.Close)

	tokenSource, err := NewStaticTokenSource("access-token")
	if err != nil {
		t.Fatalf("create token source: %v", err)
	}

	client, err := NewClient(Options{
		HTTPClient: server.Client(), TokenSource: tokenSource, APIBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	object, err := client.Put(context.Background(), "empty.bin", bytes.NewReader(nil), provider.PutOptions{})
	if err != nil {
		t.Fatalf("upload empty object: %v", err)
	}

	if object.SizeBytes != 0 || drive.uploaded.Len() != 0 {
		t.Fatalf("unexpected empty object result: object=%+v uploaded=%d", object, drive.uploaded.Len())
	}
}

func (drive *fakeDrive) download(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Range") != "bytes=2-5" {
		drive.testing.Errorf("unexpected range header %q", request.Header.Get("Range"))
	}

	writer.Header().Set("Content-Range", fmt.Sprintf("bytes 2-5/%d", len(testPayload)))
	writer.WriteHeader(http.StatusPartialContent)
	_, _ = io.WriteString(writer, testPayload[2:6])
}

func (drive *fakeDrive) writeJSON(writer http.ResponseWriter, value any) {
	drive.testing.Helper()
	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(value); err != nil {
		drive.testing.Errorf("encode fake drive response: %v", err)
	}
}

func TestClientUploadsStatsAndDownloadsRange(t *testing.T) {
	t.Parallel()

	drive := &fakeDrive{testing: t}
	server := httptest.NewServer(drive)
	drive.serverURL = server.URL
	t.Cleanup(server.Close)

	tokenSource, err := NewStaticTokenSource("access-token")
	if err != nil {
		t.Fatalf("create token source: %v", err)
	}

	client, err := NewClient(Options{
		HTTPClient:      server.Client(),
		TokenSource:     tokenSource,
		APIBaseURL:      server.URL,
		UploadPartBytes: 4,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	object, err := client.Put(
		context.Background(),
		"archive/block.bin",
		strings.NewReader(testPayload),
		provider.PutOptions{SizeBytes: uint64(len(testPayload))},
	)
	if err != nil {
		t.Fatalf("upload object: %v", err)
	}

	if object.Key != "archive/block.bin" || object.SizeBytes != uint64(len(testPayload)) || object.Version != "file-1" {
		t.Fatalf("unexpected uploaded object: %+v", object)
	}

	drive.mutex.Lock()
	uploaded := drive.uploaded.String()
	drive.mutex.Unlock()

	if uploaded != testPayload {
		t.Fatalf("unexpected uploaded payload %q", uploaded)
	}

	stat, err := client.Stat(context.Background(), "archive/block.bin")
	if err != nil {
		t.Fatalf("stat object: %v", err)
	}

	if stat.ETag != "sha1-value" || stat.SizeBytes != uint64(len(testPayload)) {
		t.Fatalf("unexpected stat result: %+v", stat)
	}

	reader, err := client.OpenRange(context.Background(), "archive/block.bin", 2, 4)
	if err != nil {
		t.Fatalf("open range: %v", err)
	}

	rangeBody, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read range: %v", err)
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("close range: %v", err)
	}

	if string(rangeBody) != testPayload[2:6] {
		t.Fatalf("unexpected range body %q", rangeBody)
	}
}

func TestSplitObjectKeyRejectsNonCanonicalPaths(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"", "/absolute", "../escape", "a//b", "a/../b", `a\b`} {
		if _, err := splitObjectKey(key); err == nil {
			t.Errorf("expected key %q to fail", key)
		}
	}
}

func TestSafeServiceURLRejectsPlaintextRemoteEndpoints(t *testing.T) {
	t.Parallel()

	if safeServiceURL("http://openapi.alipan.com") {
		t.Fatal("expected remote plaintext HTTP to be rejected")
	}

	for _, endpoint := range []string{"https://openapi.alipan.com", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if !safeServiceURL(endpoint) {
			t.Errorf("expected endpoint %q to be accepted", endpoint)
		}
	}
}
