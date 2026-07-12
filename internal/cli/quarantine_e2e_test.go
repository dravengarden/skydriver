package cli

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
	"testing"
	"time"

	"github.com/dravengarden/carrack/sdk"
)

func TestQuarantineAcknowledgeCommandCommitsExactRevision(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))

	const (
		operationID = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
		incarnation = "0123456789abcdef0123456789abcdef"
		namespaceID = "202122232425262728292a2b2c2d2e2f"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/quarantine-actions":
			var body struct {
				Action           sdk.QuarantineAction `json:"action"`
				ExpectedRevision uint64               `json:"expected_revision"`
				StorageKey       string               `json:"storage_key"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode CLI quarantine action: %v", err)
			}

			if body.Action != sdk.QuarantineActionAcknowledge || body.ExpectedRevision != 7 ||
				body.StorageKey != "archive/objects/orphan" {
				t.Errorf("unexpected CLI quarantine request: %+v", body)
			}

			value = sdk.QuarantineActionOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: "gc", State: "planned",
				Phase: "planned", RequestedBy: "cli-client", Incarnation: incarnation,
				Revision: 1, Action: sdk.QuarantineActionAcknowledge, DriverID: "local-main",
				DriverRevision: 1, StorageKey: "archive/objects/orphan", ExpectedRevision: 7,
				SizeBytes: 13, Reason: "checked recovery ownership", GraceSeconds: 90,
				CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-client", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/quarantine-actions/" + operationID + "/complete":
			value = sdk.CompletedQuarantineAction{
				OperationID: operationID, Action: sdk.QuarantineActionAcknowledge,
				State: "succeeded", QuarantineState: "acknowledged", QuarantineRevision: 8,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode CLI quarantine response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv(controlTokenEnvironment, token)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{
		"quarantine", "acknowledge", "--control-url", server.URL,
		"--namespace", namespaceID, "--driver-id", "local-main",
		"--storage-key", "archive/objects/orphan", "--expected-revision", "7",
		"--reason", "checked recovery ownership",
		"--idempotency-key", "acknowledge-orphan-v7", "--format", "json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run quarantine acknowledge command: %v", err)
	}

	var result struct {
		Completion sdk.CompletedQuarantineAction `json:"completion"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode quarantine command output: %v", err)
	}

	if result.Completion.QuarantineState != "acknowledged" ||
		result.Completion.QuarantineRevision != 8 {
		t.Fatalf("unexpected quarantine command result: %+v", result)
	}
}

func TestQuarantineSweepCommandDeletesExactLocalObject(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32))

	const (
		operationID = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		incarnation = "0123456789abcdef0123456789abcdef"
		storageKey  = "archive/orphan"
	)

	root := t.TempDir()

	objectPath := filepath.Join(root, filepath.FromSlash(storageKey))
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		t.Fatalf("create quarantine object directory: %v", err)
	}

	content := []byte("orphaned ciphertext")
	if err := os.WriteFile(objectPath, content, 0o600); err != nil {
		t.Fatalf("write quarantine object: %v", err)
	}

	digestBytes := sha256.Sum256(content)
	digest := hex.EncodeToString(digestBytes[:])
	version := "sha256:" + digest
	etag := digest

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		task := sdk.QuarantineDeleteTask{
			TaskID: operationID + "/quarantine-delete", OperationID: operationID,
			DriverID: "local-main", DriverRevision: 1, StorageKey: storageKey,
			ExpectedRevision: 4, ProviderVersion: &version, ETag: &etag,
			SizeBytes: uint64(len(content)), DeleteAfter: 1, OwnerClientID: "cli-client",
			Incarnation: incarnation, LeaseExpiresAt: uint64(time.Now().Add(time.Minute).Unix()),
			AttemptCount: 1, State: "claimed",
		}

		var value any

		switch request.URL.Path {
		case "/api/v1/quarantine-actions/" + operationID + "/deletes/claim":
			task.FencingToken = 1
			value = sdk.QuarantineDeleteClaim{State: "claimed", Task: &task}
		case "/api/v1/quarantine-deletes/revalidate":
			task.FencingToken = 2
			value = task
		case "/api/v1/quarantine-deletes/complete":
			var body struct {
				FencingToken uint64 `json:"fencing_token"`
				Outcome      string `json:"outcome"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode CLI quarantine delete completion: %v", err)
			}

			if body.FencingToken != 2 || body.Outcome != "deleted" {
				t.Errorf("unexpected CLI quarantine completion: %+v", body)
			}

			value = sdk.CompletedQuarantineDelete{
				TaskID: task.TaskID, OperationID: operationID, QuarantineRevision: 5,
				TaskState: "deleted", QuarantineState: "deleted", Outcome: "deleted",
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode CLI quarantine delete response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv(controlTokenEnvironment, token)

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{
		"quarantine", "sweep", operationID, "--control-url", server.URL,
		"--local-driver-id", "local-main", "--local-root", root, "--format", "json",
	}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run quarantine sweep command: %v", err)
	}

	if _, err := os.Stat(objectPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("quarantine sweep retained local object: %v", err)
	}

	var result sdk.QuarantineSweepResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode quarantine sweep output: %v", err)
	}

	if result.State != "deleted" || result.ObjectsDeleted != 1 {
		t.Fatalf("unexpected quarantine sweep output: %+v", result)
	}
}
