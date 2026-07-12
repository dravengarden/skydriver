package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
