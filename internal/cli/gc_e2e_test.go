package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestGCMarkCommandCreatesPolicyEpoch(t *testing.T) {
	const (
		namespaceID = "202122232425262728292a2b2c2d2e2f"
		operationID = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	graceUntil := uint64(1_000)
	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/gc/epochs":
			writeCLIJSON(t, response, sdk.GCOperation{
				ID: operationID, NamespaceID: namespaceID, Kind: "gc", State: "planned",
				Phase: "planned", RequestedBy: "cli-admin", Incarnation: incarnation,
				Revision: 1, CutoffAt: 100, GraceSeconds: 60, GCState: "marking",
				CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			writeCLIJSON(t, response, sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "cli-admin", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/gc/" + operationID + "/mark":
			writeCLIJSON(t, response, sdk.GCMark{
				OperationID: operationID, CandidatesMarked: 2, ObjectsMarked: 1,
				GraceUntil: &graceUntil, State: "grace",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)
	t.Setenv(controlTokenEnvironment, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)))

	var stdout bytes.Buffer

	err := Run(context.Background(), []string{
		gcCommandName, "mark", "--control-url", control.URL,
		"--namespace", namespaceID, "--idempotency-key", "gc-retired-generation-1",
		"--format", outputFormatJSON,
	}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("execute GC mark: %v", err)
	}

	if !strings.Contains(stdout.String(), `"candidates_marked": 2`) ||
		!strings.Contains(stdout.String(), `"state": "grace"`) {
		t.Fatalf("unexpected GC mark output: %s", stdout.String())
	}
}

func TestGCSweepCommandDeletesAuthorizedLocalObject(t *testing.T) {
	const (
		operationID = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	root := t.TempDir()
	key := "retired/object"

	objectPath := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		t.Fatalf("create GC source directory: %v", err)
	}

	if err := os.WriteFile(objectPath, []byte("retired ciphertext"), 0o600); err != nil {
		t.Fatalf("write GC source object: %v", err)
	}

	var completed atomic.Bool

	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/gc/" + operationID + "/deletes/claim":
			if completed.Load() {
				writeCLIJSON(t, response, sdk.GCDeleteClaim{State: "succeeded"})

				return
			}

			writeCLIJSON(t, response, sdk.GCDeleteClaim{
				State: "claimed",
				Task: &sdk.GCDeleteTask{
					TaskID: operationID + "/location", OperationID: operationID,
					DriverID: "local-archive", StorageKey: key, ExpectedLocationCount: 1,
					OwnerClientID: "cli-janitor", Incarnation: incarnation, FencingToken: 1,
					LeaseExpiresAt: 1 << 40, AttemptCount: 1, State: "claimed",
				},
			})
		case "/api/v1/gc/deletes/revalidate":
			writeCLIJSON(t, response, sdk.GCDeleteTask{
				TaskID: operationID + "/location", OperationID: operationID,
				DriverID: "local-archive", StorageKey: key, ExpectedLocationCount: 1,
				OwnerClientID: "cli-janitor", Incarnation: incarnation, FencingToken: 2,
				LeaseExpiresAt: 1 << 40, AttemptCount: 1, State: "claimed",
			})
		case "/api/v1/gc/deletes/complete":
			completed.Store(true)
			writeCLIJSON(t, response, sdk.CompletedGCDelete{
				TaskID: operationID + "/location", OperationID: operationID,
				LocationsDeleted: 1, TaskState: "deleted", GCState: "succeeded",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)
	t.Setenv(controlTokenEnvironment, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32)))

	var stdout bytes.Buffer

	err := Run(context.Background(), []string{
		gcCommandName, "sweep", operationID, "--control-url", control.URL,
		"--local-driver-id", "local-archive", "--local-root", root,
		"--format", outputFormatJSON,
	}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("execute GC sweep: %v", err)
	}

	if _, err := os.Stat(objectPath); !os.IsNotExist(err) {
		t.Fatalf("GC sweep retained source object: %v", err)
	}

	if !strings.Contains(stdout.String(), `"State": "succeeded"`) ||
		!strings.Contains(stdout.String(), `"ObjectsDeleted": 1`) {
		t.Fatalf("unexpected GC sweep output: %s", stdout.String())
	}
}
