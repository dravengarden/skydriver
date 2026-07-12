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

func TestMoveSweepCommandDeletesAuthorizedLocalObject(t *testing.T) {
	const (
		operationID = "707172737475767778797a7b7c7d7e7f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	root := t.TempDir()
	key := "source/object"

	objectPath := filepath.Join(root, filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(objectPath), 0o700); err != nil {
		t.Fatalf("create move source directory: %v", err)
	}

	if err := os.WriteFile(objectPath, []byte("obsolete ciphertext"), 0o600); err != nil {
		t.Fatalf("write move source object: %v", err)
	}

	var completed atomic.Bool

	control := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/moves/" + operationID + "/deletes/claim":
			if completed.Load() {
				writeCLIJSON(t, response, sdk.MoveDeleteClaim{State: "succeeded"})

				return
			}

			writeCLIJSON(t, response, sdk.MoveDeleteClaim{
				State: "claimed",
				Task: &sdk.MoveDeleteTask{
					TaskID: operationID + "/location", OperationID: operationID,
					DriverID: "local-source", StorageKey: key, ExpectedLocationCount: 1,
					OwnerClientID: "cli-janitor", Incarnation: incarnation,
					FencingToken: 1, LeaseExpiresAt: 1 << 40, AttemptCount: 1, State: "claimed",
				},
			})
		case "/api/v1/moves/deletes/revalidate":
			writeCLIJSON(t, response, sdk.MoveDeleteTask{
				TaskID: operationID + "/location", OperationID: operationID,
				DriverID: "local-source", StorageKey: key, ExpectedLocationCount: 1,
				OwnerClientID: "cli-janitor", Incarnation: incarnation,
				FencingToken: 2, LeaseExpiresAt: 1 << 40, AttemptCount: 1, State: "claimed",
			})
		case "/api/v1/moves/deletes/complete":
			completed.Store(true)
			writeCLIJSON(t, response, sdk.CompletedMoveDelete{
				TaskID: operationID + "/location", OperationID: operationID,
				LocationsDeleted: 1, TaskState: "deleted", MoveState: "succeeded",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(control.Close)

	t.Setenv(controlTokenEnvironment, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)))

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	err := Run(context.Background(), []string{
		moveCommandName, "sweep", operationID,
		"--control-url", control.URL,
		"--local-driver-id", "local-source",
		"--local-root", root,
		"--format", outputFormatJSON,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("execute move sweep: %v; stderr=%s", err, stderr.String())
	}

	if _, err := os.Stat(objectPath); !os.IsNotExist(err) {
		t.Fatalf("move sweep retained source object: %v", err)
	}

	if !strings.Contains(stdout.String(), `"State": "succeeded"`) ||
		!strings.Contains(stdout.String(), `"ObjectsDeleted": 1`) {
		t.Fatalf("unexpected move sweep output: %s", stdout.String())
	}
}
