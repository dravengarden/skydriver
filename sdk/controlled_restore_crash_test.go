package sdk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errInjectedRestoreTerminalCrash = errors.New("injected Carrack restore terminal crash")

type restoreTerminalCrashPoint string

const (
	crashBeforeRestoreComplete restoreTerminalCrashPoint = "before_restore_complete"
	crashAfterRestoreComplete  restoreTerminalCrashPoint = "after_restore_complete"
	crashBeforeRestoreFail     restoreTerminalCrashPoint = "before_restore_fail"
	crashAfterRestoreFail      restoreTerminalCrashPoint = "after_restore_fail"
)

const (
	restoreTerminalOperationID = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	restoreTerminalIncarnation = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	restoreTerminalClientID    = "restore-terminal-client"
	restoreTerminalVersionID   = "restore-terminal-version"
	restoreTerminalLeaseID     = "operation/a0a1a2a3a4a5a6a7a8a9aaabacadaeaf/read"
)

type restoreTerminalCrashScript struct {
	mutex  sync.Mutex
	target restoreTerminalCrashPoint
	fired  bool
}

func (script *restoreTerminalCrashScript) hit(point restoreTerminalCrashPoint) error {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	if script.fired || script.target != point {
		return nil
	}

	script.fired = true

	return fmt.Errorf("%w: %s", errInjectedRestoreTerminalCrash, point)
}

func (script *restoreTerminalCrashScript) didFire() bool {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	return script.fired
}

type restoreTerminalCrashTransport struct {
	base   http.RoundTripper
	script *restoreTerminalCrashScript
}

func (transport *restoreTerminalCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := restoreTerminalHTTPPoints(request.URL.Path)
	if controlled {
		if err := transport.script.hit(before); err != nil {
			return nil, err
		}
	}

	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	if controlled {
		if crashErr := transport.script.hit(after); crashErr != nil {
			return nil, errors.Join(crashErr, response.Body.Close())
		}
	}

	return response, nil
}

func restoreTerminalHTTPPoints(
	path string,
) (restoreTerminalCrashPoint, restoreTerminalCrashPoint, bool) {
	switch {
	case strings.HasSuffix(path, "/complete"):
		return crashBeforeRestoreComplete, crashAfterRestoreComplete, true
	case strings.HasSuffix(path, "/fail"):
		return crashBeforeRestoreFail, crashAfterRestoreFail, true
	default:
		return "", "", false
	}
}

type countingRestoreReader struct {
	reader provider.Reader
	opens  atomic.Int64
}

func (reader *countingRestoreReader) Stat(
	ctx context.Context,
	key string,
) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader *countingRestoreReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	reader.opens.Add(1)

	return reader.reader.OpenRange(ctx, key, offset, length)
}

type restoreTerminalReplayState struct {
	mutex sync.Mutex

	recovery manifest.RecoveryManifest
	bodies   map[string][]byte
	calls    map[string]int
	state    string

	completeCommits int
	failCommits     int
}

type restoreTerminalCrashFixture struct {
	coordinator *sdk.ControlledRestorer
	request     sdk.ControlledRestoreRequest
	state       *restoreTerminalReplayState
	reader      *countingRestoreReader
	destination string
	plaintext   []byte
}

type restoreTerminalProgressBody struct {
	FencingToken        uint64 `json:"fencing_token"`
	Sequence            uint64 `json:"sequence"`
	WireBytesRead       uint64 `json:"wire_bytes_read"`
	UsefulBytesVerified uint64 `json:"useful_bytes_verified"`
	ActiveNanoseconds   uint64 `json:"active_nanoseconds"`
	RetryCount          uint64 `json:"retry_count"`
}

func TestControlledRestorerConvergesAfterTerminalResponseLoss(t *testing.T) {
	t.Parallel()

	for _, point := range []restoreTerminalCrashPoint{
		crashBeforeRestoreComplete,
		crashAfterRestoreComplete,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testRestoreCompletionResponseLoss(t, point)
		})
	}
}

func TestControlledRestorerConvergesAfterFailureResponseLoss(t *testing.T) {
	t.Parallel()

	for _, point := range []restoreTerminalCrashPoint{
		crashBeforeRestoreFail,
		crashAfterRestoreFail,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testRestoreFailureResponseLoss(t, point)
		})
	}
}

func testRestoreCompletionResponseLoss(t *testing.T, point restoreTerminalCrashPoint) {
	t.Helper()

	script := &restoreTerminalCrashScript{target: point}
	fixture := newRestoreTerminalCrashFixture(t, script, false)

	_, firstErr := fixture.coordinator.Restore(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedRestoreTerminalCrash) {
		t.Fatalf("first restore did not stop at %s: %v", point, firstErr)
	}

	assertRestoredPlaintext(t, fixture.destination, fixture.plaintext)
	readsAfterFirst := fixture.reader.opens.Load()

	result, retryErr := fixture.coordinator.Restore(context.Background(), fixture.request)
	if retryErr != nil || result.Completion.State != "succeeded" {
		t.Fatalf("restore did not converge after %s: result=%+v err=%v", point, result, retryErr)
	}

	wantAlreadyCompleted := point == crashAfterRestoreComplete
	if result.AlreadyCompleted != wantAlreadyCompleted {
		t.Fatalf(
			"restore completion receipt after %s = %v, want %v",
			point,
			result.AlreadyCompleted,
			wantAlreadyCompleted,
		)
	}

	assertRestoredPlaintext(t, fixture.destination, fixture.plaintext)
	assertRestoreReplayReads(t, point, readsAfterFirst, fixture.reader.opens.Load())
	fixture.state.assertTerminal(t, "succeeded", point)

	if !script.didFire() {
		t.Fatalf("restore terminal crash point %s was never reached", point)
	}
}

func testRestoreFailureResponseLoss(t *testing.T, point restoreTerminalCrashPoint) {
	t.Helper()

	script := &restoreTerminalCrashScript{target: point}
	fixture := newRestoreTerminalCrashFixture(t, script, true)

	_, firstErr := fixture.coordinator.Restore(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedRestoreTerminalCrash) ||
		!errors.Is(firstErr, cryptostream.ErrFrameAuthentication) {
		t.Fatalf("first failed restore did not stop at %s: %v", point, firstErr)
	}

	readsAfterFirst := fixture.reader.opens.Load()

	result, retryErr := fixture.coordinator.Restore(context.Background(), fixture.request)
	if point == crashAfterRestoreFail {
		if !errors.Is(retryErr, sdk.ErrRestoreOperationFailed) || result.Completion.State != "failed" {
			t.Fatalf("failed restore receipt did not converge after %s: result=%+v err=%v", point, result, retryErr)
		}
	} else if !errors.Is(retryErr, cryptostream.ErrFrameAuthentication) {
		t.Fatalf("failed restore did not close after %s: %v", point, retryErr)
	}

	if _, err := os.Stat(fixture.destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminally failed restore published plaintext after %s: %v", point, err)
	}

	assertRestoreReplayReads(t, point, readsAfterFirst, fixture.reader.opens.Load())
	fixture.state.assertTerminal(t, "failed", point)

	if !script.didFire() {
		t.Fatalf("restore failure crash point %s was never reached", point)
	}
}

func assertRestoreReplayReads(
	t *testing.T,
	point restoreTerminalCrashPoint,
	before,
	after int64,
) {
	t.Helper()

	responseWasLost := point == crashAfterRestoreComplete || point == crashAfterRestoreFail
	if responseWasLost && after != before {
		t.Fatalf("terminal receipt after %s repeated provider reads: before=%d after=%d", point, before, after)
	}

	if !responseWasLost && after <= before {
		t.Fatalf("uncommitted terminal transition after %s did not resume provider reads", point)
	}
}

func assertRestoredPlaintext(t *testing.T, destination string, expected []byte) {
	t.Helper()

	actual, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read restored plaintext: %v", err)
	}

	if !bytes.Equal(actual, expected) {
		t.Fatalf("restored plaintext = %q, want %q", actual, expected)
	}
}

func newRestoreTerminalCrashFixture(
	t *testing.T,
	script *restoreTerminalCrashScript,
	wrongKey bool,
) restoreTerminalCrashFixture {
	t.Helper()

	plaintext := []byte("restore terminal responses remain idempotent")
	archiveStore, imported, epochKey := importRestoreFixture(t, plaintext)
	reader := &countingRestoreReader{reader: archiveStore}
	state := &restoreTerminalReplayState{
		recovery: imported.Recovery, bodies: make(map[string][]byte),
		calls: make(map[string]int), state: "planned",
	}
	token, encodedToken := testClientToken(t)
	server := newRestoreTerminalServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &restoreTerminalCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct restore terminal control client: %v", err)
	}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{"memory-primary": reader}, 128)
	if err != nil {
		t.Fatalf("construct restore terminal restorer: %v", err)
	}

	coordinator, err := sdk.NewControlledRestorer(control, restorer, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct terminal controlled restorer: %v", err)
	}

	if wrongKey {
		epochKey[0] ^= 1
	}

	destination := filepath.Join(t.TempDir(), "restored.bin")

	return restoreTerminalCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledRestoreRequest{
			NamespaceID:    imported.Manifest.NamespaceID,
			ManifestSHA256: imported.Recovery.ManifestSHA256,
			IdempotencyKey: "restore-terminal-crash-v1",
			EpochKey:       epochKey, Destination: destination,
		},
		state: state, reader: reader, destination: destination, plaintext: plaintext,
	}
}

func newRestoreTerminalServer(
	t *testing.T,
	encodedToken string,
	state *restoreTerminalReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read restore terminal request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/restores":
			state.serveCreate(t, response, body)
		case "/api/v1/restores/" + restoreTerminalOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/restores/" + restoreTerminalOperationID + "/manifest":
			state.serveManifest(t, response, body)
		case "/api/v1/operations/" + restoreTerminalOperationID + "/progress":
			state.serveProgress(t, response, body)
		case "/api/v1/restores/" + restoreTerminalOperationID + "/complete":
			state.serveComplete(t, response, body)
		case "/api/v1/restores/" + restoreTerminalOperationID + "/fail":
			state.serveFail(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *restoreTerminalReplayState) serveCreate(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "create", body)

	state.mutex.Lock()
	operation := state.operationLocked()
	state.mutex.Unlock()

	writeJSON(t, response, operation)
}

func (state *restoreTerminalReplayState) operationLocked() sdk.RestoreOperation {
	phase := "planned"
	revision := uint64(1)

	switch state.state {
	case "running":
		phase = "restoring"
		revision = 2
	case "succeeded":
		phase = "completed"
		revision = 5
	case "failed":
		phase = "failed"
		revision = 3
	case "planned":
	default:
	}

	return sdk.RestoreOperation{
		ID: restoreTerminalOperationID, NamespaceID: state.recovery.Manifest.NamespaceID,
		Kind: "restore", State: state.state, Phase: phase,
		RequestedBy: restoreTerminalClientID, Incarnation: restoreTerminalIncarnation,
		Revision: revision, UsefulBytesTotal: state.recovery.Manifest.PlaintextSize,
		VersionID: restoreTerminalVersionID, ObjectID: state.recovery.Manifest.ObjectID,
		Generation:     state.recovery.Manifest.Generation,
		ManifestSHA256: state.recovery.ManifestSHA256, CreatedAt: 1, UpdatedAt: revision,
	}
}

func (state *restoreTerminalReplayState) serveClaim(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "claim", body)

	state.mutex.Lock()
	state.state = "running"
	state.mutex.Unlock()

	writeJSON(t, response, sdk.RestoreReadLease{
		OperationID: restoreTerminalOperationID, LeaseID: restoreTerminalLeaseID,
		OwnerClientID: restoreTerminalClientID, Incarnation: restoreTerminalIncarnation,
		FencingToken: 1, ExpiresAt: 1 << 40, OperationRevision: 2,
		OperationState: "running", VersionID: restoreTerminalVersionID,
		ManifestSHA256: state.recovery.ManifestSHA256,
	})
}

func (state *restoreTerminalReplayState) serveManifest(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "manifest", body)
	writeJSON(t, response, state.recovery)
}

func (state *restoreTerminalReplayState) serveProgress(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()

	var progress restoreTerminalProgressBody
	if err := json.Unmarshal(body, &progress); err != nil {
		t.Errorf("decode restore terminal progress: %v", err)
		http.Error(response, "invalid progress", http.StatusBadRequest)

		return
	}

	state.mutex.Lock()
	state.calls["progress"]++
	state.mutex.Unlock()

	writeJSON(t, response, sdk.ProgressSnapshot{
		ComponentID: restoreTerminalOperationID + "/restore",
		Attempt:     progress.FencingToken, Sequence: progress.Sequence,
		WireBytesRead:       progress.WireBytesRead,
		UsefulBytesVerified: progress.UsefulBytesVerified,
		ActiveNanoseconds:   progress.ActiveNanoseconds,
		RetryCount:          progress.RetryCount, Disposition: "current",
	})
}

func (state *restoreTerminalReplayState) serveComplete(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "complete", body)

	state.mutex.Lock()
	if state.state == "running" {
		state.state = "succeeded"
		state.completeCommits++
	}
	state.mutex.Unlock()

	writeJSON(t, response, sdk.CompletedRestore{
		OperationID:    restoreTerminalOperationID,
		ManifestSHA256: state.recovery.ManifestSHA256,
		State:          "succeeded",
	})
}

func (state *restoreTerminalReplayState) serveFail(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "fail", body)

	state.mutex.Lock()
	if state.state == "running" {
		state.state = "failed"
		state.failCommits++
	}
	state.mutex.Unlock()

	writeJSON(t, response, sdk.CompletedRestore{
		OperationID:    restoreTerminalOperationID,
		ManifestSHA256: state.recovery.ManifestSHA256,
		State:          "failed",
	})
}

func (state *restoreTerminalReplayState) recordExact(
	t *testing.T,
	name string,
	body []byte,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.calls[name]++

	previous, exists := state.bodies[name]
	if !exists {
		state.bodies[name] = bytes.Clone(body)

		return
	}

	if !bytes.Equal(previous, body) {
		t.Errorf("restore retry changed its %s request", name)
	}
}

func (state *restoreTerminalReplayState) assertTerminal(
	t *testing.T,
	wantState string,
	point restoreTerminalCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.state != wantState {
		t.Fatalf("restore state after %s = %s, want %s", point, state.state, wantState)
	}

	if wantState == "succeeded" && (state.completeCommits != 1 || state.failCommits != 0) {
		t.Fatalf(
			"restore completion after %s committed complete/fail %d/%d times",
			point,
			state.completeCommits,
			state.failCommits,
		)
	}

	if wantState == "failed" && (state.completeCommits != 0 || state.failCommits != 1) {
		t.Fatalf(
			"restore failure after %s committed complete/fail %d/%d times",
			point,
			state.completeCommits,
			state.failCommits,
		)
	}

	expectedClaims := 2
	if point == crashAfterRestoreComplete || point == crashAfterRestoreFail {
		expectedClaims = 1
	}

	if state.calls["claim"] != expectedClaims {
		t.Fatalf("restore after %s claimed %d times, want %d", point, state.calls["claim"], expectedClaims)
	}
}
