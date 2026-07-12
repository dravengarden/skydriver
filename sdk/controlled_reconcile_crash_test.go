package sdk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledReconcileCrashOperationID = "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0"
	controlledReconcileCrashIncarnation = "d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"
	controlledReconcileCrashClientID    = "controlled-reconcile-crash-client"
	controlledReconcileCrashLeaseID     = "operation/c1c2c3c4c5c6c7c8c9cacbcccdcecfd0/write"
	controlledReconcileReportSHA256     = "abababababababababababababababababababababababababababababababab"
)

const (
	crashBeforeReconcileCreate   = "before_reconcile_create"
	crashAfterReconcileCreate    = "after_reconcile_create"
	crashBeforeReconcileClaim    = "before_reconcile_claim"
	crashAfterReconcileClaim     = "after_reconcile_claim"
	crashBeforeReconcileSnapshot = "before_reconcile_snapshot"
	crashAfterReconcileSnapshot  = "after_reconcile_snapshot"
	crashBeforeReconcileComplete = "before_reconcile_complete"
	crashAfterReconcileComplete  = "after_reconcile_complete"
)

type controlledReconcileCrashFixture struct {
	coordinator *sdk.ControlledReconciler
	request     sdk.ControlledReconcileRequest
	state       *controlledReconcileReplayState
}

type controlledReconcileReplayState struct {
	mutex sync.Mutex

	recovery       manifest.RecoveryManifest
	bodies         map[string][]byte
	calls          map[string]int
	terminalState  string
	operationState string
	operationPhase string

	created           bool
	claimed           bool
	completed         bool
	createCommits     int
	claimTransitions  int
	completionCommits int
	completion        sdk.CompletedReconcile
}

type controlledReconcileSnapshotBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type controlledReconcileCompletionBody struct {
	LeaseID        string                       `json:"lease_id"`
	Incarnation    string                       `json:"incarnation"`
	FencingToken   uint64                       `json:"fencing_token"`
	ManifestSHA256 string                       `json:"manifest_sha256"`
	Evidence       []sdk.ReconciliationEvidence `json:"evidence"`
}

type controlledReconcileCrashTransport struct {
	base   http.RoundTripper
	script *deterministicCrashScript
}

func (transport *controlledReconcileCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := controlledReconcileHTTPPoints(request.URL.Path)
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

func controlledReconcileHTTPPoints(
	path string,
) (replicationCrashPoint, replicationCrashPoint, bool) {
	switch path {
	case "/api/v1/reconciliations":
		return crashBeforeReconcileCreate, crashAfterReconcileCreate, true
	case "/api/v1/operations/" + controlledReconcileCrashOperationID + "/claim":
		return crashBeforeReconcileClaim, crashAfterReconcileClaim, true
	case "/api/v1/reconciliations/" + controlledReconcileCrashOperationID + "/snapshot":
		return crashBeforeReconcileSnapshot, crashAfterReconcileSnapshot, true
	case "/api/v1/reconciliations/" + controlledReconcileCrashOperationID + "/complete":
		return crashBeforeReconcileComplete, crashAfterReconcileComplete, true
	default:
		return "", "", false
	}
}

func TestControlledReconcilerCrashMatrixConverges(t *testing.T) {
	t.Parallel()

	for _, point := range []replicationCrashPoint{
		crashBeforeReconcileCreate,
		crashAfterReconcileCreate,
		crashBeforeReconcileClaim,
		crashAfterReconcileClaim,
		crashBeforeReconcileSnapshot,
		crashAfterReconcileSnapshot,
		crashBeforeReconcileComplete,
		crashAfterReconcileComplete,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testControlledReconcileCrashPoint(t, point)
		})
	}
}

func TestControlledReconcilerReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledReconcileCrashFixture(t, &deterministicCrashScript{})
			fixture.state.terminalState = terminalState

			result, err := fixture.coordinator.Reconcile(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrReconcileOperationFailed) ||
				result.Operation.State != terminalState {
				t.Fatalf("unexpected recovered reconcile result: result=%+v err=%v", result, err)
			}

			if fixture.state.callCount("claim") != 0 ||
				fixture.state.callCount("snapshot") != 0 ||
				fixture.state.callCount("completion") != 0 {
				t.Fatalf("terminal reconcile crossed a post-create boundary: %+v", fixture.state.calls)
			}
		})
	}
}

func TestControlledReconcilerRejectsInvalidOperationStatePhase(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		state string
		phase string
	}{
		{name: "planned reconciling", state: "planned", phase: "reconciling"},
		{name: "running planned", state: "running", phase: "planned"},
		{name: "failed phase mismatch", state: "failed", phase: "failed"},
		{name: "succeeded without receipt", state: "succeeded", phase: "completed"},
		{name: "unknown state", state: "verifying", phase: "verifying"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledReconcileCrashFixture(t, &deterministicCrashScript{})
			fixture.state.operationState = testCase.state
			fixture.state.operationPhase = testCase.phase

			_, err := fixture.coordinator.Reconcile(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrControlPlaneResponse) {
				t.Fatalf("invalid reconcile state/phase was accepted: %v", err)
			}

			if fixture.state.callCount("claim") != 0 || fixture.state.callCount("snapshot") != 0 {
				t.Fatalf("invalid reconcile crossed a post-create boundary: %+v", fixture.state.calls)
			}
		})
	}
}

func testControlledReconcileCrashPoint(t *testing.T, point replicationCrashPoint) {
	t.Helper()

	script := &deterministicCrashScript{target: point}
	fixture := newControlledReconcileCrashFixture(t, script)

	_, firstErr := fixture.coordinator.Reconcile(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedReplicationCrash) {
		t.Fatalf("first controlled reconcile did not stop at %s: %v", point, firstErr)
	}

	snapshotsBeforeRetry := fixture.state.callCount("snapshot")
	if point != crashAfterReconcileComplete && fixture.state.isCompleted() {
		t.Fatalf("controlled reconcile committed before retry at %s", point)
	}

	result, retryErr := fixture.coordinator.Reconcile(context.Background(), fixture.request)
	if retryErr != nil {
		t.Fatalf("controlled reconcile did not converge after %s: %v", point, retryErr)
	}

	if !script.didFire() {
		t.Fatalf("controlled reconcile crash point %s was never reached", point)
	}

	wantAlreadyCompleted := point == crashAfterReconcileComplete
	if result.Completion.State != "succeeded" ||
		result.Completion.ReportSHA256 != controlledReconcileReportSHA256 ||
		result.Completion.Unindexed != 0 || result.Completion.Orphan != 0 ||
		result.Completion.Degraded != 1 || result.AlreadyCompleted != wantAlreadyCompleted {
		t.Fatalf("controlled reconcile returned an invalid result after %s: %+v", point, result)
	}

	if !wantAlreadyCompleted && result.Reconciliation.Degraded != 1 {
		t.Fatalf("controlled reconcile lost local evidence after %s: %+v", point, result)
	}

	fixture.state.assertConverged(t, point)

	if wantAlreadyCompleted && fixture.state.callCount("snapshot") != snapshotsBeforeRetry {
		t.Fatalf("lost completion response repeated the reconcile snapshot")
	}
}

func newControlledReconcileCrashFixture(
	t *testing.T,
	script *deterministicCrashScript,
) controlledReconcileCrashFixture {
	t.Helper()

	recovery := controlRecoveryManifest(t)
	state := &controlledReconcileReplayState{
		recovery: recovery, bodies: make(map[string][]byte), calls: make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledReconcileCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &controlledReconcileCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct reconcile crash control client: %v", err)
	}

	coordinator, err := sdk.NewControlledReconciler(control, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled reconciler: %v", err)
	}

	return controlledReconcileCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledReconcileRequest{
			NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
			IdempotencyKey: "controlled-reconcile-crash-v1",
		},
		state: state,
	}
}

func newControlledReconcileCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledReconcileReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled reconcile request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/reconciliations":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledReconcileCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/reconciliations/" + controlledReconcileCrashOperationID + "/snapshot":
			state.serveSnapshot(t, response, body)
		case "/api/v1/reconciliations/" + controlledReconcileCrashOperationID + "/complete":
			state.serveCompletion(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledReconcileReplayState) serveOperation(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "create", body)

	state.mutex.Lock()
	if !state.created {
		state.created = true
		state.createCommits++
	}

	operation := state.operationLocked()
	state.mutex.Unlock()

	writeJSON(t, response, operation)
}

func (state *controlledReconcileReplayState) operationLocked() sdk.ReconcileOperation {
	operationState := "planned"
	phase := "planned"
	revision := uint64(1)

	if state.claimed {
		operationState = "running"
		phase = "reconciling"
		revision = 2
	}

	if state.terminalState != "" {
		operationState = state.terminalState
		phase = "control_plane_recovered"
		revision = 3
	}

	if state.completed {
		operationState = "succeeded"
		phase = "completed"
		revision = 5
	}

	if state.operationState != "" {
		operationState = state.operationState
	}

	if state.operationPhase != "" {
		phase = state.operationPhase
	}

	operation := sdk.ReconcileOperation{
		ID: controlledReconcileCrashOperationID, NamespaceID: state.recovery.Manifest.NamespaceID,
		Kind: "reconcile", State: operationState, Phase: phase,
		RequestedBy: controlledReconcileCrashClientID,
		Incarnation: controlledReconcileCrashIncarnation, Revision: revision,
		UsefulBytesTotal: 1, VersionID: "version-1",
		ManifestSHA256:   state.recovery.ManifestSHA256,
		RecoveryRevision: 1, MinimumAvailableReplicas: 2,
		CreatedAt: 1, UpdatedAt: revision,
	}
	if state.completed {
		operation.CompletedReportSHA256 = state.completion.ReportSHA256
		operation.CompletedUnindexed = state.completion.Unindexed
		operation.CompletedOrphan = state.completion.Orphan
		operation.CompletedDegraded = state.completion.Degraded
	}

	return operation
}

func (state *controlledReconcileReplayState) serveClaim(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "claim", body)

	state.mutex.Lock()
	if !state.claimed {
		state.claimed = true
		state.claimTransitions++
	}
	state.mutex.Unlock()

	writeJSON(t, response, sdk.OperationLease{
		OperationID: controlledReconcileCrashOperationID,
		LeaseID:     controlledReconcileCrashLeaseID, OwnerClientID: controlledReconcileCrashClientID,
		Incarnation: controlledReconcileCrashIncarnation, FencingToken: 19,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledReconcileReplayState) serveSnapshot(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "snapshot", body)

	var requested controlledReconcileSnapshotBody
	if err := json.Unmarshal(body, &requested); err != nil {
		t.Errorf("decode reconcile snapshot: %v", err)
		http.Error(response, "invalid snapshot", http.StatusBadRequest)

		return
	}

	if requested.LeaseID != controlledReconcileCrashLeaseID ||
		requested.Incarnation != controlledReconcileCrashIncarnation ||
		requested.FencingToken != 19 {
		t.Errorf("invalid controlled reconcile snapshot: %+v", requested)
		http.Error(response, "invalid snapshot identity", http.StatusConflict)

		return
	}

	location := state.recovery.Locations[0]
	writeJSON(t, response, sdk.ReconcileSnapshot{
		Recovery: state.recovery, RecoveryRevision: 1, MinimumAvailableReplicas: 2,
		Locations: []sdk.IndexedLocation{{
			ID: "location-1", ExtentSHA256: location.ExtentSHA256,
			DriverID: location.DriverID, StorageKey: location.StorageKey,
			ProviderVersion: location.ProviderVersion, Offset: location.Offset,
			Length: location.Length, State: "available",
		}},
	})
}

func (state *controlledReconcileReplayState) serveCompletion(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "completion", body)

	var completed controlledReconcileCompletionBody
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Errorf("decode reconcile completion: %v", err)
		http.Error(response, "invalid completion", http.StatusBadRequest)

		return
	}

	if completed.LeaseID != controlledReconcileCrashLeaseID ||
		completed.Incarnation != controlledReconcileCrashIncarnation ||
		completed.FencingToken != 19 || completed.ManifestSHA256 != state.recovery.ManifestSHA256 ||
		len(completed.Evidence) != 1 ||
		completed.Evidence[0].Condition != sdk.ReconciliationDegraded {
		t.Errorf("invalid controlled reconcile completion: %+v", completed)
		http.Error(response, "invalid completion identity", http.StatusConflict)

		return
	}

	completion := sdk.CompletedReconcile{
		OperationID:    controlledReconcileCrashOperationID,
		ManifestSHA256: state.recovery.ManifestSHA256, State: "succeeded",
		ReportSHA256: controlledReconcileReportSHA256, Degraded: 1,
	}

	state.mutex.Lock()
	if !state.completed {
		state.completed = true
		state.completionCommits++
		state.completion = completion
	}
	state.mutex.Unlock()

	writeJSON(t, response, completion)
}

func (state *controlledReconcileReplayState) recordExactRequest(
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
		t.Errorf("controlled reconcile retry changed its %s request", name)
	}
}

func (state *controlledReconcileReplayState) callCount(name string) int {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.calls[name]
}

func (state *controlledReconcileReplayState) isCompleted() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.completed
}

func (state *controlledReconcileReplayState) assertConverged(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.completionCommits != 1 || !state.completed {
		t.Fatalf(
			"controlled reconcile did not converge logical commits after %s: create=%d claim=%d complete=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.completionCommits,
		)
	}

	expectedCreateCalls := 2
	if point == crashBeforeReconcileCreate {
		expectedCreateCalls = 1
	}

	expectedClaimCalls := 2
	if point == crashBeforeReconcileCreate || point == crashAfterReconcileCreate ||
		point == crashBeforeReconcileClaim || point == crashAfterReconcileComplete {
		expectedClaimCalls = 1
	}

	expectedSnapshotCalls := 1
	if point == crashAfterReconcileSnapshot || point == crashBeforeReconcileComplete {
		expectedSnapshotCalls = 2
	}

	if state.calls["create"] != expectedCreateCalls || state.calls["claim"] != expectedClaimCalls ||
		state.calls["snapshot"] != expectedSnapshotCalls || state.calls["completion"] != 1 {
		t.Fatalf(
			"controlled reconcile crossed remote barriers incorrectly after %s: create=%d/%d claim=%d/%d snapshot=%d/%d complete=%d/1",
			point,
			state.calls["create"],
			expectedCreateCalls,
			state.calls["claim"],
			expectedClaimCalls,
			state.calls["snapshot"],
			expectedSnapshotCalls,
			state.calls["completion"],
		)
	}
}
