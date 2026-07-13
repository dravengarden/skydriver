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

	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledGCCrashNamespaceID = "202122232425262728292a2b2c2d2e2f"
	controlledGCCrashOperationID = "e1e2e3e4e5e6e7e8e9eaebecedeeeff0"
	controlledGCCrashIncarnation = "f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"
	controlledGCCrashClientID    = "controlled-gc-crash-client"
	controlledGCCrashLeaseID     = "operation/e1e2e3e4e5e6e7e8e9eaebecedeeeff0/write"
)

const (
	crashBeforeGCCreate = "before_gc_create"
	crashAfterGCCreate  = "after_gc_create"
	crashBeforeGCClaim  = "before_gc_claim"
	crashAfterGCClaim   = "after_gc_claim"
	crashBeforeGCMark   = "before_gc_mark"
	crashAfterGCMark    = "after_gc_mark"
)

type controlledGCCrashFixture struct {
	collector *sdk.ControlledGarbageCollector
	request   sdk.ControlledGCRequest
	state     *controlledGCReplayState
}

type controlledGCReplayState struct {
	mutex sync.Mutex

	hasCandidates  bool
	bodies         map[string][]byte
	calls          map[string]int
	terminalState  string
	operationState string
	operationPhase string
	gcState        string

	created          bool
	claimed          bool
	marked           bool
	createCommits    int
	claimTransitions int
	markCommits      int
}

type controlledGCMarkBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type controlledGCCrashTransport struct {
	base   http.RoundTripper
	script *deterministicCrashScript
}

func (transport *controlledGCCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := controlledGCHTTPPoints(request.URL.Path)
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

func controlledGCHTTPPoints(path string) (replicationCrashPoint, replicationCrashPoint, bool) {
	switch path {
	case "/api/v1/gc/epochs":
		return crashBeforeGCCreate, crashAfterGCCreate, true
	case "/api/v1/operations/" + controlledGCCrashOperationID + "/claim":
		return crashBeforeGCClaim, crashAfterGCClaim, true
	case "/api/v1/gc/" + controlledGCCrashOperationID + "/mark":
		return crashBeforeGCMark, crashAfterGCMark, true
	default:
		return "", "", false
	}
}

func TestControlledGarbageCollectorCrashMatrixConverges(t *testing.T) {
	t.Parallel()

	for _, mode := range []struct {
		name          string
		hasCandidates bool
	}{
		{name: "marked candidates", hasCandidates: true},
		{name: "empty epoch", hasCandidates: false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()

			for _, point := range []replicationCrashPoint{
				crashBeforeGCCreate,
				crashAfterGCCreate,
				crashBeforeGCClaim,
				crashAfterGCClaim,
				crashBeforeGCMark,
				crashAfterGCMark,
			} {
				t.Run(string(point), func(t *testing.T) {
					t.Parallel()

					testControlledGCCrashPoint(t, point, mode.hasCandidates)
				})
			}
		})
	}
}

func TestControlledGarbageCollectorReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledGCCrashFixture(t, &deterministicCrashScript{}, true)
			fixture.state.terminalState = terminalState

			result, err := fixture.collector.Mark(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrGCOperationFailed) || result.Operation.State != terminalState {
				t.Fatalf("unexpected recovered GC result: result=%+v err=%v", result, err)
			}

			if fixture.state.callCount("claim") != 0 || fixture.state.callCount("mark") != 0 {
				t.Fatalf("terminal GC crossed a post-create boundary: %+v", fixture.state.calls)
			}
		})
	}
}

func TestControlledGarbageCollectorRejectsInvalidOperationStatePhase(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name    string
		state   string
		phase   string
		gcState string
	}{
		{name: "planned marking", state: "planned", phase: "marking", gcState: "marking"},
		{name: "running planned", state: "running", phase: "planned", gcState: "marking"},
		{name: "failed phase mismatch", state: "failed", phase: "failed", gcState: "failed"},
		{name: "succeeded phase mismatch", state: "succeeded", phase: "completed", gcState: "succeeded"},
		{name: "unknown epoch state", state: "running", phase: "marking", gcState: "unknown"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledGCCrashFixture(t, &deterministicCrashScript{}, false)
			fixture.state.operationState = testCase.state
			fixture.state.operationPhase = testCase.phase
			fixture.state.gcState = testCase.gcState

			_, err := fixture.collector.Mark(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrControlPlaneResponse) {
				t.Fatalf("invalid GC state/phase was accepted: %v", err)
			}

			if fixture.state.callCount("claim") != 0 || fixture.state.callCount("mark") != 0 {
				t.Fatalf("invalid GC crossed a post-create boundary: %+v", fixture.state.calls)
			}
		})
	}
}

func testControlledGCCrashPoint(
	t *testing.T,
	point replicationCrashPoint,
	hasCandidates bool,
) {
	t.Helper()

	script := &deterministicCrashScript{target: point}
	fixture := newControlledGCCrashFixture(t, script, hasCandidates)

	_, firstErr := fixture.collector.Mark(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedReplicationCrash) {
		t.Fatalf("first controlled GC did not stop at %s: %v", point, firstErr)
	}

	if point != crashAfterGCMark && fixture.state.isMarked() {
		t.Fatalf("controlled GC committed mark before retry at %s", point)
	}

	result, retryErr := fixture.collector.Mark(context.Background(), fixture.request)
	if retryErr != nil {
		t.Fatalf("controlled GC did not converge after %s: %v", point, retryErr)
	}

	if !script.didFire() {
		t.Fatalf("controlled GC crash point %s was never reached", point)
	}

	wantAlreadyMarked := point == crashAfterGCMark
	if result.AlreadyMarked != wantAlreadyMarked {
		t.Fatalf(
			"controlled GC returned the wrong replay state after %s: got=%t want=%t",
			point,
			result.AlreadyMarked,
			wantAlreadyMarked,
		)
	}

	assertControlledGCMark(t, result.Mark, hasCandidates)
	fixture.state.assertConverged(t, point)
}

func assertControlledGCMark(t *testing.T, mark sdk.GCMark, hasCandidates bool) {
	t.Helper()

	if mark.OperationID != controlledGCCrashOperationID {
		t.Fatalf("controlled GC returned another operation: %+v", mark)
	}

	if hasCandidates {
		if mark.State != "grace" || mark.CandidatesMarked != 3 || mark.ObjectsMarked != 2 ||
			mark.GraceUntil == nil || *mark.GraceUntil != 1_000 {
			t.Fatalf("controlled GC returned an invalid marked receipt: %+v", mark)
		}

		return
	}

	if mark.State != "succeeded" || mark.CandidatesMarked != 0 || mark.ObjectsMarked != 0 ||
		mark.GraceUntil != nil {
		t.Fatalf("controlled GC returned an invalid empty receipt: %+v", mark)
	}
}

func newControlledGCCrashFixture(
	t *testing.T,
	script *deterministicCrashScript,
	hasCandidates bool,
) controlledGCCrashFixture {
	t.Helper()

	state := &controlledGCReplayState{
		hasCandidates: hasCandidates, bodies: make(map[string][]byte), calls: make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledGCCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &controlledGCCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct GC crash control client: %v", err)
	}

	collector, err := sdk.NewControlledGarbageCollector(control, 15)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled GC: %v", err)
	}

	return controlledGCCrashFixture{
		collector: collector,
		request: sdk.ControlledGCRequest{
			NamespaceID:    controlledGCCrashNamespaceID,
			IdempotencyKey: "controlled-gc-crash-v1",
		},
		state: state,
	}
}

func newControlledGCCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledGCReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled GC request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/gc/epochs":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledGCCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/gc/" + controlledGCCrashOperationID + "/mark":
			state.serveMark(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledGCReplayState) serveOperation(
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

func (state *controlledGCReplayState) operationLocked() sdk.GCOperation {
	var (
		operationState = "planned"
		phase          = "planned"
		epochState     = "marking"
		revision       = uint64(1)
		graceUntil     *uint64
		candidates     uint64
		objects        uint64
	)

	if state.claimed {
		operationState = "running"
		phase = "marking"
		revision = 2
	}

	if state.terminalState != "" {
		operationState = state.terminalState
		phase = "control_plane_recovered"
		epochState = "failed"
		revision = 3
	}

	if state.marked {
		revision = 3

		if state.hasCandidates {
			deadline := uint64(1_000)
			operationState = "running"
			phase = "grace"
			epochState = "grace"
			graceUntil = &deadline
			candidates = 3
			objects = 2
		} else {
			operationState = "succeeded"
			phase = "succeeded"
			epochState = "succeeded"
			revision = 5
		}
	}

	if state.operationState != "" {
		operationState = state.operationState
	}

	if state.operationPhase != "" {
		phase = state.operationPhase
	}

	if state.gcState != "" {
		epochState = state.gcState
	}

	return sdk.GCOperation{
		ID: controlledGCCrashOperationID, NamespaceID: controlledGCCrashNamespaceID,
		Kind: "gc", State: operationState, Phase: phase, RequestedBy: controlledGCCrashClientID,
		Incarnation: controlledGCCrashIncarnation, Revision: revision,
		CutoffAt: 100, GraceSeconds: 60, GraceUntil: graceUntil, GCState: epochState,
		CandidateCount: candidates, ObjectCount: objects, CreatedAt: 1, UpdatedAt: revision,
	}
}

func (state *controlledGCReplayState) serveClaim(
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
		OperationID: controlledGCCrashOperationID,
		LeaseID:     controlledGCCrashLeaseID, OwnerClientID: controlledGCCrashClientID,
		Incarnation: controlledGCCrashIncarnation, FencingToken: 23,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledGCReplayState) serveMark(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "mark", body)

	var requested controlledGCMarkBody
	if err := json.Unmarshal(body, &requested); err != nil {
		t.Errorf("decode GC mark: %v", err)
		http.Error(response, "invalid mark", http.StatusBadRequest)

		return
	}

	if requested.LeaseID != controlledGCCrashLeaseID ||
		requested.Incarnation != controlledGCCrashIncarnation || requested.FencingToken != 23 {
		t.Errorf("invalid controlled GC mark: %+v", requested)
		http.Error(response, "invalid mark identity", http.StatusConflict)

		return
	}

	state.mutex.Lock()
	if !state.marked {
		state.marked = true
		state.markCommits++
	}

	operation := state.operationLocked()
	state.mutex.Unlock()

	writeJSON(t, response, sdk.GCMark{
		OperationID:      controlledGCCrashOperationID,
		CandidatesMarked: operation.CandidateCount, ObjectsMarked: operation.ObjectCount,
		GraceUntil: operation.GraceUntil, State: operation.GCState,
	})
}

func (state *controlledGCReplayState) recordExactRequest(
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
		t.Errorf("controlled GC retry changed its %s request", name)
	}
}

func (state *controlledGCReplayState) callCount(name string) int {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.calls[name]
}

func (state *controlledGCReplayState) isMarked() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.marked
}

func (state *controlledGCReplayState) assertConverged(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.markCommits != 1 || !state.marked {
		t.Fatalf(
			"controlled GC did not converge logical commits after %s: create=%d claim=%d mark=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.markCommits,
		)
	}

	expectedCreateCalls := 2
	if point == crashBeforeGCCreate {
		expectedCreateCalls = 1
	}

	expectedClaimCalls := 2
	if point == crashBeforeGCCreate || point == crashAfterGCCreate ||
		point == crashBeforeGCClaim || point == crashAfterGCMark {
		expectedClaimCalls = 1
	}

	if state.calls["create"] != expectedCreateCalls || state.calls["claim"] != expectedClaimCalls ||
		state.calls["mark"] != 1 {
		t.Fatalf(
			"controlled GC crossed remote barriers incorrectly after %s: create=%d/%d claim=%d/%d mark=%d/1",
			point,
			state.calls["create"],
			expectedCreateCalls,
			state.calls["claim"],
			expectedClaimCalls,
			state.calls["mark"],
		)
	}
}
