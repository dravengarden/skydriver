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
	"sync"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledQuarantineCrashNamespaceID = "202122232425262728292a2b2c2d2e2f"
	controlledQuarantineCrashOperationID = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0"
	controlledQuarantineCrashIncarnation = "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0"
	controlledQuarantineCrashClientID    = "controlled-quarantine-crash-client"
	controlledQuarantineCrashLeaseID     = "operation/a1a2a3a4a5a6a7a8a9aaabacadaeafb0/write"
)

const (
	crashBeforeQuarantineCreate   quarantineCrashPoint = "before_quarantine_create"
	crashAfterQuarantineCreate    quarantineCrashPoint = "after_quarantine_create"
	crashBeforeQuarantineClaim    quarantineCrashPoint = "before_quarantine_claim"
	crashAfterQuarantineClaim     quarantineCrashPoint = "after_quarantine_claim"
	crashBeforeQuarantineComplete quarantineCrashPoint = "before_quarantine_complete"
	crashAfterQuarantineComplete  quarantineCrashPoint = "after_quarantine_complete"
)

type quarantineCrashPoint string

type controlledQuarantineCrashScript struct {
	mutex  sync.Mutex
	target quarantineCrashPoint
	fired  bool
}

func (script *controlledQuarantineCrashScript) hit(point quarantineCrashPoint) error {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	if script.fired || script.target != point {
		return nil
	}

	script.fired = true

	return fmt.Errorf("%w: %s", errInjectedReplicationCrash, point)
}

func (script *controlledQuarantineCrashScript) didFire() bool {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	return script.fired
}

type controlledQuarantineCrashFixture struct {
	reviewer *sdk.ControlledQuarantineReviewer
	request  sdk.ControlledQuarantineRequest
	state    *controlledQuarantineReplayState
}

type controlledQuarantineReplayState struct {
	mutex sync.Mutex

	action         sdk.QuarantineAction
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
}

type controlledQuarantineCompletionBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
}

type controlledQuarantineCrashTransport struct {
	base   http.RoundTripper
	script *controlledQuarantineCrashScript
}

func (transport *controlledQuarantineCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := controlledQuarantineHTTPPoints(request.URL.Path)
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

func controlledQuarantineHTTPPoints(
	path string,
) (quarantineCrashPoint, quarantineCrashPoint, bool) {
	switch path {
	case "/api/v1/quarantine-actions":
		return crashBeforeQuarantineCreate, crashAfterQuarantineCreate, true
	case "/api/v1/operations/" + controlledQuarantineCrashOperationID + "/claim":
		return crashBeforeQuarantineClaim, crashAfterQuarantineClaim, true
	case "/api/v1/quarantine-actions/" + controlledQuarantineCrashOperationID + "/complete":
		return crashBeforeQuarantineComplete, crashAfterQuarantineComplete, true
	default:
		return "", "", false
	}
}

func TestControlledQuarantineCrashMatrixConverges(t *testing.T) {
	t.Parallel()

	for _, action := range []sdk.QuarantineAction{
		sdk.QuarantineActionAcknowledge,
		sdk.QuarantineActionTombstone,
	} {
		t.Run(string(action), func(t *testing.T) {
			t.Parallel()

			for _, point := range []quarantineCrashPoint{
				crashBeforeQuarantineCreate,
				crashAfterQuarantineCreate,
				crashBeforeQuarantineClaim,
				crashAfterQuarantineClaim,
				crashBeforeQuarantineComplete,
				crashAfterQuarantineComplete,
			} {
				t.Run(string(point), func(t *testing.T) {
					t.Parallel()

					testControlledQuarantineCrashPoint(t, action, point)
				})
			}
		})
	}
}

func TestControlledQuarantineReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledQuarantineCrashFixture(
				t,
				&controlledQuarantineCrashScript{},
				sdk.QuarantineActionAcknowledge,
			)
			fixture.state.terminalState = terminalState

			result, err := fixture.reviewer.Act(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrQuarantineOperationFailed) ||
				result.Operation.State != terminalState {
				t.Fatalf(
					"unexpected recovered quarantine result: result=%+v err=%v",
					result,
					err,
				)
			}

			if fixture.state.callCount("claim") != 0 || fixture.state.callCount("complete") != 0 {
				t.Fatalf(
					"terminal quarantine crossed a post-create boundary: %+v",
					fixture.state.calls,
				)
			}
		})
	}
}

func TestControlledQuarantineRejectsInvalidOperationStatePhase(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		state string
		phase string
	}{
		{name: "planned review", state: "planned", phase: "reviewing_quarantine"},
		{name: "running planned", state: "running", phase: "planned"},
		{name: "failed phase mismatch", state: "failed", phase: "failed"},
		{name: "succeeded phase mismatch", state: "succeeded", phase: "reviewing_quarantine"},
		{name: "unknown state", state: "unknown", phase: "planned"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledQuarantineCrashFixture(
				t,
				&controlledQuarantineCrashScript{},
				sdk.QuarantineActionAcknowledge,
			)
			fixture.state.operationState = testCase.state
			fixture.state.operationPhase = testCase.phase

			_, err := fixture.reviewer.Act(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrControlPlaneResponse) {
				t.Fatalf("invalid quarantine state/phase was accepted: %v", err)
			}

			if fixture.state.callCount("claim") != 0 || fixture.state.callCount("complete") != 0 {
				t.Fatalf(
					"invalid quarantine crossed a post-create boundary: %+v",
					fixture.state.calls,
				)
			}
		})
	}
}

func testControlledQuarantineCrashPoint(
	t *testing.T,
	action sdk.QuarantineAction,
	point quarantineCrashPoint,
) {
	t.Helper()

	script := &controlledQuarantineCrashScript{target: point}
	fixture := newControlledQuarantineCrashFixture(t, script, action)

	_, firstErr := fixture.reviewer.Act(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedReplicationCrash) {
		t.Fatalf("first controlled quarantine did not stop at %s: %v", point, firstErr)
	}

	if point != crashAfterQuarantineComplete && fixture.state.isCompleted() {
		t.Fatalf("controlled quarantine committed before retry at %s", point)
	}

	result, retryErr := fixture.reviewer.Act(context.Background(), fixture.request)
	if retryErr != nil {
		t.Fatalf("controlled quarantine did not converge after %s: %v", point, retryErr)
	}

	if !script.didFire() {
		t.Fatalf("controlled quarantine crash point %s was never reached", point)
	}

	wantAlreadyCompleted := point == crashAfterQuarantineComplete
	if result.AlreadyCompleted != wantAlreadyCompleted {
		t.Fatalf(
			"controlled quarantine returned the wrong replay state after %s: got=%t want=%t",
			point,
			result.AlreadyCompleted,
			wantAlreadyCompleted,
		)
	}

	assertControlledQuarantineCompletion(t, result.Completion, action)
	fixture.state.assertConverged(t, point)
}

func assertControlledQuarantineCompletion(
	t *testing.T,
	completion sdk.CompletedQuarantineAction,
	action sdk.QuarantineAction,
) {
	t.Helper()

	if completion.OperationID != controlledQuarantineCrashOperationID ||
		completion.Action != action || completion.State != "succeeded" ||
		completion.QuarantineRevision != 5 {
		t.Fatalf("controlled quarantine returned another completion: %+v", completion)
	}

	if action == sdk.QuarantineActionAcknowledge {
		if completion.QuarantineState != "acknowledged" || completion.DeleteAfter != nil {
			t.Fatalf("controlled quarantine returned an invalid acknowledgement: %+v", completion)
		}

		return
	}

	if completion.QuarantineState != "tombstoned" || completion.DeleteAfter == nil ||
		*completion.DeleteAfter != 1_000 {
		t.Fatalf("controlled quarantine returned an invalid tombstone: %+v", completion)
	}
}

func newControlledQuarantineCrashFixture(
	t *testing.T,
	script *controlledQuarantineCrashScript,
	action sdk.QuarantineAction,
) controlledQuarantineCrashFixture {
	t.Helper()

	state := &controlledQuarantineReplayState{
		action: action, bodies: make(map[string][]byte), calls: make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledQuarantineCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &controlledQuarantineCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct quarantine crash control client: %v", err)
	}

	reviewer, err := sdk.NewControlledQuarantineReviewer(control, 15)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled quarantine reviewer: %v", err)
	}

	return controlledQuarantineCrashFixture{
		reviewer: reviewer,
		request: sdk.ControlledQuarantineRequest{
			NamespaceID: controlledQuarantineCrashNamespaceID, Action: action,
			DriverID: "local-main", StorageKey: "archive/objects/orphan", ExpectedRevision: 4,
			Reason:         "reviewed orphan has no recovery ownership",
			IdempotencyKey: "controlled-quarantine-" + string(action) + "-crash-v1",
		},
		state: state,
	}
}

func newControlledQuarantineCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledQuarantineReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled quarantine request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/quarantine-actions":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledQuarantineCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/quarantine-actions/" + controlledQuarantineCrashOperationID + "/complete":
			state.serveCompletion(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledQuarantineReplayState) serveOperation(
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

func (state *controlledQuarantineReplayState) operationLocked() sdk.QuarantineActionOperation {
	operationState := "planned"
	phase := "planned"
	revision := uint64(1)
	updatedAt := uint64(1)

	var (
		resultRevision *uint64
		resultState    *string
		deleteAfter    *uint64
	)

	if state.claimed {
		operationState = "running"
		phase = "reviewing_quarantine"
		revision = 2
		updatedAt = 2
	}

	if state.terminalState != "" {
		operationState = state.terminalState
		phase = "control_plane_recovered"
		revision = 3
		updatedAt = 3
	}

	if state.completed {
		operationState = "succeeded"
		phase = "completed"
		revision = 5
		updatedAt = 10
		completedRevision := uint64(5)
		completedState := "acknowledged"
		resultRevision = &completedRevision
		resultState = &completedState

		if state.action == sdk.QuarantineActionTombstone {
			completedState = "tombstoned"
			deadline := uint64(1_000)
			deleteAfter = &deadline
		}
	}

	if state.operationState != "" {
		operationState = state.operationState
	}

	if state.operationPhase != "" {
		phase = state.operationPhase
	}

	return sdk.QuarantineActionOperation{
		ID: controlledQuarantineCrashOperationID, NamespaceID: controlledQuarantineCrashNamespaceID,
		Kind: "gc", State: operationState, Phase: phase,
		RequestedBy: controlledQuarantineCrashClientID,
		Incarnation: controlledQuarantineCrashIncarnation, Revision: revision,
		Action: state.action, DriverID: "local-main", DriverRevision: 2,
		StorageKey: "archive/objects/orphan", ExpectedRevision: 4,
		ProviderVersion: "orphan-v1", ETag: "orphan-etag", SizeBytes: 13,
		Reason: "reviewed orphan has no recovery ownership", GraceSeconds: 90,
		ResultRevision: resultRevision, ResultState: resultState, DeleteAfter: deleteAfter,
		CreatedAt: 1, UpdatedAt: updatedAt,
	}
}

func (state *controlledQuarantineReplayState) serveClaim(
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
		OperationID: controlledQuarantineCrashOperationID,
		LeaseID:     controlledQuarantineCrashLeaseID, OwnerClientID: controlledQuarantineCrashClientID,
		Incarnation: controlledQuarantineCrashIncarnation, FencingToken: 29,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledQuarantineReplayState) serveCompletion(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "complete", body)

	var requested controlledQuarantineCompletionBody
	if err := json.Unmarshal(body, &requested); err != nil {
		t.Errorf("decode quarantine completion: %v", err)
		http.Error(response, "invalid completion", http.StatusBadRequest)

		return
	}

	if requested.LeaseID != controlledQuarantineCrashLeaseID ||
		requested.Incarnation != controlledQuarantineCrashIncarnation ||
		requested.FencingToken != 29 {
		t.Errorf("invalid controlled quarantine completion: %+v", requested)
		http.Error(response, "invalid completion identity", http.StatusConflict)

		return
	}

	state.mutex.Lock()
	if !state.completed {
		state.completed = true
		state.completionCommits++
	}

	operation := state.operationLocked()
	state.mutex.Unlock()

	writeJSON(t, response, completedQuarantineActionFromReplay(operation))
}

func completedQuarantineActionFromReplay(
	operation sdk.QuarantineActionOperation,
) sdk.CompletedQuarantineAction {
	return sdk.CompletedQuarantineAction{
		OperationID: operation.ID, Action: operation.Action, State: operation.State,
		QuarantineState: *operation.ResultState, QuarantineRevision: *operation.ResultRevision,
		DeleteAfter: operation.DeleteAfter,
	}
}

func (state *controlledQuarantineReplayState) recordExactRequest(
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
		t.Errorf("controlled quarantine retry changed its %s request", name)
	}
}

func (state *controlledQuarantineReplayState) callCount(name string) int {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.calls[name]
}

func (state *controlledQuarantineReplayState) isCompleted() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.completed
}

func (state *controlledQuarantineReplayState) assertConverged(
	t *testing.T,
	point quarantineCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.completionCommits != 1 || !state.completed {
		t.Fatalf(
			"controlled quarantine did not converge logical commits after %s: create=%d claim=%d complete=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.completionCommits,
		)
	}

	expectedCreateCalls := 2
	if point == crashBeforeQuarantineCreate {
		expectedCreateCalls = 1
	}

	expectedClaimCalls := 2
	if point == crashBeforeQuarantineCreate || point == crashAfterQuarantineCreate ||
		point == crashBeforeQuarantineClaim || point == crashAfterQuarantineComplete {
		expectedClaimCalls = 1
	}

	if state.calls["create"] != expectedCreateCalls || state.calls["claim"] != expectedClaimCalls ||
		state.calls["complete"] != 1 {
		t.Fatalf(
			"controlled quarantine crossed remote barriers incorrectly after %s: create=%d/%d claim=%d/%d complete=%d/1",
			point,
			state.calls["create"],
			expectedCreateCalls,
			state.calls["claim"],
			expectedClaimCalls,
			state.calls["complete"],
		)
	}
}
