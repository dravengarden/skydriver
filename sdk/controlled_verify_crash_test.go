package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledVerifyCrashOperationID = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	controlledVerifyCrashIncarnation = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
	controlledVerifyCrashClientID    = "controlled-verify-crash-client"
	controlledVerifyCrashLeaseID     = "operation/b0b1b2b3b4b5b6b7b8b9babbbcbdbebf/write"
)

const (
	crashBeforeVerifyCreate   = "before_verify_create"
	crashAfterVerifyCreate    = "after_verify_create"
	crashBeforeVerifyClaim    = "before_verify_claim"
	crashAfterVerifyClaim     = "after_verify_claim"
	crashBeforeVerifyManifest = "before_verify_manifest"
	crashAfterVerifyManifest  = "after_verify_manifest"
	crashBeforeVerifyRead     = "before_verify_provider_read"
	crashAfterVerifyRead      = "after_verify_provider_read"
	crashBeforeVerifyComplete = "before_verify_complete"
	crashAfterVerifyComplete  = "after_verify_complete"
)

type controlledVerifyCrashFixture struct {
	coordinator  *sdk.ControlledVerifier
	request      sdk.ControlledVerifyRequest
	state        *controlledVerifyReplayState
	reader       *controlledVerifyCrashReader
	cancellation *controlledVerifyCancellation
}

type controlledVerifyReplayState struct {
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
	completion        sdk.CompletedVerify
}

type controlledVerifyCompletionBody struct {
	LeaseID        string                     `json:"lease_id"`
	Incarnation    string                     `json:"incarnation"`
	FencingToken   uint64                     `json:"fencing_token"`
	ManifestSHA256 string                     `json:"manifest_sha256"`
	Evidence       []sdk.VerificationEvidence `json:"evidence"`
}

type controlledVerifyCrashTransport struct {
	base   http.RoundTripper
	script *deterministicCrashScript
}

func (transport *controlledVerifyCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := controlledVerifyHTTPPoints(request.URL.Path)
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

func controlledVerifyHTTPPoints(
	path string,
) (replicationCrashPoint, replicationCrashPoint, bool) {
	switch path {
	case "/api/v1/verifications":
		return crashBeforeVerifyCreate, crashAfterVerifyCreate, true
	case "/api/v1/operations/" + controlledVerifyCrashOperationID + "/claim":
		return crashBeforeVerifyClaim, crashAfterVerifyClaim, true
	case "/api/v1/verifications/" + controlledVerifyCrashOperationID + "/manifest":
		return crashBeforeVerifyManifest, crashAfterVerifyManifest, true
	case "/api/v1/verifications/" + controlledVerifyCrashOperationID + "/complete":
		return crashBeforeVerifyComplete, crashAfterVerifyComplete, true
	default:
		return "", "", false
	}
}

type controlledVerifyCancellation struct {
	mutex  sync.Mutex
	cancel context.CancelFunc
}

func (cancellation *controlledVerifyCancellation) replace(cancel context.CancelFunc) {
	cancellation.mutex.Lock()
	cancellation.cancel = cancel
	cancellation.mutex.Unlock()
}

func (cancellation *controlledVerifyCancellation) trigger() {
	cancellation.mutex.Lock()
	cancel := cancellation.cancel
	cancellation.mutex.Unlock()

	if cancel != nil {
		cancel()
	}
}

type controlledVerifyCrashReader struct {
	reader       provider.Reader
	script       *deterministicCrashScript
	cancellation *controlledVerifyCancellation
	opens        atomic.Int64
}

func (reader *controlledVerifyCrashReader) Stat(
	ctx context.Context,
	key string,
) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader *controlledVerifyCrashReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if err := reader.script.hit(crashBeforeVerifyRead); err != nil {
		reader.cancellation.trigger()

		return nil, err
	}

	reader.opens.Add(1)

	stream, err := reader.reader.OpenRange(ctx, key, offset, length)
	if err != nil {
		return nil, err
	}

	return &controlledVerifyCrashReadCloser{
		ReadCloser: stream, script: reader.script, cancellation: reader.cancellation,
	}, nil
}

type controlledVerifyCrashReadCloser struct {
	io.ReadCloser

	script       *deterministicCrashScript
	cancellation *controlledVerifyCancellation
}

func (stream *controlledVerifyCrashReadCloser) Close() error {
	closeErr := stream.ReadCloser.Close()

	crashErr := stream.script.hit(crashAfterVerifyRead)
	if crashErr != nil {
		stream.cancellation.trigger()
	}

	return errors.Join(closeErr, crashErr)
}

func TestControlledVerifierCrashMatrixConverges(t *testing.T) {
	t.Parallel()

	for _, point := range []replicationCrashPoint{
		crashBeforeVerifyCreate,
		crashAfterVerifyCreate,
		crashBeforeVerifyClaim,
		crashAfterVerifyClaim,
		crashBeforeVerifyManifest,
		crashAfterVerifyManifest,
		crashBeforeVerifyRead,
		crashAfterVerifyRead,
		crashBeforeVerifyComplete,
		crashAfterVerifyComplete,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testControlledVerifyCrashPoint(t, point)
		})
	}
}

func TestControlledVerifierReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledVerifyCrashFixture(t, &deterministicCrashScript{})
			fixture.state.terminalState = terminalState

			result, err := fixture.coordinator.Verify(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrVerifyOperationFailed) ||
				result.Operation.State != terminalState {
				t.Fatalf("unexpected recovered verify result: result=%+v err=%v", result, err)
			}

			fixture.state.mutex.Lock()
			claimCalls := fixture.state.calls["claim"]
			fixture.state.mutex.Unlock()

			if claimCalls != 0 || fixture.reader.opens.Load() != 0 {
				t.Fatalf(
					"terminal verify crossed remote boundaries: claims=%d reads=%d",
					claimCalls,
					fixture.reader.opens.Load(),
				)
			}
		})
	}
}

func TestControlledVerifierRejectsInvalidOperationStatePhase(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		state string
		phase string
	}{
		{name: "planned verifying", state: "planned", phase: "verifying"},
		{name: "running planned", state: "running", phase: "planned"},
		{name: "committing", state: "committing", phase: "committing"},
		{name: "failed phase mismatch", state: "failed", phase: "failed"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledVerifyCrashFixture(t, &deterministicCrashScript{})
			fixture.state.operationState = testCase.state
			fixture.state.operationPhase = testCase.phase

			_, err := fixture.coordinator.Verify(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrControlPlaneResponse) {
				t.Fatalf("invalid verify state/phase was accepted: %v", err)
			}

			if fixture.reader.opens.Load() != 0 {
				t.Fatalf("invalid verify state/phase performed %d provider reads", fixture.reader.opens.Load())
			}
		})
	}
}

func testControlledVerifyCrashPoint(t *testing.T, point replicationCrashPoint) {
	t.Helper()

	script := &deterministicCrashScript{target: point}
	fixture := newControlledVerifyCrashFixture(t, script)
	firstContext, cancelFirst := context.WithCancel(context.Background())
	fixture.cancellation.replace(cancelFirst)

	_, firstErr := fixture.coordinator.Verify(firstContext, fixture.request)

	cancelFirst()

	readsBeforeRetry := fixture.reader.opens.Load()

	if point == crashBeforeVerifyRead || point == crashAfterVerifyRead {
		if !errors.Is(firstErr, context.Canceled) {
			t.Fatalf("provider crash did not cancel controlled verify at %s: %v", point, firstErr)
		}
	} else if !errors.Is(firstErr, errInjectedReplicationCrash) {
		t.Fatalf("first controlled verify did not stop at %s: %v", point, firstErr)
	}

	if point != crashAfterVerifyComplete && fixture.state.isCompleted() {
		t.Fatalf("controlled verify committed before retry at %s", point)
	}

	result, retryErr := fixture.coordinator.Verify(context.Background(), fixture.request)
	if retryErr != nil {
		t.Fatalf("controlled verify did not converge after %s: %v", point, retryErr)
	}

	if !script.didFire() {
		t.Fatalf("controlled verify crash point %s was never reached", point)
	}

	wantAlreadyCompleted := point == crashAfterVerifyComplete
	if result.Completion.State != "succeeded" || result.Completion.Verified != 1 ||
		result.AlreadyCompleted != wantAlreadyCompleted {
		t.Fatalf("controlled verify returned an invalid terminal result after %s: %+v", point, result)
	}

	if !wantAlreadyCompleted && (result.Verification.Verified != 1 ||
		len(result.Verification.Evidence) != 1) {
		t.Fatalf("controlled verify lost local evidence after %s: %+v", point, result)
	}

	fixture.state.assertConverged(t, point)

	if point == crashAfterVerifyComplete && fixture.reader.opens.Load() != readsBeforeRetry {
		t.Fatalf(
			"lost verify completion response repeated provider reads: before=%d after=%d",
			readsBeforeRetry,
			fixture.reader.opens.Load(),
		)
	}
}

func newControlledVerifyCrashFixture(
	t *testing.T,
	script *deterministicCrashScript,
) controlledVerifyCrashFixture {
	t.Helper()

	payload := bytes.Repeat([]byte{'v'}, 18)
	digest := sha256.Sum256(payload)
	recovery := verificationRecovery(t, hex.EncodeToString(digest[:]), []manifest.Location{{
		DriverID: "memory", StorageKey: "verify/extent", Length: uint64(len(payload)),
	}})
	cancellation := &controlledVerifyCancellation{}
	reader := &controlledVerifyCrashReader{
		reader:       verificationReader{data: payload},
		script:       script,
		cancellation: cancellation,
	}

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{"memory": reader})
	if err != nil {
		t.Fatalf("construct crash-matrix verifier: %v", err)
	}

	state := &controlledVerifyReplayState{
		recovery: recovery, bodies: make(map[string][]byte), calls: make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledVerifyCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &controlledVerifyCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct verify crash control client: %v", err)
	}

	coordinator, err := sdk.NewControlledVerifier(control, verifier, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled verifier: %v", err)
	}

	return controlledVerifyCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledVerifyRequest{
			NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
			DriverID: "memory", IdempotencyKey: "controlled-verify-crash-v1",
		},
		state: state, reader: reader, cancellation: cancellation,
	}
}

func newControlledVerifyCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledVerifyReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled verify crash request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/verifications":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledVerifyCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/verifications/" + controlledVerifyCrashOperationID + "/manifest":
			state.serveManifest(t, response, body)
		case "/api/v1/verifications/" + controlledVerifyCrashOperationID + "/complete":
			state.serveCompletion(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledVerifyReplayState) serveOperation(
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

func (state *controlledVerifyReplayState) operationLocked() sdk.VerifyOperation {
	operationState := "planned"
	phase := "planned"
	revision := uint64(1)

	if state.claimed {
		operationState = "running"
		phase = "verifying"
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

	operation := sdk.VerifyOperation{
		ID:          controlledVerifyCrashOperationID,
		NamespaceID: state.recovery.Manifest.NamespaceID,
		Kind:        "verify", State: operationState, Phase: phase,
		RequestedBy: controlledVerifyCrashClientID, Incarnation: controlledVerifyCrashIncarnation,
		Revision: revision, UsefulBytesTotal: state.recovery.Locations[0].Length,
		VersionID: state.recovery.ManifestSHA256, ManifestSHA256: state.recovery.ManifestSHA256,
		RecoveryRevision: 1, DriverID: "memory", CreatedAt: 1, UpdatedAt: revision,
	}
	if state.completed {
		operation.CompletedVerified = state.completion.Verified
		operation.CompletedMissing = state.completion.Missing
		operation.CompletedCorrupt = state.completion.Corrupt
		operation.CompletedUnavailable = state.completion.Unavailable
	}

	return operation
}

func (state *controlledVerifyReplayState) serveClaim(
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
		OperationID: controlledVerifyCrashOperationID,
		LeaseID:     controlledVerifyCrashLeaseID, OwnerClientID: controlledVerifyCrashClientID,
		Incarnation: controlledVerifyCrashIncarnation, FencingToken: 13,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledVerifyReplayState) serveManifest(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "manifest", body)
	writeJSON(t, response, state.recovery)
}

func (state *controlledVerifyReplayState) serveCompletion(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "completion", body)

	var completed controlledVerifyCompletionBody
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Errorf("decode verify completion: %v", err)
		http.Error(response, "invalid completion", http.StatusBadRequest)

		return
	}

	if completed.LeaseID != controlledVerifyCrashLeaseID ||
		completed.Incarnation != controlledVerifyCrashIncarnation ||
		completed.FencingToken != 13 || completed.ManifestSHA256 != state.recovery.ManifestSHA256 ||
		len(completed.Evidence) != 1 ||
		completed.Evidence[0].Condition != sdk.VerificationVerified {
		t.Errorf("invalid controlled verify completion: %+v", completed)
		http.Error(response, "invalid completion identity", http.StatusConflict)

		return
	}

	completion := sdk.CompletedVerify{
		OperationID:    controlledVerifyCrashOperationID,
		ManifestSHA256: state.recovery.ManifestSHA256,
		State:          "succeeded", Verified: 1,
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

func (state *controlledVerifyReplayState) recordExactRequest(
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
		t.Errorf("controlled verify retry changed its %s request", name)
	}
}

func (state *controlledVerifyReplayState) isCompleted() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.completed
}

func (state *controlledVerifyReplayState) assertConverged(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.completionCommits != 1 || !state.completed {
		t.Fatalf(
			"controlled verify did not converge logical commits after %s: create=%d claim=%d complete=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.completionCommits,
		)
	}

	expectedCreateCalls := 2
	if point == crashBeforeVerifyCreate {
		expectedCreateCalls = 1
	}

	expectedClaimCalls := 2
	if point == crashBeforeVerifyCreate || point == crashAfterVerifyCreate ||
		point == crashBeforeVerifyClaim || point == crashAfterVerifyComplete {
		expectedClaimCalls = 1
	}

	if state.calls["create"] != expectedCreateCalls ||
		state.calls["claim"] != expectedClaimCalls || state.calls["completion"] != 1 {
		t.Fatalf(
			"controlled verify crossed remote barriers incorrectly after %s: create=%d/%d claim=%d/%d complete=%d/1",
			point,
			state.calls["create"],
			expectedCreateCalls,
			state.calls["claim"],
			expectedClaimCalls,
			state.calls["completion"],
		)
	}
}
