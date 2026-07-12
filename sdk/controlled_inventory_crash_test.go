package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledInventoryCrashOperationID = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	controlledInventoryCrashIncarnation = "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
	controlledInventoryCrashClientID    = "controlled-inventory-crash-client"
	controlledInventoryCrashLeaseID     = "operation/d0d1d2d3d4d5d6d7d8d9dadbdcdddedf/write"
	controlledInventoryNamespaceID      = "202122232425262728292a2b2c2d2e2f"
)

const (
	crashBeforeInventoryCreate    = "before_inventory_create"
	crashAfterInventoryCreate     = "after_inventory_create"
	crashBeforeInventoryClaim     = "before_inventory_claim"
	crashAfterInventoryClaim      = "after_inventory_claim"
	crashBeforeInventoryListOne   = "before_inventory_list_page_1"
	crashAfterInventoryListOne    = "after_inventory_list_page_1"
	crashBeforeInventoryReportOne = "before_inventory_report_page_1"
	crashAfterInventoryReportOne  = "after_inventory_report_page_1"
	crashBeforeInventoryListTwo   = "before_inventory_list_page_2"
	crashAfterInventoryListTwo    = "after_inventory_list_page_2"
	crashBeforeInventoryReportTwo = "before_inventory_report_page_2"
	crashAfterInventoryReportTwo  = "after_inventory_report_page_2"
	crashBeforeInventoryComplete  = "before_inventory_complete"
	crashAfterInventoryComplete   = "after_inventory_complete"
)

var errUnexpectedControlledInventory = errors.New("unexpected controlled inventory request")

type controlledInventoryCrashFixture struct {
	coordinator *sdk.ControlledInventoryReconciler
	request     sdk.ControlledInventoryRequest
	state       *controlledInventoryReplayState
	inventory   *controlledInventoryCrashProvider
}

type controlledInventoryReplayState struct {
	mutex sync.Mutex

	pageHashes     [2]string
	reportSHA256   string
	bodies         map[string][]byte
	calls          map[string]int
	terminalState  string
	operationState string
	operationPhase string

	created           bool
	claimed           bool
	completed         bool
	pageCommitted     [2]bool
	createCommits     int
	claimTransitions  int
	pageCommits       [2]int
	completionCommits int
	completion        sdk.CompletedInventory
}

type controlledInventoryPageBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	Sequence     uint64 `json:"sequence"`
	Cursor       string `json:"cursor"`
	NextCursor   string `json:"next_cursor"`
	Objects      []struct {
		StorageKey string `json:"storage_key"`
	} `json:"objects"`
}

type controlledInventoryCompletionBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	LastSequence uint64 `json:"last_sequence"`
	ReportSHA256 string `json:"report_sha256"`
}

type controlledInventoryCrashTransport struct {
	base   http.RoundTripper
	script *deterministicCrashScript
	mutex  sync.Mutex
	pages  int
}

func (transport *controlledInventoryCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := transport.crashPoints(request.URL.Path)
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

func (transport *controlledInventoryCrashTransport) crashPoints(
	path string,
) (replicationCrashPoint, replicationCrashPoint, bool) {
	switch path {
	case "/api/v1/inventory-reconciliations":
		return crashBeforeInventoryCreate, crashAfterInventoryCreate, true
	case "/api/v1/operations/" + controlledInventoryCrashOperationID + "/claim":
		return crashBeforeInventoryClaim, crashAfterInventoryClaim, true
	case "/api/v1/inventory-reconciliations/" + controlledInventoryCrashOperationID + "/pages":
		transport.mutex.Lock()
		transport.pages++
		page := transport.pages
		transport.mutex.Unlock()

		switch page {
		case 1:
			return crashBeforeInventoryReportOne, crashAfterInventoryReportOne, true
		case 2:
			return crashBeforeInventoryReportTwo, crashAfterInventoryReportTwo, true
		default:
			return "", "", false
		}
	case "/api/v1/inventory-reconciliations/" + controlledInventoryCrashOperationID + "/complete":
		return crashBeforeInventoryComplete, crashAfterInventoryComplete, true
	default:
		return "", "", false
	}
}

type controlledInventoryCrashProvider struct {
	script *deterministicCrashScript
	lists  atomic.Int64
}

func (inventory *controlledInventoryCrashProvider) List(
	_ context.Context,
	prefix,
	cursor string,
) (provider.InventoryPage, error) {
	if prefix != "archive" {
		return provider.InventoryPage{}, fmt.Errorf(
			"%w: prefix %q",
			errUnexpectedControlledInventory,
			prefix,
		)
	}

	inventory.lists.Add(1)

	before := replicationCrashPoint(crashBeforeInventoryListOne)
	after := replicationCrashPoint(crashAfterInventoryListOne)
	page := provider.InventoryPage{
		Objects: []provider.Object{{
			Key: "archive/objects/known", SizeBytes: 11,
			ETag: "known-etag", Version: "known-v1",
		}},
		NextCursor: "archive/objects/known",
	}

	if cursor != "" {
		before = crashBeforeInventoryListTwo
		after = crashAfterInventoryListTwo

		if cursor != "archive/objects/known" {
			return provider.InventoryPage{}, fmt.Errorf(
				"%w: cursor %q",
				errUnexpectedControlledInventory,
				cursor,
			)
		}

		page = provider.InventoryPage{Objects: []provider.Object{{
			Key: "archive/objects/unknown", SizeBytes: 13,
			ETag: "unknown-etag", Version: "unknown-v1",
		}}}
	}

	if err := inventory.script.hit(before); err != nil {
		return provider.InventoryPage{}, err
	}

	if err := inventory.script.hit(after); err != nil {
		return provider.InventoryPage{}, err
	}

	return page, nil
}

func TestControlledInventoryCrashMatrixConverges(t *testing.T) {
	t.Parallel()

	for _, point := range []replicationCrashPoint{
		crashBeforeInventoryCreate,
		crashAfterInventoryCreate,
		crashBeforeInventoryClaim,
		crashAfterInventoryClaim,
		crashBeforeInventoryListOne,
		crashAfterInventoryListOne,
		crashBeforeInventoryReportOne,
		crashAfterInventoryReportOne,
		crashBeforeInventoryListTwo,
		crashAfterInventoryListTwo,
		crashBeforeInventoryReportTwo,
		crashAfterInventoryReportTwo,
		crashBeforeInventoryComplete,
		crashAfterInventoryComplete,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testControlledInventoryCrashPoint(t, point)
		})
	}
}

func TestControlledInventoryReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledInventoryCrashFixture(t, &deterministicCrashScript{})
			fixture.state.terminalState = terminalState

			result, err := fixture.coordinator.Reconcile(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrInventoryOperationFailed) ||
				result.Operation.State != terminalState {
				t.Fatalf("unexpected recovered inventory result: result=%+v err=%v", result, err)
			}

			fixture.state.mutex.Lock()
			claimCalls := fixture.state.calls["claim"]
			fixture.state.mutex.Unlock()

			if claimCalls != 0 || fixture.inventory.lists.Load() != 0 {
				t.Fatalf(
					"terminal inventory crossed remote boundaries: claims=%d lists=%d",
					claimCalls,
					fixture.inventory.lists.Load(),
				)
			}
		})
	}
}

func TestControlledInventoryRejectsInvalidOperationStatePhase(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		state string
		phase string
	}{
		{name: "planned inventorying", state: "planned", phase: "inventorying"},
		{name: "running planned", state: "running", phase: "planned"},
		{name: "verifying inventory", state: "verifying", phase: "verifying_inventory"},
		{name: "failed phase mismatch", state: "failed", phase: "failed"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledInventoryCrashFixture(t, &deterministicCrashScript{})
			fixture.state.operationState = testCase.state
			fixture.state.operationPhase = testCase.phase

			_, err := fixture.coordinator.Reconcile(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrControlPlaneResponse) {
				t.Fatalf("invalid inventory state/phase was accepted: %v", err)
			}

			if fixture.inventory.lists.Load() != 0 {
				t.Fatalf("invalid inventory performed %d provider lists", fixture.inventory.lists.Load())
			}
		})
	}
}

func testControlledInventoryCrashPoint(t *testing.T, point replicationCrashPoint) {
	t.Helper()

	script := &deterministicCrashScript{target: point}
	fixture := newControlledInventoryCrashFixture(t, script)

	_, firstErr := fixture.coordinator.Reconcile(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedReplicationCrash) {
		t.Fatalf("first controlled inventory did not stop at %s: %v", point, firstErr)
	}

	listsBeforeRetry := fixture.inventory.lists.Load()
	if point != crashAfterInventoryComplete && fixture.state.isCompleted() {
		t.Fatalf("controlled inventory committed before retry at %s", point)
	}

	result, retryErr := fixture.coordinator.Reconcile(context.Background(), fixture.request)
	if retryErr != nil {
		t.Fatalf("controlled inventory did not converge after %s: %v", point, retryErr)
	}

	if !script.didFire() {
		t.Fatalf("controlled inventory crash point %s was never reached", point)
	}

	wantAlreadyCompleted := point == crashAfterInventoryComplete
	if result.Completion.State != "succeeded" || result.Completion.Pages != 2 ||
		result.Completion.Objects != 2 || result.Completion.Known != 1 ||
		result.Completion.Quarantined != 1 || result.Completion.Missing != 1 ||
		result.AlreadyCompleted != wantAlreadyCompleted {
		t.Fatalf("controlled inventory returned an invalid terminal result after %s: %+v", point, result)
	}

	fixture.state.assertConverged(t, point)

	if wantAlreadyCompleted && fixture.inventory.lists.Load() != listsBeforeRetry {
		t.Fatalf(
			"lost inventory completion response repeated provider listing: before=%d after=%d",
			listsBeforeRetry,
			fixture.inventory.lists.Load(),
		)
	}
}

func newControlledInventoryCrashFixture(
	t *testing.T,
	script *deterministicCrashScript,
) controlledInventoryCrashFixture {
	t.Helper()

	pageHashes := [2]string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	reportDigest := sha256.Sum256([]byte(pageHashes[0] + pageHashes[1]))
	state := &controlledInventoryReplayState{
		pageHashes: pageHashes, reportSHA256: hex.EncodeToString(reportDigest[:]),
		bodies: make(map[string][]byte), calls: make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledInventoryCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &controlledInventoryCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct inventory crash control client: %v", err)
	}

	inventory := &controlledInventoryCrashProvider{script: script}

	coordinator, err := sdk.NewControlledInventoryReconciler(control, inventory, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled inventory: %v", err)
	}

	return controlledInventoryCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledInventoryRequest{
			NamespaceID: controlledInventoryNamespaceID, DriverID: "local-main",
			Prefix: "archive", IdempotencyKey: "controlled-inventory-crash-v1",
		},
		state: state, inventory: inventory,
	}
}

func newControlledInventoryCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledInventoryReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled inventory crash request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/inventory-reconciliations":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledInventoryCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/inventory-reconciliations/" + controlledInventoryCrashOperationID + "/pages":
			state.servePage(t, response, body)
		case "/api/v1/inventory-reconciliations/" + controlledInventoryCrashOperationID + "/complete":
			state.serveCompletion(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledInventoryReplayState) serveOperation(
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

func (state *controlledInventoryReplayState) operationLocked() sdk.InventoryOperation {
	operationState := "planned"
	phase := "planned"
	revision := uint64(1)

	if state.claimed {
		operationState = "running"
		phase = "inventorying"
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

	operation := sdk.InventoryOperation{
		ID: controlledInventoryCrashOperationID, NamespaceID: controlledInventoryNamespaceID,
		Kind: "reconcile", State: operationState, Phase: phase,
		RequestedBy: controlledInventoryCrashClientID,
		Incarnation: controlledInventoryCrashIncarnation, Revision: revision,
		DriverID: "local-main", DriverRevision: 3, Prefix: "archive",
		QuarantineGraceSeconds: 86_400, CreatedAt: 1, UpdatedAt: revision,
	}
	if state.completed {
		operation.CompletedReportSHA256 = state.completion.ReportSHA256
		operation.CompletedPages = state.completion.Pages
		operation.CompletedObjects = state.completion.Objects
		operation.CompletedKnown = state.completion.Known
		operation.CompletedQuarantined = state.completion.Quarantined
		operation.CompletedMissing = state.completion.Missing
	}

	return operation
}

func (state *controlledInventoryReplayState) serveClaim(
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
		OperationID:   controlledInventoryCrashOperationID,
		LeaseID:       controlledInventoryCrashLeaseID,
		OwnerClientID: controlledInventoryCrashClientID,
		Incarnation:   controlledInventoryCrashIncarnation, FencingToken: 17,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledInventoryReplayState) servePage(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()

	var page controlledInventoryPageBody
	if err := json.Unmarshal(body, &page); err != nil {
		t.Errorf("decode inventory page: %v", err)
		http.Error(response, "invalid page", http.StatusBadRequest)

		return
	}

	if page.Sequence == 0 || page.Sequence > 2 {
		t.Errorf("invalid inventory page sequence: %d", page.Sequence)
		http.Error(response, "invalid sequence", http.StatusBadRequest)

		return
	}

	index := int(page.Sequence - 1)
	state.recordExactRequest(t, fmt.Sprintf("page-%d", page.Sequence), body)

	wantCursor := ""
	wantNextCursor := "archive/objects/known"
	wantKey := "archive/objects/known"

	if page.Sequence == 2 {
		wantCursor = "archive/objects/known"
		wantNextCursor = ""
		wantKey = "archive/objects/unknown"
	}

	if page.LeaseID != controlledInventoryCrashLeaseID ||
		page.Incarnation != controlledInventoryCrashIncarnation || page.FencingToken != 17 ||
		page.Cursor != wantCursor || page.NextCursor != wantNextCursor ||
		len(page.Objects) != 1 || page.Objects[0].StorageKey != wantKey {
		t.Errorf("invalid controlled inventory page: %+v", page)
		http.Error(response, "invalid page identity", http.StatusConflict)

		return
	}

	state.mutex.Lock()
	if !state.pageCommitted[index] {
		state.pageCommitted[index] = true
		state.pageCommits[index]++
	}
	state.mutex.Unlock()

	writeJSON(t, response, sdk.InventoryPageReceipt{
		OperationID: controlledInventoryCrashOperationID, Sequence: page.Sequence,
		ReportSHA256: state.pageHashes[index], ObjectCount: 1, NextCursor: page.NextCursor,
	})
}

func (state *controlledInventoryReplayState) serveCompletion(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "completion", body)

	var completed controlledInventoryCompletionBody
	if err := json.Unmarshal(body, &completed); err != nil {
		t.Errorf("decode inventory completion: %v", err)
		http.Error(response, "invalid completion", http.StatusBadRequest)

		return
	}

	state.mutex.Lock()
	pagesCommitted := state.pageCommitted[0] && state.pageCommitted[1]
	state.mutex.Unlock()

	if completed.LeaseID != controlledInventoryCrashLeaseID ||
		completed.Incarnation != controlledInventoryCrashIncarnation ||
		completed.FencingToken != 17 || completed.LastSequence != 2 ||
		completed.ReportSHA256 != state.reportSHA256 || !pagesCommitted {
		t.Errorf("invalid controlled inventory completion: %+v", completed)
		http.Error(response, "invalid completion identity", http.StatusConflict)

		return
	}

	completion := sdk.CompletedInventory{
		OperationID: controlledInventoryCrashOperationID, State: "succeeded",
		ReportSHA256: state.reportSHA256, Pages: 2, Objects: 2,
		Known: 1, Quarantined: 1, Missing: 1,
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

func (state *controlledInventoryReplayState) recordExactRequest(
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
		t.Errorf("controlled inventory retry changed its %s request", name)
	}
}

func (state *controlledInventoryReplayState) isCompleted() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.completed
}

func (state *controlledInventoryReplayState) assertConverged(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.pageCommits != [2]int{1, 1} || state.completionCommits != 1 || !state.completed {
		t.Fatalf(
			"controlled inventory did not converge logical commits after %s: create=%d claim=%d pages=%v complete=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.pageCommits,
			state.completionCommits,
		)
	}

	expectedCreateCalls := 2
	if point == crashBeforeInventoryCreate {
		expectedCreateCalls = 1
	}

	expectedClaimCalls := 2
	if point == crashBeforeInventoryCreate || point == crashAfterInventoryCreate ||
		point == crashBeforeInventoryClaim || point == crashAfterInventoryComplete {
		expectedClaimCalls = 1
	}

	if state.calls["create"] != expectedCreateCalls ||
		state.calls["claim"] != expectedClaimCalls || state.calls["completion"] != 1 ||
		state.calls["page-1"] < 1 || state.calls["page-1"] > 2 ||
		state.calls["page-2"] < 1 || state.calls["page-2"] > 2 {
		t.Fatalf(
			"controlled inventory crossed remote barriers incorrectly after %s: create=%d/%d claim=%d/%d pages=%d,%d complete=%d/1",
			point,
			state.calls["create"],
			expectedCreateCalls,
			state.calls["claim"],
			expectedClaimCalls,
			state.calls["page-1"],
			state.calls["page-2"],
			state.calls["completion"],
		)
	}
}
