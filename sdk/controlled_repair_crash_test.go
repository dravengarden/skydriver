package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

var errInjectedRepairCrash = errors.New("injected Carrack repair crash")

type repairCrashPoint string

const (
	crashBeforeRepairCreate     repairCrashPoint = "before_repair_create"
	crashAfterRepairCreate      repairCrashPoint = "after_repair_create"
	crashBeforeRepairClaim      repairCrashPoint = "before_repair_claim"
	crashAfterRepairClaim       repairCrashPoint = "after_repair_claim"
	crashBeforeRepairSnapshot   repairCrashPoint = "before_repair_snapshot"
	crashAfterRepairSnapshot    repairCrashPoint = "after_repair_snapshot"
	crashBeforeRepairSourceRead repairCrashPoint = "before_repair_source_read"
	crashAfterRepairSourceRead  repairCrashPoint = "after_repair_source_read"
	crashBeforeRepairPut        repairCrashPoint = "before_repair_target_put"
	crashAfterRepairPut         repairCrashPoint = "after_repair_target_put"
	crashBeforeRepairReadback   repairCrashPoint = "before_repair_target_readback"
	crashAfterRepairReadback    repairCrashPoint = "after_repair_target_readback"
	crashBeforeRepairStat       repairCrashPoint = "before_repair_target_stat"
	crashAfterRepairStat        repairCrashPoint = "after_repair_target_stat"
	crashBeforeRepairComplete   repairCrashPoint = "before_repair_complete"
	crashAfterRepairComplete    repairCrashPoint = "after_repair_complete"
)

const (
	repairCrashOperationID = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
	repairCrashIncarnation = "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	repairCrashClientID    = "repair-crash-client"
	repairCrashLeaseID     = "operation/c0c1c2c3c4c5c6c7c8c9cacbcccdcecf/write"
	repairCrashTargetID    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	repairCrashSourceID    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type repairCrashScript struct {
	mutex  sync.Mutex
	target repairCrashPoint
	fired  bool
}

func (script *repairCrashScript) hit(point repairCrashPoint) error {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	if script.fired || script.target != point {
		return nil
	}

	script.fired = true

	return fmt.Errorf("%w: %s", errInjectedRepairCrash, point)
}

func (script *repairCrashScript) didFire() bool {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	return script.fired
}

type repairCrashTransport struct {
	base   http.RoundTripper
	script *repairCrashScript
}

func (transport *repairCrashTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	before, after, controlled := repairHTTPPoints(request.URL.Path)
	if !controlled {
		return transport.base.RoundTrip(request)
	}

	if err := transport.script.hit(before); err != nil {
		return nil, err
	}

	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	if crashErr := transport.script.hit(after); crashErr != nil {
		return nil, errors.Join(crashErr, response.Body.Close())
	}

	return response, nil
}

func repairHTTPPoints(path string) (repairCrashPoint, repairCrashPoint, bool) {
	switch path {
	case "/api/v1/repairs":
		return crashBeforeRepairCreate, crashAfterRepairCreate, true
	case "/api/v1/operations/" + repairCrashOperationID + "/claim":
		return crashBeforeRepairClaim, crashAfterRepairClaim, true
	case "/api/v1/repairs/" + repairCrashOperationID + "/snapshot":
		return crashBeforeRepairSnapshot, crashAfterRepairSnapshot, true
	case "/api/v1/repairs/" + repairCrashOperationID + "/complete":
		return crashBeforeRepairComplete, crashAfterRepairComplete, true
	default:
		return "", "", false
	}
}

type countingRepairArchive struct {
	base   *memoryArchive
	script *repairCrashScript
	puts   atomic.Int64
	reads  atomic.Int64
}

func (archiveStore *countingRepairArchive) Stat(
	ctx context.Context,
	key string,
) (provider.Object, error) {
	if err := archiveStore.script.hit(crashBeforeRepairStat); err != nil {
		return provider.Object{}, err
	}

	object, err := archiveStore.base.Stat(ctx, key)
	if err != nil {
		return provider.Object{}, err
	}

	if err := archiveStore.script.hit(crashAfterRepairStat); err != nil {
		return provider.Object{}, err
	}

	return object, nil
}

func (archiveStore *countingRepairArchive) Put(
	ctx context.Context,
	key string,
	body io.Reader,
	options provider.PutOptions,
) (provider.Object, error) {
	if err := archiveStore.script.hit(crashBeforeRepairPut); err != nil {
		return provider.Object{}, err
	}

	archiveStore.puts.Add(1)

	object, err := archiveStore.base.Put(ctx, key, body, options)
	if err != nil {
		return provider.Object{}, err
	}

	if err := archiveStore.script.hit(crashAfterRepairPut); err != nil {
		return provider.Object{}, err
	}

	return object, nil
}

func (archiveStore *countingRepairArchive) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if err := archiveStore.script.hit(crashBeforeRepairReadback); err != nil {
		return nil, err
	}

	archiveStore.reads.Add(1)

	stream, err := archiveStore.base.OpenRange(ctx, key, offset, length)
	if err != nil {
		return nil, err
	}

	return &repairCrashReadCloser{
		ReadCloser: stream, script: archiveStore.script, after: crashAfterRepairReadback,
	}, nil
}

type repairCrashSourceReader struct {
	reader provider.Reader
	script *repairCrashScript
}

func (reader *repairCrashSourceReader) Stat(
	ctx context.Context,
	key string,
) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader *repairCrashSourceReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if err := reader.script.hit(crashBeforeRepairSourceRead); err != nil {
		return nil, err
	}

	stream, err := reader.reader.OpenRange(ctx, key, offset, length)
	if err != nil {
		return nil, err
	}

	return &repairCrashReadCloser{
		ReadCloser: stream, script: reader.script, after: crashAfterRepairSourceRead,
	}, nil
}

type repairCrashReadCloser struct {
	io.ReadCloser

	script *repairCrashScript
	after  repairCrashPoint
}

func (stream *repairCrashReadCloser) Close() error {
	return errors.Join(stream.ReadCloser.Close(), stream.script.hit(stream.after))
}

type repairCrashState struct {
	mutex sync.Mutex

	recovery manifest.RecoveryManifest
	payload  []byte
	digest   string
	state    string
	bodies   map[string][]byte
	calls    map[string]int

	completeCommits int
}

type repairCrashFixture struct {
	coordinator      *sdk.ControlledRepairer
	request          sdk.ControlledRepairRequest
	state            *repairCrashState
	destination      *countingRepairArchive
	stagingDirectory string
}

func TestControlledRepairerNonterminalCrashMatrixConverges(t *testing.T) {
	t.Parallel()

	for _, point := range []repairCrashPoint{
		crashBeforeRepairCreate,
		crashAfterRepairCreate,
		crashBeforeRepairClaim,
		crashAfterRepairClaim,
		crashBeforeRepairSnapshot,
		crashAfterRepairSnapshot,
		crashBeforeRepairSourceRead,
		crashAfterRepairSourceRead,
		crashBeforeRepairPut,
		crashAfterRepairPut,
		crashBeforeRepairReadback,
		crashAfterRepairReadback,
		crashBeforeRepairStat,
		crashAfterRepairStat,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testRepairNonterminalCrashPoint(t, point)
		})
	}
}

func TestControlledRepairerConvergesAfterLostCompletionResponse(t *testing.T) {
	t.Parallel()

	for _, point := range []repairCrashPoint{
		crashBeforeRepairComplete,
		crashAfterRepairComplete,
	} {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testRepairCompletionCrashPoint(t, point)
		})
	}
}

func testRepairNonterminalCrashPoint(t *testing.T, point repairCrashPoint) {
	t.Helper()

	script := &repairCrashScript{target: point}
	fixture := newRepairCrashFixture(t, script)

	_, firstErr := fixture.coordinator.Repair(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedRepairCrash) {
		t.Fatalf("first repair did not stop at %s: %v", point, firstErr)
	}

	fixture.state.assertUncommitted(t, point)

	result, retryErr := fixture.coordinator.Repair(context.Background(), fixture.request)
	if retryErr != nil || result.Completion.State != "succeeded" || result.AlreadyCompleted {
		t.Fatalf("repair did not converge after %s: result=%+v err=%v", point, result, retryErr)
	}

	assertRepairCrashObject(t, fixture)
	assertDirectoryEmpty(t, fixture.stagingDirectory)
	fixture.state.assertSucceeded(t, point)

	if !script.didFire() {
		t.Fatalf("repair nonterminal crash point %s was never reached", point)
	}
}

func TestControlledRepairerReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			script := &repairCrashScript{}
			fixture := newRepairCrashFixture(t, script)
			fixture.state.setState(terminalState)

			result, err := fixture.coordinator.Repair(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrRepairOperationFailed) || result.Operation.State != terminalState {
				t.Fatalf("repair terminal receipt did not return %s: result=%+v err=%v", terminalState, result, err)
			}

			if fixture.destination.puts.Load() != 0 || fixture.state.callCount("claim") != 0 {
				t.Fatalf("terminal repair %s performed new work", terminalState)
			}
		})
	}
}

func testRepairCompletionCrashPoint(t *testing.T, point repairCrashPoint) {
	t.Helper()

	script := &repairCrashScript{target: point}
	fixture := newRepairCrashFixture(t, script)

	_, firstErr := fixture.coordinator.Repair(context.Background(), fixture.request)
	if !errors.Is(firstErr, errInjectedRepairCrash) {
		t.Fatalf("first repair did not stop at %s: %v", point, firstErr)
	}

	putsAfterFirst := fixture.destination.puts.Load()
	readsAfterFirst := fixture.destination.reads.Load()
	assertRepairCrashObject(t, fixture)

	result, retryErr := fixture.coordinator.Repair(context.Background(), fixture.request)
	if retryErr != nil || result.Completion.State != "succeeded" {
		t.Fatalf("repair did not converge after %s: result=%+v err=%v", point, result, retryErr)
	}

	wantAlreadyCompleted := point == crashAfterRepairComplete
	if result.AlreadyCompleted != wantAlreadyCompleted {
		t.Fatalf(
			"repair completion receipt after %s = %v, want %v",
			point,
			result.AlreadyCompleted,
			wantAlreadyCompleted,
		)
	}

	if wantAlreadyCompleted {
		if fixture.destination.puts.Load() != putsAfterFirst ||
			fixture.destination.reads.Load() != readsAfterFirst {
			t.Fatalf("committed repair response loss repeated provider I/O after %s", point)
		}
	} else if fixture.destination.puts.Load() <= putsAfterFirst ||
		fixture.destination.reads.Load() <= readsAfterFirst {
		t.Fatalf("uncommitted repair did not repeat safe provider I/O after %s", point)
	}

	assertRepairCrashObject(t, fixture)
	assertDirectoryEmpty(t, fixture.stagingDirectory)
	fixture.state.assertSucceeded(t, point)

	if !script.didFire() {
		t.Fatalf("repair completion crash point %s was never reached", point)
	}
}

func newRepairCrashFixture(t *testing.T, script *repairCrashScript) repairCrashFixture {
	t.Helper()

	payload := bytes.Repeat([]byte{'r'}, 18)
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])
	recovery := verificationRecovery(t, digestHex, []manifest.Location{
		{DriverID: "target", StorageKey: "objects/target", Length: uint64(len(payload))},
		{DriverID: "source", StorageKey: "objects/source", Length: uint64(len(payload))},
	})
	state := &repairCrashState{
		recovery: recovery, payload: payload, digest: digestHex, state: "planned",
		bodies: make(map[string][]byte), calls: make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newRepairCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &repairCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct repair crash control client: %v", err)
	}

	destination := &countingRepairArchive{base: newMemoryArchive(), script: script}
	source := &repairCrashSourceReader{
		reader: verificationReader{data: payload}, script: script,
	}

	repairer, err := sdk.NewRepairer(
		map[string]provider.Reader{"source": source},
		map[string]provider.ReadWriter{"target": destination},
		uint64(len(payload)),
		uint64(len(payload)),
	)
	if err != nil {
		t.Fatalf("construct crash-matrix repairer: %v", err)
	}

	coordinator, err := sdk.NewControlledRepairer(control, repairer, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled repairer: %v", err)
	}

	stagingDirectory := t.TempDir()

	return repairCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledRepairRequest{
			NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
			TargetDriverID: "target", IdempotencyKey: "repair-crash-v1",
			StagingDirectory: stagingDirectory,
		},
		state: state, destination: destination, stagingDirectory: stagingDirectory,
	}
}

func newRepairCrashServer(
	t *testing.T,
	encodedToken string,
	state *repairCrashState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read repair crash request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/repairs":
			state.serveCreate(t, response, body)
		case "/api/v1/operations/" + repairCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/repairs/" + repairCrashOperationID + "/snapshot":
			state.serveSnapshot(t, response, body)
		case "/api/v1/repairs/" + repairCrashOperationID + "/complete":
			state.serveComplete(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *repairCrashState) serveCreate(
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

func (state *repairCrashState) operationLocked() sdk.RepairOperation {
	phase := "planned"
	revision := uint64(1)

	switch state.state {
	case "running":
		phase = "repairing"
		revision = 2
	case "succeeded":
		phase = "completed"
		revision = 5
	case "failed", "cancelled":
		phase = "control_plane_recovered"
		revision = 3
	case "planned":
	default:
	}

	return sdk.RepairOperation{
		ID: repairCrashOperationID, NamespaceID: state.recovery.Manifest.NamespaceID,
		Kind: "copy", State: state.state, Phase: phase,
		RequestedBy: repairCrashClientID, Incarnation: repairCrashIncarnation,
		Revision: revision, UsefulBytesTotal: uint64(len(state.payload)),
		VersionID: "repair-version", ObjectID: state.recovery.Manifest.ObjectID,
		Generation: state.recovery.Manifest.Generation, ManifestSHA256: state.recovery.ManifestSHA256,
		RecoveryRevision: 3, TargetDriverID: "target", ExpectedObjectCount: 1,
		ExpectedTargetCount: 1, CreatedAt: 1, UpdatedAt: revision,
	}
}

func (state *repairCrashState) serveClaim(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "claim", body)

	state.mutex.Lock()
	state.state = "running"
	state.mutex.Unlock()

	writeJSON(t, response, sdk.OperationLease{
		OperationID: repairCrashOperationID, LeaseID: repairCrashLeaseID,
		OwnerClientID: repairCrashClientID, Incarnation: repairCrashIncarnation,
		FencingToken: 1, ExpiresAt: 1 << 40, OperationRevision: 2,
		OperationState: "running",
	})
}

func (state *repairCrashState) serveSnapshot(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExact(t, "snapshot", body)

	writeJSON(t, response, sdk.RepairSnapshot{
		Recovery: state.recovery, RecoveryRevision: 3, TargetDriverID: "target",
		TargetLocationIDs: []string{repairCrashTargetID},
		Locations: []sdk.IndexedLocation{
			{
				ID: repairCrashTargetID, ExtentSHA256: state.digest, DriverID: "target",
				StorageKey: "objects/target", Length: uint64(len(state.payload)), State: "missing",
			},
			{
				ID: repairCrashSourceID, ExtentSHA256: state.digest, DriverID: "source",
				StorageKey: "objects/source", Length: uint64(len(state.payload)), State: "available",
			},
		},
	})
}

func (state *repairCrashState) serveComplete(
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

	writeJSON(t, response, sdk.CompletedRepair{
		OperationID: repairCrashOperationID, ManifestSHA256: state.recovery.ManifestSHA256,
		State: "succeeded", ObjectsRepaired: 1, LocationsRepaired: 1,
		CiphertextBytes: uint64(len(state.payload)), RecoveryRevision: 3,
	})
}

func (state *repairCrashState) recordExact(t *testing.T, name string, body []byte) {
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
		t.Errorf("repair retry changed its %s request", name)
	}
}

func (state *repairCrashState) setState(value string) {
	state.mutex.Lock()
	state.state = value
	state.mutex.Unlock()
}

func (state *repairCrashState) callCount(name string) int {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.calls[name]
}

func (state *repairCrashState) assertUncommitted(t *testing.T, point repairCrashPoint) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.state == "succeeded" || state.completeCommits != 0 || state.calls["complete"] != 0 {
		t.Fatalf(
			"nonterminal repair committed after %s: state=%s commits=%d requests=%d",
			point,
			state.state,
			state.completeCommits,
			state.calls["complete"],
		)
	}
}

func (state *repairCrashState) assertSucceeded(
	t *testing.T,
	point repairCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	expectedClaims := 2
	oneClaimPoints := map[repairCrashPoint]struct{}{
		crashBeforeRepairCreate:  {},
		crashAfterRepairCreate:   {},
		crashBeforeRepairClaim:   {},
		crashAfterRepairComplete: {},
	}

	if _, oneClaim := oneClaimPoints[point]; oneClaim {
		expectedClaims = 1
	}

	if state.state != "succeeded" || state.completeCommits != 1 ||
		state.calls["claim"] != expectedClaims || state.calls["complete"] != 1 {
		t.Fatalf(
			"repair did not converge after %s: state=%s commits=%d claims=%d/%d complete=%d/1",
			point,
			state.state,
			state.completeCommits,
			state.calls["claim"],
			expectedClaims,
			state.calls["complete"],
		)
	}
}

func assertRepairCrashObject(t *testing.T, fixture repairCrashFixture) {
	t.Helper()

	actual := fixture.destination.base.object("objects/target")
	if !bytes.Equal(actual, fixture.state.payload) {
		t.Fatalf("repaired object = %x, want %x", actual, fixture.state.payload)
	}

	fixture.destination.base.mutex.RLock()
	objectCount := len(fixture.destination.base.objects)
	fixture.destination.base.mutex.RUnlock()

	if objectCount != 1 {
		t.Fatalf("repair response loss retained %d provider objects, want 1", objectCount)
	}
}
