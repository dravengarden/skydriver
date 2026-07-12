package sdk_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledCompactCrashOperationID = "909192939495969798999a9b9c9d9e9f"
	controlledCompactCrashIncarnation = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	controlledCompactCrashClientID    = "controlled-compact-crash-client"
	controlledCompactCrashLeaseID     = "operation/909192939495969798999a9b9c9d9e9f/write"
)

const (
	crashBeforeCompactCreate     = "before_compact_create"
	crashAfterCompactCreate      = "after_compact_create"
	crashBeforeCompactClaim      = "before_compact_claim"
	crashAfterCompactClaim       = "after_compact_claim"
	crashBeforeCompactManifest   = "before_compact_manifest"
	crashAfterCompactManifest    = "after_compact_manifest"
	crashBeforeCompactSourceKey  = "before_compact_source_key"
	crashAfterCompactSourceKey   = "after_compact_source_key"
	crashBeforeCompactTargetKey  = "before_compact_target_key"
	crashAfterCompactTargetKey   = "after_compact_target_key"
	crashBeforeCompactSourceRead = "before_compact_source_read"
	crashAfterCompactSourceRead  = "after_compact_source_read"
)

type controlledCompactCrashFixture struct {
	coordinator       *sdk.ControlledCompactor
	request           sdk.ControlledCompactRequest
	state             *controlledCompactReplayState
	script            *deterministicCrashScript
	sourceArchive     *memoryArchive
	targetArchive     *memoryArchive
	sourceObjectCount int
	plaintext         []byte
	targetKey         cryptostream.EpochKey
}

type controlledCompactReplayState struct {
	mutex sync.Mutex

	sourceRecovery       manifest.RecoveryManifest
	sourceRecoverySHA256 string
	sourceKey            string
	targetKey            string
	bodies               map[string][]byte
	calls                map[string]int
	terminalState        string
	operationState       string
	operationPhase       string

	created            bool
	claimed            bool
	published          bool
	createCommits      int
	claimTransitions   int
	stageCommits       int
	publicationCommits int
	staged             sdk.StagedRecovery
	targetRecovery     manifest.RecoveryManifest
	publishedManifest  string
	publishedSidecar   string
}

type controlledCompactPublicationBody struct {
	OperationID            string `json:"operation_id"`
	LeaseID                string `json:"lease_id"`
	Incarnation            string `json:"incarnation"`
	FencingToken           uint64 `json:"fencing_token"`
	ManifestSHA256         string `json:"manifest_sha256"`
	RecoverySHA256         string `json:"recovery_sha256"`
	R2Key                  string `json:"r2_key"`
	R2Version              string `json:"r2_version"`
	SidecarDriverID        string `json:"sidecar_driver_id"`
	SidecarStorageKey      string `json:"sidecar_storage_key"`
	ExpectedObjectRevision uint64 `json:"expected_object_revision"`
}

type controlledCompactCrashTransport struct {
	base   http.RoundTripper
	script *deterministicCrashScript
}

func (transport *controlledCompactCrashTransport) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	before, after, controlled := controlledCompactHTTPPoints(request.URL.Path)
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

func controlledCompactHTTPPoints(
	path string,
) (replicationCrashPoint, replicationCrashPoint, bool) {
	switch path {
	case "/api/v1/compactions":
		return crashBeforeCompactCreate, crashAfterCompactCreate, true
	case "/api/v1/operations/" + controlledCompactCrashOperationID + "/claim":
		return crashBeforeCompactClaim, crashAfterCompactClaim, true
	case "/api/v1/compactions/" + controlledCompactCrashOperationID + "/manifest":
		return crashBeforeCompactManifest, crashAfterCompactManifest, true
	case "/api/v1/compactions/" + controlledCompactCrashOperationID + "/source-key":
		return crashBeforeCompactSourceKey, crashAfterCompactSourceKey, true
	case "/api/v1/compactions/" + controlledCompactCrashOperationID + "/target-key":
		return crashBeforeCompactTargetKey, crashAfterCompactTargetKey, true
	case "/api/v1/recovery-manifests/stage":
		return crashBeforeR2Stage, crashAfterR2Stage, true
	case "/api/v1/operations/" + controlledCompactCrashOperationID + "/progress":
		return crashBeforeD1Progress, crashAfterD1Progress, true
	case "/api/v1/compactions/publish":
		return crashBeforeD1Publish, crashAfterD1Publish, true
	default:
		return "", "", false
	}
}

type controlledCompactSourceReader struct {
	reader provider.Reader
	script *deterministicCrashScript
}

func (reader *controlledCompactSourceReader) Stat(
	ctx context.Context,
	key string,
) (provider.Object, error) {
	return reader.reader.Stat(ctx, key)
}

func (reader *controlledCompactSourceReader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if err := reader.script.hit(crashBeforeCompactSourceRead); err != nil {
		return nil, err
	}

	stream, err := reader.reader.OpenRange(ctx, key, offset, length)
	if err != nil {
		return nil, err
	}

	return &crashAfterReadCloser{
		ReadCloser: stream, script: reader.script, point: crashAfterCompactSourceRead,
	}, nil
}

func TestControlledCompactorCrashMatrixConvergesEveryRemoteBoundary(t *testing.T) {
	t.Parallel()

	for _, point := range controlledCompactCrashPoints() {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testControlledCompactCrashPoint(t, point)
		})
	}
}

func TestControlledCompactorReturnsRecoveredTerminalFailure(t *testing.T) {
	t.Parallel()

	for _, terminalState := range []string{"failed", "cancelled"} {
		t.Run(terminalState, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledCompactCrashFixture(
				t,
				&deterministicCrashScript{},
			)
			fixture.state.terminalState = terminalState

			result, err := fixture.coordinator.Compact(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrCompactOperationFailed) ||
				result.Operation.State != terminalState {
				t.Fatalf("unexpected recovered compact result: result=%+v err=%v", result, err)
			}

			fixture.state.mutex.Lock()
			claimCalls := fixture.state.calls["claim"]
			fixture.state.mutex.Unlock()

			if claimCalls != 0 {
				t.Fatalf("terminal compact attempted %d lease claims", claimCalls)
			}

			fixture.targetArchive.mutex.RLock()
			targetObjects := len(fixture.targetArchive.objects)
			fixture.targetArchive.mutex.RUnlock()

			if targetObjects != 0 {
				t.Fatalf("terminal compact wrote %d provider objects", targetObjects)
			}

			assertControlledCompactWorkspace(t, fixture.request)
		})
	}
}

func TestControlledCompactorRejectsInvalidOperationStatePhase(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name  string
		state string
		phase string
	}{
		{name: "planned compacting", state: "planned", phase: "compacting"},
		{name: "running planned", state: "running", phase: "planned"},
		{name: "verifying", state: "verifying", phase: "verifying"},
		{name: "failed phase mismatch", state: "failed", phase: "failed"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			fixture := newControlledCompactCrashFixture(
				t,
				&deterministicCrashScript{},
			)
			fixture.state.operationState = testCase.state
			fixture.state.operationPhase = testCase.phase

			_, err := fixture.coordinator.Compact(context.Background(), fixture.request)
			if !errors.Is(err, sdk.ErrControlPlaneResponse) {
				t.Fatalf("invalid compact state/phase was accepted: %v", err)
			}

			fixture.state.mutex.Lock()
			claimCalls := fixture.state.calls["claim"]
			fixture.state.mutex.Unlock()

			if claimCalls != 0 {
				t.Fatalf("invalid compact state/phase attempted %d lease claims", claimCalls)
			}
		})
	}
}

func controlledCompactCrashPoints() []replicationCrashPoint {
	return []replicationCrashPoint{
		crashBeforeCompactCreate,
		crashAfterCompactCreate,
		crashBeforeCompactClaim,
		crashAfterCompactClaim,
		crashBeforeCompactManifest,
		crashAfterCompactManifest,
		crashBeforeCompactSourceKey,
		crashAfterCompactSourceKey,
		crashBeforeCompactTargetKey,
		crashAfterCompactTargetKey,
		crashBeforeCompactSourceRead,
		crashAfterCompactSourceRead,
		crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead,
		crashBeforeR2Stage,
		crashAfterR2Stage,
		crashBeforeD1Progress,
		crashAfterD1Progress,
		crashBeforeD1Publish,
		crashAfterD1Publish,
	}
}

func testControlledCompactCrashPoint(t *testing.T, point replicationCrashPoint) {
	t.Helper()

	script := &deterministicCrashScript{target: point}
	fixture := newControlledCompactCrashFixture(t, script)

	first, firstErr := fixture.coordinator.Compact(context.Background(), fixture.request)
	planBeforeRetry := readPlanAfterControlledCompactInterruption(t, fixture.request.PlanFile, point)
	providerEventsBeforeRetry := controlledCompactProviderEvents(script)
	result := first

	if controlledCompactProgressPoint(point) {
		if firstErr != nil || first.TelemetryWarning == "" {
			t.Fatalf(
				"compact progress response loss did not remain advisory at %s: result=%+v err=%v",
				point,
				first,
				firstErr,
			)
		}
	} else {
		if !errors.Is(firstErr, errInjectedReplicationCrash) {
			t.Fatalf("first controlled compact did not stop at %s: %v", point, firstErr)
		}

		if point != crashAfterD1Publish && fixture.state.isPublished() {
			t.Fatalf("controlled compact published before retry at %s", point)
		}

		var retryErr error

		result, retryErr = fixture.coordinator.Compact(context.Background(), fixture.request)
		if retryErr != nil {
			t.Fatalf("controlled compact did not converge after %s: %v", point, retryErr)
		}
	}

	if !script.didFire() {
		t.Fatalf("controlled compact crash point %s was never reached", point)
	}

	wantAlreadyPublished := point == crashAfterD1Publish
	if result.Publication.State != "published" || result.AlreadyPublished != wantAlreadyPublished {
		t.Fatalf("controlled compact returned an invalid terminal result after %s: %+v", point, result)
	}

	if controlledCompactProgressPoint(point) != (result.TelemetryWarning != "") {
		t.Fatalf("controlled compact returned the wrong telemetry warning after %s: %+v", point, result)
	}

	assertControlledCompactPlanStable(t, fixture.request.PlanFile, planBeforeRetry)
	fixture.state.assertConverged(t, point)
	assertControlledCompactArchive(t, fixture)
	assertControlledCompactWorkspace(t, fixture.request)
	assertControlledCompactSourceUnchanged(t, fixture)

	if point == crashAfterD1Publish {
		assertControlledCompactSkippedProviderReplay(t, script, providerEventsBeforeRetry)
	}
}

func controlledCompactProgressPoint(point replicationCrashPoint) bool {
	return point == crashBeforeD1Progress || point == crashAfterD1Progress
}

func controlledCompactPlanPersisted(point replicationCrashPoint) bool {
	persisted := map[replicationCrashPoint]struct{}{
		crashBeforePayloadPut: {}, crashAfterPayloadPut: {},
		crashBeforePayloadRead: {}, crashAfterPayloadRead: {},
		crashBeforeSidecarPut: {}, crashAfterSidecarPut: {},
		crashBeforeSidecarRead: {}, crashAfterSidecarRead: {},
		crashBeforeR2Stage: {}, crashAfterR2Stage: {},
		crashBeforeD1Progress: {}, crashAfterD1Progress: {},
		crashBeforeD1Publish: {}, crashAfterD1Publish: {},
	}
	_, exists := persisted[point]

	return exists
}

func readPlanAfterControlledCompactInterruption(
	t *testing.T,
	planFile string,
	point replicationCrashPoint,
) []byte {
	t.Helper()

	encoded, err := os.ReadFile(planFile)
	if !controlledCompactPlanPersisted(point) {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("compact interruption unexpectedly persisted a plan at %s: %v", point, err)
		}

		return nil
	}

	if err != nil {
		t.Fatalf("read persisted compact plan after %s: %v", point, err)
	}

	return encoded
}

func assertControlledCompactPlanStable(t *testing.T, planFile string, before []byte) {
	t.Helper()

	after, err := os.ReadFile(planFile)
	if err != nil {
		t.Fatalf("read converged compact plan: %v", err)
	}

	if before != nil && !bytes.Equal(before, after) {
		t.Fatal("controlled compact retry changed its persisted random plan")
	}

	if _, err := sdk.ParseImportPlan(after); err != nil {
		t.Fatalf("parse converged compact plan: %v", err)
	}
}

func newControlledCompactCrashFixture(
	t *testing.T,
	script *deterministicCrashScript,
) controlledCompactCrashFixture {
	t.Helper()

	plaintext := []byte("three deliberately small source packs for controlled compaction")
	sourcePlaintext := &mutableMemorySource{data: plaintext, version: "compact-source-v1"}
	sourceArchive := newMemoryArchive()
	sourceLayout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   4,
		LogicalPackBytes:   16,
	}

	sourceImporter, err := sdk.NewImporter(sourcePlaintext, sourceArchive, sourceLayout)
	if err != nil {
		t.Fatalf("construct compact crash source importer: %v", err)
	}

	sourcePlan, err := sourceImporter.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID: importIdentifier(), ObjectID: "compact-object", Generation: 1,
		RootVersion: 1, KeyEpoch: 7, SourceKey: "source",
		DestinationDriverID: "source-archive", DestinationPrefix: "compact-source",
	})
	if err != nil {
		t.Fatalf("plan compact crash source: %v", err)
	}

	sourceKey := importEpochKey(t, importIdentifier())

	source, err := sourceImporter.Execute(context.Background(), sourcePlan, sourceKey, t.TempDir())
	if err != nil {
		t.Fatalf("write compact crash source: %v", err)
	}

	if len(source.Manifest.Packs) < 2 {
		t.Fatalf("compact crash source has only %d pack(s)", len(source.Manifest.Packs))
	}

	sourceArchive.mutex.RLock()
	sourceObjectCount := len(sourceArchive.objects)
	sourceArchive.mutex.RUnlock()

	reader := &controlledCompactSourceReader{reader: sourceArchive, script: script}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{"source-archive": reader}, 1<<20)
	if err != nil {
		t.Fatalf("construct compact crash restorer: %v", err)
	}

	targetArchive := newMemoryArchive()

	compactor, err := sdk.NewCompactor(
		restorer,
		&crashInjectedArchive{base: targetArchive, script: script},
		archive.Layout{
			PhysicalBlockBytes: 64,
			CryptoFrameBytes:   4,
			LogicalPackBytes:   64,
		},
		sdk.ImporterOptions{},
	)
	if err != nil {
		t.Fatalf("construct crash-matrix compactor: %v", err)
	}

	targetKey := sourceKey
	targetKey[0] ^= 0xff
	state := &controlledCompactReplayState{
		sourceRecovery:       source.Recovery,
		sourceRecoverySHA256: testDigest(mustMarshalRecovery(t, source.Recovery)),
		sourceKey:            base64.RawURLEncoding.EncodeToString(sourceKey[:]),
		targetKey:            base64.RawURLEncoding.EncodeToString(targetKey[:]),
		bodies:               make(map[string][]byte),
		calls:                make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledCompactCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &controlledCompactCrashTransport{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct compact crash control client: %v", err)
	}

	coordinator, err := sdk.NewControlledCompactor(control, compactor, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled compactor: %v", err)
	}

	workspace := t.TempDir()

	return controlledCompactCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledCompactRequest{
			NamespaceID:         source.Manifest.NamespaceID,
			ManifestSHA256:      source.Recovery.ManifestSHA256,
			DestinationDriverID: "target-archive", DestinationPrefix: "compact-target",
			IdempotencyKey: "controlled-compact-crash-v1", StagingDirectory: workspace,
			PlaintextPath: filepath.Join(workspace, "compact.plaintext"),
			PlanFile:      filepath.Join(workspace, "compact-plan.json"),
		},
		state: state, script: script, sourceArchive: sourceArchive, targetArchive: targetArchive,
		sourceObjectCount: sourceObjectCount, plaintext: plaintext, targetKey: targetKey,
	}
}

func newControlledCompactCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledCompactReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled compact crash request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/compactions":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledCompactCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/compactions/" + controlledCompactCrashOperationID + "/manifest":
			state.serveManifest(t, response, body)
		case "/api/v1/compactions/" + controlledCompactCrashOperationID + "/source-key":
			state.serveKeyGrant(t, response, body, "source")
		case "/api/v1/compactions/" + controlledCompactCrashOperationID + "/target-key":
			state.serveKeyGrant(t, response, body, "target")
		case "/api/v1/recovery-manifests/stage":
			state.serveRecoveryStage(t, response, body)
		case "/api/v1/operations/" + controlledCompactCrashOperationID + "/progress":
			state.serveProgress(t, response, body)
		case "/api/v1/compactions/publish":
			state.servePublication(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledCompactReplayState) serveOperation(
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

func (state *controlledCompactReplayState) operationLocked() sdk.CompactOperation {
	operationState := "planned"
	phase := "planned"
	revision := uint64(1)

	if state.claimed {
		operationState = "running"
		phase = "compacting"
		revision = 2
	}

	if state.terminalState != "" {
		operationState = state.terminalState
		phase = "control_plane_recovered"
		revision = 3
	}

	if state.published {
		operationState = "succeeded"
		phase = "succeeded"
		revision = 3
	}

	if state.operationState != "" {
		operationState = state.operationState
	}

	if state.operationPhase != "" {
		phase = state.operationPhase
	}

	source := state.sourceRecovery.Manifest

	operation := sdk.CompactOperation{
		ID: controlledCompactCrashOperationID, NamespaceID: source.NamespaceID,
		Kind: "compact", State: operationState, Phase: phase,
		RequestedBy: controlledCompactCrashClientID, Incarnation: controlledCompactCrashIncarnation,
		Revision: revision, UsefulBytesTotal: source.PlaintextSize,
		VersionID: state.sourceRecovery.ManifestSHA256, ObjectID: source.ObjectID,
		SourceGeneration:     source.Generation,
		SourceManifestSHA256: state.sourceRecovery.ManifestSHA256,
		SourceRecoverySHA256: state.sourceRecoverySHA256, SourceRecoveryRevision: 1,
		SourcePlaintextSHA256: source.PlaintextSHA256, SourcePackCount: uint64(len(source.Packs)),
		SourceRootVersion: source.Crypto.RootVersion, SourceKeyEpoch: source.Crypto.KeyEpoch,
		ExpectedObjectRevision: 1, TargetGeneration: source.Generation + 1,
		TargetRootVersion: 1, TargetKeyEpoch: 7, DestinationDriverID: "target-archive",
		CreatedAt: 1, UpdatedAt: revision,
	}
	if state.published {
		operation.PublishedManifestSHA256 = state.publishedManifest
		operation.PublishedSidecarStorageKey = state.publishedSidecar
	}

	return operation
}

func (state *controlledCompactReplayState) serveClaim(
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
		OperationID: controlledCompactCrashOperationID,
		LeaseID:     controlledCompactCrashLeaseID, OwnerClientID: controlledCompactCrashClientID,
		Incarnation: controlledCompactCrashIncarnation, FencingToken: 11,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledCompactReplayState) serveManifest(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "manifest", body)
	writeJSON(t, response, state.sourceRecovery)
}

func (state *controlledCompactReplayState) serveKeyGrant(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
	purpose string,
) {
	t.Helper()
	state.recordExactRequest(t, purpose+"-key", body)

	epochKey := state.sourceKey
	if purpose == "target" {
		epochKey = state.targetKey
	}

	writeJSON(t, response, map[string]any{
		"operation_id": controlledCompactCrashOperationID,
		"purpose":      purpose,
		"root_version": 1,
		"key_epoch":    7,
		"epoch_key":    epochKey,
	})
}

func (state *controlledCompactReplayState) serveRecoveryStage(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "recovery-stage", body)

	var recovery manifest.RecoveryManifest
	if err := json.Unmarshal(body, &recovery); err != nil {
		t.Errorf("decode compact recovery stage: %v", err)
		http.Error(response, "invalid recovery", http.StatusBadRequest)

		return
	}

	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		t.Errorf("validate compact recovery stage: %v", err)
		http.Error(response, "invalid recovery", http.StatusBadRequest)

		return
	}

	recoverySHA256 := testDigest(encoded)
	staged := sdk.StagedRecovery{
		ManifestSHA256: recovery.ManifestSHA256, RecoverySHA256: recoverySHA256,
		NamespaceID: recovery.Manifest.NamespaceID, ObjectID: recovery.Manifest.ObjectID,
		Generation: recovery.Manifest.Generation,
		R2Key:      "manifests/compact-crash/" + recoverySHA256 + ".json",
		R2Version:  "r2-compact-v1", Bytes: uint64(len(encoded)),
	}

	state.mutex.Lock()
	if state.stageCommits == 0 {
		state.stageCommits = 1
		state.staged = staged
		state.targetRecovery = recovery
	}
	state.mutex.Unlock()

	writeJSON(t, response, staged)
}

func (state *controlledCompactReplayState) serveProgress(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()

	var progress controlledImportProgressBody
	if err := json.Unmarshal(body, &progress); err != nil {
		t.Errorf("decode compact progress: %v", err)
		http.Error(response, "invalid progress", http.StatusBadRequest)

		return
	}

	state.mutex.Lock()
	state.calls["progress"]++
	state.mutex.Unlock()

	writeJSON(t, response, sdk.ProgressSnapshot{
		ComponentID: controlledCompactCrashOperationID + "/compact",
		Attempt:     progress.FencingToken, Sequence: progress.Sequence,
		WireBytesRead: progress.WireBytesRead, WireBytesWritten: progress.WireBytesWritten,
		UsefulBytesVerified: progress.UsefulBytesVerified,
		ActiveNanoseconds:   progress.ActiveNanoseconds,
		RetryCount:          progress.RetryCount, ThrottleCount: progress.ThrottleCount,
		ObservedAt: 2, Disposition: "current",
	})
}

func (state *controlledCompactReplayState) servePublication(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "publication", body)

	var publication controlledCompactPublicationBody
	if err := json.Unmarshal(body, &publication); err != nil {
		t.Errorf("decode compact publication: %v", err)
		http.Error(response, "invalid publication", http.StatusBadRequest)

		return
	}

	state.mutex.Lock()
	if publication.OperationID != controlledCompactCrashOperationID ||
		publication.LeaseID != controlledCompactCrashLeaseID ||
		publication.Incarnation != controlledCompactCrashIncarnation ||
		publication.FencingToken != 11 || publication.ExpectedObjectRevision != 1 ||
		publication.SidecarDriverID != "target-archive" || state.stageCommits != 1 ||
		publication.ManifestSHA256 != state.staged.ManifestSHA256 ||
		publication.RecoverySHA256 != state.staged.RecoverySHA256 ||
		publication.R2Key != state.staged.R2Key || publication.R2Version != state.staged.R2Version {
		state.mutex.Unlock()
		t.Errorf("compact publication crossed the recovery barrier: %+v", publication)
		http.Error(response, "invalid publication identity", http.StatusConflict)

		return
	}

	if !state.published {
		state.published = true
		state.publicationCommits++
		state.publishedManifest = publication.ManifestSHA256
		state.publishedSidecar = publication.SidecarStorageKey
	}
	state.mutex.Unlock()

	writeJSON(t, response, sdk.PublishedImport{
		OperationID:    controlledCompactCrashOperationID,
		ObjectID:       state.sourceRecovery.Manifest.ObjectID,
		Generation:     state.sourceRecovery.Manifest.Generation + 1,
		ManifestSHA256: publication.ManifestSHA256,
		State:          "published",
	})
}

func (state *controlledCompactReplayState) recordExactRequest(
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
		t.Errorf("controlled compact retry changed its %s request", name)
	}
}

func (state *controlledCompactReplayState) isPublished() bool {
	state.mutex.Lock()
	defer state.mutex.Unlock()

	return state.published
}

func (state *controlledCompactReplayState) assertConverged(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.stageCommits != 1 || state.publicationCommits != 1 || !state.published {
		t.Fatalf(
			"controlled compact did not converge logical commits after %s: create=%d claim=%d stage=%d publish=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.stageCommits,
			state.publicationCommits,
		)
	}

	expectedCreateCalls := 2
	if point == crashBeforeCompactCreate || controlledCompactProgressPoint(point) {
		expectedCreateCalls = 1
	}

	expectedClaimCalls := 2
	if point == crashBeforeCompactCreate || point == crashAfterCompactCreate ||
		point == crashBeforeCompactClaim || controlledCompactProgressPoint(point) ||
		point == crashAfterD1Publish {
		expectedClaimCalls = 1
	}

	expectedStageCalls := 1
	if point == crashAfterR2Stage || point == crashBeforeD1Publish {
		expectedStageCalls = 2
	}

	expectedProgressCalls := 1

	progressOverrides := map[replicationCrashPoint]int{
		crashBeforeD1Progress: 0,
		crashBeforeD1Publish:  2,
	}
	if overridden, exists := progressOverrides[point]; exists {
		expectedProgressCalls = overridden
	}

	if state.calls["create"] != expectedCreateCalls || state.calls["claim"] != expectedClaimCalls ||
		state.calls["recovery-stage"] != expectedStageCalls ||
		state.calls["progress"] != expectedProgressCalls || state.calls["publication"] != 1 {
		t.Fatalf(
			"controlled compact crossed remote barriers incorrectly after %s: create=%d/%d claim=%d/%d stage=%d/%d progress=%d/%d publish=%d/1",
			point,
			state.calls["create"],
			expectedCreateCalls,
			state.calls["claim"],
			expectedClaimCalls,
			state.calls["recovery-stage"],
			expectedStageCalls,
			state.calls["progress"],
			expectedProgressCalls,
			state.calls["publication"],
		)
	}
}

func (state *controlledCompactReplayState) publishedArchive(
	t *testing.T,
) (manifest.RecoveryManifest, string) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if !state.published || state.publishedSidecar == "" {
		t.Fatal("controlled compact archive was not published")
	}

	return state.targetRecovery, state.publishedSidecar
}

func assertControlledCompactArchive(t *testing.T, fixture controlledCompactCrashFixture) {
	t.Helper()

	recovery, sidecarKey := fixture.state.publishedArchive(t)
	if recovery.Manifest.Generation != 2 || len(recovery.Manifest.Packs) != 1 ||
		recovery.Manifest.PlaintextSHA256 != fixture.state.sourceRecovery.Manifest.PlaintextSHA256 {
		t.Fatalf("controlled compact published an invalid replacement: %+v", recovery.Manifest)
	}

	restored := restoreMemoryArchive(t, fixture.targetArchive, sdk.ImportResult{
		Manifest: recovery.Manifest, Recovery: recovery,
	}, fixture.targetKey)
	if !bytes.Equal(restored, fixture.plaintext) {
		t.Fatalf("controlled compact retry restored %q, want %q", restored, fixture.plaintext)
	}

	encodedRecovery, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal converged compact recovery: %v", err)
	}

	if sidecar := fixture.targetArchive.object(sidecarKey); !bytes.Equal(sidecar, encodedRecovery) {
		t.Fatal("controlled compact sidecar differs from the R2 recovery document")
	}

	expectedObjects := map[string]struct{}{sidecarKey: {}}
	for _, location := range recovery.Locations {
		expectedObjects[location.StorageKey] = struct{}{}
	}

	fixture.targetArchive.mutex.RLock()
	actualObjects := len(fixture.targetArchive.objects)
	fixture.targetArchive.mutex.RUnlock()

	if actualObjects != len(expectedObjects) {
		t.Fatalf(
			"controlled compact retry retained duplicate objects: stored=%d expected=%d",
			actualObjects,
			len(expectedObjects),
		)
	}
}

func assertControlledCompactWorkspace(t *testing.T, requested sdk.ControlledCompactRequest) {
	t.Helper()

	if _, err := os.Stat(requested.PlaintextPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("controlled compact retained its plaintext bridge: %v", err)
	}

	entries, err := os.ReadDir(requested.StagingDirectory)
	if err != nil {
		t.Fatalf("read controlled compact workspace: %v", err)
	}

	if len(entries) == 0 {
		return
	}

	if len(entries) != 1 || entries[0].Name() != filepath.Base(requested.PlanFile) {
		t.Fatalf("controlled compact retained unexpected workspace entries: %+v", entries)
	}
}

func assertControlledCompactSourceUnchanged(t *testing.T, fixture controlledCompactCrashFixture) {
	t.Helper()

	fixture.sourceArchive.mutex.RLock()
	actualObjects := len(fixture.sourceArchive.objects)
	fixture.sourceArchive.mutex.RUnlock()

	if actualObjects != fixture.sourceObjectCount {
		t.Fatalf(
			"controlled compact changed its immutable source archive: got=%d want=%d",
			actualObjects,
			fixture.sourceObjectCount,
		)
	}
}

func controlledCompactProviderEvents(
	script *deterministicCrashScript,
) map[replicationCrashPoint]int {
	points := []replicationCrashPoint{
		crashBeforeCompactSourceRead,
		crashAfterCompactSourceRead,
		crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead,
	}

	counts := make(map[replicationCrashPoint]int, len(points))
	for _, point := range points {
		counts[point] = script.eventCount(point)
	}

	return counts
}

func assertControlledCompactSkippedProviderReplay(
	t *testing.T,
	script *deterministicCrashScript,
	before map[replicationCrashPoint]int,
) {
	t.Helper()

	for point, count := range before {
		if after := script.eventCount(point); after != count {
			t.Fatalf(
				"lost compact publication response repeated %s: before=%d after=%d",
				point,
				count,
				after,
			)
		}
	}
}
