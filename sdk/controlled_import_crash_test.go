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
	"github.com/dravengarden/carrack/sdk"
)

const (
	controlledImportCrashOperationID = "808182838485868788898a8b8c8d8e8f"
	controlledImportCrashIncarnation = "101112131415161718191a1b1c1d1e1f"
	controlledImportCrashClientID    = "controlled-import-crash-client"
	controlledImportCrashLeaseID     = "operation/808182838485868788898a8b8c8d8e8f/write"
)

type controlledImportCrashFixture struct {
	coordinator      *sdk.ControlledImporter
	request          sdk.ControlledImportRequest
	state            *controlledImportReplayState
	destination      *memoryArchive
	stagingDirectory string
	planFile         string
	plaintext        []byte
	epochKey         cryptostream.EpochKey
}

type controlledImportReplayState struct {
	mutex sync.Mutex

	usefulBytes uint64
	epochKey    string
	bodies      map[string][]byte
	calls       map[string]int

	created             bool
	claimed             bool
	published           bool
	createCommits       int
	claimTransitions    int
	stageCommits        int
	publicationCommits  int
	staged              sdk.StagedRecovery
	recovery            manifest.RecoveryManifest
	publishedManifest   string
	publishedDriver     string
	publishedSidecarKey string
}

type controlledImportProgressBody struct {
	FencingToken        uint64 `json:"fencing_token"`
	Sequence            uint64 `json:"sequence"`
	WireBytesRead       uint64 `json:"wire_bytes_read"`
	WireBytesWritten    uint64 `json:"wire_bytes_written"`
	UsefulBytesVerified uint64 `json:"useful_bytes_verified"`
	ActiveNanoseconds   uint64 `json:"active_nanoseconds"`
	RetryCount          uint64 `json:"retry_count"`
	ThrottleCount       uint64 `json:"throttle_count"`
}

type controlledImportPublicationBody struct {
	OperationID       string `json:"operation_id"`
	ManifestSHA256    string `json:"manifest_sha256"`
	RecoverySHA256    string `json:"recovery_sha256"`
	SidecarDriverID   string `json:"sidecar_driver_id"`
	SidecarStorageKey string `json:"sidecar_storage_key"`
}

func TestControlledImporterCrashMatrixConvergesEveryRemoteBoundary(t *testing.T) {
	t.Parallel()

	for _, point := range controlledImportCrashPoints() {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			testControlledImportCrashPoint(t, point)
		})
	}
}

func controlledImportCrashPoints() []replicationCrashPoint {
	return []replicationCrashPoint{
		crashBeforeD1Create,
		crashAfterD1Create,
		crashBeforeD1Claim,
		crashAfterD1Claim,
		crashBeforeKeyGrant,
		crashAfterKeyGrant,
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

func testControlledImportCrashPoint(t *testing.T, point replicationCrashPoint) {
	t.Helper()

	script := &deterministicCrashScript{target: point}
	fixture := newControlledImportCrashFixture(t, script)

	first, firstErr := fixture.coordinator.Import(context.Background(), fixture.request)
	planBeforeRetry := readPlanAfterControlledImportInterruption(t, fixture.planFile, point)

	result := first
	if controlledImportProgressPoint(point) {
		if firstErr != nil || first.TelemetryWarning == "" {
			t.Fatalf(
				"progress response loss did not remain advisory at %s: result=%+v err=%v",
				point,
				first,
				firstErr,
			)
		}
	} else {
		if !errors.Is(firstErr, errInjectedReplicationCrash) {
			t.Fatalf("first controlled import did not stop at %s: %v", point, firstErr)
		}

		var retryErr error

		result, retryErr = fixture.coordinator.Import(context.Background(), fixture.request)
		if retryErr != nil {
			t.Fatalf("controlled import did not converge after %s: %v", point, retryErr)
		}
	}

	if !script.didFire() {
		t.Fatalf("controlled import crash point %s was never reached", point)
	}

	if result.Publication.State != "published" ||
		(!controlledImportProgressPoint(point) && result.TelemetryWarning != "") {
		t.Fatalf("controlled import returned an invalid terminal result after %s: %+v", point, result)
	}

	assertControlledImportPlanStable(t, fixture.planFile, planBeforeRetry)
	fixture.state.assertConverged(t, point)
	assertControlledImportCrashArchive(t, fixture)
	assertLostPublicationSkippedProviderReplay(t, script, point)
	assertDirectoryEmpty(t, fixture.stagingDirectory)
}

func readPlanAfterControlledImportInterruption(
	t *testing.T,
	planFile string,
	point replicationCrashPoint,
) []byte {
	t.Helper()

	encoded, err := os.ReadFile(planFile)
	if controlledImportCreatePoint(point) {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("operation creation interruption unexpectedly persisted a plan at %s: %v", point, err)
		}

		return nil
	}

	if err != nil {
		t.Fatalf("read persisted import plan after %s: %v", point, err)
	}

	return encoded
}

func assertControlledImportPlanStable(t *testing.T, planFile string, before []byte) {
	t.Helper()

	after, err := os.ReadFile(planFile)
	if err != nil {
		t.Fatalf("read converged controlled import plan: %v", err)
	}

	if before != nil && !bytes.Equal(before, after) {
		t.Fatal("controlled import retry changed its persisted random plan")
	}

	if _, err := sdk.ParseImportPlan(after); err != nil {
		t.Fatalf("parse converged controlled import plan: %v", err)
	}
}

func controlledImportCreatePoint(point replicationCrashPoint) bool {
	return point == crashBeforeD1Create || point == crashAfterD1Create
}

func controlledImportProgressPoint(point replicationCrashPoint) bool {
	return point == crashBeforeD1Progress || point == crashAfterD1Progress
}

func newControlledImportCrashFixture(
	t *testing.T,
	script *deterministicCrashScript,
) controlledImportCrashFixture {
	t.Helper()

	plaintext := []byte("controlled import crash boundary")
	source := &mutableMemorySource{data: plaintext, version: "source-v1"}
	destination := newMemoryArchive()

	importer, err := sdk.NewImporter(
		source,
		&crashInjectedArchive{base: destination, script: script},
		archive.Layout{
			PhysicalBlockBytes: 64,
			CryptoFrameBytes:   4,
			LogicalPackBytes:   64,
		},
	)
	if err != nil {
		t.Fatalf("construct crash-matrix importer: %v", err)
	}

	epochKey := importEpochKey(t, importIdentifier())
	state := &controlledImportReplayState{
		usefulBytes: uint64(len(plaintext)),
		epochKey:    base64.RawURLEncoding.EncodeToString(epochKey[:]),
		bodies:      make(map[string][]byte),
		calls:       make(map[string]int),
	}
	token, encodedToken := testClientToken(t)
	server := newControlledImportCrashServer(t, encodedToken, state)

	httpClient := *server.Client()
	httpClient.Transport = &crashRoundTripper{
		base: server.Client().Transport, script: script,
	}

	control, err := sdk.NewControlClient(server.URL, token, &httpClient)
	if err != nil {
		t.Fatalf("construct crash-matrix control client: %v", err)
	}

	coordinator, err := sdk.NewControlledImporter(control, importer, 15, 10*time.Second)
	if err != nil {
		t.Fatalf("construct crash-matrix controlled importer: %v", err)
	}

	stagingDirectory := t.TempDir()
	planFile := filepath.Join(t.TempDir(), "import-plan.json")
	total := uint64(len(plaintext))

	return controlledImportCrashFixture{
		coordinator: coordinator,
		request: sdk.ControlledImportRequest{
			NamespaceID: controlledImportNamespace(), ObjectID: "object-1", Generation: 1,
			SourceKey: "source", DestinationDriverID: "memory-primary",
			DestinationPrefix: "archive", IdempotencyKey: "controlled-import-crash-v1",
			UsefulBytesTotal: &total, ExpectedObjectRevision: 1,
			StagingDirectory: stagingDirectory, PlanFile: planFile,
		},
		state: state, destination: destination, stagingDirectory: stagingDirectory,
		planFile: planFile, plaintext: plaintext, epochKey: epochKey,
	}
}

func newControlledImportCrashServer(
	t *testing.T,
	encodedToken string,
	state *controlledImportReplayState,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read controlled import crash request: %v", err)
			http.Error(response, "read request", http.StatusBadRequest)

			return
		}

		switch request.URL.Path {
		case "/api/v1/operations":
			state.serveOperation(t, response, body)
		case "/api/v1/operations/" + controlledImportCrashOperationID + "/claim":
			state.serveClaim(t, response, body)
		case "/api/v1/imports/" + controlledImportCrashOperationID + "/key":
			state.serveKeyGrant(t, response, body)
		case "/api/v1/recovery-manifests/stage":
			state.serveRecoveryStage(t, response, body)
		case "/api/v1/operations/" + controlledImportCrashOperationID + "/progress":
			state.serveProgress(t, response, body)
		case "/api/v1/imports/publish":
			state.servePublication(t, response, body)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func (state *controlledImportReplayState) serveOperation(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "/api/v1/operations", body)

	state.mutex.Lock()
	if !state.created {
		state.created = true
		state.createCommits++
	}

	operation := state.operationLocked()
	state.mutex.Unlock()

	writeJSON(t, response, operation)
}

func (state *controlledImportReplayState) operationLocked() sdk.ImportOperation {
	operationState := "planned"
	phase := "planned"
	revision := uint64(1)

	if state.claimed {
		operationState = "running"
		phase = "running"
		revision = 2
	}

	if state.published {
		operationState = "succeeded"
		phase = "succeeded"
		revision = 3
	}

	total := state.usefulBytes

	operation := sdk.ImportOperation{
		ID: controlledImportCrashOperationID, NamespaceID: controlledImportNamespace(),
		Kind: "import", State: operationState, Phase: phase,
		RequestedBy: controlledImportCrashClientID, Incarnation: controlledImportCrashIncarnation,
		Revision: revision, UsefulBytesTotal: &total, RootVersion: 1, KeyEpoch: 7,
		CreatedAt: 1, UpdatedAt: revision,
	}
	if state.published {
		operation.PublishedObjectID = "object-1"
		operation.PublishedGeneration = 1
		operation.PublishedManifestSHA256 = state.publishedManifest
		operation.PublishedDestinationDriverID = state.publishedDriver
		operation.PublishedSidecarStorageKey = state.publishedSidecarKey
	}

	return operation
}

func (state *controlledImportReplayState) serveClaim(
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
		OperationID: controlledImportCrashOperationID,
		LeaseID:     controlledImportCrashLeaseID, OwnerClientID: controlledImportCrashClientID,
		Incarnation: controlledImportCrashIncarnation, FencingToken: 7,
		ExpiresAt: 1 << 40, OperationRevision: 2, OperationState: "running",
	})
}

func (state *controlledImportReplayState) serveKeyGrant(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "key-grant", body)

	writeJSON(t, response, map[string]any{
		"operation_id": controlledImportCrashOperationID,
		"root_version": 1,
		"key_epoch":    7,
		"epoch_key":    state.epochKey,
	})
}

func (state *controlledImportReplayState) serveRecoveryStage(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "recovery-stage", body)

	var recovery manifest.RecoveryManifest
	if err := json.Unmarshal(body, &recovery); err != nil {
		t.Errorf("decode crash-matrix recovery: %v", err)
		http.Error(response, "invalid recovery", http.StatusBadRequest)

		return
	}

	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		t.Errorf("validate crash-matrix recovery: %v", err)
		http.Error(response, "invalid recovery", http.StatusBadRequest)

		return
	}

	recoverySHA256 := testDigest(encoded)
	staged := sdk.StagedRecovery{
		ManifestSHA256: recovery.ManifestSHA256, RecoverySHA256: recoverySHA256,
		NamespaceID: recovery.Manifest.NamespaceID, ObjectID: recovery.Manifest.ObjectID,
		Generation: recovery.Manifest.Generation,
		R2Key:      "manifests/import-crash/" + recoverySHA256 + ".json", R2Version: "r2-import-v1",
		Bytes: uint64(len(encoded)),
	}

	state.mutex.Lock()
	if state.stageCommits == 0 {
		state.stageCommits = 1
		state.staged = staged
		state.recovery = recovery
	}
	state.mutex.Unlock()

	writeJSON(t, response, staged)
}

func (state *controlledImportReplayState) serveProgress(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()

	var progress controlledImportProgressBody
	if err := json.Unmarshal(body, &progress); err != nil {
		t.Errorf("decode crash-matrix progress: %v", err)
		http.Error(response, "invalid progress", http.StatusBadRequest)

		return
	}

	state.mutex.Lock()
	state.calls["progress"]++
	state.mutex.Unlock()

	writeJSON(t, response, sdk.ProgressSnapshot{
		ComponentID: controlledImportCrashOperationID + "/transfer",
		Attempt:     progress.FencingToken, Sequence: progress.Sequence,
		WireBytesRead: progress.WireBytesRead, WireBytesWritten: progress.WireBytesWritten,
		UsefulBytesVerified: progress.UsefulBytesVerified,
		ActiveNanoseconds:   progress.ActiveNanoseconds,
		RetryCount:          progress.RetryCount, ThrottleCount: progress.ThrottleCount,
		ObservedAt: 2, Disposition: "current",
	})
}

func (state *controlledImportReplayState) servePublication(
	t *testing.T,
	response http.ResponseWriter,
	body []byte,
) {
	t.Helper()
	state.recordExactRequest(t, "publication", body)

	var publication controlledImportPublicationBody
	if err := json.Unmarshal(body, &publication); err != nil {
		t.Errorf("decode crash-matrix publication: %v", err)
		http.Error(response, "invalid publication", http.StatusBadRequest)

		return
	}

	state.mutex.Lock()
	if publication.OperationID != controlledImportCrashOperationID || state.stageCommits != 1 ||
		publication.ManifestSHA256 != state.staged.ManifestSHA256 ||
		publication.RecoverySHA256 != state.staged.RecoverySHA256 {
		state.mutex.Unlock()
		t.Errorf("publication crossed the recovery barrier: %+v", publication)
		http.Error(response, "invalid publication identity", http.StatusConflict)

		return
	}

	if !state.published {
		state.published = true
		state.publicationCommits++
		state.publishedManifest = publication.ManifestSHA256
		state.publishedDriver = publication.SidecarDriverID
		state.publishedSidecarKey = publication.SidecarStorageKey
	}
	state.mutex.Unlock()

	writeJSON(t, response, sdk.PublishedImport{
		OperationID: controlledImportCrashOperationID, ObjectID: "object-1", Generation: 1,
		ManifestSHA256: publication.ManifestSHA256, State: "published",
	})
}

func (state *controlledImportReplayState) recordExactRequest(
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
		t.Errorf("controlled import retry changed its %s request", name)
	}
}

func (state *controlledImportReplayState) assertConverged(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if state.createCommits != 1 || state.claimTransitions != 1 ||
		state.stageCommits != 1 || state.publicationCommits != 1 || !state.published {
		t.Fatalf(
			"controlled import did not converge logical commits after %s: create=%d claim=%d stage=%d publish=%d",
			point,
			state.createCommits,
			state.claimTransitions,
			state.stageCommits,
			state.publicationCommits,
		)
	}

	expectedStageCalls := 1
	if point == crashAfterR2Stage || point == crashBeforeD1Publish {
		expectedStageCalls = 2
	}

	if state.calls["recovery-stage"] != expectedStageCalls || state.calls["publication"] != 1 {
		t.Fatalf(
			"controlled import crossed remote barriers incorrectly after %s: stage=%d/%d publish=%d/1",
			point,
			state.calls["recovery-stage"],
			expectedStageCalls,
			state.calls["publication"],
		)
	}

	expectedProgressCalls := 1
	progressCallOverrides := map[replicationCrashPoint]int{
		crashBeforeD1Progress: 0,
		crashBeforeD1Publish:  2,
	}

	if overridden, exists := progressCallOverrides[point]; exists {
		expectedProgressCalls = overridden
	}

	if state.calls["progress"] != expectedProgressCalls {
		t.Fatalf(
			"controlled import progress crossed D1 %d times after %s; want %d",
			state.calls["progress"],
			point,
			expectedProgressCalls,
		)
	}
}

func (state *controlledImportReplayState) publishedArchive(
	t *testing.T,
) (manifest.RecoveryManifest, string) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	if !state.published || state.publishedSidecarKey == "" {
		t.Fatal("controlled import archive was not published")
	}

	return state.recovery, state.publishedSidecarKey
}

func assertControlledImportCrashArchive(t *testing.T, fixture controlledImportCrashFixture) {
	t.Helper()

	recovery, sidecarKey := fixture.state.publishedArchive(t)

	restored := restoreMemoryArchive(t, fixture.destination, sdk.ImportResult{
		Manifest: recovery.Manifest, Recovery: recovery,
	}, fixture.epochKey)
	if !bytes.Equal(restored, fixture.plaintext) {
		t.Fatalf("controlled import retry restored %q, want %q", restored, fixture.plaintext)
	}

	encodedRecovery, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal converged recovery: %v", err)
	}

	if sidecar := fixture.destination.object(sidecarKey); !bytes.Equal(sidecar, encodedRecovery) {
		t.Fatal("controlled import sidecar differs from the R2 recovery document")
	}

	expectedObjects := map[string]struct{}{sidecarKey: {}}
	for _, location := range recovery.Locations {
		expectedObjects[location.StorageKey] = struct{}{}
	}

	fixture.destination.mutex.RLock()
	actualObjects := len(fixture.destination.objects)
	fixture.destination.mutex.RUnlock()

	if actualObjects != len(expectedObjects) {
		t.Fatalf(
			"controlled import retry retained duplicate objects: stored=%d expected=%d",
			actualObjects,
			len(expectedObjects),
		)
	}
}

func assertLostPublicationSkippedProviderReplay(
	t *testing.T,
	script *deterministicCrashScript,
	point replicationCrashPoint,
) {
	t.Helper()

	if point != crashAfterD1Publish {
		return
	}

	providerBoundaries := []replicationCrashPoint{
		crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead,
	}
	for _, boundary := range providerBoundaries {
		if count := script.eventCount(boundary); count != 1 {
			t.Fatalf(
				"lost final publication response repeated %s %d times; want 1",
				boundary,
				count,
			)
		}
	}
}
