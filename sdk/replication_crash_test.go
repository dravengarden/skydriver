package sdk_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errInjectedReplicationCrash = errors.New("injected Carrack replication crash")

type replicationCrashPoint string

const (
	crashBeforePayloadPut  replicationCrashPoint = "before_payload_put"
	crashAfterPayloadPut   replicationCrashPoint = "after_payload_put"
	crashBeforePayloadRead replicationCrashPoint = "before_payload_readback"
	crashAfterPayloadRead  replicationCrashPoint = "after_payload_readback"
	crashBeforeSidecarPut  replicationCrashPoint = "before_sidecar_put"
	crashAfterSidecarPut   replicationCrashPoint = "after_sidecar_put"
	crashBeforeSidecarRead replicationCrashPoint = "before_sidecar_readback"
	crashAfterSidecarRead  replicationCrashPoint = "after_sidecar_readback"
	crashBeforeR2Stage     replicationCrashPoint = "before_r2_stage"
	crashAfterR2Stage      replicationCrashPoint = "after_r2_stage"
	crashBeforeD1Publish   replicationCrashPoint = "before_d1_publish"
	crashAfterD1Publish    replicationCrashPoint = "after_d1_publish"
	crashBeforeD1Tombstone replicationCrashPoint = "before_d1_tombstone"
	crashAfterD1Tombstone  replicationCrashPoint = "after_d1_tombstone"
)

type deterministicCrashScript struct {
	mutex  sync.Mutex
	target replicationCrashPoint
	fired  bool
	events []replicationCrashPoint
}

func (script *deterministicCrashScript) hit(point replicationCrashPoint) error {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	script.events = append(script.events, point)
	if script.fired || point != script.target {
		return nil
	}

	script.fired = true

	return fmt.Errorf("%w: %s", errInjectedReplicationCrash, point)
}

func (script *deterministicCrashScript) didFire() bool {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	return script.fired
}

type crashInjectedArchive struct {
	base   *memoryArchive
	script *deterministicCrashScript
}

func (archiveStore *crashInjectedArchive) Stat(
	ctx context.Context,
	key string,
) (provider.Object, error) {
	return archiveStore.base.Stat(ctx, key)
}

func (archiveStore *crashInjectedArchive) Put(
	ctx context.Context,
	key string,
	body io.Reader,
	options provider.PutOptions,
) (provider.Object, error) {
	before, after := replicationPutCrashPoints(key)
	if err := archiveStore.script.hit(before); err != nil {
		return provider.Object{}, err
	}

	object, err := archiveStore.base.Put(ctx, key, body, options)
	if err != nil {
		return provider.Object{}, err
	}

	if err := archiveStore.script.hit(after); err != nil {
		return provider.Object{}, err
	}

	return object, nil
}

func (archiveStore *crashInjectedArchive) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	before, after := replicationReadCrashPoints(key)
	if err := archiveStore.script.hit(before); err != nil {
		return nil, err
	}

	stream, err := archiveStore.base.OpenRange(ctx, key, offset, length)
	if err != nil {
		return nil, err
	}

	return &crashAfterReadCloser{
		ReadCloser: stream,
		script:     archiveStore.script,
		point:      after,
	}, nil
}

type crashAfterReadCloser struct {
	io.ReadCloser

	script *deterministicCrashScript
	point  replicationCrashPoint
}

func (stream *crashAfterReadCloser) Close() error {
	return errors.Join(stream.ReadCloser.Close(), stream.script.hit(stream.point))
}

func replicationPutCrashPoints(key string) (replicationCrashPoint, replicationCrashPoint) {
	if strings.Contains(key, "/manifests/") {
		return crashBeforeSidecarPut, crashAfterSidecarPut
	}

	return crashBeforePayloadPut, crashAfterPayloadPut
}

func replicationReadCrashPoints(key string) (replicationCrashPoint, replicationCrashPoint) {
	if strings.Contains(key, "/manifests/") {
		return crashBeforeSidecarRead, crashAfterSidecarRead
	}

	return crashBeforePayloadRead, crashAfterPayloadRead
}

func TestReplicationCrashMatrixConvergesContentAddressedSideEffects(t *testing.T) {
	t.Parallel()

	points := []replicationCrashPoint{
		crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead,
	}

	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			fixture := newReplicationFixture(t)
			base := newMemoryArchive()
			script := &deterministicCrashScript{target: point}
			destination := &crashInjectedArchive{base: base, script: script}
			replicator := newTestReplicator(
				t,
				map[string]provider.Reader{"source": fixture.source},
				destination,
				200,
				1<<20,
			)
			stagingDirectory := t.TempDir()
			request := sdk.ReplicationRequest{
				Recovery: fixture.recovery, DestinationDriverID: "destination",
				DestinationPrefix: "crash-matrix", StagingDirectory: stagingDirectory,
			}

			_, firstErr := replicator.Replicate(context.Background(), request)
			if !errors.Is(firstErr, errInjectedReplicationCrash) {
				t.Fatalf("first replication did not stop at %s: %v", point, firstErr)
			}

			result, retryErr := replicator.Replicate(context.Background(), request)
			if retryErr != nil {
				t.Fatalf("replication did not converge after %s: %v", point, retryErr)
			}

			if !script.didFire() {
				t.Fatalf("crash point %s was never reached", point)
			}

			base.mutex.RLock()
			objectCount := len(base.objects)
			base.mutex.RUnlock()

			if objectCount != len(result.ProviderObjects)+1 {
				t.Fatalf(
					"retry after %s left duplicate or missing objects: stored=%d payload=%d",
					point,
					objectCount,
					len(result.ProviderObjects),
				)
			}

			if len(result.Locations) == 0 ||
				len(result.Recovery.Locations) != len(fixture.recovery.Locations)+len(result.Locations) {
				t.Fatalf("retry after %s changed recovery coverage: %+v", point, result)
			}

			assertGaplessProviderLocations(t, base, result.Locations)
			assertReplicatedLocationDigests(t, base, result.Locations)
			assertReplicationSidecar(t, base, result)
			assertDirectoryEmpty(t, stagingDirectory)
		})
	}
}

type crashRoundTripper struct {
	base   http.RoundTripper
	script *deterministicCrashScript
}

func (transport *crashRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	before, after, controlled := controlCrashPoints(request.URL.Path)
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

func controlCrashPoints(path string) (replicationCrashPoint, replicationCrashPoint, bool) {
	switch path {
	case "/api/v1/recovery-manifests/stage":
		return crashBeforeR2Stage, crashAfterR2Stage, true
	case "/api/v1/copies/publish", "/api/v1/moves/publish-destination":
		return crashBeforeD1Publish, crashAfterD1Publish, true
	case "/api/v1/moves/tombstone-source":
		return crashBeforeD1Tombstone, crashAfterD1Tombstone, true
	default:
		return "", "", false
	}
}

type replayControlState struct {
	mutex sync.Mutex

	stageBody          []byte
	publicationBody    []byte
	tombstoneBody      []byte
	stageCalls         int
	publicationCalls   int
	tombstoneCalls     int
	stageCommits       int
	publicationCommits int
	tombstoneCommits   int
}

type replayControlIdentity struct {
	operationID         string
	manifestSHA256      string
	destinationDriverID string
	locationsAdded      uint64
	sourceDriverID      string
	locationsTombstoned uint64
	recoveryRevision    uint64
	graceUntil          uint64
}

func TestCopyControlLostResponseMatrixReplaysExactRequests(t *testing.T) {
	t.Parallel()

	points := []replicationCrashPoint{
		crashBeforeR2Stage,
		crashAfterR2Stage,
		crashBeforeD1Publish,
		crashAfterD1Publish,
	}

	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			result, staged := prepareCrashControlReplication(t)
			token, encodedToken := testClientToken(t)
			operation, lease := crashCopyIdentities(result.Recovery)
			publication := sdk.PublishCopyRequest{
				Operation: operation, Lease: lease, StagedRecovery: staged, Result: result,
			}
			state := &replayControlState{}
			server := newReplayControlServer(t, encodedToken, staged, state, replayControlIdentity{
				operationID: operation.ID, manifestSHA256: operation.ManifestSHA256,
				destinationDriverID: operation.DestinationDriverID,
				locationsAdded:      uint64(len(result.Locations)),
				recoveryRevision:    operation.SourceRecoveryRevision + 1,
			})

			script := &deterministicCrashScript{target: point}
			httpClient := *server.Client()
			httpClient.Transport = &crashRoundTripper{
				base: server.Client().Transport, script: script,
			}

			control, err := sdk.NewControlClient(server.URL, token, &httpClient)
			if err != nil {
				t.Fatalf("construct crash control client: %v", err)
			}

			exerciseControlCrashReplay(t, point, control, result.Recovery, staged, publication)

			if !script.didFire() {
				t.Fatalf("control crash point %s was never reached", point)
			}

			state.assertSingleCommit(t, point)
		})
	}
}

func TestMoveControlLostResponseMatrixReplaysExactDestinationPublication(t *testing.T) {
	t.Parallel()

	points := []replicationCrashPoint{crashBeforeD1Publish, crashAfterD1Publish}

	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			result, staged := prepareCrashControlReplication(t)
			token, encodedToken := testClientToken(t)
			operation, lease := crashMoveIdentities(result.Recovery)
			publication := sdk.PublishMoveDestinationRequest{
				Operation: operation, Lease: lease, StagedRecovery: staged, Result: result,
			}
			state := &replayControlState{}
			server := newReplayControlServer(t, encodedToken, staged, state, replayControlIdentity{
				operationID: operation.ID, manifestSHA256: operation.ManifestSHA256,
				destinationDriverID: operation.DestinationDriverID,
				locationsAdded:      uint64(len(result.Locations)),
				recoveryRevision:    operation.SourceRecoveryRevision + 1,
			})

			script := &deterministicCrashScript{target: point}
			httpClient := *server.Client()
			httpClient.Transport = &crashRoundTripper{
				base: server.Client().Transport, script: script,
			}

			control, err := sdk.NewControlClient(server.URL, token, &httpClient)
			if err != nil {
				t.Fatalf("construct move crash control client: %v", err)
			}

			prepared, err := control.StageRecovery(context.Background(), result.Recovery)
			if err != nil || prepared != staged {
				t.Fatalf("prepare staged move recovery: result=%+v err=%v", prepared, err)
			}

			_, firstErr := control.PublishMoveDestination(context.Background(), publication)
			if !errors.Is(firstErr, errInjectedReplicationCrash) {
				t.Fatalf("first move publication did not stop at %s: %v", point, firstErr)
			}

			replayed, replayErr := control.PublishMoveDestination(context.Background(), publication)
			if replayErr != nil || replayed.State != "destination_published" {
				t.Fatalf(
					"move publication did not replay after %s: result=%+v err=%v",
					point,
					replayed,
					replayErr,
				)
			}

			if !script.didFire() {
				t.Fatalf("move crash point %s was never reached", point)
			}

			state.assertSingleCommit(t, point)
		})
	}
}

func prepareCrashControlReplication(t *testing.T) (sdk.ReplicationResult, sdk.StagedRecovery) {
	t.Helper()

	fixture := newReplicationFixture(t)
	destination := newMemoryArchive()
	replicator := newTestReplicator(
		t,
		map[string]provider.Reader{"source": fixture.source},
		destination,
		200,
		1<<20,
	)

	result, err := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: fixture.recovery, DestinationDriverID: "destination",
		DestinationPrefix: "control-crash", StagingDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("prepare replicated transfer: %v", err)
	}

	encodedRecovery := mustMarshalRecovery(t, result.Recovery)
	staged := sdk.StagedRecovery{
		ManifestSHA256: result.Recovery.ManifestSHA256,
		RecoverySHA256: testDigest(encodedRecovery),
		NamespaceID:    result.Recovery.Manifest.NamespaceID,
		ObjectID:       result.Recovery.Manifest.ObjectID,
		Generation:     result.Recovery.Manifest.Generation,
		R2Key:          "manifests/crash-matrix/recovery.json",
		R2Version:      "r2-version-1",
		Bytes:          uint64(len(encodedRecovery)),
	}

	return result, staged
}

func newReplayControlServer(
	t *testing.T,
	encodedToken string,
	staged sdk.StagedRecovery,
	state *replayControlState,
	identity replayControlIdentity,
) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(
		response http.ResponseWriter,
		request *http.Request,
	) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read replay request: %v", err)

			return
		}

		switch request.URL.Path {
		case "/api/v1/recovery-manifests/stage":
			state.recordStage(t, body)
			writeJSON(t, response, staged)
		case "/api/v1/copies/publish":
			state.recordPublication(t, body)
			writeJSON(t, response, sdk.PublishedCopy{
				OperationID: identity.operationID, ManifestSHA256: identity.manifestSHA256,
				RecoverySHA256:      staged.RecoverySHA256,
				DestinationDriverID: identity.destinationDriverID,
				LocationsAdded:      identity.locationsAdded,
				RecoveryRevision:    identity.recoveryRevision,
				State:               "published",
			})
		case "/api/v1/moves/publish-destination":
			state.recordPublication(t, body)
			writeJSON(t, response, sdk.PublishedMoveDestination{
				OperationID: identity.operationID, ManifestSHA256: identity.manifestSHA256,
				RecoverySHA256:      staged.RecoverySHA256,
				DestinationDriverID: identity.destinationDriverID,
				LocationsAdded:      identity.locationsAdded,
				RecoveryRevision:    identity.recoveryRevision,
				State:               "destination_published",
			})
		case "/api/v1/moves/tombstone-source":
			state.recordTombstone(t, body)
			writeJSON(t, response, sdk.TombstonedMoveSource{
				OperationID: identity.operationID, ManifestSHA256: identity.manifestSHA256,
				RecoverySHA256:            staged.RecoverySHA256,
				SourceDriverID:            identity.sourceDriverID,
				SourceLocationsTombstoned: identity.locationsTombstoned,
				RecoveryRevision:          identity.recoveryRevision,
				GraceUntil:                identity.graceUntil,
				State:                     "source_delete_pending",
			})
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	return server
}

func exerciseControlCrashReplay(
	t *testing.T,
	point replicationCrashPoint,
	control *sdk.ControlClient,
	recovery manifest.RecoveryManifest,
	staged sdk.StagedRecovery,
	publication sdk.PublishCopyRequest,
) {
	t.Helper()

	switch point {
	case crashBeforeR2Stage, crashAfterR2Stage:
		_, firstErr := control.StageRecovery(context.Background(), recovery)
		if !errors.Is(firstErr, errInjectedReplicationCrash) {
			t.Fatalf("first stage did not stop at %s: %v", point, firstErr)
		}

		replayed, replayErr := control.StageRecovery(context.Background(), recovery)
		if replayErr != nil || replayed != staged {
			t.Fatalf("stage did not replay after %s: result=%+v err=%v", point, replayed, replayErr)
		}
	case crashBeforeD1Publish, crashAfterD1Publish:
		prepared, stageErr := control.StageRecovery(context.Background(), recovery)
		if stageErr != nil || prepared != staged {
			t.Fatalf("prepare staged recovery: result=%+v err=%v", prepared, stageErr)
		}

		_, firstErr := control.PublishCopy(context.Background(), publication)
		if !errors.Is(firstErr, errInjectedReplicationCrash) {
			t.Fatalf("first publication did not stop at %s: %v", point, firstErr)
		}

		replayed, replayErr := control.PublishCopy(context.Background(), publication)
		if replayErr != nil || replayed.State != "published" {
			t.Fatalf(
				"publication did not replay after %s: result=%+v err=%v",
				point,
				replayed,
				replayErr,
			)
		}
	case crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead:
		t.Fatalf("provider crash point %s cannot exercise the control client", point)
	case crashBeforeD1Tombstone, crashAfterD1Tombstone:
		t.Fatalf("move tombstone crash point %s cannot exercise copy publication", point)
	default:
		t.Fatalf("unsupported control crash point %s", point)
	}
}

func crashCopyIdentities(recovery manifest.RecoveryManifest) (sdk.CopyOperation, sdk.OperationLease) {
	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	operation := sdk.CopyOperation{
		ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
		Kind: "copy", Incarnation: incarnation,
		ObjectID: recovery.Manifest.ObjectID, Generation: recovery.Manifest.Generation,
		ManifestSHA256: recovery.ManifestSHA256, SourceRecoveryRevision: 1,
		DestinationDriverID: "destination",
	}
	lease := sdk.OperationLease{
		OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
		Incarnation: incarnation, FencingToken: 3,
	}

	return operation, lease
}

func crashMoveIdentities(recovery manifest.RecoveryManifest) (sdk.MoveOperation, sdk.OperationLease) {
	copyOperation, lease := crashCopyIdentities(recovery)
	sourceLocationCount := uint64(0)

	for _, location := range recovery.Locations {
		if location.DriverID == "source" {
			sourceLocationCount++
		}
	}

	operation := sdk.MoveOperation{
		ID: copyOperation.ID, NamespaceID: copyOperation.NamespaceID,
		Kind: "move", Incarnation: copyOperation.Incarnation,
		ObjectID: copyOperation.ObjectID, Generation: copyOperation.Generation,
		ManifestSHA256:         copyOperation.ManifestSHA256,
		SourceRecoverySHA256:   copyOperation.SourceRecoverySHA256,
		SourceRecoveryRevision: copyOperation.SourceRecoveryRevision,
		SourceDriverID:         "source",
		DestinationDriverID:    copyOperation.DestinationDriverID,
		SourceLocationCount:    sourceLocationCount,
	}

	return operation, lease
}

func (state *replayControlState) recordStage(t *testing.T, body []byte) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.stageCalls++
	if state.stageBody == nil {
		state.stageBody = bytes.Clone(body)
		state.stageCommits++

		return
	}

	if !bytes.Equal(state.stageBody, body) {
		t.Error("replayed recovery staging request changed")
	}
}

func (state *replayControlState) recordPublication(t *testing.T, body []byte) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.publicationCalls++
	if state.publicationBody == nil {
		state.publicationBody = bytes.Clone(body)
		state.publicationCommits++

		return
	}

	if !bytes.Equal(state.publicationBody, body) {
		t.Error("replayed publication request changed")
	}
}

func (state *replayControlState) recordTombstone(t *testing.T, body []byte) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	state.tombstoneCalls++
	if state.tombstoneBody == nil {
		state.tombstoneBody = bytes.Clone(body)
		state.tombstoneCommits++

		return
	}

	if !bytes.Equal(state.tombstoneBody, body) {
		t.Error("replayed tombstone request changed")
	}
}

func (state *replayControlState) assertSingleCommit(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	expectedStageCalls := 1
	expectedPublicationCalls := 0
	expectedPublicationCommits := 0

	switch point {
	case crashBeforeR2Stage:
	case crashAfterR2Stage:
		expectedStageCalls = 2
	case crashBeforeD1Publish:
		expectedPublicationCalls = 1
		expectedPublicationCommits = 1
	case crashAfterD1Publish:
		expectedPublicationCalls = 2
		expectedPublicationCommits = 1
	case crashBeforeD1Tombstone, crashAfterD1Tombstone:
		t.Fatalf("move tombstone point %s requires tombstone-phase assertions", point)
	case crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead:
		t.Fatalf("provider crash point %s has no control-plane commit counts", point)
	default:
		t.Fatalf("unsupported control crash point %s", point)
	}

	if state.stageCalls != expectedStageCalls {
		t.Fatalf("stage received %d calls after %s; want %d", state.stageCalls, point, expectedStageCalls)
	}

	if state.stageCommits != 1 {
		t.Fatalf("stage committed %d times after %s", state.stageCommits, point)
	}

	if state.publicationCalls != expectedPublicationCalls {
		t.Fatalf(
			"publication received %d calls after %s; want %d",
			state.publicationCalls,
			point,
			expectedPublicationCalls,
		)
	}

	if state.publicationCommits != expectedPublicationCommits {
		t.Fatalf(
			"publication committed %d times after %s; want %d",
			state.publicationCommits,
			point,
			expectedPublicationCommits,
		)
	}

	if state.tombstoneCalls != 0 || state.tombstoneCommits != 0 {
		t.Fatalf(
			"destination replay unexpectedly reached tombstone after %s: calls=%d commits=%d",
			point,
			state.tombstoneCalls,
			state.tombstoneCommits,
		)
	}
}

func (state *replayControlState) assertTombstonePhaseSingleCommit(
	t *testing.T,
	point replicationCrashPoint,
) {
	t.Helper()

	state.mutex.Lock()
	defer state.mutex.Unlock()

	expectedStageCalls := 1
	expectedTombstoneCalls := 1

	switch point {
	case crashBeforeR2Stage:
	case crashAfterR2Stage:
		expectedStageCalls = 2
	case crashBeforeD1Tombstone:
	case crashAfterD1Tombstone:
		expectedTombstoneCalls = 2
	case crashBeforePayloadPut,
		crashAfterPayloadPut,
		crashBeforePayloadRead,
		crashAfterPayloadRead,
		crashBeforeSidecarPut,
		crashAfterSidecarPut,
		crashBeforeSidecarRead,
		crashAfterSidecarRead,
		crashBeforeD1Publish,
		crashAfterD1Publish:
		t.Fatalf("crash point %s does not belong to the move tombstone phase", point)
	default:
		t.Fatalf("unsupported move tombstone crash point %s", point)
	}

	if state.stageCalls != expectedStageCalls || state.stageCommits != 1 {
		t.Fatalf(
			"tombstone staging did not converge after %s: calls=%d/%d commits=%d/1",
			point,
			state.stageCalls,
			expectedStageCalls,
			state.stageCommits,
		)
	}

	if state.publicationCalls != 0 || state.publicationCommits != 0 {
		t.Fatalf(
			"tombstone replay unexpectedly published a destination after %s: calls=%d commits=%d",
			point,
			state.publicationCalls,
			state.publicationCommits,
		)
	}

	if state.tombstoneCalls != expectedTombstoneCalls || state.tombstoneCommits != 1 {
		t.Fatalf(
			"source tombstone did not converge after %s: calls=%d/%d commits=%d/1",
			point,
			state.tombstoneCalls,
			expectedTombstoneCalls,
			state.tombstoneCommits,
		)
	}
}
