package sdk_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type moveTombstoneCrashFixture struct {
	current      manifest.RecoveryManifest
	finalSidecar sdk.RecoverySidecar
	staged       sdk.StagedRecovery
	operation    sdk.MoveOperation
	lease        sdk.OperationLease
}

func TestMoveControlLostResponseMatrixCompletesExactSourceTombstone(t *testing.T) {
	t.Parallel()

	points := []replicationCrashPoint{
		crashBeforeR2Stage,
		crashAfterR2Stage,
		crashBeforeD1Tombstone,
		crashAfterD1Tombstone,
	}

	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			fixture := newMoveTombstoneCrashFixture(t)
			token, encodedToken := testClientToken(t)
			state := &replayControlState{}
			server := newReplayControlServer(t, encodedToken, fixture.staged, state, replayControlIdentity{
				operationID: fixture.operation.ID, manifestSHA256: fixture.operation.ManifestSHA256,
				sourceDriverID:      fixture.operation.SourceDriverID,
				locationsTombstoned: fixture.operation.SourceLocationCount,
				recoveryRevision:    fixture.operation.SourceRecoveryRevision + 2,
				graceUntil:          90_000,
			})

			script := &deterministicCrashScript{target: point}
			httpClient := *server.Client()
			httpClient.Transport = &crashRoundTripper{
				base: server.Client().Transport, script: script,
			}

			control, err := sdk.NewControlClient(server.URL, token, &httpClient)
			if err != nil {
				t.Fatalf("construct tombstone crash control client: %v", err)
			}

			request := sdk.TombstoneMoveSourceRequest{
				Operation: fixture.operation, Lease: fixture.lease,
				CurrentRecovery: fixture.current, FinalSidecar: fixture.finalSidecar,
				StagedRecovery: fixture.staged,
			}
			exerciseMoveTombstoneCrashReplay(t, point, control, request)

			if !script.didFire() {
				t.Fatalf("move tombstone crash point %s was never reached", point)
			}

			state.assertTombstonePhaseSingleCommit(t, point)
		})
	}
}

func newMoveTombstoneCrashFixture(t *testing.T) moveTombstoneCrashFixture {
	t.Helper()

	source := newReplicationFixture(t)
	destination := newMemoryArchive()
	replicator := newTestReplicator(
		t,
		map[string]provider.Reader{"source": source.source},
		destination,
		200,
		1<<20,
	)

	replicated, err := replicator.Replicate(context.Background(), sdk.ReplicationRequest{
		Recovery: source.recovery, DestinationDriverID: "destination",
		DestinationPrefix: "tombstone-crash", StagingDirectory: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("prepare move tombstone replication: %v", err)
	}

	operation, lease := crashMoveIdentities(replicated.Recovery)
	finalRecovery := recoveryWithoutCrashMoveSource(t, replicated.Recovery, operation)

	finalSidecar, err := replicator.WriteRecoverySidecar(
		context.Background(),
		"tombstone-crash",
		finalRecovery,
	)
	if err != nil {
		t.Fatalf("prepare final move recovery sidecar: %v", err)
	}

	if finalSidecar.Key == replicated.RecoveryKey {
		t.Fatalf("move source removal reused the destination recovery sidecar: %s", finalSidecar.Key)
	}

	encodedRecovery := mustMarshalRecovery(t, finalRecovery)
	staged := sdk.StagedRecovery{
		ManifestSHA256: finalRecovery.ManifestSHA256,
		RecoverySHA256: testDigest(encodedRecovery),
		NamespaceID:    finalRecovery.Manifest.NamespaceID,
		ObjectID:       finalRecovery.Manifest.ObjectID,
		Generation:     finalRecovery.Manifest.Generation,
		R2Key:          "manifests/crash-matrix/final-recovery.json",
		R2Version:      "r2-version-final",
		Bytes:          uint64(len(encodedRecovery)),
	}

	return moveTombstoneCrashFixture{
		current: replicated.Recovery, finalSidecar: finalSidecar, staged: staged,
		operation: operation, lease: lease,
	}
}

func recoveryWithoutCrashMoveSource(
	t *testing.T,
	current manifest.RecoveryManifest,
	operation sdk.MoveOperation,
) manifest.RecoveryManifest {
	t.Helper()

	locations := make([]manifest.Location, 0, len(current.Locations))
	removed := uint64(0)

	for _, location := range current.Locations {
		if location.DriverID == operation.SourceDriverID {
			removed++

			continue
		}

		locations = append(locations, location)
	}

	if removed != operation.SourceLocationCount {
		t.Fatalf("removed %d move source locations; want %d", removed, operation.SourceLocationCount)
	}

	finalRecovery, err := manifest.NewRecoveryManifest(current.Manifest, locations)
	if err != nil {
		t.Fatalf("construct final move tombstone recovery: %v", err)
	}

	return finalRecovery
}

func exerciseMoveTombstoneCrashReplay(
	t *testing.T,
	point replicationCrashPoint,
	control *sdk.ControlClient,
	request sdk.TombstoneMoveSourceRequest,
) {
	t.Helper()

	switch point {
	case crashBeforeR2Stage, crashAfterR2Stage:
		_, firstErr := control.StageRecovery(context.Background(), request.FinalSidecar.Recovery)
		if !errors.Is(firstErr, errInjectedReplicationCrash) {
			t.Fatalf("first final recovery stage did not stop at %s: %v", point, firstErr)
		}

		replayed, replayErr := control.StageRecovery(context.Background(), request.FinalSidecar.Recovery)
		if replayErr != nil || replayed != request.StagedRecovery {
			t.Fatalf("final recovery stage did not replay after %s: result=%+v err=%v", point, replayed, replayErr)
		}

		tombstoned, tombstoneErr := control.TombstoneMoveSource(context.Background(), request)
		if tombstoneErr != nil || tombstoned.State != "source_delete_pending" {
			t.Fatalf("move did not tombstone after staging replay: result=%+v err=%v", tombstoned, tombstoneErr)
		}
	case crashBeforeD1Tombstone, crashAfterD1Tombstone:
		staged, stageErr := control.StageRecovery(context.Background(), request.FinalSidecar.Recovery)
		if stageErr != nil || staged != request.StagedRecovery {
			t.Fatalf("prepare final staged recovery: result=%+v err=%v", staged, stageErr)
		}

		_, firstErr := control.TombstoneMoveSource(context.Background(), request)
		if !errors.Is(firstErr, errInjectedReplicationCrash) {
			t.Fatalf("first source tombstone did not stop at %s: %v", point, firstErr)
		}

		replayed, replayErr := control.TombstoneMoveSource(context.Background(), request)
		if replayErr != nil || replayed.State != "source_delete_pending" {
			t.Fatalf("source tombstone did not replay after %s: result=%+v err=%v", point, replayed, replayErr)
		}
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
	case crashBeforeD1Create,
		crashAfterD1Create,
		crashBeforeD1Claim,
		crashAfterD1Claim,
		crashBeforeKeyGrant,
		crashAfterKeyGrant,
		crashBeforeD1Progress,
		crashAfterD1Progress:
		t.Fatalf("import-only crash point %s does not belong to the move tombstone phase", point)
	default:
		t.Fatalf("unsupported move tombstone crash point %s", point)
	}
}
