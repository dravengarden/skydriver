package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

func TestRepairerRebuildsAndReadsBackMissingImmutableObject(t *testing.T) {
	payload := bytes.Repeat([]byte{'r'}, 18)
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])
	recovery := verificationRecovery(t, digestHex, []manifest.Location{
		{DriverID: "target", StorageKey: "objects/target", Length: uint64(len(payload))},
		{DriverID: "source", StorageKey: "objects/source", Length: uint64(len(payload))},
	})
	indexed := []sdk.IndexedLocation{
		{
			ID: "target-location", ExtentSHA256: digestHex, DriverID: "target",
			StorageKey: "objects/target", Length: uint64(len(payload)), State: "missing",
		},
		{
			ID: "source-location", ExtentSHA256: digestHex, DriverID: "source",
			StorageKey: "objects/source", Length: uint64(len(payload)), State: "available",
		},
	}

	plan, err := (sdk.RepairPlanner{}).PlanMissing(recovery, indexed, []string{"target-location"})
	if err != nil {
		t.Fatalf("plan missing repair: %v", err)
	}

	root := t.TempDir()

	destination, err := localfs.NewClient(root)
	if err != nil {
		t.Fatalf("open repair destination: %v", err)
	}

	repairer, err := sdk.NewRepairer(
		map[string]provider.Reader{"source": verificationReader{data: payload}},
		map[string]provider.ReadWriter{"target": destination},
		uint64(len(payload)),
		uint64(len(payload)),
	)
	if err != nil {
		t.Fatalf("construct repairer: %v", err)
	}

	result, err := repairer.Repair(context.Background(), plan, t.TempDir())
	if err != nil {
		t.Fatalf("execute repair: %v", err)
	}

	repaired, err := os.ReadFile(filepath.Join(root, "objects", "target"))
	if err != nil {
		t.Fatalf("read repaired object: %v", err)
	}

	if !bytes.Equal(repaired, payload) || result.ObjectsRepaired != 1 || result.ExtentsRepaired != 1 {
		t.Fatalf("unexpected repair result: result=%+v bytes=%x", result, repaired)
	}
}

func TestRepairerRequiresStablePinnedProviderVersion(t *testing.T) {
	payload := bytes.Repeat([]byte{'v'}, 18)
	digest := sha256.Sum256(payload)
	digestHex := hex.EncodeToString(digest[:])
	recovery := verificationRecovery(t, digestHex, []manifest.Location{
		{
			DriverID: "target", StorageKey: "target", ProviderVersion: "pinned-v1",
			Length: uint64(len(payload)),
		},
		{DriverID: "source", StorageKey: "source", Length: uint64(len(payload))},
	})

	plan, err := (sdk.RepairPlanner{}).PlanMissing(recovery, []sdk.IndexedLocation{
		{
			ID: "target-location", ExtentSHA256: digestHex, DriverID: "target",
			StorageKey: "target", ProviderVersion: "pinned-v1",
			Length: uint64(len(payload)), State: "missing",
		},
		{
			ID: "source-location", ExtentSHA256: digestHex, DriverID: "source",
			StorageKey: "source", Length: uint64(len(payload)), State: "available",
		},
	}, []string{"target-location"})
	if err != nil {
		t.Fatalf("plan version-pinned repair: %v", err)
	}

	destination := newMemoryArchive()

	repairer, err := sdk.NewRepairer(
		map[string]provider.Reader{"source": verificationReader{data: payload}},
		map[string]provider.ReadWriter{"target": destination},
		uint64(len(payload)),
		uint64(len(payload)),
	)
	if err != nil {
		t.Fatalf("construct version-pinned repairer: %v", err)
	}

	_, err = repairer.Repair(context.Background(), plan, t.TempDir())
	if !errors.Is(err, sdk.ErrRepairRequiresRelocation) {
		t.Fatalf("expected provider-version relocation, got %v", err)
	}
}
