package sdk_test

import (
	"errors"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestRepairPlannerReconstructsCompleteMissingObjectFromAvailableReplica(t *testing.T) {
	base := controlRecoveryManifest(t)
	extent := base.Locations[0]

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{
		{
			ExtentSHA256: extent.ExtentSHA256, DriverID: "missing-driver",
			StorageKey: "object", ProviderVersion: "missing-v1", Length: extent.Length,
		},
		{
			ExtentSHA256: extent.ExtentSHA256, DriverID: "source-driver",
			StorageKey: "source", ProviderVersion: "source-v1", Length: extent.Length,
		},
	})
	if err != nil {
		t.Fatalf("construct repair recovery: %v", err)
	}

	indexed := []sdk.IndexedLocation{
		{
			ID: "missing-location", ExtentSHA256: extent.ExtentSHA256,
			DriverID: "missing-driver", StorageKey: "object", ProviderVersion: "missing-v1",
			Length: extent.Length, State: "missing",
		},
		{
			ID: "source-location", ExtentSHA256: extent.ExtentSHA256,
			DriverID: "source-driver", StorageKey: "source", ProviderVersion: "source-v1",
			Length: extent.Length, State: "available",
		},
	}

	plan, err := (sdk.RepairPlanner{}).PlanMissing(recovery, indexed, []string{"missing-location"})
	if err != nil {
		t.Fatalf("plan missing repair: %v", err)
	}

	if len(plan.Objects) != 1 || len(plan.Objects[0].Extents) != 1 ||
		len(plan.Objects[0].Extents[0].Sources) != 1 ||
		plan.Objects[0].Length != extent.Length {
		t.Fatalf("unexpected repair plan: %+v", plan)
	}
}

func TestRepairPlannerRejectsCorruptImmutableTarget(t *testing.T) {
	recovery := controlRecoveryManifest(t)
	location := recovery.Locations[0]

	_, err := (sdk.RepairPlanner{}).PlanMissing(recovery, []sdk.IndexedLocation{{
		ID: "corrupt-location", ExtentSHA256: location.ExtentSHA256,
		DriverID: location.DriverID, StorageKey: location.StorageKey,
		Length: location.Length, State: "corrupt",
	}}, []string{"corrupt-location"})
	if !errors.Is(err, sdk.ErrRepairRequiresRelocation) {
		t.Fatalf("expected relocation requirement, got %v", err)
	}
}

func TestRepairPlannerRequiresIndependentAvailableSource(t *testing.T) {
	recovery := controlRecoveryManifest(t)
	location := recovery.Locations[0]

	_, err := (sdk.RepairPlanner{}).PlanMissing(recovery, []sdk.IndexedLocation{{
		ID: "missing-location", ExtentSHA256: location.ExtentSHA256,
		DriverID: location.DriverID, StorageKey: location.StorageKey,
		Length: location.Length, State: "missing",
	}}, []string{"missing-location"})
	if !errors.Is(err, sdk.ErrNoRepairSource) {
		t.Fatalf("expected unavailable repair source, got %v", err)
	}
}
