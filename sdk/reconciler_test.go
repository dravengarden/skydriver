package sdk_test

import (
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestReconcilerClassifiesMetadataDifferencesWithoutPhysicalClaims(t *testing.T) {
	base := controlRecoveryManifest(t)

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, []manifest.Location{
		{
			ExtentSHA256: base.Locations[0].ExtentSHA256, DriverID: "one",
			StorageKey: "one", ProviderVersion: "v1", Length: base.Locations[0].Length,
		},
		{
			ExtentSHA256: base.Locations[0].ExtentSHA256, DriverID: "two",
			StorageKey: "two", ProviderVersion: "v2", Length: base.Locations[0].Length,
		},
	})
	if err != nil {
		t.Fatalf("construct reconciliation recovery: %v", err)
	}

	result, err := (sdk.Reconciler{}).Reconcile(recovery, []sdk.IndexedLocation{
		{
			ID: "location-one", ExtentSHA256: base.Locations[0].ExtentSHA256,
			DriverID: "one", StorageKey: "one", ProviderVersion: "v1",
			Length: base.Locations[0].Length, State: "available",
		},
		{
			ID: "location-orphan", ExtentSHA256: base.Locations[0].ExtentSHA256,
			DriverID: "three", StorageKey: "three", ProviderVersion: "v3",
			Length: base.Locations[0].Length, State: "available",
		},
	}, 2)
	if err != nil {
		t.Fatalf("reconcile metadata: %v", err)
	}

	if result.RecoveryOnly != 1 || result.IndexOnly != 1 || result.Degraded != 1 ||
		len(result.Evidence) != 3 {
		t.Fatalf("unexpected reconciliation result: %+v", result)
	}

	conditions := map[sdk.ReconciliationCondition]bool{}
	for _, evidence := range result.Evidence {
		conditions[evidence.Condition] = true
	}

	for _, condition := range []sdk.ReconciliationCondition{
		sdk.ReconciliationUnindexed, sdk.ReconciliationOrphan, sdk.ReconciliationDegraded,
	} {
		if !conditions[condition] {
			t.Errorf("missing reconciliation condition %q", condition)
		}
	}
}

func TestReconcilerRejectsDuplicateIndexIdentity(t *testing.T) {
	recovery := controlRecoveryManifest(t)

	location := sdk.IndexedLocation{
		ID: "one", ExtentSHA256: recovery.Locations[0].ExtentSHA256,
		DriverID: recovery.Locations[0].DriverID, StorageKey: recovery.Locations[0].StorageKey,
		Length: recovery.Locations[0].Length, State: "available",
	}
	if _, err := (sdk.Reconciler{}).Reconcile(recovery, []sdk.IndexedLocation{location, location}, 1); err == nil {
		t.Fatal("duplicate indexed identity was accepted")
	}
}
