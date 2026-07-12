package sdk

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/dravengarden/carrack/manifest"
)

var (
	// ErrInvalidRepair indicates inconsistent recovery or D1 repair inputs.
	ErrInvalidRepair = errors.New("invalid Carrack repair input")
	// ErrRepairRequiresRelocation indicates immutable corrupt bytes cannot be overwritten safely.
	ErrRepairRequiresRelocation = errors.New("carrack repair requires a new location")
	// ErrNoRepairSource indicates that an extent lacks an independently available source.
	ErrNoRepairSource = errors.New("carrack repair extent has no available source")
)

// RepairExtent reconstructs one exact range within a missing provider object.
type RepairExtent struct {
	ExtentSHA256 string              `json:"extent_sha256" yaml:"extent_sha256"`
	Offset       uint64              `json:"offset"        yaml:"offset"`
	Length       uint64              `json:"length"        yaml:"length"`
	Sources      []manifest.Location `json:"sources"       yaml:"sources"`
}

// RepairObject reconstructs one complete immutable provider object.
type RepairObject struct {
	DriverID        string         `json:"driver_id"        yaml:"driver_id"`
	StorageKey      string         `json:"storage_key"      yaml:"storage_key"`
	ProviderVersion string         `json:"provider_version" yaml:"provider_version"`
	Length          uint64         `json:"length"           yaml:"length"`
	Extents         []RepairExtent `json:"extents"          yaml:"extents"`
}

// RepairPlan contains only missing-object reconstruction; it never authorizes deletion.
type RepairPlan struct {
	ManifestSHA256 string         `json:"manifest_sha256" yaml:"manifest_sha256"`
	Objects        []RepairObject `json:"objects"         yaml:"objects"`
}

// RepairPlanner derives object-complete reconstruction work from one fenced snapshot.
type RepairPlanner struct{}

// PlanMissing requires every server-pinned target range to belong to recovery
// and every constituent extent to have an independently available source.
func (RepairPlanner) PlanMissing(
	recovery manifest.RecoveryManifest,
	indexed []IndexedLocation,
	targetLocationIDs []string,
) (RepairPlan, error) {
	if err := recovery.Validate(); err != nil {
		return RepairPlan{}, fmt.Errorf("%w: recovery manifest: %w", ErrInvalidRepair, err)
	}

	if len(targetLocationIDs) == 0 {
		return RepairPlan{}, fmt.Errorf("%w: repair targets are empty", ErrInvalidRepair)
	}

	indexes, err := indexRepairLocations(recovery.Locations, indexed)
	if err != nil {
		return RepairPlan{}, err
	}

	targetObjects, err := selectRepairTargetObjects(targetLocationIDs, indexes)
	if err != nil {
		return RepairPlan{}, err
	}

	if err := rejectCorruptTargetObjects(indexed, targetObjects); err != nil {
		return RepairPlan{}, err
	}

	objects := make([]RepairObject, 0, len(targetObjects))
	for identity := range targetObjects {
		object, err := planMissingObject(
			identity,
			indexes.locationsByObject[identity],
			recovery.Locations,
			indexes.indexedByIdentity,
		)
		if err != nil {
			return RepairPlan{}, err
		}

		objects = append(objects, object)
	}

	slices.SortFunc(objects, func(left, right RepairObject) int {
		if driverOrder := cmp.Compare(left.DriverID, right.DriverID); driverOrder != 0 {
			return driverOrder
		}

		return cmp.Compare(left.StorageKey, right.StorageKey)
	})

	return RepairPlan{ManifestSHA256: recovery.ManifestSHA256, Objects: objects}, nil
}

type repairObjectIdentity struct {
	driverID   string
	storageKey string
}

type repairLocationIndexes struct {
	recoveryByIdentity map[string]manifest.Location
	locationsByObject  map[repairObjectIdentity][]manifest.Location
	indexedByIdentity  map[string]IndexedLocation
	indexedByID        map[string]IndexedLocation
}

func indexRepairLocations(
	recovery []manifest.Location,
	indexed []IndexedLocation,
) (repairLocationIndexes, error) {
	indexes := repairLocationIndexes{
		recoveryByIdentity: make(map[string]manifest.Location, len(recovery)),
		locationsByObject:  make(map[repairObjectIdentity][]manifest.Location),
		indexedByIdentity:  make(map[string]IndexedLocation, len(indexed)),
		indexedByID:        make(map[string]IndexedLocation, len(indexed)),
	}

	for _, location := range recovery {
		identity := reconciliationLocationKey(
			location.ExtentSHA256, location.DriverID, location.StorageKey,
			location.ProviderVersion, location.Offset, location.Length,
		)
		indexes.recoveryByIdentity[identity] = location
		object := repairObjectIdentity{driverID: location.DriverID, storageKey: location.StorageKey}
		indexes.locationsByObject[object] = append(indexes.locationsByObject[object], location)
	}

	for _, location := range indexed {
		if err := validateIndexedLocation(location); err != nil {
			return repairLocationIndexes{}, fmt.Errorf("%w: %w", ErrInvalidRepair, err)
		}

		identity := reconciliationLocationKey(
			location.ExtentSHA256, location.DriverID, location.StorageKey,
			location.ProviderVersion, location.Offset, location.Length,
		)
		if _, duplicate := indexes.indexedByIdentity[identity]; duplicate {
			return repairLocationIndexes{}, fmt.Errorf("%w: duplicate indexed location", ErrInvalidRepair)
		}

		if _, duplicate := indexes.indexedByID[location.ID]; duplicate {
			return repairLocationIndexes{}, fmt.Errorf("%w: duplicate indexed location ID", ErrInvalidRepair)
		}

		indexes.indexedByIdentity[identity] = location
		indexes.indexedByID[location.ID] = location
	}

	return indexes, nil
}

func selectRepairTargetObjects(
	targetLocationIDs []string,
	indexes repairLocationIndexes,
) (map[repairObjectIdentity]struct{}, error) {
	targetIDs := make(map[string]struct{}, len(targetLocationIDs))
	targetObjects := make(map[repairObjectIdentity]struct{})

	for _, locationID := range targetLocationIDs {
		if !validControlString(locationID, 2_048) {
			return nil, fmt.Errorf("%w: malformed repair target ID", ErrInvalidRepair)
		}

		if _, duplicate := targetIDs[locationID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate repair target ID", ErrInvalidRepair)
		}

		targetIDs[locationID] = struct{}{}

		location, exists := indexes.indexedByID[locationID]
		if !exists {
			return nil, fmt.Errorf("%w: pinned target is not missing", ErrInvalidRepair)
		}

		if location.State == indexedStateCorrupt {
			return nil, repairRelocationError(location)
		}

		if location.State != indexedStateMissing {
			return nil, fmt.Errorf("%w: pinned target is not missing", ErrInvalidRepair)
		}

		identity := reconciliationLocationKey(
			location.ExtentSHA256, location.DriverID, location.StorageKey,
			location.ProviderVersion, location.Offset, location.Length,
		)
		if _, exists := indexes.recoveryByIdentity[identity]; !exists {
			return nil, fmt.Errorf("%w: missing target is absent from recovery", ErrInvalidRepair)
		}

		targetObjects[repairObjectIdentity{
			driverID: location.DriverID, storageKey: location.StorageKey,
		}] = struct{}{}
	}

	return targetObjects, nil
}

func rejectCorruptTargetObjects(
	indexed []IndexedLocation,
	targetObjects map[repairObjectIdentity]struct{},
) error {
	for _, location := range indexed {
		object := repairObjectIdentity{driverID: location.DriverID, storageKey: location.StorageKey}
		if location.State != indexedStateCorrupt {
			continue
		}

		if _, targeted := targetObjects[object]; targeted {
			return repairRelocationError(location)
		}
	}

	return nil
}

func repairRelocationError(location IndexedLocation) error {
	return fmt.Errorf(
		"%w: driver %q key %q",
		ErrRepairRequiresRelocation,
		location.DriverID,
		location.StorageKey,
	)
}

func planMissingObject(
	identity repairObjectIdentity,
	targets []manifest.Location,
	allRecovery []manifest.Location,
	indexed map[string]IndexedLocation,
) (RepairObject, error) {
	slices.SortFunc(targets, func(left, right manifest.Location) int {
		if left.Offset < right.Offset {
			return -1
		}

		if left.Offset > right.Offset {
			return 1
		}

		return 0
	})

	expectedOffset := uint64(0)
	providerVersion := ""

	extents := make([]RepairExtent, 0, len(targets))
	for index, target := range targets {
		if target.Offset != expectedOffset || target.Length > ^uint64(0)-expectedOffset {
			return RepairObject{}, fmt.Errorf(
				"%w: target object %q ranges are not gapless",
				ErrInvalidRepair,
				identity.storageKey,
			)
		}

		if index == 0 {
			providerVersion = target.ProviderVersion
		} else if target.ProviderVersion != providerVersion {
			return RepairObject{}, fmt.Errorf(
				"%w: target object %q has inconsistent provider versions",
				ErrInvalidRepair,
				identity.storageKey,
			)
		}

		sources := availableRepairSources(target, identity, allRecovery, indexed)
		if len(sources) == 0 {
			return RepairObject{}, fmt.Errorf(
				"%w: extent %s",
				ErrNoRepairSource,
				target.ExtentSHA256,
			)
		}

		extents = append(extents, RepairExtent{
			ExtentSHA256: target.ExtentSHA256,
			Offset:       target.Offset,
			Length:       target.Length,
			Sources:      sources,
		})
		expectedOffset += target.Length
	}

	return RepairObject{
		DriverID:        identity.driverID,
		StorageKey:      identity.storageKey,
		ProviderVersion: providerVersion,
		Length:          expectedOffset,
		Extents:         extents,
	}, nil
}

func availableRepairSources(
	target manifest.Location,
	targetObject repairObjectIdentity,
	allRecovery []manifest.Location,
	indexed map[string]IndexedLocation,
) []manifest.Location {
	sources := make([]manifest.Location, 0)

	for _, candidate := range allRecovery {
		if candidate.ExtentSHA256 != target.ExtentSHA256 ||
			(candidate.DriverID == targetObject.driverID && candidate.StorageKey == targetObject.storageKey) {
			continue
		}

		key := reconciliationLocationKey(
			candidate.ExtentSHA256, candidate.DriverID, candidate.StorageKey,
			candidate.ProviderVersion, candidate.Offset, candidate.Length,
		)
		if indexedLocation, exists := indexed[key]; !exists || indexedLocation.State != indexedStateAvailable {
			continue
		}

		sources = append(sources, candidate)
	}

	return sources
}
