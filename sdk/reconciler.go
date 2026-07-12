package sdk

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/dravengarden/carrack/manifest"
)

// ErrInvalidReconciliation indicates an unsafe or inconsistent index snapshot.
var ErrInvalidReconciliation = errors.New("invalid Carrack reconciliation input")

const (
	indexedStateAvailable = "available"
	indexedStateMissing   = string(VerificationMissing)
	indexedStateCorrupt   = string(VerificationCorrupt)
)

// ReconciliationCondition identifies one metadata-only discrepancy.
type ReconciliationCondition string

const (
	// ReconciliationUnindexed means portable recovery references a location absent from D1.
	ReconciliationUnindexed ReconciliationCondition = "unindexed"
	// ReconciliationOrphan means D1 exposes an available location absent from pinned recovery.
	ReconciliationOrphan ReconciliationCondition = "orphan"
	// ReconciliationDegraded means exact available replicas fall below pinned policy.
	ReconciliationDegraded ReconciliationCondition = "degraded"
)

// IndexedLocation is one exact D1 location from a pinned recovery revision.
type IndexedLocation struct {
	ID              string `json:"id"                         yaml:"id"`
	ExtentSHA256    string `json:"extent_sha256"              yaml:"extent_sha256"`
	DriverID        string `json:"driver_id"                  yaml:"driver_id"`
	StorageKey      string `json:"storage_key"                yaml:"storage_key"`
	ProviderVersion string `json:"provider_version,omitempty" yaml:"provider_version,omitempty"`
	Offset          uint64 `json:"offset"                     yaml:"offset"`
	Length          uint64 `json:"length"                     yaml:"length"`
	State           string `json:"state"                      yaml:"state"`
}

// ReconciliationEvidence describes one non-destructive metadata discrepancy.
type ReconciliationEvidence struct {
	Condition    ReconciliationCondition `json:"condition"             yaml:"condition"`
	SubjectID    string                  `json:"subject_id"            yaml:"subject_id"`
	ExtentSHA256 string                  `json:"extent_sha256"         yaml:"extent_sha256"`
	DriverID     string                  `json:"driver_id,omitempty"   yaml:"driver_id,omitempty"`
	StorageKey   string                  `json:"storage_key,omitempty" yaml:"storage_key,omitempty"`
	Offset       uint64                  `json:"offset,omitempty"      yaml:"offset,omitempty"`
	Length       uint64                  `json:"length,omitempty"      yaml:"length,omitempty"`
	Available    uint64                  `json:"available,omitempty"   yaml:"available,omitempty"`
	Required     uint64                  `json:"required,omitempty"    yaml:"required,omitempty"`
}

// ReconciliationResult is a deterministic comparison of recovery and D1 metadata.
type ReconciliationResult struct {
	ManifestSHA256 string                   `json:"manifest_sha256" yaml:"manifest_sha256"`
	RecoveryOnly   uint64                   `json:"recovery_only"   yaml:"recovery_only"`
	IndexOnly      uint64                   `json:"index_only"      yaml:"index_only"`
	Degraded       uint64                   `json:"degraded"        yaml:"degraded"`
	Evidence       []ReconciliationEvidence `json:"evidence"        yaml:"evidence"`
}

// Reconciler compares portable recovery against one fenced D1 location snapshot.
type Reconciler struct{}

// Reconcile performs no provider I/O and never mutates either input.
func (Reconciler) Reconcile(
	recovery manifest.RecoveryManifest,
	indexed []IndexedLocation,
	minimumAvailableReplicas uint64,
) (ReconciliationResult, error) {
	if err := recovery.Validate(); err != nil {
		return ReconciliationResult{}, fmt.Errorf("%w: recovery manifest: %w", ErrInvalidReconciliation, err)
	}

	if minimumAvailableReplicas == 0 || minimumAvailableReplicas > 64 {
		return ReconciliationResult{}, fmt.Errorf("%w: replica policy is out of range", ErrInvalidReconciliation)
	}

	recoveryLocations := make(map[string]manifest.Location, len(recovery.Locations))
	for _, location := range recovery.Locations {
		recoveryLocations[reconciliationLocationKey(
			location.ExtentSHA256,
			location.DriverID,
			location.StorageKey,
			location.ProviderVersion,
			location.Offset,
			location.Length,
		)] = location
	}

	indexedLocations := make(map[string]IndexedLocation, len(indexed))
	for _, location := range indexed {
		if err := validateIndexedLocation(location); err != nil {
			return ReconciliationResult{}, err
		}

		key := reconciliationLocationKey(
			location.ExtentSHA256,
			location.DriverID,
			location.StorageKey,
			location.ProviderVersion,
			location.Offset,
			location.Length,
		)
		if _, duplicate := indexedLocations[key]; duplicate {
			return ReconciliationResult{}, fmt.Errorf("%w: duplicate indexed location", ErrInvalidReconciliation)
		}

		indexedLocations[key] = location
	}

	result := ReconciliationResult{
		ManifestSHA256: recovery.ManifestSHA256,
		Evidence:       make([]ReconciliationEvidence, 0),
	}
	availableByExtent := make(map[string]uint64)

	for key, location := range recoveryLocations {
		indexedLocation, exists := indexedLocations[key]
		if !exists {
			result.RecoveryOnly++
			result.Evidence = append(result.Evidence, recoveryOnlyEvidence(location))

			continue
		}

		if indexedLocation.State == indexedStateAvailable {
			availableByExtent[location.ExtentSHA256]++
		}
	}

	for key, location := range indexedLocations {
		if _, exists := recoveryLocations[key]; exists || location.State != indexedStateAvailable {
			continue
		}

		result.IndexOnly++
		result.Evidence = append(result.Evidence, ReconciliationEvidence{
			Condition: ReconciliationOrphan, SubjectID: location.ID,
			ExtentSHA256: location.ExtentSHA256, DriverID: location.DriverID,
			StorageKey: location.StorageKey, Offset: location.Offset, Length: location.Length,
		})
	}

	for _, pack := range recovery.Manifest.Packs {
		for _, extent := range pack.Extents {
			available := availableByExtent[extent.CiphertextSHA256]
			if available >= minimumAvailableReplicas {
				continue
			}

			result.Degraded++
			result.Evidence = append(result.Evidence, ReconciliationEvidence{
				Condition: ReconciliationDegraded, SubjectID: extent.CiphertextSHA256,
				ExtentSHA256: extent.CiphertextSHA256, Available: available,
				Required: minimumAvailableReplicas,
			})
		}
	}

	sortReconciliationEvidence(result.Evidence)

	return result, nil
}

func sortReconciliationEvidence(evidence []ReconciliationEvidence) {
	slices.SortFunc(evidence, func(left, right ReconciliationEvidence) int {
		if conditionOrder := cmp.Compare(left.Condition, right.Condition); conditionOrder != 0 {
			return conditionOrder
		}

		return cmp.Compare(left.SubjectID, right.SubjectID)
	})
}

func validateIndexedLocation(location IndexedLocation) error {
	if !validControlString(location.ID, 2_048) || !validControlHex(location.ExtentSHA256, 64) ||
		!validControlString(location.DriverID, 256) ||
		!validControlString(location.StorageKey, 4_096) || location.Length == 0 ||
		location.Offset > ^uint64(0)-location.Length || !validIndexedLocationState(location.State) {
		return fmt.Errorf("%w: malformed indexed location", ErrInvalidReconciliation)
	}

	return nil
}

func validIndexedLocationState(state string) bool {
	switch state {
	case "staging", "verified", indexedStateAvailable, indexedStateMissing, indexedStateCorrupt,
		"quarantined", operationStateTombstoned, operationStateDeleted:
		return true
	default:
		return false
	}
}

func recoveryOnlyEvidence(location manifest.Location) ReconciliationEvidence {
	return ReconciliationEvidence{
		Condition: ReconciliationUnindexed,
		SubjectID: reconciliationLocationKey(
			location.ExtentSHA256,
			location.DriverID,
			location.StorageKey,
			location.ProviderVersion,
			location.Offset,
			location.Length,
		),
		ExtentSHA256: location.ExtentSHA256, DriverID: location.DriverID,
		StorageKey: location.StorageKey, Offset: location.Offset, Length: location.Length,
	}
}

func reconciliationLocationKey(
	extentSHA256,
	driverID,
	storageKey,
	providerVersion string,
	offset,
	length uint64,
) string {
	encoded, err := json.Marshal([6]any{
		extentSHA256, driverID, storageKey, providerVersion, offset, length,
	})
	if err != nil {
		panic("serializing a reconciliation location identity cannot fail")
	}

	return string(encoded)
}
