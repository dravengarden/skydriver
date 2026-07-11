package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
)

var (
	// ErrImportSourceChanged indicates that a persisted plan no longer matches
	// the provider object it pinned.
	ErrImportSourceChanged = errors.New("carrack import source changed after planning")
	// ErrImportIntegrity indicates that uploaded bytes failed independent readback.
	ErrImportIntegrity = errors.New("carrack import destination integrity check failed")
)

// ImportResult contains publication-ready logical and portable manifests.
type ImportResult struct {
	Manifest            manifest.Manifest
	Recovery            manifest.RecoveryManifest
	DestinationDriverID string
	RecoveryKey         string
	RecoveryObject      provider.Object
}

// Execute encrypts, uploads, and independently verifies every planned extent,
// then writes and verifies the destination recovery sidecar. It does not
// publish D1 metadata.
func (importer *Importer) Execute(
	ctx context.Context,
	plan ImportPlan,
	epochKey cryptostream.EpochKey,
	stagingDirectory string,
) (ImportResult, error) {
	if importer == nil || importer.source == nil || importer.destination == nil {
		return ImportResult{}, fmt.Errorf("%w: importer is not initialized", ErrInvalidConfiguration)
	}

	if err := plan.Validate(); err != nil {
		return ImportResult{}, err
	}

	if plan.Layout != importer.layout {
		return ImportResult{}, fmt.Errorf("%w: plan layout differs from importer layout", ErrInvalidImportPlan)
	}

	if err := validateStagingDirectory(stagingDirectory); err != nil {
		return ImportResult{}, err
	}

	if err := importer.verifySourceIdentity(ctx, plan); err != nil {
		return ImportResult{}, err
	}

	namespaceID, err := parseCryptoIdentifier(plan.NamespaceID)
	if err != nil {
		return ImportResult{}, err
	}

	content := manifest.Manifest{
		SchemaVersion:   manifest.SchemaVersion,
		NamespaceID:     plan.NamespaceID,
		ObjectID:        plan.ObjectID,
		Generation:      plan.Generation,
		PlaintextSize:   plan.Source.SizeBytes,
		PlaintextSHA256: "",
		Layout:          plan.Layout,
		Crypto: manifest.Crypto{
			Suite:       cryptostream.SuiteAES128GCMHKDFSHA256V1,
			RootVersion: plan.RootVersion,
			KeyEpoch:    plan.KeyEpoch,
		},
		Packs: make([]manifest.Pack, 0, len(plan.Packs)),
	}
	locations := make([]manifest.Location, 0)
	plaintextHash := sha256.New()

	for _, plannedPack := range plan.Packs {
		pack, packLocations, packErr := importer.executePack(
			ctx,
			plan,
			plannedPack,
			namespaceID,
			epochKey,
			stagingDirectory,
			plaintextHash,
		)
		if packErr != nil {
			return ImportResult{}, packErr
		}

		content.Packs = append(content.Packs, pack)
		locations = append(locations, packLocations...)
	}

	content.PlaintextSHA256 = hex.EncodeToString(plaintextHash.Sum(nil))

	if identityErr := importer.verifySourceIdentity(ctx, plan); identityErr != nil {
		return ImportResult{}, identityErr
	}

	recovery, err := manifest.NewRecoveryManifest(content, locations)
	if err != nil {
		return ImportResult{}, fmt.Errorf("construct import recovery manifest: %w", err)
	}

	recoveryKey, recoveryObject, err := importer.uploadRecoverySidecar(ctx, plan, recovery)
	if err != nil {
		return ImportResult{}, err
	}

	return ImportResult{
		Manifest:            content,
		Recovery:            recovery,
		DestinationDriverID: plan.DestinationDriverID,
		RecoveryKey:         recoveryKey,
		RecoveryObject:      recoveryObject,
	}, nil
}

func (importer *Importer) executePack(
	ctx context.Context,
	plan ImportPlan,
	planned PlannedPack,
	namespaceID cryptostream.Identifier,
	epochKey cryptostream.EpochKey,
	stagingDirectory string,
	plaintextHash hash.Hash,
) (manifest.Pack, []manifest.Location, error) {
	packID, err := parseCryptoIdentifier(planned.PackID)
	if err != nil {
		return manifest.Pack{}, nil, err
	}

	descriptor := cryptostream.Descriptor{
		Suite:          cryptostream.SuiteAES128GCMHKDFSHA256V1,
		RootVersion:    plan.RootVersion,
		NamespaceID:    namespaceID,
		EpochID:        plan.KeyEpoch,
		PackID:         packID,
		FrameBytes:     plan.Layout.CryptoFrameBytes,
		PlaintextBytes: planned.PlaintextSize,
	}

	packKey, err := cryptostream.DerivePackKey(epochKey, packID)
	if err != nil {
		return manifest.Pack{}, nil, fmt.Errorf("derive import pack %d key: %w", planned.Ordinal, err)
	}

	packCipher, err := cryptostream.NewCipher(packKey, descriptor)
	if err != nil {
		return manifest.Pack{}, nil, fmt.Errorf("construct import pack %d cipher: %w", planned.Ordinal, err)
	}

	spans, err := plan.Layout.PlanExtents(planned.PlaintextSize)
	if err != nil {
		return manifest.Pack{}, nil, fmt.Errorf("plan import pack %d extents: %w", planned.Ordinal, err)
	}

	ciphertextBytes, err := descriptor.CiphertextBytes()
	if err != nil {
		return manifest.Pack{}, nil, fmt.Errorf("calculate import pack %d size: %w", planned.Ordinal, err)
	}

	pack := manifest.Pack{
		Ordinal:          planned.Ordinal,
		PackID:           planned.PackID,
		PlaintextOffset:  planned.PlaintextOffset,
		PlaintextSize:    planned.PlaintextSize,
		CiphertextSize:   ciphertextBytes,
		CiphertextSHA256: "",
		Extents:          make([]manifest.Extent, 0, len(spans)),
	}
	locations := make([]manifest.Location, 0, len(spans))
	packHash := sha256.New()

	groups, err := planProviderObjectGroups(
		packCipher,
		spans,
		importer.providerObjectBytes,
		importer.maximumObjectBytes,
	)
	if err != nil {
		return manifest.Pack{}, nil, fmt.Errorf("plan import pack %d provider objects: %w", planned.Ordinal, err)
	}

	for _, group := range groups {
		extents, groupLocations, groupErr := importer.executeProviderObject(
			ctx,
			plan,
			planned,
			group,
			packCipher,
			stagingDirectory,
			plaintextHash,
			packHash,
		)
		if groupErr != nil {
			return manifest.Pack{}, nil, groupErr
		}

		pack.Extents = append(pack.Extents, extents...)
		locations = append(locations, groupLocations...)
	}

	pack.CiphertextSHA256 = hex.EncodeToString(packHash.Sum(nil))

	return pack, locations, nil
}

type plannedCiphertextExtent struct {
	span             archive.ExtentSpan
	ciphertextOffset uint64
	ciphertextBytes  uint64
}

type providerObjectGroup struct {
	ciphertextBytes uint64
	extents         []plannedCiphertextExtent
}

func planProviderObjectGroups(
	packCipher *cryptostream.Cipher,
	spans []archive.ExtentSpan,
	targetBytes,
	maximumBytes uint64,
) ([]providerObjectGroup, error) {
	groups := make([]providerObjectGroup, 0)
	current := providerObjectGroup{extents: make([]plannedCiphertextExtent, 0)}

	for _, span := range spans {
		ciphertextOffset, ciphertextBytes, err := packCipher.Descriptor().CiphertextSpan(
			span.FirstFrame,
			span.FrameCount,
		)
		if err != nil {
			return nil, fmt.Errorf("calculate extent %d ciphertext span: %w", span.Ordinal, err)
		}

		if maximumBytes > 0 && ciphertextBytes > maximumBytes {
			return nil, fmt.Errorf(
				"%w: extent %d has %d ciphertext bytes, driver maximum is %d",
				ErrInvalidConfiguration,
				span.Ordinal,
				ciphertextBytes,
				maximumBytes,
			)
		}

		if len(current.extents) > 0 &&
			(current.ciphertextBytes >= targetBytes || ciphertextBytes > targetBytes-current.ciphertextBytes) {
			groups = append(groups, current)
			current = providerObjectGroup{extents: make([]plannedCiphertextExtent, 0)}
		}

		if ciphertextBytes > math.MaxUint64-current.ciphertextBytes {
			return nil, fmt.Errorf("%w: provider-object group size overflows", ErrInvalidConfiguration)
		}

		current.extents = append(current.extents, plannedCiphertextExtent{
			span:             span,
			ciphertextOffset: ciphertextOffset,
			ciphertextBytes:  ciphertextBytes,
		})
		current.ciphertextBytes += ciphertextBytes
	}

	if len(current.extents) > 0 {
		groups = append(groups, current)
	}

	return groups, nil
}

func (importer *Importer) executeProviderObject(
	ctx context.Context,
	plan ImportPlan,
	plannedPack PlannedPack,
	group providerObjectGroup,
	packCipher *cryptostream.Cipher,
	stagingDirectory string,
	plaintextHash,
	packHash hash.Hash,
) (_ []manifest.Extent, _ []manifest.Location, returnErr error) {
	temporary, err := os.CreateTemp(stagingDirectory, ".carrack-provider-object-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create import provider-object staging file: %w", err)
	}

	temporaryPath := temporary.Name()

	defer func() {
		closeErr := temporary.Close()
		removeErr := os.Remove(temporaryPath)

		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}

		returnErr = errors.Join(returnErr, closeErr, removeErr)
	}()

	extents := make([]manifest.Extent, 0, len(group.extents))
	locations := make([]manifest.Location, 0, len(group.extents))
	objectHash := sha256.New()
	objectOffset := uint64(0)

	for _, plannedExtent := range group.extents {
		transformed, transformErr := importer.encryptExtent(
			ctx,
			plan,
			plannedPack,
			plannedExtent.span,
			packCipher,
			io.MultiWriter(temporary, objectHash),
			plaintextHash,
			packHash,
		)
		if transformErr != nil {
			return nil, nil, transformErr
		}

		if transformed.PlaintextBytes != plannedExtent.span.PlaintextSize ||
			transformed.CiphertextBytes != plannedExtent.ciphertextBytes {
			return nil, nil, fmt.Errorf("%w: extent size changed", ErrImportIntegrity)
		}

		ciphertextDigest := hex.EncodeToString(transformed.CiphertextSHA256[:])
		extents = append(extents, manifest.Extent{
			Ordinal:          plannedExtent.span.Ordinal,
			FirstFrame:       plannedExtent.span.FirstFrame,
			FrameCount:       plannedExtent.span.FrameCount,
			CiphertextOffset: plannedExtent.ciphertextOffset,
			CiphertextSize:   plannedExtent.ciphertextBytes,
			CiphertextSHA256: ciphertextDigest,
		})
		locations = append(locations, manifest.Location{
			ExtentSHA256: ciphertextDigest,
			DriverID:     plan.DestinationDriverID,
			Offset:       objectOffset,
			Length:       plannedExtent.ciphertextBytes,
		})
		objectOffset += plannedExtent.ciphertextBytes
	}

	if objectOffset != group.ciphertextBytes {
		return nil, nil, fmt.Errorf("%w: provider-object group size changed", ErrImportIntegrity)
	}

	if _, seekErr := temporary.Seek(0, io.SeekStart); seekErr != nil {
		return nil, nil, fmt.Errorf("rewind import provider object: %w", seekErr)
	}

	objectDigest := hex.EncodeToString(objectHash.Sum(nil))
	storageKey := providerObjectStorageKey(plan.DestinationPrefix, objectDigest)

	uploaded, err := importer.destination.Put(ctx, storageKey, temporary, provider.PutOptions{
		SizeBytes: group.ciphertextBytes,
		SHA256:    objectDigest,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("upload import provider object %q: %w", storageKey, err)
	}

	if uploaded.SizeBytes != group.ciphertextBytes {
		return nil, nil, fmt.Errorf(
			"%w: uploaded provider object has %d bytes, expected %d",
			ErrImportIntegrity,
			uploaded.SizeBytes,
			group.ciphertextBytes,
		)
	}

	if verifyErr := verifyProviderObject(
		ctx,
		importer.destination,
		storageKey,
		group.ciphertextBytes,
		objectHash.Sum(nil),
		ErrImportIntegrity,
	); verifyErr != nil {
		return nil, nil, verifyErr
	}

	for index := range locations {
		locations[index].StorageKey = storageKey
		locations[index].ProviderVersion = uploaded.Version
	}

	return extents, locations, nil
}

func (importer *Importer) encryptExtent(
	ctx context.Context,
	plan ImportPlan,
	plannedPack PlannedPack,
	span archive.ExtentSpan,
	packCipher *cryptostream.Cipher,
	destination io.Writer,
	plaintextHash,
	packHash hash.Hash,
) (cryptostream.TransformResult, error) {
	sourceOffset := plannedPack.PlaintextOffset + span.PlaintextOffset

	source, err := importer.source.OpenRange(ctx, plan.Source.Key, sourceOffset, span.PlaintextSize)
	if err != nil {
		return cryptostream.TransformResult{}, fmt.Errorf(
			"open import source range at %d: %w",
			sourceOffset,
			err,
		)
	}

	plaintext := io.TeeReader(source, plaintextHash)
	ciphertext := io.MultiWriter(destination, packHash)
	transformed, transformErr := packCipher.SealFrames(
		ctx,
		ciphertext,
		plaintext,
		span.FirstFrame,
		span.FrameCount,
	)

	closeSourceErr := source.Close()
	if transformErr != nil || closeSourceErr != nil {
		return cryptostream.TransformResult{}, fmt.Errorf(
			"encrypt import pack %d extent %d: %w",
			plannedPack.Ordinal,
			span.Ordinal,
			errors.Join(transformErr, closeSourceErr),
		)
	}

	return transformed, nil
}

func (importer *Importer) uploadRecoverySidecar(
	ctx context.Context,
	plan ImportPlan,
	recovery manifest.RecoveryManifest,
) (string, provider.Object, error) {
	return writeRecoverySidecar(
		ctx,
		importer.destination,
		plan.DestinationPrefix,
		recovery,
		importer.maximumObjectBytes,
		ErrInvalidConfiguration,
		ErrImportIntegrity,
	)
}

func (importer *Importer) verifySourceIdentity(ctx context.Context, plan ImportPlan) error {
	current, err := importer.source.Stat(ctx, plan.Source.Key)
	if err != nil {
		return fmt.Errorf("restat import source %q: %w", plan.Source.Key, err)
	}

	if current.SizeBytes != plan.Source.SizeBytes ||
		(plan.Source.Version != "" && current.Version != plan.Source.Version) ||
		(plan.Source.ETag != "" && current.ETag != plan.Source.ETag) {
		return fmt.Errorf("%w: source identity no longer matches persisted plan", ErrImportSourceChanged)
	}

	if plan.Source.SizeBytes > plan.Layout.PhysicalBlockBytes &&
		plan.Source.Version == "" && plan.Source.ETag == "" {
		return fmt.Errorf("%w: multi-range source has no immutable version or ETag", ErrImportSourceChanged)
	}

	return nil
}

func validateStagingDirectory(directory string) error {
	information, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat Carrack staging directory: %w", err)
	}

	if !information.IsDir() {
		return fmt.Errorf("%w: staging path must be a directory", ErrInvalidConfiguration)
	}

	return nil
}

func parseCryptoIdentifier(value string) (cryptostream.Identifier, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(cryptostream.Identifier{}) {
		return cryptostream.Identifier{}, fmt.Errorf("%w: invalid crypto identifier", ErrInvalidImportPlan)
	}

	var identifier cryptostream.Identifier
	copy(identifier[:], decoded)

	return identifier, nil
}
