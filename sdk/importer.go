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
	"path"
	"strings"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
)

const verificationBufferBytes = 1 << 20

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

	for _, span := range spans {
		extent, location, err := importer.executeExtent(
			ctx,
			plan,
			planned,
			span,
			packCipher,
			stagingDirectory,
			plaintextHash,
			packHash,
		)
		if err != nil {
			return manifest.Pack{}, nil, err
		}

		pack.Extents = append(pack.Extents, extent)
		locations = append(locations, location)
	}

	pack.CiphertextSHA256 = hex.EncodeToString(packHash.Sum(nil))

	return pack, locations, nil
}

func (importer *Importer) executeExtent(
	ctx context.Context,
	plan ImportPlan,
	plannedPack PlannedPack,
	span archive.ExtentSpan,
	packCipher *cryptostream.Cipher,
	stagingDirectory string,
	plaintextHash,
	packHash hash.Hash,
) (_ manifest.Extent, _ manifest.Location, returnErr error) {
	temporary, err := os.CreateTemp(stagingDirectory, ".carrack-extent-*")
	if err != nil {
		return manifest.Extent{}, manifest.Location{}, fmt.Errorf("create import extent staging file: %w", err)
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

	transformed, err := importer.encryptExtent(
		ctx,
		plan,
		plannedPack,
		span,
		packCipher,
		temporary,
		plaintextHash,
		packHash,
	)
	if err != nil {
		return manifest.Extent{}, manifest.Location{}, err
	}

	if transformed.PlaintextBytes != span.PlaintextSize {
		return manifest.Extent{}, manifest.Location{}, fmt.Errorf(
			"%w: extent plaintext size changed",
			ErrImportIntegrity,
		)
	}

	if _, seekErr := temporary.Seek(0, io.SeekStart); seekErr != nil {
		return manifest.Extent{}, manifest.Location{}, fmt.Errorf("rewind import extent: %w", seekErr)
	}

	ciphertextDigest := hex.EncodeToString(transformed.CiphertextSHA256[:])
	storageKey := extentStorageKey(plan.DestinationPrefix, ciphertextDigest)

	uploaded, err := importer.destination.Put(ctx, storageKey, temporary, provider.PutOptions{
		SizeBytes: transformed.CiphertextBytes,
		SHA256:    ciphertextDigest,
	})
	if err != nil {
		return manifest.Extent{}, manifest.Location{}, fmt.Errorf("upload import extent %q: %w", storageKey, err)
	}

	if uploaded.SizeBytes != transformed.CiphertextBytes {
		return manifest.Extent{}, manifest.Location{}, fmt.Errorf(
			"%w: uploaded extent has %d bytes, expected %d",
			ErrImportIntegrity,
			uploaded.SizeBytes,
			transformed.CiphertextBytes,
		)
	}

	if verifyErr := verifyProviderObject(
		ctx,
		importer.destination,
		storageKey,
		transformed.CiphertextBytes,
		transformed.CiphertextSHA256,
	); verifyErr != nil {
		return manifest.Extent{}, manifest.Location{}, verifyErr
	}

	ciphertextOffset, ciphertextSize, err := packCipher.Descriptor().CiphertextSpan(
		span.FirstFrame,
		span.FrameCount,
	)
	if err != nil {
		return manifest.Extent{}, manifest.Location{}, fmt.Errorf(
			"calculate import extent ciphertext span: %w",
			err,
		)
	}

	return manifest.Extent{
			Ordinal:          span.Ordinal,
			FirstFrame:       span.FirstFrame,
			FrameCount:       span.FrameCount,
			CiphertextOffset: ciphertextOffset,
			CiphertextSize:   ciphertextSize,
			CiphertextSHA256: ciphertextDigest,
		}, manifest.Location{
			ExtentSHA256:    ciphertextDigest,
			DriverID:        plan.DestinationDriverID,
			StorageKey:      storageKey,
			ProviderVersion: uploaded.Version,
			Offset:          0,
			Length:          transformed.CiphertextBytes,
		}, nil
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
	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		return "", provider.Object{}, fmt.Errorf("marshal recovery sidecar: %w", err)
	}

	digest := sha256.Sum256(encoded)

	contentDigest, err := recovery.Manifest.Digest()
	if err != nil {
		return "", provider.Object{}, fmt.Errorf("calculate recovery content digest: %w", err)
	}

	storageKey := path.Join(plan.DestinationPrefix, "manifests", contentDigest+".json")

	uploaded, err := importer.destination.Put(
		ctx,
		storageKey,
		strings.NewReader(string(encoded)),
		provider.PutOptions{SizeBytes: uint64(len(encoded)), SHA256: hex.EncodeToString(digest[:])},
	)
	if err != nil {
		return "", provider.Object{}, fmt.Errorf("upload recovery sidecar %q: %w", storageKey, err)
	}

	if uploaded.SizeBytes != uint64(len(encoded)) {
		return "", provider.Object{}, fmt.Errorf("%w: recovery sidecar size changed", ErrImportIntegrity)
	}

	if err := verifyProviderObject(
		ctx,
		importer.destination,
		storageKey,
		uint64(len(encoded)),
		cryptostream.StreamDigest(digest),
	); err != nil {
		return "", provider.Object{}, err
	}

	return storageKey, uploaded, nil
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

func verifyProviderObject(
	ctx context.Context,
	reader provider.Reader,
	key string,
	expectedBytes uint64,
	expectedDigest cryptostream.StreamDigest,
) error {
	expectedLength, err := safeInt64(expectedBytes)
	if err != nil {
		return fmt.Errorf("verify destination %q: %w", key, err)
	}

	stream, err := reader.OpenRange(ctx, key, 0, expectedBytes)
	if err != nil {
		return fmt.Errorf("verify destination %q: open range: %w", key, err)
	}

	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(
		hasher,
		io.LimitReader(stream, expectedLength+1),
		make([]byte, verificationBufferBytes),
	)

	closeErr := stream.Close()
	if copyErr != nil || closeErr != nil {
		return fmt.Errorf("verify destination %q: read: %w", key, errors.Join(copyErr, closeErr))
	}

	if written != expectedLength {
		return fmt.Errorf(
			"%w: destination %q returned %d bytes, expected %d",
			ErrImportIntegrity,
			key,
			written,
			expectedBytes,
		)
	}

	actual := hasher.Sum(nil)
	if !equalDigest(actual, expectedDigest[:]) {
		return fmt.Errorf("%w: destination %q SHA-256 mismatch", ErrImportIntegrity, key)
	}

	return nil
}

func safeInt64(value uint64) (int64, error) {
	if value >= math.MaxInt64 {
		return 0, fmt.Errorf("%w: object exceeds signed stream range", ErrImportIntegrity)
	}

	return int64(value), nil
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

func extentStorageKey(prefix, digest string) string {
	return path.Join(prefix, "extents", digest[:2], digest)
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}

	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}

	return difference == 0
}
