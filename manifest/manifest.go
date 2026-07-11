// Package manifest defines Carrack's immutable, portable archive indexes.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
)

const (
	// SchemaVersion is the only content-manifest version understood here.
	SchemaVersion = "carrack.manifest.v1"
	// RecoverySchemaVersion is Carrack's portable recovery-envelope version.
	RecoverySchemaVersion = "carrack.recovery.v1"

	identifierHexBytes = 32
	sha256HexBytes     = 64
	maximumObjectBytes = 2_048
	maximumDriverBytes = 256
	maximumKeyBytes    = 4_096
)

var (
	// ErrInvalidManifest indicates malformed or inconsistent logical metadata.
	ErrInvalidManifest = errors.New("invalid Carrack manifest")
	// ErrInvalidRecoveryManifest indicates malformed physical recovery metadata.
	ErrInvalidRecoveryManifest = errors.New("invalid Carrack recovery manifest")
	errTrailingJSON            = errors.New("unexpected trailing JSON value")
	errInvalidIdentifier       = errors.New("invalid identifier")
)

// Crypto identifies the immutable key hierarchy used by every pack.
type Crypto struct {
	Suite       string `json:"suite"`
	RootVersion uint32 `json:"root_version"`
	KeyEpoch    uint64 `json:"key_epoch"`
}

// Manifest describes one immutable logical object version without provider
// locations. Its JSON field order is the canonical Carrack V1 encoding.
type Manifest struct {
	SchemaVersion   string         `json:"schema_version"`
	NamespaceID     string         `json:"namespace_id"`
	ObjectID        string         `json:"object_id"`
	Generation      uint64         `json:"generation"`
	PlaintextSize   uint64         `json:"plaintext_size"`
	PlaintextSHA256 string         `json:"plaintext_sha256"`
	Layout          archive.Layout `json:"layout"`
	Crypto          Crypto         `json:"crypto"`
	Packs           []Pack         `json:"packs"`
}

// Pack is one independently keyed ciphertext stream in plaintext order.
type Pack struct {
	Ordinal          uint64   `json:"ordinal"`
	PackID           string   `json:"pack_id"`
	PlaintextOffset  uint64   `json:"plaintext_offset"`
	PlaintextSize    uint64   `json:"plaintext_size"`
	CiphertextSize   uint64   `json:"ciphertext_size"`
	CiphertextSHA256 string   `json:"ciphertext_sha256"`
	Extents          []Extent `json:"extents"`
}

// Extent is one independently transferable group of complete crypto frames.
type Extent struct {
	Ordinal          uint64 `json:"ordinal"`
	FirstFrame       uint64 `json:"first_frame"`
	FrameCount       uint64 `json:"frame_count"`
	CiphertextOffset uint64 `json:"ciphertext_offset"`
	CiphertextSize   uint64 `json:"ciphertext_size"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
}

// RecoveryManifest combines a logical manifest with enough non-secret
// physical metadata to rebuild D1 after a control-plane loss.
type RecoveryManifest struct {
	SchemaVersion  string     `json:"schema_version"`
	ManifestSHA256 string     `json:"manifest_sha256"`
	Manifest       Manifest   `json:"manifest"`
	Locations      []Location `json:"locations"`
}

// Location maps one exact ciphertext extent to a provider object range.
type Location struct {
	ExtentSHA256    string `json:"extent_sha256"`
	DriverID        string `json:"driver_id"`
	StorageKey      string `json:"storage_key"`
	ProviderVersion string `json:"provider_version,omitempty"`
	Offset          uint64 `json:"offset"`
	Length          uint64 `json:"length"`
}

// NewRecoveryManifest constructs and validates a portable recovery envelope.
func NewRecoveryManifest(content Manifest, locations []Location) (RecoveryManifest, error) {
	digest, err := content.Digest()
	if err != nil {
		return RecoveryManifest{}, err
	}

	copiedLocations := make([]Location, len(locations))
	copy(copiedLocations, locations)

	recovery := RecoveryManifest{
		SchemaVersion:  RecoverySchemaVersion,
		ManifestSHA256: digest,
		Manifest:       content,
		Locations:      copiedLocations,
	}
	if err := recovery.Validate(); err != nil {
		return RecoveryManifest{}, err
	}

	return recovery, nil
}

// Validate checks the logical manifest's canonical ordering and complete
// plaintext, frame, and ciphertext coverage.
func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != SchemaVersion {
		return invalidManifest("unsupported schema version %q", manifest.SchemaVersion)
	}

	if !validIdentifier(manifest.NamespaceID) {
		return invalidManifest("namespace ID must be 32 lowercase hexadecimal characters")
	}

	if !validBoundedString(manifest.ObjectID, maximumObjectBytes) {
		return invalidManifest("object ID must contain between 1 and %d bytes", maximumObjectBytes)
	}

	if manifest.Generation == 0 {
		return invalidManifest("generation must be positive")
	}

	if !validSHA256(manifest.PlaintextSHA256) {
		return invalidManifest("plaintext SHA-256 must be 64 lowercase hexadecimal characters")
	}

	if err := manifest.Layout.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}

	if manifest.Crypto.Suite != cryptostream.SuiteAES128GCMHKDFSHA256V1 {
		return invalidManifest("unsupported crypto suite %q", manifest.Crypto.Suite)
	}

	if manifest.Crypto.RootVersion == 0 || manifest.Crypto.KeyEpoch == 0 {
		return invalidManifest("root version and key epoch must be positive")
	}

	if manifest.Packs == nil {
		return invalidManifest("packs must be an array, not null")
	}

	expectedPlaintextOffset := uint64(0)
	packIDs := make(map[string]struct{}, len(manifest.Packs))

	for index, pack := range manifest.Packs {
		if err := manifest.validatePack(pack, uint64(index), expectedPlaintextOffset); err != nil {
			return err
		}

		if _, duplicate := packIDs[pack.PackID]; duplicate {
			return invalidManifest("pack %d repeats pack ID %q", pack.Ordinal, pack.PackID)
		}

		packIDs[pack.PackID] = struct{}{}
		expectedPlaintextOffset += pack.PlaintextSize
	}

	if expectedPlaintextOffset != manifest.PlaintextSize {
		return invalidManifest(
			"packs cover %d plaintext bytes, expected %d",
			expectedPlaintextOffset,
			manifest.PlaintextSize,
		)
	}

	if manifest.PlaintextSize == 0 && len(manifest.Packs) != 0 {
		return invalidManifest("empty plaintext must not contain packs")
	}

	return nil
}

func validateExtents(pack Pack, descriptor cryptostream.Descriptor) error {
	if len(pack.Extents) == 0 {
		return invalidManifest("pack %d must contain at least one extent", pack.Ordinal)
	}

	expectedFirstFrame := uint64(0)
	expectedCiphertextOffset := uint64(0)

	for index, extent := range pack.Extents {
		if extent.Ordinal != uint64(index) {
			return invalidManifest("pack %d extent ordinal %d must be %d", pack.Ordinal, extent.Ordinal, index)
		}

		if extent.FirstFrame != expectedFirstFrame {
			return invalidManifest(
				"pack %d extent %d first frame must be %d",
				pack.Ordinal,
				extent.Ordinal,
				expectedFirstFrame,
			)
		}

		offset, length, err := descriptor.CiphertextSpan(extent.FirstFrame, extent.FrameCount)
		if err != nil {
			return fmt.Errorf("%w: pack %d extent %d: %w", ErrInvalidManifest, pack.Ordinal, extent.Ordinal, err)
		}

		if extent.CiphertextOffset != expectedCiphertextOffset || extent.CiphertextOffset != offset {
			return invalidManifest(
				"pack %d extent %d ciphertext offset must be %d",
				pack.Ordinal,
				extent.Ordinal,
				expectedCiphertextOffset,
			)
		}

		if extent.CiphertextSize != length {
			return invalidManifest(
				"pack %d extent %d ciphertext size is %d, expected %d",
				pack.Ordinal,
				extent.Ordinal,
				extent.CiphertextSize,
				length,
			)
		}

		if !validSHA256(extent.CiphertextSHA256) {
			return invalidManifest(
				"pack %d extent %d has a non-canonical ciphertext SHA-256",
				pack.Ordinal,
				extent.Ordinal,
			)
		}

		expectedFirstFrame += extent.FrameCount
		expectedCiphertextOffset += extent.CiphertextSize
	}

	if expectedFirstFrame != descriptor.FrameCount() || expectedCiphertextOffset != pack.CiphertextSize {
		return invalidManifest("pack %d extents do not cover the complete ciphertext", pack.Ordinal)
	}

	return nil
}

// Validate checks the embedded content digest, all referenced extents, and
// complete physical location coverage.
func (recovery RecoveryManifest) Validate() error {
	if recovery.SchemaVersion != RecoverySchemaVersion {
		return invalidRecovery("unsupported schema version %q", recovery.SchemaVersion)
	}

	if err := recovery.Manifest.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRecoveryManifest, err)
	}

	digest, err := recovery.Manifest.Digest()
	if err != nil {
		return fmt.Errorf("%w: calculate content digest: %w", ErrInvalidRecoveryManifest, err)
	}

	if recovery.ManifestSHA256 != digest {
		return invalidRecovery("manifest SHA-256 does not match canonical content")
	}

	if recovery.Locations == nil {
		return invalidRecovery("locations must be an array, not null")
	}

	extentSizes, err := indexExtentSizes(recovery.Manifest)
	if err != nil {
		return err
	}

	return validateRecoveryLocations(recovery.Locations, extentSizes)
}

// MarshalCanonical returns the stable Carrack V1 JSON representation.
func (manifest Manifest) MarshalCanonical() ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal Carrack manifest: %w", err)
	}

	return encoded, nil
}

// Digest returns the lowercase SHA-256 of the canonical manifest bytes.
func (manifest Manifest) Digest() (string, error) {
	encoded, err := manifest.MarshalCanonical()
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(encoded)

	return hex.EncodeToString(digest[:]), nil
}

func (manifest Manifest) validatePack(pack Pack, expectedOrdinal, expectedOffset uint64) error {
	if pack.Ordinal != expectedOrdinal {
		return invalidManifest("pack ordinal %d must be %d", pack.Ordinal, expectedOrdinal)
	}

	if !validIdentifier(pack.PackID) {
		return invalidManifest("pack %d has a non-canonical pack ID", pack.Ordinal)
	}

	if pack.PlaintextOffset != expectedOffset {
		return invalidManifest("pack %d plaintext offset must be %d", pack.Ordinal, expectedOffset)
	}

	if pack.PlaintextSize == 0 || pack.PlaintextSize > manifest.Layout.LogicalPackBytes {
		return invalidManifest("pack %d plaintext size is out of range", pack.Ordinal)
	}

	if !validSHA256(pack.CiphertextSHA256) {
		return invalidManifest("pack %d has a non-canonical ciphertext SHA-256", pack.Ordinal)
	}

	descriptor, err := manifest.packDescriptor(pack)
	if err != nil {
		return err
	}

	expectedCiphertextSize, err := descriptor.CiphertextBytes()
	if err != nil {
		return fmt.Errorf("%w: pack %d descriptor: %w", ErrInvalidManifest, pack.Ordinal, err)
	}

	if pack.CiphertextSize != expectedCiphertextSize {
		return invalidManifest(
			"pack %d ciphertext size is %d, expected %d",
			pack.Ordinal,
			pack.CiphertextSize,
			expectedCiphertextSize,
		)
	}

	return validateExtents(pack, descriptor)
}

func (manifest Manifest) packDescriptor(pack Pack) (cryptostream.Descriptor, error) {
	namespaceID, err := decodeIdentifier(manifest.NamespaceID)
	if err != nil {
		return cryptostream.Descriptor{}, invalidManifest("decode namespace ID: %v", err)
	}

	packID, err := decodeIdentifier(pack.PackID)
	if err != nil {
		return cryptostream.Descriptor{}, invalidManifest("decode pack %d ID: %v", pack.Ordinal, err)
	}

	return cryptostream.Descriptor{
		Suite:          manifest.Crypto.Suite,
		RootVersion:    manifest.Crypto.RootVersion,
		NamespaceID:    namespaceID,
		EpochID:        manifest.Crypto.KeyEpoch,
		PackID:         packID,
		FrameBytes:     manifest.Layout.CryptoFrameBytes,
		PlaintextBytes: pack.PlaintextSize,
	}, nil
}

// MarshalCanonical returns the stable Carrack V1 recovery representation.
func (recovery RecoveryManifest) MarshalCanonical() ([]byte, error) {
	if err := recovery.Validate(); err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(recovery)
	if err != nil {
		return nil, fmt.Errorf("marshal Carrack recovery manifest: %w", err)
	}

	return encoded, nil
}

// Parse rejects unknown fields, trailing values, and invalid content.
func Parse(encoded []byte) (Manifest, error) {
	var result Manifest
	if err := decodeStrict(encoded, &result); err != nil {
		return Manifest{}, fmt.Errorf("%w: decode: %w", ErrInvalidManifest, err)
	}

	if err := result.Validate(); err != nil {
		return Manifest{}, err
	}

	return result, nil
}

// ParseRecovery rejects unknown fields, trailing values, and invalid content.
func ParseRecovery(encoded []byte) (RecoveryManifest, error) {
	var result RecoveryManifest
	if err := decodeStrict(encoded, &result); err != nil {
		return RecoveryManifest{}, fmt.Errorf("%w: decode: %w", ErrInvalidRecoveryManifest, err)
	}

	if err := result.Validate(); err != nil {
		return RecoveryManifest{}, err
	}

	return result, nil
}

func decodeStrict(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errTrailingJSON
		}

		return fmt.Errorf("decode trailing JSON: %w", err)
	}

	return nil
}

func indexExtentSizes(content Manifest) (map[string]uint64, error) {
	extentSizes := make(map[string]uint64)

	for _, pack := range content.Packs {
		for _, extent := range pack.Extents {
			if size, exists := extentSizes[extent.CiphertextSHA256]; exists && size != extent.CiphertextSize {
				return nil, invalidRecovery("equal extent hashes have conflicting lengths")
			}

			extentSizes[extent.CiphertextSHA256] = extent.CiphertextSize
		}
	}

	return extentSizes, nil
}

func validateRecoveryLocations(locations []Location, extentSizes map[string]uint64) error {
	coverage := make(map[string]uint64, len(extentSizes))
	uniqueLocations := make(map[string]struct{}, len(locations))

	for index, location := range locations {
		if err := validateRecoveryLocation(location, index, extentSizes); err != nil {
			return err
		}

		identity := locationIdentity(location)
		if _, duplicate := uniqueLocations[identity]; duplicate {
			return invalidRecovery("location %d is duplicated", index)
		}

		uniqueLocations[identity] = struct{}{}
		coverage[location.ExtentSHA256]++
	}

	for extentDigest := range extentSizes {
		if coverage[extentDigest] == 0 {
			return invalidRecovery("extent %s has no recovery location", extentDigest)
		}
	}

	return nil
}

func validateRecoveryLocation(location Location, index int, extentSizes map[string]uint64) error {
	expectedLength, exists := extentSizes[location.ExtentSHA256]
	if !exists {
		return invalidRecovery("location %d references an unknown extent", index)
	}

	if !validBoundedString(location.DriverID, maximumDriverBytes) {
		return invalidRecovery("location %d has an invalid driver ID", index)
	}

	if !validBoundedString(location.StorageKey, maximumKeyBytes) {
		return invalidRecovery("location %d has an invalid storage key", index)
	}

	if location.Length != expectedLength || location.Offset > ^uint64(0)-location.Length {
		return invalidRecovery("location %d has an invalid byte range", index)
	}

	return nil
}

func locationIdentity(location Location) string {
	return fmt.Sprintf(
		"%s\x00%s\x00%s\x00%d\x00%d",
		location.ExtentSHA256,
		location.DriverID,
		location.StorageKey,
		location.Offset,
		location.Length,
	)
}

func decodeIdentifier(value string) (cryptostream.Identifier, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(cryptostream.Identifier{}) {
		return cryptostream.Identifier{}, errInvalidIdentifier
	}

	var identifier cryptostream.Identifier
	copy(identifier[:], decoded)

	return identifier, nil
}

func validIdentifier(value string) bool {
	return len(value) == identifierHexBytes && canonicalHex(value)
}

func validSHA256(value string) bool {
	return len(value) == sha256HexBytes && canonicalHex(value)
}

func canonicalHex(value string) bool {
	if value != strings.ToLower(value) {
		return false
	}

	_, err := hex.DecodeString(value)

	return err == nil
}

func validBoundedString(value string, maximumBytes int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximumBytes
}

func invalidManifest(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidManifest, fmt.Sprintf(format, arguments...))
}

func invalidRecovery(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecoveryManifest, fmt.Sprintf(format, arguments...))
}
