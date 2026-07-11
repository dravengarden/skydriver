package manifest_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
)

const (
	contentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secondHash  = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	namespaceID = "202122232425262728292a2b2c2d2e2f"
	packID      = "404142434445464748494a4b4c4d4e4f"
)

func TestManifestValidatesPackAndExtentCoverage(t *testing.T) {
	t.Parallel()

	value := validManifest()
	if err := value.Validate(); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}

	encoded, err := value.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal canonical manifest: %v", err)
	}

	parsed, err := manifest.Parse(encoded)
	if err != nil {
		t.Fatalf("parse canonical manifest: %v", err)
	}

	reencoded, err := parsed.MarshalCanonical()
	if err != nil {
		t.Fatalf("re-marshal canonical manifest: %v", err)
	}

	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("canonical manifest changed after round trip\nfirst:  %s\nsecond: %s", encoded, reencoded)
	}
}

func TestManifestDigestIsDeterministicAndContentSensitive(t *testing.T) {
	t.Parallel()

	value := validManifest()

	first, err := value.Digest()
	if err != nil {
		t.Fatalf("calculate first digest: %v", err)
	}

	second, err := value.Digest()
	if err != nil {
		t.Fatalf("calculate second digest: %v", err)
	}

	if first != second || len(first) != 64 {
		t.Fatalf("non-deterministic manifest digest: %q and %q", first, second)
	}

	value.Generation++

	mutated, err := value.Digest()
	if err != nil {
		t.Fatalf("calculate mutated digest: %v", err)
	}

	if mutated == first {
		t.Fatal("manifest digest ignored generation mutation")
	}
}

func TestManifestRejectsCoverageAndCryptoMutations(t *testing.T) {
	t.Parallel()

	mutations := []func(*manifest.Manifest){
		func(value *manifest.Manifest) { value.NamespaceID = strings.ToUpper(value.NamespaceID) },
		func(value *manifest.Manifest) { value.Generation = 0 },
		func(value *manifest.Manifest) { value.Crypto.Suite = "unknown" },
		func(value *manifest.Manifest) { value.Crypto.RootVersion = 0 },
		func(value *manifest.Manifest) { value.Packs[0].PlaintextOffset = 1 },
		func(value *manifest.Manifest) { value.Packs[0].CiphertextSize-- },
		func(value *manifest.Manifest) { value.Packs[0].Extents[1].FirstFrame-- },
		func(value *manifest.Manifest) { value.Packs[0].Extents[1].CiphertextOffset-- },
		func(value *manifest.Manifest) { value.Packs[0].Extents[0].FrameCount = 0 },
		func(value *manifest.Manifest) { value.Packs[0].Extents[1].CiphertextSHA256 = "invalid" },
	}

	for index, mutate := range mutations {
		value := validManifest()
		mutate(&value)

		if err := value.Validate(); !errors.Is(err, manifest.ErrInvalidManifest) {
			t.Errorf("mutation %d: expected ErrInvalidManifest, got %v", index, err)
		}
	}
}

func TestManifestAcceptsCanonicalEmptyObject(t *testing.T) {
	t.Parallel()

	value := validManifest()
	value.PlaintextSize = 0
	value.PlaintextSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	value.Packs = []manifest.Pack{}

	if err := value.Validate(); err != nil {
		t.Fatalf("validate empty manifest: %v", err)
	}
}

func TestManifestRejectsNullCollections(t *testing.T) {
	t.Parallel()

	value := validManifest()
	value.Packs = nil

	if err := value.Validate(); !errors.Is(err, manifest.ErrInvalidManifest) {
		t.Fatalf("expected null packs rejection, got %v", err)
	}

	empty := validManifest()
	empty.PlaintextSize = 0
	empty.PlaintextSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	empty.Packs = []manifest.Pack{}

	recovery, err := manifest.NewRecoveryManifest(empty, []manifest.Location{})
	if err != nil {
		t.Fatalf("construct empty recovery manifest: %v", err)
	}

	recovery.Locations = nil
	if err := recovery.Validate(); !errors.Is(err, manifest.ErrInvalidRecoveryManifest) {
		t.Fatalf("expected null locations rejection, got %v", err)
	}
}

func TestRecoveryManifestRequiresEveryExtentAndMatchingDigest(t *testing.T) {
	t.Parallel()

	content := validManifest()

	recovery, err := manifest.NewRecoveryManifest(content, validLocations())
	if err != nil {
		t.Fatalf("construct recovery manifest: %v", err)
	}

	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal recovery manifest: %v", err)
	}

	parsed, err := manifest.ParseRecovery(encoded)
	if err != nil {
		t.Fatalf("parse recovery manifest: %v", err)
	}

	if parsed.ManifestSHA256 != recovery.ManifestSHA256 {
		t.Fatalf("manifest digest changed: got %q want %q", parsed.ManifestSHA256, recovery.ManifestSHA256)
	}

	missing := recovery
	missing.Locations = missing.Locations[:1]

	if err := missing.Validate(); !errors.Is(err, manifest.ErrInvalidRecoveryManifest) {
		t.Fatalf("expected missing extent rejection, got %v", err)
	}

	wrongDigest := recovery
	wrongDigest.ManifestSHA256 = contentHash

	if err := wrongDigest.Validate(); !errors.Is(err, manifest.ErrInvalidRecoveryManifest) {
		t.Fatalf("expected content digest rejection, got %v", err)
	}
}

func TestRecoveryManifestSupportsReplicasAndRejectsUnsafeLocations(t *testing.T) {
	t.Parallel()

	content := validManifest()

	locations := append(validLocations(), manifest.Location{
		ExtentSHA256:    contentHash,
		DriverID:        "r2-backup",
		StorageKey:      "packs/backup",
		Offset:          5,
		Length:          72,
		ProviderVersion: "v2",
	})

	recovery, err := manifest.NewRecoveryManifest(content, locations)
	if err != nil {
		t.Fatalf("construct replicated recovery manifest: %v", err)
	}

	mutations := []func(*manifest.RecoveryManifest){
		func(value *manifest.RecoveryManifest) { value.Locations[0].ExtentSHA256 = strings.Repeat("f", 64) },
		func(value *manifest.RecoveryManifest) { value.Locations[0].Length-- },
		func(value *manifest.RecoveryManifest) { value.Locations[0].DriverID = " " },
		func(value *manifest.RecoveryManifest) { value.Locations[0].StorageKey = "" },
		func(value *manifest.RecoveryManifest) {
			value.Locations = append(value.Locations, value.Locations[0])
		},
	}

	for index, mutate := range mutations {
		candidate := recovery
		candidate.Locations = append([]manifest.Location(nil), recovery.Locations...)
		mutate(&candidate)

		if err := candidate.Validate(); !errors.Is(err, manifest.ErrInvalidRecoveryManifest) {
			t.Errorf("mutation %d: expected ErrInvalidRecoveryManifest, got %v", index, err)
		}
	}
}

func TestStrictParsersRejectUnknownFieldsAndTrailingValues(t *testing.T) {
	t.Parallel()

	encoded, err := validManifest().MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	unknown := bytes.Replace(encoded, []byte(`"object_id":`), []byte(`"unknown":1,"object_id":`), 1)
	if _, parseErr := manifest.Parse(unknown); !errors.Is(parseErr, manifest.ErrInvalidManifest) {
		t.Fatalf("expected unknown field rejection, got %v", parseErr)
	}

	trailing := append(bytes.Clone(encoded), []byte(` {}`)...)
	if _, parseErr := manifest.Parse(trailing); !errors.Is(parseErr, manifest.ErrInvalidManifest) {
		t.Fatalf("expected trailing value rejection, got %v", parseErr)
	}
}

func FuzzParseManifestNeverAcceptsNonCanonicalRoundTrip(fuzz *testing.F) {
	seed, err := validManifest().MarshalCanonical()
	if err != nil {
		fuzz.Fatalf("marshal fuzz seed: %v", err)
	}

	fuzz.Add(seed)
	fuzz.Add([]byte(`{}`))
	fuzz.Add([]byte(`null`))

	fuzz.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 1<<20 {
			t.Skip()
		}

		parsed, parseErr := manifest.Parse(encoded)
		if parseErr != nil {
			return
		}

		canonical, marshalErr := parsed.MarshalCanonical()
		if marshalErr != nil {
			t.Fatalf("accepted manifest cannot be marshalled: %v", marshalErr)
		}

		reparsed, reparseErr := manifest.Parse(canonical)
		if reparseErr != nil {
			t.Fatalf("canonical manifest cannot be parsed: %v", reparseErr)
		}

		if reparsed.ObjectID != parsed.ObjectID {
			t.Fatal("canonical round trip changed object identity")
		}
	})
}

func validManifest() manifest.Manifest {
	return manifest.Manifest{
		SchemaVersion:   manifest.SchemaVersion,
		NamespaceID:     namespaceID,
		ObjectID:        "object-1",
		Generation:      1,
		PlaintextSize:   10,
		PlaintextSHA256: contentHash,
		Layout: archive.Layout{
			PhysicalBlockBytes: 8,
			CryptoFrameBytes:   2,
			LogicalPackBytes:   16,
		},
		Crypto: manifest.Crypto{
			Suite:       cryptostream.SuiteAES128GCMHKDFSHA256V1,
			RootVersion: 1,
			KeyEpoch:    7,
		},
		Packs: []manifest.Pack{
			{
				Ordinal:          0,
				PackID:           packID,
				PlaintextOffset:  0,
				PlaintextSize:    10,
				CiphertextSize:   90,
				CiphertextSHA256: secondHash,
				Extents: []manifest.Extent{
					{
						Ordinal:          0,
						FirstFrame:       0,
						FrameCount:       4,
						CiphertextOffset: 0,
						CiphertextSize:   72,
						CiphertextSHA256: contentHash,
					},
					{
						Ordinal:          1,
						FirstFrame:       4,
						FrameCount:       1,
						CiphertextOffset: 72,
						CiphertextSize:   18,
						CiphertextSHA256: secondHash,
					},
				},
			},
		},
	}
}

func validLocations() []manifest.Location {
	return []manifest.Location{
		{
			ExtentSHA256: contentHash,
			DriverID:     "aliyun-primary",
			StorageKey:   "packs/40/pack",
			Offset:       0,
			Length:       72,
		},
		{
			ExtentSHA256:    secondHash,
			DriverID:        "aliyun-primary",
			StorageKey:      "packs/40/pack",
			ProviderVersion: "v1",
			Offset:          72,
			Length:          18,
		},
	}
}
