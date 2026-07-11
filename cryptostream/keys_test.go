package cryptostream_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/dravengarden/carrack/cryptostream"
)

func TestKeyDerivationIsDeterministicAndDomainSeparated(t *testing.T) {
	t.Parallel()

	rootKey := sequentialRootKey()
	namespaceID := identifier(0x20)
	packID := identifier(0x40)

	firstEpoch, err := cryptostream.DeriveEpochKey(rootKey, cryptostream.EpochContext{
		NamespaceID: namespaceID,
		EpochID:     7,
	})
	if err != nil {
		t.Fatalf("derive first epoch key: %v", err)
	}

	secondEpoch, err := cryptostream.DeriveEpochKey(rootKey, cryptostream.EpochContext{
		NamespaceID: namespaceID,
		EpochID:     8,
	})
	if err != nil {
		t.Fatalf("derive second epoch key: %v", err)
	}

	repeatedEpoch, err := cryptostream.DeriveEpochKey(rootKey, cryptostream.EpochContext{
		NamespaceID: namespaceID,
		EpochID:     7,
	})
	if err != nil {
		t.Fatalf("derive repeated epoch key: %v", err)
	}

	if firstEpoch != repeatedEpoch || firstEpoch == secondEpoch {
		t.Fatal("epoch derivation is not deterministic and domain separated")
	}

	firstPack, err := cryptostream.DerivePackKey(firstEpoch, packID)
	if err != nil {
		t.Fatalf("derive first pack key: %v", err)
	}

	secondPack, err := cryptostream.DerivePackKey(firstEpoch, identifier(0x50))
	if err != nil {
		t.Fatalf("derive second pack key: %v", err)
	}

	if firstPack == secondPack {
		t.Fatal("different pack IDs produced the same key")
	}
}

func TestKeyDerivationRejectsZeroContexts(t *testing.T) {
	t.Parallel()

	_, err := cryptostream.DeriveEpochKey(cryptostream.RootKey{}, cryptostream.EpochContext{
		NamespaceID: identifier(1),
	})
	if !errors.Is(err, cryptostream.ErrInvalidKeyContext) {
		t.Fatalf("expected invalid root key, got %v", err)
	}

	_, err = cryptostream.DeriveEpochKey(sequentialRootKey(), cryptostream.EpochContext{})
	if !errors.Is(err, cryptostream.ErrInvalidKeyContext) {
		t.Fatalf("expected invalid namespace ID, got %v", err)
	}

	_, err = cryptostream.DerivePackKey(cryptostream.EpochKey{}, identifier(1))
	if !errors.Is(err, cryptostream.ErrInvalidKeyContext) {
		t.Fatalf("expected invalid epoch key, got %v", err)
	}
}

func TestKeyDerivationGoldenVector(t *testing.T) {
	t.Parallel()

	encoded, err := os.ReadFile("../schemas/crypto-v1-vectors.json")
	if err != nil {
		t.Fatalf("read shared crypto vector: %v", err)
	}

	var vector cryptoVector
	if decodeErr := json.Unmarshal(encoded, &vector); decodeErr != nil {
		t.Fatalf("decode shared crypto vector: %v", decodeErr)
	}

	var (
		rootKey     cryptostream.RootKey
		namespaceID cryptostream.Identifier
		packID      cryptostream.Identifier
	)

	copy(rootKey[:], decodeFixed(t, vector.RootSeedBase64, len(rootKey)))
	copy(namespaceID[:], decodeFixed(t, vector.NamespaceIDBase64, len(namespaceID)))
	copy(packID[:], decodeFixed(t, vector.PackIDBase64, len(packID)))

	epochKey, err := cryptostream.DeriveEpochKey(rootKey, cryptostream.EpochContext{
		NamespaceID: namespaceID,
		EpochID:     vector.EpochID,
	})
	if err != nil {
		t.Fatalf("derive epoch key: %v", err)
	}

	packKey, err := cryptostream.DerivePackKey(epochKey, packID)
	if err != nil {
		t.Fatalf("derive pack key: %v", err)
	}

	if cryptostream.SuiteAES128GCMHKDFSHA256V1 != vector.Suite {
		t.Fatalf("unexpected suite %q", vector.Suite)
	}

	if actual := base64.StdEncoding.EncodeToString(epochKey[:]); actual != vector.EpochKeyBase64 {
		t.Fatalf("unexpected epoch key %s", actual)
	}

	if actual := base64.StdEncoding.EncodeToString(packKey[:]); actual != vector.PackKeyBase64 {
		t.Fatalf("unexpected pack key %s", actual)
	}
}

type cryptoVector struct {
	Suite             string `json:"suite"`
	RootSeedBase64    string `json:"root_seed_base64"`
	NamespaceIDBase64 string `json:"namespace_id_base64"`
	EpochID           uint64 `json:"epoch_id"`
	PackIDBase64      string `json:"pack_id_base64"`
	EpochKeyBase64    string `json:"epoch_key_base64"`
	PackKeyBase64     string `json:"pack_key_base64"`
}

func decodeFixed(t *testing.T, encoded string, expectedBytes int) []byte {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode vector base64: %v", err)
	}

	if len(decoded) != expectedBytes {
		t.Fatalf("decoded vector has %d bytes, expected %d", len(decoded), expectedBytes)
	}

	return decoded
}

func sequentialRootKey() cryptostream.RootKey {
	var rootKey cryptostream.RootKey
	for index := range rootKey {
		rootKey[index] = byte(index + 1)
	}

	return rootKey
}

func identifier(start byte) cryptostream.Identifier {
	var value cryptostream.Identifier
	for index := range value {
		value[index] = start + byte(index)
	}

	return value
}
