package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type verificationReader struct {
	data    []byte
	openErr error
}

var errUnexpectedVerificationStat = errors.New("unexpected verification Stat")

func (reader verificationReader) Stat(context.Context, string) (provider.Object, error) {
	return provider.Object{}, errUnexpectedVerificationStat
}

func (reader verificationReader) OpenRange(context.Context, string, uint64, uint64) (io.ReadCloser, error) {
	if reader.openErr != nil {
		return nil, reader.openErr
	}

	return io.NopCloser(bytes.NewReader(reader.data)), nil
}

func TestVerifierRecordsEachLocationWithoutReplicaShortCircuit(t *testing.T) {
	payload := bytes.Repeat([]byte{'a'}, 18)
	digest := sha256.Sum256(payload)
	recovery := verificationRecovery(t, hex.EncodeToString(digest[:]), []manifest.Location{
		{DriverID: "good", StorageKey: "one", Length: uint64(len(payload))},
		{DriverID: "missing", StorageKey: "two", Length: uint64(len(payload))},
		{DriverID: "corrupt", StorageKey: "three", Length: uint64(len(payload))},
		{DriverID: "offline", StorageKey: "four", Length: uint64(len(payload))},
	})

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{
		"good":    verificationReader{data: payload},
		"missing": verificationReader{openErr: provider.ErrObjectNotFound},
		"corrupt": verificationReader{data: bytes.Repeat([]byte{'x'}, len(payload))},
	})
	if err != nil {
		t.Fatalf("construct verifier: %v", err)
	}

	result, err := verifier.Verify(context.Background(), recovery, "")
	if err != nil {
		t.Fatalf("verify recovery: %v", err)
	}

	if result.Verified != 1 || result.Missing != 1 || result.Corrupt != 1 || result.Unavailable != 1 {
		t.Fatalf("unexpected counters: %+v", result)
	}

	conditions := []sdk.VerificationCondition{sdk.VerificationVerified, sdk.VerificationMissing, sdk.VerificationCorrupt, sdk.VerificationUnavailable}
	for index, expected := range conditions {
		if result.Evidence[index].Condition != expected {
			t.Errorf("evidence %d condition = %q, want %q", index, result.Evidence[index].Condition, expected)
		}
	}
}

func TestVerifierDriverFilterAndShortRead(t *testing.T) {
	payload := bytes.Repeat([]byte{'a'}, 18)
	digest := sha256.Sum256(payload)
	recovery := verificationRecovery(t, hex.EncodeToString(digest[:]), []manifest.Location{
		{DriverID: "selected", StorageKey: "one", Length: uint64(len(payload))},
		{DriverID: "ignored", StorageKey: "two", Length: uint64(len(payload))},
	})

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{"selected": verificationReader{data: payload[:3]}})
	if err != nil {
		t.Fatalf("construct verifier: %v", err)
	}

	result, err := verifier.Verify(context.Background(), recovery, "selected")
	if err != nil {
		t.Fatalf("verify selected driver: %v", err)
	}

	if len(result.Evidence) != 1 || result.Corrupt != 1 {
		t.Fatalf("unexpected filtered result: %+v", result)
	}
}

func verificationRecovery(t *testing.T, digest string, locations []manifest.Location) manifest.RecoveryManifest {
	t.Helper()
	base := controlRecoveryManifest(t)

	base.Manifest.Packs[0].Extents[0].CiphertextSHA256 = digest
	for index := range locations {
		locations[index].ExtentSHA256 = digest
	}

	recovery, err := manifest.NewRecoveryManifest(base.Manifest, locations)
	if err != nil {
		t.Fatalf("construct verification recovery: %v", err)
	}

	return recovery
}
