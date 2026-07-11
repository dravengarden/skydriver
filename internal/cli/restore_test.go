package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestParseEpochKeyRequiresExactUnpaddedBase64URL(t *testing.T) {
	t.Parallel()

	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

	key, err := parseEpochKey(encoded)
	if err != nil {
		t.Fatalf("parse epoch key: %v", err)
	}

	if key[0] != 7 || key[len(key)-1] != 7 {
		t.Fatalf("decoded unexpected epoch key: %x", key)
	}

	if _, err := parseEpochKey(encoded + "="); !errors.Is(err, errEpochKeyEncoding) {
		t.Fatalf("padded epoch key was not rejected: %v", err)
	}
}

func TestRestoreIdempotencyPinsManifestAndAbsoluteDestination(t *testing.T) {
	t.Parallel()

	first := restoreIdempotencyKey(strings.Repeat("a", 64), "/tmp/one")
	if first != restoreIdempotencyKey(strings.Repeat("a", 64), "/tmp/one") {
		t.Fatal("restore idempotency key is not deterministic")
	}

	if first == restoreIdempotencyKey(strings.Repeat("b", 64), "/tmp/one") ||
		first == restoreIdempotencyKey(strings.Repeat("a", 64), "/tmp/two") {
		t.Fatal("restore idempotency key did not bind every identity")
	}
}

func TestExecuteRestoreRejectsMissingSecretsBeforeNetwork(t *testing.T) {
	t.Parallel()

	_, err := executeRestore(context.Background(), restoreFlags{}, "destination", func(string) string {
		return ""
	})
	if !errors.Is(err, sdk.ErrInvalidControlPlane) {
		t.Fatalf("missing control token returned unexpected error: %v", err)
	}
}
