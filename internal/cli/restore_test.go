package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/aliyundrive"
	"github.com/dravengarden/carrack/provider/publichttp"
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

func TestRestoreCredentialStoreInitializesEncryptedRefreshToken(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{9}, credentialKeyBytes)
	values := map[string]string{
		credentialKeyEnvironment: base64.RawURLEncoding.EncodeToString(key),
		aliyunRefreshEnvironment: "refresh-secret",
	}

	store, err := restoreCredentialStore(
		context.Background(),
		restoreFlags{credentialStore: filepath.Join(t.TempDir(), "credential.json")},
		func(name string) string { return values[name] },
	)
	if err != nil {
		t.Fatalf("initialize refresh credential store: %v", err)
	}

	record, err := store.Load(context.Background(), cliCredentialReference)
	if err != nil {
		t.Fatalf("load initialized refresh credential: %v", err)
	}

	var credential map[string]string
	if err := json.Unmarshal(record.Payload, &credential); err != nil {
		t.Fatalf("decode initialized refresh credential: %v", err)
	}

	if credential["refresh_token"] != "refresh-secret" {
		t.Fatalf("unexpected initialized credential: %v", credential)
	}
}

func TestOpenRestoreReadersSupportsPublicHTTPWithoutCredentials(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)

	registry, err := provider.NewRegistry(aliyundrive.Factory{}, publichttp.Factory{})
	if err != nil {
		t.Fatalf("construct restore registry: %v", err)
	}

	readers, err := openRestoreReaders(
		context.Background(),
		registry,
		server.Client(),
		restoreFlags{publicDriverID: "public-replica", publicBaseURL: server.URL},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatalf("open public restore reader: %v", err)
	}

	if len(readers) != 1 || readers["public-replica"] == nil {
		t.Fatalf("unexpected restore readers: %v", readers)
	}
}
