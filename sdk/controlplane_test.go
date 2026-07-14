package sdk_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientAuthenticatesWithoutLeakingTokenToHealth(t *testing.T) {
	t.Parallel()

	token, encoded := testClientToken(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		if request.Header.Get("Carrack-Protocol-Epoch") != "2" ||
			request.Header.Get("Carrack-Sdk-Version") != sdk.SDKVersion {
			t.Error("request omitted Carrack compatibility headers")
		}

		switch request.URL.Path {
		case "/api/health":
			if request.Header.Get("Authorization") != "" {
				t.Error("health request sent authentication token")
			}

			_, _ = response.Write([]byte(`{"service":"carrack-control-plane","environment":"dev","transfer_mode":"direct","mode":"active","incarnation":"0123456789abcdef0123456789abcdef","revision":1,"external_maintenance":false,"mutations_allowed":true}`))
		case "/api/client/session":
			if request.Header.Get("Authorization") != "Bearer "+encoded {
				t.Error("session request did not send the expected bearer token")
			}

			_, _ = response.Write([]byte(`{"id":"client-1","name":"hawk","sdk_version":"0.1.0"}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	health, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("read health: %v", err)
	}

	if !health.MutationsAllowed || health.Mode != "active" || health.Environment != "dev" {
		t.Fatalf("unexpected health response: %+v", health)
	}

	session, err := client.Session(context.Background())
	if err != nil {
		t.Fatalf("read client session: %v", err)
	}

	if session.ID != "client-1" || session.Name != "hawk" {
		t.Fatalf("unexpected client session: %+v", session)
	}
}

func TestControlClientFailsFastOnIncompatibleProtocol(t *testing.T) {
	t.Parallel()

	token, _ := testClientToken(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		if request.URL.Path == "/api/compatibility" {
			_, _ = response.Write([]byte(`{"schema":"carrack.protocol-compatibility.v1","protocol_epoch":3,"minimum_sdk_version":"2.0.0","server_version":"2.0.0","enforcement":"required","upgrade_command":"upgrade carrack"}`))
			return
		}

		response.WriteHeader(http.StatusUpgradeRequired)
		_, _ = response.Write([]byte(`{"schema":"carrack.protocol-error.v1","code":"sdk_upgrade_required","message":"incompatible","protocol_epoch":3,"minimum_sdk_version":"2.0.0","server_version":"2.0.0","upgrade_command":"upgrade carrack"}`))
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	if _, err := client.CheckCompatibility(context.Background()); !errors.Is(err, sdk.ErrUpgradeRequired) {
		t.Fatalf("expected preflight upgrade failure, got %v", err)
	}

	if _, err := client.Session(context.Background()); !errors.Is(err, sdk.ErrUpgradeRequired) {
		t.Fatalf("expected HTTP 426 upgrade failure, got %v", err)
	}
}

func TestControlClientRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	token, _ := testClientToken(t)

	for _, endpoint := range []string{
		"",
		"http://example.com",
		"https://user:password@example.com",
		"https://example.com?token=secret",
	} {
		_, err := sdk.NewControlClient(endpoint, token, http.DefaultClient)
		if !errors.Is(err, sdk.ErrInvalidControlPlane) {
			t.Errorf("endpoint %q: expected invalid configuration, got %v", endpoint, err)
		}
	}

	_, err := sdk.NewControlClient("https://example.com", sdk.ClientToken{}, http.DefaultClient)
	if !errors.Is(err, sdk.ErrInvalidControlPlane) {
		t.Fatalf("expected zero-token rejection, got %v", err)
	}
}

func TestControlClientRejectsMalformedResponsesWithoutReturningBody(t *testing.T) {
	t.Parallel()

	token, _ := testClientToken(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/client/session" {
			response.WriteHeader(http.StatusUnauthorized)
			_, _ = response.Write([]byte("secret diagnostic body"))

			return
		}

		_, _ = response.Write([]byte(`{"service":"carrack","transfer_mode":"direct","mode":"active","incarnation":"id","revision":1,"external_maintenance":false,"mutations_allowed":true,"unknown":1}`))
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	_, err = client.Session(context.Background())
	if !errors.Is(err, sdk.ErrControlPlaneResponse) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe session error: %v", err)
	}

	_, err = client.Health(context.Background())
	if !errors.Is(err, sdk.ErrControlPlaneResponse) {
		t.Fatalf("expected strict health rejection, got %v", err)
	}
}

func TestClientTokenParsingAndClear(t *testing.T) {
	t.Parallel()

	token, encoded := testClientToken(t)

	parsed, err := sdk.ParseClientToken(encoded)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	if parsed != token {
		t.Fatal("parsed token changed bytes")
	}

	parsed.Clear()

	if parsed != (sdk.ClientToken{}) {
		t.Fatal("clear did not overwrite token")
	}

	if _, err := sdk.ParseClientToken("invalid"); !errors.Is(err, sdk.ErrInvalidControlPlane) {
		t.Fatalf("expected malformed token rejection, got %v", err)
	}
}

func TestControlClientStagesExactRecoveryManifest(t *testing.T) {
	t.Parallel()

	token, encodedToken := testClientToken(t)
	recovery := controlRecoveryManifest(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken ||
			request.Header.Get("Content-Type") != "application/json" {
			http.Error(response, "invalid request metadata", http.StatusUnauthorized)

			return
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(response, "read body", http.StatusBadRequest)

			return
		}

		parsed, err := manifest.ParseRecovery(body)
		if err != nil {
			http.Error(response, "invalid recovery", http.StatusBadRequest)

			return
		}

		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"manifest_sha256":"` + parsed.ManifestSHA256 +
			`","recovery_sha256":"` + testDigest(body) + `",` +
			`"namespace_id":"` + parsed.Manifest.NamespaceID + `","object_id":"` +
			parsed.Manifest.ObjectID + `","generation":1,"r2_key":"manifests/test.json",` +
			`"r2_version":"v1","bytes":` + strconv.Itoa(len(body)) + `}`))
	}))
	defer server.Close()

	client, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	staged, err := client.StageRecovery(context.Background(), recovery)
	if err != nil {
		t.Fatalf("stage recovery manifest: %v", err)
	}

	if staged.ManifestSHA256 != recovery.ManifestSHA256 || staged.R2Version != "v1" {
		t.Fatalf("unexpected staged recovery: %+v", staged)
	}
}

func testClientToken(t *testing.T) (sdk.ClientToken, string) {
	t.Helper()

	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = byte(index + 1)
	}

	encoded := base64.RawURLEncoding.EncodeToString(raw)

	token, err := sdk.ParseClientToken(encoded)
	if err != nil {
		t.Fatalf("parse test token: %v", err)
	}

	return token, encoded
}

func controlRecoveryManifest(t *testing.T) manifest.RecoveryManifest {
	t.Helper()

	content := manifest.Manifest{
		SchemaVersion:   manifest.SchemaVersion,
		NamespaceID:     "202122232425262728292a2b2c2d2e2f",
		ObjectID:        "object-1",
		Generation:      1,
		PlaintextSize:   2,
		PlaintextSHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		Layout: archive.Layout{
			PhysicalBlockBytes: 2,
			CryptoFrameBytes:   2,
			LogicalPackBytes:   2,
		},
		Crypto: manifest.Crypto{
			Suite:       cryptostream.SuiteAES128GCMHKDFSHA256V1,
			RootVersion: 1,
			KeyEpoch:    7,
		},
		Packs: []manifest.Pack{
			{
				Ordinal:          0,
				PackID:           "404142434445464748494a4b4c4d4e4f",
				PlaintextOffset:  0,
				PlaintextSize:    2,
				CiphertextSize:   18,
				CiphertextSHA256: "1111111111111111111111111111111111111111111111111111111111111111",
				Extents: []manifest.Extent{
					{
						Ordinal:          0,
						FirstFrame:       0,
						FrameCount:       1,
						CiphertextOffset: 0,
						CiphertextSize:   18,
						CiphertextSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
					},
				},
			},
		},
	}

	recovery, err := manifest.NewRecoveryManifest(content, []manifest.Location{
		{
			ExtentSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
			DriverID:     "memory",
			StorageKey:   "extent",
			Offset:       0,
			Length:       18,
		},
	})
	if err != nil {
		t.Fatalf("construct control recovery manifest: %v", err)
	}

	return recovery
}
