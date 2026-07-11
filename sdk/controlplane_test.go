package sdk_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestControlClientAuthenticatesWithoutLeakingTokenToHealth(t *testing.T) {
	t.Parallel()

	token, encoded := testClientToken(t)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/health":
			if request.Header.Get("Authorization") != "" {
				t.Error("health request sent authentication token")
			}

			_, _ = response.Write([]byte(`{"service":"carrack-control-plane","transfer_mode":"direct","mode":"active","incarnation":"0123456789abcdef0123456789abcdef","revision":1,"external_maintenance":false,"mutations_allowed":true}`))
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

	if !health.MutationsAllowed || health.Mode != "active" {
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
