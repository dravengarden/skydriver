package aliyundrive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestOpenListTokenSourceRenewsCachesAndPersists(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	requests := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()

		requests = append(requests, request.URL.Query().Get("refresh_ui"))
		requestNumber := len(requests)
		mutex.Unlock()

		if request.URL.Query().Get("server_use") != "true" {
			t.Error("server_use query parameter is missing")
		}

		if request.URL.Query().Get("driver_txt") != "alicloud_qr" {
			t.Error("driver_txt query parameter is incorrect")
		}

		writer.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(writer).Encode(map[string]string{
			"access_token":  fmt.Sprintf("access-%d", requestNumber),
			"refresh_token": fmt.Sprintf("refresh-%d", requestNumber),
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	persisted := make([]string, 0, 2)

	source, err := NewOpenListTokenSource(RenewOptions{
		HTTPClient:   server.Client(),
		Endpoint:     server.URL,
		RefreshToken: "refresh-0",
		PersistRefreshToken: func(_ context.Context, refreshToken string) error {
			persisted = append(persisted, refreshToken)

			return nil
		},
	})
	if err != nil {
		t.Fatalf("construct token source: %v", err)
	}

	first, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("get first token: %v", err)
	}

	second, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("get cached token: %v", err)
	}

	if first != "access-1" || second != first {
		t.Fatalf("unexpected cached tokens: first=%q second=%q", first, second)
	}

	source.Invalidate()

	third, err := source.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("get renewed token: %v", err)
	}

	if third != "access-2" {
		t.Fatalf("unexpected renewed token %q", third)
	}

	mutex.Lock()
	defer mutex.Unlock()

	if fmt.Sprint(requests) != "[refresh-0 refresh-1]" {
		t.Fatalf("unexpected refresh token sequence: %v", requests)
	}

	if fmt.Sprint(persisted) != "[refresh-1 refresh-2]" {
		t.Fatalf("unexpected persisted token sequence: %v", persisted)
	}
}

func TestStaticTokenSourceRejectsEmptyToken(t *testing.T) {
	t.Parallel()

	if _, err := NewStaticTokenSource(""); err == nil {
		t.Fatal("expected an empty token error")
	}
}
