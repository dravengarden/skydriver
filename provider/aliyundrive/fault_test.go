package aliyundrive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
)

type rotatingTokenSource struct {
	mutex         sync.Mutex
	tokens        []string
	index         int
	invalidations int
}

func (source *rotatingTokenSource) AccessToken(context.Context) (string, error) {
	source.mutex.Lock()
	defer source.mutex.Unlock()

	return source.tokens[source.index], nil
}

func (source *rotatingTokenSource) Invalidate() {
	source.mutex.Lock()
	defer source.mutex.Unlock()

	source.invalidations++
	if source.index+1 < len(source.tokens) {
		source.index++
	}
}

func TestClientRefreshesExpiredAccessTokenExactlyOnce(t *testing.T) {
	t.Parallel()

	tokens := &rotatingTokenSource{tokens: []string{"expired-token", "fresh-token"}}

	var mutex sync.Mutex

	authorizations := make([]string, 0, 3)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()

		authorizations = append(authorizations, request.Header.Get("Authorization"))
		mutex.Unlock()

		switch request.URL.Path {
		case "/adrive/v1.0/user/getDriveInfo":
			if request.Header.Get("Authorization") == "Bearer expired-token" {
				writer.WriteHeader(http.StatusUnauthorized)
				writeFaultJSON(t, writer, apiError{Code: "AccessTokenExpired", Message: "expired"})

				return
			}

			writeFaultJSON(t, writer, driveInfoResponse{ResourceDriveID: "drive-1"})
		case "/adrive/v1.0/openFile/list":
			writeFaultJSON(t, writer, listResponse{Items: []fileRecord{{
				FileID: "file-1", Name: "object.bin", Size: 4, Type: objectTypeFile,
			}}})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	client := newFaultClient(t, server, tokens)

	object, err := client.Stat(context.Background(), "object.bin")
	if err != nil {
		t.Fatalf("stat after token refresh: %v", err)
	}

	if object.Key != "object.bin" || object.Version != "file-1" || object.SizeBytes != 4 {
		t.Fatalf("unexpected object after token refresh: %+v", object)
	}

	tokens.mutex.Lock()
	invalidations := tokens.invalidations
	tokens.mutex.Unlock()

	mutex.Lock()
	actualAuthorizations := slices.Clone(authorizations)
	mutex.Unlock()

	expectedAuthorizations := []string{
		"Bearer expired-token", "Bearer fresh-token", "Bearer fresh-token",
	}
	if invalidations != 1 || !slices.Equal(actualAuthorizations, expectedAuthorizations) {
		t.Fatalf(
			"unexpected refresh sequence: invalidations=%d authorizations=%v",
			invalidations,
			actualAuthorizations,
		)
	}
}

func TestClientPropagatesProviderControlFailuresWithoutRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		apiCode    string
	}{
		{name: "throttled", statusCode: http.StatusTooManyRequests, apiCode: "TooManyRequests"},
		{name: "authorization lost", statusCode: http.StatusForbidden, apiCode: "AccessDenied"},
		{name: "quota exhausted", statusCode: http.StatusForbidden, apiCode: "QuotaExhausted"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requestCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				requestCount++

				writer.WriteHeader(test.statusCode)
				writeFaultJSON(t, writer, apiError{Code: test.apiCode, Message: test.name})
			}))
			t.Cleanup(server.Close)

			tokenSource, err := NewStaticTokenSource("access-token")
			if err != nil {
				t.Fatalf("create static token source: %v", err)
			}

			client := newFaultClient(t, server, tokenSource)
			_, statErr := client.Stat(context.Background(), "object.bin")

			var responseErr apiError
			if !errors.As(statErr, &responseErr) || responseErr.Code != test.apiCode {
				t.Fatalf("provider failure was not preserved: err=%v parsed=%+v", statErr, responseErr)
			}

			if requestCount != 1 {
				t.Fatalf("non-token provider failure was retried: requests=%d", requestCount)
			}
		})
	}
}

func TestClientRejectsInexactDownloadRangeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		contentRange  string
		contentLength string
		body          string
	}{
		{name: "missing content range", contentLength: "4", body: "rack"},
		{name: "shifted content range", contentRange: "bytes 1-4/9", contentLength: "4", body: "arra"},
		{name: "wrong object size", contentRange: "bytes 2-5/10", contentLength: "4", body: "rack"},
		{name: "wrong content length", contentRange: "bytes 2-5/9", contentLength: "3", body: "rac"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newDownloadFaultClient(t, func(writer http.ResponseWriter, _ *http.Request) {
				if test.contentRange != "" {
					writer.Header().Set("Content-Range", test.contentRange)
				}

				writer.Header().Set("Content-Length", test.contentLength)
				writer.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(writer, test.body)
			})

			stream, err := client.OpenRange(context.Background(), "object.bin", 2, 4)
			if stream != nil {
				_ = stream.Close()
			}

			if !errors.Is(err, errInvalidAPIResponse) {
				t.Fatalf("inexact download range was accepted: %v", err)
			}
		})
	}
}

func TestClientSurfacesShortDownloadBody(t *testing.T) {
	t.Parallel()

	client := newDownloadFaultClient(t, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Range", "bytes 2-5/9")
		writer.Header().Set("Content-Length", "4")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(writer, "ra")
	})

	stream, err := client.OpenRange(context.Background(), "object.bin", 2, 4)
	if err != nil {
		t.Fatalf("open short range response: %v", err)
	}

	_, readErr := io.ReadAll(stream)

	closeErr := stream.Close()
	if !errors.Is(readErr, io.ErrUnexpectedEOF) || closeErr != nil {
		t.Fatalf("short download body was not surfaced: read=%v close=%v", readErr, closeErr)
	}
}

func newDownloadFaultClient(
	t *testing.T,
	downloadHandler func(http.ResponseWriter, *http.Request),
) *Client {
	t.Helper()

	var server *httptest.Server

	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/adrive/v1.0/user/getDriveInfo":
			writeFaultJSON(t, writer, driveInfoResponse{ResourceDriveID: "drive-1"})
		case "/adrive/v1.0/openFile/list":
			writeFaultJSON(t, writer, listResponse{Items: []fileRecord{{
				FileID: "file-1", Name: "object.bin", Size: 9, Type: objectTypeFile,
			}}})
		case "/adrive/v1.0/openFile/getDownloadUrl":
			writeFaultJSON(t, writer, downloadURLResponse{URL: server.URL + "/download"})
		case "/download":
			if request.Header.Get("Range") != "bytes=2-5" ||
				request.Header.Get("Accept-Encoding") != "identity" {
				t.Errorf(
					"unexpected download headers: range=%q encoding=%q",
					request.Header.Get("Range"),
					request.Header.Get("Accept-Encoding"),
				)
			}

			downloadHandler(writer, request)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	tokenSource, err := NewStaticTokenSource("access-token")
	if err != nil {
		t.Fatalf("create static token source: %v", err)
	}

	return newFaultClient(t, server, tokenSource)
}

func newFaultClient(t *testing.T, server *httptest.Server, tokenSource TokenSource) *Client {
	t.Helper()

	client, err := NewClient(Options{
		HTTPClient: server.Client(), TokenSource: tokenSource, APIBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("create fault-test client: %v", err)
	}

	return client
}

func writeFaultJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()

	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Errorf("encode fault response: %v", err)
	}
}
