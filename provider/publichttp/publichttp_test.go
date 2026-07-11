package publichttp_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/dravengarden/carrack/provider/publichttp"
)

func TestReaderStatsAndReadsExactRange(t *testing.T) {
	t.Parallel()

	payload := []byte("public immutable ciphertext")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/archive/object.bin" {
			http.NotFound(response, request)

			return
		}

		response.Header().Set("ETag", `"version-1"`)
		response.Header().Set("Accept-Ranges", "bytes")

		if request.Method == http.MethodHead {
			response.Header().Set("Content-Length", strconv.Itoa(len(payload)))

			return
		}

		if request.Header.Get("Range") != "bytes=3-8" {
			t.Errorf("unexpected range %q", request.Header.Get("Range"))
		}

		response.Header().Set("Content-Length", "6")
		response.Header().Set("Content-Range", fmt.Sprintf("bytes 3-8/%d", len(payload)))
		response.WriteHeader(http.StatusPartialContent)
		_, _ = response.Write(payload[3:9])
	}))
	t.Cleanup(server.Close)

	reader, err := publichttp.NewReader(server.URL+"/archive", server.Client())
	if err != nil {
		t.Fatalf("construct public reader: %v", err)
	}

	object, err := reader.Stat(context.Background(), "object.bin")
	if err != nil {
		t.Fatalf("stat public object: %v", err)
	}

	if object.SizeBytes != uint64(len(payload)) || object.ETag != `"version-1"` {
		t.Fatalf("unexpected public object: %+v", object)
	}

	stream, err := reader.OpenRange(context.Background(), "object.bin", 3, 6)
	if err != nil {
		t.Fatalf("open public range: %v", err)
	}

	selected, readErr := io.ReadAll(stream)

	closeErr := stream.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read public range: %v", errors.Join(readErr, closeErr))
	}

	if !bytes.Equal(selected, payload[3:9]) {
		t.Fatalf("public range is %q", selected)
	}
}

func TestReaderRejectsImpreciseRangesAndUnsafeKeys(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("whole object"))
	}))
	t.Cleanup(server.Close)

	reader, err := publichttp.NewReader(server.URL, server.Client())
	if err != nil {
		t.Fatalf("construct public reader: %v", err)
	}

	if _, err := reader.OpenRange(context.Background(), "../secret", 0, 1); !errors.Is(err, publichttp.ErrInvalidConfiguration) {
		t.Fatalf("unsafe object key was not rejected: %v", err)
	}

	if _, err := reader.OpenRange(context.Background(), "object", 0, 1); !errors.Is(err, publichttp.ErrInvalidResponse) {
		t.Fatalf("whole-object response was not rejected: %v", err)
	}
}

func TestReaderRejectsCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)

	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"/object", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	reader, err := publichttp.NewReader(source.URL, source.Client())
	if err != nil {
		t.Fatalf("construct public reader: %v", err)
	}

	if _, err := reader.OpenRange(context.Background(), "object", 0, 1); !errors.Is(err, publichttp.ErrInvalidResponse) {
		t.Fatalf("cross-origin redirect was not rejected: %v", err)
	}
}
