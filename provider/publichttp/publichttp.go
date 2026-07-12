// Package publichttp implements read-only access to public HTTP archives.
package publichttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/dravengarden/carrack/provider"
)

const (
	// DriverKind identifies the initial public HTTP range contract.
	DriverKind      provider.DriverKind = "public-http/v1"
	safeConcurrency                     = uint32(8)
)

var (
	// ErrInvalidConfiguration indicates an unsafe base URL or object key.
	ErrInvalidConfiguration = errors.New("invalid Carrack public HTTP configuration")
	// ErrInvalidResponse indicates an HTTP response that cannot prove the requested range.
	ErrInvalidResponse  = errors.New("invalid Carrack public HTTP response")
	errTooManyRedirects = errors.New("public HTTP stopped after 10 redirects")
)

// DriverConfig contains non-secret public HTTP configuration.
type DriverConfig struct {
	BaseURL string `json:"base_url"`
}

// Factory opens public HTTP readers from typed driver specifications.
type Factory struct{}

// Kind returns the versioned public HTTP driver kind.
func (Factory) Kind() provider.DriverKind { return DriverKind }

// Open validates the base URL and creates a same-origin HTTP reader.
func (Factory) Open(
	_ context.Context,
	specification provider.DriverSpec,
	dependencies provider.Dependencies,
) (provider.Handle, error) {
	var configuration DriverConfig

	decoder := json.NewDecoder(strings.NewReader(string(specification.Config)))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&configuration); err != nil {
		return provider.Handle{}, fmt.Errorf("decode public HTTP config: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return provider.Handle{}, fmt.Errorf("decode public HTTP config trailing data: %w", err)
	}

	reader, err := NewReader(configuration.BaseURL, dependencies.HTTPClient)
	if err != nil {
		return provider.Handle{}, err
	}

	return provider.Handle{
		ID: specification.ID, Kind: DriverKind,
		Capabilities: provider.Capabilities{RangeRead: true, SafeConcurrency: safeConcurrency},
		Reader:       reader,
	}, nil
}

// Reader performs bounded same-origin HEAD and range GET requests.
type Reader struct {
	baseURL    *url.URL
	httpClient *http.Client
}

// NewReader constructs a public HTTP reader without network I/O.
func NewReader(baseURL string, httpClient *http.Client) (*Reader, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !safeURL(parsed) || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return nil, fmt.Errorf("%w: base URL must be HTTPS or loopback HTTP without credentials, query, or fragment", ErrInvalidConfiguration)
	}

	if httpClient == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", ErrInvalidConfiguration)
	}

	client := *httpClient
	priorRedirect := client.CheckRedirect

	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if !sameOrigin(parsed, request.URL) {
			return fmt.Errorf("%w: redirect changed origin", ErrInvalidResponse)
		}

		if priorRedirect != nil {
			return priorRedirect(request, via)
		}

		if len(via) >= 10 {
			return errTooManyRedirects
		}

		return nil
	}

	return &Reader{baseURL: parsed, httpClient: &client}, nil
}

// Stat reads immutable public object metadata through HEAD.
func (reader *Reader) Stat(ctx context.Context, key string) (provider.Object, error) {
	objectURL, err := reader.objectURL(key)
	if err != nil {
		return provider.Object{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodHead, objectURL.String(), http.NoBody)
	if err != nil {
		return provider.Object{}, fmt.Errorf("create public HTTP metadata request: %w", err)
	}

	response, err := reader.httpClient.Do(request)
	if err != nil {
		return provider.Object{}, fmt.Errorf("read public HTTP metadata: %w", err)
	}

	closeErr := response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		return provider.Object{}, errors.Join(
			fmt.Errorf("%w: HEAD status %d", provider.ErrObjectNotFound, response.StatusCode),
			closeErr,
		)
	}

	if closeErr != nil {
		return provider.Object{}, fmt.Errorf("close public HTTP metadata response: %w", closeErr)
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices || response.ContentLength < 0 {
		return provider.Object{}, fmt.Errorf("%w: HEAD status %d or missing length", ErrInvalidResponse, response.StatusCode)
	}

	version := response.Header.Get("ETag")
	if version == "" {
		version = response.Header.Get("Last-Modified")
	}

	return provider.Object{Key: key, SizeBytes: uint64(response.ContentLength), ETag: response.Header.Get("ETag"), Version: version}, nil
}

// OpenRange opens exactly one HTTP byte range.
func (reader *Reader) OpenRange(
	ctx context.Context,
	key string,
	offset,
	length uint64,
) (io.ReadCloser, error) {
	if length == 0 || offset > ^uint64(0)-(length-1) {
		return nil, fmt.Errorf("%w: range is empty or overflows", ErrInvalidConfiguration)
	}

	objectURL, err := reader.objectURL(key)
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, objectURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create public HTTP range request: %w", err)
	}

	end := offset + length - 1
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
	request.Header.Set("Accept-Encoding", "identity")

	response, err := reader.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read public HTTP range: %w", err)
	}

	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
		closeErr := response.Body.Close()
		return nil, errors.Join(fmt.Errorf("%w: range status %d", provider.ErrObjectNotFound, response.StatusCode), closeErr)
	}

	if response.StatusCode != http.StatusPartialContent ||
		(response.ContentLength >= 0 && uint64(response.ContentLength) != length) ||
		!exactContentRange(response.Header.Get("Content-Range"), offset, end) {
		closeErr := response.Body.Close()

		return nil, errors.Join(
			fmt.Errorf("%w: range status or headers changed", ErrInvalidResponse),
			closeErr,
		)
	}

	return response.Body, nil
}

func (reader *Reader) objectURL(key string) (*url.URL, error) {
	if reader == nil || reader.baseURL == nil {
		return nil, fmt.Errorf("%w: reader is not initialized", ErrInvalidConfiguration)
	}

	if key == "" || strings.Contains(key, "\\") || strings.HasPrefix(key, "/") || path.Clean(key) != key || key == "." || strings.HasPrefix(key, "../") {
		return nil, fmt.Errorf("%w: object key must be a canonical relative slash path", ErrInvalidConfiguration)
	}

	result := *reader.baseURL

	segments := make([]string, 0, strings.Count(key, "/")+1)

	for segment := range strings.SplitSeq(key, "/") {
		if segment == "" {
			return nil, fmt.Errorf("%w: object key contains an empty segment", ErrInvalidConfiguration)
		}

		segments = append(segments, segment)
	}

	result.RawPath = ""
	result.Path = strings.TrimSuffix(result.Path, "/") + "/" + strings.Join(segments, "/")

	return &result, nil
}

func exactContentRange(value string, expectedStart, expectedEnd uint64) bool {
	if !strings.HasPrefix(value, "bytes ") {
		return false
	}

	span, _, found := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !found {
		return false
	}

	start, end, found := strings.Cut(span, "-")
	if !found {
		return false
	}

	parsedStart, startErr := strconv.ParseUint(start, 10, 64)
	parsedEnd, endErr := strconv.ParseUint(end, 10, 64)

	return startErr == nil && endErr == nil && parsedStart == expectedStart && parsedEnd == expectedEnd
}

func safeURL(value *url.URL) bool {
	if value == nil || value.Host == "" {
		return false
	}

	if value.Scheme == "https" {
		return true
	}

	host := value.Hostname()

	return value.Scheme == "http" && (host == "localhost" || net.ParseIP(host).IsLoopback())
}

func sameOrigin(base, target *url.URL) bool {
	return safeURL(target) && strings.EqualFold(base.Scheme, target.Scheme) && strings.EqualFold(base.Host, target.Host)
}

var _ provider.Reader = (*Reader)(nil)
