// Package aliyundrive implements Carrack storage access through the official
// Aliyun Drive Open API.
package aliyundrive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

const (
	defaultRenewEndpoint = "https://api.oplist.org/alicloud/renewapi"
	defaultRenewDriver   = "alicloud_qr"
	maximumTokenResponse = 1 << 20
)

var (
	// ErrInvalidTokenConfiguration indicates incomplete or unsafe token settings.
	ErrInvalidTokenConfiguration = errors.New("invalid Aliyun Drive token configuration")
	errTokenRenewal              = errors.New("token renewal for Aliyun Drive failed")
	errResponseTooLarge          = errors.New("response exceeds size limit")
)

// TokenSource supplies and invalidates bearer tokens used by the Open API.
type TokenSource interface {
	AccessToken(ctx context.Context) (string, error)
	Invalidate()
}

// RefreshTokenPersister stores a rotated refresh token before Carrack uses it.
type RefreshTokenPersister func(ctx context.Context, refreshToken string) error

// RenewOptions configures the OpenList-compatible renewal endpoint.
type RenewOptions struct {
	HTTPClient          *http.Client
	Endpoint            string
	RefreshToken        string
	Driver              string
	PersistRefreshToken RefreshTokenPersister
}

// StaticTokenSource supplies a caller-managed access token.
type StaticTokenSource struct {
	token string
}

// OpenListTokenSource renews the same OAuth token format used by OpenList.
// It does not require an OpenList server process.
type OpenListTokenSource struct {
	httpClient          *http.Client
	endpoint            string
	driver              string
	persistRefreshToken RefreshTokenPersister

	mutex        sync.Mutex
	refreshToken string
	accessToken  string
}

type renewResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	ErrorMessage string `json:"text"`
}

// NewStaticTokenSource validates and stores a fixed access token.
func NewStaticTokenSource(token string) (*StaticTokenSource, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: access token is required", ErrInvalidTokenConfiguration)
	}

	return &StaticTokenSource{token: token}, nil
}

// AccessToken returns the fixed token.
func (source *StaticTokenSource) AccessToken(_ context.Context) (string, error) {
	return source.token, nil
}

// Invalidate is a no-op because the caller owns fixed-token rotation.
func (*StaticTokenSource) Invalidate() {}

// NewOpenListTokenSource constructs a lazy, concurrency-safe token source.
func NewOpenListTokenSource(options RenewOptions) (*OpenListTokenSource, error) {
	if options.RefreshToken == "" {
		return nil, fmt.Errorf("%w: refresh token is required", ErrInvalidTokenConfiguration)
	}

	client := options.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := options.Endpoint
	if endpoint == "" {
		endpoint = defaultRenewEndpoint
	}

	if !safeServiceURL(endpoint) {
		return nil, fmt.Errorf("%w: renewal endpoint must use HTTPS or loopback HTTP", ErrInvalidTokenConfiguration)
	}

	driver := options.Driver
	if driver == "" {
		driver = defaultRenewDriver
	}

	return &OpenListTokenSource{
		httpClient:          client,
		endpoint:            endpoint,
		driver:              driver,
		persistRefreshToken: options.PersistRefreshToken,
		refreshToken:        options.RefreshToken,
		accessToken:         "",
	}, nil
}

// AccessToken returns a cached token or renews it through the configured API.
func (source *OpenListTokenSource) AccessToken(ctx context.Context) (string, error) {
	source.mutex.Lock()
	defer source.mutex.Unlock()

	if source.accessToken != "" {
		return source.accessToken, nil
	}

	token, err := source.renew(ctx)
	if err != nil {
		return "", err
	}

	if token.RefreshToken != source.refreshToken && source.persistRefreshToken != nil {
		if err := source.persistRefreshToken(ctx, token.RefreshToken); err != nil {
			return "", fmt.Errorf("persist rotated Aliyun Drive refresh token: %w", err)
		}
	}

	source.refreshToken = token.RefreshToken
	source.accessToken = token.AccessToken

	return source.accessToken, nil
}

// Invalidate drops the cached access token so the next request renews it.
func (source *OpenListTokenSource) Invalidate() {
	source.mutex.Lock()
	defer source.mutex.Unlock()

	source.accessToken = ""
}

func (source *OpenListTokenSource) renew(ctx context.Context) (renewResponse, error) {
	endpoint, err := url.Parse(source.endpoint)
	if err != nil {
		return renewResponse{}, fmt.Errorf("parse Aliyun Drive renewal endpoint: %w", err)
	}

	query := endpoint.Query()
	query.Set("refresh_ui", source.refreshToken)
	query.Set("server_use", "true")
	query.Set("driver_txt", source.driver)
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return renewResponse{}, fmt.Errorf("create Aliyun Drive token request: %w", err)
	}

	response, err := source.httpClient.Do(request) //nolint:bodyclose // readAndCloseLimited closes every response body.
	if err != nil {
		return renewResponse{}, fmt.Errorf("renew Aliyun Drive token: %w", err)
	}

	body, err := readAndCloseLimited(response.Body, maximumTokenResponse)
	if err != nil {
		return renewResponse{}, fmt.Errorf("read Aliyun Drive token response: %w", err)
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return renewResponse{}, fmt.Errorf("%w: HTTP status %d", errTokenRenewal, response.StatusCode)
	}

	var token renewResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return renewResponse{}, fmt.Errorf("decode Aliyun Drive token response: %w", err)
	}

	if token.AccessToken == "" || token.RefreshToken == "" {
		if token.ErrorMessage != "" {
			return renewResponse{}, fmt.Errorf("%w: %s", errTokenRenewal, token.ErrorMessage)
		}

		return renewResponse{}, fmt.Errorf("%w: endpoint returned an empty token", errTokenRenewal)
	}

	return token, nil
}

func readLimited(reader io.Reader, maximum int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read limited response: %w", err)
	}

	if int64(len(body)) > maximum {
		return nil, errResponseTooLarge
	}

	return body, nil
}

func readAndCloseLimited(body io.ReadCloser, maximum int64) ([]byte, error) {
	contents, readErr := readLimited(body, maximum)
	closeErr := body.Close()

	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}

	return contents, nil
}
