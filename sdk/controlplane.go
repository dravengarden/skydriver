package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/dravengarden/carrack/manifest"
)

const (
	clientTokenBytes        = 32
	maximumControlBodyBytes = 1 << 20
)

var (
	// ErrInvalidControlPlane indicates an unsafe endpoint, token, or transport.
	ErrInvalidControlPlane = errors.New("invalid Carrack control-plane configuration")
	// ErrControlPlaneResponse indicates a rejected or malformed API response.
	ErrControlPlaneResponse = errors.New("invalid Carrack control-plane response")
)

// ClientToken is a random 256-bit SDK authentication token.
type ClientToken [clientTokenBytes]byte

// ControlClient accesses Carrack metadata APIs. It never sends payload bytes.
type ControlClient struct {
	baseURL    *url.URL
	token      ClientToken
	httpClient *http.Client
}

// ClientSession describes the identity bound to one client token.
type ClientSession struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	SDKVersion string `json:"sdk_version"`
}

// ControlHealth reports whether the current incarnation accepts mutations.
type ControlHealth struct {
	Service             string `json:"service"`
	TransferMode        string `json:"transfer_mode"`
	Mode                string `json:"mode"`
	Incarnation         string `json:"incarnation"`
	Revision            uint64 `json:"revision"`
	ExternalMaintenance bool   `json:"external_maintenance"`
	MutationsAllowed    bool   `json:"mutations_allowed"`
}

// StagedRecovery identifies one portable recovery manifest durably archived in
// the control-plane R2 bucket but not yet published in D1.
type StagedRecovery struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	RecoverySHA256 string `json:"recovery_sha256"`
	NamespaceID    string `json:"namespace_id"`
	ObjectID       string `json:"object_id"`
	Generation     uint64 `json:"generation"`
	R2Key          string `json:"r2_key"`
	R2Version      string `json:"r2_version"`
	Bytes          uint64 `json:"bytes"`
}

// ParseClientToken decodes the one-time base64url token returned at enrollment.
func ParseClientToken(encoded string) (ClientToken, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != clientTokenBytes {
		return ClientToken{}, fmt.Errorf("%w: token must encode exactly 32 bytes", ErrInvalidControlPlane)
	}

	var token ClientToken
	copy(token[:], decoded)

	return token, nil
}

// Clear overwrites this token instance after its client is no longer used.
func (token *ClientToken) Clear() {
	if token == nil {
		return
	}

	clear(token[:])
}

// NewControlClient validates an HTTPS endpoint and copies the token. Plain HTTP
// is accepted only for an explicit loopback address used by local tests.
func NewControlClient(
	endpoint string,
	token ClientToken,
	httpClient *http.Client,
) (*ControlClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: parse endpoint: %w", ErrInvalidControlPlane, err)
	}

	if err := validateControlURL(parsed); err != nil {
		return nil, err
	}

	if allZeroToken(token) {
		return nil, fmt.Errorf("%w: token must not be zero", ErrInvalidControlPlane)
	}

	if httpClient == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", ErrInvalidControlPlane)
	}

	baseURL := *parsed
	baseURL.Path = strings.TrimSuffix(baseURL.Path, "/")

	return &ControlClient{baseURL: &baseURL, token: token, httpClient: httpClient}, nil
}

// Health reads public control-plane availability without sending the token.
func (client *ControlClient) Health(ctx context.Context) (ControlHealth, error) {
	var response ControlHealth
	if err := client.request(ctx, http.MethodGet, "/api/health", "", nil, &response); err != nil {
		return ControlHealth{}, err
	}

	return response, nil
}

// Session verifies the token and returns its bound client identity.
func (client *ControlClient) Session(ctx context.Context) (ClientSession, error) {
	var response ClientSession

	authorization := "Bearer " + base64.RawURLEncoding.EncodeToString(client.token[:])
	if err := client.request(ctx, http.MethodGet, "/api/client/session", authorization, nil, &response); err != nil {
		return ClientSession{}, err
	}

	return response, nil
}

// StageRecovery archives a validated portable manifest in control-plane R2.
// It does not make the object version visible in D1.
func (client *ControlClient) StageRecovery(
	ctx context.Context,
	recovery manifest.RecoveryManifest,
) (StagedRecovery, error) {
	encoded, err := recovery.MarshalCanonical()
	if err != nil {
		return StagedRecovery{}, fmt.Errorf("marshal recovery manifest for staging: %w", err)
	}

	authorization := "Bearer " + base64.RawURLEncoding.EncodeToString(client.token[:])

	var response StagedRecovery

	if err := client.request(
		ctx,
		http.MethodPost,
		"/api/v1/recovery-manifests/stage",
		authorization,
		encoded,
		&response,
	); err != nil {
		return StagedRecovery{}, err
	}

	if response.ManifestSHA256 != recovery.ManifestSHA256 ||
		response.NamespaceID != recovery.Manifest.NamespaceID ||
		response.ObjectID != recovery.Manifest.ObjectID ||
		response.Generation != recovery.Manifest.Generation {
		return StagedRecovery{}, fmt.Errorf(
			"%w: staged recovery identity changed",
			ErrControlPlaneResponse,
		)
	}

	return response, nil
}

func (client *ControlClient) request(
	ctx context.Context,
	method, path string,
	authorization string,
	body []byte,
	destination any,
) error {
	if client == nil || client.baseURL == nil || client.httpClient == nil {
		return fmt.Errorf("%w: control client is not initialized", ErrInvalidControlPlane)
	}

	endpoint := *client.baseURL
	endpoint.Path += path

	requestBody := io.Reader(http.NoBody)
	if body != nil {
		requestBody = bytes.NewReader(body)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return fmt.Errorf("create Carrack control-plane request: %w", err)
	}

	request.Header.Set("Accept", "application/json")

	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send Carrack control-plane request: %w", err)
	}

	limited := io.LimitReader(response.Body, maximumControlBodyBytes+1)
	body, readErr := io.ReadAll(limited)
	closeErr := response.Body.Close()

	if readErr != nil || closeErr != nil {
		return fmt.Errorf(
			"read Carrack control-plane response: %w",
			errors.Join(readErr, closeErr),
		)
	}

	if len(body) > maximumControlBodyBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrControlPlaneResponse, maximumControlBodyBytes)
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: HTTP status %d", ErrControlPlaneResponse, response.StatusCode)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode JSON: %w", ErrControlPlaneResponse, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", ErrControlPlaneResponse)
	}

	return nil
}

func validateControlURL(endpoint *url.URL) error {
	if endpoint.Scheme == "" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("%w: endpoint must be an absolute URL without credentials, query, or fragment", ErrInvalidControlPlane)
	}

	if endpoint.Scheme == "https" {
		return nil
	}

	host := endpoint.Hostname()
	if endpoint.Scheme == "http" && (host == "localhost" || net.ParseIP(host).IsLoopback()) {
		return nil
	}

	return fmt.Errorf("%w: endpoint must use HTTPS outside loopback", ErrInvalidControlPlane)
}

func allZeroToken(token ClientToken) bool {
	var combined byte
	for _, value := range token {
		combined |= value
	}

	return combined == 0
}
