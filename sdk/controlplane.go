package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dravengarden/carrack/manifest"
)

const (
	clientTokenBytes        = 32
	maximumControlBodyBytes = 64 << 20

	// ProtocolEpoch is the incompatible Carrack wire-protocol generation.
	ProtocolEpoch = 2
	// SDKVersion is sent on every request so the server can fail before I/O.
	SDKVersion = "0.3.0"
)

var (
	// ErrInvalidControlPlane indicates an unsafe endpoint, token, or transport.
	ErrInvalidControlPlane = errors.New("invalid Carrack control-plane configuration")
	// ErrControlPlaneResponse indicates a rejected or malformed API response.
	ErrControlPlaneResponse = errors.New("invalid Carrack control-plane response")
	// ErrUpgradeRequired indicates that the server rejected this protocol or SDK version.
	ErrUpgradeRequired = errors.New("carrack SDK upgrade required")
)

// UpgradeRequiredError is the machine-readable HTTP 426 compatibility failure.
type UpgradeRequiredError struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	ProtocolEpoch     uint64 `json:"protocol_epoch"`
	MinimumSDKVersion string `json:"minimum_sdk_version"`
	ServerVersion     string `json:"server_version"`
	UpgradeCommand    string `json:"upgrade_command"`
	Schema            string `json:"schema"`
}

func (failure UpgradeRequiredError) Error() string {
	return fmt.Sprintf(
		"%v: protocol epoch %d requires SDK %s or newer (%s)",
		ErrUpgradeRequired,
		failure.ProtocolEpoch,
		failure.MinimumSDKVersion,
		failure.UpgradeCommand,
	)
}

// Unwrap supports errors.Is(err, ErrUpgradeRequired).
func (UpgradeRequiredError) Unwrap() error { return ErrUpgradeRequired }

// ProtocolCompatibility is the public fail-fast contract for this server.
type ProtocolCompatibility struct {
	Schema            string `json:"schema"`
	ProtocolEpoch     uint64 `json:"protocol_epoch"`
	MinimumSDKVersion string `json:"minimum_sdk_version"`
	ServerVersion     string `json:"server_version"`
	Enforcement       string `json:"enforcement"`
	UpgradeCommand    string `json:"upgrade_command"`
}

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
	Environment         string `json:"environment"`
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
	if err := client.request(ctx, http.MethodGet, "/api/health", "", "", nil, &response); err != nil {
		return ControlHealth{}, err
	}

	return response, nil
}

// CheckCompatibility fails before callers perform metadata mutations or provider I/O.
func (client *ControlClient) CheckCompatibility(ctx context.Context) (ProtocolCompatibility, error) {
	var response ProtocolCompatibility
	if err := client.request(ctx, http.MethodGet, "/api/compatibility", "", "", nil, &response); err != nil {
		return ProtocolCompatibility{}, err
	}

	if response.Schema != "carrack.protocol-compatibility.v1" ||
		response.ProtocolEpoch != ProtocolEpoch ||
		response.Enforcement != "required" ||
		!versionAtLeast(SDKVersion, response.MinimumSDKVersion) ||
		!validControlString(response.ServerVersion, 128) ||
		!validControlString(response.UpgradeCommand, 512) {
		return ProtocolCompatibility{}, UpgradeRequiredError{
			Code:              "sdk_upgrade_required",
			Message:           "Carrack protocol or SDK version is incompatible",
			ProtocolEpoch:     response.ProtocolEpoch,
			MinimumSDKVersion: response.MinimumSDKVersion,
			ServerVersion:     response.ServerVersion,
			UpgradeCommand:    response.UpgradeCommand,
			Schema:            "carrack.protocol-error.v1",
		}
	}

	return response, nil
}

// Session verifies the token and returns its bound client identity.
func (client *ControlClient) Session(ctx context.Context) (ClientSession, error) {
	var response ClientSession

	authorization := "Bearer " + base64.RawURLEncoding.EncodeToString(client.token[:])
	if err := client.request(ctx, http.MethodGet, "/api/client/session", authorization, "", nil, &response); err != nil {
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

	var response StagedRecovery

	if err := client.authenticatedPost(
		ctx,
		"/api/v1/recovery-manifests/stage",
		encoded,
		&response,
	); err != nil {
		return StagedRecovery{}, err
	}

	recoveryDigest := sha256.Sum256(encoded)

	if response.ManifestSHA256 != recovery.ManifestSHA256 ||
		response.NamespaceID != recovery.Manifest.NamespaceID ||
		response.ObjectID != recovery.Manifest.ObjectID ||
		response.Generation != recovery.Manifest.Generation ||
		response.RecoverySHA256 != hex.EncodeToString(recoveryDigest[:]) ||
		!validControlString(response.R2Key, 4_096) ||
		!validControlString(response.R2Version, 1_024) ||
		response.Bytes != uint64(len(encoded)) {
		return StagedRecovery{}, fmt.Errorf(
			"%w: staged recovery identity changed",
			ErrControlPlaneResponse,
		)
	}

	return response, nil
}

func (client *ControlClient) authenticatedPost(
	ctx context.Context,
	path string,
	body []byte,
	destination any,
) error {
	if client == nil {
		return fmt.Errorf("%w: control client is not initialized", ErrInvalidControlPlane)
	}

	authorization := "Bearer " + base64.RawURLEncoding.EncodeToString(client.token[:])

	return client.request(ctx, http.MethodPost, path, authorization, "application/json", body, destination)
}

func (client *ControlClient) authenticatedGet(
	ctx context.Context,
	path string,
	query url.Values,
	destination any,
) error {
	if client == nil {
		return fmt.Errorf("%w: control client is not initialized", ErrInvalidControlPlane)
	}

	authorization := "Bearer " + base64.RawURLEncoding.EncodeToString(client.token[:])

	return client.requestWithQuery(
		ctx,
		http.MethodGet,
		path,
		query,
		authorization,
		"",
		nil,
		destination,
	)
}

func (client *ControlClient) authenticatedBinaryPost(
	ctx context.Context,
	path string,
	body []byte,
	destination any,
) error {
	if client == nil {
		return fmt.Errorf("%w: control client is not initialized", ErrInvalidControlPlane)
	}

	authorization := "Bearer " + base64.RawURLEncoding.EncodeToString(client.token[:])

	return client.request(ctx, http.MethodPost, path, authorization, "application/octet-stream", body, destination)
}

func (client *ControlClient) request(
	ctx context.Context,
	method, path string,
	authorization, contentType string,
	body []byte,
	destination any,
) error {
	return client.requestWithQuery(
		ctx,
		method,
		path,
		nil,
		authorization,
		contentType,
		body,
		destination,
	)
}

func (client *ControlClient) requestWithQuery(
	ctx context.Context,
	method, path string,
	query url.Values,
	authorization, contentType string,
	body []byte,
	destination any,
) error {
	if client == nil || client.baseURL == nil || client.httpClient == nil {
		return fmt.Errorf("%w: control client is not initialized", ErrInvalidControlPlane)
	}

	endpoint := *client.baseURL
	endpoint.Path += path
	endpoint.RawQuery = query.Encode()

	requestBody := io.Reader(http.NoBody)
	if body != nil {
		requestBody = bytes.NewReader(body)
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), requestBody)
	if err != nil {
		return fmt.Errorf("create Carrack control-plane request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("Carrack-Protocol-Epoch", strconv.FormatUint(ProtocolEpoch, 10))
	request.Header.Set("Carrack-Sdk-Version", SDKVersion)

	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}

	if body != nil && contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send Carrack control-plane request: %w", err)
	}

	return decodeControlResponse(response, destination)
}

func decodeControlResponse(response *http.Response, destination any) error {
	limited := io.LimitReader(response.Body, maximumControlBodyBytes+1)
	responseBody, readErr := io.ReadAll(limited)
	closeErr := response.Body.Close()

	if readErr != nil || closeErr != nil {
		return fmt.Errorf(
			"read Carrack control-plane response: %w",
			errors.Join(readErr, closeErr),
		)
	}

	if len(responseBody) > maximumControlBodyBytes {
		return fmt.Errorf("%w: body exceeds %d bytes", ErrControlPlaneResponse, maximumControlBodyBytes)
	}

	if response.StatusCode == http.StatusUpgradeRequired {
		return decodeUpgradeRequired(responseBody)
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: HTTP status %d", ErrControlPlaneResponse, response.StatusCode)
	}

	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode JSON: %w", ErrControlPlaneResponse, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", ErrControlPlaneResponse)
	}

	return nil
}

func decodeUpgradeRequired(body []byte) error {
	var failure UpgradeRequiredError

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&failure); err == nil &&
		failure.Schema == "carrack.protocol-error.v1" &&
		failure.Code == "sdk_upgrade_required" &&
		failure.ProtocolEpoch > 0 &&
		validControlString(failure.MinimumSDKVersion, 128) &&
		validControlString(failure.UpgradeCommand, 512) {
		return failure
	}

	return fmt.Errorf("%w: malformed HTTP 426 response", ErrUpgradeRequired)
}

func versionAtLeast(candidate, minimum string) bool {
	current, currentOK := parseSDKVersion(candidate)
	required, requiredOK := parseSDKVersion(minimum)

	if !currentOK || !requiredOK {
		return false
	}

	for index := range current {
		if current[index] != required[index] {
			return current[index] > required[index]
		}
	}

	return true
}

func parseSDKVersion(value string) ([3]uint64, bool) {
	core, _, _ := strings.Cut(value, "-")
	fields := strings.Split(core, ".")

	if len(fields) != 3 || strings.Contains(value, "+") {
		return [3]uint64{}, false
	}

	var result [3]uint64

	for index, field := range fields {
		if field == "" || (len(field) > 1 && field[0] == '0') {
			return [3]uint64{}, false
		}

		parsed, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return [3]uint64{}, false
		}

		result[index] = parsed
	}

	return result, true
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
