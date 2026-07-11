package aliyundrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

const (
	defaultAPIBaseURL       = "https://openapi.alipan.com"
	defaultDriveType        = "resource"
	defaultRootFolderID     = "root"
	defaultUploadPartBytes  = uint64(20 << 20)
	maximumUploadPartBytes  = uint64(512 << 20)
	maximumAPIResponseBytes = int64(8 << 20)
	maximumUploadParts      = uint64(10_000)
)

var (
	// ErrInvalidConfiguration indicates an unusable Aliyun Drive client setup.
	ErrInvalidConfiguration = errors.New("invalid Aliyun Drive configuration")
	errInvalidAPIResponse   = errors.New("invalid Aliyun Drive API response")
	errUnknownRequestClass  = errors.New("unknown Aliyun Drive request class")
	errObjectState          = errors.New("invalid Aliyun Drive object state")
	errUpload               = errors.New("upload to Aliyun Drive failed")
)

const (
	objectTypeFolder = "folder"
	objectTypeFile   = "file"
)

// Options configures an Aliyun Drive provider client.
type Options struct {
	HTTPClient      *http.Client
	TokenSource     TokenSource
	APIBaseURL      string
	DriveType       string
	RootFolderID    string
	UploadPartBytes uint64
}

// Client implements Carrack provider access to one Aliyun Drive root.
type Client struct {
	httpClient      *http.Client
	tokenSource     TokenSource
	apiBaseURL      string
	driveType       string
	rootFolderID    string
	uploadPartBytes uint64
	limiters        requestLimiters

	initializationMutex sync.Mutex
	driveID             string
}

type requestClass uint8

const (
	requestList requestClass = iota
	requestLink
	requestOther
)

type requestLimiters struct {
	list  *rate.Limiter
	link  *rate.Limiter
	other *rate.Limiter
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type driveInfoResponse struct {
	DefaultDriveID  string `json:"default_drive_id"`
	ResourceDriveID string `json:"resource_drive_id"`
	BackupDriveID   string `json:"backup_drive_id"`
}

func (apiErr apiError) Error() string {
	return fmt.Sprintf("Aliyun Drive API %s: %s", apiErr.Code, apiErr.Message)
}

// NewClient validates options without performing network I/O.
func NewClient(options Options) (*Client, error) {
	if options.TokenSource == nil {
		return nil, fmt.Errorf("%w: token source is required", ErrInvalidConfiguration)
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	apiBaseURL := strings.TrimRight(options.APIBaseURL, "/")
	if apiBaseURL == "" {
		apiBaseURL = defaultAPIBaseURL
	}

	if !safeServiceURL(apiBaseURL) {
		return nil, fmt.Errorf("%w: API base URL must use HTTPS or loopback HTTP", ErrInvalidConfiguration)
	}

	driveType := options.DriveType
	if driveType == "" {
		driveType = defaultDriveType
	}

	if driveType != "default" && driveType != "resource" && driveType != "backup" {
		return nil, fmt.Errorf("%w: unsupported drive type %q", ErrInvalidConfiguration, driveType)
	}

	rootFolderID := options.RootFolderID
	if rootFolderID == "" {
		rootFolderID = defaultRootFolderID
	}

	uploadPartBytes := options.UploadPartBytes
	if uploadPartBytes == 0 {
		uploadPartBytes = defaultUploadPartBytes
	}

	if uploadPartBytes > maximumUploadPartBytes {
		return nil, fmt.Errorf("%w: upload part size exceeds %d bytes", ErrInvalidConfiguration, maximumUploadPartBytes)
	}

	return &Client{
		httpClient:      httpClient,
		tokenSource:     options.TokenSource,
		apiBaseURL:      apiBaseURL,
		driveType:       driveType,
		rootFolderID:    rootFolderID,
		uploadPartBytes: uploadPartBytes,
		limiters: requestLimiters{
			list:  rate.NewLimiter(rate.Limit(3.9), 1),
			link:  rate.NewLimiter(rate.Limit(0.9), 1),
			other: rate.NewLimiter(rate.Limit(14.9), 1),
		},
		driveID: "",
	}, nil
}

func (client *Client) initialize(ctx context.Context) error {
	client.initializationMutex.Lock()
	defer client.initializationMutex.Unlock()

	if client.driveID != "" {
		return nil
	}

	var info driveInfoResponse
	if err := client.doAPI(ctx, requestOther, "/adrive/v1.0/user/getDriveInfo", nil, &info); err != nil {
		return fmt.Errorf("get Aliyun Drive information: %w", err)
	}

	switch client.driveType {
	case "default":
		client.driveID = info.DefaultDriveID
	case "resource":
		client.driveID = info.ResourceDriveID
	case "backup":
		client.driveID = info.BackupDriveID
	default:
		return fmt.Errorf("%w: unsupported drive type %q", ErrInvalidConfiguration, client.driveType)
	}

	if client.driveID == "" {
		return fmt.Errorf("%w: response omitted %s drive ID", errInvalidAPIResponse, client.driveType)
	}

	return nil
}

func (client *Client) doAPI(
	ctx context.Context,
	class requestClass,
	endpoint string,
	requestBody any,
	responseBody any,
) error {
	err := client.doAPIOnce(ctx, class, endpoint, requestBody, responseBody)
	if err == nil {
		return nil
	}

	var responseErr apiError
	if !errors.As(err, &responseErr) || !accessTokenExpired(responseErr.Code) {
		return err
	}

	client.tokenSource.Invalidate()

	return client.doAPIOnce(ctx, class, endpoint, requestBody, responseBody)
}

func (client *Client) doAPIOnce(
	ctx context.Context,
	class requestClass,
	endpoint string,
	requestBody any,
	responseBody any,
) error {
	if err := client.wait(ctx, class); err != nil {
		return fmt.Errorf("wait for Aliyun Drive rate limit: %w", err)
	}

	accessToken, err := client.tokenSource.AccessToken(ctx)
	if err != nil {
		return fmt.Errorf("get Aliyun Drive access token: %w", err)
	}

	encodedBody, err := encodeRequestBody(requestBody)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.apiBaseURL+endpoint, encodedBody)
	if err != nil {
		return fmt.Errorf("create Aliyun Drive API request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("User-Agent", "carrack/0.1")

	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := client.httpClient.Do(request) //nolint:bodyclose // readAndCloseLimited closes every response body.
	if err != nil {
		return fmt.Errorf("call Aliyun Drive API: %w", err)
	}

	body, err := readAndCloseLimited(response.Body, maximumAPIResponseBytes)
	if err != nil {
		return fmt.Errorf("read Aliyun Drive API response: %w", err)
	}

	parsedAPIError := decodeAPIError(body)
	if parsedAPIError.Code != "" {
		return parsedAPIError
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: HTTP status %d", errInvalidAPIResponse, response.StatusCode)
	}

	if responseBody != nil && len(body) > 0 {
		if err := json.Unmarshal(body, responseBody); err != nil {
			return fmt.Errorf("decode Aliyun Drive API response: %w", err)
		}
	}

	return nil
}

func (client *Client) wait(ctx context.Context, class requestClass) error {
	var err error

	switch class {
	case requestList:
		err = client.limiters.list.Wait(ctx)
	case requestLink:
		err = client.limiters.link.Wait(ctx)
	case requestOther:
		err = client.limiters.other.Wait(ctx)
	default:
		return errUnknownRequestClass
	}

	if err != nil {
		return fmt.Errorf("request limiter for Aliyun Drive: %w", err)
	}

	return nil
}

func encodeRequestBody(body any) (io.Reader, error) {
	if body == nil {
		return http.NoBody, nil
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode Aliyun Drive API request: %w", err)
	}

	return bytes.NewReader(encoded), nil
}

func decodeAPIError(body []byte) apiError {
	var parsed apiError
	if len(body) > 0 {
		if err := json.Unmarshal(body, &parsed); err != nil {
			return apiError{}
		}
	}

	return parsed
}

func accessTokenExpired(code string) bool {
	return code == "AccessTokenInvalid" || code == "AccessTokenExpired" || code == "I400JD"
}

func safeServiceURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}

	if parsed.Scheme == "https" {
		return true
	}

	hostname := parsed.Hostname()
	ipAddress := net.ParseIP(hostname)

	return parsed.Scheme == "http" && (hostname == "localhost" || ipAddress != nil && ipAddress.IsLoopback())
}
