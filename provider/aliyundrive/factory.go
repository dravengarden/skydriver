package aliyundrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dravengarden/carrack/provider"
)

const (
	// DriverKind identifies the versioned Aliyun Drive Open API contract.
	DriverKind      provider.DriverKind = "aliyundrive-open/v1"
	safeConcurrency                     = uint32(1)
)

// DriverConfig is the non-secret configuration for one Aliyun Drive root.
type DriverConfig struct {
	APIBaseURL      string `json:"api_base_url,omitempty"`
	DriveType       string `json:"drive_type,omitempty"`
	RootFolderID    string `json:"root_folder_id,omitempty"`
	UploadPartBytes uint64 `json:"upload_part_bytes,omitempty"`
}

// DriverCredential contains exactly one Aliyun Drive OAuth credential.
type DriverCredential struct {
	AccessToken   string `json:"access_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
	RenewEndpoint string `json:"renew_endpoint,omitempty"`
	RenewDriver   string `json:"renew_driver,omitempty"`
}

// Factory opens Aliyun Drive clients from control-plane driver specifications.
type Factory struct{}

// Kind returns the versioned registry identifier.
func (Factory) Kind() provider.DriverKind {
	return DriverKind
}

// Open validates typed configuration, resolves a credential grant, and opens
// an Aliyun Drive client without performing network I/O.
func (Factory) Open(
	ctx context.Context,
	specification provider.DriverSpec,
	dependencies provider.Dependencies,
) (provider.Handle, error) {
	configuration, err := decodeStrict[DriverConfig](specification.Config)
	if err != nil {
		return provider.Handle{}, fmt.Errorf("decode Aliyun Drive driver config: %w", err)
	}

	tokenSource, err := openTokenSource(ctx, specification, dependencies)
	if err != nil {
		return provider.Handle{}, err
	}

	client, err := NewClient(Options{
		HTTPClient:      dependencies.HTTPClient,
		TokenSource:     tokenSource,
		APIBaseURL:      configuration.APIBaseURL,
		DriveType:       configuration.DriveType,
		RootFolderID:    configuration.RootFolderID,
		UploadPartBytes: configuration.UploadPartBytes,
	})
	if err != nil {
		return provider.Handle{}, fmt.Errorf("construct Aliyun Drive client: %w", err)
	}

	return provider.Handle{
		ID:   specification.ID,
		Kind: DriverKind,
		Capabilities: provider.Capabilities{
			RangeRead:            true,
			StreamingWrite:       true,
			MaximumObjectBytes:   client.uploadPartBytes * maximumUploadParts,
			PreferredObjectBytes: 1 << 30,
			PreferredPartBytes:   client.uploadPartBytes,
			SafeConcurrency:      safeConcurrency,
		},
		Reader: client,
		Writer: client,
	}, nil
}

func openTokenSource(
	ctx context.Context,
	specification provider.DriverSpec,
	dependencies provider.Dependencies,
) (TokenSource, error) {
	if specification.CredentialRef == "" {
		return nil, fmt.Errorf("%w: credential reference is required", provider.ErrInvalidDriver)
	}

	if dependencies.Credentials == nil {
		return nil, fmt.Errorf("%w: credential store is required", provider.ErrInvalidDriver)
	}

	record, err := dependencies.Credentials.Load(ctx, specification.CredentialRef)
	if err != nil {
		return nil, fmt.Errorf("load Aliyun Drive credential %q: %w", specification.CredentialRef, err)
	}

	credential, err := decodeStrict[DriverCredential](record.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode Aliyun Drive credential %q: %w", specification.CredentialRef, err)
	}

	if (credential.AccessToken == "") == (credential.RefreshToken == "") {
		return nil, fmt.Errorf(
			"%w: credential must contain exactly one access token or refresh token",
			provider.ErrInvalidDriver,
		)
	}

	if credential.AccessToken != "" {
		return NewStaticTokenSource(credential.AccessToken)
	}

	revision := record.Revision
	persist := func(persistContext context.Context, refreshToken string) error {
		credential.RefreshToken = refreshToken

		// The credential store encrypts this payload before persistence. This is
		// intentional secret serialization, never logging or plaintext storage.
		replacement, marshalErr := json.Marshal(credential) //nolint:gosec
		if marshalErr != nil {
			return fmt.Errorf("encode rotated Aliyun Drive credential: %w", marshalErr)
		}

		updated, swapErr := dependencies.Credentials.CompareAndSwap(
			persistContext,
			specification.CredentialRef,
			revision,
			replacement,
		)
		if swapErr != nil {
			return fmt.Errorf("persist rotated Aliyun Drive credential: %w", swapErr)
		}

		revision = updated.Revision

		return nil
	}

	return NewOpenListTokenSource(RenewOptions{
		HTTPClient:          dependencies.HTTPClient,
		Endpoint:            credential.RenewEndpoint,
		RefreshToken:        credential.RefreshToken,
		Driver:              credential.RenewDriver,
		PersistRefreshToken: persist,
	})
}

func decodeStrict[valueType any](encoded json.RawMessage) (valueType, error) {
	var decoded valueType

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&decoded); err != nil {
		return decoded, fmt.Errorf("decode JSON object: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return decoded, fmt.Errorf("decode JSON object: trailing content: %w", err)
	}

	return decoded, nil
}
