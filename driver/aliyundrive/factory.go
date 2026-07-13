// Package aliyundrive adapts the Aliyun Drive Open API to the Carrack VFS V2
// complete-object driver contract.
package aliyundrive

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/provider"
	provideraliyun "github.com/dravengarden/carrack/provider/aliyundrive"
)

const (
	// Kind identifies the compiled Aliyun Drive Open API VFS contract.
	Kind driver.Kind = "aliyundrive-open/v2"

	maximumObjectBytes = uint64(512<<20) * 10_000
	maximumRangeBytes  = uint64(512 << 20)
)

var errInvalidConfiguration = errors.New("invalid Aliyun Drive VFS driver configuration")

var errTrailingJSON = errors.New("trailing JSON")

type configuration struct {
	APIBaseURL      string `json:"api_base_url,omitempty"`
	DriveType       string `json:"drive_type,omitempty"`
	RootFolderID    string `json:"root_folder_id,omitempty"`
	UploadPartBytes uint64 `json:"upload_part_bytes,omitempty"`
}

type credential struct {
	AccessToken string `json:"access_token"`
}

type adapter struct {
	client *provideraliyun.Client
}

// ValidateConfig rejects unknown or unusable non-secret configuration without
// requiring credential material or performing network I/O.
func ValidateConfig(encoded json.RawMessage) error {
	var config configuration
	if err := decodeStrict(encoded, &config); err != nil {
		return fmt.Errorf("%w: config: %w", errInvalidConfiguration, err)
	}

	tokenSource, err := provideraliyun.NewStaticTokenSource("configuration-validation")
	if err != nil {
		return fmt.Errorf("%w: validation token source: %w", errInvalidConfiguration, err)
	}

	_, err = provideraliyun.NewClient(provideraliyun.Options{
		TokenSource:     tokenSource,
		APIBaseURL:      config.APIBaseURL,
		DriveType:       config.DriveType,
		RootFolderID:    config.RootFolderID,
		UploadPartBytes: config.UploadPartBytes,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidConfiguration, err)
	}

	return nil
}

// Factory strictly validates one authorized grant and opens an Aliyun Drive
// client without performing network I/O.
func Factory(_ context.Context, instance driver.Instance) (driver.Handle, error) {
	if instance.Kind != Kind {
		return driver.Handle{}, fmt.Errorf("%w: kind differs", errInvalidConfiguration)
	}

	if err := ValidateConfig(instance.Config); err != nil {
		return driver.Handle{}, err
	}

	var config configuration
	if err := decodeStrict(instance.Config, &config); err != nil {
		return driver.Handle{}, fmt.Errorf("%w: config: %w", errInvalidConfiguration, err)
	}

	var secret credential
	if err := decodeStrict(instance.Credential, &secret); err != nil || secret.AccessToken == "" {
		return driver.Handle{}, fmt.Errorf("%w: credential must contain one access token", errInvalidConfiguration)
	}

	tokenSource, err := provideraliyun.NewStaticTokenSource(secret.AccessToken)
	if err != nil {
		return driver.Handle{}, fmt.Errorf("%w: access token: %w", errInvalidConfiguration, err)
	}

	client, err := provideraliyun.NewClient(provideraliyun.Options{
		TokenSource:     tokenSource,
		APIBaseURL:      config.APIBaseURL,
		DriveType:       config.DriveType,
		RootFolderID:    config.RootFolderID,
		UploadPartBytes: config.UploadPartBytes,
	})
	if err != nil {
		return driver.Handle{}, fmt.Errorf("%w: %w", errInvalidConfiguration, err)
	}

	opened := &adapter{client: client}

	return driver.Handle{
		Descriptor: driver.Descriptor{
			ID:      instance.ID,
			Kind:    Kind,
			Summary: "Aliyun Drive Open API complete-object storage",
			Capabilities: driver.Capabilities{
				Read: driver.ReadCapabilities{
					Complete:          driver.SupportNative,
					Range:             driver.SupportNative,
					MaxParallelRanges: 1,
					MaximumRangeBytes: maximumRangeBytes,
				},
				Write: driver.WriteCapabilities{
					Complete:      driver.SupportNative,
					Resume:        driver.SupportUnavailable,
					ParallelParts: driver.SupportUnavailable,
					PartOrdering:  driver.PartOrderingNone,
				},
				Delete:         driver.SupportUnavailable,
				Inventory:      driver.SupportUnavailable,
				ServerSideCopy: driver.SupportUnavailable,
				Integrity: driver.IntegrityCapabilities{
					StrongUploadChecksum: driver.SupportUnavailable,
					RequiresReadback:     true,
				},
				MaximumObjectBytes: maximumObjectBytes,
				SafeConcurrency:    1,
			},
		},
		Reader:      opened,
		RangeReader: opened,
		Writer:      opened,
	}, nil
}

func (opened *adapter) Stat(ctx context.Context, storageKey string) (driver.Object, error) {
	object, err := opened.client.Stat(ctx, storageKey)
	if err != nil {
		return driver.Object{}, fmt.Errorf("stat Aliyun Drive VFS object: %w", err)
	}

	return fromProviderObject(object), nil
}

func (opened *adapter) Open(ctx context.Context, object driver.Object) (io.ReadCloser, error) {
	if object.SizeBytes == 0 {
		current, err := opened.Stat(ctx, object.Locator.StorageKey)
		if err != nil {
			return nil, err
		}

		if current != object {
			return nil, fmt.Errorf("%w: zero-length object identity changed", driver.ErrInvalidDriver)
		}

		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	return opened.OpenRange(ctx, object, 0, object.SizeBytes)
}

func (opened *adapter) OpenRange(
	ctx context.Context,
	object driver.Object,
	offset uint64,
	length uint64,
) (io.ReadCloser, error) {
	reader, err := opened.client.OpenPinnedRange(ctx, toProviderObject(object), offset, length)
	if err != nil {
		return nil, fmt.Errorf("open Aliyun Drive VFS range: %w", err)
	}

	return reader, nil
}

func (opened *adapter) Put(ctx context.Context, request driver.PutRequest) (driver.Object, error) {
	if request.Body == nil || !validSHA256(request.Checksum) {
		return driver.Object{}, fmt.Errorf("%w: invalid Aliyun Drive put request", driver.ErrInvalidDriver)
	}

	object, err := opened.client.Put(ctx, request.StorageKey, request.Body, provider.PutOptions{
		SizeBytes: request.SizeBytes,
		SHA256:    request.Checksum,
	})
	if err != nil {
		return driver.Object{}, fmt.Errorf("put Aliyun Drive VFS object: %w", err)
	}

	return fromProviderObject(object), nil
}

func decodeStrict(encoded json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errTrailingJSON
	}

	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)

	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func fromProviderObject(object provider.Object) driver.Object {
	return driver.Object{
		Locator: driver.Locator{
			StorageKey: object.Key,
			NativeID:   object.Version,
			Version:    object.Version,
			ETag:       object.ETag,
		},
		SizeBytes: object.SizeBytes,
	}
}

func toProviderObject(object driver.Object) provider.Object {
	return provider.Object{
		Key:       object.Locator.StorageKey,
		SizeBytes: object.SizeBytes,
		ETag:      object.Locator.ETag,
		Version:   object.Locator.Version,
	}
}

var (
	_ driver.Reader      = (*adapter)(nil)
	_ driver.RangeReader = (*adapter)(nil)
	_ driver.Writer      = (*adapter)(nil)
)
