package aliyundrive

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/dravengarden/carrack/provider"
)

type downloadURLRequest struct {
	DriveID  string `json:"drive_id"`
	FileID   string `json:"file_id"`
	ExpireIn int    `json:"expire_sec"`
}

type downloadURLResponse struct {
	URL string `json:"url"`
}

// Stat resolves metadata for an immutable object key.
func (client *Client) Stat(ctx context.Context, key string) (provider.Object, error) {
	file, err := client.resolve(ctx, key)
	if err != nil {
		return provider.Object{}, fmt.Errorf("stat Aliyun Drive object %q: %w", key, err)
	}

	if file.Type == objectTypeFolder {
		return provider.Object{}, fmt.Errorf("stat Aliyun Drive object %q: %w: object is a folder", key, errObjectState)
	}

	return objectFromFile(key, file), nil
}

// OpenRange opens an exact byte range through a short-lived download URL.
func (client *Client) OpenRange(
	ctx context.Context,
	key string,
	offset uint64,
	length uint64,
) (io.ReadCloser, error) {
	if length == 0 {
		return nil, fmt.Errorf("open Aliyun Drive range: %w: length must be positive", errObjectState)
	}

	file, err := client.resolve(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("open Aliyun Drive range for %q: %w", key, err)
	}

	if file.Size < 0 || offset > uint64(file.Size) || length > uint64(file.Size)-offset {
		return nil, fmt.Errorf("open Aliyun Drive range for %q: %w: requested range exceeds object size", key, errObjectState)
	}

	downloadURL, err := client.getDownloadURL(ctx, file.FileID)
	if err != nil {
		return nil, fmt.Errorf("open Aliyun Drive range for %q: %w", key, err)
	}

	if !safeServiceURL(downloadURL) {
		return nil, fmt.Errorf("open Aliyun Drive range for %q: %w: download URL must use HTTPS", key, errInvalidAPIResponse)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create Aliyun Drive download request: %w", err)
	}

	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+length-1))
	request.Header.Set("User-Agent", "carrack/0.1")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download Aliyun Drive object: %w", err)
	}

	if response.StatusCode != http.StatusPartialContent {
		if err := response.Body.Close(); err != nil {
			return nil, fmt.Errorf("close rejected Aliyun Drive download: %w", err)
		}

		return nil, fmt.Errorf("download Aliyun Drive range: %w: HTTP status %d", errInvalidAPIResponse, response.StatusCode)
	}

	return response.Body, nil
}

func (client *Client) getDownloadURL(ctx context.Context, fileID string) (string, error) {
	request := downloadURLRequest{DriveID: client.driveID, FileID: fileID, ExpireIn: 14_400}

	var response downloadURLResponse
	if err := client.doAPI(ctx, requestLink, "/adrive/v1.0/openFile/getDownloadUrl", request, &response); err != nil {
		return "", err
	}

	if response.URL == "" {
		return "", fmt.Errorf("%w: response omitted download URL", errInvalidAPIResponse)
	}

	return response.URL, nil
}

func objectFromFile(key string, file fileRecord) provider.Object {
	size := uint64(0)
	if file.Size > 0 {
		size = uint64(file.Size)
	}

	return provider.Object{
		Key:       key,
		SizeBytes: size,
		ETag:      file.ContentHash,
		Version:   file.FileID,
	}
}

var (
	_ provider.Reader = (*Client)(nil)
	_ provider.Writer = (*Client)(nil)
)
