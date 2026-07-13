package aliyundrive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

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

	return client.openResolvedRange(ctx, key, file, offset, length, uint64(file.Size))
}

// OpenPinnedRange opens an exact range only when the current immutable object
// still matches every identity field observed by Stat.
func (client *Client) OpenPinnedRange(
	ctx context.Context,
	object provider.Object,
	offset uint64,
	length uint64,
) (io.ReadCloser, error) {
	if length == 0 {
		return nil, fmt.Errorf("open Aliyun Drive pinned range: %w: length must be positive", errObjectState)
	}

	file, err := client.resolve(ctx, object.Key)
	if err != nil {
		return nil, fmt.Errorf("open Aliyun Drive pinned range for %q: %w", object.Key, err)
	}

	current := objectFromFile(object.Key, file)
	if current != object {
		return nil, fmt.Errorf("open Aliyun Drive pinned range for %q: %w: object identity changed", object.Key, errObjectState)
	}

	if offset > current.SizeBytes || length > current.SizeBytes-offset {
		return nil, fmt.Errorf("open Aliyun Drive pinned range for %q: %w: requested range exceeds object size", object.Key, errObjectState)
	}

	return client.openResolvedRange(ctx, object.Key, file, offset, length, current.SizeBytes)
}

func (client *Client) openResolvedRange(
	ctx context.Context,
	key string,
	file fileRecord,
	offset uint64,
	length uint64,
	totalBytes uint64,
) (io.ReadCloser, error) {
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

	end := offset + length - 1
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "carrack/0.1")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download Aliyun Drive object: %w", err)
	}

	if response.StatusCode != http.StatusPartialContent ||
		(response.ContentLength >= 0 && uint64(response.ContentLength) != length) ||
		!exactDownloadContentRange(
			response.Header.Get("Content-Range"),
			offset,
			end,
			totalBytes,
		) {
		closeErr := response.Body.Close()

		return nil, errors.Join(
			fmt.Errorf(
				"download Aliyun Drive range: %w: HTTP status or range headers changed",
				errInvalidAPIResponse,
			),
			closeErr,
		)
	}

	return response.Body, nil
}

func exactDownloadContentRange(value string, expectedStart, expectedEnd, expectedTotal uint64) bool {
	if !strings.HasPrefix(value, "bytes ") {
		return false
	}

	span, total, found := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !found {
		return false
	}

	start, end, found := strings.Cut(span, "-")
	if !found {
		return false
	}

	parsedStart, startErr := strconv.ParseUint(start, 10, 64)
	parsedEnd, endErr := strconv.ParseUint(end, 10, 64)
	parsedTotal, totalErr := strconv.ParseUint(total, 10, 64)

	return startErr == nil && endErr == nil && totalErr == nil &&
		parsedStart == expectedStart && parsedEnd == expectedEnd && parsedTotal == expectedTotal
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
