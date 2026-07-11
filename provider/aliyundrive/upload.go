package aliyundrive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dravengarden/carrack/provider"
)

const uploadAttempts = 3

type partRequest struct {
	PartNumber int `json:"part_number"`
}

type partInformation struct {
	PartNumber int    `json:"part_number"`
	UploadURL  string `json:"upload_url"`
}

type createFileRequest struct {
	DriveID       string        `json:"drive_id"`
	ParentFileID  string        `json:"parent_file_id"`
	Name          string        `json:"name"`
	Type          string        `json:"type"`
	CheckNameMode string        `json:"check_name_mode"`
	PartInfoList  []partRequest `json:"part_info_list"`
}

type createFileResponse struct {
	FileID       string            `json:"file_id"`
	UploadID     string            `json:"upload_id"`
	RapidUpload  bool              `json:"rapid_upload"`
	PartInfoList []partInformation `json:"part_info_list"`
}

type completeFileRequest struct {
	DriveID  string `json:"drive_id"`
	FileID   string `json:"file_id"`
	UploadID string `json:"upload_id"`
}

// Put uploads one immutable Carrack object with bounded-memory multipart I/O.
func (client *Client) Put(
	ctx context.Context,
	key string,
	body io.Reader,
	options provider.PutOptions,
) (provider.Object, error) {
	if body == nil {
		return provider.Object{}, fmt.Errorf("%w: body is required", errUpload)
	}

	if options.SizeBytes == 0 {
		return provider.Object{}, fmt.Errorf("%w: size must be positive", errUpload)
	}

	partCount := 1 + (options.SizeBytes-1)/client.uploadPartBytes
	if partCount > maximumUploadParts {
		return provider.Object{}, fmt.Errorf("%w: %d parts exceeds limit %d", errUpload, partCount, maximumUploadParts)
	}

	parent, name, err := client.ensureParent(ctx, key)
	if err != nil {
		return provider.Object{}, fmt.Errorf("prepare Aliyun Drive destination %q: %w", key, err)
	}

	upload, err := client.createFile(ctx, parent.FileID, name, partCount)
	if err != nil {
		return client.resolveExistingUpload(ctx, key, options.SizeBytes, err)
	}

	if uploadErr := client.uploadParts(ctx, body, options.SizeBytes, upload.PartInfoList); uploadErr != nil {
		return provider.Object{}, fmt.Errorf("upload Aliyun Drive object %q: %w", key, uploadErr)
	}

	created, err := client.completeFile(ctx, upload.FileID, upload.UploadID)
	if err != nil {
		return provider.Object{}, fmt.Errorf("complete Aliyun Drive object %q: %w", key, err)
	}

	return objectFromFile(key, created), nil
}

func (client *Client) createFile(
	ctx context.Context,
	parentID string,
	name string,
	partCount uint64,
) (createFileResponse, error) {
	parts := make([]partRequest, partCount)
	for index := range parts {
		parts[index] = partRequest{PartNumber: index + 1}
	}

	request := createFileRequest{
		DriveID:       client.driveID,
		ParentFileID:  parentID,
		Name:          name,
		Type:          objectTypeFile,
		CheckNameMode: "refuse",
		PartInfoList:  parts,
	}

	var response createFileResponse
	if err := client.doAPI(ctx, requestOther, "/adrive/v1.0/openFile/create", request, &response); err != nil {
		return createFileResponse{}, err
	}

	if response.FileID == "" || response.UploadID == "" {
		return createFileResponse{}, fmt.Errorf("%w: create file response omitted upload identity", errInvalidAPIResponse)
	}

	if response.RapidUpload {
		return createFileResponse{}, fmt.Errorf("%w: unexpected rapid upload response", errInvalidAPIResponse)
	}

	if uint64(len(response.PartInfoList)) != partCount {
		return createFileResponse{}, fmt.Errorf(
			"%w: create file response returned %d upload parts, expected %d",
			errInvalidAPIResponse,
			len(response.PartInfoList),
			partCount,
		)
	}

	return response, nil
}

func (client *Client) uploadParts(
	ctx context.Context,
	reader io.Reader,
	totalBytes uint64,
	parts []partInformation,
) error {
	remaining := totalBytes
	buffer := make([]byte, min(client.uploadPartBytes, totalBytes))

	for index, part := range parts {
		partBytes := min(client.uploadPartBytes, remaining)
		chunk := buffer[:partBytes]

		if _, err := io.ReadFull(reader, chunk); err != nil {
			return fmt.Errorf("read upload part %d: %w", index+1, err)
		}

		if err := client.uploadPart(ctx, part.UploadURL, chunk); err != nil {
			return fmt.Errorf("write upload part %d: %w", index+1, err)
		}

		remaining -= partBytes
	}

	if remaining != 0 {
		return fmt.Errorf("%w: multipart plan left %d bytes unread", errUpload, remaining)
	}

	var extra [1]byte

	readBytes, err := reader.Read(extra[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("check upload body length: %w", err)
	}

	if readBytes != 0 {
		return fmt.Errorf("%w: body exceeds declared size", errUpload)
	}

	return nil
}

func (client *Client) uploadPart(ctx context.Context, uploadURL string, body []byte) error {
	if !safeServiceURL(uploadURL) {
		return fmt.Errorf("%w: upload URL must use HTTPS or loopback HTTP", errInvalidAPIResponse)
	}

	var lastErr error

	for attempt := range uploadAttempts {
		request, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create upload request: %w", err)
		}

		request.ContentLength = int64(len(body))
		request.Header.Set("User-Agent", "carrack/0.1")

		response, err := client.httpClient.Do(request)
		if err == nil {
			_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, maximumAPIResponseBytes))
			closeErr := response.Body.Close()

			if copyErr != nil {
				return fmt.Errorf("discard upload response: %w", copyErr)
			}

			if closeErr != nil {
				return fmt.Errorf("close upload response: %w", closeErr)
			}

			if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusConflict {
				return nil
			}

			lastErr = fmt.Errorf("%w: upload URL returned HTTP status %d", errUpload, response.StatusCode)
		} else {
			lastErr = err
		}

		if attempt+1 < uploadAttempts {
			if err := waitForRetry(ctx, time.Duration(1<<attempt)*time.Second); err != nil {
				return err
			}
		}
	}

	return fmt.Errorf("upload part after %d attempts: %w", uploadAttempts, lastErr)
}

func (client *Client) completeFile(ctx context.Context, fileID, uploadID string) (fileRecord, error) {
	request := completeFileRequest{DriveID: client.driveID, FileID: fileID, UploadID: uploadID}

	var response fileRecord

	if err := client.doAPI(ctx, requestOther, "/adrive/v1.0/openFile/complete", request, &response); err != nil {
		return fileRecord{}, err
	}

	if response.FileID == "" {
		response.FileID = fileID
	}

	return response, nil
}

func (client *Client) resolveExistingUpload(
	ctx context.Context,
	key string,
	expectedSize uint64,
	createErr error,
) (provider.Object, error) {
	existing, resolveErr := client.resolve(ctx, key)
	if resolveErr != nil || existing.Size < 0 || uint64(existing.Size) != expectedSize || existing.Type == objectTypeFolder {
		return provider.Object{}, fmt.Errorf("create Aliyun Drive object %q: %w", key, createErr)
	}

	return objectFromFile(key, existing), nil
}

func waitForRetry(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return fmt.Errorf("wait to retry Aliyun Drive upload: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}
