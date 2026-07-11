package aliyundrive

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

var errObjectNotFound = errors.New("object not found in Aliyun Drive")

type fileRecord struct {
	DriveID      string    `json:"drive_id"`
	FileID       string    `json:"file_id"`
	ParentFileID string    `json:"parent_file_id"`
	Name         string    `json:"name"`
	FileName     string    `json:"file_name"`
	Size         int64     `json:"size"`
	ContentHash  string    `json:"content_hash"`
	Type         string    `json:"type"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type listResponse struct {
	Items      []fileRecord `json:"items"`
	NextMarker string       `json:"next_marker"`
}

type listRequest struct {
	DriveID        string `json:"drive_id"`
	ParentFileID   string `json:"parent_file_id"`
	Limit          int    `json:"limit"`
	Marker         string `json:"marker"`
	OrderBy        string `json:"order_by"`
	OrderDirection string `json:"order_direction"`
}

type createDirectoryRequest struct {
	DriveID       string `json:"drive_id"`
	ParentFileID  string `json:"parent_file_id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	CheckNameMode string `json:"check_name_mode"`
}

func (client *Client) resolve(ctx context.Context, key string) (fileRecord, error) {
	segments, err := splitObjectKey(key)
	if err != nil {
		return fileRecord{}, err
	}

	if initializeErr := client.initialize(ctx); initializeErr != nil {
		return fileRecord{}, initializeErr
	}

	current := fileRecord{FileID: client.rootFolderID, Name: defaultRootFolderID, Type: objectTypeFolder}
	for _, segment := range segments {
		current, err = client.findChild(ctx, current.FileID, segment)
		if err != nil {
			return fileRecord{}, fmt.Errorf("resolve Aliyun Drive object %q: %w", key, err)
		}
	}

	return current, nil
}

func (client *Client) ensureParent(ctx context.Context, key string) (fileRecord, string, error) {
	segments, err := splitObjectKey(key)
	if err != nil {
		return fileRecord{}, "", err
	}

	if initializeErr := client.initialize(ctx); initializeErr != nil {
		return fileRecord{}, "", initializeErr
	}

	current := fileRecord{FileID: client.rootFolderID, Name: defaultRootFolderID, Type: objectTypeFolder}
	for _, segment := range segments[:len(segments)-1] {
		child, findErr := client.findChild(ctx, current.FileID, segment)
		if findErr == nil {
			if child.Type != objectTypeFolder {
				return fileRecord{}, "", fmt.Errorf("%w: path component %q is not a folder", errObjectState, segment)
			}

			current = child

			continue
		}

		if !errors.Is(findErr, errObjectNotFound) {
			return fileRecord{}, "", findErr
		}

		current, err = client.createDirectory(ctx, current.FileID, segment)
		if err != nil {
			return fileRecord{}, "", fmt.Errorf("create Aliyun Drive folder %q: %w", segment, err)
		}
	}

	return current, segments[len(segments)-1], nil
}

func (client *Client) findChild(ctx context.Context, parentID, name string) (fileRecord, error) {
	children, err := client.listChildren(ctx, parentID)
	if err != nil {
		return fileRecord{}, err
	}

	var found *fileRecord

	for index := range children {
		child := &children[index]
		if child.Name != name && child.FileName != name {
			continue
		}

		if found != nil {
			return fileRecord{}, fmt.Errorf("%w: multiple objects named %q", errObjectState, name)
		}

		found = child
	}

	if found == nil {
		return fileRecord{}, fmt.Errorf("%w: %s", errObjectNotFound, name)
	}

	return *found, nil
}

func (client *Client) listChildren(ctx context.Context, parentID string) ([]fileRecord, error) {
	children := make([]fileRecord, 0)
	marker := ""

	for {
		request := listRequest{
			DriveID:        client.driveID,
			ParentFileID:   parentID,
			Limit:          200,
			Marker:         marker,
			OrderBy:        "name",
			OrderDirection: "ASC",
		}

		var response listResponse
		if err := client.doAPI(ctx, requestList, "/adrive/v1.0/openFile/list", request, &response); err != nil {
			return nil, fmt.Errorf("list Aliyun Drive folder: %w", err)
		}

		children = append(children, response.Items...)
		if response.NextMarker == "" {
			return children, nil
		}

		marker = response.NextMarker
	}
}

func (client *Client) createDirectory(ctx context.Context, parentID, name string) (fileRecord, error) {
	request := createDirectoryRequest{
		DriveID:       client.driveID,
		ParentFileID:  parentID,
		Name:          name,
		Type:          objectTypeFolder,
		CheckNameMode: "refuse",
	}

	var created fileRecord
	if err := client.doAPI(ctx, requestOther, "/adrive/v1.0/openFile/create", request, &created); err != nil {
		return fileRecord{}, err
	}

	if created.FileID == "" {
		return fileRecord{}, fmt.Errorf("%w: create folder response omitted file ID", errInvalidAPIResponse)
	}

	created.Name = name
	created.Type = objectTypeFolder

	return created, nil
}

func splitObjectKey(key string) ([]string, error) {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") {
		return nil, fmt.Errorf("%w: object key must be a non-empty relative slash path", ErrInvalidConfiguration)
	}

	cleaned := path.Clean(key)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != key {
		return nil, fmt.Errorf("%w: object key %q is not canonical", ErrInvalidConfiguration, key)
	}

	segments := strings.Split(cleaned, "/")
	if slices.Contains(segments, "") {
		return nil, fmt.Errorf("%w: object key contains an empty path component", ErrInvalidConfiguration)
	}

	return segments, nil
}
