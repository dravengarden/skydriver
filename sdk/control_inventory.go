package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/dravengarden/carrack/provider"
)

const maximumInventoryPageObjects = 64

// CreateInventoryOperationRequest pins one provider scope for read-only discovery.
type CreateInventoryOperationRequest struct {
	NamespaceID    string
	DriverID       string
	Prefix         string
	IdempotencyKey string
}

// InventoryOperation is one fenced provider-to-D1 reconciliation intent.
type InventoryOperation struct {
	ID                     string `json:"id"`
	NamespaceID            string `json:"namespace_id"`
	Kind                   string `json:"kind"`
	State                  string `json:"state"`
	Phase                  string `json:"phase"`
	RequestedBy            string `json:"requested_by"`
	Incarnation            string `json:"incarnation"`
	Revision               uint64 `json:"revision"`
	DriverID               string `json:"driver_id"`
	DriverRevision         uint64 `json:"driver_revision"`
	Prefix                 string `json:"prefix"`
	QuarantineGraceSeconds uint64 `json:"quarantine_grace_seconds"`
	CreatedAt              uint64 `json:"created_at"`
	UpdatedAt              uint64 `json:"updated_at"`
}

type createInventoryOperationBody struct {
	NamespaceID    string `json:"namespace_id"`
	DriverID       string `json:"driver_id"`
	Prefix         string `json:"prefix"`
	IdempotencyKey string `json:"idempotency_key"`
}

type inventoryReportObject struct {
	StorageKey      string `json:"storage_key"`
	SizeBytes       uint64 `json:"size_bytes"`
	ProviderVersion string `json:"provider_version,omitempty"`
	ETag            string `json:"etag,omitempty"`
}

type inventoryPageBody struct {
	LeaseID      string                  `json:"lease_id"`
	Incarnation  string                  `json:"incarnation"`
	FencingToken uint64                  `json:"fencing_token"`
	Sequence     uint64                  `json:"sequence"`
	Cursor       string                  `json:"cursor"`
	NextCursor   string                  `json:"next_cursor"`
	Objects      []inventoryReportObject `json:"objects"`
}

// InventoryPageReceipt confirms one exact, fenced page append.
type InventoryPageReceipt struct {
	OperationID  string `json:"operation_id"`
	Sequence     uint64 `json:"sequence"`
	ReportSHA256 string `json:"report_sha256"`
	ObjectCount  uint64 `json:"object_count"`
	NextCursor   string `json:"next_cursor"`
}

type completeInventoryBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	LastSequence uint64 `json:"last_sequence"`
	ReportSHA256 string `json:"report_sha256"`
}

// CompletedInventory confirms durable quarantine and missing-object findings.
type CompletedInventory struct {
	OperationID  string `json:"operation_id"`
	State        string `json:"state"`
	ReportSHA256 string `json:"report_sha256"`
	Pages        uint64 `json:"pages"`
	Objects      uint64 `json:"objects"`
	Known        uint64 `json:"known"`
	Quarantined  uint64 `json:"quarantined"`
	Missing      uint64 `json:"missing"`
}

// CreateInventoryOperation creates or returns one pinned inventory scope.
func (client *ControlClient) CreateInventoryOperation(
	ctx context.Context,
	requested CreateInventoryOperationRequest,
) (InventoryOperation, error) {
	if !validControlHex(requested.NamespaceID, 32) ||
		!validControlString(requested.DriverID, 256) ||
		!validInventoryPath(requested.Prefix, 2_048) ||
		!validControlString(requested.IdempotencyKey, 256) {
		return InventoryOperation{}, fmt.Errorf("%w: invalid inventory operation request", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(createInventoryOperationBody(requested))
	if err != nil {
		return InventoryOperation{}, fmt.Errorf("marshal inventory operation: %w", err)
	}

	var response InventoryOperation
	if err := client.authenticatedPost(ctx, "/api/v1/inventory-reconciliations", body, &response); err != nil {
		return InventoryOperation{}, err
	}

	if response.NamespaceID != requested.NamespaceID || response.DriverID != requested.DriverID ||
		response.Prefix != requested.Prefix || response.Kind != operationKindReconcile ||
		!validControlHex(response.ID, 32) || !validControlHex(response.Incarnation, 32) ||
		response.Revision == 0 || response.DriverRevision == 0 ||
		response.QuarantineGraceSeconds < 60 || response.QuarantineGraceSeconds > 365*24*60*60 {
		return InventoryOperation{}, fmt.Errorf("%w: invalid inventory operation identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// ClaimInventoryOperation acquires or renews the inventory report fence.
func (client *ControlClient) ClaimInventoryOperation(
	ctx context.Context,
	operation InventoryOperation,
	leaseSeconds uint64,
) (OperationLease, error) {
	if !validControlHex(operation.ID, 32) || !validControlHex(operation.Incarnation, 32) ||
		operation.Kind != operationKindReconcile || leaseSeconds < minimumOperationLeaseSeconds ||
		leaseSeconds > maximumOperationLeaseSeconds {
		return OperationLease{}, fmt.Errorf("%w: invalid inventory lease request", ErrInvalidControlPlane)
	}

	return client.claimOperation(ctx, operation.ID, operation.Incarnation, leaseSeconds, operationKindReconcile)
}

// ReportInventoryPage appends one provider page under the current fence.
func (client *ControlClient) ReportInventoryPage(
	ctx context.Context,
	operation InventoryOperation,
	lease OperationLease,
	sequence uint64,
	cursor string,
	page provider.InventoryPage,
) (InventoryPageReceipt, error) {
	objects, err := prepareInventoryPage(operation, lease, sequence, cursor, page)
	if err != nil {
		return InventoryPageReceipt{}, err
	}

	body, err := json.Marshal(inventoryPageBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, Sequence: sequence, Cursor: cursor,
		NextCursor: page.NextCursor, Objects: objects,
	})
	if err != nil {
		return InventoryPageReceipt{}, fmt.Errorf("marshal inventory page: %w", err)
	}

	var response InventoryPageReceipt

	path := "/api/v1/inventory-reconciliations/" + operation.ID + "/pages"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return InventoryPageReceipt{}, err
	}

	if response.OperationID != operation.ID || response.Sequence != sequence ||
		response.ObjectCount != uint64(len(objects)) || response.NextCursor != page.NextCursor ||
		!validControlHex(response.ReportSHA256, 64) {
		return InventoryPageReceipt{}, fmt.Errorf("%w: inventory page receipt changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// CompleteInventory commits the complete report's conservative classifications.
func (client *ControlClient) CompleteInventory(
	ctx context.Context,
	operation InventoryOperation,
	lease OperationLease,
	lastSequence uint64,
	reportSHA256 string,
) (CompletedInventory, error) {
	if lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 || lastSequence == 0 ||
		!validControlHex(reportSHA256, 64) {
		return CompletedInventory{}, fmt.Errorf("%w: invalid inventory completion", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(completeInventoryBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, LastSequence: lastSequence,
		ReportSHA256: reportSHA256,
	})
	if err != nil {
		return CompletedInventory{}, fmt.Errorf("marshal inventory completion: %w", err)
	}

	var response CompletedInventory

	path := "/api/v1/inventory-reconciliations/" + operation.ID + "/complete"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return CompletedInventory{}, err
	}

	if response.OperationID != operation.ID || response.State != operationStateSucceeded ||
		response.ReportSHA256 != reportSHA256 || response.Pages != lastSequence ||
		response.Known > response.Objects || response.Quarantined != response.Objects-response.Known {
		return CompletedInventory{}, fmt.Errorf("%w: inventory completion identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func inventoryReportSHA256(pageHashes []string) (string, error) {
	if len(pageHashes) == 0 {
		return "", fmt.Errorf("%w: inventory report has no pages", ErrInvalidControlPlane)
	}

	digest := sha256.New()

	for _, pageHash := range pageHashes {
		if !validControlHex(pageHash, 64) {
			return "", fmt.Errorf("%w: invalid inventory page hash", ErrControlPlaneResponse)
		}

		_, _ = digest.Write([]byte(pageHash))
	}

	return hex.EncodeToString(digest.Sum(nil)), nil
}

func validInventoryPath(value string, maximum int) bool {
	if !validControlString(value, maximum) || strings.HasPrefix(value, "/") ||
		strings.HasSuffix(value, "/") || strings.Contains(value, `\`) {
		return false
	}

	for component := range strings.SplitSeq(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}

	return true
}

func validInventoryCursor(value string) bool {
	return value == "" || validInventoryPath(value, 4_096)
}

func validOptionalInventoryIdentity(value string) bool {
	return value == "" || validControlString(value, 4_096)
}

func inventoryKeyWithinPrefix(prefix, key string) bool {
	return strings.HasPrefix(key, prefix+"/")
}

func prepareInventoryPage(
	operation InventoryOperation,
	lease OperationLease,
	sequence uint64,
	cursor string,
	page provider.InventoryPage,
) ([]inventoryReportObject, error) {
	if !validInventoryPageFence(operation, lease, sequence, cursor, page) {
		return nil, fmt.Errorf("%w: invalid inventory page fence", ErrInvalidControlPlane)
	}

	objects := make([]inventoryReportObject, len(page.Objects))
	previous := ""

	for index, object := range page.Objects {
		if !validInventoryObject(operation.Prefix, object, index, previous) {
			return nil, fmt.Errorf("%w: invalid inventory page object", ErrInvalidControlPlane)
		}

		objects[index] = inventoryReportObject{
			StorageKey: object.Key, SizeBytes: object.SizeBytes,
			ProviderVersion: object.Version, ETag: object.ETag,
		}
		previous = object.Key
	}

	if !validInventoryPageOrder(cursor, page) {
		return nil, fmt.Errorf("%w: invalid inventory page order", ErrInvalidControlPlane)
	}

	return objects, nil
}

func validInventoryPageOrder(cursor string, page provider.InventoryPage) bool {
	if len(page.Objects) == 0 {
		return page.NextCursor == ""
	}

	if cursor != "" && page.Objects[0].Key <= cursor {
		return false
	}

	return page.NextCursor == "" || page.NextCursor == page.Objects[len(page.Objects)-1].Key
}

func validInventoryPageFence(
	operation InventoryOperation,
	lease OperationLease,
	sequence uint64,
	cursor string,
	page provider.InventoryPage,
) bool {
	return lease.OperationID == operation.ID && lease.Incarnation == operation.Incarnation &&
		lease.LeaseID != "" && lease.FencingToken > 0 && sequence > 0 &&
		(sequence == 1) == (cursor == "") && len(page.Objects) <= maximumInventoryPageObjects &&
		(page.NextCursor == "" || len(page.Objects) > 0) && validInventoryCursor(cursor) &&
		validInventoryCursor(page.NextCursor)
}

func validInventoryObject(prefix string, object provider.Object, index int, previous string) bool {
	return validInventoryPath(object.Key, 4_096) && inventoryKeyWithinPrefix(prefix, object.Key) &&
		object.SizeBytes <= math.MaxInt64 && validOptionalInventoryIdentity(object.Version) &&
		validOptionalInventoryIdentity(object.ETag) && (index == 0 || previous < object.Key)
}
