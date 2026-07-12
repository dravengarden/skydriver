package sdk

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dravengarden/carrack/cryptostream"
)

type importKeyGrantBody struct {
	LeaseID      string `json:"lease_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	RootVersion  uint32 `json:"root_version"`
	KeyEpoch     uint64 `json:"key_epoch"`
}

type importKeyGrant struct {
	OperationID string `json:"operation_id"`
	RootVersion uint32 `json:"root_version"`
	KeyEpoch    uint64 `json:"key_epoch"`
	EpochKey    string `json:"epoch_key"`
}

// GrantImportEpochKey derives the crypto context pinned when the import was created.
func (client *ControlClient) GrantImportEpochKey(
	ctx context.Context,
	operation ImportOperation,
	lease OperationLease,
) (cryptostream.EpochKey, error) {
	if !validControlHex(operation.ID, 32) || operation.RootVersion == 0 || operation.KeyEpoch == 0 ||
		lease.OperationID != operation.ID || lease.Incarnation != operation.Incarnation ||
		lease.LeaseID == "" || lease.FencingToken == 0 {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: invalid import key fence", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(importKeyGrantBody{
		LeaseID: lease.LeaseID, Incarnation: lease.Incarnation,
		FencingToken: lease.FencingToken, RootVersion: operation.RootVersion,
		KeyEpoch: operation.KeyEpoch,
	})
	if err != nil {
		return cryptostream.EpochKey{}, fmt.Errorf("marshal import key grant: %w", err)
	}

	var response importKeyGrant

	path := "/api/v1/imports/" + operation.ID + "/key"
	if requestErr := client.authenticatedPost(ctx, path, body, &response); requestErr != nil {
		return cryptostream.EpochKey{}, requestErr
	}

	if response.OperationID != operation.ID || response.RootVersion != operation.RootVersion ||
		response.KeyEpoch != operation.KeyEpoch {
		return cryptostream.EpochKey{}, fmt.Errorf("%w: import key identity changed", ErrControlPlaneResponse)
	}

	return decodeGrantedEpochKey(response.EpochKey, "import")
}
