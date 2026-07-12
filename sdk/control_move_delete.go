package sdk

import (
	"context"
	"encoding/json"
	"fmt"
)

// MoveDeleteTask authorizes one idempotent provider-object deletion.
type MoveDeleteTask struct {
	TaskID                string `json:"task_id"`
	OperationID           string `json:"operation_id"`
	DriverID              string `json:"driver_id"`
	StorageKey            string `json:"storage_key"`
	ExpectedLocationCount uint64 `json:"expected_location_count"`
	OwnerClientID         string `json:"owner_client_id"`
	Incarnation           string `json:"incarnation"`
	FencingToken          uint64 `json:"fencing_token"`
	LeaseExpiresAt        uint64 `json:"lease_expires_at"`
	AttemptCount          uint64 `json:"attempt_count"`
	State                 string `json:"state"`
}

// MoveDeleteClaim is either one safe object task or a completed move signal.
type MoveDeleteClaim struct {
	State string          `json:"state"`
	Task  *MoveDeleteTask `json:"task"`
}

// CompletedMoveDelete records one provider object and all its ranges as deleted.
type CompletedMoveDelete struct {
	TaskID           string `json:"task_id"`
	OperationID      string `json:"operation_id"`
	LocationsDeleted uint64 `json:"locations_deleted"`
	TaskState        string `json:"task_state"`
	MoveState        string `json:"move_state"`
}

type moveDeleteClaimBody struct {
	LeaseSeconds uint64 `json:"lease_seconds"`
}

type moveDeleteFenceBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	LeaseSeconds uint64 `json:"lease_seconds,omitempty"`
}

type moveDeleteFailureBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	ErrorCode    string `json:"error_code"`
}

type failedMoveDelete struct {
	TaskID       string  `json:"task_id"`
	OperationID  string  `json:"operation_id"`
	Incarnation  *string `json:"incarnation"`
	FencingToken uint64  `json:"fencing_token"`
	State        string  `json:"state"`
}

// ClaimMoveDelete claims or resumes one object task after server-side grace,
// active-read, reachability, and replica-policy checks.
func (client *ControlClient) ClaimMoveDelete(
	ctx context.Context,
	operationID string,
	leaseSeconds uint64,
) (MoveDeleteClaim, error) {
	if !validControlHex(operationID, 32) ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return MoveDeleteClaim{}, fmt.Errorf("%w: invalid move delete claim", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(moveDeleteClaimBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return MoveDeleteClaim{}, fmt.Errorf("marshal move delete claim: %w", err)
	}

	var response MoveDeleteClaim

	path := "/api/v1/moves/" + operationID + "/deletes/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return MoveDeleteClaim{}, err
	}

	if response.State == operationStateSucceeded && response.Task == nil {
		return response, nil
	}

	if response.State != "claimed" || response.Task == nil ||
		!validMoveDeleteTask(*response.Task, operationID) {
		return MoveDeleteClaim{}, fmt.Errorf("%w: invalid move delete claim identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// RevalidateMoveDelete rotates the task fence after repeating every destructive
// safety check immediately before provider I/O.
func (client *ControlClient) RevalidateMoveDelete(
	ctx context.Context,
	task MoveDeleteTask,
	leaseSeconds uint64,
) (MoveDeleteTask, error) {
	if !validMoveDeleteTask(task, task.OperationID) ||
		leaseSeconds < minimumOperationLeaseSeconds || leaseSeconds > maximumOperationLeaseSeconds {
		return MoveDeleteTask{}, fmt.Errorf("%w: invalid move delete revalidation", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(moveDeleteFenceBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, LeaseSeconds: leaseSeconds,
	})
	if err != nil {
		return MoveDeleteTask{}, fmt.Errorf("marshal move delete revalidation: %w", err)
	}

	var response MoveDeleteTask
	if err := client.authenticatedPost(ctx, "/api/v1/moves/deletes/revalidate", body, &response); err != nil {
		return MoveDeleteTask{}, err
	}

	if !validMoveDeleteTask(response, task.OperationID) || response.TaskID != task.TaskID ||
		response.OwnerClientID != task.OwnerClientID || response.Incarnation != task.Incarnation ||
		response.FencingToken != task.FencingToken+1 ||
		response.DriverID != task.DriverID || response.StorageKey != task.StorageKey {
		return MoveDeleteTask{}, fmt.Errorf("%w: revalidated move delete identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// CompleteMoveDelete commits provider deletion under the revalidated task fence.
// Repeating the exact completion after a lost response is idempotent.
func (client *ControlClient) CompleteMoveDelete(
	ctx context.Context,
	task MoveDeleteTask,
) (CompletedMoveDelete, error) {
	if !validMoveDeleteTask(task, task.OperationID) {
		return CompletedMoveDelete{}, fmt.Errorf("%w: invalid move delete completion", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(moveDeleteFenceBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation, FencingToken: task.FencingToken,
	})
	if err != nil {
		return CompletedMoveDelete{}, fmt.Errorf("marshal move delete completion: %w", err)
	}

	var response CompletedMoveDelete
	if err := client.authenticatedPost(ctx, "/api/v1/moves/deletes/complete", body, &response); err != nil {
		return CompletedMoveDelete{}, err
	}

	if response.TaskID != task.TaskID || response.OperationID != task.OperationID ||
		response.LocationsDeleted != task.ExpectedLocationCount || response.TaskState != "deleted" ||
		(response.MoveState != "deleting" && response.MoveState != operationStateSucceeded) {
		return CompletedMoveDelete{}, fmt.Errorf("%w: completed move delete identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// FailMoveDelete releases a failed task for a later fenced retry.
func (client *ControlClient) FailMoveDelete(
	ctx context.Context,
	task MoveDeleteTask,
	errorCode string,
) error {
	if !validMoveDeleteTask(task, task.OperationID) || !validControlString(errorCode, 256) {
		return fmt.Errorf("%w: invalid move delete failure", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(moveDeleteFailureBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, ErrorCode: errorCode,
	})
	if err != nil {
		return fmt.Errorf("marshal move delete failure: %w", err)
	}

	var response failedMoveDelete
	if err := client.authenticatedPost(ctx, "/api/v1/moves/deletes/fail", body, &response); err != nil {
		return err
	}

	if response.TaskID != task.TaskID || response.OperationID != task.OperationID ||
		response.Incarnation == nil || *response.Incarnation != task.Incarnation ||
		response.FencingToken != task.FencingToken || response.State != "failed" {
		return fmt.Errorf("%w: failed move delete identity changed", ErrControlPlaneResponse)
	}

	return nil
}

func validMoveDeleteTask(task MoveDeleteTask, operationID string) bool {
	return validControlString(task.TaskID, 8_192) && validControlHex(operationID, 32) &&
		task.OperationID == operationID && validControlString(task.DriverID, 256) &&
		validControlString(task.StorageKey, 4_096) && task.ExpectedLocationCount > 0 &&
		task.OwnerClientID != "" && validControlHex(task.Incarnation, 32) &&
		task.FencingToken > 0 && task.LeaseExpiresAt > 0 && task.AttemptCount > 0 &&
		task.State == "claimed"
}
