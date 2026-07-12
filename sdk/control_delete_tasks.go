package sdk

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	operationStateClaimed  = "claimed"
	operationStateDeleted  = "deleted"
	operationStateFailed   = "failed"
	operationPhaseGrace    = "grace"
	operationPhaseMarking  = "marking"
	operationPhaseSweeping = "sweeping"
)

// ProviderDeleteTask authorizes one idempotent, fenced provider-object deletion.
type ProviderDeleteTask struct {
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

// ProviderDeleteClaim is one safe provider object or a completed workflow signal.
type ProviderDeleteClaim struct {
	State string              `json:"state"`
	Task  *ProviderDeleteTask `json:"task"`
}

type deleteTaskProtocol struct {
	label          string
	claimPrefix    string
	revalidatePath string
	completePath   string
	failPath       string
	runningState   string
	stateField     string
}

var (
	moveDeleteProtocol = deleteTaskProtocol{
		label: operationKindMove, claimPrefix: "/api/v1/moves/", runningState: "deleting",
		revalidatePath: "/api/v1/moves/deletes/revalidate",
		completePath:   "/api/v1/moves/deletes/complete",
		failPath:       "/api/v1/moves/deletes/fail",
		stateField:     "move",
	}
	gcDeleteProtocol = deleteTaskProtocol{
		label: "GC", claimPrefix: "/api/v1/gc/", runningState: operationPhaseSweeping,
		revalidatePath: "/api/v1/gc/deletes/revalidate",
		completePath:   "/api/v1/gc/deletes/complete",
		failPath:       "/api/v1/gc/deletes/fail",
		stateField:     "gc",
	}
)

type deleteClaimBody struct {
	LeaseSeconds uint64 `json:"lease_seconds"`
}

type deleteFenceBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	LeaseSeconds uint64 `json:"lease_seconds,omitempty"`
}

type deleteFailureBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	ErrorCode    string `json:"error_code"`
}

type completedProviderDelete struct {
	TaskID           string `json:"task_id"`
	OperationID      string `json:"operation_id"`
	LocationsDeleted uint64 `json:"locations_deleted"`
	TaskState        string `json:"task_state"`
	MoveState        string `json:"move_state"`
	GCState          string `json:"gc_state"`
}

type failedProviderDelete struct {
	TaskID       string  `json:"task_id"`
	OperationID  string  `json:"operation_id"`
	Incarnation  *string `json:"incarnation"`
	FencingToken uint64  `json:"fencing_token"`
	State        string  `json:"state"`
}

type providerDeleteCompletion struct {
	TaskID           string
	OperationID      string
	LocationsDeleted uint64
	WorkflowState    string
}

func (client *ControlClient) claimProviderDelete(
	ctx context.Context,
	operationID string,
	leaseSeconds uint64,
	protocol deleteTaskProtocol,
) (ProviderDeleteClaim, error) {
	if !validControlHex(operationID, 32) || !validDeleteLeaseSeconds(leaseSeconds) {
		return ProviderDeleteClaim{}, fmt.Errorf("%w: invalid %s delete claim", ErrInvalidControlPlane, protocol.label)
	}

	body, err := json.Marshal(deleteClaimBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return ProviderDeleteClaim{}, fmt.Errorf("marshal %s delete claim: %w", protocol.label, err)
	}

	var response ProviderDeleteClaim

	path := protocol.claimPrefix + operationID + "/deletes/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return ProviderDeleteClaim{}, err
	}

	if response.State == operationStateSucceeded && response.Task == nil {
		return response, nil
	}

	if response.State != operationStateClaimed || response.Task == nil ||
		!validProviderDeleteTask(*response.Task, operationID) {
		return ProviderDeleteClaim{}, fmt.Errorf("%w: invalid %s delete claim identity", ErrControlPlaneResponse, protocol.label)
	}

	return response, nil
}

func (client *ControlClient) revalidateProviderDelete(
	ctx context.Context,
	task ProviderDeleteTask,
	leaseSeconds uint64,
	protocol deleteTaskProtocol,
) (ProviderDeleteTask, error) {
	if !validProviderDeleteTask(task, task.OperationID) || !validDeleteLeaseSeconds(leaseSeconds) {
		return ProviderDeleteTask{}, fmt.Errorf("%w: invalid %s delete revalidation", ErrInvalidControlPlane, protocol.label)
	}

	body, err := json.Marshal(deleteFenceBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, LeaseSeconds: leaseSeconds,
	})
	if err != nil {
		return ProviderDeleteTask{}, fmt.Errorf("marshal %s delete revalidation: %w", protocol.label, err)
	}

	var response ProviderDeleteTask
	if err := client.authenticatedPost(ctx, protocol.revalidatePath, body, &response); err != nil {
		return ProviderDeleteTask{}, err
	}

	if !sameRevalidatedDeleteTask(response, task) {
		return ProviderDeleteTask{}, fmt.Errorf("%w: revalidated %s delete identity changed", ErrControlPlaneResponse, protocol.label)
	}

	return response, nil
}

func (client *ControlClient) completeProviderDelete(
	ctx context.Context,
	task ProviderDeleteTask,
	protocol deleteTaskProtocol,
) (providerDeleteCompletion, error) {
	if !validProviderDeleteTask(task, task.OperationID) {
		return providerDeleteCompletion{}, fmt.Errorf("%w: invalid %s delete completion", ErrInvalidControlPlane, protocol.label)
	}

	body, err := json.Marshal(deleteFenceBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation, FencingToken: task.FencingToken,
	})
	if err != nil {
		return providerDeleteCompletion{}, fmt.Errorf("marshal %s delete completion: %w", protocol.label, err)
	}

	var response completedProviderDelete
	if err := client.authenticatedPost(ctx, protocol.completePath, body, &response); err != nil {
		return providerDeleteCompletion{}, err
	}

	workflowState := response.MoveState
	if protocol.stateField == "gc" {
		workflowState = response.GCState
	}

	if response.TaskID != task.TaskID || response.OperationID != task.OperationID ||
		response.LocationsDeleted != task.ExpectedLocationCount ||
		response.TaskState != operationStateDeleted ||
		(workflowState != protocol.runningState && workflowState != operationStateSucceeded) {
		return providerDeleteCompletion{}, fmt.Errorf("%w: completed %s delete identity changed", ErrControlPlaneResponse, protocol.label)
	}

	return providerDeleteCompletion{
		TaskID: response.TaskID, OperationID: response.OperationID,
		LocationsDeleted: response.LocationsDeleted, WorkflowState: workflowState,
	}, nil
}

func (client *ControlClient) failProviderDelete(
	ctx context.Context,
	task ProviderDeleteTask,
	errorCode string,
	protocol deleteTaskProtocol,
) error {
	if !validProviderDeleteTask(task, task.OperationID) || !validControlString(errorCode, 256) {
		return fmt.Errorf("%w: invalid %s delete failure", ErrInvalidControlPlane, protocol.label)
	}

	body, err := json.Marshal(deleteFailureBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, ErrorCode: errorCode,
	})
	if err != nil {
		return fmt.Errorf("marshal %s delete failure: %w", protocol.label, err)
	}

	var response failedProviderDelete
	if err := client.authenticatedPost(ctx, protocol.failPath, body, &response); err != nil {
		return err
	}

	if response.TaskID != task.TaskID || response.OperationID != task.OperationID ||
		response.Incarnation == nil || *response.Incarnation != task.Incarnation ||
		response.FencingToken != task.FencingToken || response.State != operationStateFailed {
		return fmt.Errorf("%w: failed %s delete identity changed", ErrControlPlaneResponse, protocol.label)
	}

	return nil
}

func sameRevalidatedDeleteTask(response, requested ProviderDeleteTask) bool {
	return validProviderDeleteTask(response, requested.OperationID) &&
		response.TaskID == requested.TaskID && response.OwnerClientID == requested.OwnerClientID &&
		response.Incarnation == requested.Incarnation &&
		response.FencingToken == requested.FencingToken+1 &&
		response.DriverID == requested.DriverID && response.StorageKey == requested.StorageKey
}

func validProviderDeleteTask(task ProviderDeleteTask, operationID string) bool {
	return validControlString(task.TaskID, 8_192) && validControlHex(operationID, 32) &&
		task.OperationID == operationID && validControlString(task.DriverID, 256) &&
		validControlString(task.StorageKey, 4_096) && task.ExpectedLocationCount > 0 &&
		task.OwnerClientID != "" && validControlHex(task.Incarnation, 32) &&
		task.FencingToken > 0 && task.LeaseExpiresAt > 0 && task.AttemptCount > 0 &&
		task.State == operationStateClaimed
}

func validDeleteLeaseSeconds(leaseSeconds uint64) bool {
	return leaseSeconds >= minimumOperationLeaseSeconds && leaseSeconds <= maximumOperationLeaseSeconds
}
