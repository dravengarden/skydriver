package sdk

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	quarantineDeleteStateSuperseded = "superseded"
	quarantineDeleteOutcomeDeleted  = "deleted"
	quarantineDeleteOutcomeAbsent   = "already_absent"
)

// QuarantineDeleteTask authorizes deletion of one exact, unreferenced provider object.
type QuarantineDeleteTask struct {
	TaskID           string  `json:"task_id"`
	OperationID      string  `json:"operation_id"`
	DriverID         string  `json:"driver_id"`
	DriverRevision   uint64  `json:"driver_revision"`
	StorageKey       string  `json:"storage_key"`
	ExpectedRevision uint64  `json:"expected_revision"`
	ProviderVersion  *string `json:"provider_version"`
	ETag             *string `json:"etag"`
	SizeBytes        uint64  `json:"size_bytes"`
	DeleteAfter      uint64  `json:"delete_after"`
	OwnerClientID    string  `json:"owner_client_id"`
	Incarnation      string  `json:"incarnation"`
	FencingToken     uint64  `json:"fencing_token"`
	LeaseExpiresAt   uint64  `json:"lease_expires_at"`
	AttemptCount     uint64  `json:"attempt_count"`
	State            string  `json:"state"`
}

// QuarantineDeleteClaim contains one safe object or a terminal cleanup state.
type QuarantineDeleteClaim struct {
	State   string                `json:"state"`
	Task    *QuarantineDeleteTask `json:"task"`
	Outcome string                `json:"outcome,omitempty"`
}

// CompletedQuarantineDelete records the exact ledger transition after provider cleanup.
type CompletedQuarantineDelete struct {
	TaskID             string `json:"task_id"`
	OperationID        string `json:"operation_id"`
	QuarantineRevision uint64 `json:"quarantine_revision"`
	TaskState          string `json:"task_state"`
	QuarantineState    string `json:"quarantine_state"`
	Outcome            string `json:"outcome"`
}

type quarantineDeleteClaimBody struct {
	LeaseSeconds uint64 `json:"lease_seconds"`
}

type quarantineDeleteFenceBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	LeaseSeconds uint64 `json:"lease_seconds,omitempty"`
}

type quarantineDeleteCompletionBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	Outcome      string `json:"outcome"`
}

type quarantineDeleteFailureBody struct {
	TaskID       string `json:"task_id"`
	Incarnation  string `json:"incarnation"`
	FencingToken uint64 `json:"fencing_token"`
	ErrorCode    string `json:"error_code"`
}

type failedQuarantineDelete struct {
	TaskID       string  `json:"task_id"`
	OperationID  string  `json:"operation_id"`
	Incarnation  *string `json:"incarnation"`
	FencingToken uint64  `json:"fencing_token"`
	State        string  `json:"state"`
}

// ClaimQuarantineDelete acquires or resumes the exact task created by a tombstone action.
func (client *ControlClient) ClaimQuarantineDelete(
	ctx context.Context,
	operationID string,
	leaseSeconds uint64,
) (QuarantineDeleteClaim, error) {
	if !validControlHex(operationID, 32) || !validDeleteLeaseSeconds(leaseSeconds) {
		return QuarantineDeleteClaim{}, fmt.Errorf("%w: invalid quarantine delete claim", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(quarantineDeleteClaimBody{LeaseSeconds: leaseSeconds})
	if err != nil {
		return QuarantineDeleteClaim{}, fmt.Errorf("marshal quarantine delete claim: %w", err)
	}

	var response QuarantineDeleteClaim

	path := "/api/v1/quarantine-actions/" + operationID + "/deletes/claim"
	if err := client.authenticatedPost(ctx, path, body, &response); err != nil {
		return QuarantineDeleteClaim{}, err
	}

	if response.State == operationStateClaimed && response.Task != nil &&
		validQuarantineDeleteTask(*response.Task, operationID) && response.Outcome == "" {
		return response, nil
	}

	if response.Task == nil && response.State == operationStateDeleted &&
		validQuarantineDeleteOutcome(response.Outcome) {
		return response, nil
	}

	if response.Task == nil && response.State == quarantineDeleteStateSuperseded && response.Outcome == "" {
		return response, nil
	}

	return QuarantineDeleteClaim{}, fmt.Errorf("%w: invalid quarantine delete claim identity", ErrControlPlaneResponse)
}

// RevalidateQuarantineDelete rotates the fence after provider Stat and before Delete.
func (client *ControlClient) RevalidateQuarantineDelete(
	ctx context.Context,
	task QuarantineDeleteTask,
	leaseSeconds uint64,
) (QuarantineDeleteTask, error) {
	if !validQuarantineDeleteTask(task, task.OperationID) || !validDeleteLeaseSeconds(leaseSeconds) {
		return QuarantineDeleteTask{}, fmt.Errorf("%w: invalid quarantine delete revalidation", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(quarantineDeleteFenceBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, LeaseSeconds: leaseSeconds,
	})
	if err != nil {
		return QuarantineDeleteTask{}, fmt.Errorf("marshal quarantine delete revalidation: %w", err)
	}

	var response QuarantineDeleteTask
	if err := client.authenticatedPost(ctx, "/api/v1/quarantine-deletes/revalidate", body, &response); err != nil {
		return QuarantineDeleteTask{}, err
	}

	if !sameRevalidatedQuarantineDelete(response, task) {
		return QuarantineDeleteTask{}, fmt.Errorf("%w: revalidated quarantine delete identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// CompleteQuarantineDelete records an exact provider deletion or observed absence.
func (client *ControlClient) CompleteQuarantineDelete(
	ctx context.Context,
	task QuarantineDeleteTask,
	outcome string,
) (CompletedQuarantineDelete, error) {
	if !validQuarantineDeleteTask(task, task.OperationID) || !validQuarantineDeleteOutcome(outcome) {
		return CompletedQuarantineDelete{}, fmt.Errorf("%w: invalid quarantine delete completion", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(quarantineDeleteCompletionBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, Outcome: outcome,
	})
	if err != nil {
		return CompletedQuarantineDelete{}, fmt.Errorf("marshal quarantine delete completion: %w", err)
	}

	var response CompletedQuarantineDelete
	if err := client.authenticatedPost(ctx, "/api/v1/quarantine-deletes/complete", body, &response); err != nil {
		return CompletedQuarantineDelete{}, err
	}

	if response.TaskID != task.TaskID || response.OperationID != task.OperationID ||
		response.QuarantineRevision <= task.ExpectedRevision ||
		response.TaskState != operationStateDeleted || response.QuarantineState != operationStateDeleted ||
		response.Outcome != outcome {
		return CompletedQuarantineDelete{}, fmt.Errorf("%w: completed quarantine delete identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// FailQuarantineDelete releases a claimed task for an explicit retry.
func (client *ControlClient) FailQuarantineDelete(
	ctx context.Context,
	task QuarantineDeleteTask,
	errorCode string,
) error {
	if !validQuarantineDeleteTask(task, task.OperationID) || !validControlString(errorCode, 256) {
		return fmt.Errorf("%w: invalid quarantine delete failure", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(quarantineDeleteFailureBody{
		TaskID: task.TaskID, Incarnation: task.Incarnation,
		FencingToken: task.FencingToken, ErrorCode: errorCode,
	})
	if err != nil {
		return fmt.Errorf("marshal quarantine delete failure: %w", err)
	}

	var response failedQuarantineDelete
	if err := client.authenticatedPost(ctx, "/api/v1/quarantine-deletes/fail", body, &response); err != nil {
		return err
	}

	if response.TaskID != task.TaskID || response.OperationID != task.OperationID ||
		response.Incarnation == nil || *response.Incarnation != task.Incarnation ||
		response.FencingToken != task.FencingToken || response.State != operationStateFailed {
		return fmt.Errorf("%w: failed quarantine delete identity changed", ErrControlPlaneResponse)
	}

	return nil
}

func sameRevalidatedQuarantineDelete(response, requested QuarantineDeleteTask) bool {
	return validQuarantineDeleteTask(response, requested.OperationID) &&
		response.TaskID == requested.TaskID && response.DriverID == requested.DriverID &&
		response.DriverRevision == requested.DriverRevision &&
		response.StorageKey == requested.StorageKey &&
		response.ExpectedRevision == requested.ExpectedRevision &&
		optionalControlStringEqual(response.ProviderVersion, requested.ProviderVersion) &&
		optionalControlStringEqual(response.ETag, requested.ETag) &&
		response.SizeBytes == requested.SizeBytes && response.DeleteAfter == requested.DeleteAfter &&
		response.OwnerClientID == requested.OwnerClientID &&
		response.Incarnation == requested.Incarnation &&
		response.FencingToken == requested.FencingToken+1 &&
		response.AttemptCount == requested.AttemptCount
}

func validQuarantineDeleteTask(task QuarantineDeleteTask, operationID string) bool {
	return validControlString(task.TaskID, 8_192) && validControlHex(operationID, 32) &&
		task.OperationID == operationID && validControlString(task.DriverID, 256) &&
		task.DriverRevision > 0 && validControlString(task.StorageKey, 4_096) &&
		task.ExpectedRevision > 0 && validOptionalControlString(task.ProviderVersion, 4_096) &&
		validOptionalControlString(task.ETag, 4_096) && task.DeleteAfter > 0 &&
		validControlString(task.OwnerClientID, 256) && validControlHex(task.Incarnation, 32) &&
		task.FencingToken > 0 && task.LeaseExpiresAt > 0 && task.AttemptCount > 0 &&
		task.State == operationStateClaimed
}

func validOptionalControlString(value *string, maximum int) bool {
	return value == nil || validControlString(*value, maximum)
}

func optionalControlStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return *left == *right
}

func validQuarantineDeleteOutcome(value string) bool {
	return value == quarantineDeleteOutcomeDeleted || value == quarantineDeleteOutcomeAbsent
}
