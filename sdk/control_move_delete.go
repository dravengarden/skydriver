package sdk

import "context"

// MoveDeleteTask authorizes one idempotent provider-object deletion.
type MoveDeleteTask = ProviderDeleteTask

// MoveDeleteClaim is either one safe object task or a completed move signal.
type MoveDeleteClaim = ProviderDeleteClaim

// CompletedMoveDelete records one provider object and all its ranges as deleted.
type CompletedMoveDelete struct {
	TaskID           string `json:"task_id"`
	OperationID      string `json:"operation_id"`
	LocationsDeleted uint64 `json:"locations_deleted"`
	TaskState        string `json:"task_state"`
	MoveState        string `json:"move_state"`
}

// ClaimMoveDelete claims or resumes one object task after server-side grace,
// active-read, reachability, and replica-policy checks.
func (client *ControlClient) ClaimMoveDelete(
	ctx context.Context,
	operationID string,
	leaseSeconds uint64,
) (MoveDeleteClaim, error) {
	return client.claimProviderDelete(ctx, operationID, leaseSeconds, moveDeleteProtocol)
}

// RevalidateMoveDelete rotates the task fence after repeating every destructive
// safety check immediately before provider I/O.
func (client *ControlClient) RevalidateMoveDelete(
	ctx context.Context,
	task MoveDeleteTask,
	leaseSeconds uint64,
) (MoveDeleteTask, error) {
	return client.revalidateProviderDelete(ctx, task, leaseSeconds, moveDeleteProtocol)
}

// CompleteMoveDelete commits provider deletion under the revalidated task fence.
// Repeating the exact completion after a lost response is idempotent.
func (client *ControlClient) CompleteMoveDelete(
	ctx context.Context,
	task MoveDeleteTask,
) (CompletedMoveDelete, error) {
	completed, err := client.completeProviderDelete(ctx, task, moveDeleteProtocol)
	if err != nil {
		return CompletedMoveDelete{}, err
	}

	return CompletedMoveDelete{
		TaskID: completed.TaskID, OperationID: completed.OperationID,
		LocationsDeleted: completed.LocationsDeleted, TaskState: operationStateDeleted,
		MoveState: completed.WorkflowState,
	}, nil
}

// FailMoveDelete releases a failed task for a later fenced retry.
func (client *ControlClient) FailMoveDelete(
	ctx context.Context,
	task MoveDeleteTask,
	errorCode string,
) error {
	return client.failProviderDelete(ctx, task, errorCode, moveDeleteProtocol)
}
