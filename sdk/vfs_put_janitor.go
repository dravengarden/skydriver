package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/dravengarden/carrack/driver"
)

const (
	defaultVFSPutDeleteLeaseSeconds = uint64(60)
	vfsDeleteFencingTokenField      = "fencing_token"
	vfsDeleteIncarnationField       = "incarnation"
)

var (
	// ErrInvalidVFSPutJanitor indicates missing control-plane or driver configuration.
	ErrInvalidVFSPutJanitor = errors.New("invalid Carrack VFS Put janitor")
	// ErrVFSPutDeleteIdentityChanged indicates that the provider object no longer matches upload evidence.
	ErrVFSPutDeleteIdentityChanged = errors.New("carrack VFS Put delete identity changed")
)

// VFSPutDeleteTask pins one unreferenced complete provider object and its lease fence.
type VFSPutDeleteTask struct {
	Schema            string  `json:"schema"`
	TaskID            string  `json:"task_id"`
	FilesystemID      string  `json:"filesystem_id"`
	DirectoryID       string  `json:"directory_id"`
	DriverID          string  `json:"driver_id"`
	DriverRevision    uint64  `json:"driver_revision"`
	StorageKey        string  `json:"storage_key"`
	NativeID          *string `json:"native_id"`
	ProviderVersion   *string `json:"provider_version"`
	ETag              *string `json:"etag"`
	SizeBytes         uint64  `json:"size_bytes"`
	EncodedSHA256     string  `json:"encoded_sha256"`
	DeleteAfter       uint64  `json:"delete_after"`
	Incarnation       *string `json:"incarnation"`
	FencingToken      uint64  `json:"fencing_token"`
	LeaseExpiresAt    *uint64 `json:"lease_expires_at"`
	AttemptCount      uint64  `json:"attempt_count"`
	State             string  `json:"state"`
	CompletionOutcome *string `json:"completion_outcome"`
}

type vfsPutDeleteClaim struct {
	State string            `json:"state"`
	Task  *VFSPutDeleteTask `json:"task"`
}

type vfsPutDeleteDriverGrantWire struct {
	Schema         string           `json:"schema"`
	TaskID         string           `json:"task_id"`
	DriverID       string           `json:"driver_id"`
	DriverKind     driver.Kind      `json:"driver_kind"`
	DriverRevision uint64           `json:"driver_revision"`
	Config         json.RawMessage  `json:"config"`
	Credential     *json.RawMessage `json:"credential"`
	ExpiresAt      uint64           `json:"expires_at"`
}

// VFSPutDeleteDriverGrant contains a transient, lease-bounded compiled driver instance.
type VFSPutDeleteDriverGrant struct {
	TaskID    string
	Instance  driver.Instance
	ExpiresAt uint64
}

// Clear overwrites transient driver configuration and credential bytes.
func (grant *VFSPutDeleteDriverGrant) Clear() {
	if grant == nil {
		return
	}

	clear(grant.Instance.Config)
	clear(grant.Instance.Credential)
	grant.Instance.Config = nil
	grant.Instance.Credential = nil
}

// ClaimPutDelete claims the oldest safe expired-upload object visible to this token.
func (client *VFSControlClient) ClaimPutDelete(
	ctx context.Context,
	leaseSeconds uint64,
) (string, *VFSPutDeleteTask, error) {
	if leaseSeconds < 15 || leaseSeconds > 300 {
		return "", nil, fmt.Errorf("%w: invalid VFS Put delete lease", ErrInvalidControlPlane)
	}

	body, err := marshalVFSDeleteBody(map[string]any{"lease_seconds": leaseSeconds})
	if err != nil {
		return "", nil, err
	}

	var response vfsPutDeleteClaim
	if err := client.postJSON(ctx, "/api/v2/put-deletes/claim", body, &response); err != nil {
		return "", nil, err
	}

	if response.State == "idle" && response.Task == nil {
		return response.State, nil, nil
	}

	if response.State != "claimed" || response.Task == nil || !validClaimedVFSPutDelete(*response.Task) {
		return "", nil, fmt.Errorf("%w: invalid VFS Put delete claim", ErrControlPlaneResponse)
	}

	return response.State, response.Task, nil
}

// GrantPutDeleteDriver returns the exact driver revision pinned by a claimed task.
func (client *VFSControlClient) GrantPutDeleteDriver(
	ctx context.Context,
	task VFSPutDeleteTask,
) (VFSPutDeleteDriverGrant, error) {
	if !validClaimedVFSPutDelete(task) {
		return VFSPutDeleteDriverGrant{}, fmt.Errorf("%w: invalid VFS Put delete task", ErrInvalidControlPlane)
	}

	var wire vfsPutDeleteDriverGrantWire

	path := "/api/v2/put-deletes/" + task.TaskID + "/driver-grant"
	if err := client.postJSON(ctx, path, nil, &wire); err != nil {
		return VFSPutDeleteDriverGrant{}, err
	}

	if wire.Schema != "carrack.vfs.put-delete-driver-grant.v1" || wire.TaskID != task.TaskID ||
		wire.DriverID != task.DriverID || wire.DriverRevision != task.DriverRevision ||
		!validControlString(string(wire.DriverKind), 256) || wire.ExpiresAt == 0 ||
		!validJSONObjectWire(wire.Config) || wire.Credential != nil && !validJSONObjectWire(*wire.Credential) {
		return VFSPutDeleteDriverGrant{}, fmt.Errorf("%w: VFS Put delete driver grant changed identity", ErrControlPlaneResponse)
	}

	instance := driver.Instance{ID: wire.DriverID, Kind: wire.DriverKind, Revision: wire.DriverRevision, Config: wire.Config}
	if wire.Credential != nil {
		instance.Credential = *wire.Credential
	}

	return VFSPutDeleteDriverGrant{TaskID: wire.TaskID, Instance: instance, ExpiresAt: wire.ExpiresAt}, nil
}

// RevalidatePutDelete rotates the task fence immediately before provider deletion.
func (client *VFSControlClient) RevalidatePutDelete(
	ctx context.Context,
	task VFSPutDeleteTask,
	leaseSeconds uint64,
) (VFSPutDeleteTask, error) {
	if !validClaimedVFSPutDelete(task) || leaseSeconds < 15 || leaseSeconds > 300 {
		return VFSPutDeleteTask{}, fmt.Errorf("%w: invalid VFS Put delete revalidation", ErrInvalidControlPlane)
	}

	body, err := marshalVFSDeleteBody(map[string]any{
		vfsDeleteIncarnationField: *task.Incarnation, vfsDeleteFencingTokenField: task.FencingToken, "lease_seconds": leaseSeconds,
	})
	if err != nil {
		return VFSPutDeleteTask{}, err
	}

	var response VFSPutDeleteTask

	path := "/api/v2/put-deletes/" + task.TaskID + "/revalidate"
	if err := client.postJSON(ctx, path, body, &response); err != nil {
		return VFSPutDeleteTask{}, err
	}

	if !sameVFSPutDeleteIdentity(task, response) || !validClaimedVFSPutDelete(response) ||
		response.FencingToken != task.FencingToken+1 {
		return VFSPutDeleteTask{}, fmt.Errorf("%w: VFS Put delete revalidation changed identity", ErrControlPlaneResponse)
	}

	return response, nil
}

// CompletePutDelete records an exact deletion or an already-absent object.
func (client *VFSControlClient) CompletePutDelete(
	ctx context.Context,
	task VFSPutDeleteTask,
	outcome string,
) (VFSPutDeleteTask, error) {
	if !validClaimedVFSPutDelete(task) || outcome != operationStateDeleted && outcome != quarantineDeleteOutcomeAbsent {
		return VFSPutDeleteTask{}, fmt.Errorf("%w: invalid VFS Put delete completion", ErrInvalidControlPlane)
	}

	body, err := marshalVFSDeleteBody(map[string]any{
		vfsDeleteIncarnationField: *task.Incarnation, vfsDeleteFencingTokenField: task.FencingToken, "outcome": outcome,
	})
	if err != nil {
		return VFSPutDeleteTask{}, err
	}

	var response VFSPutDeleteTask

	path := "/api/v2/put-deletes/" + task.TaskID + "/complete"
	if err := client.postJSON(ctx, path, body, &response); err != nil {
		return VFSPutDeleteTask{}, err
	}

	if !sameVFSPutDeleteIdentity(task, response) || response.State != operationStateDeleted ||
		response.CompletionOutcome == nil || *response.CompletionOutcome != outcome {
		return VFSPutDeleteTask{}, fmt.Errorf("%w: invalid VFS Put delete completion receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

// FailPutDelete releases a claim fence for conservative retry.
func (client *VFSControlClient) FailPutDelete(
	ctx context.Context,
	task VFSPutDeleteTask,
	errorCode string,
) error {
	if !validClaimedVFSPutDelete(task) || !validVFSDeleteErrorCode(errorCode) {
		return fmt.Errorf("%w: invalid VFS Put delete failure", ErrInvalidControlPlane)
	}

	body, err := marshalVFSDeleteBody(map[string]any{
		vfsDeleteIncarnationField: *task.Incarnation, vfsDeleteFencingTokenField: task.FencingToken, "error_code": errorCode,
	})
	if err != nil {
		return err
	}

	var response VFSPutDeleteTask

	path := "/api/v2/put-deletes/" + task.TaskID + "/fail"
	if err := client.postJSON(ctx, path, body, &response); err != nil {
		return err
	}

	if !sameVFSPutDeleteIdentity(task, response) || response.State != "failed" {
		return fmt.Errorf("%w: invalid VFS Put delete failure receipt", ErrControlPlaneResponse)
	}

	return nil
}

// VFSPutJanitor safely removes complete upload objects left by lost publication races.
type VFSPutJanitor struct {
	control      *VFSControlClient
	drivers      *driver.Registry
	leaseSeconds uint64
}

// VFSPutJanitorResult describes one bounded janitor step.
type VFSPutJanitorResult struct {
	Schema  string `json:"schema"              yaml:"schema"`
	TaskID  string `json:"task_id,omitempty"   yaml:"task_id,omitempty"`
	Driver  string `json:"driver_id,omitempty" yaml:"driver_id,omitempty"`
	Outcome string `json:"outcome"             yaml:"outcome"`
}

// NewVFSPutJanitor constructs a janitor over explicitly compiled driver factories.
func NewVFSPutJanitor(
	control *VFSControlClient,
	drivers *driver.Registry,
	leaseDuration time.Duration,
) (*VFSPutJanitor, error) {
	if leaseDuration < 0 {
		return nil, fmt.Errorf("%w: invalid configuration", ErrInvalidVFSPutJanitor)
	}

	leaseSeconds := uint64(leaseDuration / time.Second) // #nosec G115 -- non-negative duration is checked above.
	if leaseDuration == 0 {
		leaseSeconds = defaultVFSPutDeleteLeaseSeconds
	}

	if control == nil || control.control == nil || drivers == nil || leaseSeconds < 15 || leaseSeconds > 300 {
		return nil, fmt.Errorf("%w: invalid configuration", ErrInvalidVFSPutJanitor)
	}

	return &VFSPutJanitor{control: control, drivers: drivers, leaseSeconds: leaseSeconds}, nil
}

// SweepOne processes at most one globally claimable object, keeping provider I/O bounded.
func (janitor *VFSPutJanitor) SweepOne(ctx context.Context) (VFSPutJanitorResult, error) {
	result := VFSPutJanitorResult{Schema: "carrack.sdk.vfs-put-janitor-result.v1", Outcome: "idle"}

	_, task, err := janitor.control.ClaimPutDelete(ctx, janitor.leaseSeconds)
	if err != nil {
		return result, fmt.Errorf("claim VFS Put delete: %w", err)
	}

	if task == nil {
		return result, nil
	}

	result.TaskID, result.Driver = task.TaskID, task.DriverID

	return janitor.deleteClaimed(ctx, *task, result)
}

func (janitor *VFSPutJanitor) deleteClaimed(
	ctx context.Context,
	task VFSPutDeleteTask,
	result VFSPutJanitorResult,
) (VFSPutJanitorResult, error) {
	grant, err := janitor.control.GrantPutDeleteDriver(ctx, task)
	if err != nil {
		return result, errors.Join(fmt.Errorf("grant VFS Put delete driver: %w", err), janitor.control.FailPutDelete(ctx, task, "driver_grant_failed"))
	}
	defer grant.Clear()

	handle, err := janitor.drivers.Open(ctx, grant.Instance)
	if err != nil {
		return result, errors.Join(fmt.Errorf("open VFS Put delete driver: %w", err), janitor.control.FailPutDelete(ctx, task, "driver_open_failed"))
	}

	if handle.Reader == nil || handle.Deleter == nil || !handle.Descriptor.Capabilities.Delete.Available() {
		return result, errors.Join(
			fmt.Errorf("%w: driver %q cannot Stat and delete; use a driver with exact delete support", ErrInvalidVFSPutJanitor, task.DriverID),
			janitor.control.FailPutDelete(ctx, task, "delete_capability_unavailable"),
		)
	}

	observed, statErr := handle.Reader.Stat(ctx, task.StorageKey)
	absent := errors.Is(statErr, fs.ErrNotExist)

	if statErr != nil && !absent {
		return result, errors.Join(fmt.Errorf("stat VFS Put delete object: %w", statErr), janitor.control.FailPutDelete(ctx, task, "provider_stat_failed"))
	}

	if !absent && !matchesVFSPutDeleteObject(task, observed) {
		return result, errors.Join(ErrVFSPutDeleteIdentityChanged, janitor.control.FailPutDelete(ctx, task, "provider_identity_changed"))
	}

	revalidated, err := janitor.control.RevalidatePutDelete(ctx, task, janitor.leaseSeconds)
	if err != nil {
		return result, fmt.Errorf("revalidate VFS Put delete: %w", err)
	}

	outcome := quarantineDeleteOutcomeAbsent

	if !absent {
		if err := handle.Deleter.Delete(ctx, observed); err != nil {
			return result, errors.Join(fmt.Errorf("delete VFS Put object: %w", err), janitor.control.FailPutDelete(ctx, revalidated, "provider_delete_failed"))
		}

		outcome = operationStateDeleted
	}

	if _, err := janitor.control.CompletePutDelete(ctx, revalidated, outcome); err != nil {
		return result, fmt.Errorf("complete VFS Put delete: %w", err)
	}

	result.Outcome = outcome

	return result, nil
}

func matchesVFSPutDeleteObject(task VFSPutDeleteTask, object driver.Object) bool {
	return (task.NativeID != nil || task.ProviderVersion != nil || task.ETag != nil) &&
		object.Locator.StorageKey == task.StorageKey && object.SizeBytes == task.SizeBytes &&
		optionalVFSDeleteIdentity(task.NativeID, object.Locator.NativeID) &&
		optionalVFSDeleteIdentity(task.ProviderVersion, object.Locator.Version) &&
		optionalVFSDeleteIdentity(task.ETag, object.Locator.ETag)
}

func optionalVFSDeleteIdentity(expected *string, observed string) bool {
	if expected == nil {
		return observed == ""
	}

	return *expected == observed
}

func validClaimedVFSPutDelete(task VFSPutDeleteTask) bool {
	return task.Schema == "carrack.vfs.put-delete-task.v1" && validIdentifier(task.TaskID) &&
		validIdentifier(task.FilesystemID) && validIdentifier(task.DirectoryID) &&
		validControlString(task.DriverID, 256) && task.DriverRevision > 0 &&
		validControlString(task.StorageKey, 1_024) && validDigest(task.EncodedSHA256) &&
		task.DeleteAfter > 0 && task.Incarnation != nil && validIdentifier(*task.Incarnation) &&
		task.FencingToken > 0 && task.LeaseExpiresAt != nil && *task.LeaseExpiresAt > 0 && task.State == "claimed"
}

func sameVFSPutDeleteIdentity(left, right VFSPutDeleteTask) bool {
	return left.TaskID == right.TaskID && left.FilesystemID == right.FilesystemID &&
		left.DirectoryID == right.DirectoryID && left.DriverID == right.DriverID &&
		left.DriverRevision == right.DriverRevision && left.StorageKey == right.StorageKey &&
		left.SizeBytes == right.SizeBytes && left.EncodedSHA256 == right.EncodedSHA256 &&
		optionalStringEqual(left.NativeID, right.NativeID) && optionalStringEqual(left.ProviderVersion, right.ProviderVersion) &&
		optionalStringEqual(left.ETag, right.ETag)
}

func optionalStringEqual(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func validVFSDeleteErrorCode(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}

	for _, character := range value {
		if character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}

	return true
}

func marshalVFSDeleteBody(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal VFS Put delete request: %w", err)
	}

	return body, nil
}
