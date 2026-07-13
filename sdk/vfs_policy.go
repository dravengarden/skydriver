package sdk

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
)

const (
	vfsACLSchema           = "carrack.vfs.acl.v1"
	vfsPlacementsSchema    = "carrack.vfs.placements.v1"
	vfsPolicyReceiptSchema = "carrack.vfs.policy-mutation-receipt.v1"
)

// VFSRole is a named UI/API preset expanded into fixed actions when written.
// Stored grants remain explicit actions; roles are not a programmable policy
// language.
type VFSRole string

// Fixed VFS role presets.
const (
	VFSRoleViewer                VFSRole = "viewer"
	VFSRoleEditor                VFSRole = "editor"
	VFSRolePublisher             VFSRole = "publisher"
	VFSRoleSecurityAdministrator VFSRole = "security_administrator"
	VFSRoleStorageOperator       VFSRole = "storage_operator"
	VFSRoleJanitor               VFSRole = "janitor"
	VFSRoleSystemAdministrator   VFSRole = "system_administrator"
)

// VFSACLGrant is one direct allow-only grant. Exactly one of PrincipalID and
// GroupID is set.
type VFSACLGrant struct {
	ID          string    `json:"id"`
	PrincipalID *string   `json:"principal_id"`
	GroupID     *string   `json:"group_id"`
	Action      VFSAction `json:"action"`
	SourceRole  *VFSRole  `json:"source_role"`
}

// VFSACL is the direct grant set and optimistic revision for one directory.
type VFSACL struct {
	Schema      string        `json:"schema"`
	DirectoryID string        `json:"directory_id"`
	ACLInherits bool          `json:"acl_inherits"`
	ACLRevision uint64        `json:"acl_revision"`
	Grants      []VFSACLGrant `json:"grants"`
}

// VFSReplaceACLRequest replaces every direct action for one principal. Set
// exactly one of Actions or Role. A non-nil empty Actions slice removes all
// direct grants for that principal.
type VFSReplaceACLRequest struct {
	PrincipalID         string      `json:"principal_id"`
	Actions             []VFSAction `json:"actions"`
	Role                VFSRole     `json:"role,omitempty"`
	ExpectedACLRevision uint64      `json:"expected_acl_revision"`
	IdempotencyKey      string      `json:"idempotency_key"`
}

// VFSPlacement is one active write placement. Smaller priorities are preferred.
type VFSPlacement struct {
	DriverID      string `json:"driver_id"`
	WritePriority uint64 `json:"write_priority"`
}

// VFSPlacementView includes non-secret driver identity for one placement.
type VFSPlacementView struct {
	DriverID       string `json:"driver_id"`
	DriverKind     string `json:"driver_kind"`
	DriverRevision uint64 `json:"driver_revision"`
	WritePriority  uint64 `json:"write_priority"`
	State          string `json:"state"`
}

// VFSPlacements is the complete active/disabled placement set and optimistic revision.
type VFSPlacements struct {
	Schema            string             `json:"schema"`
	DirectoryID       string             `json:"directory_id"`
	PlacementRevision uint64             `json:"placement_revision"`
	Placements        []VFSPlacementView `json:"placements"`
}

// VFSReplacePlacementsRequest replaces the complete placement set. This
// replace-all operation requires an unscoped driver-management token.
type VFSReplacePlacementsRequest struct {
	Placements                []VFSPlacement `json:"placements"`
	ExpectedPlacementRevision uint64         `json:"expected_placement_revision"`
	IdempotencyKey            string         `json:"idempotency_key"`
}

// VFSPolicyMutation is an idempotent optimistic policy receipt. Policy holds
// the canonical ACL subject/actions or placement set committed by the server.
type VFSPolicyMutation struct {
	Schema        string          `json:"schema"`
	OperationID   string          `json:"operation_id"`
	Kind          string          `json:"kind"`
	DirectoryID   string          `json:"directory_id"`
	FinalRevision uint64          `json:"final_revision"`
	Policy        json.RawMessage `json:"policy"`
	CommittedAt   uint64          `json:"committed_at"`
	State         string          `json:"state"`
}

// ACL reads direct grants. Effective inherited authority is still evaluated
// dynamically by the control plane on every operation.
func (client *VFSControlClient) ACL(ctx context.Context, directoryID string) (VFSACL, error) {
	if client == nil || client.control == nil || !validIdentifier(directoryID) {
		return VFSACL{}, fmt.Errorf("%w: invalid VFS ACL query", ErrInvalidControlPlane)
	}

	var response VFSACL

	path := "/api/v2/directories/" + directoryID + "/acl"
	if err := client.control.authenticatedGet(ctx, path, url.Values{}, &response); err != nil {
		return VFSACL{}, err
	}

	if !validVFSACL(response, directoryID) {
		return VFSACL{}, fmt.Errorf("%w: invalid VFS ACL response", ErrControlPlaneResponse)
	}

	return response, nil
}

// ReplaceACL atomically replaces one principal's direct grants at an exact ACL revision.
func (client *VFSControlClient) ReplaceACL(
	ctx context.Context,
	directoryID string,
	requested VFSReplaceACLRequest,
) (VFSPolicyMutation, error) {
	canonical, err := canonicalACLRequest(directoryID, requested)
	if err != nil {
		return VFSPolicyMutation{}, err
	}

	body, err := json.Marshal(canonical.Wire)
	if err != nil {
		return VFSPolicyMutation{}, fmt.Errorf("marshal VFS ACL replacement: %w", err)
	}

	var response VFSPolicyMutation

	path := "/api/v2/directories/" + directoryID + "/acl/replace"
	if postErr := client.postJSON(ctx, path, body, &response); postErr != nil {
		return VFSPolicyMutation{}, postErr
	}

	var policy struct {
		PrincipalID string   `json:"principal_id"`
		Actions     []string `json:"actions"`
		SourceRole  *string  `json:"source_role"`
	}
	if !validPolicyMutation(response, "acl.replace", directoryID, requested.ExpectedACLRevision) ||
		json.Unmarshal(response.Policy, &policy) != nil || policy.PrincipalID != requested.PrincipalID ||
		!slices.Equal(policy.Actions, canonical.Actions) ||
		!equalOptionalString(policy.SourceRole, canonical.Role) {
		return VFSPolicyMutation{}, fmt.Errorf("%w: invalid VFS ACL receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

// Placements reads non-secret driver placement metadata for one directory.
func (client *VFSControlClient) Placements(
	ctx context.Context,
	directoryID string,
) (VFSPlacements, error) {
	if client == nil || client.control == nil || !validIdentifier(directoryID) {
		return VFSPlacements{}, fmt.Errorf("%w: invalid VFS placements query", ErrInvalidControlPlane)
	}

	var response VFSPlacements

	path := "/api/v2/directories/" + directoryID + "/placements"
	if err := client.control.authenticatedGet(ctx, path, url.Values{}, &response); err != nil {
		return VFSPlacements{}, err
	}

	if !validVFSPlacements(response, directoryID) {
		return VFSPlacements{}, fmt.Errorf("%w: invalid VFS placements response", ErrControlPlaneResponse)
	}

	return response, nil
}

// ReplacePlacements atomically replaces the complete placement set at an exact revision.
func (client *VFSControlClient) ReplacePlacements(
	ctx context.Context,
	directoryID string,
	requested VFSReplacePlacementsRequest,
) (VFSPolicyMutation, error) {
	wire, placements, err := canonicalPlacementsRequest(directoryID, requested)
	if err != nil {
		return VFSPolicyMutation{}, err
	}

	body, err := json.Marshal(wire)
	if err != nil {
		return VFSPolicyMutation{}, fmt.Errorf("marshal VFS placement replacement: %w", err)
	}

	var response VFSPolicyMutation

	path := "/api/v2/directories/" + directoryID + "/placements/replace"
	if postErr := client.postJSON(ctx, path, body, &response); postErr != nil {
		return VFSPolicyMutation{}, postErr
	}

	var policy struct {
		Placements []VFSPlacement `json:"placements"`
	}
	if !validPolicyMutation(response, "placement.replace", directoryID, requested.ExpectedPlacementRevision) ||
		json.Unmarshal(response.Policy, &policy) != nil || !slices.Equal(policy.Placements, placements) {
		return VFSPolicyMutation{}, fmt.Errorf("%w: invalid VFS placement receipt", ErrControlPlaneResponse)
	}

	return response, nil
}

type replaceACLWire struct {
	PrincipalID         string   `json:"principal_id"`
	Actions             []string `json:"actions"`
	Role                *string  `json:"role"`
	ExpectedACLRevision uint64   `json:"expected_acl_revision"`
	IdempotencyKey      string   `json:"idempotency_key"`
}

type canonicalACL struct {
	Wire    replaceACLWire
	Actions []string
	Role    *string
}

func canonicalACLRequest(directoryID string, request VFSReplaceACLRequest) (canonicalACL, error) {
	if !validIdentifier(directoryID) || !validIdentifier(request.PrincipalID) ||
		request.ExpectedACLRevision == 0 || !validControlString(request.IdempotencyKey, 256) ||
		(request.Actions == nil) == (request.Role == "") {
		return canonicalACL{}, fmt.Errorf("%w: invalid VFS ACL replacement", ErrInvalidControlPlane)
	}

	if request.Role != "" {
		if !validVFSRole(request.Role) {
			return canonicalACL{}, fmt.Errorf("%w: invalid VFS role", ErrInvalidControlPlane)
		}

		role := string(request.Role)

		return canonicalACL{
			Wire: replaceACLWire{
				PrincipalID: request.PrincipalID, Role: &role,
				ExpectedACLRevision: request.ExpectedACLRevision, IdempotencyKey: request.IdempotencyKey,
			},
			Actions: roleActions(request.Role), Role: &role,
		}, nil
	}

	actionSet := make(map[string]struct{}, len(request.Actions))
	for _, action := range request.Actions {
		if !validVFSAction(action) {
			return canonicalACL{}, fmt.Errorf("%w: invalid VFS action", ErrInvalidControlPlane)
		}

		actionSet[string(action)] = struct{}{}
	}

	actions := make([]string, 0, len(actionSet))
	for action := range actionSet {
		actions = append(actions, action)
	}

	slices.Sort(actions)

	return canonicalACL{
		Wire: replaceACLWire{
			PrincipalID: request.PrincipalID, Actions: actions,
			ExpectedACLRevision: request.ExpectedACLRevision, IdempotencyKey: request.IdempotencyKey,
		},
		Actions: actions,
	}, nil
}

func canonicalPlacementsRequest(directoryID string, request VFSReplacePlacementsRequest) (VFSReplacePlacementsRequest, []VFSPlacement, error) {
	if !validIdentifier(directoryID) || request.ExpectedPlacementRevision == 0 ||
		!validControlString(request.IdempotencyKey, 256) || len(request.Placements) == 0 || len(request.Placements) > 256 {
		return VFSReplacePlacementsRequest{}, nil, fmt.Errorf("%w: invalid VFS placement replacement", ErrInvalidControlPlane)
	}

	placements := slices.Clone(request.Placements)
	slices.SortFunc(placements, func(left, right VFSPlacement) int {
		if priority := cmp.Compare(left.WritePriority, right.WritePriority); priority != 0 {
			return priority
		}

		return slices.Compare([]byte(left.DriverID), []byte(right.DriverID))
	})
	drivers := make(map[string]struct{}, len(placements))

	priorities := make(map[uint64]struct{}, len(placements))
	for _, placement := range placements {
		if !validControlString(placement.DriverID, 256) {
			return VFSReplacePlacementsRequest{}, nil, fmt.Errorf("%w: invalid VFS placement", ErrInvalidControlPlane)
		}

		drivers[placement.DriverID] = struct{}{}
		priorities[placement.WritePriority] = struct{}{}
	}

	if len(drivers) != len(placements) || len(priorities) != len(placements) {
		return VFSReplacePlacementsRequest{}, nil, fmt.Errorf("%w: duplicate VFS placement", ErrInvalidControlPlane)
	}

	request.Placements = placements

	return request, placements, nil
}

func validVFSACL(response VFSACL, directoryID string) bool {
	if response.Schema != vfsACLSchema || response.DirectoryID != directoryID || response.ACLRevision == 0 {
		return false
	}

	for _, grant := range response.Grants {
		if !validIdentifier(grant.ID) || (grant.PrincipalID == nil) == (grant.GroupID == nil) ||
			grant.PrincipalID != nil && !validIdentifier(*grant.PrincipalID) ||
			grant.GroupID != nil && !validIdentifier(*grant.GroupID) || !validVFSAction(grant.Action) {
			return false
		}
	}

	return true
}

func validVFSPlacements(response VFSPlacements, directoryID string) bool {
	if response.Schema != vfsPlacementsSchema || response.DirectoryID != directoryID || response.PlacementRevision == 0 {
		return false
	}

	for _, placement := range response.Placements {
		if !validControlString(placement.DriverID, 256) || !validControlString(placement.DriverKind, 256) ||
			placement.DriverRevision == 0 || placement.State != "active" && placement.State != "disabled" {
			return false
		}
	}

	return true
}

func validPolicyMutation(response VFSPolicyMutation, kind, directoryID string, expectedRevision uint64) bool {
	return response.Schema == vfsPolicyReceiptSchema && validIdentifier(response.OperationID) &&
		response.Kind == kind && response.DirectoryID == directoryID &&
		response.FinalRevision >= expectedRevision && response.CommittedAt > 0 &&
		response.State == vfsCommittedState && json.Valid(response.Policy)
}

func validVFSRole(role VFSRole) bool {
	switch role {
	case VFSRoleViewer, VFSRoleEditor, VFSRolePublisher, VFSRoleSecurityAdministrator,
		VFSRoleStorageOperator, VFSRoleJanitor, VFSRoleSystemAdministrator:
		return true
	default:
		return false
	}
}

func roleActions(role VFSRole) []string {
	roles := map[VFSRole][]string{
		VFSRoleViewer:                {string(VFSActionContentRead), string(VFSActionDirectoryList)},
		VFSRoleEditor:                {string(VFSActionContentRead), string(VFSActionContentWrite), string(VFSActionDirectoryList), string(VFSActionEntryDelete)},
		VFSRolePublisher:             {string(VFSActionContentRead), string(VFSActionContentWrite), string(VFSActionDirectoryList), string(VFSActionEntryDelete), string(VFSActionSnapshotPublish)},
		VFSRoleSecurityAdministrator: {string(VFSActionACLManage), string(VFSActionAuditRead), string(VFSActionDirectoryList), string(VFSActionTokenIssue)},
		VFSRoleStorageOperator:       {string(VFSActionAuditRead), string(VFSActionDriverManage), string(VFSActionDriverUse)},
		VFSRoleJanitor:               {string(VFSActionAuditRead), string(VFSActionDriverUse), string(VFSActionGCRun)},
		VFSRoleSystemAdministrator:   {string(VFSActionACLManage), string(VFSActionAuditRead), string(VFSActionDriverManage), string(VFSActionGCRun), string(VFSActionSystemManage), string(VFSActionTokenIssue)},
	}

	return slices.Clone(roles[role])
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
