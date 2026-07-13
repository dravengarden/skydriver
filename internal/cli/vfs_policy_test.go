package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

const (
	cliTestDirectoryID = "019f10b4d77d7000a123456789abcdef"
	cliTestPrincipalID = "019f10b4d77d7000a123456789abcdeb"
	cliTestOperationID = "019f10b4d77d7000a123456789abcdee"
)

func TestVFSACLReplacementModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		flags       vfsACLReplaceFlags
		wantActions []sdk.VFSAction
		wantRole    sdk.VFSRole
		wantError   bool
	}{
		{
			name: "explicit actions",
			flags: vfsACLReplaceFlags{
				actions:          []string{"directory.list", "content.read"},
				expectedRevision: 2,
				idempotencyKey:   "actions-v1",
			},
			wantActions: []sdk.VFSAction{sdk.VFSActionDirectoryList, sdk.VFSActionContentRead},
		},
		{
			name: "fixed role",
			flags: vfsACLReplaceFlags{
				role:             "viewer",
				expectedRevision: 2,
				idempotencyKey:   "role-v1",
			},
			wantRole: sdk.VFSRoleViewer,
		},
		{
			name: "clear",
			flags: vfsACLReplaceFlags{
				clear:            true,
				expectedRevision: 2,
				idempotencyKey:   "clear-v1",
			},
			wantActions: []sdk.VFSAction{},
		},
		{
			name: "missing mode",
			flags: vfsACLReplaceFlags{
				expectedRevision: 2,
				idempotencyKey:   "missing-v1",
			},
			wantError: true,
		},
		{
			name: "conflicting modes",
			flags: vfsACLReplaceFlags{
				actions:          []string{"directory.list"},
				role:             "viewer",
				expectedRevision: 2,
				idempotencyKey:   "conflict-v1",
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request, err := vfsACLReplacement(test.flags, cliTestPrincipalID)
			if test.wantError {
				if !errors.Is(err, errVFSACLSelection) {
					t.Fatalf("expected ACL selection error, got %v", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("construct ACL replacement: %v", err)
			}

			if request.PrincipalID != cliTestPrincipalID || request.Role != test.wantRole ||
				!equalVFSActions(request.Actions, test.wantActions) {
				t.Fatalf("unexpected ACL replacement: %#v", request)
			}
		})
	}
}

func TestParseVFSPlacements(t *testing.T) {
	t.Parallel()

	placements, err := parseVFSPlacements([]string{"archive=secondary=10", "local-main=0"})
	if err != nil {
		t.Fatalf("parse placements: %v", err)
	}

	if len(placements) != 2 || placements[0].DriverID != "archive=secondary" ||
		placements[0].WritePriority != 10 || placements[1].DriverID != "local-main" ||
		placements[1].WritePriority != 0 {
		t.Fatalf("unexpected placements: %#v", placements)
	}

	for _, value := range []string{"local-main", "=0", "local-main=", "local-main=fast"} {
		if _, parseErr := parseVFSPlacements([]string{value}); !errors.Is(parseErr, errVFSPlacement) {
			t.Fatalf("expected placement error for %q, got %v", value, parseErr)
		}
	}
}

func TestVFSPolicyTableOutput(t *testing.T) {
	t.Parallel()

	principalID := cliTestPrincipalID
	role := sdk.VFSRoleViewer
	values := []struct {
		value any
		want  string
	}{
		{
			value: sdk.VFSACL{
				DirectoryID: cliTestDirectoryID,
				ACLInherits: true,
				ACLRevision: 2,
				Grants: []sdk.VFSACLGrant{{
					ID: cliTestOperationID, PrincipalID: &principalID,
					Action: sdk.VFSActionDirectoryList, SourceRole: &role,
				}},
			},
			want: "SOURCE ROLE",
		},
		{
			value: sdk.VFSPlacements{
				DirectoryID: cliTestDirectoryID, PlacementRevision: 3,
				Placements: []sdk.VFSPlacementView{{
					DriverID: "local-main", DriverKind: "local-filesystem/v2",
					DriverRevision: 1, WritePriority: 0, State: "active",
				}},
			},
			want: "WRITE PRIORITY",
		},
		{
			value: sdk.VFSCatalogSyncResult{
				RootDirectoryID: cliTestDirectoryID,
				RootDataRoot:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RootRevision:    3,
				CacheDirectory:  "/tmp/catalog",
				Directories:     2,
				Entries:         1,
				FetchedNodes:    1,
				ReusedNodes:     1,
			},
			want: "FETCHED",
		},
		{
			value: sdk.VFSPolicyMutation{
				OperationID: cliTestOperationID, Kind: "acl.replace", DirectoryID: cliTestDirectoryID,
				FinalRevision: 4, CommittedAt: 2_000_000_000, State: "committed",
			},
			want: "FINAL REVISION",
		},
	}

	for _, value := range values {
		var output bytes.Buffer
		if err := writeValue(&output, outputFormatTable, value.value); err != nil {
			t.Fatalf("write VFS policy table: %v", err)
		}

		if !strings.Contains(output.String(), value.want) {
			t.Fatalf("table output %q does not contain %q", output.String(), value.want)
		}
	}
}

func equalVFSActions(left, right []sdk.VFSAction) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}
