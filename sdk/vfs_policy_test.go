package sdk_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dravengarden/carrack/sdk"
)

func TestVFSPolicyClient(t *testing.T) {
	t.Parallel()

	tokenBytes := bytes.Repeat([]byte{3}, 32)
	encodedToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(writer, "missing bearer", http.StatusUnauthorized)

			return
		}

		writer.Header().Set("Content-Type", "application/json")

		switch request.Method + " " + request.URL.Path {
		case http.MethodGet + " /api/v2/directories/" + testDirectoryID + "/acl":
			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.acl.v1","directory_id":%q,"acl_inherits":true,"acl_revision":2,"grants":[{"id":%q,"principal_id":%q,"group_id":null,"action":"directory.list","source_role":"viewer"}]}`,
				testDirectoryID,
				testOperationID,
				testPrincipalID,
			)
		case http.MethodPost + " /api/v2/directories/" + testDirectoryID + "/acl/replace":
			assertACLReplacement(t, request)

			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.policy-mutation-receipt.v1","operation_id":%q,"kind":"acl.replace","directory_id":%q,"final_revision":5,"policy":{"principal_id":%q,"actions":["content.read","directory.list"],"source_role":"viewer"},"committed_at":1999999000,"state":"committed"}`,
				testOperationID,
				testDirectoryID,
				testPrincipalID,
			)
		case http.MethodGet + " /api/v2/directories/" + testDirectoryID + "/placements":
			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.placements.v1","directory_id":%q,"placement_revision":3,"placements":[{"driver_id":"local-main","driver_kind":"local-filesystem/v2","driver_revision":1,"write_priority":0,"state":"active"}]}`,
				testDirectoryID,
			)
		case http.MethodPost + " /api/v2/directories/" + testDirectoryID + "/placements/replace":
			assertPlacementReplacement(t, request)

			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.policy-mutation-receipt.v1","operation_id":%q,"kind":"placement.replace","directory_id":%q,"final_revision":7,"policy":{"placements":[{"driver_id":"local-main","write_priority":0},{"driver_id":"archive","write_priority":10}]},"committed_at":1999999000,"state":"committed"}`,
				testOperationID,
				testDirectoryID,
			)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	token, err := sdk.ParseVFSToken(encodedToken)
	if err != nil {
		t.Fatalf("parse VFS token: %v", err)
	}
	defer token.Clear()

	client, err := sdk.NewVFSControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct VFS control client: %v", err)
	}
	defer client.Clear()

	acl, err := client.ACL(context.Background(), testDirectoryID)
	if err != nil {
		t.Fatalf("read ACL: %v", err)
	}

	if acl.ACLRevision != 2 || len(acl.Grants) != 1 || acl.Grants[0].SourceRole == nil ||
		*acl.Grants[0].SourceRole != sdk.VFSRoleViewer {
		t.Fatalf("unexpected ACL: %#v", acl)
	}

	aclReceipt, err := client.ReplaceACL(context.Background(), testDirectoryID, sdk.VFSReplaceACLRequest{
		PrincipalID:         testPrincipalID,
		Role:                sdk.VFSRoleViewer,
		ExpectedACLRevision: 2,
		IdempotencyKey:      "viewer-v1",
	})
	if err != nil {
		t.Fatalf("replace ACL: %v", err)
	}

	if aclReceipt.Kind != "acl.replace" || aclReceipt.FinalRevision != 5 {
		t.Fatalf("unexpected ACL receipt: %#v", aclReceipt)
	}

	placements, err := client.Placements(context.Background(), testDirectoryID)
	if err != nil {
		t.Fatalf("read placements: %v", err)
	}

	if placements.PlacementRevision != 3 || len(placements.Placements) != 1 ||
		placements.Placements[0].DriverID != "local-main" {
		t.Fatalf("unexpected placements: %#v", placements)
	}

	placementReceipt, err := client.ReplacePlacements(
		context.Background(),
		testDirectoryID,
		sdk.VFSReplacePlacementsRequest{
			Placements: []sdk.VFSPlacement{
				{DriverID: "archive", WritePriority: 10},
				{DriverID: "local-main", WritePriority: 0},
			},
			ExpectedPlacementRevision: 3,
			IdempotencyKey:            "primary-backup-v1",
		},
	)
	if err != nil {
		t.Fatalf("replace placements: %v", err)
	}

	if placementReceipt.Kind != "placement.replace" || placementReceipt.FinalRevision != 7 {
		t.Fatalf("unexpected placement receipt: %#v", placementReceipt)
	}
}

func assertACLReplacement(t *testing.T, request *http.Request) {
	t.Helper()

	var body struct {
		PrincipalID         string   `json:"principal_id"`
		Actions             []string `json:"actions"`
		Role                *string  `json:"role"`
		ExpectedACLRevision uint64   `json:"expected_acl_revision"`
		IdempotencyKey      string   `json:"idempotency_key"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		t.Errorf("decode ACL replacement: %v", err)

		return
	}

	if body.PrincipalID != testPrincipalID || body.Actions != nil || body.Role == nil ||
		*body.Role != "viewer" || body.ExpectedACLRevision != 2 || body.IdempotencyKey != "viewer-v1" {
		t.Errorf("unexpected ACL replacement: %#v", body)
	}
}

func assertPlacementReplacement(t *testing.T, request *http.Request) {
	t.Helper()

	var body sdk.VFSReplacePlacementsRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		t.Errorf("decode placement replacement: %v", err)

		return
	}

	want := []sdk.VFSPlacement{
		{DriverID: "local-main", WritePriority: 0},
		{DriverID: "archive", WritePriority: 10},
	}
	if !reflect.DeepEqual(body.Placements, want) || body.ExpectedPlacementRevision != 3 ||
		body.IdempotencyKey != "primary-backup-v1" {
		t.Errorf("unexpected placement replacement: %#v", body)
	}
}
