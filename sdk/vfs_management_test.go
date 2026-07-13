package sdk_test

import (
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

const (
	testDirectoryID   = "019f10b4d77d7000a123456789abcdef"
	testFilesystemID  = "019f10b4d77d7000a123456789abcdea"
	testPrincipalID   = "019f10b4d77d7000a123456789abcdeb"
	testParentTokenID = "019f10b4d77d7000a123456789abcdec"
	testChildTokenID  = "019f10b4d77d7000a123456789abcded"
	testOperationID   = "019f10b4d77d7000a123456789abcdee"
	testChildDirID    = "019f10b4d77d7000a123456789abcdef"
)

func TestVFSManagementClient(t *testing.T) {
	t.Parallel()

	parentBytes := [32]byte{}
	childBytes := [32]byte{}

	for index := range parentBytes {
		parentBytes[index] = 1
		childBytes[index] = 2
	}

	parentEncoded := base64.RawURLEncoding.EncodeToString(parentBytes[:])
	childEncoded := base64.RawURLEncoding.EncodeToString(childBytes[:])

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+parentEncoded {
			http.Error(writer, "missing bearer", http.StatusUnauthorized)

			return
		}

		writer.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v2/directories/" + testDirectoryID + "/children":
			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.directory-create-receipt.v1","operation_id":%q,"filesystem_id":%q,"parent_directory_id":%q,"directory_id":%q,"name":"releases","data_root":%q,"crypto_suite":"carrack-vfs-aes256gcm-hkdfsha256-v1","key_epoch":1,"catalog_revision_id":7,"created_at":1999999000,"state":"committed"}`,
				testOperationID,
				testFilesystemID,
				testDirectoryID,
				testChildDirID,
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			)
		case "/api/v2/directories/" + testDirectoryID + "/entries":
			if request.Method != http.MethodGet || request.URL.Query().Get("limit") != "25" {
				http.Error(writer, "invalid directory request", http.StatusBadRequest)

				return
			}

			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.directory-list.v1","directory":{"id":%q,"filesystem_id":%q,"parent_id":null,"name":"","data_root":%q,"crypto_suite":"plaintext/v1","active_key_epoch":1,"acl_inherits":false,"revision":3,"acl_revision":13,"placement_revision":2},"entries":[],"next_cursor":null}`,
				testDirectoryID,
				testFilesystemID,
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			)
		case "/api/v2/tokens":
			var body struct {
				RootDirectoryID string   `json:"root_directory_id"`
				Actions         []string `json:"actions"`
				DriverIDs       []string `json:"driver_ids"`
				ExpiresAt       uint64   `json:"expires_at"`
				IdempotencyKey  string   `json:"idempotency_key"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				http.Error(writer, "invalid JSON", http.StatusBadRequest)

				return
			}

			if body.RootDirectoryID != testDirectoryID ||
				!reflect.DeepEqual(body.Actions, []string{"content.read", "directory.list"}) ||
				!reflect.DeepEqual(body.DriverIDs, []string{"archive", "local-main"}) ||
				body.ExpiresAt != 2_000_000_000 || body.IdempotencyKey != "ai-reader-v1" {
				http.Error(writer, "noncanonical token request", http.StatusBadRequest)

				return
			}

			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.token-issue-receipt.v1","token_id":%q,"principal_id":%q,"parent_token_id":%q,"root_directory_id":%q,"actions":["content.read","directory.list"],"driver_ids":["archive","local-main"],"expires_at":2000000000,"token":%q}`,
				testChildTokenID,
				testPrincipalID,
				testParentTokenID,
				testDirectoryID,
				childEncoded,
			)
		case "/api/v2/tokens/" + testChildTokenID + "/revoke":
			_, _ = fmt.Fprintf(
				writer,
				`{"schema":"carrack.vfs.token-revoke-receipt.v1","token_id":%q,"principal_id":%q,"root_directory_id":%q,"revoked_at":1999999000,"state":"revoked"}`,
				testChildTokenID,
				testPrincipalID,
				testDirectoryID,
			)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	parent, err := sdk.ParseVFSToken(parentEncoded)
	if err != nil {
		t.Fatalf("parse parent token: %v", err)
	}

	client, err := sdk.NewVFSControlClient(server.URL, parent, server.Client())
	if err != nil {
		t.Fatalf("construct VFS control client: %v", err)
	}

	created, err := client.CreateDirectory(context.Background(), testDirectoryID, sdk.VFSCreateDirectoryRequest{
		Name:           "releases",
		IdempotencyKey: "mkdir-releases-v1",
	})
	if err != nil {
		t.Fatalf("create directory: %v", err)
	}

	if created.DirectoryID != testChildDirID || created.ParentDirectoryID != testDirectoryID {
		t.Fatalf("unexpected directory creation: %#v", created)
	}

	page, err := client.ListDirectory(context.Background(), testDirectoryID, "", 25)
	if err != nil {
		t.Fatalf("list directory: %v", err)
	}

	if page.Directory.ID != testDirectoryID || len(page.Entries) != 0 || page.NextCursor != "" {
		t.Fatalf("unexpected directory page: %#v", page)
	}

	issued, err := client.IssueToken(context.Background(), sdk.VFSIssueTokenRequest{
		RootDirectoryID: testDirectoryID,
		Actions: []sdk.VFSAction{
			sdk.VFSActionDirectoryList,
			sdk.VFSActionContentRead,
			sdk.VFSActionDirectoryList,
		},
		DriverIDs:      []string{"local-main", "archive", "local-main"},
		ExpiresAt:      2_000_000_000,
		IdempotencyKey: "ai-reader-v1",
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	if issued.TokenID != testChildTokenID || issued.Bearer.Encode() != childEncoded {
		t.Fatalf("unexpected issued token: %#v", issued)
	}

	issued.Clear()

	if encoded := issued.Bearer.Encode(); encoded != "" {
		t.Fatalf("cleared bearer still encodes as %q", encoded)
	}

	revoked, err := client.RevokeToken(context.Background(), testChildTokenID, "revoke-reader-v1")
	if err != nil {
		t.Fatalf("revoke token: %v", err)
	}

	if revoked.TokenID != testChildTokenID || revoked.State != "revoked" {
		t.Fatalf("unexpected revoke receipt: %#v", revoked)
	}
}
