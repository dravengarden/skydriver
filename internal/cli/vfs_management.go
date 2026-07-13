package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/sdk"
)

const (
	vfsDirectoryCommandName = "directory"
	vfsTokenCommandName     = "token" // #nosec G101 -- command name, not a credential.
	vfsListCommandName      = "list"
	vfsCreateCommandName    = "create"
	vfsIssueCommandName     = "issue"
	vfsRevokeCommandName    = "revoke"
)

type vfsDirectoryListFlags struct {
	controlURL   string
	cursor       string
	limit        uint32
	outputFormat string
}

type vfsDirectoryCreateFlags struct {
	controlURL     string
	cryptoSuite    string
	idempotencyKey string
	outputFormat   string
}

type vfsTokenIssueFlags struct {
	controlURL     string
	actions        []string
	driverIDs      []string
	expiresAt      uint64
	idempotencyKey string
	outputFormat   string
}

type vfsTokenRevokeFlags struct {
	controlURL     string
	idempotencyKey string
	outputFormat   string
}

type vfsTokenIssueOutput struct {
	Schema          string          `json:"schema"               yaml:"schema"`
	TokenID         string          `json:"token_id"             yaml:"token_id"`
	PrincipalID     string          `json:"principal_id"         yaml:"principal_id"`
	ParentTokenID   string          `json:"parent_token_id"      yaml:"parent_token_id"`
	RootDirectoryID string          `json:"root_directory_id"    yaml:"root_directory_id"`
	Actions         []sdk.VFSAction `json:"actions"              yaml:"actions"`
	DriverIDs       []string        `json:"driver_ids,omitempty" yaml:"driver_ids,omitempty"`
	ExpiresAt       uint64          `json:"expires_at"           yaml:"expires_at"`
	Token           string          `json:"token"                yaml:"token"` // #nosec G117 -- deliberate one-time CLI output.
}

func newVFSDirectoryCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   vfsDirectoryCommandName,
		Short: "Read and manage VFS directories",
	}
	command.AddCommand(
		newVFSDirectoryListCommand(ctx, stdout),
		newVFSDirectoryCreateCommand(ctx, stdout),
	)

	return command
}

func newVFSDirectoryCreateCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsDirectoryCreateFlags

	command := &cobra.Command{
		Use:   vfsCreateCommandName + " PARENT_DIRECTORY_ID NAME",
		Short: "Create an empty child and atomically publish its Merkle path",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSDirectoryCreate(
				ctx,
				flags,
				arguments[0],
				arguments[1],
				defaultGetenv,
			)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.cryptoSuite, "crypto-suite", "", "child crypto suite; empty inherits the parent")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact child-directory creation")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, idempotencyKeyFlag} {
		mustMarkRequired(command, name)
	}

	return command
}

func newVFSDirectoryListCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsDirectoryListFlags

	command := &cobra.Command{
		Use:   vfsListCommandName + " DIRECTORY_ID",
		Short: "List one revision-consistent VFS directory page",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSDirectoryList(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.cursor, "cursor", "", "opaque cursor returned by the preceding page")
	command.Flags().Uint32Var(&flags.limit, "limit", 0, "page size from 1 through 1000; zero uses the server default")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")
	mustMarkRequired(command, controlURLFlag)

	return command
}

func newVFSTokenCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   vfsTokenCommandName,
		Short: "Issue and revoke attenuated VFS tokens",
	}
	command.AddCommand(
		newVFSTokenIssueCommand(ctx, stdout),
		newVFSTokenRevokeCommand(ctx, stdout),
	)

	return command
}

func newVFSTokenIssueCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsTokenIssueFlags

	command := &cobra.Command{
		Use:   vfsIssueCommandName + " ROOT_DIRECTORY_ID",
		Short: "Issue a same-principal token with narrower explicit scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSTokenIssue(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringSliceVar(&flags.actions, "action", nil, "exact VFS action; repeat for each allowed action")
	command.Flags().StringSliceVar(&flags.driverIDs, "driver-id", nil, "allowed driver ID; omit to inherit an unrestricted parent scope")
	command.Flags().Uint64Var(&flags.expiresAt, "expires-at", 0, "absolute Unix expiry; keeps idempotent retries byte-stable")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact child-token scope")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, "action", "expires-at", idempotencyKeyFlag} {
		mustMarkRequired(command, name)
	}

	return command
}

func newVFSTokenRevokeCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsTokenRevokeFlags

	command := &cobra.Command{
		Use:   vfsRevokeCommandName + " TOKEN_ID",
		Short: "Monotonically revoke one same-principal VFS token",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSTokenRevoke(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact token revocation")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, idempotencyKeyFlag} {
		mustMarkRequired(command, name)
	}

	return command
}

func executeVFSDirectoryList(
	ctx context.Context,
	flags vfsDirectoryListFlags,
	directoryID string,
	getenv func(string) string,
) (sdk.VFSDirectoryPage, error) {
	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSDirectoryPage{}, err
	}
	defer control.Clear()

	page, err := control.ListDirectory(ctx, directoryID, flags.cursor, flags.limit)
	if err != nil {
		return sdk.VFSDirectoryPage{}, fmt.Errorf("list VFS directory: %w", err)
	}

	return page, nil
}

func executeVFSDirectoryCreate(
	ctx context.Context,
	flags vfsDirectoryCreateFlags,
	parentDirectoryID,
	name string,
	getenv func(string) string,
) (sdk.VFSDirectoryCreation, error) {
	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSDirectoryCreation{}, err
	}
	defer control.Clear()

	created, err := control.CreateDirectory(ctx, parentDirectoryID, sdk.VFSCreateDirectoryRequest{
		Name:           name,
		CryptoSuite:    flags.cryptoSuite,
		IdempotencyKey: flags.idempotencyKey,
	})
	if err != nil {
		return sdk.VFSDirectoryCreation{}, fmt.Errorf("create VFS directory: %w", err)
	}

	return created, nil
}

func executeVFSTokenIssue(
	ctx context.Context,
	flags vfsTokenIssueFlags,
	rootDirectoryID string,
	getenv func(string) string,
) (vfsTokenIssueOutput, error) {
	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return vfsTokenIssueOutput{}, err
	}
	defer control.Clear()

	actions := make([]sdk.VFSAction, len(flags.actions))
	for index, action := range flags.actions {
		actions[index] = sdk.VFSAction(action)
	}

	issued, err := control.IssueToken(ctx, sdk.VFSIssueTokenRequest{
		RootDirectoryID: rootDirectoryID,
		Actions:         actions,
		DriverIDs:       flags.driverIDs,
		ExpiresAt:       flags.expiresAt,
		IdempotencyKey:  flags.idempotencyKey,
	})
	if err != nil {
		return vfsTokenIssueOutput{}, fmt.Errorf("issue VFS token: %w", err)
	}
	defer issued.Clear()

	return vfsTokenIssueOutput{
		Schema:          issued.Schema,
		TokenID:         issued.TokenID,
		PrincipalID:     issued.PrincipalID,
		ParentTokenID:   issued.ParentTokenID,
		RootDirectoryID: issued.RootDirectoryID,
		Actions:         append([]sdk.VFSAction(nil), issued.Actions...),
		DriverIDs:       append([]string(nil), issued.DriverIDs...),
		ExpiresAt:       issued.ExpiresAt,
		Token:           issued.Bearer.Encode(),
	}, nil
}

func executeVFSTokenRevoke(
	ctx context.Context,
	flags vfsTokenRevokeFlags,
	tokenID string,
	getenv func(string) string,
) (sdk.VFSTokenRevocation, error) {
	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSTokenRevocation{}, err
	}
	defer control.Clear()

	receipt, err := control.RevokeToken(ctx, tokenID, flags.idempotencyKey)
	if err != nil {
		return sdk.VFSTokenRevocation{}, fmt.Errorf("revoke VFS token: %w", err)
	}

	return receipt, nil
}

func newVFSControlClientFromEnvironment(
	controlURL string,
	getenv func(string) string,
) (*sdk.VFSControlClient, error) {
	if getenv == nil {
		return nil, errVFSEnvironment
	}

	token, err := sdk.ParseVFSToken(getenv(vfsTokenEnvironment))
	if err != nil {
		return nil, fmt.Errorf("parse VFS token: %w", err)
	}
	defer token.Clear()

	control, err := sdk.NewVFSControlClient(controlURL, token, &http.Client{})
	if err != nil {
		return nil, fmt.Errorf("construct VFS control client: %w", err)
	}

	return control, nil
}

func writeVFSDirectoryPageTable(
	table *tabwriter.Writer,
	page sdk.VFSDirectoryPage,
) error {
	if _, err := fmt.Fprintf(
		table,
		"DIRECTORY ID\tREVISION\tACL REVISION\tDATA ROOT\tNEXT CURSOR\n%s\t%d\t%d\t%s\t%s\n",
		page.Directory.ID,
		page.Directory.Revision,
		page.Directory.ACLRevision,
		page.Directory.DataRoot,
		page.NextCursor,
	); err != nil {
		return fmt.Errorf("write VFS directory identity table: %w", err)
	}

	if _, err := fmt.Fprintln(table, "NAME\tKIND\tBYTES\tREVISION\tTARGET ID"); err != nil {
		return fmt.Errorf("write VFS directory-entry header: %w", err)
	}

	for _, entry := range page.Entries {
		if _, err := fmt.Fprintf(
			table,
			"%s\t%s\t%d\t%d\t%s\n",
			entry.Name,
			entry.Kind,
			entry.SizeBytes,
			entry.Revision,
			vfsEntryTargetID(entry),
		); err != nil {
			return fmt.Errorf("write VFS directory entry: %w", err)
		}
	}

	return nil
}

func vfsEntryTargetID(entry sdk.VFSDirectoryEntry) string {
	if entry.FileID != nil {
		return *entry.FileID
	}

	if entry.ChildDirectoryID != nil {
		return *entry.ChildDirectoryID
	}

	return ""
}

func supportsVFSManagementTable(value any) bool {
	switch value.(type) {
	case sdk.VFSDirectoryPage,
		sdk.VFSDirectoryCreation,
		sdk.VFSACL,
		sdk.VFSCatalogSyncResult,
		sdk.VFSPlacements,
		sdk.VFSPolicyMutation,
		vfsTokenIssueOutput,
		sdk.VFSTokenRevocation:
		return true
	default:
		return false
	}
}

func writeVFSManagementTable(writer io.Writer, value any) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)

	switch typedValue := value.(type) {
	case sdk.VFSDirectoryPage:
		if err := writeVFSDirectoryPageTable(table, typedValue); err != nil {
			return err
		}
	case sdk.VFSDirectoryCreation:
		if _, err := fmt.Fprintf(
			table,
			"DIRECTORY ID\tPARENT DIRECTORY ID\tNAME\tCRYPTO SUITE\tCATALOG REVISION\tSTATE\n%s\t%s\t%s\t%s\t%d\t%s\n",
			typedValue.DirectoryID,
			typedValue.ParentDirectoryID,
			typedValue.Name,
			typedValue.CryptoSuite,
			typedValue.CatalogRevisionID,
			typedValue.State,
		); err != nil {
			return fmt.Errorf("write VFS directory-create table: %w", err)
		}
	case sdk.VFSACL:
		if err := writeVFSACLTable(table, typedValue); err != nil {
			return err
		}
	case sdk.VFSCatalogSyncResult:
		if err := writeVFSCatalogSyncTable(table, typedValue); err != nil {
			return err
		}
	case sdk.VFSPlacements:
		if err := writeVFSPlacementsTable(table, typedValue); err != nil {
			return err
		}
	case sdk.VFSPolicyMutation:
		if err := writeVFSPolicyMutationTable(table, typedValue); err != nil {
			return err
		}
	case vfsTokenIssueOutput:
		if _, err := fmt.Fprintf(
			table,
			"TOKEN ID\tPRINCIPAL ID\tROOT DIRECTORY ID\tEXPIRES AT\tTOKEN\n%s\t%s\t%s\t%d\t%s\n",
			typedValue.TokenID,
			typedValue.PrincipalID,
			typedValue.RootDirectoryID,
			typedValue.ExpiresAt,
			typedValue.Token,
		); err != nil {
			return fmt.Errorf("write VFS token table: %w", err)
		}
	case sdk.VFSTokenRevocation:
		if _, err := fmt.Fprintf(
			table,
			"TOKEN ID\tROOT DIRECTORY ID\tREVOKED AT\tSTATE\n%s\t%s\t%d\t%s\n",
			typedValue.TokenID,
			typedValue.RootDirectoryID,
			typedValue.RevokedAt,
			typedValue.State,
		); err != nil {
			return fmt.Errorf("write VFS token-revocation table: %w", err)
		}
	default:
		return fmt.Errorf("%w for %T", errUnsupportedTable, value)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush VFS management table: %w", err)
	}

	return nil
}

func mustMarkRequired(command *cobra.Command, name string) {
	if err := command.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}

func defaultGetenv(name string) string {
	return os.Getenv(name)
}
