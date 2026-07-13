package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/sdk"
)

const (
	vfsACLCommandName                = "acl"
	vfsPlacementCommandName          = "placement"
	vfsPolicyShowCommandName         = "show"
	vfsPolicyReplaceCommandName      = "replace"
	vfsExpectedACLRevisionFlag       = "expected-acl-revision"
	vfsExpectedPlacementRevisionFlag = "expected-placement-revision"
	vfsPlacementFlag                 = "placement"
)

var (
	errVFSACLSelection = errors.New("select exactly one ACL replacement mode: --role, --action, or --clear")
	errVFSPlacement    = errors.New("placement must use DRIVER_ID=WRITE_PRIORITY")
)

type vfsACLShowFlags struct {
	controlURL   string
	outputFormat string
}

type vfsACLReplaceFlags struct {
	controlURL       string
	actions          []string
	role             string
	clear            bool
	expectedRevision uint64
	idempotencyKey   string
	outputFormat     string
}

type vfsPlacementListFlags struct {
	controlURL   string
	outputFormat string
}

type vfsPlacementReplaceFlags struct {
	controlURL       string
	placements       []string
	expectedRevision uint64
	idempotencyKey   string
	outputFormat     string
}

func newVFSACLCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   vfsACLCommandName,
		Short: "Inspect and replace direct VFS directory grants",
	}
	command.AddCommand(
		newVFSACLShowCommand(ctx, stdout),
		newVFSACLReplaceCommand(ctx, stdout),
	)

	return command
}

func newVFSACLShowCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsACLShowFlags

	command := &cobra.Command{
		Use:   vfsPolicyShowCommandName + " DIRECTORY_ID",
		Short: "Show direct grants and the current ACL revision",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSACLShow(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")
	mustMarkRequired(command, controlURLFlag)

	return command
}

func newVFSACLReplaceCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsACLReplaceFlags

	command := &cobra.Command{
		Use:   vfsPolicyReplaceCommandName + " DIRECTORY_ID PRINCIPAL_ID",
		Short: "Replace one principal's direct grants with optimistic concurrency",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSACLReplace(ctx, flags, arguments[0], arguments[1], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringArrayVar(&flags.actions, "action", nil, "exact direct VFS action; repeat to grant several actions")
	command.Flags().StringVar(&flags.role, "role", "", "fixed role preset expanded into direct actions when committed")
	command.Flags().BoolVar(&flags.clear, "clear", false, "remove every direct grant for this principal")
	command.Flags().Uint64Var(
		&flags.expectedRevision,
		vfsExpectedACLRevisionFlag,
		0,
		"ACL revision returned by vfs acl show",
	)
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact ACL replacement")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, vfsExpectedACLRevisionFlag, idempotencyKeyFlag} {
		mustMarkRequired(command, name)
	}

	return command
}

func newVFSPlacementCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   vfsPlacementCommandName,
		Short: "Inspect and replace VFS directory storage placements",
	}
	command.AddCommand(
		newVFSPlacementListCommand(ctx, stdout),
		newVFSPlacementReplaceCommand(ctx, stdout),
	)

	return command
}

func newVFSPlacementListCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsPlacementListFlags

	command := &cobra.Command{
		Use:   vfsListCommandName + " DIRECTORY_ID",
		Short: "List the complete placement set and its current revision",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSPlacementList(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")
	mustMarkRequired(command, controlURLFlag)

	return command
}

func newVFSPlacementReplaceCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsPlacementReplaceFlags

	command := &cobra.Command{
		Use:   vfsPolicyReplaceCommandName + " DIRECTORY_ID",
		Short: "Replace the complete placement set with optimistic concurrency",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSPlacementReplace(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringArrayVar(
		&flags.placements,
		vfsPlacementFlag,
		nil,
		"complete placement as DRIVER_ID=WRITE_PRIORITY; repeat for every driver",
	)
	command.Flags().Uint64Var(
		&flags.expectedRevision,
		vfsExpectedPlacementRevisionFlag,
		0,
		"placement revision returned by vfs placement list",
	)
	command.Flags().StringVar(
		&flags.idempotencyKey,
		idempotencyKeyFlag,
		"",
		"stable identity for this exact placement replacement",
	)
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag,
		vfsPlacementFlag,
		vfsExpectedPlacementRevisionFlag,
		idempotencyKeyFlag,
	} {
		mustMarkRequired(command, name)
	}

	return command
}

func executeVFSACLShow(
	ctx context.Context,
	flags vfsACLShowFlags,
	directoryID string,
	getenv func(string) string,
) (sdk.VFSACL, error) {
	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSACL{}, err
	}
	defer control.Clear()

	acl, err := control.ACL(ctx, directoryID)
	if err != nil {
		return sdk.VFSACL{}, fmt.Errorf("read VFS ACL: %w", err)
	}

	return acl, nil
}

func executeVFSACLReplace(
	ctx context.Context,
	flags vfsACLReplaceFlags,
	directoryID,
	principalID string,
	getenv func(string) string,
) (sdk.VFSPolicyMutation, error) {
	request, err := vfsACLReplacement(flags, principalID)
	if err != nil {
		return sdk.VFSPolicyMutation{}, err
	}

	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSPolicyMutation{}, err
	}
	defer control.Clear()

	receipt, err := control.ReplaceACL(ctx, directoryID, request)
	if err != nil {
		return sdk.VFSPolicyMutation{}, fmt.Errorf("replace VFS ACL: %w", err)
	}

	return receipt, nil
}

func executeVFSPlacementList(
	ctx context.Context,
	flags vfsPlacementListFlags,
	directoryID string,
	getenv func(string) string,
) (sdk.VFSPlacements, error) {
	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSPlacements{}, err
	}
	defer control.Clear()

	placements, err := control.Placements(ctx, directoryID)
	if err != nil {
		return sdk.VFSPlacements{}, fmt.Errorf("read VFS placements: %w", err)
	}

	return placements, nil
}

func executeVFSPlacementReplace(
	ctx context.Context,
	flags vfsPlacementReplaceFlags,
	directoryID string,
	getenv func(string) string,
) (sdk.VFSPolicyMutation, error) {
	placements, err := parseVFSPlacements(flags.placements)
	if err != nil {
		return sdk.VFSPolicyMutation{}, err
	}

	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSPolicyMutation{}, err
	}
	defer control.Clear()

	receipt, err := control.ReplacePlacements(ctx, directoryID, sdk.VFSReplacePlacementsRequest{
		Placements:                placements,
		ExpectedPlacementRevision: flags.expectedRevision,
		IdempotencyKey:            flags.idempotencyKey,
	})
	if err != nil {
		return sdk.VFSPolicyMutation{}, fmt.Errorf("replace VFS placements: %w", err)
	}

	return receipt, nil
}

func vfsACLReplacement(flags vfsACLReplaceFlags, principalID string) (sdk.VFSReplaceACLRequest, error) {
	modeCount := 0
	if len(flags.actions) > 0 {
		modeCount++
	}

	if flags.role != "" {
		modeCount++
	}

	if flags.clear {
		modeCount++
	}

	if modeCount != 1 {
		return sdk.VFSReplaceACLRequest{}, errVFSACLSelection
	}

	request := sdk.VFSReplaceACLRequest{
		PrincipalID:         principalID,
		ExpectedACLRevision: flags.expectedRevision,
		IdempotencyKey:      flags.idempotencyKey,
	}

	if flags.role != "" {
		request.Role = sdk.VFSRole(flags.role)

		return request, nil
	}

	request.Actions = make([]sdk.VFSAction, len(flags.actions))
	for index, action := range flags.actions {
		request.Actions[index] = sdk.VFSAction(action)
	}

	return request, nil
}

func parseVFSPlacements(values []string) ([]sdk.VFSPlacement, error) {
	placements := make([]sdk.VFSPlacement, 0, len(values))

	for _, value := range values {
		separator := strings.LastIndexByte(value, '=')
		if separator <= 0 || separator == len(value)-1 {
			return nil, fmt.Errorf("%w: %q", errVFSPlacement, value)
		}

		priority, err := strconv.ParseUint(value[separator+1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %w", errVFSPlacement, value, err)
		}

		placements = append(placements, sdk.VFSPlacement{
			DriverID:      value[:separator],
			WritePriority: priority,
		})
	}

	return placements, nil
}

func writeVFSACLTable(table *tabwriter.Writer, acl sdk.VFSACL) error {
	if _, err := fmt.Fprintf(
		table,
		"DIRECTORY ID\tACL REVISION\tINHERITS\n%s\t%d\t%t\n",
		acl.DirectoryID,
		acl.ACLRevision,
		acl.ACLInherits,
	); err != nil {
		return fmt.Errorf("write VFS ACL identity table: %w", err)
	}

	if _, err := fmt.Fprintln(table, "GRANT ID\tSUBJECT TYPE\tSUBJECT ID\tACTION\tSOURCE ROLE"); err != nil {
		return fmt.Errorf("write VFS ACL grant header: %w", err)
	}

	for _, grant := range acl.Grants {
		subjectType, subjectID := vfsACLSubject(grant)
		if _, err := fmt.Fprintf(
			table,
			"%s\t%s\t%s\t%s\t%s\n",
			grant.ID,
			subjectType,
			subjectID,
			grant.Action,
			vfsACLSourceRole(grant.SourceRole),
		); err != nil {
			return fmt.Errorf("write VFS ACL grant: %w", err)
		}
	}

	return nil
}

func writeVFSPlacementsTable(table *tabwriter.Writer, placements sdk.VFSPlacements) error {
	if _, err := fmt.Fprintf(
		table,
		"DIRECTORY ID\tPLACEMENT REVISION\n%s\t%d\n",
		placements.DirectoryID,
		placements.PlacementRevision,
	); err != nil {
		return fmt.Errorf("write VFS placement identity table: %w", err)
	}

	if _, err := fmt.Fprintln(table, "DRIVER ID\tKIND\tDRIVER REVISION\tWRITE PRIORITY\tSTATE"); err != nil {
		return fmt.Errorf("write VFS placement header: %w", err)
	}

	for _, placement := range placements.Placements {
		if _, err := fmt.Fprintf(
			table,
			"%s\t%s\t%d\t%d\t%s\n",
			placement.DriverID,
			placement.DriverKind,
			placement.DriverRevision,
			placement.WritePriority,
			placement.State,
		); err != nil {
			return fmt.Errorf("write VFS placement: %w", err)
		}
	}

	return nil
}

func writeVFSPolicyMutationTable(table *tabwriter.Writer, mutation sdk.VFSPolicyMutation) error {
	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tKIND\tDIRECTORY ID\tFINAL REVISION\tCOMMITTED AT\tSTATE\n%s\t%s\t%s\t%d\t%d\t%s\n",
		mutation.OperationID,
		mutation.Kind,
		mutation.DirectoryID,
		mutation.FinalRevision,
		mutation.CommittedAt,
		mutation.State,
	); err != nil {
		return fmt.Errorf("write VFS policy-mutation table: %w", err)
	}

	return nil
}

func vfsACLSubject(grant sdk.VFSACLGrant) (subjectType, subjectID string) {
	if grant.PrincipalID != nil {
		return "principal", *grant.PrincipalID
	}

	if grant.GroupID != nil {
		return "group", *grant.GroupID
	}

	return "invalid", ""
}

func vfsACLSourceRole(role *sdk.VFSRole) string {
	if role == nil {
		return ""
	}

	return string(*role)
}
