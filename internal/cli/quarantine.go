package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/sdk"
)

type quarantineActionFlags struct {
	controlURL       string
	namespaceID      string
	driverID         string
	storageKey       string
	expectedRevision uint64
	reason           string
	idempotencyKey   string
	leaseSeconds     uint64
	outputFormat     string
}

func newQuarantineCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   quarantineCommandName,
		Short: "Review quarantined provider objects without deleting payload",
	}
	command.AddCommand(
		newQuarantineActionCommand(ctx, stdout, sdk.QuarantineActionAcknowledge),
		newQuarantineActionCommand(ctx, stdout, sdk.QuarantineActionTombstone),
	)

	return command
}

func newQuarantineActionCommand(
	ctx context.Context,
	stdout io.Writer,
	action sdk.QuarantineAction,
) *cobra.Command {
	var flags quarantineActionFlags

	short := "Acknowledge completed ownership review after quarantine"
	if action == sdk.QuarantineActionTombstone {
		short = "Tombstone an acknowledged object and begin deletion grace"
	}

	command := &cobra.Command{
		Use:   string(action),
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeQuarantineAction(ctx, flags, action, os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeQuarantineActionTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	command.Flags().StringVar(&flags.driverID, "driver-id", "", "quarantined provider driver ID")
	command.Flags().StringVar(&flags.storageKey, "storage-key", "", "exact quarantined provider storage key")
	command.Flags().Uint64Var(&flags.expectedRevision, "expected-revision", 0, "exact quarantine revision shown by the integrity console")
	command.Flags().StringVar(&flags.reason, "reason", "", "operator review or tombstone justification")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this review action")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "review operation lease duration")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag,
		namespaceFlag,
		"driver-id",
		"storage-key",
		"expected-revision",
		"reason",
		idempotencyKeyFlag,
	} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeQuarantineAction(
	ctx context.Context,
	flags quarantineActionFlags,
	action sdk.QuarantineAction,
	getenv func(string) string,
) (sdk.ControlledQuarantineResult, error) {
	control, clearToken, err := newGCControlClient(flags.controlURL, getenv)
	if err != nil {
		return sdk.ControlledQuarantineResult{}, err
	}
	defer clearToken()

	reviewer, err := sdk.NewControlledQuarantineReviewer(control, flags.leaseSeconds)
	if err != nil {
		return sdk.ControlledQuarantineResult{}, fmt.Errorf("construct quarantine reviewer: %w", err)
	}

	result, err := reviewer.Act(ctx, sdk.ControlledQuarantineRequest{
		NamespaceID: flags.namespaceID, Action: action, DriverID: flags.driverID,
		StorageKey: flags.storageKey, ExpectedRevision: flags.expectedRevision,
		Reason: flags.reason, IdempotencyKey: flags.idempotencyKey,
	})
	if err != nil {
		return sdk.ControlledQuarantineResult{}, fmt.Errorf("execute quarantine %s: %w", action, err)
	}

	return result, nil
}

func writeQuarantineActionTable(
	writer io.Writer,
	result sdk.ControlledQuarantineResult,
) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)

	deleteAfter := uint64(0)
	if result.Completion.DeleteAfter != nil {
		deleteAfter = *result.Completion.DeleteAfter
	}

	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tACTION\tQUARANTINE STATE\tREVISION\tDELETE AFTER\n%s\t%s\t%s\t%d\t%d\n",
		result.Operation.ID,
		result.Completion.Action,
		result.Completion.QuarantineState,
		result.Completion.QuarantineRevision,
		deleteAfter,
	); err != nil {
		return fmt.Errorf("write quarantine action table: %w", err)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush quarantine action table: %w", err)
	}

	return nil
}
