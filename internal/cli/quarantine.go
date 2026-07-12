package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errQuarantineDeleteCapability = errors.New("local filesystem driver lacks quarantine Stat or delete capability")

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

type quarantineSweepFlags = localJanitorFlags

func newQuarantineCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   quarantineCommandName,
		Short: "Review and explicitly clean quarantined provider objects",
	}
	command.AddCommand(
		newQuarantineActionCommand(ctx, stdout, sdk.QuarantineActionAcknowledge),
		newQuarantineActionCommand(ctx, stdout, sdk.QuarantineActionTombstone),
		newQuarantineSweepCommand(ctx, stdout),
	)

	return command
}

func newQuarantineSweepCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags quarantineSweepFlags

	command := &cobra.Command{
		Use:   "sweep TOMBSTONE_OPERATION_ID",
		Short: "Stat and delete one object after its quarantine grace expires",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeQuarantineSweep(ctx, flags, arguments[0], os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeQuarantineSweepTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	configureLocalJanitorFlags(command, &flags, "quarantine")

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

func executeQuarantineSweep(
	ctx context.Context,
	flags quarantineSweepFlags,
	operationID string,
	getenv func(string) string,
) (sdk.QuarantineSweepResult, error) {
	control, clearToken, err := newGCControlClient(flags.controlURL, getenv)
	if err != nil {
		return sdk.QuarantineSweepResult{}, err
	}
	defer clearToken()

	handle, err := openLocalJanitorProvider(
		ctx,
		flags.localDriverID,
		flags.localRoot,
		"quarantine",
	)
	if err != nil {
		return sdk.QuarantineSweepResult{}, err
	}

	if handle.Reader == nil || handle.Deleter == nil || !handle.Capabilities.RangeRead ||
		!handle.Capabilities.Delete {
		return sdk.QuarantineSweepResult{}, errQuarantineDeleteCapability
	}

	target := struct {
		provider.Reader
		provider.Deleter
	}{Reader: handle.Reader, Deleter: handle.Deleter}

	janitor, err := sdk.NewQuarantineJanitor(
		control,
		map[string]sdk.QuarantineDeleteProvider{handle.ID: target},
		flags.leaseSeconds,
	)
	if err != nil {
		return sdk.QuarantineSweepResult{}, fmt.Errorf("construct quarantine janitor: %w", err)
	}

	result, err := janitor.Sweep(ctx, operationID)
	if err != nil {
		return sdk.QuarantineSweepResult{}, fmt.Errorf("sweep quarantine deletion: %w", err)
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

func writeQuarantineSweepTable(writer io.Writer, result sdk.QuarantineSweepResult) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tOBJECTS DELETED\tALREADY ABSENT\tSTATE\n%s\t%d\t%d\t%s\n",
		result.OperationID,
		result.ObjectsDeleted,
		result.AlreadyAbsent,
		result.State,
	); err != nil {
		return fmt.Errorf("write quarantine sweep table: %w", err)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush quarantine sweep table: %w", err)
	}

	return nil
}
