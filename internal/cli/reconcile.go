package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/sdk"
)

type reconcileFlags struct {
	controlURL      string
	namespaceID     string
	manifestSHA256  string
	idempotencyKey  string
	leaseSeconds    uint64
	renewalInterval time.Duration
	outputFormat    string
}

func newReconcileCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags reconcileFlags

	command := &cobra.Command{Use: reconcileCommandName, Short: "Reconcile recovery and indexed metadata"}
	run := &cobra.Command{
		Use:   runCommandName,
		Short: "Run one fenced metadata reconciliation",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeReconcile(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeReconcileTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	run.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	run.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	run.Flags().StringVar(&flags.manifestSHA256, manifestFlag, "", "published manifest SHA-256")
	run.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this reconciliation")
	run.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "reconciliation lease duration")
	run.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, "lease renewal interval")
	run.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, namespaceFlag, manifestFlag, idempotencyKeyFlag} {
		if err := run.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	command.AddCommand(run)

	return command
}

func executeReconcile(
	ctx context.Context,
	flags reconcileFlags,
	getenv func(string) string,
) (sdk.ControlledReconcileResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return sdk.ControlledReconcileResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return sdk.ControlledReconcileResult{}, fmt.Errorf("construct control client: %w", err)
	}

	coordinator, err := sdk.NewControlledReconciler(
		control,
		flags.leaseSeconds,
		flags.renewalInterval,
	)
	if err != nil {
		return sdk.ControlledReconcileResult{}, fmt.Errorf("construct controlled reconciler: %w", err)
	}

	result, err := coordinator.Reconcile(ctx, sdk.ControlledReconcileRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		IdempotencyKey: flags.idempotencyKey,
	})
	if err != nil {
		return sdk.ControlledReconcileResult{}, fmt.Errorf("execute controlled reconcile: %w", err)
	}

	return result, nil
}

func writeReconcileTable(writer io.Writer, result sdk.ControlledReconcileResult) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tSTATE\tUNINDEXED\tORPHAN\tDEGRADED\n%s\t%s\t%d\t%d\t%d\n",
		result.Operation.ID,
		result.Completion.State,
		result.Completion.Unindexed,
		result.Completion.Orphan,
		result.Completion.Degraded,
	); err != nil {
		return fmt.Errorf("write reconciliation table: %w", err)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush reconciliation table: %w", err)
	}

	return nil
}
