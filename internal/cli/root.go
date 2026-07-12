// Package cli implements the Carrack command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/sdk"
)

const (
	developmentVersion           = "0.1.0-dev"
	versionCommandName           = "version"
	outputFormatJSON             = "json"
	outputFormatTable            = "table"
	controlURLFlag               = "control-url"
	namespaceFlag                = "namespace"
	manifestFlag                 = "manifest"
	importCommandName            = "import"
	moveCommandName              = "move"
	copyCommandName              = "copy"
	sourceLocalDriverIDFlag      = "source-local-driver-id"
	sourceLocalRootFlag          = "source-local-root"
	destinationLocalDriverIDFlag = "destination-local-driver-id"
	destinationLocalRootFlag     = "destination-local-root"
	destinationPrefixFlag        = "destination-prefix"
	stagingDirectoryFlag         = "staging-directory"
	runCommandName               = "run"
	reconcileCommandName         = "reconcile"
	repairCommandName            = "repair"
	compactCommandName           = "compact"
	idempotencyKeyFlag           = "idempotency-key"
	localDriverIDFlag            = "local-driver-id"
	localRootFlag                = "local-root"
)

var (
	errUnsupportedFormat = errors.New("unsupported output format")
	errUnsupportedTable  = errors.New("table output is not supported")
)

// Run executes Carrack with explicit process dependencies.
func Run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	command := newRootCommand(ctx, stdout, stderr)
	command.SetArgs(arguments)

	if err := command.ExecuteContext(ctx); err != nil {
		return fmt.Errorf("execute carrack: %w", err)
	}

	return nil
}

func newRootCommand(ctx context.Context, stdout, stderr io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:           "carrack",
		Short:         "Move and archive datasets across storage providers",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	command.SetOut(stdout)
	command.SetErr(stderr)
	command.AddCommand(
		newVersionCommand(stdout),
		newLayoutCommand(stdout),
		newImportCommand(ctx, stdout),
		newRestoreCommand(ctx, stdout),
		newCopyCommand(ctx, stdout),
		newMoveCommand(ctx, stdout),
		newVerifyCommand(ctx, stdout),
		newReconcileCommand(ctx, stdout),
		newRepairCommand(ctx, stdout),
		newCompactCommand(ctx, stdout),
	)

	return command
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	var outputFormat string

	command := &cobra.Command{
		Use:   versionCommandName,
		Short: "Show the Carrack version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return writeValue(stdout, outputFormat, map[string]string{versionCommandName: developmentVersion})
		},
	}
	command.Flags().StringVar(&outputFormat, "format", "table", "output format: table, json, or yaml")

	return command
}

func newLayoutCommand(stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: "layout", Short: "Inspect archive layout profiles"}
	command.AddCommand(newLayoutShowCommand(stdout))

	return command
}

func newLayoutShowCommand(stdout io.Writer) *cobra.Command {
	var outputFormat string

	command := &cobra.Command{
		Use:   "show",
		Short: "Show the default archive layout",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return writeValue(stdout, outputFormat, archive.DefaultLayout())
		},
	}
	command.Flags().StringVar(&outputFormat, "format", "table", "output format: table, json, or yaml")

	return command
}

func writeValue(writer io.Writer, outputFormat string, value any) error {
	switch outputFormat {
	case outputFormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")

		if err := encoder.Encode(value); err != nil {
			return fmt.Errorf("encode JSON output: %w", err)
		}
	case "yaml":
		encoder := yaml.NewEncoder(writer)

		if err := encoder.Encode(value); err != nil {
			return fmt.Errorf("encode YAML output: %w", err)
		}

		if err := encoder.Close(); err != nil {
			return fmt.Errorf("close YAML encoder: %w", err)
		}
	case outputFormatTable:
		if err := writeTable(writer, value); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w %q", errUnsupportedFormat, outputFormat)
	}

	return nil
}

func writeTable(writer io.Writer, value any) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)

	switch typedValue := value.(type) {
	case sdk.VerificationResult:
		if _, err := fmt.Fprintf(table, "STATE\tVERIFIED\tMISSING\tCORRUPT\tUNAVAILABLE\n%s\t%d\t%d\t%d\t%d\n", typedValue.State, typedValue.Verified, typedValue.Missing, typedValue.Corrupt, typedValue.Unavailable); err != nil {
			return fmt.Errorf("write verification table: %w", err)
		}
	case archive.Layout:
		if _, err := fmt.Fprintf(table, "PHYSICAL BLOCK BYTES\tCRYPTO FRAME BYTES\tLOGICAL PACK BYTES\n%d\t%d\t%d\n", typedValue.PhysicalBlockBytes, typedValue.CryptoFrameBytes, typedValue.LogicalPackBytes); err != nil {
			return fmt.Errorf("write layout table: %w", err)
		}
	case map[string]string:
		if _, err := fmt.Fprintf(table, "VERSION\n%s\n", typedValue[versionCommandName]); err != nil {
			return fmt.Errorf("write version table: %w", err)
		}
	case sdk.MoveSweepResult:
		if _, err := fmt.Fprintf(
			table,
			"OPERATION ID\tOBJECTS DELETED\tLOCATIONS DELETED\tSTATE\n%s\t%d\t%d\t%s\n",
			typedValue.OperationID,
			typedValue.ObjectsDeleted,
			typedValue.LocationsDeleted,
			typedValue.State,
		); err != nil {
			return fmt.Errorf("write move sweep table: %w", err)
		}
	case moveRunResult:
		if _, err := fmt.Fprintf(
			table,
			"OPERATION ID\tSOURCE\tDESTINATION\tOBJECTS\tLOCATIONS\tBYTES\tRECOVERY REVISION\tGRACE UNTIL\tSTATE\n%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
			typedValue.OperationID,
			typedValue.SourceDriverID,
			typedValue.DestinationDriverID,
			typedValue.ObjectsWritten,
			typedValue.LocationsAdded,
			typedValue.CiphertextBytes,
			typedValue.RecoveryRevision,
			typedValue.GraceUntil,
			typedValue.State,
		); err != nil {
			return fmt.Errorf("write move run table: %w", err)
		}
	case copyRunResult:
		if _, err := fmt.Fprintf(
			table,
			"OPERATION ID\tSOURCE\tDESTINATION\tOBJECTS\tLOCATIONS\tBYTES\tRECOVERY REVISION\tSTATE\n%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
			typedValue.OperationID,
			typedValue.SourceDriverID,
			typedValue.DestinationDriverID,
			typedValue.ObjectsWritten,
			typedValue.LocationsAdded,
			typedValue.CiphertextBytes,
			typedValue.RecoveryRevision,
			typedValue.State,
		); err != nil {
			return fmt.Errorf("write copy run table: %w", err)
		}
	case importRunResult:
		if _, err := fmt.Fprintf(
			table,
			"OPERATION ID\tOBJECT ID\tGENERATION\tMANIFEST SHA-256\tDESTINATION\tOBJECTS\tLOCATIONS\tPLAINTEXT BYTES\tCIPHERTEXT BYTES\tPLAN FILE\tALREADY PUBLISHED\tSTATE\tTELEMETRY WARNING\n%s\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%s\t%t\t%s\t%s\n",
			typedValue.OperationID,
			typedValue.ObjectID,
			typedValue.Generation,
			typedValue.ManifestSHA256,
			typedValue.DestinationDriverID,
			typedValue.ObjectsWritten,
			typedValue.LocationsWritten,
			typedValue.PlaintextBytes,
			typedValue.CiphertextBytes,
			typedValue.PlanFile,
			typedValue.AlreadyPublished,
			typedValue.State,
			typedValue.TelemetryWarning,
		); err != nil {
			return fmt.Errorf("write import run table: %w", err)
		}
	case sdk.ControlledRestoreResult:
		if _, err := fmt.Fprintf(
			table,
			"OPERATION\tMANIFEST SHA-256\tDESTINATION\tPLAINTEXT BYTES\tSTATE\tTELEMETRY WARNING\n%s\t%s\t%s\t%d\t%s\t%s\n",
			typedValue.Operation.ID,
			typedValue.Restore.ManifestSHA256,
			typedValue.Restore.Destination,
			typedValue.Restore.PlaintextBytes,
			typedValue.Completion.State,
			typedValue.TelemetryWarning,
		); err != nil {
			return fmt.Errorf("write restore table: %w", err)
		}
	default:
		return fmt.Errorf("%w for %T", errUnsupportedTable, value)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush table output: %w", err)
	}

	return nil
}
