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

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type repairRunFlags struct {
	controlURL       string
	namespaceID      string
	manifestSHA256   string
	sourceDriverID   string
	sourceRoot       string
	targetDriverID   string
	targetRoot       string
	idempotencyKey   string
	stagingDirectory string
	maximumExtent    uint64
	leaseSeconds     uint64
	renewalInterval  time.Duration
	outputFormat     string
}

type repairRunResult struct {
	OperationID       string `json:"operation_id"       yaml:"operation_id"`
	ManifestSHA256    string `json:"manifest_sha256"    yaml:"manifest_sha256"`
	TargetDriverID    string `json:"target_driver_id"   yaml:"target_driver_id"`
	ObjectsRepaired   uint64 `json:"objects_repaired"   yaml:"objects_repaired"`
	LocationsRepaired uint64 `json:"locations_repaired" yaml:"locations_repaired"`
	CiphertextBytes   uint64 `json:"ciphertext_bytes"   yaml:"ciphertext_bytes"`
	RecoveryRevision  uint64 `json:"recovery_revision"  yaml:"recovery_revision"`
	State             string `json:"state"              yaml:"state"`
}

func newRepairCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags repairRunFlags

	command := &cobra.Command{Use: repairCommandName, Short: "Repair missing provider objects"}
	run := &cobra.Command{
		Use:   runCommandName,
		Short: "Run one fenced local filesystem repair",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeRepairRun(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeRepairTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	run.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	run.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	run.Flags().StringVar(&flags.manifestSHA256, manifestFlag, "", "published manifest SHA-256")
	run.Flags().StringVar(&flags.sourceDriverID, sourceLocalDriverIDFlag, "", "verified source local filesystem driver ID")
	run.Flags().StringVar(&flags.sourceRoot, sourceLocalRootFlag, "", "verified source local filesystem archive root")
	run.Flags().StringVar(&flags.targetDriverID, destinationLocalDriverIDFlag, "", "missing target local filesystem driver ID")
	run.Flags().StringVar(&flags.targetRoot, destinationLocalRootFlag, "", "missing target local filesystem archive root")
	run.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this repair attempt")
	run.Flags().StringVar(&flags.stagingDirectory, stagingDirectoryFlag, os.TempDir(), "bounded local repair staging directory")
	run.Flags().Uint64Var(&flags.maximumExtent, "maximum-extent-bytes", defaultMaximumExtent, "maximum ciphertext extent allocation")
	run.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "repair write lease duration")
	run.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, "repair lease renewal interval")
	run.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag, namespaceFlag, manifestFlag, sourceLocalDriverIDFlag,
		sourceLocalRootFlag, destinationLocalDriverIDFlag, destinationLocalRootFlag,
		idempotencyKeyFlag,
	} {
		if err := run.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	command.AddCommand(run)

	return command
}

func writeRepairTable(writer io.Writer, result repairRunResult) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tTARGET\tOBJECTS\tLOCATIONS\tBYTES\tRECOVERY REVISION\tSTATE\n%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
		result.OperationID,
		result.TargetDriverID,
		result.ObjectsRepaired,
		result.LocationsRepaired,
		result.CiphertextBytes,
		result.RecoveryRevision,
		result.State,
	); err != nil {
		return fmt.Errorf("write repair run table: %w", err)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush repair table: %w", err)
	}

	return nil
}

func executeRepairRun(
	ctx context.Context,
	flags repairRunFlags,
	getenv func(string) string,
) (repairRunResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return repairRunResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return repairRunResult{}, fmt.Errorf("construct control client: %w", err)
	}

	source, target, err := openLocalTransferProviders(
		ctx,
		flags.sourceDriverID,
		flags.sourceRoot,
		flags.targetDriverID,
		flags.targetRoot,
	)
	if err != nil {
		return repairRunResult{}, err
	}

	repairer, err := sdk.NewRepairer(
		map[string]provider.Reader{source.ID: source.Reader},
		map[string]provider.ReadWriter{target.ID: destinationReadWriter(target)},
		flags.maximumExtent,
		target.Capabilities.MaximumObjectBytes,
	)
	if err != nil {
		return repairRunResult{}, fmt.Errorf("construct repairer: %w", err)
	}

	coordinator, err := sdk.NewControlledRepairer(
		control,
		repairer,
		flags.leaseSeconds,
		flags.renewalInterval,
	)
	if err != nil {
		return repairRunResult{}, fmt.Errorf("construct controlled repairer: %w", err)
	}

	result, err := coordinator.Repair(ctx, sdk.ControlledRepairRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		TargetDriverID: flags.targetDriverID, IdempotencyKey: flags.idempotencyKey,
		StagingDirectory: flags.stagingDirectory,
	})
	if err != nil {
		return repairRunResult{}, fmt.Errorf("execute controlled repair: %w", err)
	}

	return repairRunResult{
		OperationID: result.Operation.ID, ManifestSHA256: result.Operation.ManifestSHA256,
		TargetDriverID:    result.Operation.TargetDriverID,
		ObjectsRepaired:   result.Completion.ObjectsRepaired,
		LocationsRepaired: result.Completion.LocationsRepaired,
		CiphertextBytes:   result.Completion.CiphertextBytes,
		RecoveryRevision:  result.Completion.RecoveryRevision,
		State:             result.Completion.State,
	}, nil
}
