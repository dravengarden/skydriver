package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type compactRunFlags struct {
	localTransferRunFlags

	idempotencyKey string
}

var errCompactStagingNotDirectory = errors.New("compact staging path is not a directory")

type compactRunResult struct {
	OperationID         string `json:"operation_id"          yaml:"operation_id"`
	ObjectID            string `json:"object_id"             yaml:"object_id"`
	SourceManifest      string `json:"source_manifest"       yaml:"source_manifest"`
	TargetManifest      string `json:"target_manifest"       yaml:"target_manifest"`
	SourceGeneration    uint64 `json:"source_generation"     yaml:"source_generation"`
	TargetGeneration    uint64 `json:"target_generation"     yaml:"target_generation"`
	SourceDriverID      string `json:"source_driver_id"      yaml:"source_driver_id"`
	DestinationDriverID string `json:"destination_driver_id" yaml:"destination_driver_id"`
	PacksBefore         uint64 `json:"packs_before"          yaml:"packs_before"`
	PacksAfter          uint64 `json:"packs_after"           yaml:"packs_after"`
	ObjectsWritten      uint64 `json:"objects_written"       yaml:"objects_written"`
	LocationsWritten    uint64 `json:"locations_written"     yaml:"locations_written"`
	PlaintextBytes      uint64 `json:"plaintext_bytes"       yaml:"plaintext_bytes"`
	CiphertextBytes     uint64 `json:"ciphertext_bytes"      yaml:"ciphertext_bytes"`
	PlanFile            string `json:"plan_file"             yaml:"plan_file"`
	State               string `json:"state"                 yaml:"state"`
	TelemetryWarning    string `json:"telemetry_warning"     yaml:"telemetry_warning"`
	CleanupWarning      string `json:"cleanup_warning"       yaml:"cleanup_warning"`
	AlreadyPublished    bool   `json:"already_published"     yaml:"already_published"`
}

func newCompactCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: compactCommandName, Short: "Repack immutable archive generations"}
	command.AddCommand(newCompactRunCommand(ctx, stdout))

	return command
}

func newCompactRunCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags compactRunFlags

	command := &cobra.Command{
		Use:   runCommandName,
		Short: "Decrypt, repack, verify, and conditionally publish one local archive generation",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeCompactRun(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeCompactTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	configureLocalTransferRunFlags(command, &flags.localTransferRunFlags, compactCommandName)
	command.Flags().StringVar(
		&flags.idempotencyKey,
		idempotencyKeyFlag,
		"",
		"stable identity for this immutable repack",
	)

	if err := command.MarkFlagRequired(idempotencyKeyFlag); err != nil {
		panic(err)
	}

	return command
}

func executeCompactRun(
	ctx context.Context,
	flags compactRunFlags,
	getenv func(string) string,
) (compactRunResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return compactRunResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return compactRunResult{}, fmt.Errorf("construct control client: %w", err)
	}

	source, destination, err := openLocalTransferProviders(
		ctx,
		flags.sourceDriverID,
		flags.sourceRoot,
		flags.destinationDriverID,
		flags.destinationRoot,
	)
	if err != nil {
		return compactRunResult{}, err
	}

	restorer, err := sdk.NewRestorer(
		map[string]provider.Reader{source.ID: source.Reader},
		flags.maximumExtent,
	)
	if err != nil {
		return compactRunResult{}, fmt.Errorf("construct compact restorer: %w", err)
	}

	compactor, err := sdk.NewCompactor(
		restorer,
		destinationReadWriter(destination),
		archive.DefaultLayout(),
		sdk.ImporterOptionsFromCapabilities(destination.Capabilities),
	)
	if err != nil {
		return compactRunResult{}, fmt.Errorf("construct compactor: %w", err)
	}

	coordinator, err := sdk.NewControlledCompactor(
		control,
		compactor,
		flags.leaseSeconds,
		flags.renewalInterval,
	)
	if err != nil {
		return compactRunResult{}, fmt.Errorf("construct controlled compactor: %w", err)
	}

	workspace, err := compactWorkspace(
		flags.stagingDirectory,
		flags.idempotencyKey,
	)
	if err != nil {
		return compactRunResult{}, err
	}

	result, err := coordinator.Compact(ctx, sdk.ControlledCompactRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		DestinationDriverID: destination.ID, DestinationPrefix: flags.destinationPrefix,
		IdempotencyKey: flags.idempotencyKey, StagingDirectory: workspace.directory,
		PlaintextPath: workspace.plaintext, PlanFile: workspace.plan,
	})
	if err != nil {
		return compactRunResult{}, fmt.Errorf("execute controlled compact: %w", err)
	}

	output := compactRunResult{
		OperationID: result.Operation.ID, ObjectID: result.Operation.ObjectID,
		SourceManifest:   result.Operation.SourceManifestSHA256,
		TargetManifest:   result.Publication.ManifestSHA256,
		SourceGeneration: result.Operation.SourceGeneration,
		TargetGeneration: result.Operation.TargetGeneration,
		SourceDriverID:   source.ID, DestinationDriverID: destination.ID,
		PacksBefore:    result.Operation.SourcePackCount,
		PlaintextBytes: result.Operation.UsefulBytesTotal, PlanFile: workspace.plan,
		State: result.Publication.State, TelemetryWarning: result.TelemetryWarning,
		CleanupWarning: result.CleanupWarning, AlreadyPublished: result.AlreadyPublished,
	}
	if !result.AlreadyPublished {
		output.PacksAfter = uint64(len(result.Execution.Import.Manifest.Packs))
		output.ObjectsWritten = distinctImportObjects(result.Execution.Import.Recovery.Locations)
		output.LocationsWritten = uint64(len(result.Execution.Import.Recovery.Locations))

		output.CiphertextBytes, err = importCiphertextBytes(result.Execution.Import.Manifest)
		if err != nil {
			return compactRunResult{}, err
		}
	}

	return output, nil
}

type compactWorkspacePaths struct {
	directory string
	plaintext string
	plan      string
}

func compactWorkspace(stagingDirectory, idempotencyKey string) (compactWorkspacePaths, error) {
	absolute, err := filepath.Abs(stagingDirectory)
	if err != nil {
		return compactWorkspacePaths{}, fmt.Errorf("resolve compact staging directory: %w", err)
	}

	information, err := os.Stat(absolute)
	if err != nil {
		return compactWorkspacePaths{}, fmt.Errorf("inspect compact staging directory: %w", err)
	}

	if !information.IsDir() {
		return compactWorkspacePaths{}, errCompactStagingNotDirectory
	}

	digest := sha256.Sum256([]byte(idempotencyKey))
	identity := hex.EncodeToString(digest[:])

	return compactWorkspacePaths{
		directory: absolute,
		plaintext: filepath.Join(absolute, "carrack-compact-"+identity+".plaintext"),
		plan:      filepath.Join(absolute, "carrack-compact-"+identity+".json"),
	}, nil
}

func writeCompactTable(writer io.Writer, result compactRunResult) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tOBJECT\tSOURCE GENERATION\tTARGET GENERATION\tPACKS BEFORE\tPACKS AFTER\tTARGET MANIFEST\tSTATE\tALREADY PUBLISHED\tTELEMETRY WARNING\tCLEANUP WARNING\n%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\t%t\t%s\t%s\n",
		result.OperationID,
		result.ObjectID,
		result.SourceGeneration,
		result.TargetGeneration,
		result.PacksBefore,
		result.PacksAfter,
		result.TargetManifest,
		result.State,
		result.AlreadyPublished,
		result.TelemetryWarning,
		result.CleanupWarning,
	); err != nil {
		return fmt.Errorf("write compact table: %w", err)
	}

	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush compact table: %w", err)
	}

	return nil
}
