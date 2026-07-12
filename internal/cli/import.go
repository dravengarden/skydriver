package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errImportCiphertextOverflow = errors.New("import ciphertext size overflow")

const (
	objectIDFlag               = "object-id"
	sourceKeyFlag              = "source-key"
	generationFlag             = "generation"
	expectedObjectRevisionFlag = "expected-object-revision"
	planFileFlag               = "plan-file"
)

type importRunFlags struct {
	controlURL             string
	namespaceID            string
	objectID               string
	generation             uint64
	sourceDriverID         string
	sourceRoot             string
	sourceKey              string
	destinationDriverID    string
	destinationRoot        string
	destinationPrefix      string
	expectedObjectRevision uint64
	stagingDirectory       string
	planFile               string
	leaseSeconds           uint64
	renewalInterval        time.Duration
	outputFormat           string
}

type importRunResult struct {
	OperationID         string `json:"operation_id"          yaml:"operation_id"`
	ObjectID            string `json:"object_id"             yaml:"object_id"`
	Generation          uint64 `json:"generation"            yaml:"generation"`
	ManifestSHA256      string `json:"manifest_sha256"       yaml:"manifest_sha256"`
	DestinationDriverID string `json:"destination_driver_id" yaml:"destination_driver_id"`
	ObjectsWritten      uint64 `json:"objects_written"       yaml:"objects_written"`
	LocationsWritten    uint64 `json:"locations_written"     yaml:"locations_written"`
	PlaintextBytes      uint64 `json:"plaintext_bytes"       yaml:"plaintext_bytes"`
	CiphertextBytes     uint64 `json:"ciphertext_bytes"      yaml:"ciphertext_bytes"`
	PlanFile            string `json:"plan_file"             yaml:"plan_file"`
	State               string `json:"state"                 yaml:"state"`
	TelemetryWarning    string `json:"telemetry_warning"     yaml:"telemetry_warning"`
	AlreadyPublished    bool   `json:"already_published"     yaml:"already_published"`
}

func newImportCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: importCommandName, Short: "Import plaintext into a durable archive"}
	command.AddCommand(newImportRunCommand(ctx, stdout))

	return command
}

func newImportRunCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags importRunFlags

	command := &cobra.Command{
		Use:   runCommandName,
		Short: "Encrypt, verify, and publish one local filesystem source",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeImportRun(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	configureImportRunFlags(command, &flags)

	return command
}

func configureImportRunFlags(command *cobra.Command, flags *importRunFlags) {
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	command.Flags().StringVar(&flags.objectID, objectIDFlag, "", "immutable logical object ID")
	command.Flags().Uint64Var(&flags.generation, generationFlag, 1, "immutable object generation")
	command.Flags().StringVar(&flags.sourceDriverID, sourceLocalDriverIDFlag, "", "source local filesystem driver ID")
	command.Flags().StringVar(&flags.sourceRoot, sourceLocalRootFlag, "", "source local filesystem root")
	command.Flags().StringVar(&flags.sourceKey, sourceKeyFlag, "", "canonical plaintext source key beneath the source root")
	command.Flags().StringVar(&flags.destinationDriverID, destinationLocalDriverIDFlag, "", "destination local filesystem driver ID")
	command.Flags().StringVar(&flags.destinationRoot, destinationLocalRootFlag, "", "destination local filesystem archive root")
	command.Flags().StringVar(&flags.destinationPrefix, destinationPrefixFlag, "", "destination-owned object prefix")
	command.Flags().Uint64Var(&flags.expectedObjectRevision, expectedObjectRevisionFlag, 1, "object revision required for publication CAS")
	command.Flags().StringVar(&flags.stagingDirectory, stagingDirectoryFlag, os.TempDir(), "bounded local encryption staging directory")
	command.Flags().StringVar(&flags.planFile, planFileFlag, "", "persisted non-secret import plan path")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "import write lease duration")
	command.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, "import lease renewal interval")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag, namespaceFlag, objectIDFlag, sourceLocalDriverIDFlag, sourceLocalRootFlag,
		sourceKeyFlag, destinationLocalDriverIDFlag, destinationLocalRootFlag,
		destinationPrefixFlag,
	} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}

func executeImportRun(
	ctx context.Context,
	flags importRunFlags,
	getenv func(string) string,
) (importRunResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return importRunResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return importRunResult{}, fmt.Errorf("construct control client: %w", err)
	}

	source, destination, err := openLocalTransferProviders(
		ctx,
		flags.sourceDriverID,
		flags.sourceRoot,
		flags.destinationDriverID,
		flags.destinationRoot,
	)
	if err != nil {
		return importRunResult{}, err
	}

	sourceObject, err := source.Reader.Stat(ctx, flags.sourceKey)
	if err != nil {
		return importRunResult{}, fmt.Errorf("inspect import source: %w", err)
	}

	importer, err := sdk.NewImporterWithOptions(
		source.Reader,
		destinationReadWriter(destination),
		archive.DefaultLayout(),
		sdk.ImporterOptionsFromCapabilities(destination.Capabilities),
	)
	if err != nil {
		return importRunResult{}, fmt.Errorf("construct importer: %w", err)
	}

	coordinator, err := sdk.NewControlledImporter(
		control,
		importer,
		flags.leaseSeconds,
		flags.renewalInterval,
	)
	if err != nil {
		return importRunResult{}, fmt.Errorf("construct controlled importer: %w", err)
	}

	idempotencyKey := importRunIdempotencyKey(flags, sourceObject)

	planFile, err := resolveImportPlanFile(flags.planFile, flags.stagingDirectory, idempotencyKey)
	if err != nil {
		return importRunResult{}, err
	}

	result, err := coordinator.Import(ctx, sdk.ControlledImportRequest{
		NamespaceID: flags.namespaceID, ObjectID: flags.objectID, Generation: flags.generation,
		SourceKey: flags.sourceKey, DestinationDriverID: destination.ID,
		DestinationPrefix: flags.destinationPrefix, IdempotencyKey: idempotencyKey,
		UsefulBytesTotal:       &sourceObject.SizeBytes,
		ExpectedObjectRevision: flags.expectedObjectRevision,
		StagingDirectory:       flags.stagingDirectory, PlanFile: planFile,
	})
	if err != nil {
		return importRunResult{}, fmt.Errorf("execute controlled import: %w", err)
	}

	var (
		objectsWritten   uint64
		locationsWritten uint64
		plaintextBytes   = result.Plan.Source.SizeBytes
		ciphertextBytes  uint64
	)

	if !result.AlreadyPublished {
		objectsWritten = distinctImportObjects(result.Import.Recovery.Locations)
		locationsWritten = uint64(len(result.Import.Recovery.Locations))

		ciphertextBytes, err = importCiphertextBytes(result.Import.Manifest)
		if err != nil {
			return importRunResult{}, err
		}
	}

	return importRunResult{
		OperationID: result.Operation.ID, ObjectID: result.Publication.ObjectID,
		Generation: result.Publication.Generation, ManifestSHA256: result.Publication.ManifestSHA256,
		DestinationDriverID: result.Plan.DestinationDriverID,
		ObjectsWritten:      objectsWritten, LocationsWritten: locationsWritten,
		PlaintextBytes: plaintextBytes, CiphertextBytes: ciphertextBytes,
		PlanFile: planFile, State: result.Publication.State,
		TelemetryWarning: result.TelemetryWarning,
		AlreadyPublished: result.AlreadyPublished,
	}, nil
}

func importRunIdempotencyKey(flags importRunFlags, source provider.Object) string {
	identity := strings.Join([]string{
		flags.namespaceID,
		flags.objectID,
		strconv.FormatUint(flags.generation, 10),
		flags.sourceDriverID,
		flags.sourceKey,
		strconv.FormatUint(source.SizeBytes, 10),
		source.ETag,
		source.Version,
		flags.destinationDriverID,
		flags.destinationPrefix,
		strconv.FormatUint(flags.expectedObjectRevision, 10),
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))

	return "import/" + hex.EncodeToString(digest[:])
}

func resolveImportPlanFile(configured, stagingDirectory, idempotencyKey string) (string, error) {
	planFile := configured
	if planFile == "" {
		planFile = filepath.Join(
			stagingDirectory,
			"carrack-import-"+strings.TrimPrefix(idempotencyKey, "import/")+".json",
		)
	}

	absolute, err := filepath.Abs(planFile)
	if err != nil {
		return "", fmt.Errorf("resolve import plan path: %w", err)
	}

	return absolute, nil
}

func distinctImportObjects(locations []manifest.Location) uint64 {
	objects := make(map[string]struct{}, len(locations))
	for _, location := range locations {
		objects[location.StorageKey] = struct{}{}
	}

	return uint64(len(objects))
}

func importCiphertextBytes(content manifest.Manifest) (uint64, error) {
	var total uint64

	for _, pack := range content.Packs {
		if pack.CiphertextSize > math.MaxUint64-total {
			return 0, errImportCiphertextOverflow
		}

		total += pack.CiphertextSize
	}

	return total, nil
}
