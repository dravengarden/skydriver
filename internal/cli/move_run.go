package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

var errMoveLocalConfiguration = errors.New("invalid local filesystem move configuration")

type moveRunFlags struct {
	controlURL          string
	namespaceID         string
	manifestSHA256      string
	sourceDriverID      string
	sourceRoot          string
	destinationDriverID string
	destinationRoot     string
	destinationPrefix   string
	stagingDirectory    string
	maximumExtent       uint64
	leaseSeconds        uint64
	renewalInterval     time.Duration
	outputFormat        string
}

type moveRunResult struct {
	OperationID         string `json:"operation_id"          yaml:"operation_id"`
	ManifestSHA256      string `json:"manifest_sha256"       yaml:"manifest_sha256"`
	SourceDriverID      string `json:"source_driver_id"      yaml:"source_driver_id"`
	DestinationDriverID string `json:"destination_driver_id" yaml:"destination_driver_id"`
	ObjectsWritten      uint64 `json:"objects_written"       yaml:"objects_written"`
	LocationsAdded      uint64 `json:"locations_added"       yaml:"locations_added"`
	CiphertextBytes     uint64 `json:"ciphertext_bytes"      yaml:"ciphertext_bytes"`
	RecoveryRevision    uint64 `json:"recovery_revision"     yaml:"recovery_revision"`
	GraceUntil          uint64 `json:"grace_until"           yaml:"grace_until"`
	State               string `json:"state"                 yaml:"state"`
}

func newMoveRunCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags moveRunFlags

	command := &cobra.Command{
		Use:   "run",
		Short: "Replicate, publish, and tombstone one local filesystem source",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeMoveRun(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	command.Flags().StringVar(&flags.manifestSHA256, manifestFlag, "", "published manifest SHA-256")
	command.Flags().StringVar(&flags.sourceDriverID, "source-local-driver-id", "", "source local filesystem driver ID")
	command.Flags().StringVar(&flags.sourceRoot, "source-local-root", "", "source local filesystem archive root")
	command.Flags().StringVar(&flags.destinationDriverID, "destination-local-driver-id", "", "destination local filesystem driver ID")
	command.Flags().StringVar(&flags.destinationRoot, "destination-local-root", "", "destination local filesystem archive root")
	command.Flags().StringVar(&flags.destinationPrefix, "destination-prefix", "", "destination-owned object prefix")
	command.Flags().StringVar(&flags.stagingDirectory, "staging-directory", os.TempDir(), "bounded local replication staging directory")
	command.Flags().Uint64Var(&flags.maximumExtent, "maximum-extent-bytes", defaultMaximumExtent, "maximum ciphertext extent allocation")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "move write lease duration")
	command.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, "move lease renewal interval")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag, namespaceFlag, manifestFlag, "source-local-driver-id", "source-local-root",
		"destination-local-driver-id", "destination-local-root", "destination-prefix",
	} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeMoveRun(
	ctx context.Context,
	flags moveRunFlags,
	getenv func(string) string,
) (moveRunResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return moveRunResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return moveRunResult{}, fmt.Errorf("construct control client: %w", err)
	}

	source, destination, err := openLocalMoveProviders(ctx, flags)
	if err != nil {
		return moveRunResult{}, err
	}

	replicator, err := sdk.NewReplicator(
		map[string]provider.Reader{source.ID: source.Reader},
		destinationReadWriter(destination),
		sdk.ReplicatorOptionsFromCapabilities(flags.maximumExtent, destination.Capabilities),
	)
	if err != nil {
		return moveRunResult{}, fmt.Errorf("construct move replicator: %w", err)
	}

	mover, err := sdk.NewControlledMover(control, replicator, flags.leaseSeconds, flags.renewalInterval)
	if err != nil {
		return moveRunResult{}, fmt.Errorf("construct controlled mover: %w", err)
	}

	result, err := mover.Move(ctx, sdk.ControlledMoveRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		SourceDriverID: source.ID, DestinationDriverID: destination.ID,
		DestinationPrefix: flags.destinationPrefix,
		IdempotencyKey: moveRunIdempotencyKey(
			flags.namespaceID,
			flags.manifestSHA256,
			source.ID,
			destination.ID,
			flags.destinationPrefix,
		),
		StagingDirectory: flags.stagingDirectory,
	})
	if err != nil {
		return moveRunResult{}, fmt.Errorf("execute controlled move: %w", err)
	}

	return moveRunResult{
		OperationID: result.Operation.ID, ManifestSHA256: result.Operation.ManifestSHA256,
		SourceDriverID:      result.Operation.SourceDriverID,
		DestinationDriverID: result.Operation.DestinationDriverID,
		ObjectsWritten:      uint64(len(result.Replication.ProviderObjects)),
		LocationsAdded:      result.DestinationPublication.LocationsAdded,
		CiphertextBytes:     result.Replication.CiphertextBytes,
		RecoveryRevision:    result.SourceTombstone.RecoveryRevision,
		GraceUntil:          result.SourceTombstone.GraceUntil,
		State:               result.SourceTombstone.State,
	}, nil
}

func openLocalMoveProviders(
	ctx context.Context,
	flags moveRunFlags,
) (source, destination provider.Handle, returnErr error) {
	if flags.sourceDriverID == flags.destinationDriverID {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("%w: driver IDs must differ", errMoveLocalConfiguration)
	}

	sourceRoot, err := filepath.Abs(flags.sourceRoot)
	if err != nil {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("resolve move source root: %w", err)
	}

	destinationRoot, err := filepath.Abs(flags.destinationRoot)
	if err != nil {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("resolve move destination root: %w", err)
	}

	if sourceRoot == destinationRoot {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("%w: source and destination roots must differ", errMoveLocalConfiguration)
	}

	registry, err := provider.NewRegistry(localfs.Factory{})
	if err != nil {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("construct move provider registry: %w", err)
	}

	source, err = openLocalMoveProvider(ctx, registry, flags.sourceDriverID, sourceRoot)
	if err != nil {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("open move source: %w", err)
	}

	destination, err = openLocalMoveProvider(
		ctx,
		registry,
		flags.destinationDriverID,
		destinationRoot,
	)
	if err != nil {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("open move destination: %w", err)
	}

	if source.Reader == nil || destination.Reader == nil || destination.Writer == nil {
		return provider.Handle{}, provider.Handle{}, fmt.Errorf("%w: provider capabilities are incomplete", errMoveLocalConfiguration)
	}

	return source, destination, nil
}

func openLocalMoveProvider(
	ctx context.Context,
	registry *provider.Registry,
	driverID,
	root string,
) (provider.Handle, error) {
	configuration, err := json.Marshal(localfs.DriverConfig{Root: root})
	if err != nil {
		return provider.Handle{}, fmt.Errorf("encode local move configuration: %w", err)
	}

	handle, err := registry.Open(ctx, provider.DriverSpec{
		ID: driverID, Kind: localfs.DriverKind, Config: configuration,
	}, provider.Dependencies{})
	if err != nil {
		return provider.Handle{}, fmt.Errorf("open local move provider: %w", err)
	}

	return handle, nil
}

func destinationReadWriter(handle provider.Handle) provider.ReadWriter {
	return struct {
		provider.Reader
		provider.Writer
	}{Reader: handle.Reader, Writer: handle.Writer}
}

func moveRunIdempotencyKey(namespaceID, manifestSHA256, sourceID, destinationID, prefix string) string {
	digest := sha256.Sum256([]byte(
		namespaceID + "\x00" + manifestSHA256 + "\x00" + sourceID + "\x00" + destinationID + "\x00" + prefix,
	))

	return "move/" + hex.EncodeToString(digest[:])
}
