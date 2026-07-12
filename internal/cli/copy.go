package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type copyRunFlags = localTransferRunFlags

type copyRunResult struct {
	OperationID         string `json:"operation_id"          yaml:"operation_id"`
	ManifestSHA256      string `json:"manifest_sha256"       yaml:"manifest_sha256"`
	SourceDriverID      string `json:"source_driver_id"      yaml:"source_driver_id"`
	DestinationDriverID string `json:"destination_driver_id" yaml:"destination_driver_id"`
	ObjectsWritten      uint64 `json:"objects_written"       yaml:"objects_written"`
	LocationsAdded      uint64 `json:"locations_added"       yaml:"locations_added"`
	CiphertextBytes     uint64 `json:"ciphertext_bytes"      yaml:"ciphertext_bytes"`
	RecoveryRevision    uint64 `json:"recovery_revision"     yaml:"recovery_revision"`
	State               string `json:"state"                 yaml:"state"`
}

func newCopyCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: copyCommandName, Short: "Operate durable copy workflows"}
	command.AddCommand(newCopyRunCommand(ctx, stdout))

	return command
}

func newCopyRunCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags copyRunFlags

	command := &cobra.Command{
		Use:   runCommandName,
		Short: "Replicate and publish one local filesystem destination",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeCopyRun(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	configureLocalTransferRunFlags(command, &flags, copyCommandName)

	return command
}

func executeCopyRun(
	ctx context.Context,
	flags copyRunFlags,
	getenv func(string) string,
) (copyRunResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return copyRunResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return copyRunResult{}, fmt.Errorf("construct control client: %w", err)
	}

	source, destination, err := openLocalTransferProviders(
		ctx,
		flags.sourceDriverID,
		flags.sourceRoot,
		flags.destinationDriverID,
		flags.destinationRoot,
	)
	if err != nil {
		return copyRunResult{}, err
	}

	replicator, err := sdk.NewReplicator(
		map[string]provider.Reader{source.ID: source.Reader},
		destinationReadWriter(destination),
		sdk.ReplicatorOptionsFromCapabilities(flags.maximumExtent, destination.Capabilities),
	)
	if err != nil {
		return copyRunResult{}, fmt.Errorf("construct copy replicator: %w", err)
	}

	coordinator, err := sdk.NewControlledReplicator(
		control,
		replicator,
		flags.leaseSeconds,
		flags.renewalInterval,
	)
	if err != nil {
		return copyRunResult{}, fmt.Errorf("construct controlled copy: %w", err)
	}

	result, err := coordinator.Copy(ctx, sdk.ControlledCopyRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		DestinationDriverID: flags.destinationDriverID,
		DestinationPrefix:   flags.destinationPrefix,
		IdempotencyKey: copyRunIdempotencyKey(
			flags.namespaceID,
			flags.manifestSHA256,
			source.ID,
			destination.ID,
			flags.destinationPrefix,
		),
		StagingDirectory: flags.stagingDirectory,
	})
	if err != nil {
		return copyRunResult{}, fmt.Errorf("execute controlled copy: %w", err)
	}

	return copyRunResult{
		OperationID: result.Operation.ID, ManifestSHA256: result.Operation.ManifestSHA256,
		SourceDriverID: source.ID, DestinationDriverID: result.Operation.DestinationDriverID,
		ObjectsWritten:   uint64(len(result.Replication.ProviderObjects)),
		LocationsAdded:   result.Publication.LocationsAdded,
		CiphertextBytes:  result.Replication.CiphertextBytes,
		RecoveryRevision: result.Publication.RecoveryRevision,
		State:            result.Publication.State,
	}, nil
}

func copyRunIdempotencyKey(namespaceID, manifestSHA256, sourceID, destinationID, prefix string) string {
	digest := sha256.Sum256([]byte(
		namespaceID + "\x00" + manifestSHA256 + "\x00" + sourceID + "\x00" + destinationID + "\x00" + prefix,
	))

	return "copy/" + hex.EncodeToString(digest[:])
}
