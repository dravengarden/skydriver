package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

var errMoveDeleteCapability = errors.New("local filesystem driver lacks delete capability")

type moveSweepFlags struct {
	controlURL    string
	localDriverID string
	localRoot     string
	leaseSeconds  uint64
	outputFormat  string
}

func newMoveCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: "move", Short: "Operate durable move sagas"}
	command.AddCommand(newMoveSweepCommand(ctx, stdout))

	return command
}

func newMoveSweepCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags moveSweepFlags

	command := &cobra.Command{
		Use:   "sweep OPERATION_ID",
		Short: "Run explicitly authorized delayed provider deletion",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeMoveSweep(ctx, flags, arguments[0], os.Getenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, "control-url", "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.localDriverID, "local-driver-id", "", "local filesystem source driver ID")
	command.Flags().StringVar(&flags.localRoot, "local-root", "", "local filesystem archive root")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "delete task lease duration")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{"control-url", "local-driver-id", "local-root"} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeMoveSweep(
	ctx context.Context,
	flags moveSweepFlags,
	operationID string,
	getenv func(string) string,
) (sdk.MoveSweepResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("construct control client: %w", err)
	}

	absoluteRoot, err := filepath.Abs(flags.localRoot)
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("resolve local filesystem root: %w", err)
	}

	configuration, err := json.Marshal(localfs.DriverConfig{Root: absoluteRoot})
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("encode local filesystem configuration: %w", err)
	}

	registry, err := provider.NewRegistry(localfs.Factory{})
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("construct provider registry: %w", err)
	}

	handle, err := registry.Open(ctx, provider.DriverSpec{
		ID: flags.localDriverID, Kind: localfs.DriverKind, Config: configuration,
	}, provider.Dependencies{})
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("open local filesystem janitor provider: %w", err)
	}

	if handle.Deleter == nil || !handle.Capabilities.Delete {
		return sdk.MoveSweepResult{}, errMoveDeleteCapability
	}

	janitor, err := sdk.NewMoveJanitor(
		control,
		map[string]provider.Deleter{handle.ID: handle.Deleter},
		flags.leaseSeconds,
	)
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("construct move janitor: %w", err)
	}

	result, err := janitor.SweepMove(ctx, operationID)
	if err != nil {
		return sdk.MoveSweepResult{}, fmt.Errorf("sweep move deletion: %w", err)
	}

	return result, nil
}
