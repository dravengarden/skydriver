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
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

var errGCDeleteCapability = errors.New("local filesystem driver lacks GC delete capability")

type gcMarkFlags struct {
	controlURL     string
	namespaceID    string
	idempotencyKey string
	leaseSeconds   uint64
	outputFormat   string
}

type gcSweepFlags struct {
	controlURL    string
	localDriverID string
	localRoot     string
	leaseSeconds  uint64
	outputFormat  string
}

func newGCCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: gcCommandName, Short: "Collect unreachable immutable payloads"}
	command.AddCommand(newGCMarkCommand(ctx, stdout), newGCSweepCommand(ctx, stdout))

	return command
}

func newGCMarkCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags gcMarkFlags

	command := &cobra.Command{
		Use:   "mark",
		Short: "Tombstone one policy-derived unreachable payload set",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeGCMark(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeGCMarkTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this GC epoch")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "mark operation lease duration")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, namespaceFlag, idempotencyKeyFlag} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func newGCSweepCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags gcSweepFlags

	command := &cobra.Command{
		Use:   "sweep OPERATION_ID",
		Short: "Delete provider objects authorized by one expired GC grace period",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeGCSweep(ctx, flags, arguments[0], os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeGCSweepTable(stdout, result)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.localDriverID, localDriverIDFlag, "", "local filesystem GC driver ID")
	command.Flags().StringVar(&flags.localRoot, localRootFlag, "", "local filesystem archive root")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "delete task lease duration")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, localDriverIDFlag, localRootFlag} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeGCMark(
	ctx context.Context,
	flags gcMarkFlags,
	getenv func(string) string,
) (sdk.ControlledGCResult, error) {
	control, clearToken, err := newGCControlClient(flags.controlURL, getenv)
	if err != nil {
		return sdk.ControlledGCResult{}, err
	}
	defer clearToken()

	collector, err := sdk.NewControlledGarbageCollector(control, flags.leaseSeconds)
	if err != nil {
		return sdk.ControlledGCResult{}, fmt.Errorf("construct controlled garbage collector: %w", err)
	}

	result, err := collector.Mark(ctx, sdk.ControlledGCRequest{
		NamespaceID: flags.namespaceID, IdempotencyKey: flags.idempotencyKey,
	})
	if err != nil {
		return sdk.ControlledGCResult{}, fmt.Errorf("execute controlled GC mark: %w", err)
	}

	return result, nil
}

func executeGCSweep(
	ctx context.Context,
	flags gcSweepFlags,
	operationID string,
	getenv func(string) string,
) (sdk.GCSweepResult, error) {
	control, clearToken, err := newGCControlClient(flags.controlURL, getenv)
	if err != nil {
		return sdk.GCSweepResult{}, err
	}
	defer clearToken()

	absoluteRoot, err := filepath.Abs(flags.localRoot)
	if err != nil {
		return sdk.GCSweepResult{}, fmt.Errorf("resolve local filesystem root: %w", err)
	}

	configuration, err := json.Marshal(localfs.DriverConfig{Root: absoluteRoot})
	if err != nil {
		return sdk.GCSweepResult{}, fmt.Errorf("encode local filesystem configuration: %w", err)
	}

	registry, err := provider.NewRegistry(localfs.Factory{})
	if err != nil {
		return sdk.GCSweepResult{}, fmt.Errorf("construct provider registry: %w", err)
	}

	handle, err := registry.Open(ctx, provider.DriverSpec{
		ID: flags.localDriverID, Kind: localfs.DriverKind, Config: configuration,
	}, provider.Dependencies{})
	if err != nil {
		return sdk.GCSweepResult{}, fmt.Errorf("open local filesystem GC provider: %w", err)
	}

	if handle.Deleter == nil || !handle.Capabilities.Delete {
		return sdk.GCSweepResult{}, errGCDeleteCapability
	}

	janitor, err := sdk.NewGCJanitor(
		control,
		map[string]provider.Deleter{handle.ID: handle.Deleter},
		flags.leaseSeconds,
	)
	if err != nil {
		return sdk.GCSweepResult{}, fmt.Errorf("construct GC janitor: %w", err)
	}

	result, err := janitor.Sweep(ctx, operationID)
	if err != nil {
		return sdk.GCSweepResult{}, fmt.Errorf("sweep GC deletion: %w", err)
	}

	return result, nil
}

func newGCControlClient(
	controlURL string,
	getenv func(string) string,
) (*sdk.ControlClient, func(), error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return nil, func() {}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}

	control, err := sdk.NewControlClient(controlURL, controlToken, &http.Client{})
	if err != nil {
		controlToken.Clear()

		return nil, func() {}, fmt.Errorf("construct control client: %w", err)
	}

	return control, controlToken.Clear, nil
}

func writeGCMarkTable(writer io.Writer, result sdk.ControlledGCResult) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)

	graceUntil := uint64(0)
	if result.Mark.GraceUntil != nil {
		graceUntil = *result.Mark.GraceUntil
	}

	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tCANDIDATES\tOBJECTS\tGRACE UNTIL\tSTATE\n%s\t%d\t%d\t%d\t%s\n",
		result.Operation.ID,
		result.Mark.CandidatesMarked,
		result.Mark.ObjectsMarked,
		graceUntil,
		result.Mark.State,
	); err != nil {
		return fmt.Errorf("write GC mark table: %w", err)
	}

	return flushGCTable(table, "mark")
}

func writeGCSweepTable(writer io.Writer, result sdk.GCSweepResult) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintf(
		table,
		"OPERATION ID\tOBJECTS DELETED\tLOCATIONS DELETED\tSTATE\n%s\t%d\t%d\t%s\n",
		result.OperationID,
		result.ObjectsDeleted,
		result.LocationsDeleted,
		result.State,
	); err != nil {
		return fmt.Errorf("write GC sweep table: %w", err)
	}

	return flushGCTable(table, "sweep")
}

func flushGCTable(table *tabwriter.Writer, phase string) error {
	if err := table.Flush(); err != nil {
		return fmt.Errorf("flush GC %s table: %w", phase, err)
	}

	return nil
}
