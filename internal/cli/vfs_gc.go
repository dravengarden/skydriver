package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/driver"
	driveraliyun "github.com/dravengarden/carrack/driver/aliyundrive"
	driverlocalfs "github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/sdk"
)

const vfsGCSweepSchema = "carrack.cli.vfs-gc-sweep.v1"

var errInvalidVFSGCBounds = errors.New("invalid VFS GC bounds: limit must be 1..100 and lease-seconds 15..300")

type vfsGCFlags struct {
	controlURL   string
	leaseSeconds uint64
	limit        uint32
	outputFormat string
}

type vfsGCSweepResult struct {
	Schema  string                    `json:"schema"  yaml:"schema"`
	Scanned uint32                    `json:"scanned" yaml:"scanned"`
	Idle    bool                      `json:"idle"    yaml:"idle"`
	Results []sdk.VFSPutJanitorResult `json:"results" yaml:"results"`
}

func newVFSGCCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	flags := vfsGCFlags{leaseSeconds: 60, limit: 1, outputFormat: outputFormatJSON}
	command := &cobra.Command{
		Use:   "gc",
		Short: "Delete expired unreferenced VFS Put objects under fenced authorization",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeVFSGC(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "short claim lease from 15 through 300 seconds")
	command.Flags().Uint32Var(&flags.limit, "limit", 1, "maximum objects to process in this bounded invocation")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")

	if err := command.MarkFlagRequired(controlURLFlag); err != nil {
		panic(err)
	}

	return command
}

func executeVFSGC(
	ctx context.Context,
	flags vfsGCFlags,
	getenv func(string) string,
) (vfsGCSweepResult, error) {
	if flags.limit == 0 || flags.limit > 100 || flags.leaseSeconds < 15 || flags.leaseSeconds > 300 {
		return vfsGCSweepResult{}, errInvalidVFSGCBounds
	}

	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return vfsGCSweepResult{}, err
	}
	defer control.Clear()

	registry := driver.NewRegistry()
	if registerErr := registry.Register(driverlocalfs.Kind, driverlocalfs.Factory); registerErr != nil {
		return vfsGCSweepResult{}, fmt.Errorf("register local filesystem VFS driver: %w", registerErr)
	}

	if registerErr := registry.Register(driveraliyun.Kind, driveraliyun.Factory); registerErr != nil {
		return vfsGCSweepResult{}, fmt.Errorf("register Aliyun Drive VFS driver: %w", registerErr)
	}

	janitor, err := sdk.NewVFSPutJanitor(control, registry, time.Duration(flags.leaseSeconds)*time.Second)
	if err != nil {
		return vfsGCSweepResult{}, fmt.Errorf("construct VFS Put janitor: %w", err)
	}

	result := vfsGCSweepResult{Schema: vfsGCSweepSchema, Results: make([]sdk.VFSPutJanitorResult, 0, flags.limit)}
	for range flags.limit {
		step, err := janitor.SweepOne(ctx)
		if err != nil {
			return result, fmt.Errorf("sweep VFS Put garbage: %w", err)
		}

		if step.Outcome == "idle" {
			result.Idle = true

			break
		}

		result.Results = append(result.Results, step)
		result.Scanned++
	}

	return result, nil
}

func writeVFSGCTable(writer io.Writer, result vfsGCSweepResult) error {
	if _, err := fmt.Fprintf(
		writer,
		"SCANNED\tIDLE\tOUTCOMES\n%d\t%t\t%d\n",
		result.Scanned,
		result.Idle,
		len(result.Results),
	); err != nil {
		return fmt.Errorf("write VFS GC table: %w", err)
	}

	return nil
}
