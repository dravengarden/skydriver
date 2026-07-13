package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/sdk"
)

const (
	vfsCatalogCommandName = "catalog"
	vfsCatalogSyncName    = "sync"
	vfsCatalogCacheFlag   = "cache-directory"
)

var errVFSCatalogCacheHome = errors.New("HOME or XDG_CACHE_HOME is required for the VFS catalog")

type vfsCatalogSyncFlags struct {
	controlURL     string
	cacheDirectory string
	pageSize       uint32
	maxConcurrency uint32
	outputFormat   string
}

func newVFSCatalogCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   vfsCatalogCommandName,
		Short: "Synchronize the verified local VFS metadata DAG",
	}
	command.AddCommand(newVFSCatalogSyncCommand(ctx, stdout))

	return command
}

func newVFSCatalogSyncCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsCatalogSyncFlags

	command := &cobra.Command{
		Use:   vfsCatalogSyncName + " ROOT_DIRECTORY_ID",
		Short: "Fetch only missing Merkle-addressed directory nodes",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVFSCatalogSync(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(
		&flags.cacheDirectory,
		vfsCatalogCacheFlag,
		"",
		"private content-addressed catalog cache",
	)
	command.Flags().Uint32Var(&flags.pageSize, "page-size", 1_000, "directory page size from 1 through 1000")
	command.Flags().Uint32Var(&flags.maxConcurrency, "max-concurrency", 8, "independent child-directory fetches from 1 through 64")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: table, json, or yaml")
	mustMarkRequired(command, controlURLFlag)

	return command
}

func executeVFSCatalogSync(
	ctx context.Context,
	flags vfsCatalogSyncFlags,
	rootDirectoryID string,
	getenv func(string) string,
) (sdk.VFSCatalogSyncResult, error) {
	cacheDirectory, err := resolveVFSCatalogDirectory(flags.cacheDirectory, getenv)
	if err != nil {
		return sdk.VFSCatalogSyncResult{}, err
	}

	store, err := sdk.NewVFSCatalogStore(cacheDirectory)
	if err != nil {
		return sdk.VFSCatalogSyncResult{}, fmt.Errorf("open VFS catalog cache: %w", err)
	}

	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSCatalogSyncResult{}, err
	}
	defer control.Clear()

	result, err := control.SyncCatalog(ctx, rootDirectoryID, store, sdk.VFSCatalogSyncOptions{
		PageSize:       flags.pageSize,
		MaxConcurrency: flags.maxConcurrency,
	})
	if err != nil {
		return sdk.VFSCatalogSyncResult{}, fmt.Errorf("synchronize VFS catalog: %w", err)
	}

	return result, nil
}

func resolveVFSCatalogDirectory(cacheDirectory string, getenv func(string) string) (string, error) {
	if getenv == nil {
		return "", errVFSEnvironment
	}

	if cacheDirectory == "" {
		cacheRoot := getenv("XDG_CACHE_HOME")
		if cacheRoot == "" {
			home := getenv("HOME")
			if home == "" {
				return "", errVFSCatalogCacheHome
			}

			cacheRoot = filepath.Join(home, ".cache")
		}

		cacheDirectory = filepath.Join(cacheRoot, "carrack", "vfs", "catalog")
	}

	absolute, err := filepath.Abs(cacheDirectory)
	if err != nil {
		return "", fmt.Errorf("resolve VFS catalog directory: %w", err)
	}

	return filepath.Clean(absolute), nil
}

func writeVFSCatalogSyncTable(table *tabwriter.Writer, result sdk.VFSCatalogSyncResult) error {
	if _, err := fmt.Fprintf(
		table,
		"DIRECTORY ID\tDATA ROOT\tREVISION\tDIRECTORIES\tENTRIES\tFETCHED\tREUSED\tCACHE\n%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
		result.RootDirectoryID,
		result.RootDataRoot,
		result.RootRevision,
		result.Directories,
		result.Entries,
		result.FetchedNodes,
		result.ReusedNodes,
		result.CacheDirectory,
	); err != nil {
		return fmt.Errorf("write VFS catalog-sync table: %w", err)
	}

	return nil
}
