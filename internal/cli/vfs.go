package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/driver"
	driveraliyun "github.com/dravengarden/carrack/driver/aliyundrive"
	driverlocalfs "github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/sdk"
)

const (
	vfsCommandName       = "vfs"
	vfsTokenEnvironment  = "CARRACK_VFS_TOKEN" // #nosec G101 -- environment variable name, not a credential.
	directoryIDFlag      = "directory-id"
	entryRevisionFlag    = "expected-entry-revision"
	preferredDriverFlag  = "preferred-driver-id"
	journalDirectoryFlag = "journal-directory"
)

var (
	errVFSStdinRequired = errors.New("stdin is required for VFS Put")
	errVFSEnvironment   = errors.New("environment lookup is required")
	errVFSStateHome     = errors.New("HOME or XDG_STATE_HOME is required for the VFS journal")
	errVFSCacheHome     = errors.New("HOME or XDG_CACHE_HOME is required for VFS staging")
)

type vfsPutFlags struct {
	controlURL             string
	directoryID            string
	expectedEntryRevision  uint64
	preferredDriverID      string
	idempotencyKey         string
	journalDirectory       string
	stagingDirectory       string
	verificationBlockBytes uint64
	encryptionFrameBytes   uint64
	partBytes              uint64
	maxConcurrency         uint32
	requireResumable       bool
	requireParallel        bool
	requireStrongChecksum  bool
	resumeJournalID        string
	outputFormat           string
}

func newVFSCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   vfsCommandName,
		Short: "Operate the Carrack virtual filesystem",
	}
	command.AddCommand(
		newVFSPutCommand(ctx, stdout),
		newVFSDirectoryCommand(ctx, stdout),
		newVFSACLCommand(ctx, stdout),
		newVFSCatalogCommand(ctx, stdout),
		newVFSPlacementCommand(ctx, stdout),
		newVFSTokenCommand(ctx, stdout),
		newVFSJournalCommand(stdout),
		newVFSGCCommand(ctx, stdout),
	)

	return command
}

func newVFSPutCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags vfsPutFlags

	command := &cobra.Command{
		Use:   "put LOCAL_FILE ENTRY_NAME",
		Short: "Upload one local file or stdin as one complete VFS object",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, arguments []string) error {
			result, err := executeVFSPut(
				ctx,
				flags,
				arguments[0],
				arguments[1],
				command.InOrStdin(),
				os.Getenv,
			)
			if err != nil {
				return err
			}

			for _, warning := range result.Warnings {
				if _, err := fmt.Fprintf(
					command.ErrOrStderr(),
					"warning: %s: %s; fallback: %s\n",
					warning.Code,
					warning.PerformanceImpact,
					warning.Fallback,
				); err != nil {
					return fmt.Errorf("write VFS Put warning: %w", err)
				}
			}

			if result.StagingCleanupWarning != "" {
				if _, err := fmt.Fprintf(command.ErrOrStderr(), "warning: %s\n", result.StagingCleanupWarning); err != nil {
					return fmt.Errorf("write VFS staging warning: %w", err)
				}
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.directoryID, directoryIDFlag, "", "destination VFS directory ID")
	command.Flags().Uint64Var(&flags.expectedEntryRevision, entryRevisionFlag, 0, "expected current entry revision; zero requires absence")
	command.Flags().StringVar(&flags.preferredDriverID, preferredDriverFlag, "", "authorized destination driver preference")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact file version Put")
	command.Flags().StringVar(&flags.journalDirectory, journalDirectoryFlag, "", "private durable transfer-journal directory")
	command.Flags().StringVar(&flags.stagingDirectory, stagingDirectoryFlag, "", "private encoded-object staging directory")
	command.Flags().Uint64Var(&flags.verificationBlockBytes, "verification-block-bytes", 4<<20, "plaintext Merkle verification block size")
	command.Flags().Uint64Var(&flags.encryptionFrameBytes, "encryption-frame-bytes", 4<<20, "authenticated encryption frame size")
	command.Flags().Uint64Var(&flags.partBytes, "part-bytes", 0, "provider multipart size; zero uses the driver preference")
	command.Flags().Uint32Var(&flags.maxConcurrency, "max-concurrency", 0, "bounded provider transfer concurrency")
	command.Flags().BoolVar(&flags.requireResumable, "require-resumable", false, "fail instead of restarting this file when resume is unavailable")
	command.Flags().BoolVar(&flags.requireParallel, "require-parallel", false, "fail instead of sequential upload when parallel parts are unavailable")
	command.Flags().BoolVar(&flags.requireStrongChecksum, "require-strong-checksum", false, "fail instead of complete readback when provider checksum is unavailable")
	command.Flags().StringVar(&flags.resumeJournalID, "resume-journal-id", "", "resume one exact durable VFS upload journal")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{controlURLFlag, directoryIDFlag, idempotencyKeyFlag} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeVFSPut(
	ctx context.Context,
	flags vfsPutFlags,
	sourcePath,
	entryName string,
	stdin io.Reader,
	getenv func(string) string,
) (sdk.VFSPutResult, error) {
	journalDirectory, stagingDirectory, err := resolveVFSStateDirectories(
		flags.journalDirectory,
		flags.stagingDirectory,
		getenv,
	)
	if err != nil {
		return sdk.VFSPutResult{}, err
	}

	control, err := newVFSControlClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.VFSPutResult{}, err
	}
	defer control.Clear()

	registry := driver.NewRegistry()
	if registerErr := registry.Register(driverlocalfs.Kind, driverlocalfs.Factory); registerErr != nil {
		return sdk.VFSPutResult{}, fmt.Errorf("register local filesystem VFS driver: %w", registerErr)
	}

	if registerErr := registry.Register(driveraliyun.Kind, driveraliyun.Factory); registerErr != nil {
		return sdk.VFSPutResult{}, fmt.Errorf("register Aliyun Drive VFS driver: %w", registerErr)
	}

	client, err := sdk.NewVFSClient(control, registry, sdk.VFSClientOptions{
		JournalDirectory: journalDirectory,
		StagingDirectory: stagingDirectory,
		MaxConcurrency:   flags.maxConcurrency,
	})
	if err != nil {
		return sdk.VFSPutResult{}, fmt.Errorf("construct VFS client: %w", err)
	}

	putOptions := sdk.VFSPutOptions{
		DirectoryID:            flags.directoryID,
		EntryName:              entryName,
		ExpectedEntryRevision:  flags.expectedEntryRevision,
		PreferredDriverID:      flags.preferredDriverID,
		IdempotencyKey:         flags.idempotencyKey,
		VerificationBlockBytes: flags.verificationBlockBytes,
		EncryptionFrameBytes:   flags.encryptionFrameBytes,
		UploadPartBytes:        flags.partBytes,
		RequireResumable:       flags.requireResumable,
		RequireParallel:        flags.requireParallel,
		RequireStrongChecksum:  flags.requireStrongChecksum,
		ResumeJournalID:        flags.resumeJournalID,
	}

	if sourcePath != "-" {
		result, putErr := client.PutFile(ctx, sourcePath, putOptions)
		if putErr != nil {
			return sdk.VFSPutResult{}, fmt.Errorf("put local file into VFS: %w", putErr)
		}

		return result, nil
	}

	if stdin == nil {
		return sdk.VFSPutResult{}, errVFSStdinRequired
	}

	spooledPath, err := spoolVFSStdin(ctx, stagingDirectory, stdin)
	if err != nil {
		return sdk.VFSPutResult{}, err
	}

	defer removeCLIFileBestEffort(spooledPath)

	result, err := client.PutFile(ctx, spooledPath, putOptions)
	if err != nil {
		return sdk.VFSPutResult{}, fmt.Errorf("put spooled stdin into VFS: %w", err)
	}

	return result, nil
}

func resolveVFSStateDirectories(
	journalDirectory,
	stagingDirectory string,
	getenv func(string) string,
) (journalPath, stagingPath string, returnErr error) {
	if getenv == nil {
		return "", "", errVFSEnvironment
	}

	journalPath, err := resolveVFSJournalDirectory(journalDirectory, getenv)
	if err != nil {
		return "", "", err
	}

	if stagingDirectory == "" {
		cacheRoot := getenv("XDG_CACHE_HOME")
		if cacheRoot == "" {
			home := getenv("HOME")
			if home == "" {
				return "", "", errVFSCacheHome
			}

			cacheRoot = filepath.Join(home, ".cache")
		}

		stagingDirectory = filepath.Join(cacheRoot, "carrack", "vfs", "staging")
	}

	stagingDirectory, err = filepath.Abs(stagingDirectory)
	if err != nil {
		return "", "", fmt.Errorf("resolve VFS staging directory: %w", err)
	}

	return journalPath, filepath.Clean(stagingDirectory), nil
}

func spoolVFSStdin(ctx context.Context, directory string, source io.Reader) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create VFS stdin staging directory: %w", err)
	}

	file, err := os.CreateTemp(directory, ".stdin-*.partial")
	if err != nil {
		return "", fmt.Errorf("create VFS stdin staging: %w", err)
	}

	filePath := file.Name()
	remove := true

	defer func() {
		if remove {
			removeCLIFileBestEffort(filePath)
		}
	}()

	_, copyErr := io.Copy(file, &vfsCLIContextReader{cancellation: ctx.Err, reader: source})
	syncErr := file.Sync()

	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, syncErr, closeErr)
	}

	remove = false

	return filePath, nil
}

type vfsCLIContextReader struct {
	cancellation func() error
	reader       io.Reader
}

func (reader *vfsCLIContextReader) Read(buffer []byte) (int, error) {
	if err := reader.cancellation(); err != nil {
		return 0, fmt.Errorf("read VFS stdin: %w", err)
	}

	return reader.reader.Read(buffer) //nolint:wrapcheck // io.Reader must preserve EOF.
}

func removeCLIFileBestEffort(filePath string) {
	if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}
