package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/driver/localfs"
	"github.com/dravengarden/carrack/sdk"
)

const operatorCredentialEnvironment = "CARRACK_OPERATOR_CREDENTIAL" // #nosec G101 -- environment variable name, not a credential.

var errOperatorCredentialEnvironment = errors.New("CARRACK_OPERATOR_CREDENTIAL is required")

var (
	errAdminIdempotencyKeyRequired = errors.New("--idempotency-key is required unless --check is used")
	errAdminVerificationMismatch   = errors.New("token annotation receipt did not match effective server state")
	errAdminDriverMismatch         = errors.New("driver state receipt did not match effective server state")
	errAdminDriverLocalValidation  = errors.New("driver configuration failed local validation")
)

type adminReadFlags struct {
	controlURL   string
	outputFormat string
}

type adminTokenAnnotationFlags struct {
	adminReadFlags

	label            string
	note             string
	expectedRevision uint64
	idempotencyKey   string
	check            bool
}

type adminDriverStateFlags struct {
	adminReadFlags

	expectedRevision uint64
	idempotencyKey   string
	check            bool
}

type adminDriverStateSpec struct {
	verb    string
	enabled bool
}

func newAdminCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "admin",
		Short: "Inspect and safely configure the Carrack management plane",
	}
	command.AddCommand(
		newAdminSnapshotCommand(ctx, stdout),
		newAdminDirectoryCommand(ctx, stdout),
		newAdminDriverCommand(ctx, stdout),
		newAdminTokenCommand(ctx, stdout),
	)

	return command
}

func newAdminDriverCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{Use: "driver", Short: "Validate and apply driver configuration state"}
	command.AddCommand(
		newAdminDriverStateCommand(ctx, stdout, adminDriverStateSpec{verb: "enable", enabled: true}),
		newAdminDriverStateCommand(ctx, stdout, adminDriverStateSpec{verb: "disable"}),
	)

	return command
}

func newAdminDriverStateCommand(
	ctx context.Context,
	stdout io.Writer,
	spec adminDriverStateSpec,
) *cobra.Command {
	var flags adminDriverStateFlags

	command := &cobra.Command{
		Use:   spec.verb + " DRIVER_ID",
		Short: "Validate and atomically " + spec.verb + " one registered driver",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			value, err := executeAdminDriverState(ctx, flags, arguments[0], spec, defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, value)
		},
	}
	addAdminReadFlags(command, &flags.adminReadFlags)
	command.Flags().Uint64Var(&flags.expectedRevision, "expected-revision", 0, "exact observed driver revision")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact state transition")
	command.Flags().BoolVar(&flags.check, "check", false, "run local and server validation without applying")
	mustMarkRequired(command, "expected-revision")

	return command
}

func newAdminTokenCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	command := &cobra.Command{
		Use:   "token",
		Short: "Validate and apply token management metadata",
	}
	command.AddCommand(newAdminTokenAnnotateCommand(ctx, stdout))

	return command
}

func newAdminTokenAnnotateCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags adminTokenAnnotationFlags

	command := &cobra.Command{
		Use:   "annotate TOKEN_ID",
		Short: "Validate and atomically apply a token label and note",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			value, err := executeAdminTokenAnnotation(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, value)
		},
	}
	addAdminReadFlags(command, &flags.adminReadFlags)
	command.Flags().StringVar(&flags.label, "label", "", "human-readable token label")
	command.Flags().StringVar(&flags.note, "note", "", "non-secret operator note")
	command.Flags().Uint64Var(&flags.expectedRevision, "expected-revision", 0, "exact observed token metadata revision")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this exact annotation")
	command.Flags().BoolVar(&flags.check, "check", false, "run local and server validation without applying")
	mustMarkRequired(command, "label")
	mustMarkRequired(command, "expected-revision")

	return command
}

func newAdminSnapshotCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags adminReadFlags

	command := &cobra.Command{
		Use:   "snapshot",
		Short: "Export the redacted driver, VFS, and token management snapshot",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			value, err := executeAdminSnapshot(ctx, flags, defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, value)
		},
	}
	addAdminReadFlags(command, &flags)

	return command
}

func newAdminDirectoryCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags adminReadFlags

	command := &cobra.Command{
		Use:   "directory DIRECTORY_ID",
		Short: "Inspect one VFS collection with recursive statistics and complete entries",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			value, err := executeAdminDirectory(ctx, flags, arguments[0], defaultGetenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, value)
		},
	}
	addAdminReadFlags(command, &flags)

	return command
}

func addAdminReadFlags(command *cobra.Command, flags *adminReadFlags) {
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.outputFormat, "format", outputFormatJSON, "output format: json or yaml")
	mustMarkRequired(command, controlURLFlag)
}

func executeAdminSnapshot(
	ctx context.Context,
	flags adminReadFlags,
	getenv func(string) string,
) (sdk.ManagementSnapshot, error) {
	client, err := newAdminClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.ManagementSnapshot{}, err
	}
	defer client.Clear()

	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return sdk.ManagementSnapshot{}, fmt.Errorf("read management snapshot: %w", err)
	}

	return snapshot, nil
}

func executeAdminDirectory(
	ctx context.Context,
	flags adminReadFlags,
	directoryID string,
	getenv func(string) string,
) (sdk.ManagementDirectory, error) {
	client, err := newAdminClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return sdk.ManagementDirectory{}, err
	}
	defer client.Clear()

	directory, err := client.Directory(ctx, directoryID)
	if err != nil {
		return sdk.ManagementDirectory{}, fmt.Errorf("read management directory: %w", err)
	}

	return directory, nil
}

func executeAdminTokenAnnotation(
	ctx context.Context,
	flags adminTokenAnnotationFlags,
	tokenID string,
	getenv func(string) string,
) (any, error) {
	client, err := newAdminClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return nil, err
	}
	defer client.Clear()

	validation, err := client.ValidateTokenAnnotation(ctx, tokenID, sdk.ValidateTokenAnnotationRequest{
		Label: flags.label, Note: flags.note, ExpectedRevision: flags.expectedRevision,
	})
	if err != nil {
		return nil, fmt.Errorf("validate token annotation: %w", err)
	}

	if flags.check {
		return validation, nil
	}

	if flags.idempotencyKey == "" {
		return nil, errAdminIdempotencyKeyRequired
	}

	if enableErr := client.EnableConfiguration(ctx); enableErr != nil {
		return nil, fmt.Errorf("enable configuration session: %w", enableErr)
	}

	receipt, err := client.ApplyTokenAnnotation(ctx, tokenID, sdk.ApplyTokenAnnotationRequest{
		Label:               validation.Label,
		Note:                validation.Note,
		ExpectedRevision:    validation.ExpectedRevision,
		ValidationExpiresAt: validation.ValidationExpiresAt,
		ValidationDigest:    validation.ValidationDigest,
		IdempotencyKey:      flags.idempotencyKey,
	})
	if err != nil {
		return nil, fmt.Errorf("apply token annotation: %w", err)
	}

	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify token annotation: %w", err)
	}

	for _, token := range snapshot.Tokens {
		if token.ID == tokenID && token.Label == receipt.Label && token.Note == receipt.Note &&
			token.MetadataRevision == receipt.FinalRevision {
			return receipt, nil
		}
	}

	return nil, errAdminVerificationMismatch
}

func executeAdminDriverState(
	ctx context.Context,
	flags adminDriverStateFlags,
	driverID string,
	spec adminDriverStateSpec,
	getenv func(string) string,
) (any, error) {
	client, err := newAdminClientFromEnvironment(flags.controlURL, getenv)
	if err != nil {
		return nil, err
	}
	defer client.Clear()

	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("read driver before validation: %w", err)
	}

	driver, found := findManagementDriver(snapshot, driverID)
	if !found || driver.Revision != flags.expectedRevision {
		return nil, errAdminDriverLocalValidation
	}

	if spec.enabled {
		if validationErr := validateDriverOnAgent(driver); validationErr != nil {
			return nil, validationErr
		}
	}

	validation, err := client.ValidateDriverState(ctx, driverID, sdk.ValidateDriverStateRequest{
		Enabled: spec.enabled, ExpectedRevision: flags.expectedRevision,
	})
	if err != nil {
		return nil, fmt.Errorf("validate driver state: %w", err)
	}

	if flags.check {
		return validation, nil
	}

	if flags.idempotencyKey == "" {
		return nil, errAdminIdempotencyKeyRequired
	}

	if enableErr := client.EnableConfiguration(ctx); enableErr != nil {
		return nil, fmt.Errorf("enable configuration session: %w", enableErr)
	}

	receipt, err := client.ApplyDriverState(ctx, driverID, sdk.ApplyDriverStateRequest{
		Enabled:             validation.Enabled,
		ExpectedRevision:    validation.ExpectedRevision,
		ValidationExpiresAt: validation.ValidationExpiresAt,
		ValidationDigest:    validation.ValidationDigest,
		IdempotencyKey:      flags.idempotencyKey,
	})
	if err != nil {
		return nil, fmt.Errorf("apply driver state: %w", err)
	}

	effective, err := client.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify driver state: %w", err)
	}

	updated, found := findManagementDriver(effective, driverID)
	if !found || updated.Enabled != receipt.Enabled || updated.Revision != receipt.FinalRevision {
		return nil, errAdminDriverMismatch
	}

	return receipt, nil
}

func findManagementDriver(snapshot sdk.ManagementSnapshot, driverID string) (sdk.ManagementDriver, bool) {
	for _, driver := range snapshot.Drivers {
		if driver.ID == driverID {
			return driver, true
		}
	}

	return sdk.ManagementDriver{}, false
}

func validateDriverOnAgent(driver sdk.ManagementDriver) error {
	if driver.Kind != string(localfs.Kind) {
		return fmt.Errorf("%w: unsupported kind %q", errAdminDriverLocalValidation, driver.Kind)
	}

	var configuration struct {
		Root string `json:"root"`
	}

	decoder := json.NewDecoder(bytes.NewReader(driver.Config))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&configuration); err != nil {
		return fmt.Errorf("%w: %w", errAdminDriverLocalValidation, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing driver configuration JSON", errAdminDriverLocalValidation)
	}

	if _, err := localfs.Open(driver.ID, configuration.Root); err != nil {
		return fmt.Errorf("%w: %w", errAdminDriverLocalValidation, err)
	}

	return nil
}

func newAdminClientFromEnvironment(
	controlURL string,
	getenv func(string) string,
) (*sdk.AdminClient, error) {
	if getenv == nil {
		return nil, errVFSEnvironment
	}

	encoded := getenv(operatorCredentialEnvironment)
	if encoded == "" {
		return nil, errOperatorCredentialEnvironment
	}

	credential, err := sdk.ParseOperatorCredential(encoded)
	if err != nil {
		return nil, fmt.Errorf("parse operator credential: %w", err)
	}
	defer credential.Clear()

	client, err := sdk.NewAdminClient(
		controlURL,
		credential,
		&http.Client{Timeout: 30 * time.Second},
	)
	if err != nil {
		return nil, fmt.Errorf("construct Carrack admin client: %w", err)
	}

	return client, nil
}
