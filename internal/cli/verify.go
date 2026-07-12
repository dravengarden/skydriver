package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/localfs"
	"github.com/dravengarden/carrack/sdk"
)

type verifyFlags struct {
	localDriverID string
	localRoot     string
	outputFormat  string
}

type controlledVerifyFlags struct {
	controlURL      string
	namespaceID     string
	manifestSHA256  string
	localDriverID   string
	localRoot       string
	idempotencyKey  string
	leaseSeconds    uint64
	renewalInterval time.Duration
	outputFormat    string
}

func newVerifyCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags verifyFlags

	command := &cobra.Command{
		Use:   "verify RECOVERY_MANIFEST",
		Short: "Verify complete ciphertext extents in a local archive",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeVerify(ctx, flags, arguments[0])
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.localDriverID, localDriverIDFlag, "", "local filesystem driver ID used by manifest locations")
	command.Flags().StringVar(&flags.localRoot, localRootFlag, "", "local filesystem archive root")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{localDriverIDFlag, localRootFlag} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	command.AddCommand(newVerifyRunCommand(ctx, stdout))

	return command
}

func newVerifyRunCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags controlledVerifyFlags

	command := &cobra.Command{
		Use:   runCommandName,
		Short: "Run one fenced local archive verification",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			result, err := executeControlledVerify(ctx, flags, os.Getenv)
			if err != nil {
				return err
			}

			if flags.outputFormat == outputFormatTable {
				return writeValue(stdout, flags.outputFormat, result.Verification)
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	command.Flags().StringVar(&flags.manifestSHA256, manifestFlag, "", "published manifest SHA-256")
	command.Flags().StringVar(&flags.localDriverID, localDriverIDFlag, "", "local filesystem driver ID")
	command.Flags().StringVar(&flags.localRoot, localRootFlag, "", "local filesystem archive root")
	command.Flags().StringVar(&flags.idempotencyKey, idempotencyKeyFlag, "", "stable identity for this audit attempt")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "verification lease duration")
	command.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, "lease renewal interval")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag, namespaceFlag, manifestFlag, localDriverIDFlag, localRootFlag, idempotencyKeyFlag,
	} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeVerify(ctx context.Context, flags verifyFlags, recoveryPath string) (sdk.VerificationResult, error) {
	encoded, err := os.ReadFile(recoveryPath) // #nosec G304 -- the operator explicitly selects the recovery sidecar.
	if err != nil {
		return sdk.VerificationResult{}, fmt.Errorf("read recovery manifest: %w", err)
	}

	recovery, err := manifest.ParseRecovery(encoded)
	if err != nil {
		return sdk.VerificationResult{}, fmt.Errorf("parse recovery manifest: %w", err)
	}

	absoluteRoot, err := filepath.Abs(flags.localRoot)
	if err != nil {
		return sdk.VerificationResult{}, fmt.Errorf("resolve local filesystem root: %w", err)
	}

	reader, err := localfs.NewClient(absoluteRoot)
	if err != nil {
		return sdk.VerificationResult{}, fmt.Errorf("open local filesystem archive: %w", err)
	}

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{flags.localDriverID: reader})
	if err != nil {
		return sdk.VerificationResult{}, fmt.Errorf("construct verifier: %w", err)
	}

	result, err := verifier.Verify(ctx, recovery, flags.localDriverID)
	if err != nil {
		return sdk.VerificationResult{}, fmt.Errorf("verify local archive: %w", err)
	}

	return result, nil
}

func executeControlledVerify(
	ctx context.Context,
	flags controlledVerifyFlags,
	getenv func(string) string,
) (sdk.ControlledVerifyResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, &http.Client{})
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("construct control client: %w", err)
	}

	absoluteRoot, err := filepath.Abs(flags.localRoot)
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("resolve local filesystem root: %w", err)
	}

	reader, err := localfs.NewClient(absoluteRoot)
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("open local filesystem archive: %w", err)
	}

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{flags.localDriverID: reader})
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("construct verifier: %w", err)
	}

	coordinator, err := sdk.NewControlledVerifier(
		control,
		verifier,
		flags.leaseSeconds,
		flags.renewalInterval,
	)
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("construct controlled verifier: %w", err)
	}

	result, err := coordinator.Verify(ctx, sdk.ControlledVerifyRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		DriverID: flags.localDriverID, IdempotencyKey: flags.idempotencyKey,
	})
	if err != nil {
		return sdk.ControlledVerifyResult{}, fmt.Errorf("execute controlled verify: %w", err)
	}

	return result, nil
}
