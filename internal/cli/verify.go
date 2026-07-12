package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	command.Flags().StringVar(&flags.localDriverID, "local-driver-id", "", "local filesystem driver ID used by manifest locations")
	command.Flags().StringVar(&flags.localRoot, "local-root", "", "local filesystem archive root")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{"local-driver-id", "local-root"} {
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
