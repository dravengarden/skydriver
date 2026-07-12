package cli

import (
	"os"
	"time"

	"github.com/spf13/cobra"
)

type localTransferRunFlags struct {
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

func configureLocalTransferRunFlags(
	command *cobra.Command,
	flags *localTransferRunFlags,
	operation string,
) {
	command.Flags().StringVar(&flags.controlURL, controlURLFlag, "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, namespaceFlag, "", "namespace ID")
	command.Flags().StringVar(&flags.manifestSHA256, manifestFlag, "", "published manifest SHA-256")
	command.Flags().StringVar(&flags.sourceDriverID, sourceLocalDriverIDFlag, "", "source local filesystem driver ID")
	command.Flags().StringVar(&flags.sourceRoot, sourceLocalRootFlag, "", "source local filesystem archive root")
	command.Flags().StringVar(&flags.destinationDriverID, destinationLocalDriverIDFlag, "", "destination local filesystem driver ID")
	command.Flags().StringVar(&flags.destinationRoot, destinationLocalRootFlag, "", "destination local filesystem archive root")
	command.Flags().StringVar(&flags.destinationPrefix, destinationPrefixFlag, "", "destination-owned object prefix")
	command.Flags().StringVar(&flags.stagingDirectory, stagingDirectoryFlag, os.TempDir(), "bounded local replication staging directory")
	command.Flags().Uint64Var(&flags.maximumExtent, "maximum-extent-bytes", defaultMaximumExtent, "maximum ciphertext extent allocation")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, operation+" write lease duration")
	command.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, operation+" lease renewal interval")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{
		controlURLFlag, namespaceFlag, manifestFlag, sourceLocalDriverIDFlag, sourceLocalRootFlag,
		destinationLocalDriverIDFlag, destinationLocalRootFlag, destinationPrefixFlag,
	} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}
