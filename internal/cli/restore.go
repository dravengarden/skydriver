package cli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/provider/aliyundrive"
	"github.com/dravengarden/carrack/sdk"
)

const (
	controlTokenEnvironment  = "CARRACK_CONTROL_TOKEN"
	epochKeyEnvironment      = "CARRACK_EPOCH_KEY"
	aliyunTokenEnvironment   = "CARRACK_ALIYUN_ACCESS_TOKEN"  // #nosec G101 -- environment variable name, not a credential.
	aliyunRefreshEnvironment = "CARRACK_ALIYUN_REFRESH_TOKEN" // #nosec G101 -- environment variable name, not a credential.
	credentialKeyEnvironment = "CARRACK_CREDENTIAL_KEY"       // #nosec G101 -- environment variable name, not a credential.
	cliCredentialReference   = "cli/aliyundrive/oauth"        // #nosec G101 -- opaque reference, not a credential.
	defaultMaximumExtent     = uint64(65 << 20)
)

var (
	errEpochKeyEncoding  = errors.New("invalid Carrack epoch key encoding")
	errUnknownCredential = errors.New("unknown CLI credential reference")
	errCredentialMode    = errors.New("invalid Aliyun Drive credential mode")
)

type restoreFlags struct {
	controlURL      string
	namespaceID     string
	manifestSHA256  string
	driverID        string
	apiBaseURL      string
	driveType       string
	rootFolderID    string
	renewEndpoint   string
	renewDriver     string
	credentialStore string
	maximumExtent   uint64
	leaseSeconds    uint64
	renewalInterval time.Duration
	outputFormat    string
}

func newRestoreCommand(ctx context.Context, stdout io.Writer) *cobra.Command {
	var flags restoreFlags

	command := &cobra.Command{
		Use:   "restore DESTINATION",
		Short: "Restore one pinned archive version to a local file",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, arguments []string) error {
			result, err := executeRestore(ctx, flags, arguments[0], os.Getenv)
			if err != nil {
				return err
			}

			return writeValue(stdout, flags.outputFormat, result)
		},
	}
	command.Flags().StringVar(&flags.controlURL, "control-url", "", "Carrack control-plane URL")
	command.Flags().StringVar(&flags.namespaceID, "namespace", "", "namespace ID")
	command.Flags().StringVar(&flags.manifestSHA256, "manifest", "", "published manifest SHA-256")
	command.Flags().StringVar(&flags.driverID, "driver-id", "", "provider driver ID used by manifest locations")
	command.Flags().StringVar(&flags.apiBaseURL, "aliyun-api-base-url", "", "Aliyun Drive API base URL")
	command.Flags().StringVar(&flags.driveType, "aliyun-drive-type", "", "Aliyun Drive type")
	command.Flags().StringVar(&flags.rootFolderID, "aliyun-root-folder-id", "", "Aliyun Drive root folder ID")
	command.Flags().StringVar(&flags.renewEndpoint, "aliyun-renew-endpoint", "", "Aliyun refresh-token renewal endpoint")
	command.Flags().StringVar(&flags.renewDriver, "aliyun-renew-driver", "", "Aliyun renewal driver identifier")
	command.Flags().StringVar(&flags.credentialStore, "credential-store", "", "encrypted refresh-token store path")
	command.Flags().Uint64Var(&flags.maximumExtent, "maximum-extent-bytes", defaultMaximumExtent, "maximum ciphertext extent allocation")
	command.Flags().Uint64Var(&flags.leaseSeconds, "lease-seconds", 60, "read lease duration")
	command.Flags().DurationVar(&flags.renewalInterval, "renewal-interval", 30*time.Second, "read lease renewal interval")
	command.Flags().StringVar(&flags.outputFormat, "format", "table", "output format: table, json, or yaml")

	for _, name := range []string{"control-url", "namespace", "manifest", "driver-id"} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}

	return command
}

func executeRestore(
	ctx context.Context,
	flags restoreFlags,
	destination string,
	getenv func(string) string,
) (sdk.ControlledRestoreResult, error) {
	controlToken, err := sdk.ParseClientToken(getenv(controlTokenEnvironment))
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("read %s: %w", controlTokenEnvironment, err)
	}
	defer controlToken.Clear()

	var epochKey cryptostream.EpochKey
	if encodedEpochKey := getenv(epochKeyEnvironment); encodedEpochKey != "" {
		epochKey, err = parseEpochKey(encodedEpochKey)
		if err != nil {
			return sdk.ControlledRestoreResult{}, err
		}
	}
	defer clear(epochKey[:])

	httpClient := &http.Client{}

	control, err := sdk.NewControlClient(flags.controlURL, controlToken, httpClient)
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("construct control client: %w", err)
	}

	configuration, err := json.Marshal(aliyundrive.DriverConfig{
		APIBaseURL: flags.apiBaseURL, DriveType: flags.driveType, RootFolderID: flags.rootFolderID,
	})
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("encode Aliyun Drive configuration: %w", err)
	}

	credentials, err := restoreCredentialStore(ctx, flags, getenv)
	if err != nil {
		return sdk.ControlledRestoreResult{}, err
	}

	registry, err := provider.NewRegistry(aliyundrive.Factory{})
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("construct provider registry: %w", err)
	}

	handle, err := registry.Open(ctx, provider.DriverSpec{
		ID: flags.driverID, Kind: aliyundrive.DriverKind, Config: configuration,
		CredentialRef: cliCredentialReference,
	}, provider.Dependencies{
		HTTPClient:  httpClient,
		Credentials: credentials,
	})
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("open restore provider: %w", err)
	}

	restorer, err := sdk.NewRestorer(map[string]provider.Reader{flags.driverID: handle.Reader}, flags.maximumExtent)
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("construct local restorer: %w", err)
	}

	coordinator, err := sdk.NewControlledRestorer(control, restorer, flags.leaseSeconds, flags.renewalInterval)
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("construct restore coordinator: %w", err)
	}

	absoluteDestination, err := filepath.Abs(destination)
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("resolve restore destination: %w", err)
	}

	result, err := coordinator.Restore(ctx, sdk.ControlledRestoreRequest{
		NamespaceID: flags.namespaceID, ManifestSHA256: flags.manifestSHA256,
		IdempotencyKey: restoreIdempotencyKey(flags.manifestSHA256, absoluteDestination),
		EpochKey:       epochKey, Destination: absoluteDestination,
	})
	if err != nil {
		return sdk.ControlledRestoreResult{}, fmt.Errorf("execute restore: %w", err)
	}

	return result, nil
}

func restoreCredentialStore(
	ctx context.Context,
	flags restoreFlags,
	getenv func(string) string,
) (provider.CredentialStore, error) {
	accessToken := getenv(aliyunTokenEnvironment)
	refreshToken := getenv(aliyunRefreshEnvironment)

	if flags.credentialStore == "" {
		if accessToken == "" || refreshToken != "" {
			return nil, fmt.Errorf("%w: set only %s for static mode", errCredentialMode, aliyunTokenEnvironment)
		}

		credential, err := json.Marshal(aliyundrive.DriverCredential{AccessToken: accessToken}) // #nosec G117 -- secret remains in-memory for the typed factory.
		if err != nil {
			return nil, fmt.Errorf("encode Aliyun Drive credential: %w", err)
		}

		return staticCredentialStore{payload: credential}, nil
	}

	if accessToken != "" {
		return nil, fmt.Errorf("%w: %s cannot be used with --credential-store", errCredentialMode, aliyunTokenEnvironment)
	}

	store, err := newEncryptedCredentialStore(
		flags.credentialStore,
		getenv(credentialKeyEnvironment),
	)
	if err != nil {
		return nil, fmt.Errorf("construct encrypted credential store: %w", err)
	}

	if refreshToken != "" {
		credential, marshalErr := json.Marshal(aliyundrive.DriverCredential{ // #nosec G117 -- encrypted before persistence.
			RefreshToken: refreshToken, RenewEndpoint: flags.renewEndpoint, RenewDriver: flags.renewDriver,
		})
		if marshalErr != nil {
			return nil, fmt.Errorf("encode Aliyun Drive refresh credential: %w", marshalErr)
		}

		if initializeErr := store.Initialize(ctx, credential); initializeErr != nil {
			return nil, initializeErr
		}
	}

	return store, nil
}

func parseEpochKey(encoded string) (cryptostream.EpochKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(cryptostream.EpochKey{}) {
		return cryptostream.EpochKey{}, fmt.Errorf(
			"%w: %s must be unpadded base64url for exactly 32 bytes",
			errEpochKeyEncoding,
			epochKeyEnvironment,
		)
	}

	return cryptostream.EpochKey(decoded), nil
}

func restoreIdempotencyKey(manifestSHA256, destination string) string {
	digest := sha256.Sum256([]byte(manifestSHA256 + "\x00" + destination))

	return "restore/" + hex.EncodeToString(digest[:])
}

type staticCredentialStore struct {
	payload json.RawMessage
}

func (store staticCredentialStore) Load(
	_ context.Context,
	reference string,
) (provider.CredentialRecord, error) {
	if reference != cliCredentialReference {
		return provider.CredentialRecord{}, fmt.Errorf("%w %q", errUnknownCredential, reference)
	}

	return provider.CredentialRecord{Payload: store.payload, Revision: 1}, nil
}

func (staticCredentialStore) CompareAndSwap(
	context.Context,
	string,
	uint64,
	json.RawMessage,
) (provider.CredentialRecord, error) {
	return provider.CredentialRecord{}, provider.ErrCredentialConflict
}
