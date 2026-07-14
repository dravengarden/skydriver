package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/dravengarden/carrack/driver"
	"github.com/dravengarden/carrack/vfs/cryptofile"
)

const (
	vfsTokenBytes     = 32
	vfsCommittedState = "committed"

	// VFSPlaintextSuite stores complete provider objects without content encryption.
	VFSPlaintextSuite = "plaintext/v1"
	// VFSEncryptedSuite stores complete provider objects as authenticated AES-GCM frames.
	VFSEncryptedSuite = cryptofile.Suite

	// VFSVerificationProviderChecksum attests a strong complete-object upload checksum.
	VFSVerificationProviderChecksum = "provider_checksum"
	// VFSVerificationCompleteReadback attests a complete independent object readback.
	VFSVerificationCompleteReadback = "complete_readback"
)

// VFSToken is one 256-bit bearer token attenuated by VFS actions, directory,
// driver, expiry, and the current inherited ACL.
type VFSToken [vfsTokenBytes]byte

// ParseVFSToken decodes the base64url bearer returned by VFS bootstrap or token issuance.
func ParseVFSToken(encoded string) (VFSToken, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != vfsTokenBytes {
		return VFSToken{}, fmt.Errorf("%w: VFS token must encode exactly 32 bytes", ErrInvalidControlPlane)
	}

	var token VFSToken
	copy(token[:], decoded)

	if allZeroBytes(token[:]) {
		return VFSToken{}, fmt.Errorf("%w: VFS token must not be zero", ErrInvalidControlPlane)
	}

	return token, nil
}

// Clear overwrites this token instance after its client is no longer used.
func (token *VFSToken) Clear() {
	if token != nil {
		clear(token[:])
	}
}

// Encode returns this token's base64url bearer form. It returns an empty
// string after the token has been cleared.
func (token *VFSToken) Encode() string {
	if token == nil || allZeroBytes(token[:]) {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(token[:])
}

// VFSControlClient accesses VFS metadata and short-lived grant APIs. Payload
// bytes still flow directly between the caller and a compiled driver.
type VFSControlClient struct {
	control *ControlClient
}

// NewVFSControlClient validates the endpoint and copies the VFS bearer token.
// Plain HTTP is accepted only for an explicit loopback test endpoint.
func NewVFSControlClient(
	endpoint string,
	token VFSToken,
	httpClient *http.Client,
) (*VFSControlClient, error) {
	control, err := NewControlClient(endpoint, ClientToken(token), httpClient)
	if err != nil {
		return nil, err
	}

	return &VFSControlClient{control: control}, nil
}

// Clear overwrites the client's private bearer copy. The client must not be
// used after this call.
func (client *VFSControlClient) Clear() {
	if client == nil || client.control == nil {
		return
	}

	client.control.token.Clear()
}

// CheckCompatibility performs the mandatory preflight before a transfer pipeline.
func (client *VFSControlClient) CheckCompatibility(ctx context.Context) (ProtocolCompatibility, error) {
	if client == nil || client.control == nil {
		return ProtocolCompatibility{}, fmt.Errorf("%w: VFS control client is not initialized", ErrInvalidControlPlane)
	}

	return client.control.CheckCompatibility(ctx)
}

// PrepareVFSPutRequest fixes one plaintext identity and optimistic VFS entry precondition.
type PrepareVFSPutRequest struct {
	DirectoryID            string  `json:"directory_id"`
	EntryName              string  `json:"entry_name"`
	ExpectedEntryRevision  uint64  `json:"expected_entry_revision"`
	PlaintextBytes         uint64  `json:"plaintext_bytes"`
	VerificationBlockBytes uint64  `json:"verification_block_bytes"`
	VerificationBlockCount uint64  `json:"verification_block_count"`
	FileRoot               string  `json:"file_root"`
	MetadataRoot           string  `json:"metadata_root"`
	BlockManifestSHA256    string  `json:"block_manifest_sha256"`
	BlockManifestBytes     uint64  `json:"block_manifest_bytes"`
	EncryptionFrameBytes   uint64  `json:"encryption_frame_bytes"`
	PreferredDriverID      *string `json:"preferred_driver_id"`
	IdempotencyKey         string  `json:"idempotency_key"`
}

// VFSPutPreparation is an immutable, expiring allocation for one complete-object upload.
type VFSPutPreparation struct {
	Schema                string `json:"schema"`
	IntentID              string `json:"intent_id"`
	FilesystemID          string `json:"filesystem_id"`
	DirectoryID           string `json:"directory_id"`
	EntryName             string `json:"entry_name"`
	ExpectedEntryRevision uint64 `json:"expected_entry_revision"`
	FileID                string `json:"file_id"`
	VersionID             string `json:"version_id"`
	LocationID            string `json:"location_id"`
	DriverID              string `json:"driver_id"`
	StorageKey            string `json:"storage_key"`
	BlockManifestR2Key    string `json:"block_manifest_r2_key"`
	CryptoSuite           string `json:"crypto_suite"`
	KeyEpoch              uint64 `json:"key_epoch"`
	EncryptionFrameBytes  uint64 `json:"encryption_frame_bytes"`
	RequiresEncryptionKey bool   `json:"requires_encryption_key"`
	State                 string `json:"state"`
	ExpiresAt             uint64 `json:"expires_at"`
}

// VFSDirectoryKeyGrant contains one in-memory directory epoch key. Call Clear
// immediately after constructing the immutable file cipher.
type VFSDirectoryKeyGrant struct {
	IntentID    string
	DirectoryID string
	VersionID   string
	CryptoSuite string
	KeyEpoch    uint64
	Key         *cryptofile.DirectoryKey
	ExpiresAt   uint64
}

// Clear overwrites and releases the granted directory secret.
func (grant *VFSDirectoryKeyGrant) Clear() {
	if grant == nil || grant.Key == nil {
		return
	}

	grant.Key.Clear()
	grant.Key = nil
}

// VFSDriverGrant contains one authorized compiled-driver instance. Credential
// JSON is held in memory only and must never be written to a transfer journal.
type VFSDriverGrant struct {
	IntentID  string
	Instance  driver.Instance
	ExpiresAt uint64
}

// Clear overwrites the transient credential and configuration copies.
func (grant *VFSDriverGrant) Clear() {
	if grant == nil {
		return
	}

	clear(grant.Instance.Config)
	clear(grant.Instance.Credential)
	grant.Instance.Config = nil
	grant.Instance.Credential = nil
}

// VFSBlockManifestStage identifies one immutable integrity manifest in control-plane R2.
type VFSBlockManifestStage struct {
	Schema    string `json:"schema"`
	IntentID  string `json:"intent_id"`
	SHA256    string `json:"sha256"`
	Bytes     uint64 `json:"bytes"`
	R2Key     string `json:"r2_key"`
	R2Version string `json:"r2_version"`
}

// CommitVFSPutRequest provides independently verified complete-object evidence.
type CommitVFSPutRequest struct {
	BlockManifestR2Version string  `json:"block_manifest_r2_version"`
	EncodedBytes           uint64  `json:"encoded_bytes"`
	EncodedSHA256          string  `json:"encoded_sha256"`
	VerificationMethod     string  `json:"verification_method"`
	NativeID               *string `json:"native_id"`
	ProviderVersion        *string `json:"provider_version"`
	ETag                   *string `json:"etag"`
}

// VFSPutReceipt is the durable publication identity returned by an idempotent commit.
type VFSPutReceipt struct {
	Schema                 string  `json:"schema"`
	IntentID               string  `json:"intent_id"`
	FileID                 string  `json:"file_id"`
	VersionID              string  `json:"version_id"`
	LocationID             string  `json:"location_id"`
	DriverID               string  `json:"driver_id"`
	StorageKey             string  `json:"storage_key"`
	BlockManifestR2Version string  `json:"block_manifest_r2_version"`
	EncodedBytes           uint64  `json:"encoded_bytes"`
	EncodedSHA256          string  `json:"encoded_sha256"`
	VerificationMethod     string  `json:"verification_method"`
	NativeID               *string `json:"native_id"`
	ProviderVersion        *string `json:"provider_version"`
	ETag                   *string `json:"etag"`
	EntryRevision          uint64  `json:"entry_revision"`
	CatalogRevisionID      uint64  `json:"catalog_revision_id"`
	CommittedAt            uint64  `json:"committed_at"`
	State                  string  `json:"state"`
}

type vfsKeyGrantWire struct {
	Schema       string  `json:"schema"`
	IntentID     string  `json:"intent_id"`
	DirectoryID  string  `json:"directory_id"`
	VersionID    string  `json:"version_id"`
	CryptoSuite  string  `json:"crypto_suite"`
	KeyEpoch     uint64  `json:"key_epoch"`
	DirectoryKey *string `json:"directory_key"`
	ExpiresAt    uint64  `json:"expires_at"`
}

type vfsDriverGrantWire struct {
	Schema         string           `json:"schema"`
	IntentID       string           `json:"intent_id"`
	DriverID       string           `json:"driver_id"`
	DriverKind     driver.Kind      `json:"driver_kind"`
	DriverRevision uint64           `json:"driver_revision"`
	Config         json.RawMessage  `json:"config"`
	Credential     *json.RawMessage `json:"credential"`
	ExpiresAt      uint64           `json:"expires_at"`
}

// PreparePut creates or replays one immutable VFS Put intent.
func (client *VFSControlClient) PreparePut(
	ctx context.Context,
	requested PrepareVFSPutRequest,
) (VFSPutPreparation, error) {
	if !validPrepareVFSPutRequest(requested) {
		return VFSPutPreparation{}, fmt.Errorf("%w: invalid VFS Put preparation", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return VFSPutPreparation{}, fmt.Errorf("marshal VFS Put preparation: %w", err)
	}

	var response VFSPutPreparation
	if err := client.postJSON(ctx, "/api/v2/puts/prepare", body, &response); err != nil {
		return VFSPutPreparation{}, err
	}

	if !validVFSPutPreparation(response, requested) {
		return VFSPutPreparation{}, fmt.Errorf("%w: VFS Put preparation identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// GrantPutKey returns the current authorized directory key for one Put intent.
func (client *VFSControlClient) GrantPutKey(
	ctx context.Context,
	preparation VFSPutPreparation,
) (VFSDirectoryKeyGrant, error) {
	if !validIdentifier(preparation.IntentID) {
		return VFSDirectoryKeyGrant{}, fmt.Errorf("%w: invalid VFS Put intent", ErrInvalidControlPlane)
	}

	var wire vfsKeyGrantWire

	path := "/api/v2/puts/" + preparation.IntentID + "/key-grant"
	if err := client.postJSON(ctx, path, nil, &wire); err != nil {
		return VFSDirectoryKeyGrant{}, err
	}

	if wire.Schema != "carrack.vfs.directory-key-grant.v1" ||
		wire.IntentID != preparation.IntentID || wire.DirectoryID != preparation.DirectoryID ||
		wire.VersionID != preparation.VersionID || wire.CryptoSuite != preparation.CryptoSuite ||
		wire.KeyEpoch != preparation.KeyEpoch || wire.ExpiresAt == 0 {
		return VFSDirectoryKeyGrant{}, fmt.Errorf("%w: VFS directory-key grant identity changed", ErrControlPlaneResponse)
	}

	grant := VFSDirectoryKeyGrant{
		IntentID: wire.IntentID, DirectoryID: wire.DirectoryID, VersionID: wire.VersionID,
		CryptoSuite: wire.CryptoSuite, KeyEpoch: wire.KeyEpoch, ExpiresAt: wire.ExpiresAt,
	}
	switch wire.CryptoSuite {
	case VFSPlaintextSuite:
		if wire.DirectoryKey != nil {
			return VFSDirectoryKeyGrant{}, fmt.Errorf("%w: plaintext grant exposed a directory key", ErrControlPlaneResponse)
		}
	case VFSEncryptedSuite:
		if wire.DirectoryKey == nil {
			return VFSDirectoryKeyGrant{}, fmt.Errorf("%w: encrypted grant omitted its directory key", ErrControlPlaneResponse)
		}

		decoded, err := base64.RawURLEncoding.DecodeString(*wire.DirectoryKey)
		if err != nil || len(decoded) != 32 || allZeroBytes(decoded) {
			clear(decoded)
			return VFSDirectoryKeyGrant{}, fmt.Errorf("%w: invalid VFS directory key", ErrControlPlaneResponse)
		}

		key := cryptofile.DirectoryKey(decoded)
		clear(decoded)

		grant.Key = &key
	default:
		return VFSDirectoryKeyGrant{}, fmt.Errorf("%w: unsupported VFS crypto suite", ErrControlPlaneResponse)
	}

	return grant, nil
}

// GrantPutDriver returns one current driver configuration and transient credential grant.
func (client *VFSControlClient) GrantPutDriver(
	ctx context.Context,
	preparation VFSPutPreparation,
) (VFSDriverGrant, error) {
	if !validIdentifier(preparation.IntentID) {
		return VFSDriverGrant{}, fmt.Errorf("%w: invalid VFS Put intent", ErrInvalidControlPlane)
	}

	var wire vfsDriverGrantWire

	path := "/api/v2/puts/" + preparation.IntentID + "/driver-grant"
	if err := client.postJSON(ctx, path, nil, &wire); err != nil {
		return VFSDriverGrant{}, err
	}

	if wire.Schema != "carrack.vfs.driver-grant.v1" || wire.IntentID != preparation.IntentID ||
		wire.DriverID != preparation.DriverID || !validControlString(string(wire.DriverKind), 256) ||
		wire.DriverRevision == 0 || wire.ExpiresAt == 0 || !validJSONObjectWire(wire.Config) ||
		wire.Credential != nil && !validJSONObjectWire(*wire.Credential) {
		return VFSDriverGrant{}, fmt.Errorf("%w: invalid VFS driver grant", ErrControlPlaneResponse)
	}

	instance := driver.Instance{
		ID: wire.DriverID, Kind: wire.DriverKind, Revision: wire.DriverRevision,
		Config: bytes.Clone(wire.Config),
	}
	if wire.Credential != nil {
		instance.Credential = bytes.Clone(*wire.Credential)
	}

	return VFSDriverGrant{IntentID: wire.IntentID, Instance: instance, ExpiresAt: wire.ExpiresAt}, nil
}

// StagePutBlockManifest stores one canonical plaintext integrity manifest in R2.
func (client *VFSControlClient) StagePutBlockManifest(
	ctx context.Context,
	preparation VFSPutPreparation,
	manifest []byte,
) (VFSBlockManifestStage, error) {
	if !validIdentifier(preparation.IntentID) || len(manifest) == 0 {
		return VFSBlockManifestStage{}, fmt.Errorf("%w: invalid VFS block-manifest stage", ErrInvalidControlPlane)
	}

	var response VFSBlockManifestStage

	path := "/api/v2/puts/" + preparation.IntentID + "/block-manifest"
	if err := client.postBinary(ctx, path, manifest, &response); err != nil {
		return VFSBlockManifestStage{}, err
	}

	digest := sha256.Sum256(manifest)
	if response.Schema != "carrack.vfs.block-manifest-stage.v1" ||
		response.IntentID != preparation.IntentID || response.SHA256 != hex.EncodeToString(digest[:]) ||
		response.Bytes != uint64(len(manifest)) || response.R2Key != preparation.BlockManifestR2Key ||
		!validControlString(response.R2Version, 1_024) {
		return VFSBlockManifestStage{}, fmt.Errorf("%w: VFS block-manifest stage identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

// CommitPut atomically publishes one already verified complete provider object.
func (client *VFSControlClient) CommitPut(
	ctx context.Context,
	preparation VFSPutPreparation,
	requested CommitVFSPutRequest,
) (VFSPutReceipt, error) {
	if !validIdentifier(preparation.IntentID) || !validCommitVFSPutRequest(requested) {
		return VFSPutReceipt{}, fmt.Errorf("%w: invalid VFS Put commit", ErrInvalidControlPlane)
	}

	body, err := json.Marshal(requested)
	if err != nil {
		return VFSPutReceipt{}, fmt.Errorf("marshal VFS Put commit: %w", err)
	}

	var response VFSPutReceipt

	path := "/api/v2/puts/" + preparation.IntentID + "/commit"
	if err := client.postJSON(ctx, path, body, &response); err != nil {
		return VFSPutReceipt{}, err
	}

	if !validVFSPutReceipt(response, preparation, requested) {
		return VFSPutReceipt{}, fmt.Errorf("%w: VFS Put receipt identity changed", ErrControlPlaneResponse)
	}

	return response, nil
}

func (client *VFSControlClient) postJSON(ctx context.Context, path string, body []byte, destination any) error {
	if client == nil || client.control == nil {
		return fmt.Errorf("%w: VFS control client is not initialized", ErrInvalidControlPlane)
	}

	return client.control.authenticatedPost(ctx, path, body, destination)
}

func (client *VFSControlClient) postBinary(ctx context.Context, path string, body []byte, destination any) error {
	if client == nil || client.control == nil {
		return fmt.Errorf("%w: VFS control client is not initialized", ErrInvalidControlPlane)
	}

	return client.control.authenticatedBinaryPost(ctx, path, body, destination)
}

func validPrepareVFSPutRequest(request PrepareVFSPutRequest) bool {
	expectedBlocks := uint64(0)
	if request.PlaintextBytes > 0 && request.VerificationBlockBytes > 0 {
		expectedBlocks = 1 + (request.PlaintextBytes-1)/request.VerificationBlockBytes
	}

	return allVFSChecks(
		validIdentifier(request.DirectoryID),
		validVFSName(request.EntryName),
		request.ExpectedEntryRevision < math.MaxInt64,
		request.PlaintextBytes <= math.MaxInt64,
		request.VerificationBlockBytes > 0,
		request.VerificationBlockBytes <= math.MaxInt64,
		request.VerificationBlockCount == expectedBlocks,
		request.VerificationBlockCount <= 1_000_000,
		validDigest(request.FileRoot),
		validDigest(request.MetadataRoot),
		validDigest(request.BlockManifestSHA256),
		request.BlockManifestBytes > 0,
		request.BlockManifestBytes <= math.MaxInt64,
		request.EncryptionFrameBytes > 0,
		request.EncryptionFrameBytes <= request.VerificationBlockBytes,
		request.VerificationBlockBytes%request.EncryptionFrameBytes == 0,
		request.EncryptionFrameBytes <= math.MaxInt64,
		request.PreferredDriverID == nil || validControlString(*request.PreferredDriverID, 256),
		validControlString(request.IdempotencyKey, 256),
	)
}

func validVFSPutPreparation(response VFSPutPreparation, requested PrepareVFSPutRequest) bool {
	return allVFSChecks(
		response.Schema == "carrack.vfs.put-preparation.v1",
		validIdentifier(response.IntentID),
		validIdentifier(response.FilesystemID),
		response.DirectoryID == requested.DirectoryID,
		response.EntryName == requested.EntryName,
		response.ExpectedEntryRevision == requested.ExpectedEntryRevision,
		validIdentifier(response.FileID),
		validIdentifier(response.VersionID),
		validIdentifier(response.LocationID),
		validControlString(response.DriverID, 256),
		validControlString(response.StorageKey, 4_096),
		validControlString(response.BlockManifestR2Key, 4_096),
		response.CryptoSuite == VFSPlaintextSuite || response.CryptoSuite == VFSEncryptedSuite,
		response.KeyEpoch > 0,
		response.EncryptionFrameBytes == requested.EncryptionFrameBytes,
		response.RequiresEncryptionKey == (response.CryptoSuite != VFSPlaintextSuite),
		response.State == "prepared" || response.State == vfsCommittedState,
		response.ExpiresAt > 0,
		requested.PreferredDriverID == nil || response.DriverID == *requested.PreferredDriverID,
	)
}

func validCommitVFSPutRequest(request CommitVFSPutRequest) bool {
	return validControlString(request.BlockManifestR2Version, 1_024) && request.EncodedBytes <= math.MaxInt64 &&
		validDigest(request.EncodedSHA256) &&
		(request.VerificationMethod == VFSVerificationProviderChecksum ||
			request.VerificationMethod == VFSVerificationCompleteReadback) &&
		validOptionalControlString(request.NativeID, 1_024) &&
		validOptionalControlString(request.ProviderVersion, 1_024) && validOptionalControlString(request.ETag, 1_024)
}

func validVFSPutReceipt(
	response VFSPutReceipt,
	preparation VFSPutPreparation,
	requested CommitVFSPutRequest,
) bool {
	return response.Schema == "carrack.vfs.put-receipt.v1" && response.IntentID == preparation.IntentID &&
		response.FileID == preparation.FileID && response.VersionID == preparation.VersionID &&
		response.LocationID == preparation.LocationID && response.DriverID == preparation.DriverID &&
		response.StorageKey == preparation.StorageKey &&
		response.BlockManifestR2Version == requested.BlockManifestR2Version &&
		response.EncodedBytes == requested.EncodedBytes && response.EncodedSHA256 == requested.EncodedSHA256 &&
		response.VerificationMethod == requested.VerificationMethod &&
		optionalControlStringEqual(response.NativeID, requested.NativeID) &&
		optionalControlStringEqual(response.ProviderVersion, requested.ProviderVersion) &&
		optionalControlStringEqual(response.ETag, requested.ETag) && response.EntryRevision > 0 &&
		response.CatalogRevisionID > 0 && response.CommittedAt > 0 && response.State == vfsCommittedState
}

func validIdentifier(value string) bool {
	return validControlHex(value, 32) && value != strings.Repeat("0", 32)
}

func validDigest(value string) bool {
	return validControlHex(value, 64) && value != strings.Repeat("0", 64)
}

func validVFSName(value string) bool {
	return validControlString(value, 255) && value != "." && value != ".." &&
		utf8.ValidString(value) && norm.NFC.IsNormalString(value) && !strings.ContainsAny(value, "/\x00")
}

func validJSONObjectWire(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))

	var value map[string]json.RawMessage
	if err := decoder.Decode(&value); err != nil || value == nil {
		return false
	}

	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}

func allVFSChecks(checks ...bool) bool {
	for _, valid := range checks {
		if !valid {
			return false
		}
	}

	return true
}
