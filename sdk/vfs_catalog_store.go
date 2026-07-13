package sdk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/dravengarden/carrack/vfs/merkle"
)

const (
	vfsCatalogNodeSchema           = "carrack.vfs.catalog-node.v1"
	vfsCatalogEnvelopeSchema       = "carrack.vfs.catalog-node-envelope.v1"
	vfsCatalogNodesDirectory       = "nodes"
	vfsCatalogTemporaryPrefix      = ".catalog-node-"
	maximumVFSCatalogNodeBytes     = int64(512 << 20)
	vfsCatalogPrivateFileMode      = fs.FileMode(0o600)
	vfsCatalogPrivateDirectoryMode = fs.FileMode(0o700)
)

var (
	// ErrInvalidVFSCatalogStore indicates an unsafe path or uninitialized store.
	ErrInvalidVFSCatalogStore = errors.New("invalid Carrack VFS catalog store")
	// ErrVFSCatalogNodeNotFound indicates that one verified DAG node is not cached.
	ErrVFSCatalogNodeNotFound = errors.New("carrack VFS catalog node is not cached")
	// ErrVFSCatalogCorrupt indicates a malformed, altered, or root-inconsistent node.
	ErrVFSCatalogCorrupt      = errors.New("corrupt Carrack VFS catalog")
	errVFSCatalogTrailingJSON = errors.New("trailing JSON value")
	errVFSCatalogStableID     = errors.New("stable identity is missing")
	errVFSCatalogDirectory    = errors.New("directory entry contains file fields")
	errVFSCatalogFile         = errors.New("file entry is incomplete")
)

// VFSCatalogEntry is the content-committed subset of one directory entry.
// Mutable timestamps and row revisions are deliberately excluded because the
// directory Merkle root does not authenticate them.
type VFSCatalogEntry struct {
	Name             string  `json:"name"`
	Kind             string  `json:"kind"`
	FileID           *string `json:"file_id"`
	VersionID        *string `json:"version_id"`
	ChildDirectoryID *string `json:"child_directory_id"`
	SizeBytes        uint64  `json:"size_bytes"`
	DataRoot         string  `json:"data_root"`
	MetadataRoot     *string `json:"metadata_root"`
}

// VFSCatalogNode is one complete, independently verifiable directory in the
// local metadata DAG. DirectoryID plus DataRoot is its immutable cache key.
type VFSCatalogNode struct {
	Schema      string            `json:"schema"`
	DirectoryID string            `json:"directory_id"`
	DataRoot    string            `json:"data_root"`
	Entries     []VFSCatalogEntry `json:"entries"`
}

type vfsCatalogEnvelope struct {
	Schema  string          `json:"schema"`
	SHA256  string          `json:"sha256"`
	Payload json.RawMessage `json:"payload"`
}

// VFSCatalogStore owns content-addressed metadata nodes beneath one private
// local directory. It never persists bearer tokens, directory keys, provider
// credentials, or payload bytes.
type VFSCatalogStore struct {
	rootPath     string
	rootIdentity fs.FileInfo
}

// NewVFSCatalogStore creates or validates a canonical absolute private cache.
func NewVFSCatalogStore(rootPath string) (*VFSCatalogStore, error) {
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) != rootPath {
		return nil, fmt.Errorf("%w: root must be a canonical absolute path", ErrInvalidVFSCatalogStore)
	}

	if err := os.MkdirAll(rootPath, vfsCatalogPrivateDirectoryMode); err != nil {
		return nil, fmt.Errorf("%w: create root: %w", ErrInvalidVFSCatalogStore, err)
	}

	information, err := os.Lstat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect root: %w", ErrInvalidVFSCatalogStore, err)
	}

	if !privateRealDirectory(information) {
		return nil, fmt.Errorf("%w: root must be a private real directory", ErrInvalidVFSCatalogStore)
	}

	store := &VFSCatalogStore{rootPath: rootPath, rootIdentity: information}

	root, err := store.openRoot()
	if err != nil {
		return nil, err
	}

	ensureErr := ensureVFSCatalogDirectory(root, vfsCatalogNodesDirectory)

	closeErr := root.Close()
	if ensureErr != nil || closeErr != nil {
		return nil, errors.Join(ensureErr, closeErr)
	}

	return store, nil
}

// Directory returns the canonical private cache root.
func (store *VFSCatalogStore) Directory() string {
	if store == nil {
		return ""
	}

	return store.rootPath
}

// Load reads and revalidates one node by its expected directory identity and
// Merkle root. Missing nodes are reported with ErrVFSCatalogNodeNotFound;
// malformed existing nodes never degrade to a cache miss.
func (store *VFSCatalogStore) Load(directoryID, dataRoot string) (VFSCatalogNode, error) {
	storagePath, err := vfsCatalogNodePath(directoryID, dataRoot)
	if err != nil {
		return VFSCatalogNode{}, err
	}

	root, err := store.openRoot()
	if err != nil {
		return VFSCatalogNode{}, err
	}

	node, loadErr := loadVFSCatalogNode(root, storagePath, directoryID, dataRoot)

	closeErr := root.Close()
	if loadErr != nil || closeErr != nil {
		return VFSCatalogNode{}, errors.Join(loadErr, closeErr)
	}

	return node, nil
}

// Save durably publishes one verified immutable node. An existing exact node
// is accepted; an existing different or corrupt node is a hard error.
func (store *VFSCatalogStore) Save(node VFSCatalogNode) error {
	if err := validateVFSCatalogNode(node, node.DirectoryID, node.DataRoot); err != nil {
		return err
	}

	storagePath, err := vfsCatalogNodePath(node.DirectoryID, node.DataRoot)
	if err != nil {
		return err
	}

	encoded, err := encodeVFSCatalogNode(node)
	if err != nil {
		return err
	}

	if int64(len(encoded)) > maximumVFSCatalogNodeBytes {
		return fmt.Errorf("%w: encoded node exceeds size limit", ErrInvalidVFSCatalogStore)
	}

	root, err := store.openRoot()
	if err != nil {
		return err
	}

	saveErr := saveVFSCatalogNode(root, storagePath, encoded, node)
	closeErr := root.Close()

	return errors.Join(saveErr, closeErr)
}

func (store *VFSCatalogStore) openRoot() (*os.Root, error) {
	if store == nil || store.rootPath == "" || store.rootIdentity == nil {
		return nil, fmt.Errorf("%w: store is not initialized", ErrInvalidVFSCatalogStore)
	}

	current, err := os.Lstat(store.rootPath)
	if err != nil || !privateRealDirectory(current) || !os.SameFile(store.rootIdentity, current) {
		return nil, fmt.Errorf("%w: root identity changed", ErrInvalidVFSCatalogStore)
	}

	root, err := os.OpenRoot(store.rootPath)
	if err != nil {
		return nil, fmt.Errorf("%w: open root: %w", ErrInvalidVFSCatalogStore, err)
	}

	return root, nil
}

func privateRealDirectory(information fs.FileInfo) bool {
	return information != nil && information.IsDir() && information.Mode()&fs.ModeSymlink == 0 &&
		information.Mode().Perm()&0o077 == 0
}

func ensureVFSCatalogDirectory(root *os.Root, directory string) error {
	if err := root.Mkdir(directory, vfsCatalogPrivateDirectoryMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: create directory %q: %w", ErrInvalidVFSCatalogStore, directory, err)
	}

	information, err := root.Lstat(directory)
	if err != nil || !privateRealDirectory(information) {
		return fmt.Errorf("%w: directory %q is not private and real", ErrInvalidVFSCatalogStore, directory)
	}

	return nil
}

func vfsCatalogNodePath(directoryID, dataRoot string) (string, error) {
	if !validIdentifier(directoryID) || !validDigest(dataRoot) {
		return "", fmt.Errorf("%w: invalid node identity", ErrInvalidVFSCatalogStore)
	}

	return path.Join(
		vfsCatalogNodesDirectory,
		dataRoot[:2],
		directoryID+"-"+dataRoot+".json",
	), nil
}

func saveVFSCatalogNode(
	root *os.Root,
	storagePath string,
	encoded []byte,
	node VFSCatalogNode,
) error {
	shard := path.Dir(storagePath)
	if err := ensureVFSCatalogDirectory(root, shard); err != nil {
		return err
	}

	temporaryPath, err := writeTemporaryVFSCatalogNode(root, shard, encoded)
	if err != nil {
		return err
	}

	if err := root.Link(temporaryPath, storagePath); err != nil {
		removeErr := root.Remove(temporaryPath)
		if !errors.Is(err, fs.ErrExist) {
			return errors.Join(
				fmt.Errorf("%w: publish node: %w", ErrInvalidVFSCatalogStore, err),
				removeErr,
			)
		}

		existing, loadErr := loadVFSCatalogNode(
			root,
			storagePath,
			node.DirectoryID,
			node.DataRoot,
		)
		if loadErr != nil || !equalVFSCatalogNodes(existing, node) {
			return errors.Join(
				fmt.Errorf("%w: existing node differs", ErrVFSCatalogCorrupt),
				loadErr,
				removeErr,
			)
		}

		if removeErr != nil {
			return fmt.Errorf("%w: remove temporary node: %w", ErrInvalidVFSCatalogStore, removeErr)
		}

		return nil
	}

	if err := syncVFSCatalogDirectory(root, shard); err != nil {
		return err
	}

	removeErr := root.Remove(temporaryPath)
	syncErr := syncVFSCatalogDirectory(root, shard)

	return errors.Join(removeErr, syncErr)
}

func writeTemporaryVFSCatalogNode(root *os.Root, shard string, encoded []byte) (string, error) {
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("%w: generate temporary identity: %w", ErrInvalidVFSCatalogStore, err)
	}

	temporaryPath := path.Join(shard, vfsCatalogTemporaryPrefix+hex.EncodeToString(nonce[:]))

	file, err := root.OpenFile(
		temporaryPath,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		vfsCatalogPrivateFileMode,
	)
	if err != nil {
		return "", fmt.Errorf("%w: create temporary node: %w", ErrInvalidVFSCatalogStore, err)
	}

	if _, err := file.Write(encoded); err != nil {
		closeErr := file.Close()
		removeErr := root.Remove(temporaryPath)

		return "", errors.Join(
			fmt.Errorf("%w: write temporary node: %w", ErrInvalidVFSCatalogStore, err),
			closeErr,
			removeErr,
		)
	}

	syncErr := file.Sync()

	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		removeErr := root.Remove(temporaryPath)

		return "", errors.Join(
			fmt.Errorf("%w: persist temporary node", ErrInvalidVFSCatalogStore),
			syncErr,
			closeErr,
			removeErr,
		)
	}

	return temporaryPath, nil
}

func loadVFSCatalogNode(
	root *os.Root,
	storagePath,
	directoryID,
	dataRoot string,
) (VFSCatalogNode, error) {
	information, err := root.Lstat(storagePath)
	if errors.Is(err, fs.ErrNotExist) {
		return VFSCatalogNode{}, fmt.Errorf("%w: %s", ErrVFSCatalogNodeNotFound, storagePath)
	}

	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 ||
		information.Size() <= 0 || information.Size() > maximumVFSCatalogNodeBytes {
		return VFSCatalogNode{}, fmt.Errorf("%w: invalid node file %q", ErrVFSCatalogCorrupt, storagePath)
	}

	file, err := root.Open(storagePath)
	if err != nil {
		return VFSCatalogNode{}, fmt.Errorf("%w: open node %q: %w", ErrVFSCatalogCorrupt, storagePath, err)
	}

	openedInformation, statErr := file.Stat()
	if statErr != nil || !openedInformation.Mode().IsRegular() || !os.SameFile(information, openedInformation) {
		closeErr := file.Close()

		return VFSCatalogNode{}, errors.Join(
			fmt.Errorf("%w: node identity changed", ErrVFSCatalogCorrupt),
			statErr,
			closeErr,
		)
	}

	encoded, readErr := io.ReadAll(io.LimitReader(file, maximumVFSCatalogNodeBytes+1))

	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(encoded)) > maximumVFSCatalogNodeBytes {
		return VFSCatalogNode{}, errors.Join(
			fmt.Errorf("%w: read node %q", ErrVFSCatalogCorrupt, storagePath),
			readErr,
			closeErr,
		)
	}

	return decodeVFSCatalogNode(encoded, directoryID, dataRoot)
}

func encodeVFSCatalogNode(node VFSCatalogNode) ([]byte, error) {
	payload, err := json.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("encode VFS catalog node: %w", err)
	}

	digest := sha256.Sum256(payload)
	envelope := vfsCatalogEnvelope{
		Schema:  vfsCatalogEnvelopeSchema,
		SHA256:  hex.EncodeToString(digest[:]),
		Payload: payload,
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode VFS catalog envelope: %w", err)
	}

	return append(encoded, '\n'), nil
}

func decodeVFSCatalogNode(encoded []byte, directoryID, dataRoot string) (VFSCatalogNode, error) {
	var envelope vfsCatalogEnvelope
	if err := decodeStrictVFSCatalogJSON(encoded, &envelope); err != nil {
		return VFSCatalogNode{}, fmt.Errorf("%w: decode envelope: %w", ErrVFSCatalogCorrupt, err)
	}

	digest := sha256.Sum256(envelope.Payload)
	if envelope.Schema != vfsCatalogEnvelopeSchema ||
		envelope.SHA256 != hex.EncodeToString(digest[:]) {
		return VFSCatalogNode{}, fmt.Errorf("%w: envelope digest differs", ErrVFSCatalogCorrupt)
	}

	var node VFSCatalogNode
	if err := decodeStrictVFSCatalogJSON(envelope.Payload, &node); err != nil {
		return VFSCatalogNode{}, fmt.Errorf("%w: decode node: %w", ErrVFSCatalogCorrupt, err)
	}

	canonical, err := json.Marshal(node)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) {
		return VFSCatalogNode{}, errors.Join(
			fmt.Errorf("%w: node encoding is not canonical", ErrVFSCatalogCorrupt),
			err,
		)
	}

	if err := validateVFSCatalogNode(node, directoryID, dataRoot); err != nil {
		return VFSCatalogNode{}, err
	}

	return node, nil
}

func decodeStrictVFSCatalogJSON(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}

	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errVFSCatalogTrailingJSON
	}

	return nil
}

func validateVFSCatalogNode(node VFSCatalogNode, directoryID, dataRoot string) error {
	if node.Schema != vfsCatalogNodeSchema || node.DirectoryID != directoryID ||
		node.DataRoot != dataRoot || !validIdentifier(directoryID) || !validDigest(dataRoot) ||
		len(node.Entries) > merkle.MaximumDirectoryEntries {
		return fmt.Errorf("%w: invalid node identity", ErrVFSCatalogCorrupt)
	}

	entries := make([]merkle.DirectoryEntry, len(node.Entries))
	for index, entry := range node.Entries {
		if index > 0 && node.Entries[index-1].Name >= entry.Name {
			return fmt.Errorf("%w: entries are not canonical", ErrVFSCatalogCorrupt)
		}

		converted, err := vfsCatalogMerkleEntry(entry)
		if err != nil {
			return fmt.Errorf("%w: entry %d: %w", ErrVFSCatalogCorrupt, index, err)
		}

		entries[index] = converted
	}

	tree, err := merkle.BuildDirectory(entries)
	if err != nil || tree.Root.String() != dataRoot {
		return errors.Join(
			fmt.Errorf("%w: directory Merkle root differs", ErrVFSCatalogCorrupt),
			err,
		)
	}

	return nil
}

func vfsCatalogMerkleEntry(entry VFSCatalogEntry) (merkle.DirectoryEntry, error) {
	stableID := entry.FileID
	kind := merkle.EntryFile

	if entry.Kind == vfsEntryKindDirectory {
		stableID = entry.ChildDirectoryID
		kind = merkle.EntryDirectory
	}

	if stableID == nil {
		return merkle.DirectoryEntry{}, errVFSCatalogStableID
	}

	parsedStableID, err := merkle.ParseIdentifier(*stableID)
	if err != nil {
		return merkle.DirectoryEntry{}, fmt.Errorf("parse stable ID: %w", err)
	}

	parsedDataRoot, err := merkle.ParseDigest(entry.DataRoot)
	if err != nil {
		return merkle.DirectoryEntry{}, fmt.Errorf("parse data root: %w", err)
	}

	converted := merkle.DirectoryEntry{
		Name:      entry.Name,
		Kind:      kind,
		StableID:  parsedStableID,
		SizeBytes: entry.SizeBytes,
		DataRoot:  parsedDataRoot,
	}
	if kind == merkle.EntryDirectory {
		if entry.Kind != vfsEntryKindDirectory || entry.FileID != nil || entry.VersionID != nil ||
			entry.MetadataRoot != nil ||
			entry.ChildDirectoryID == nil || entry.SizeBytes != 0 {
			return merkle.DirectoryEntry{}, errVFSCatalogDirectory
		}

		return converted, nil
	}

	if entry.Kind != vfsEntryKindFile || entry.FileID == nil || entry.VersionID == nil || entry.ChildDirectoryID != nil ||
		entry.MetadataRoot == nil {
		return merkle.DirectoryEntry{}, errVFSCatalogFile
	}

	converted.VersionID, err = merkle.ParseIdentifier(*entry.VersionID)
	if err != nil {
		return merkle.DirectoryEntry{}, fmt.Errorf("parse version ID: %w", err)
	}

	converted.MetadataRoot, err = merkle.ParseDigest(*entry.MetadataRoot)
	if err != nil {
		return merkle.DirectoryEntry{}, fmt.Errorf("parse metadata root: %w", err)
	}

	return converted, nil
}

func equalVFSCatalogNodes(left, right VFSCatalogNode) bool {
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)

	return leftErr == nil && rightErr == nil && slices.Equal(leftEncoded, rightEncoded)
}

func syncVFSCatalogDirectory(root *os.Root, directoryPath string) error {
	directory, err := root.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("%w: open directory for sync: %w", ErrInvalidVFSCatalogStore, err)
	}

	syncErr := directory.Sync()
	closeErr := directory.Close()

	return errors.Join(syncErr, closeErr)
}
