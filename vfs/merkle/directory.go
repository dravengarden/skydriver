package merkle

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	directoryFileEntryDomain  = "carrack.vfs.directory.file-entry.v1"
	directoryChildEntryDomain = "carrack.vfs.directory.child-entry.v1"
	directoryEmptyDomain      = "carrack.vfs.directory.empty.v1"
	directoryNodeDomain       = "carrack.vfs.directory.node.v1"
	directoryRootDomain       = "carrack.vfs.directory.root.v1"
	emptyMetadataDomain       = "carrack.vfs.metadata.empty.v1"

	// MaximumNameBytes keeps one canonical component portable across ordinary
	// local filesystems. It counts normalized UTF-8 bytes, not code points.
	MaximumNameBytes = 255
	// MaximumDirectoryEntries bounds one materialized collection and tree build.
	MaximumDirectoryEntries = 1_000_000
)

// EntryKind is the canonical directory-entry union discriminator.
type EntryKind uint8 //nolint:recvcheck // Text unmarshaling necessarily uses a pointer receiver.

const (
	// EntryFile references one stable file and immutable current version.
	EntryFile EntryKind = 1
	// EntryDirectory references one child directory data root.
	EntryDirectory EntryKind = 2
)

// String returns the stable API spelling.
func (kind EntryKind) String() string {
	switch kind {
	case EntryFile:
		return "file"
	case EntryDirectory:
		return "directory"
	default:
		return fmt.Sprintf("unknown(%d)", kind)
	}
}

// MarshalText implements encoding.TextMarshaler.
func (kind EntryKind) MarshalText() ([]byte, error) {
	switch kind {
	case EntryFile, EntryDirectory:
		return []byte(kind.String()), nil
	default:
		return nil, fmt.Errorf("%w: unknown entry kind %d", ErrInvalidDirectory, kind)
	}
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (kind *EntryKind) UnmarshalText(encoded []byte) error {
	if kind == nil {
		return fmt.Errorf("%w: nil entry kind destination", ErrInvalidDirectory)
	}

	switch string(encoded) {
	case "file":
		*kind = EntryFile
	case "directory":
		*kind = EntryDirectory
	default:
		return fmt.Errorf("%w: unknown entry kind %q", ErrInvalidDirectory, encoded)
	}

	return nil
}

// DirectoryEntry is one canonical content-tree entry. StableID is a file ID
// for EntryFile and a directory ID for EntryDirectory. VersionID, SizeBytes,
// and MetadataRoot are file-only fields and must be zero for child directories.
type DirectoryEntry struct {
	Name         string     `json:"name"`
	Kind         EntryKind  `json:"kind"`
	StableID     Identifier `json:"stable_id"`
	VersionID    Identifier `json:"version_id,omitzero"`
	SizeBytes    uint64     `json:"size_bytes,omitempty"`
	DataRoot     Digest     `json:"data_root"`
	MetadataRoot Digest     `json:"metadata_root,omitzero"`
}

// HashedDirectoryEntry pairs one sorted canonical entry with its leaf digest.
type HashedDirectoryEntry struct {
	Entry  DirectoryEntry `json:"entry"`
	Digest Digest         `json:"digest"`
}

// DirectoryTree is a bytewise-name-sorted canonical content tree.
type DirectoryTree struct {
	Entries    []HashedDirectoryEntry `json:"entries"`
	TreeDigest Digest                 `json:"tree_digest"`
	Root       Digest                 `json:"root"`
}

// EmptyMetadataRoot is the V2 commitment for a file with no portable metadata
// fields. Future metadata schemas produce their own domain-separated digest.
func EmptyMetadataRoot() Digest {
	return hashEmpty(emptyMetadataDomain)
}

// BuildDirectory validates NFC names and entry unions, sorts a caller-owned
// copy by UTF-8 bytes, rejects duplicate names, and derives the content root.
func BuildDirectory(entries []DirectoryEntry) (DirectoryTree, error) {
	if len(entries) > MaximumDirectoryEntries {
		return DirectoryTree{}, fmt.Errorf("%w: entry count exceeds limit", ErrInvalidDirectory)
	}

	canonical := slices.Clone(entries)
	slices.SortFunc(canonical, func(left, right DirectoryEntry) int {
		return cmp.Compare(left.Name, right.Name)
	})

	hashed := make([]HashedDirectoryEntry, 0, len(canonical))
	leaves := make([]Digest, 0, len(canonical))

	for index, entry := range canonical {
		if err := entry.validate(); err != nil {
			return DirectoryTree{}, fmt.Errorf("%w: entry %d: %w", ErrInvalidDirectory, index, err)
		}

		if index != 0 && canonical[index-1].Name == entry.Name {
			return DirectoryTree{}, fmt.Errorf("%w: duplicate name %q", ErrInvalidDirectory, entry.Name)
		}

		digest := hashDirectoryEntry(entry)
		hashed = append(hashed, HashedDirectoryEntry{Entry: entry, Digest: digest})
		leaves = append(leaves, digest)
	}

	treeDigest := hashEmpty(directoryEmptyDomain)
	if len(leaves) != 0 {
		treeDigest = buildCanonicalTree(directoryNodeDomain, leaves, 0)
	}

	rootHasher := newDomainHasher(directoryRootDomain)
	writeUint64(rootHasher, uint64(len(leaves)))
	writeHash(rootHasher, treeDigest[:])

	return DirectoryTree{
		Entries:    hashed,
		TreeDigest: treeDigest,
		Root:       finishDigest(rootHasher),
	}, nil
}

func (entry DirectoryEntry) validate() error {
	if err := validateEntryName(entry.Name); err != nil {
		return err
	}

	if entry.StableID.IsZero() || entry.DataRoot.IsZero() {
		return fmt.Errorf("%w: stable ID and data root are required", ErrInvalidDirectory)
	}

	switch entry.Kind {
	case EntryFile:
		if entry.VersionID.IsZero() || entry.MetadataRoot.IsZero() {
			return fmt.Errorf("%w: file version and metadata roots are required", ErrInvalidDirectory)
		}
	case EntryDirectory:
		if !entry.VersionID.IsZero() || entry.SizeBytes != 0 || !entry.MetadataRoot.IsZero() {
			return fmt.Errorf("%w: child directory contains file-only fields", ErrInvalidDirectory)
		}
	default:
		return fmt.Errorf("%w: unknown entry kind %d", ErrInvalidDirectory, entry.Kind)
	}

	return nil
}

func validateEntryName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > MaximumNameBytes ||
		!utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("%w: name is not a portable UTF-8 component", ErrInvalidDirectory)
	}

	if !norm.NFC.IsNormalString(name) {
		return fmt.Errorf("%w: name must already use Unicode NFC", ErrInvalidDirectory)
	}

	return nil
}

func hashDirectoryEntry(entry DirectoryEntry) Digest {
	domain := directoryFileEntryDomain
	if entry.Kind == EntryDirectory {
		domain = directoryChildEntryDomain
	}

	hasher := newDomainHasher(domain)
	writeUint32(hasher, uint32(len(entry.Name))) //nolint:gosec // Names are capped at 255 bytes.
	writeHash(hasher, []byte(entry.Name))
	writeHash(hasher, entry.StableID[:])

	if entry.Kind == EntryFile {
		writeHash(hasher, entry.VersionID[:])
		writeUint64(hasher, entry.SizeBytes)
		writeHash(hasher, entry.DataRoot[:])
		writeHash(hasher, entry.MetadataRoot[:])
	} else {
		writeHash(hasher, entry.DataRoot[:])
	}

	return finishDigest(hasher)
}
