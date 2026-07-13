package merkle

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestBuildDirectorySortsNamesAndCommitsEntryIdentity(t *testing.T) {
	t.Parallel()

	fileTree, err := BuildFileBytes([]byte("release payload"), 4)
	if err != nil {
		t.Fatalf("build file tree: %v", err)
	}

	emptyDirectory, err := BuildDirectory(nil)
	if err != nil {
		t.Fatalf("build empty directory: %v", err)
	}

	entries := []DirectoryEntry{
		{
			Name:         "zeta.bin",
			Kind:         EntryFile,
			StableID:     mustIdentifier(t, "00112233445566778899aabbccddeeff"),
			VersionID:    mustIdentifier(t, "102132435465768798a9bacbdcedfe0f"),
			SizeBytes:    fileTree.SizeBytes,
			DataRoot:     fileTree.Root,
			MetadataRoot: EmptyMetadataRoot(),
		},
		{
			Name:     "docs",
			Kind:     EntryDirectory,
			StableID: mustIdentifier(t, "2031425364758697a8b9cadbecfd0e1f"),
			DataRoot: emptyDirectory.Root,
		},
		{
			Name:         "é.txt",
			Kind:         EntryFile,
			StableID:     mustIdentifier(t, "30415263748596a7b8c9daebfc0d1e2f"),
			VersionID:    mustIdentifier(t, "405162738495a6b7c8d9eafb0c1d2e3f"),
			SizeBytes:    0,
			DataRoot:     mustFileRoot(t, nil, 4),
			MetadataRoot: EmptyMetadataRoot(),
		},
	}
	original := slices.Clone(entries)

	tree, err := BuildDirectory(entries)
	if err != nil {
		t.Fatalf("build directory: %v", err)
	}

	if !slices.Equal(entries, original) {
		t.Fatal("BuildDirectory mutated caller entries")
	}

	names := []string{tree.Entries[0].Entry.Name, tree.Entries[1].Entry.Name, tree.Entries[2].Entry.Name}
	if !slices.Equal(names, []string{"docs", "zeta.bin", "é.txt"}) {
		t.Fatalf("unexpected bytewise order: %q", names)
	}

	reordered := []DirectoryEntry{entries[1], entries[2], entries[0]}

	rebuilt, err := BuildDirectory(reordered)
	if err != nil {
		t.Fatalf("rebuild reordered directory: %v", err)
	}

	if rebuilt.Root != tree.Root || rebuilt.TreeDigest != tree.TreeDigest {
		t.Fatal("input order changed canonical directory root")
	}

	changed := slices.Clone(entries)
	changed[0].VersionID = mustIdentifier(t, "5061728394a5b6c7d8e9fa0b1c2d3e4f")

	changedTree, err := BuildDirectory(changed)
	if err != nil {
		t.Fatalf("build changed directory: %v", err)
	}

	if changedTree.Root == tree.Root {
		t.Fatal("changed immutable file version retained directory root")
	}
}

func TestBuildDirectoryRejectsNonCanonicalNamesAndUnions(t *testing.T) {
	t.Parallel()

	root := mustFileRoot(t, []byte("x"), 4)
	base := DirectoryEntry{
		Name:         "valid",
		Kind:         EntryFile,
		StableID:     mustIdentifier(t, "00112233445566778899aabbccddeeff"),
		VersionID:    mustIdentifier(t, "102132435465768798a9bacbdcedfe0f"),
		SizeBytes:    1,
		DataRoot:     root,
		MetadataRoot: EmptyMetadataRoot(),
	}

	for _, name := range []string{"", ".", "..", "path/name", "e\u0301.txt", strings.Repeat("x", 256)} {
		entry := base

		entry.Name = name
		if _, err := BuildDirectory([]DirectoryEntry{entry}); !errors.Is(err, ErrInvalidDirectory) {
			t.Fatalf("name %q: got %v, want ErrInvalidDirectory", name, err)
		}
	}

	if _, err := BuildDirectory([]DirectoryEntry{base, base}); !errors.Is(err, ErrInvalidDirectory) {
		t.Fatalf("duplicate names: got %v, want ErrInvalidDirectory", err)
	}

	child := base

	child.Kind = EntryDirectory
	if _, err := BuildDirectory([]DirectoryEntry{child}); !errors.Is(err, ErrInvalidDirectory) {
		t.Fatalf("directory with file fields: got %v, want ErrInvalidDirectory", err)
	}
}

func TestDirectoryEntryJSONUsesStableTextForms(t *testing.T) {
	t.Parallel()

	entry := DirectoryEntry{
		Name:     "child",
		Kind:     EntryDirectory,
		StableID: mustIdentifier(t, "00112233445566778899aabbccddeeff"),
		DataRoot: mustFileRoot(t, nil, 4),
	}

	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("encode directory entry: %v", err)
	}

	if !strings.Contains(string(encoded), `"kind":"directory"`) ||
		strings.Contains(string(encoded), "version_id") || strings.Contains(string(encoded), "metadata_root") {
		t.Fatalf("unexpected JSON: %s", encoded)
	}

	var decoded DirectoryEntry
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode directory entry: %v", err)
	}

	if decoded != entry {
		t.Fatalf("decoded entry differs: got %+v, want %+v", decoded, entry)
	}
}

func mustIdentifier(t *testing.T, encoded string) Identifier {
	t.Helper()

	identifier, err := ParseIdentifier(encoded)
	if err != nil {
		t.Fatalf("parse identifier %q: %v", encoded, err)
	}

	return identifier
}

func mustFileRoot(t *testing.T, payload []byte, blockBytes uint64) Digest {
	t.Helper()

	tree, err := BuildFileBytes(payload, blockBytes)
	if err != nil {
		t.Fatalf("build file root: %v", err)
	}

	return tree.Root
}
