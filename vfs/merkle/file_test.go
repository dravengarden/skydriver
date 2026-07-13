package merkle

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestBuildFileUsesCanonicalExactBlocks(t *testing.T) {
	t.Parallel()

	payload := []byte("abcdefghij")

	tree, err := BuildFileBytes(payload, 4)
	if err != nil {
		t.Fatalf("build file tree: %v", err)
	}

	if tree.SizeBytes != 10 || tree.BlockBytes != 4 || len(tree.Blocks) != 3 {
		t.Fatalf("unexpected file layout: %+v", tree)
	}

	expected := []FileBlock{
		{Index: 0, Offset: 0, SizeBytes: 4, Digest: HashFileBlock(0, payload[0:4])},
		{Index: 1, Offset: 4, SizeBytes: 4, Digest: HashFileBlock(1, payload[4:8])},
		{Index: 2, Offset: 8, SizeBytes: 2, Digest: HashFileBlock(2, payload[8:10])},
	}

	for index := range expected {
		if tree.Blocks[index] != expected[index] {
			t.Fatalf("block %d: got %+v, want %+v", index, tree.Blocks[index], expected[index])
		}
	}

	rebuilt, err := RootFromFileBlocks(tree.SizeBytes, tree.BlockBytes, tree.Blocks)
	if err != nil {
		t.Fatalf("rebuild file root: %v", err)
	}

	if rebuilt.TreeDigest != tree.TreeDigest || rebuilt.Root != tree.Root {
		t.Fatalf("rebuilt roots differ: got %+v, want %+v", rebuilt, tree)
	}

	changed := append([]byte(nil), payload...)
	changed[5] ^= 0xff

	changedTree, err := BuildFileBytes(changed, 4)
	if err != nil {
		t.Fatalf("build changed file tree: %v", err)
	}

	if changedTree.Root == tree.Root {
		t.Fatal("changed payload retained the same file root")
	}
}

func TestBuildFileRejectsShortTrailingAndCanceledInput(t *testing.T) {
	t.Parallel()

	_, err := BuildFile(context.Background(), bytes.NewReader([]byte("short")), 6, 2)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("short reader: got %v, want ErrIntegrity", err)
	}

	_, err = BuildFile(context.Background(), bytes.NewReader([]byte("trailing")), 4, 2)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("trailing reader: got %v, want ErrIntegrity", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = BuildFile(ctx, bytes.NewReader([]byte("payload")), 7, 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reader: got %v, want context cancellation", err)
	}
}

func TestFileLayoutValidation(t *testing.T) {
	t.Parallel()

	if _, err := BuildFileBytes(nil, 0); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("zero block size: got %v, want ErrInvalidFile", err)
	}

	empty, err := BuildFileBytes(nil, 4)
	if err != nil {
		t.Fatalf("build empty file: %v", err)
	}

	if len(empty.Blocks) != 0 || empty.Root.IsZero() || empty.TreeDigest.IsZero() {
		t.Fatalf("empty file tree is invalid: %+v", empty)
	}

	invalid := []FileBlock{{Index: 1, Offset: 0, SizeBytes: 1, Digest: HashFileBlock(1, []byte("x"))}}
	if _, err := RootFromFileBlocks(1, 4, invalid); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("non-canonical blocks: got %v, want ErrInvalidFile", err)
	}
}

func TestLargestPowerOfTwoPrefix(t *testing.T) {
	t.Parallel()

	cases := map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8}
	for count, expected := range cases {
		if actual := largestPowerOfTwoPrefix(count); actual != expected {
			t.Fatalf("count %d: got %d, want %d", count, actual, expected)
		}
	}
}
