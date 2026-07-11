package archive_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/archive"
)

func TestBundleWritesGaplessCanonicalDataRegion(t *testing.T) {
	t.Parallel()

	sources := []archive.BundleSource{
		{Path: "z/last.bin", Size: 5, Reader: strings.NewReader("ijklm")},
		{Path: "a/empty", Size: 0, Reader: strings.NewReader("")},
		{Path: "a/first.bin", Size: 3, Reader: strings.NewReader("abc")},
		{Path: "m/middle.bin", Size: 5, Reader: strings.NewReader("defgh")},
	}

	var encoded bytes.Buffer

	result, err := archive.WriteBundle(context.Background(), &encoded, sources)
	if err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	const expectedData = "abcdefghijklm"
	if result.Index.DataBytes != uint64(len(expectedData)) {
		t.Fatalf("data region has %d bytes, expected %d", result.Index.DataBytes, len(expectedData))
	}

	if actual := encoded.Bytes()[:result.Index.DataBytes]; !bytes.Equal(actual, []byte(expectedData)) {
		t.Fatalf("bundle inserted padding or reordered bytes incorrectly: %q", actual)
	}

	assertGaplessEntries(t, result.Index)

	if result.TotalBytes != uint64(encoded.Len()) ||
		result.TotalBytes != result.Index.DataBytes+result.IndexBytes+archive.BundleFooterBytes {
		t.Fatalf("bundle size accounting differs: %+v, encoded=%d", result, encoded.Len())
	}

	parsed, err := archive.ReadBundleIndex(bytes.NewReader(encoded.Bytes()), result.TotalBytes)
	if err != nil {
		t.Fatalf("read bundle index: %v", err)
	}

	if !slices.Equal(parsed.Entries, result.Index.Entries) {
		t.Fatalf("parsed entries changed: got %+v, expected %+v", parsed.Entries, result.Index.Entries)
	}
}

func TestBundleExtractsAndAuthenticatesEveryEntry(t *testing.T) {
	t.Parallel()

	contents := map[string]string{
		"a.txt":        "alpha",
		"nested/b.bin": strings.Repeat("b", 10_003),
		"zero":         "",
	}
	encoded, result := writeTestBundle(t, contents)

	for filePath, expected := range contents {
		var extracted bytes.Buffer

		entry, err := archive.ExtractBundleEntry(
			context.Background(),
			&extracted,
			bytes.NewReader(encoded),
			result.Index,
			filePath,
		)
		if err != nil {
			t.Fatalf("extract %q: %v", filePath, err)
		}

		if extracted.String() != expected || entry.Size != uint64(len(expected)) {
			t.Fatalf("entry %q changed: size=%d data=%q", filePath, entry.Size, extracted.String())
		}
	}
}

func TestBundleRejectsUnsafePlansAndInexactSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sources []archive.BundleSource
	}{
		{
			name: "duplicate",
			sources: []archive.BundleSource{
				{Path: "same", Size: 1, Reader: strings.NewReader("a")},
				{Path: "same", Size: 1, Reader: strings.NewReader("b")},
			},
		},
		{name: "traversal", sources: []archive.BundleSource{{Path: "../escape", Reader: strings.NewReader("")}}},
		{name: "backslash", sources: []archive.BundleSource{{Path: `a\b`, Reader: strings.NewReader("")}}},
		{name: "short", sources: []archive.BundleSource{{Path: "short", Size: 2, Reader: strings.NewReader("x")}}},
		{name: "long", sources: []archive.BundleSource{{Path: "long", Size: 1, Reader: strings.NewReader("xy")}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := archive.WriteBundle(context.Background(), &bytes.Buffer{}, test.sources); !errors.Is(err, archive.ErrInvalidBundle) {
				t.Fatalf("expected ErrInvalidBundle, got %v", err)
			}
		})
	}
}

func TestBundleDetectsIndexAndPayloadCorruption(t *testing.T) {
	t.Parallel()

	encoded, result := writeTestBundle(t, map[string]string{"file": "payload"})

	indexCorruption := bytes.Clone(encoded)

	indexCorruption[result.Index.DataBytes] ^= 0x01
	if _, err := archive.ReadBundleIndex(bytes.NewReader(indexCorruption), uint64(len(indexCorruption))); !errors.Is(err, archive.ErrBundleIntegrity) {
		t.Fatalf("expected index integrity error, got %v", err)
	}

	payloadCorruption := bytes.Clone(encoded)
	payloadCorruption[0] ^= 0x01

	var extracted bytes.Buffer
	if _, err := archive.ExtractBundleEntry(
		context.Background(),
		&extracted,
		bytes.NewReader(payloadCorruption),
		result.Index,
		"file",
	); !errors.Is(err, archive.ErrBundleIntegrity) {
		t.Fatalf("expected payload integrity error, got %v", err)
	}
}

func TestBundleRandomizedPlansNeverInsertPadding(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewPCG(0x4341_5252_4143_4b31, 0x4741_504c_4553_5331))
	for iteration := range 200 {
		fileCount := random.IntN(64)
		sources := make([]archive.BundleSource, fileCount)
		expected := make([]byte, 0, fileCount*8_192)

		for file := range fileCount {
			size := random.IntN(8_193)
			content := make([]byte, size)

			for index := range content {
				content[index] = byte(random.Uint64())
			}

			expected = append(expected, content...)
			sources[file] = archive.BundleSource{
				Path:   fmtBundlePath(file),
				Size:   uint64(size),
				Reader: bytes.NewReader(content),
			}
		}

		var encoded bytes.Buffer

		result, err := archive.WriteBundle(context.Background(), &encoded, sources)
		if err != nil {
			t.Fatalf("iteration %d: write bundle: %v", iteration, err)
		}

		if result.Index.DataBytes != uint64(len(expected)) ||
			!bytes.Equal(encoded.Bytes()[:result.Index.DataBytes], expected) {
			t.Fatalf("iteration %d: data region contains padding or changed bytes", iteration)
		}

		assertGaplessEntries(t, result.Index)
	}
}

func FuzzBundleNeverPadsDataRegion(fuzz *testing.F) {
	fuzz.Add([]byte("alpha"), []byte(""), []byte("omega"))
	fuzz.Add([]byte{}, []byte{0}, []byte{0, 0, 0})

	fuzz.Fuzz(func(t *testing.T, first, second, third []byte) {
		if len(first)+len(second)+len(third) > 1<<20 {
			t.Skip()
		}

		sources := []archive.BundleSource{
			{Path: "1", Size: uint64(len(first)), Reader: bytes.NewReader(first)},
			{Path: "2", Size: uint64(len(second)), Reader: bytes.NewReader(second)},
			{Path: "3", Size: uint64(len(third)), Reader: bytes.NewReader(third)},
		}
		expected := slices.Concat(first, second, third)

		var encoded bytes.Buffer

		result, err := archive.WriteBundle(context.Background(), &encoded, sources)
		if err != nil {
			t.Fatalf("write fuzz bundle: %v", err)
		}

		if !bytes.Equal(encoded.Bytes()[:result.Index.DataBytes], expected) {
			t.Fatal("bundle data region contains bytes not present in its sources")
		}
	})
}

func writeTestBundle(t *testing.T, contents map[string]string) ([]byte, archive.BundleResult) {
	t.Helper()

	sources := make([]archive.BundleSource, 0, len(contents))
	for filePath, content := range contents {
		sources = append(sources, archive.BundleSource{
			Path:   filePath,
			Size:   uint64(len(content)),
			Reader: strings.NewReader(content),
		})
	}

	var encoded bytes.Buffer

	result, err := archive.WriteBundle(context.Background(), &encoded, sources)
	if err != nil {
		t.Fatalf("write test bundle: %v", err)
	}

	return encoded.Bytes(), result
}

func assertGaplessEntries(t *testing.T, index archive.BundleIndex) {
	t.Helper()

	expectedOffset := uint64(0)
	for _, entry := range index.Entries {
		if entry.Offset != expectedOffset {
			t.Fatalf("entry %q begins at %d after %d bytes", entry.Path, entry.Offset, expectedOffset)
		}

		expectedOffset += entry.Size

		decoded, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			t.Fatalf("entry %q has invalid digest %q", entry.Path, entry.SHA256)
		}
	}

	if expectedOffset != index.DataBytes {
		t.Fatalf("entries cover %d bytes, data region has %d", expectedOffset, index.DataBytes)
	}
}

func fmtBundlePath(index int) string {
	return "files/" + strings.Repeat("0", 6-len(fmtInt(index))) + fmtInt(index)
}

func fmtInt(value int) string {
	if value == 0 {
		return "0"
	}

	var reversed [20]byte

	position := len(reversed)
	for value > 0 {
		position--
		reversed[position] = byte('0' + value%10)
		value /= 10
	}

	return string(reversed[position:])
}
