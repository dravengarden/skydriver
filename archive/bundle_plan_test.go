package archive_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/archive"
)

func TestBundlePlanPersistsCanonicalGaplessMembership(t *testing.T) {
	t.Parallel()

	plan, err := archive.PlanBundle([]archive.BundleFile{
		{Path: "z", Size: 7},
		{Path: "a", Size: 0},
		{Path: "m", Size: 3},
	})
	if err != nil {
		t.Fatalf("plan bundle: %v", err)
	}

	expected := []archive.BundleMember{
		{Path: "a", Offset: 0, Size: 0},
		{Path: "m", Offset: 0, Size: 3},
		{Path: "z", Offset: 3, Size: 7},
	}
	if plan.DataBytes != 10 || !slices.Equal(plan.Members, expected) {
		t.Fatalf("unexpected gapless plan: %+v", plan)
	}

	encoded, err := plan.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal bundle plan: %v", err)
	}

	parsed, err := archive.ParseBundlePlan(encoded)
	if err != nil {
		t.Fatalf("parse bundle plan: %v", err)
	}

	if parsed.DataBytes != plan.DataBytes || !slices.Equal(parsed.Members, plan.Members) {
		t.Fatalf("parsed bundle plan changed: %+v", parsed)
	}
}

func TestPlannedBundleRetryIsByteIdentical(t *testing.T) {
	t.Parallel()

	plan, err := archive.PlanBundle([]archive.BundleFile{
		{Path: "b", Size: 4},
		{Path: "a", Size: 5},
	})
	if err != nil {
		t.Fatalf("plan bundle: %v", err)
	}

	write := func() []byte {
		t.Helper()

		var destination bytes.Buffer

		_, writeErr := archive.WritePlannedBundle(
			context.Background(),
			&destination,
			plan,
			map[string]io.Reader{
				"a": strings.NewReader("alpha"),
				"b": strings.NewReader("beta"),
			},
		)
		if writeErr != nil {
			t.Fatalf("write planned bundle: %v", writeErr)
		}

		return destination.Bytes()
	}

	first := write()

	second := write()
	if !bytes.Equal(first, second) {
		t.Fatal("retry emitted different bundle bytes")
	}
}

func TestBundlePlanRejectsMutationAndReaderSetDrift(t *testing.T) {
	t.Parallel()

	plan, err := archive.PlanBundle([]archive.BundleFile{{Path: "file", Size: 4}})
	if err != nil {
		t.Fatalf("plan bundle: %v", err)
	}

	mutations := []func(*archive.BundlePlan){
		func(value *archive.BundlePlan) { value.DataBytes++ },
		func(value *archive.BundlePlan) { value.Members[0].Offset++ },
		func(value *archive.BundlePlan) { value.Members[0].Path = "../escape" },
	}
	for index, mutate := range mutations {
		candidate := plan
		candidate.Members = slices.Clone(plan.Members)
		mutate(&candidate)

		validationErr := candidate.Validate()
		if !errors.Is(validationErr, archive.ErrInvalidBundle) {
			t.Errorf("mutation %d: expected ErrInvalidBundle, got %v", index, validationErr)
		}
	}

	var destination bytes.Buffer

	_, err = archive.WritePlannedBundle(
		context.Background(),
		&destination,
		plan,
		map[string]io.Reader{
			"file":  strings.NewReader("data"),
			"extra": strings.NewReader(""),
		},
	)
	if !errors.Is(err, archive.ErrInvalidBundle) {
		t.Fatalf("expected reader-set drift rejection, got %v", err)
	}
}
