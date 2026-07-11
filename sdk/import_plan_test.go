package sdk_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/cryptostream"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type readableDestination struct{}

func (readableDestination) Stat(
	_ context.Context,
	_ string,
) (provider.Object, error) {
	return provider.Object{}, errUnexpectedProviderCall
}

func (readableDestination) OpenRange(
	_ context.Context,
	_ string,
	_, _ uint64,
) (io.ReadCloser, error) {
	return nil, errUnexpectedProviderCall
}

func (readableDestination) Put(
	_ context.Context,
	_ string,
	_ io.Reader,
	_ provider.PutOptions,
) (provider.Object, error) {
	return provider.Object{}, errUnexpectedProviderCall
}

func TestImportPlanPersistsRandomPackIdentitiesBeforeTransfer(t *testing.T) {
	t.Parallel()

	layout := archive.Layout{
		PhysicalBlockBytes: 8,
		CryptoFrameBytes:   2,
		LogicalPackBytes:   16,
	}
	source := sourceProvider{object: provider.Object{
		Key:       "source",
		SizeBytes: 35,
		ETag:      "etag-1",
		Version:   "version-1",
	}}

	importer, err := sdk.NewImporter(source, readableDestination{}, layout)
	if err != nil {
		t.Fatalf("construct importer: %v", err)
	}

	plan, err := importer.PlanImport(context.Background(), sdk.ImportPlanRequest{
		NamespaceID:         importIdentifier(),
		ObjectID:            "object-1",
		Generation:          1,
		RootVersion:         1,
		KeyEpoch:            7,
		SourceKey:           "source",
		DestinationDriverID: "aliyun-primary",
		DestinationPrefix:   "/carrack/archive/",
	})
	if err != nil {
		t.Fatalf("plan import: %v", err)
	}

	if len(plan.Packs) != 3 || plan.Packs[2].PlaintextSize != 3 {
		t.Fatalf("unexpected pack plan: %+v", plan.Packs)
	}

	if plan.Packs[0].PackID == plan.Packs[1].PackID {
		t.Fatal("independent packs reused a random identity")
	}

	if plan.DestinationPrefix != "carrack/archive" || plan.Source.ETag != "etag-1" {
		t.Fatalf("plan did not canonicalize immutable endpoints: %+v", plan)
	}

	planPath := filepath.Join(t.TempDir(), "import-plan.json")
	if writeErr := sdk.WriteImportPlan(planPath, plan); writeErr != nil {
		t.Fatalf("write import plan: %v", writeErr)
	}

	information, err := os.Stat(planPath)
	if err != nil {
		t.Fatalf("stat import plan: %v", err)
	}

	if information.Mode().Perm() != 0o600 {
		t.Fatalf("import plan mode = %o, want 600", information.Mode().Perm())
	}

	encoded, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read import plan: %v", err)
	}

	parsed, err := sdk.ParseImportPlan(encoded)
	if err != nil {
		t.Fatalf("parse import plan: %v", err)
	}

	if parsed.Packs[0].PackID != plan.Packs[0].PackID || parsed.Source != plan.Source {
		t.Fatalf("persisted plan changed immutable identity: %+v", parsed)
	}
}

func TestImportPlanRejectsCoverageIdentityAndUnknownFields(t *testing.T) {
	t.Parallel()

	plan := validImportPlan()
	mutations := []func(*sdk.ImportPlan){
		func(value *sdk.ImportPlan) { value.NamespaceID = "00000000000000000000000000000000" },
		func(value *sdk.ImportPlan) { value.Packs[0].PlaintextOffset = 1 },
		func(value *sdk.ImportPlan) { value.Packs[0].PackID = value.Packs[1].PackID },
		func(value *sdk.ImportPlan) { value.Source.SizeBytes++ },
		func(value *sdk.ImportPlan) { value.Packs = nil },
	}

	for index, mutate := range mutations {
		candidate := plan
		candidate.Packs = append([]sdk.PlannedPack(nil), plan.Packs...)
		mutate(&candidate)

		if err := candidate.Validate(); !errors.Is(err, sdk.ErrInvalidImportPlan) {
			t.Errorf("mutation %d: expected ErrInvalidImportPlan, got %v", index, err)
		}
	}

	encoded, err := plan.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal import plan: %v", err)
	}

	encoded[len(encoded)-1] = ','
	encoded = append(encoded, []byte(`"unknown":true}`)...)

	if _, err := sdk.ParseImportPlan(encoded); !errors.Is(err, sdk.ErrInvalidImportPlan) {
		t.Fatalf("expected unknown-field rejection, got %v", err)
	}
}

func validImportPlan() sdk.ImportPlan {
	return sdk.ImportPlan{
		SchemaVersion:       sdk.ImportPlanSchemaVersion,
		NamespaceID:         "202122232425262728292a2b2c2d2e2f",
		ObjectID:            "object-1",
		Generation:          1,
		RootVersion:         1,
		KeyEpoch:            7,
		Source:              sdk.PlannedSource{Key: "source", SizeBytes: 18},
		DestinationDriverID: "aliyun-primary",
		DestinationPrefix:   "carrack/archive",
		Layout: archive.Layout{
			PhysicalBlockBytes: 8,
			CryptoFrameBytes:   2,
			LogicalPackBytes:   16,
		},
		Packs: []sdk.PlannedPack{
			{
				Ordinal:         0,
				PackID:          "404142434445464748494a4b4c4d4e4f",
				PlaintextOffset: 0,
				PlaintextSize:   16,
			},
			{
				Ordinal:         1,
				PackID:          "505152535455565758595a5b5c5d5e5f",
				PlaintextOffset: 16,
				PlaintextSize:   2,
			},
		},
	}
}

func importIdentifier() cryptostream.Identifier {
	var value cryptostream.Identifier
	for index := range value {
		value[index] = 0x20 + byte(index)
	}

	return value
}
