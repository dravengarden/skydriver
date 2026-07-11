package provider

import (
	"context"
	"io"
	"strings"
	"testing"
)

const testDriverKind DriverKind = "test/v1"

type testFactory struct{}

func (testFactory) Kind() DriverKind {
	return testDriverKind
}

func (testFactory) Open(_ context.Context, specification DriverSpec, _ Dependencies) (Handle, error) {
	driver := &testDriver{}

	return Handle{
		ID:   specification.ID,
		Kind: specification.Kind,
		Capabilities: Capabilities{
			RangeRead:       true,
			StreamingWrite:  true,
			SafeConcurrency: 1,
		},
		Reader: driver,
		Writer: driver,
	}, nil
}

type testDriver struct{}

func (driver *testDriver) Stat(_ context.Context, key string) (Object, error) {
	return Object{Key: key}, nil
}

func (driver *testDriver) OpenRange(_ context.Context, _ string, _, _ uint64) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("test")), nil
}

func (driver *testDriver) Put(_ context.Context, key string, _ io.Reader, options PutOptions) (Object, error) {
	return Object{Key: key, SizeBytes: options.SizeBytes}, nil
}

func TestRegistryOpensVersionedDriver(t *testing.T) {
	t.Parallel()

	registry, err := NewRegistry(testFactory{})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	handle, err := registry.Open(context.Background(), DriverSpec{
		ID:     "source",
		Kind:   testDriverKind,
		Config: []byte(`{}`),
	}, Dependencies{})
	if err != nil {
		t.Fatalf("open driver: %v", err)
	}

	if handle.ID != "source" || handle.Kind != testDriverKind || handle.Reader == nil || handle.Writer == nil {
		t.Fatalf("unexpected handle: %+v", handle)
	}
}

func TestRegistryRejectsUnknownAndDuplicateKinds(t *testing.T) {
	t.Parallel()

	if _, err := NewRegistry(testFactory{}, testFactory{}); err == nil {
		t.Fatal("expected duplicate factory error")
	}

	registry, err := NewRegistry()
	if err != nil {
		t.Fatalf("create empty registry: %v", err)
	}

	if _, err := registry.Open(context.Background(), DriverSpec{
		ID:     "unknown",
		Kind:   "unknown/v1",
		Config: []byte(`{}`),
	}, Dependencies{}); err == nil {
		t.Fatal("expected unknown driver error")
	}
}

func TestDriverSpecRejectsNonObjectConfig(t *testing.T) {
	t.Parallel()

	for _, config := range [][]byte{nil, []byte(`null`), []byte(`[]`), []byte(`invalid`)} {
		specification := DriverSpec{ID: "driver", Kind: testDriverKind, Config: config}
		if err := specification.Validate(); err == nil {
			t.Errorf("expected config %q to fail", config)
		}
	}
}
