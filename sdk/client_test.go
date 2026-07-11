package sdk_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

var errUnexpectedProviderCall = errors.New("unexpected provider call")

var errSourceUnavailable = errors.New("source unavailable")

type sourceProvider struct {
	object provider.Object
}

func (source sourceProvider) Stat(_ context.Context, _ string) (provider.Object, error) {
	return source.object, nil
}

func (sourceProvider) OpenRange(
	_ context.Context,
	_ string,
	_, _ uint64,
) (io.ReadCloser, error) {
	return nil, errUnexpectedProviderCall
}

type destinationProvider struct{}

func (destinationProvider) Put(
	_ context.Context,
	_ string,
	_ io.Reader,
	_ provider.PutOptions,
) (provider.Object, error) {
	return provider.Object{}, errUnexpectedProviderCall
}

const registryDriverKind provider.DriverKind = "registry-test/v1"

type registryFactory struct{}

func (registryFactory) Kind() provider.DriverKind {
	return registryDriverKind
}

func (registryFactory) Open(
	_ context.Context,
	specification provider.DriverSpec,
	_ provider.Dependencies,
) (provider.Handle, error) {
	handle := provider.Handle{
		ID:   specification.ID,
		Kind: specification.Kind,
		Capabilities: provider.Capabilities{
			SafeConcurrency: 1,
		},
	}

	switch specification.ID {
	case "source":
		handle.Capabilities.RangeRead = true
		handle.Reader = sourceProvider{object: provider.Object{Key: "source", SizeBytes: 18}}
	case "destination":
		handle.Capabilities.StreamingWrite = true
		handle.Writer = destinationProvider{}
	}

	return handle, nil
}

func TestClientPlansDirectTransfer(t *testing.T) {
	t.Parallel()

	source := sourceProvider{object: provider.Object{Key: "source", SizeBytes: 18}}
	layout := archive.Layout{PhysicalBlockBytes: 8, CryptoFrameBytes: 2, LogicalPackBytes: 16}

	client, err := sdk.NewClient(source, destinationProvider{}, layout)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	plan, err := client.Plan(context.Background(), "source", "destination")
	if err != nil {
		t.Fatalf("plan transfer: %v", err)
	}

	if len(plan.Blocks) != 3 || plan.Destination != "destination" {
		t.Fatalf("unexpected transfer plan: %+v", plan)
	}
}

func TestClientWrapsSourceFailure(t *testing.T) {
	t.Parallel()

	source := failingSource{failure: errSourceUnavailable}

	client, err := sdk.NewClient(source, destinationProvider{}, archive.DefaultLayout())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	_, err = client.Plan(context.Background(), "source", "destination")

	if err == nil || !strings.Contains(err.Error(), errSourceUnavailable.Error()) {
		t.Fatalf("expected wrapped source failure, got %v", err)
	}
}

func TestClientOpensDriversFromRegistry(t *testing.T) {
	t.Parallel()

	registry, err := provider.NewRegistry(registryFactory{})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	client, err := sdk.NewClientFromRegistry(
		context.Background(),
		registry,
		provider.DriverSpec{ID: "source", Kind: registryDriverKind, Config: []byte(`{}`)},
		provider.DriverSpec{ID: "destination", Kind: registryDriverKind, Config: []byte(`{}`)},
		provider.Dependencies{},
		archive.Layout{PhysicalBlockBytes: 8, CryptoFrameBytes: 2, LogicalPackBytes: 16},
	)
	if err != nil {
		t.Fatalf("create registry-backed client: %v", err)
	}

	plan, err := client.Plan(context.Background(), "source", "destination")
	if err != nil {
		t.Fatalf("plan transfer: %v", err)
	}

	if len(plan.Blocks) != 3 {
		t.Fatalf("unexpected transfer plan: %+v", plan)
	}
}

type failingSource struct {
	failure error
}

func (source failingSource) Stat(_ context.Context, _ string) (provider.Object, error) {
	return provider.Object{}, source.failure
}

func (failingSource) OpenRange(
	_ context.Context,
	_ string,
	_, _ uint64,
) (io.ReadCloser, error) {
	return nil, errUnexpectedProviderCall
}
