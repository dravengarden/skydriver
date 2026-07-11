// Package sdk provides the embeddable Carrack transfer API.
package sdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/dravengarden/carrack/archive"
	"github.com/dravengarden/carrack/provider"
)

// ErrInvalidConfiguration indicates missing SDK dependencies or invalid layout.
var ErrInvalidConfiguration = errors.New("invalid Carrack SDK configuration")

// Client plans direct transfers between provider implementations.
type Client struct {
	source      provider.Reader
	destination provider.Writer
	layout      archive.Layout
}

// TransferPlan describes a direct provider-to-provider transfer.
type TransferPlan struct {
	Source      provider.Object
	Destination string
	Blocks      []archive.BlockSpan
}

// NewClient validates dependencies and constructs a direct-transfer client.
func NewClient(source provider.Reader, destination provider.Writer, layout archive.Layout) (*Client, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: source provider is required", ErrInvalidConfiguration)
	}

	if destination == nil {
		return nil, fmt.Errorf("%w: destination provider is required", ErrInvalidConfiguration)
	}

	if err := layout.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfiguration, err)
	}

	return &Client{source: source, destination: destination, layout: layout}, nil
}

// NewClientFromRegistry opens versioned driver specifications and constructs a
// direct-transfer client. The same entry point is used by every Carrack SDK
// consumer, regardless of which provider pair it selects at runtime.
func NewClientFromRegistry(
	ctx context.Context,
	registry *provider.Registry,
	sourceSpecification provider.DriverSpec,
	destinationSpecification provider.DriverSpec,
	dependencies provider.Dependencies,
	layout archive.Layout,
) (*Client, error) {
	source, err := registry.Open(ctx, sourceSpecification, dependencies)
	if err != nil {
		return nil, fmt.Errorf("%w: open source driver: %w", ErrInvalidConfiguration, err)
	}

	if source.Reader == nil {
		return nil, fmt.Errorf("%w: source driver does not support range reads", ErrInvalidConfiguration)
	}

	destination, err := registry.Open(ctx, destinationSpecification, dependencies)
	if err != nil {
		return nil, fmt.Errorf("%w: open destination driver: %w", ErrInvalidConfiguration, err)
	}

	if destination.Writer == nil {
		return nil, fmt.Errorf("%w: destination driver does not support streaming writes", ErrInvalidConfiguration)
	}

	return NewClient(source.Reader, destination.Writer, layout)
}

// Plan inspects the source and returns an ordered physical block plan.
func (client *Client) Plan(ctx context.Context, sourceKey, destinationKey string) (TransferPlan, error) {
	object, err := client.source.Stat(ctx, sourceKey)
	if err != nil {
		return TransferPlan{}, fmt.Errorf("stat source object %q: %w", sourceKey, err)
	}

	blocks, err := client.layout.Plan(object.SizeBytes)
	if err != nil {
		return TransferPlan{}, fmt.Errorf("plan source object %q: %w", sourceKey, err)
	}

	return TransferPlan{Source: object, Destination: destinationKey, Blocks: blocks}, nil
}
