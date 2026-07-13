package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	// ErrInvalidDriver indicates an invalid specification, factory, or handle.
	ErrInvalidDriver = errors.New("invalid Carrack driver")
	// ErrUnknownDriver indicates that no factory supports a requested kind.
	ErrUnknownDriver = errors.New("unknown Carrack driver")
	// ErrCredentialConflict indicates concurrent credential rotation.
	ErrCredentialConflict = errors.New("carrack driver credential revision conflict")
)

// DriverKind is a versioned driver implementation identifier.
type DriverKind string

// DriverSpec is the control-plane-supplied configuration for one driver
// instance. Config is decoded strictly by the matching typed factory.
type DriverSpec struct {
	ID            string          `json:"id"`
	Kind          DriverKind      `json:"kind"`
	Config        json.RawMessage `json:"config"`
	CredentialRef string          `json:"credential_ref,omitempty"`
}

// Capabilities describes operations and safe physical limits exposed by a
// concrete driver instance.
type Capabilities struct {
	RangeRead            bool   `json:"range_read"`
	StreamingWrite       bool   `json:"streaming_write"`
	Delete               bool   `json:"delete"`
	Inventory            bool   `json:"inventory"`
	ServerSideCopy       bool   `json:"server_side_copy"`
	ResumableWrite       bool   `json:"resumable_write"`
	MaximumObjectBytes   uint64 `json:"maximum_object_bytes,omitempty"`
	PreferredObjectBytes uint64 `json:"preferred_object_bytes,omitempty"`
	PreferredPartBytes   uint64 `json:"preferred_part_bytes,omitempty"`
	SafeConcurrency      uint32 `json:"safe_concurrency"`
}

// Handle contains the optional interfaces implemented by an opened driver.
type Handle struct {
	ID           string
	Kind         DriverKind
	Capabilities Capabilities
	Reader       Reader
	Writer       Writer
	Deleter      Deleter
	Inventory    Inventory
}

// Deleter removes a provider object idempotently.
type Deleter interface {
	Delete(ctx context.Context, key string) error
}

// InventoryPage is one bounded, strictly key-ordered page of objects under a
// Carrack-owned prefix. NextCursor is empty for the terminal page; otherwise it
// is the final object key. Every returned key must be greater than the cursor
// supplied to List so adapters normalize provider pagination to one keyset
// contract.
type InventoryPage struct {
	Objects    []Object
	NextCursor string
}

// Inventory lists provider objects for reconciliation and garbage collection.
type Inventory interface {
	List(ctx context.Context, prefix, cursor string) (InventoryPage, error)
}

// CredentialRecord is a decrypted, short-lived driver credential grant.
type CredentialRecord struct {
	Payload  json.RawMessage
	Revision uint64
}

// CredentialStore resolves grants and persists rotations with optimistic CAS.
type CredentialStore interface {
	Load(ctx context.Context, reference string) (CredentialRecord, error)
	CompareAndSwap(
		ctx context.Context,
		reference string,
		expectedRevision uint64,
		replacement json.RawMessage,
	) (CredentialRecord, error)
}

// Dependencies are SDK-owned runtime facilities shared by driver factories.
// HTTPClient is caller-owned and may use Go's standard HTTP/HTTPS/SOCKS5 proxy
// support. Driver factories must not start or manage proxy daemons.
type Dependencies struct {
	HTTPClient  *http.Client
	Credentials CredentialStore
}

// Factory validates typed configuration and opens one driver instance.
type Factory interface {
	Kind() DriverKind
	Open(ctx context.Context, specification DriverSpec, dependencies Dependencies) (Handle, error)
}

// Registry is an immutable set of versioned driver factories.
type Registry struct {
	factories map[DriverKind]Factory
}

// NewRegistry rejects empty and duplicate factory kinds.
func NewRegistry(factories ...Factory) (*Registry, error) {
	registered := make(map[DriverKind]Factory, len(factories))

	for _, factory := range factories {
		if factory == nil || strings.TrimSpace(string(factory.Kind())) == "" {
			return nil, fmt.Errorf("%w: factory kind is required", ErrInvalidDriver)
		}

		if _, exists := registered[factory.Kind()]; exists {
			return nil, fmt.Errorf("%w: duplicate factory kind %q", ErrInvalidDriver, factory.Kind())
		}

		registered[factory.Kind()] = factory
	}

	return &Registry{factories: registered}, nil
}

// Open validates a specification and delegates to its typed factory.
func (registry *Registry) Open(
	ctx context.Context,
	specification DriverSpec,
	dependencies Dependencies,
) (Handle, error) {
	if registry == nil {
		return Handle{}, fmt.Errorf("%w: registry is required", ErrInvalidDriver)
	}

	if err := specification.Validate(); err != nil {
		return Handle{}, err
	}

	factory, exists := registry.factories[specification.Kind]
	if !exists {
		return Handle{}, fmt.Errorf("%w: %q", ErrUnknownDriver, specification.Kind)
	}

	handle, err := factory.Open(ctx, specification, dependencies)
	if err != nil {
		return Handle{}, fmt.Errorf("open driver %q: %w", specification.ID, err)
	}

	if err := handle.validate(specification); err != nil {
		return Handle{}, err
	}

	return handle, nil
}

// Validate checks the provider-neutral portion of a driver specification.
func (specification DriverSpec) Validate() error {
	if strings.TrimSpace(specification.ID) == "" {
		return fmt.Errorf("%w: driver ID is required", ErrInvalidDriver)
	}

	if strings.TrimSpace(string(specification.Kind)) == "" {
		return fmt.Errorf("%w: driver kind is required", ErrInvalidDriver)
	}

	if !json.Valid(specification.Config) || !jsonObject(specification.Config) {
		return fmt.Errorf("%w: driver config must be a JSON object", ErrInvalidDriver)
	}

	return nil
}

func (handle Handle) validate(specification DriverSpec) error {
	if handle.ID != specification.ID || handle.Kind != specification.Kind {
		return fmt.Errorf("%w: factory returned mismatched driver identity", ErrInvalidDriver)
	}

	if handle.Capabilities.RangeRead != (handle.Reader != nil) {
		return fmt.Errorf("%w: range-read capability and interface disagree", ErrInvalidDriver)
	}

	if handle.Capabilities.StreamingWrite != (handle.Writer != nil) {
		return fmt.Errorf("%w: streaming-write capability and interface disagree", ErrInvalidDriver)
	}

	if handle.Capabilities.Delete != (handle.Deleter != nil) {
		return fmt.Errorf("%w: delete capability and interface disagree", ErrInvalidDriver)
	}

	if handle.Capabilities.Inventory != (handle.Inventory != nil) {
		return fmt.Errorf("%w: inventory capability and interface disagree", ErrInvalidDriver)
	}

	if handle.Capabilities.SafeConcurrency == 0 {
		return fmt.Errorf("%w: safe concurrency must be positive", ErrInvalidDriver)
	}

	if handle.Capabilities.MaximumObjectBytes > 0 &&
		handle.Capabilities.PreferredObjectBytes > handle.Capabilities.MaximumObjectBytes {
		return fmt.Errorf("%w: preferred object size exceeds driver maximum", ErrInvalidDriver)
	}

	return nil
}

func jsonObject(value json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(value))

	return strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")
}
