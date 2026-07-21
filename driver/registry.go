package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

var (
	// ErrDriverKindNotRegistered indicates that the binary lacks a requested compiled driver.
	ErrDriverKindNotRegistered = errors.New("carrack V2 driver kind is not compiled")
	// ErrDriverKindRegistered indicates a duplicate compiled factory registration.
	ErrDriverKindRegistered = errors.New("carrack V2 driver kind is already registered")
)

// Instance is one authorized control-plane driver grant. Config is non-secret;
// Credential is an optional decrypted JSON value retained only in memory.
type Instance struct {
	ID         string
	Kind       Kind
	Revision   uint64
	Config     json.RawMessage
	Credential json.RawMessage
}

// Factory opens one typed, compiled driver implementation from an authorized instance.
type Factory func(ctx context.Context, instance Instance) (Handle, error)

// Registry maps versioned driver kinds to compiled typed factories. It is safe
// for concurrent opens and does not load code named by control-plane data.
type Registry struct {
	mutex     sync.RWMutex
	factories map[Kind]Factory
}

// NewRegistry constructs an empty compiled-driver registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[Kind]Factory)}
}

// Register adds one compiled versioned driver factory.
func (registry *Registry) Register(kind Kind, factory Factory) error {
	if registry == nil || strings.TrimSpace(string(kind)) == "" || factory == nil {
		return fmt.Errorf("%w: kind and factory are required", ErrInvalidDriver)
	}

	registry.mutex.Lock()
	defer registry.mutex.Unlock()

	if registry.factories == nil {
		registry.factories = make(map[Kind]Factory)
	}

	if _, exists := registry.factories[kind]; exists {
		return fmt.Errorf("%w: %s", ErrDriverKindRegistered, kind)
	}

	registry.factories[kind] = factory

	return nil
}

// Open invokes only the pre-registered compiled factory and proves that its
// returned descriptor matches the authorized instance identity.
func (registry *Registry) Open(ctx context.Context, instance Instance) (Handle, error) {
	if registry == nil {
		return Handle{}, fmt.Errorf("%w: registry is required", ErrInvalidDriver)
	}

	if err := instance.validate(); err != nil {
		return Handle{}, err
	}

	registry.mutex.RLock()
	factory := registry.factories[instance.Kind]
	registry.mutex.RUnlock()

	if factory == nil {
		return Handle{}, fmt.Errorf("%w: %s", ErrDriverKindNotRegistered, instance.Kind)
	}

	handle, err := factory(ctx, instance.clone())
	if err != nil {
		return Handle{}, fmt.Errorf("open Skydriver driver %q: %w", instance.ID, err)
	}

	if err := handle.Validate(); err != nil {
		return Handle{}, err
	}

	if handle.Descriptor.ID != instance.ID || handle.Descriptor.Kind != instance.Kind {
		return Handle{}, fmt.Errorf("%w: factory changed driver identity", ErrInvalidDriver)
	}

	return handle, nil
}

func (instance Instance) validate() error {
	if strings.TrimSpace(instance.ID) == "" || strings.TrimSpace(string(instance.Kind)) == "" || instance.Revision == 0 {
		return fmt.Errorf("%w: instance identity and revision are required", ErrInvalidDriver)
	}

	if !validJSONObject(instance.Config) {
		return fmt.Errorf("%w: driver config must be one JSON object", ErrInvalidDriver)
	}

	if len(instance.Credential) != 0 && !validJSONObject(instance.Credential) {
		return fmt.Errorf("%w: driver credential must be one JSON object", ErrInvalidDriver)
	}

	return nil
}

func (instance Instance) clone() Instance {
	instance.Config = bytes.Clone(instance.Config)
	instance.Credential = bytes.Clone(instance.Credential)

	return instance
}

func validJSONObject(encoded []byte) bool {
	if len(encoded) == 0 {
		return false
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))

	var value map[string]json.RawMessage
	if err := decoder.Decode(&value); err != nil || value == nil {
		return false
	}

	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}
