package driver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestRegistryOpensOnlyMatchingCompiledKinds(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	descriptor := fullDescriptor("local-main", "test/v1")
	implementation := completeDriver{}

	if err := registry.Register("test/v1", func(_ context.Context, instance Instance) (Handle, error) {
		return Handle{
			Descriptor: descriptor, Reader: implementation, RangeReader: implementation,
			Writer: implementation, ResumableWriter: implementation,
			Deleter: implementation, Inventory: implementation,
		}, nil
	}); err != nil {
		t.Fatalf("register driver: %v", err)
	}

	handle, err := registry.Open(context.Background(), Instance{
		ID: "local-main", Kind: "test/v1", Revision: 1, Config: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("open compiled driver: %v", err)
	}

	if handle.Descriptor.ID != descriptor.ID || handle.Descriptor.Kind != descriptor.Kind {
		t.Fatalf("opened descriptor differs: %+v", handle.Descriptor)
	}

	_, err = registry.Open(context.Background(), Instance{
		ID: "remote", Kind: "uncompiled/v1", Revision: 1, Config: json.RawMessage(`{}`),
	})
	if !errors.Is(err, ErrDriverKindNotRegistered) {
		t.Fatalf("uncompiled driver was not rejected: %v", err)
	}
}
