package aliyundrive

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dravengarden/carrack/provider"
)

var errCredentialRevision = errors.New("unexpected credential revision")

type memoryCredentialStore struct {
	record provider.CredentialRecord
}

func (store *memoryCredentialStore) Load(_ context.Context, _ string) (provider.CredentialRecord, error) {
	return store.record, nil
}

func (store *memoryCredentialStore) CompareAndSwap(
	_ context.Context,
	_ string,
	expectedRevision uint64,
	replacement json.RawMessage,
) (provider.CredentialRecord, error) {
	if expectedRevision != store.record.Revision {
		return provider.CredentialRecord{}, errCredentialRevision
	}

	store.record = provider.CredentialRecord{
		Payload:  replacement,
		Revision: expectedRevision + 1,
	}

	return store.record, nil
}

func TestFactoryOpensTypedDriver(t *testing.T) {
	t.Parallel()

	credentials := &memoryCredentialStore{record: provider.CredentialRecord{
		Payload:  []byte(`{"access_token":"test-token"}`),
		Revision: 4,
	}}

	registry, err := provider.NewRegistry(Factory{})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	handle, err := registry.Open(context.Background(), provider.DriverSpec{
		ID:            "cold-archive",
		Kind:          DriverKind,
		Config:        []byte(`{"drive_type":"resource","upload_part_bytes":8388608}`),
		CredentialRef: "credential-1",
	}, provider.Dependencies{Credentials: credentials})
	if err != nil {
		t.Fatalf("open Aliyun Drive driver: %v", err)
	}

	if handle.Reader == nil || handle.Writer == nil {
		t.Fatal("expected read and write interfaces")
	}

	if handle.Capabilities.SafeConcurrency != safeConcurrency ||
		handle.Capabilities.PreferredPartBytes != 8<<20 {
		t.Fatalf("unexpected capabilities: %+v", handle.Capabilities)
	}
}

func TestFactoryRejectsUnknownConfigurationField(t *testing.T) {
	t.Parallel()

	credentials := &memoryCredentialStore{record: provider.CredentialRecord{
		Payload:  []byte(`{"access_token":"test-token"}`),
		Revision: 1,
	}}

	_, err := (Factory{}).Open(context.Background(), provider.DriverSpec{
		ID:            "archive",
		Kind:          DriverKind,
		Config:        []byte(`{"unknown":true}`),
		CredentialRef: "credential-1",
	}, provider.Dependencies{Credentials: credentials})
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestFactoryRequiresExactlyOneToken(t *testing.T) {
	t.Parallel()

	for _, payload := range []json.RawMessage{
		[]byte(`{}`),
		[]byte(`{"access_token":"access","refresh_token":"refresh"}`),
	} {
		credentials := &memoryCredentialStore{record: provider.CredentialRecord{
			Payload:  payload,
			Revision: 1,
		}}

		_, err := (Factory{}).Open(context.Background(), provider.DriverSpec{
			ID:            "archive",
			Kind:          DriverKind,
			Config:        []byte(`{}`),
			CredentialRef: "credential-1",
		}, provider.Dependencies{Credentials: credentials})
		if err == nil {
			t.Fatalf("expected credential %s to fail", payload)
		}
	}
}
