package driver

import (
	"context"
	"io"
	"strings"
	"testing"
)

type completeDriver struct{}

func (completeDriver) Stat(_ context.Context, storageKey string) (Object, error) {
	return Object{Locator: Locator{StorageKey: storageKey}, SizeBytes: 4}, nil
}

func (completeDriver) Open(_ context.Context, _ Object) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("data")), nil
}

func (completeDriver) OpenRange(_ context.Context, _ Object, _, _ uint64) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("data")), nil
}

func (completeDriver) Put(_ context.Context, request PutRequest) (Object, error) {
	return Object{Locator: Locator{StorageKey: request.StorageKey}, SizeBytes: request.SizeBytes}, nil
}

func (completeDriver) BeginUpload(_ context.Context, _ BeginUploadRequest) (UploadSession, error) {
	return UploadSession{ID: "upload"}, nil
}

func (completeDriver) ListParts(_ context.Context, _ UploadSession) ([]UploadedPart, error) {
	return []UploadedPart{}, nil
}

func (completeDriver) PutPart(_ context.Context, request PutPartRequest) (UploadedPart, error) {
	return request.Part, nil
}

func (completeDriver) CompleteUpload(_ context.Context, request CompleteUploadRequest) (Object, error) {
	return Object{Locator: Locator{StorageKey: request.Session.ID}, SizeBytes: request.SizeBytes}, nil
}

func (completeDriver) AbortUpload(_ context.Context, _ UploadSession) error {
	return nil
}

func (completeDriver) Delete(_ context.Context, _ Object) error {
	return nil
}

func (completeDriver) List(_ context.Context, _ string, _ uint32) ([]Object, string, error) {
	return []Object{}, "", nil
}

func fullDescriptor(driverID string, kind Kind) Descriptor {
	return Descriptor{
		ID:           driverID,
		Kind:         kind,
		Summary:      "complete test driver",
		Capabilities: fullCapabilities(),
	}
}

func TestHandleRequiresAdvertisedInterfaces(t *testing.T) {
	t.Parallel()

	implementation := completeDriver{}
	handle := Handle{
		Descriptor:      fullDescriptor("full", "full/v1"),
		Reader:          implementation,
		RangeReader:     implementation,
		Writer:          implementation,
		ResumableWriter: implementation,
		Deleter:         implementation,
		Inventory:       implementation,
	}

	if err := handle.Validate(); err != nil {
		t.Fatalf("validate complete handle: %v", err)
	}

	handle.ResumableWriter = nil
	if err := handle.Validate(); err == nil {
		t.Fatal("expected missing resumable writer to fail")
	}
}

func TestHandleRejectsHiddenOptionalInterface(t *testing.T) {
	t.Parallel()

	implementation := completeDriver{}
	descriptor := fullDescriptor("sequential", "sequential/v1")
	descriptor.Capabilities.Write.Resume = SupportUnavailable
	descriptor.Capabilities.Write.ParallelParts = SupportUnavailable
	descriptor.Capabilities.Write.PartOrdering = PartOrderingNone
	descriptor.Capabilities.Write.MaxParallelParts = 0
	descriptor.Capabilities.Write.UploadSessionTTLSeconds = 0

	handle := Handle{
		Descriptor:      descriptor,
		Reader:          implementation,
		RangeReader:     implementation,
		Writer:          implementation,
		ResumableWriter: implementation,
		Deleter:         implementation,
		Inventory:       implementation,
	}

	if err := handle.Validate(); err == nil {
		t.Fatal("expected undeclared resumable interface to fail")
	}
}
