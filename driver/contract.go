package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrInvalidDriver indicates a missing identity or interface disagreement.
var ErrInvalidDriver = errors.New("invalid Skydriver V2 driver")

// Kind is a versioned compiled driver implementation identifier.
type Kind string

// Locator identifies one complete immutable object inside an opened driver
// instance. StorageKey is the opaque Skydriver-assigned name. NativeID and
// Version retain provider identities needed to reject a changed object.
type Locator struct {
	StorageKey string `json:"storage_key"`
	NativeID   string `json:"native_id,omitempty"`
	Version    string `json:"version,omitempty"`
	ETag       string `json:"etag,omitempty"`
}

// Object describes one complete provider object. SizeBytes is the exact
// encoded length, including encryption framing when enabled.
type Object struct {
	Locator   Locator `json:"locator"`
	SizeBytes uint64  `json:"size_bytes"`
}

// PutRequest describes one complete immutable-object write. StorageKey must be
// a fresh control-plane-assigned opaque name. A successful call must expose
// exactly one complete final object and must never leave partial bytes at that
// final name.
type PutRequest struct {
	StorageKey string
	Body       io.Reader
	SizeBytes  uint64
	Checksum   string
}

// Reader provides the minimum complete-object read contract.
//
// Stat must return a stable identity suitable for a later conditional read.
// Open must read exactly the pinned Object bytes or return an error; it must
// not silently substitute a newer object at the same storage key.
type Reader interface {
	Stat(ctx context.Context, storageKey string) (Object, error)
	Open(ctx context.Context, object Object) (io.ReadCloser, error)
}

// RangeReader is an optional exact-range acceleration interface.
//
// A successful call returns exactly length bytes beginning at offset from the
// pinned Object. A whole-object response, shifted range, short body, changed
// provider version, or overflowing range is an integrity error.
type RangeReader interface {
	OpenRange(ctx context.Context, object Object, offset, length uint64) (io.ReadCloser, error)
}

// Writer atomically publishes one complete immutable provider object.
//
// If the provider accepts the bytes but the response is lost, retry logic must
// recover by statting the fresh StorageKey and verifying exact identity. It
// must not overwrite a different object or report success without verification.
type Writer interface {
	Put(ctx context.Context, request PutRequest) (Object, error)
}

// UploadSession is a durable provider upload identity. Opaque is interpreted
// only by the matching compiled driver and must not contain plaintext keys.
type UploadSession struct {
	ID        string          `json:"id"`
	Opaque    json.RawMessage `json:"opaque,omitempty"`
	ExpiresAt int64           `json:"expires_at,omitempty"`
}

// UploadedPart is one verified provider-side part retained for resume and
// final object completion. Parts cease to be VFS-addressable after completion.
type UploadedPart struct {
	Number   uint32 `json:"number"`
	Offset   uint64 `json:"offset"`
	Length   uint64 `json:"length"`
	Checksum string `json:"checksum"`
	ETag     string `json:"etag,omitempty"`
}

// BeginUploadRequest fixes the final object identity and exact encoded length
// before resumable payload I/O starts.
type BeginUploadRequest struct {
	StorageKey string
	SizeBytes  uint64
	Checksum   string
}

// PutPartRequest writes one exact part. Replaying the same session, part
// number, range, and checksum must be idempotent. Conflicting bytes for an
// existing part number must fail visibly.
type PutPartRequest struct {
	Session UploadSession
	Part    UploadedPart
	Body    io.Reader
}

// CompleteUploadRequest publishes the ordered parts as one complete object.
// The complete checksum and exact length must be revalidated before success.
type CompleteUploadRequest struct {
	Session   UploadSession
	Parts     []UploadedPart
	SizeBytes uint64
	Checksum  string
}

// ResumableWriter is an optional durable upload-session interface.
//
// Sessions and completed parts must remain queryable across client restarts.
// ListParts is authoritative for recovery. Complete must publish exactly one
// final object, while Abort must never delete an already completed object.
type ResumableWriter interface {
	BeginUpload(ctx context.Context, request BeginUploadRequest) (UploadSession, error)
	ListParts(ctx context.Context, session UploadSession) ([]UploadedPart, error)
	PutPart(ctx context.Context, request PutPartRequest) (UploadedPart, error)
	CompleteUpload(ctx context.Context, request CompleteUploadRequest) (Object, error)
	AbortUpload(ctx context.Context, session UploadSession) error
}

// Deleter removes one exact immutable object idempotently. A missing object is
// success. Callers must obtain a fenced control-plane delete authorization
// immediately before invoking this interface.
type Deleter interface {
	Delete(ctx context.Context, object Object) error
}

// Inventory lists bounded pages beneath the driver's reserved Skydriver root.
// Results must be normalized to a strict, stable StorageKey order.
type Inventory interface {
	List(ctx context.Context, cursor string, limit uint32) ([]Object, string, error)
}

// Descriptor identifies one opened instance and its effective, fully probed
// capabilities. Summary is a short human-readable driver description used by
// generated documentation and replacement advice.
type Descriptor struct {
	ID           string       `json:"id"`
	Kind         Kind         `json:"kind"`
	Summary      string       `json:"summary"`
	Capabilities Capabilities `json:"capabilities"`
}

// Validate rejects missing identities and invalid capability declarations.
func (descriptor Descriptor) Validate() error {
	if strings.TrimSpace(descriptor.ID) == "" {
		return fmt.Errorf("%w: driver ID is required", ErrInvalidDriver)
	}

	if strings.TrimSpace(string(descriptor.Kind)) == "" {
		return fmt.Errorf("%w: driver kind is required", ErrInvalidDriver)
	}

	if strings.TrimSpace(descriptor.Summary) == "" {
		return fmt.Errorf("%w: driver summary is required", ErrInvalidDriver)
	}

	if err := descriptor.Capabilities.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDriver, err)
	}

	return nil
}

// Handle contains the required and optional interfaces for one opened driver.
// Validate proves that every advertised capability has a matching interface
// and that no hidden interface bypasses capability assessment and warnings.
type Handle struct {
	Descriptor      Descriptor
	Reader          Reader
	RangeReader     RangeReader
	Writer          Writer
	ResumableWriter ResumableWriter
	Deleter         Deleter
	Inventory       Inventory
}

// Validate checks descriptor and interface agreement before planning any I/O.
func (handle Handle) Validate() error {
	if err := handle.Descriptor.Validate(); err != nil {
		return err
	}

	capabilities := handle.Descriptor.Capabilities
	checks := []struct {
		name      string
		available bool
		present   bool
	}{
		{name: "complete reader", available: capabilities.Read.Complete.Available(), present: handle.Reader != nil},
		{name: "range reader", available: capabilities.Read.Range.Available(), present: handle.RangeReader != nil},
		{name: "complete writer", available: capabilities.Write.Complete.Available(), present: handle.Writer != nil},
		{name: "resumable writer", available: capabilities.Write.Resume.Available(), present: handle.ResumableWriter != nil},
		{name: "deleter", available: capabilities.Delete.Available(), present: handle.Deleter != nil},
		{name: "inventory", available: capabilities.Inventory.Available(), present: handle.Inventory != nil},
	}

	for _, check := range checks {
		if check.available != check.present {
			return fmt.Errorf("%w: %s capability and interface disagree", ErrInvalidDriver, check.name)
		}
	}

	return nil
}
