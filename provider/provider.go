// Package provider defines storage capabilities used by the Carrack SDK.
package provider

import (
	"context"
	"io"
)

// Object describes one immutable provider object.
type Object struct {
	Key       string
	SizeBytes uint64
	ETag      string
	Version   string
}

// PutOptions describes integrity and idempotency metadata for an upload.
type PutOptions struct {
	SizeBytes uint64
	SHA256    string
}

// Reader exposes the minimum source-side capabilities needed by Carrack.
type Reader interface {
	Stat(ctx context.Context, key string) (Object, error)
	OpenRange(ctx context.Context, key string, offset, length uint64) (io.ReadCloser, error)
}

// Writer exposes a streaming destination-side upload operation.
type Writer interface {
	Put(ctx context.Context, key string, body io.Reader, options PutOptions) (Object, error)
}
