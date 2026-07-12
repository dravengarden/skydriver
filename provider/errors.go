package provider

import "errors"

// ErrObjectNotFound identifies a provider response that proves the object is absent.
var ErrObjectNotFound = errors.New("carrack provider object not found")
