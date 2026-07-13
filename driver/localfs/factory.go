package localfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dravengarden/carrack/driver"
)

type configuration struct {
	Root string `json:"root"`
}

// Factory opens the versioned local-filesystem driver from one authorized
// control-plane grant. Local filesystems do not accept credential material.
func Factory(_ context.Context, instance driver.Instance) (driver.Handle, error) {
	if instance.Kind != Kind || len(instance.Credential) != 0 {
		return driver.Handle{}, fmt.Errorf("%w: local filesystem kind or credential differs", ErrInvalidConfiguration)
	}

	decoder := json.NewDecoder(bytes.NewReader(instance.Config))
	decoder.DisallowUnknownFields()

	var config configuration
	if err := decoder.Decode(&config); err != nil {
		return driver.Handle{}, fmt.Errorf("%w: decode configuration: %w", ErrInvalidConfiguration, err)
	}

	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return driver.Handle{}, fmt.Errorf("%w: trailing configuration", ErrInvalidConfiguration)
	}

	return Open(instance.ID, config.Root)
}
