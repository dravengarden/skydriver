package aliyundrive

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dravengarden/carrack/driver"
)

func TestFactoryDeclaresConservativeCapabilities(t *testing.T) {
	t.Parallel()

	handle, err := Factory(context.Background(), driver.Instance{
		ID:         "aliyun-main",
		Kind:       Kind,
		Revision:   1,
		Config:     json.RawMessage(`{"drive_type":"resource","root_folder_id":"root"}`),
		Credential: json.RawMessage(`{"access_token":"secret-token"}`),
	})
	if err != nil {
		t.Fatalf("open Aliyun Drive VFS driver: %v", err)
	}

	if err := handle.Validate(); err != nil {
		t.Fatalf("validate Aliyun Drive VFS handle: %v", err)
	}

	capabilities := handle.Descriptor.Capabilities
	if capabilities.Read.Complete != driver.SupportNative ||
		capabilities.Read.Range != driver.SupportNative ||
		capabilities.Write.Complete != driver.SupportNative ||
		capabilities.Write.Resume != driver.SupportUnavailable ||
		capabilities.Delete != driver.SupportUnavailable ||
		capabilities.Inventory != driver.SupportUnavailable ||
		!capabilities.Integrity.RequiresReadback {
		t.Fatalf("unexpected Aliyun Drive VFS capabilities: %+v", capabilities)
	}
}

func TestFactoryRejectsUnknownAndRefreshCredentialFields(t *testing.T) {
	t.Parallel()

	for name, credential := range map[string]json.RawMessage{
		"refresh token":      json.RawMessage(`{"refresh_token":"not-durably-rotatable"}`),
		"unknown field":      json.RawMessage(`{"access_token":"token","unknown":true}`),
		"empty access token": json.RawMessage(`{"access_token":""}`),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := Factory(context.Background(), driver.Instance{
				ID:         "aliyun-main",
				Kind:       Kind,
				Revision:   1,
				Config:     json.RawMessage(`{}`),
				Credential: credential,
			})
			if err == nil {
				t.Fatal("unsafe Aliyun Drive credential was accepted")
			}
		})
	}
}

func TestFactoryRejectsUnknownConfigurationFields(t *testing.T) {
	t.Parallel()

	_, err := Factory(context.Background(), driver.Instance{
		ID:         "aliyun-main",
		Kind:       Kind,
		Revision:   1,
		Config:     json.RawMessage(`{"root_folder_id":"root","bucket":"wrong-provider"}`),
		Credential: json.RawMessage(`{"access_token":"token"}`),
	})
	if err == nil {
		t.Fatal("unknown Aliyun Drive configuration was accepted")
	}
}
