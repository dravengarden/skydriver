package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dravengarden/carrack/provider"
)

func TestEncryptedCredentialStorePersistsCASRotation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credential.json")
	keyBytes := make([]byte, credentialKeyBytes)
	keyBytes[0] = 1
	key := base64.RawURLEncoding.EncodeToString(keyBytes)

	store, err := newEncryptedCredentialStore(path, key)
	if err != nil {
		t.Fatalf("construct credential store: %v", err)
	}

	initial := json.RawMessage(`{"refresh_token":"first"}`)
	if initializeErr := store.Initialize(context.Background(), initial); initializeErr != nil {
		t.Fatalf("initialize credential store: %v", initializeErr)
	}

	loaded, err := store.Load(context.Background(), cliCredentialReference)
	if err != nil {
		t.Fatalf("load credential store: %v", err)
	}

	if loaded.Revision != 1 || string(loaded.Payload) != string(initial) {
		t.Fatalf("unexpected initial credential: %+v", loaded)
	}

	replacement := json.RawMessage(`{"refresh_token":"second"}`)

	updated, err := store.CompareAndSwap(
		context.Background(),
		cliCredentialReference,
		loaded.Revision,
		replacement,
	)
	if err != nil {
		t.Fatalf("rotate credential: %v", err)
	}

	if updated.Revision != 2 || string(updated.Payload) != string(replacement) {
		t.Fatalf("unexpected rotated credential: %+v", updated)
	}

	if _, staleErr := store.CompareAndSwap(context.Background(), cliCredentialReference, 1, initial); !errors.Is(staleErr, provider.ErrCredentialConflict) {
		t.Fatalf("stale credential revision was not rejected: %v", staleErr)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat credential store: %v", err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential store permissions are %o", info.Mode().Perm())
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read encrypted credential store: %v", err)
	}

	if string(encoded) == string(replacement) || string(encoded) == string(initial) {
		t.Fatal("credential store contains plaintext payload")
	}
}

func TestEncryptedCredentialStoreRejectsWrongKeyAndBroadPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credential.json")
	keyBytes := make([]byte, credentialKeyBytes)
	keyBytes[0] = 1
	key := base64.RawURLEncoding.EncodeToString(keyBytes)

	store, err := newEncryptedCredentialStore(path, key)
	if err != nil {
		t.Fatalf("construct credential store: %v", err)
	}

	if initializeErr := store.Initialize(context.Background(), json.RawMessage(`{"refresh_token":"first"}`)); initializeErr != nil {
		t.Fatalf("initialize credential store: %v", initializeErr)
	}

	wrongKeyBytes := make([]byte, credentialKeyBytes)
	wrongKeyBytes[0] = 2

	wrongStore, err := newEncryptedCredentialStore(
		path,
		base64.RawURLEncoding.EncodeToString(wrongKeyBytes),
	)
	if err != nil {
		t.Fatalf("construct wrong-key store: %v", err)
	}

	if _, err := wrongStore.Load(context.Background(), cliCredentialReference); !errors.Is(err, errCredentialStoreIdentity) {
		t.Fatalf("wrong key was not rejected: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("broaden credential permissions: %v", err)
	}

	if _, err := store.Load(context.Background(), cliCredentialReference); !errors.Is(err, errCredentialStorePermissions) {
		t.Fatalf("broad permissions were not rejected: %v", err)
	}
}
