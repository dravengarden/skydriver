package cli

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/dravengarden/carrack/provider"
)

const (
	credentialStoreSchema = "carrack.cli-credential.v1" // #nosec G101 -- public schema identifier, not a credential.
	credentialStoreAAD    = "carrack/cli-credential/v1" // #nosec G101 -- public domain separator, not a credential.
	credentialKeyBytes    = 32
)

var (
	errCredentialStorePermissions = errors.New("credential store permissions are too broad")
	errCredentialStoreIdentity    = errors.New("credential store identity changed")
)

type encryptedCredentialStore struct {
	path      string
	reference string
	aead      cipher.AEAD
	mutex     sync.Mutex
}

type encryptedCredentialFile struct {
	SchemaVersion string `json:"schema_version"`
	Reference     string `json:"credential_ref"`
	Revision      uint64 `json:"revision"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

func newEncryptedCredentialStore(
	path,
	encodedKey string,
) (*encryptedCredentialStore, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: path is required", provider.ErrInvalidDriver)
	}

	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != credentialKeyBytes {
		return nil, fmt.Errorf("%w: credential key must encode exactly 32 bytes", provider.ErrInvalidDriver)
	}
	defer clear(key)

	var combined byte
	for _, value := range key {
		combined |= value
	}

	if combined == 0 {
		return nil, fmt.Errorf("%w: credential key must not be zero", provider.ErrInvalidDriver)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("construct credential cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("construct credential AEAD: %w", err)
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve credential store path: %w", err)
	}

	return &encryptedCredentialStore{path: absolutePath, reference: cliCredentialReference, aead: aead}, nil
}

func (store *encryptedCredentialStore) Initialize(
	ctx context.Context,
	payload json.RawMessage,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("initialize credential store: %w", err)
	}

	if !json.Valid(payload) {
		return fmt.Errorf("%w: initial credential must be valid JSON", provider.ErrInvalidDriver)
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	if _, err := os.Stat(store.path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat credential store: %w", err)
	}

	return store.writeLocked(provider.CredentialRecord{Payload: payload, Revision: 1})
}

func (store *encryptedCredentialStore) Load(
	ctx context.Context,
	reference string,
) (provider.CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return provider.CredentialRecord{}, fmt.Errorf("load credential store: %w", err)
	}

	if store == nil || reference != store.reference {
		return provider.CredentialRecord{}, provider.ErrInvalidDriver
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.loadLocked()
}

func (store *encryptedCredentialStore) CompareAndSwap(
	ctx context.Context,
	reference string,
	expectedRevision uint64,
	replacement json.RawMessage,
) (provider.CredentialRecord, error) {
	if err := ctx.Err(); err != nil {
		return provider.CredentialRecord{}, fmt.Errorf("update credential store: %w", err)
	}

	if store == nil || reference != store.reference || !json.Valid(replacement) {
		return provider.CredentialRecord{}, provider.ErrInvalidDriver
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	current, err := store.loadLocked()
	if err != nil {
		return provider.CredentialRecord{}, err
	}

	if current.Revision != expectedRevision {
		return provider.CredentialRecord{}, provider.ErrCredentialConflict
	}

	updated := provider.CredentialRecord{Payload: replacement, Revision: current.Revision + 1}
	if err := store.writeLocked(updated); err != nil {
		return provider.CredentialRecord{}, err
	}

	return updated, nil
}

func (store *encryptedCredentialStore) loadLocked() (provider.CredentialRecord, error) {
	info, err := os.Stat(store.path)
	if err != nil {
		return provider.CredentialRecord{}, fmt.Errorf("stat credential store: %w", err)
	}

	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return provider.CredentialRecord{}, errCredentialStorePermissions
	}

	// #nosec G304 -- the operator explicitly selects the credential store path.
	encoded, err := os.ReadFile(store.path)
	if err != nil {
		return provider.CredentialRecord{}, fmt.Errorf("read credential store: %w", err)
	}

	var encrypted encryptedCredentialFile

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if decodeErr := decoder.Decode(&encrypted); decodeErr != nil {
		return provider.CredentialRecord{}, fmt.Errorf("decode credential store: %w", decodeErr)
	}

	if trailingErr := decoder.Decode(&struct{}{}); !errors.Is(trailingErr, io.EOF) {
		return provider.CredentialRecord{}, fmt.Errorf("decode credential store trailing data: %w", trailingErr)
	}

	if encrypted.SchemaVersion != credentialStoreSchema || encrypted.Reference != store.reference || encrypted.Revision == 0 {
		return provider.CredentialRecord{}, errCredentialStoreIdentity
	}

	nonce, err := base64.RawURLEncoding.DecodeString(encrypted.Nonce)
	if err != nil || len(nonce) != store.aead.NonceSize() {
		return provider.CredentialRecord{}, errCredentialStoreIdentity
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return provider.CredentialRecord{}, errCredentialStoreIdentity
	}

	plaintext, err := store.aead.Open(nil, nonce, ciphertext, store.additionalData(encrypted.Revision))
	if err != nil || !json.Valid(plaintext) {
		return provider.CredentialRecord{}, errCredentialStoreIdentity
	}

	return provider.CredentialRecord{Payload: plaintext, Revision: encrypted.Revision}, nil
}

func (store *encryptedCredentialStore) writeLocked(record provider.CredentialRecord) error {
	nonce := make([]byte, store.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate credential nonce: %w", err)
	}

	ciphertext := store.aead.Seal(nil, nonce, record.Payload, store.additionalData(record.Revision))

	encoded, err := json.Marshal(encryptedCredentialFile{
		SchemaVersion: credentialStoreSchema,
		Reference:     store.reference,
		Revision:      record.Revision,
		Nonce:         base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:    base64.RawURLEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return fmt.Errorf("encode credential store: %w", err)
	}

	directory := filepath.Dir(store.path)
	if mkdirErr := os.MkdirAll(directory, 0o700); mkdirErr != nil {
		return fmt.Errorf("create credential store directory: %w", mkdirErr)
	}

	temporary, err := os.CreateTemp(directory, ".carrack-credential-*")
	if err != nil {
		return fmt.Errorf("create credential store staging file: %w", err)
	}

	temporaryPath := temporary.Name()

	defer func() {
		removeErr := os.Remove(temporaryPath)
		_ = removeErr
	}()

	writeErr := writeCredentialFile(temporary, encoded)
	if writeErr != nil {
		return writeErr
	}

	if renameErr := os.Rename(temporaryPath, store.path); renameErr != nil {
		return fmt.Errorf("publish credential store: %w", renameErr)
	}

	directoryHandle, err := os.Open(directory) // #nosec G304 -- derived from the operator-selected store path.
	if err != nil {
		return fmt.Errorf("open credential store directory: %w", err)
	}

	syncErr := directoryHandle.Sync()

	closeErr := directoryHandle.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync credential store directory: %w", errors.Join(syncErr, closeErr))
	}

	return nil
}

func (store *encryptedCredentialStore) additionalData(revision uint64) []byte {
	return fmt.Appendf(nil, "%s\x00%s\x00%d", credentialStoreAAD, store.reference, revision)
}

func writeCredentialFile(file *os.File, encoded []byte) error {
	if err := file.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("restrict credential store permissions: %w", err), file.Close())
	}

	if _, err := file.Write(encoded); err != nil {
		return errors.Join(fmt.Errorf("write credential store: %w", err), file.Close())
	}

	if err := file.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync credential store: %w", err), file.Close())
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close credential store: %w", err)
	}

	return nil
}
