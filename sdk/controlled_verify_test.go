package sdk_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dravengarden/carrack/manifest"
	"github.com/dravengarden/carrack/provider"
	"github.com/dravengarden/carrack/sdk"
)

type blockingVerificationReader struct {
	started chan<- struct{}
}

func (reader blockingVerificationReader) Stat(context.Context, string) (provider.Object, error) {
	return provider.Object{}, errUnexpectedVerificationStat
}

func (reader blockingVerificationReader) OpenRange(
	ctx context.Context,
	_ string,
	_, _ uint64,
) (io.ReadCloser, error) {
	select {
	case reader.started <- struct{}{}:
	default:
	}

	<-ctx.Done()

	return nil, ctx.Err()
}

func TestControlledVerifierCommitsCompleteDriverEvidence(t *testing.T) {
	payload := bytes.Repeat([]byte{'v'}, 18)
	digest := sha256.Sum256(payload)
	recovery := verificationRecovery(t, hex.EncodeToString(digest[:]), []manifest.Location{{
		DriverID: "memory", StorageKey: "extent", Length: uint64(len(payload)),
	}})
	token, encodedToken := testClientToken(t)

	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
		leaseID     = "operation/909192939495969798999a9b9c9d9e9f/write"
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		var value any

		switch request.URL.Path {
		case "/api/v1/verifications":
			value = sdk.VerifyOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "verify", State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(payload)),
				VersionID: "version-1", ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 1, DriverID: "memory", CreatedAt: 1, UpdatedAt: 1,
			}
		case "/api/v1/operations/" + operationID + "/claim":
			value = sdk.OperationLease{
				OperationID: operationID, LeaseID: leaseID, OwnerClientID: "client-1",
				Incarnation: incarnation, FencingToken: 1, ExpiresAt: 100,
				OperationRevision: 2, OperationState: "running",
			}
		case "/api/v1/verifications/" + operationID + "/manifest":
			value = recovery
		case "/api/v1/verifications/" + operationID + "/complete":
			var body struct {
				Evidence []sdk.VerificationEvidence `json:"evidence"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode completion: %v", err)
			}

			if len(body.Evidence) != 1 || body.Evidence[0].Condition != sdk.VerificationVerified {
				t.Errorf("unexpected completion evidence: %+v", body.Evidence)
			}

			value = sdk.CompletedVerify{
				OperationID: operationID, ManifestSHA256: recovery.ManifestSHA256,
				State: "succeeded", Verified: 1,
			}
		default:
			http.NotFound(response, request)

			return
		}

		if err := json.NewEncoder(response).Encode(value); err != nil {
			t.Errorf("encode controlled verify response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{
		"memory": verificationReader{data: payload},
	})
	if err != nil {
		t.Fatalf("construct verifier: %v", err)
	}

	coordinator, err := sdk.NewControlledVerifier(control, verifier, 60, time.Second)
	if err != nil {
		t.Fatalf("construct controlled verifier: %v", err)
	}

	result, err := coordinator.Verify(context.Background(), sdk.ControlledVerifyRequest{
		NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
		DriverID: "memory", IdempotencyKey: "verify-memory-version-1",
	})
	if err != nil {
		t.Fatalf("run controlled verify: %v", err)
	}

	if result.Verification.Verified != 1 || result.Completion.Verified != 1 {
		t.Fatalf("unexpected controlled verify result: %+v", result)
	}
}

func TestControlledVerifierCancelsProviderReadWhenLeaseIsLost(t *testing.T) {
	payload := bytes.Repeat([]byte{'v'}, 18)
	digest := sha256.Sum256(payload)
	recovery := verificationRecovery(t, hex.EncodeToString(digest[:]), []manifest.Location{{
		DriverID: "memory", StorageKey: "extent", Length: uint64(len(payload)),
	}})
	token, encodedToken := testClientToken(t)
	started := make(chan struct{}, 1)

	const (
		operationID = "909192939495969798999a9b9c9d9e9f"
		incarnation = "0123456789abcdef0123456789abcdef"
	)

	var (
		claims      atomic.Uint64
		completions atomic.Uint64
	)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+encodedToken {
			http.Error(response, "invalid authorization", http.StatusUnauthorized)

			return
		}

		response.Header().Set("Content-Type", "application/json")

		switch request.URL.Path {
		case "/api/v1/verifications":
			_ = json.NewEncoder(response).Encode(sdk.VerifyOperation{
				ID: operationID, NamespaceID: recovery.Manifest.NamespaceID,
				Kind: "verify", State: "planned", Phase: "planned", RequestedBy: "client-1",
				Incarnation: incarnation, Revision: 1, UsefulBytesTotal: uint64(len(payload)),
				VersionID: "version-1", ManifestSHA256: recovery.ManifestSHA256,
				RecoveryRevision: 1, DriverID: "memory", CreatedAt: 1, UpdatedAt: 1,
			})
		case "/api/v1/operations/" + operationID + "/claim":
			if claims.Add(1) > 1 {
				http.Error(response, "lease lost", http.StatusConflict)

				return
			}

			_ = json.NewEncoder(response).Encode(sdk.OperationLease{
				OperationID: operationID, LeaseID: "operation/" + operationID + "/write",
				OwnerClientID: "client-1", Incarnation: incarnation, FencingToken: 1,
				ExpiresAt: 100, OperationRevision: 2, OperationState: "running",
			})
		case "/api/v1/verifications/" + operationID + "/manifest":
			_ = json.NewEncoder(response).Encode(recovery)
		case "/api/v1/verifications/" + operationID + "/complete":
			completions.Add(1)
			http.Error(response, "unexpected completion", http.StatusConflict)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	control, err := sdk.NewControlClient(server.URL, token, server.Client())
	if err != nil {
		t.Fatalf("construct control client: %v", err)
	}

	verifier, err := sdk.NewVerifier(map[string]provider.Reader{
		"memory": blockingVerificationReader{started: started},
	})
	if err != nil {
		t.Fatalf("construct verifier: %v", err)
	}

	coordinator, err := sdk.NewControlledVerifier(control, verifier, 60, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("construct controlled verifier: %v", err)
	}

	_, err = coordinator.Verify(context.Background(), sdk.ControlledVerifyRequest{
		NamespaceID: recovery.Manifest.NamespaceID, ManifestSHA256: recovery.ManifestSHA256,
		DriverID: "memory", IdempotencyKey: "verify-memory-version-1",
	})
	if !errors.Is(err, sdk.ErrVerifyLeaseLost) {
		t.Fatalf("expected ErrVerifyLeaseLost, got %v", err)
	}

	if len(started) == 0 || completions.Load() != 0 {
		t.Fatalf("provider cancellation/completion mismatch: started=%d completions=%d", len(started), completions.Load())
	}
}
