package sdk_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dravengarden/carrack/provider"
)

var errInjectedJanitorCrash = errors.New("injected Carrack janitor crash")

type janitorCrashPoint string

const (
	crashBeforeDeleteClaim      janitorCrashPoint = "before_delete_claim"
	crashAfterDeleteClaim       janitorCrashPoint = "after_delete_claim"
	crashBeforeDeleteRevalidate janitorCrashPoint = "before_delete_revalidate"
	crashAfterDeleteRevalidate  janitorCrashPoint = "after_delete_revalidate"
	crashBeforeProviderDelete   janitorCrashPoint = "before_provider_delete"
	crashAfterProviderDelete    janitorCrashPoint = "after_provider_delete"
	crashBeforeDeleteCompletion janitorCrashPoint = "before_delete_completion"
	crashAfterDeleteCompletion  janitorCrashPoint = "after_delete_completion"
)

type janitorCrashScript struct {
	mutex  sync.Mutex
	target janitorCrashPoint
	fired  bool
}

func (script *janitorCrashScript) hit(point janitorCrashPoint) error {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	if script.fired || point != script.target {
		return nil
	}

	script.fired = true

	return fmt.Errorf("%w: %s", errInjectedJanitorCrash, point)
}

func (script *janitorCrashScript) didFire() bool {
	script.mutex.Lock()
	defer script.mutex.Unlock()

	return script.fired
}

type janitorCrashRoundTripper struct {
	base   http.RoundTripper
	script *janitorCrashScript
}

func (transport *janitorCrashRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	before, after, controlled := janitorHTTPPoints(request.URL.Path)
	if controlled {
		if err := transport.script.hit(before); err != nil {
			return nil, err
		}
	}

	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}

	if controlled {
		if crashErr := transport.script.hit(after); crashErr != nil {
			return nil, errors.Join(crashErr, response.Body.Close())
		}
	}

	return response, nil
}

func janitorHTTPPoints(path string) (janitorCrashPoint, janitorCrashPoint, bool) {
	switch {
	case strings.HasSuffix(path, "deletes/claim"):
		return crashBeforeDeleteClaim, crashAfterDeleteClaim, true
	case strings.HasSuffix(path, "deletes/revalidate"):
		return crashBeforeDeleteRevalidate, crashAfterDeleteRevalidate, true
	case strings.HasSuffix(path, "deletes/complete"):
		return crashBeforeDeleteCompletion, crashAfterDeleteCompletion, true
	default:
		return "", "", false
	}
}

func janitorCrashPoints() []janitorCrashPoint {
	return []janitorCrashPoint{
		crashBeforeDeleteClaim,
		crashAfterDeleteClaim,
		crashBeforeDeleteRevalidate,
		crashAfterDeleteRevalidate,
		crashBeforeProviderDelete,
		crashAfterProviderDelete,
		crashBeforeDeleteCompletion,
		crashAfterDeleteCompletion,
	}
}

type providerObjectJanitorCrashFixture struct {
	server  *httptest.Server
	deleter *recordingDeleter
	sweep   func(context.Context) (string, error)
}

func TestMoveJanitorCrashMatrixConvergesEveryDeleteBoundary(t *testing.T) {
	t.Parallel()

	testProviderObjectJanitorCrashMatrix(t, func(t *testing.T) providerObjectJanitorCrashFixture {
		t.Helper()

		fixture := newMoveJanitorFixture(t, false, nil)

		return providerObjectJanitorCrashFixture{
			server: fixture.server, deleter: fixture.deleter,
			sweep: func(ctx context.Context) (string, error) {
				result, err := fixture.janitor.SweepMove(ctx, fixture.operationID)

				return result.State, err
			},
		}
	})
}

func TestGCJanitorCrashMatrixConvergesEveryDeleteBoundary(t *testing.T) {
	t.Parallel()

	testProviderObjectJanitorCrashMatrix(t, func(t *testing.T) providerObjectJanitorCrashFixture {
		t.Helper()

		fixture := newGCJanitorFixture(t, nil)

		return providerObjectJanitorCrashFixture{
			server: fixture.server, deleter: fixture.deleter,
			sweep: func(ctx context.Context) (string, error) {
				result, err := fixture.janitor.Sweep(ctx, fixture.operationID)

				return result.State, err
			},
		}
	})
}

func testProviderObjectJanitorCrashMatrix(
	t *testing.T,
	factory func(*testing.T) providerObjectJanitorCrashFixture,
) {
	t.Helper()

	for _, point := range janitorCrashPoints() {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			fixture := factory(t)
			script := &janitorCrashScript{target: point}
			installJanitorCrashTransport(fixture.server, script)
			fixture.deleter.setCrashScript(script)

			_, firstErr := fixture.sweep(context.Background())
			if !errors.Is(firstErr, errInjectedJanitorCrash) {
				t.Fatalf("first janitor sweep did not stop at %s: %v", point, firstErr)
			}

			state, retryErr := fixture.sweep(context.Background())
			if retryErr != nil || state != "succeeded" {
				t.Fatalf("janitor did not converge after %s: state=%s err=%v", point, state, retryErr)
			}

			if !script.didFire() {
				t.Fatalf("janitor crash point %s was never reached", point)
			}

			expectedDeletes := expectedProviderDeleteCalls(point)
			if fixture.deleter.callCount() != expectedDeletes {
				t.Fatalf(
					"janitor performed %d provider deletes after %s; want %d",
					fixture.deleter.callCount(),
					point,
					expectedDeletes,
				)
			}
		})
	}
}

func expectedProviderDeleteCalls(point janitorCrashPoint) int {
	switch point {
	case crashAfterProviderDelete, crashBeforeDeleteCompletion:
		return 2
	case crashBeforeDeleteClaim,
		crashAfterDeleteClaim,
		crashBeforeDeleteRevalidate,
		crashAfterDeleteRevalidate,
		crashBeforeProviderDelete,
		crashAfterDeleteCompletion:
		return 1
	default:
		return 0
	}
}

func TestQuarantineJanitorCrashMatrixConvergesWithoutRepeatedPhysicalDelete(t *testing.T) {
	t.Parallel()

	for _, point := range janitorCrashPoints() {
		t.Run(string(point), func(t *testing.T) {
			t.Parallel()

			fixture := newQuarantineJanitorFixture(t, provider.Object{
				Key: "archive/orphan", SizeBytes: 19,
				Version: "orphan-v1", ETag: "orphan-etag",
			}, nil)
			script := &janitorCrashScript{target: point}
			installJanitorCrashTransport(fixture.server, script)
			fixture.target.enableCrashDelete(script)

			_, firstErr := fixture.janitor.Sweep(context.Background(), fixture.operationID)
			if !errors.Is(firstErr, errInjectedJanitorCrash) {
				t.Fatalf("first quarantine sweep did not stop at %s: %v", point, firstErr)
			}

			result, retryErr := fixture.janitor.Sweep(context.Background(), fixture.operationID)
			if retryErr != nil || result.State != "deleted" ||
				result.ObjectsDeleted+result.AlreadyAbsent != 1 {
				t.Fatalf(
					"quarantine janitor did not converge after %s: result=%+v err=%v",
					point,
					result,
					retryErr,
				)
			}

			if !script.didFire() || fixture.target.deleteCount() != 1 {
				t.Fatalf(
					"quarantine delete was not exactly once after %s: fired=%v deletes=%d",
					point,
					script.didFire(),
					fixture.target.deleteCount(),
				)
			}
		})
	}
}

func installJanitorCrashTransport(server *httptest.Server, script *janitorCrashScript) {
	client := server.Client()
	client.Transport = &janitorCrashRoundTripper{base: client.Transport, script: script}
}
