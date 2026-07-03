package main

// saas_feed_lifecycle_test.go — regression coverage for P6.1 UC-3: the
// globalSaaSFeed.syncLoop goroutine must exit when the application
// lifecycle context (appLifecycleCtx) is cancelled. Before the fix it
// was parented to context.Background() and could only be stopped via an
// explicit Stop() call, so a process shutdown left the goroutine running.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
)

// errRoundTripper makes the syncer's HTTP fetch fail instantly without
// touching the network or the ssrfSafeDialContext guard. The syncLoop's
// initial Sync therefore returns immediately and the loop blocks in its
// select on ticker vs ctx.Done() — the actual surface this test exercises.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("test stub: no real network")
}

// TestUC3_SaaSFeed_ExitsOnAppLifecycleCancel pins the lifecycle contract:
// cancelling appLifecycleCtx must terminate the syncLoop goroutine. With
// the production fix (resolveLifecycleCtx parenting), the test passes
// almost instantly via channel close. Without it (context.Background()
// parenting), the goroutine is detached from app lifecycle and the
// timeout fires — proving the regression-catch.
func TestUC3_SaaSFeed_ExitsOnAppLifecycleCancel(t *testing.T) {
	// Snapshot and restore the package-global lifecycle context, the
	// syncer, and the cleanup we install. Cleanups run in LIFO order, so
	// cancel-test-ctx + Stop run BEFORE we restore the originals.
	origCtx := appLifecycleCtx
	origCancel := appLifecycleCancel
	origFeed := globalSaaSFeed
	t.Cleanup(func() {
		appLifecycleCtx = origCtx
		appLifecycleCancel = origCancel
		globalSaaSFeed = origFeed
	})

	// Fresh syncer with a no-network transport. enabled defaults to false,
	// matching the production zero value (atomic.Bool).
	// interval defaults to 24h in New — the ticker will never fire during
	// the test; enabled defaults to false, matching the production zero
	// value. The lifecycle provider is the production resolveLifecycleCtx
	// so Configure picks up the test-installed appLifecycleCtx.
	globalSaaSFeed = saasfeed.New(saasfeed.Deps{
		Client:    &http.Client{Transport: errRoundTripper{}},
		Lifecycle: resolveLifecycleCtx,
	})

	// Install a test lifecycle context that Configure will pick up via
	// resolveLifecycleCtx().
	testCtx, testCancel := context.WithCancel(context.Background())
	appLifecycleCtx = testCtx
	appLifecycleCancel = testCancel
	// Belt-and-braces cleanup: if the test fails on the timeout path the
	// goroutine is still alive — cancel and drain so it doesn't leak.
	t.Cleanup(func() {
		testCancel()
		if d := globalSaaSFeed.Done(); d != nil {
			select {
			case <-d:
			case <-time.After(2 * time.Second):
			}
		}
	})

	// Start the syncer with a syntactically valid (but unused) URL.
	globalSaaSFeed.Configure("https://example.invalid/saas.json", time.Hour)

	done := globalSaaSFeed.Done()
	if done == nil {
		t.Fatal("Done() returned nil immediately after Configure — syncer did not start")
	}

	// Cancel the application lifecycle. With the fix, the syncLoop's
	// derived context is also cancelled and the goroutine exits.
	testCancel()

	select {
	case <-done:
		// expected — syncLoop observed ctx.Done() and returned, the wrapper
		// goroutine's defer closed the channel.
	case <-time.After(2 * time.Second):
		t.Fatal("syncLoop did not exit within 2s of appLifecycleCtx cancellation — the goroutine is detached from app lifecycle (P6.1 UC-3)")
	}
}
