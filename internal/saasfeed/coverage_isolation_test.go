package saasfeed

// Isolated deterministic fixtures for paths whose coverage previously depended
// on timing; see roadmap/CI-REDESIGN.md stage 5B.
//
// Both blocks were reached only by TestSyncer_ConfigureAndStop's background
// syncLoop goroutine: Configure starts it, Stop races it, and whether its
// Sync saw the URL already cleared (the empty-URL early return) or tried the
// unreachable localhost:9999 fetch (the fetch-error branch) — or neither,
// before the test binary exited — was decided by the scheduler. The fixtures
// below drive Sync synchronously with an injected transport; no network.

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

// isolationRoundTripper counts calls and returns a fixed transport error.
type isolationRoundTripper struct {
	calls atomic.Int32
	err   error
}

func (rt *isolationRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	return nil, rt.err
}

// Pins saasfeed.go Sync's fetch-error branch
// `resp, err := s.client.Do(req); if err != nil { syncFailures.Add(1); … return }`.
//
// Determinism: the transport fails every round trip with a fixed error, so
// Do returns an error without touching the network.
func TestIsolation_SyncFetchErrorCountsFailureAndMergesNothing(t *testing.T) {
	rt := &isolationRoundTripper{err: errors.New("isolation: dial refused")}
	merged := false
	s := New(Deps{
		Client: &http.Client{Transport: rt},
		Merge:  func([]Category) int { merged = true; return 1 },
	})
	s.SetFeedURLForTest("http://feed.invalid/categories.json")

	before := SyncFailures()
	s.Sync(context.Background())

	if got := rt.calls.Load(); got != 1 {
		t.Fatalf("transport called %d times, want exactly 1 fetch attempt", got)
	}
	// >= rather than ==: syncFailures is package-global, and a syncLoop
	// goroutine leaked by another test in this package may still be finishing
	// its own (failing) round. This test's failure is always counted.
	if delta := SyncFailures() - before; delta < 1 {
		t.Fatalf("SyncFailures delta = %d, want the fetch error counted", delta)
	}
	if merged {
		t.Fatal("merge callback ran after a failed fetch")
	}
	if _, lastSync, count, _ := s.Stats(); !lastSync.IsZero() || count != 0 {
		t.Fatalf("Stats after a failed fetch = (%v, %d), want untouched zero values", lastSync, count)
	}
}

// Pins saasfeed.go Sync `if feedURL == "" { return }` — an unconfigured (or
// stopped) syncer does nothing at all.
//
// Determinism: no URL is ever set, and the transport records any attempt.
func TestIsolation_SyncWithNoURLIsANoOp(t *testing.T) {
	rt := &isolationRoundTripper{err: errors.New("isolation: must not be called")}
	merged := false
	s := New(Deps{
		Client: &http.Client{Transport: rt},
		Merge:  func([]Category) int { merged = true; return 1 },
	})

	s.Sync(context.Background())

	if got := rt.calls.Load(); got != 0 {
		t.Fatalf("transport called %d times with no feed URL, want 0", got)
	}
	if merged {
		t.Fatal("merge callback ran with no feed URL")
	}
	if url, lastSync, count, _ := s.Stats(); url != "" || !lastSync.IsZero() || count != 0 {
		t.Fatalf("Stats after a no-URL Sync = (%q, %v, %d), want all zero", url, lastSync, count)
	}
	if s.Enabled() {
		t.Fatal("Sync enabled an unconfigured syncer")
	}
}
