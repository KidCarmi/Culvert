package feedsync

// Sync-cadence and sync-health gates for the UT1 community category feed.
//
// The finding these pin: internal/feedsync scheduled itself with a bare
// time.NewTicker(24h), so one failed round froze category coverage for a full
// DAY, and every node in a fleet fetched the same 50+ MB tarball from the same
// third-party mirror at the same moment forever — the rate-limit that causes
// the failure the missing backoff then holds for 24 hours.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsched"
)

// TestScheduler_FailedRoundRetriesLongBeforeTheInterval is the DEFECT GATE.
// A bare 24h ticker returns 24h here by construction.
func TestScheduler_FailedRoundRetriesLongBeforeTheInterval(t *testing.T) {
	fs := New(nil, "", 24*time.Hour)
	s := feedsched.New(fs.schedulerConfig())

	if got := s.NextDelay(true); got < 20*time.Hour || got > 28*time.Hour {
		t.Fatalf("delay after a clean round = %s, want ~24h (the configured interval, jittered)", got)
	}
	first := s.NextDelay(false)
	if first >= 24*time.Hour {
		t.Fatalf("delay after a FAILED round = %s — a failure must not wait a full day", first)
	}
	if first < time.Minute {
		t.Fatalf("delay after a failed round = %s — that is a hot loop against the third-party mirror", first)
	}
	for i := 0; i < 10; i++ {
		if d := s.NextDelay(false); d >= 24*time.Hour {
			t.Fatalf("backoff step %d reached %s — the ceiling must stay below the interval", i, d)
		}
	}
}

// TestRetryBoundsAreSaneRelativeToTheInterval is the CONTROL: the fix must not
// be "retry immediately" against a 50+ MB object on a shared public mirror.
func TestRetryBoundsAreSaneRelativeToTheInterval(t *testing.T) {
	if syncRetryMin < 5*time.Minute {
		t.Fatalf("syncRetryMin = %s — too aggressive for a 50+ MB tarball on a shared mirror", syncRetryMin)
	}
	if syncRetryMin > syncRetryMax {
		t.Fatalf("syncRetryMin %s > syncRetryMax %s", syncRetryMin, syncRetryMax)
	}
	if syncRetryMax >= 24*time.Hour {
		t.Fatalf("syncRetryMax %s is not below the default 24h interval — retrying would loosen the cadence", syncRetryMax)
	}
}

// TestSyncRound_FailureIsCountedAndClassified — the failure must be visible.
// Pre-fix the only record was a cumulative counter with no reason, no
// consecutive run, and no attempt timestamp, so "failing every round for a
// week" and "failed twice last month" were indistinguishable.
func TestSyncRound_FailureIsCountedAndClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	before := SyncFailures()
	fs := New(nil, srv.URL, time.Hour)

	if ok := fs.syncRound(); ok {
		t.Fatal("syncRound reported success against a 503 origin")
	}
	h := fs.Health()
	if h.ConsecutiveFailures != 1 {
		t.Fatalf("ConsecutiveFailures = %d, want 1", h.ConsecutiveFailures)
	}
	if h.LastFailure != failDownload {
		t.Fatalf("LastFailure = %q, want %q", h.LastFailure, failDownload)
	}
	if h.LastAttempt.IsZero() {
		t.Fatal("LastAttempt is zero after a round — a failing feed must be distinguishable from one that never ran")
	}
	if !h.LastSuccess.IsZero() {
		t.Fatalf("LastSuccess = %s after a failed round, want zero", h.LastSuccess)
	}
	if SyncFailures() != before+1 {
		t.Fatalf("SyncFailures = %d, want %d", SyncFailures(), before+1)
	}

	// A second failure accumulates rather than resetting.
	fs.syncRound()
	if got := fs.Health().ConsecutiveFailures; got != 2 {
		t.Fatalf("ConsecutiveFailures = %d after two failed rounds, want 2", got)
	}
}

// TestLastFailureIsBounded — the reason class must never carry the feed URL or
// an error string, for the same alert-dedup and disclosure reasons the threat
// feed's classification carries.
func TestLastFailureIsBounded(t *testing.T) {
	allowed := map[string]bool{"": true, failDownload: true, failWrite: true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	fs := New(nil, srv.URL, time.Hour)
	fs.syncRound()
	if got := fs.Health().LastFailure; !allowed[got] {
		t.Fatalf("LastFailure = %q, which is outside the bounded value set", got)
	}
}

// TestHealth_OnAFreshSyncerIsZeroNotGarbage — Health is read at scrape time on
// a syncer that may never have run; it must not panic on the unset atomics.
func TestHealth_OnAFreshSyncerIsZeroNotGarbage(t *testing.T) {
	fs := New(nil, "http://example.invalid/x.tar.gz", 24*time.Hour)
	h := fs.Health()
	if !h.LastSuccess.IsZero() || !h.LastAttempt.IsZero() {
		t.Fatalf("fresh syncer reports LastSuccess=%s LastAttempt=%s, want zero", h.LastSuccess, h.LastAttempt)
	}
	if h.ConsecutiveFailures != 0 || h.LastFailure != "" {
		t.Fatalf("fresh syncer reports failures: %+v", h)
	}
	if h.SyncInterval != 24*time.Hour {
		t.Fatalf("SyncInterval = %s, want 24h", h.SyncInterval)
	}
}
