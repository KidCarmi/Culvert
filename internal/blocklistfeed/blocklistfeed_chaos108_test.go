package blocklistfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsched"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// CHAOS-108 gates. The subject is the cadence of the FOURTH feed loop — the
// one internal/feedsched was written for and never applied to — plus the HTTP
// status gate its three siblings already had.
//
// Every cadence assertion drives the due-check through the clock seam rather
// than sleeping, the way internal/feedsched's own tests do. Jitter is pinned
// to identity where a delay is compared against a bound, and left at the
// production StableJitter in the one test whose subject IS the spread.

// fakeClock is a hand-advanced clock for the due-check.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// noJitter makes a computed delay exactly comparable to its bound.
func noJitter(d time.Duration) time.Duration { return d }

// newTestSyncer returns a syncer on a fixed clock with jitter disabled.
func newTestSyncer(t *testing.T, m Merger) (*Syncer, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	bs := New(m)
	bs.now = clk.Now
	bs.jitter = noJitter
	return bs, clk
}

// failingOrigin serves status for every request and counts the hits.
func failingOrigin(t *testing.T, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "origin unavailable", status)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestChaos108_FailedSyncRetriesBeforeTheConfiguredInterval is the core gate.
// Pre-fix, SyncFeed stamped lastAttempt on the error path and the due-check
// read it against the interval, so one failure bought a full interval of
// silence — 24h on a stock install.
func TestChaos108_FailedSyncRetriesBeforeTheConfiguredInterval(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv, _ := failingOrigin(t, http.StatusServiceUnavailable)

	const interval = 24 * time.Hour
	bs, clk := newTestSyncer(t, &fakeMerger{})
	bs.SetFeed(srv.URL, interval)

	if _, err := bs.SyncFeed(srv.URL); err == nil {
		t.Fatal("a 503 from the origin must be an error, not a successful sync")
	}

	// Not due immediately: a retry is a tightened cadence, not a hot loop.
	if due := bs.dueURLs(clk.Now()); len(due) != 0 {
		t.Errorf("feed is due again with zero delay after a failure: %v — that is a hot loop against the origin", due)
	}

	// Due well inside the configured interval. The ladder's first rung is
	// feedsched.DefaultBackoffMin; anything at or past the interval is the
	// pre-fix behaviour.
	clk.advance(feedsched.DefaultBackoffMin)
	due := bs.dueURLs(clk.Now())
	if len(due) != 1 || due[0] != srv.URL {
		t.Fatalf("feed not retried %v after a failed sync: due = %v; pre-fix it waited the full %v",
			feedsched.DefaultBackoffMin, due, interval)
	}
}

// TestChaos108_BootFailureDoesNotCostAFullDay is the worst shape: the node
// boots into a feed outage, so the feed has merged NOTHING, and the retry is
// what decides whether the gateway runs a day with that deny list absent.
func TestChaos108_BootFailureDoesNotCostAFullDay(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			http.Error(w, "origin unavailable", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ads.invalid\ntracker.invalid\n"))
	}))
	defer srv.Close()

	fm := &fakeMerger{added: 2}
	bs, clk := newTestSyncer(t, fm)
	bs.SetFeed(srv.URL, 24*time.Hour)

	// The boot pass runs because nothing has been attempted yet, and fails.
	bs.syncDue(context.Background())
	if fm.calls != 0 {
		t.Fatalf("a failed boot fetch merged %d time(s); an error response must never reach the blocklist", fm.calls)
	}
	if f := bs.Feeds()[0]; f.LastError == "" || !f.LastSync.IsZero() {
		t.Errorf("failed boot sync reported as healthy: %+v", f)
	}

	// The origin recovers. Within the backoff window — NOT a day — the
	// scheduler must pick the feed back up on its own.
	up.Store(true)
	clk.advance(feedsched.DefaultBackoffMin)
	bs.syncDue(context.Background())

	if fm.calls != 1 {
		t.Fatalf("feed not re-synced %v after the origin recovered (merge calls = %d); the node would serve without this deny list for the full interval",
			feedsched.DefaultBackoffMin, fm.calls)
	}
	if f := bs.Feeds()[0]; f.LastError != "" || f.LastSync.IsZero() || f.ImportedCount != 2 {
		t.Errorf("recovered sync not recorded: %+v", f)
	}
}

// TestChaos108_BackoffGrowsBoundedAndResetsOnSuccess pins the ladder: it
// doubles, it is capped, and one success clears it.
func TestChaos108_BackoffGrowsBoundedAndResetsOnSuccess(t *testing.T) {
	const interval = 24 * time.Hour
	bs, clk := newTestSyncer(t, &fakeMerger{})
	bs.SetFeed("https://feeds.example/a.txt", interval)
	bs.mu.Lock()
	st := bs.feeds["https://feeds.example/a.txt"]
	st.lastAttempt = clk.Now()
	bs.mu.Unlock()

	var prev time.Duration
	for i := 1; i <= 8; i++ {
		bs.mu.Lock()
		d := bs.scheduleNextLocked(st, false)
		bs.mu.Unlock()
		if d <= 0 {
			t.Fatalf("failure %d produced a non-positive delay %v (a hot loop)", i, d)
		}
		if d > feedsched.DefaultBackoffMax {
			t.Fatalf("failure %d delay %v exceeds the ceiling %v", i, d, feedsched.DefaultBackoffMax)
		}
		if d >= interval {
			t.Fatalf("failure %d delay %v is not shorter than the configured interval %v — retrying must TIGHTEN the cadence", i, d, interval)
		}
		if i > 1 && d < prev {
			t.Fatalf("failure %d delay %v went backwards from %v", i, d, prev)
		}
		prev = d
	}
	if prev != feedsched.DefaultBackoffMax {
		t.Errorf("ladder settled at %v, want the ceiling %v", prev, feedsched.DefaultBackoffMax)
	}

	// One success returns the feed to its steady-state cadence.
	bs.mu.Lock()
	d := bs.scheduleNextLocked(st, true)
	bs.mu.Unlock()
	if d != interval {
		t.Errorf("delay after a successful round = %v, want the configured interval %v", d, interval)
	}
}

// TestChaos108_RetryNeverLoosensTheCadence covers the interval-aware FLOOR
// clamp. With an interval shorter than BackoffMin, clamping only the ceiling
// would make a failed round wait longer than a healthy one — the regression
// feedsched itself shipped once (its backoffBounds comment records it).
func TestChaos108_RetryNeverLoosensTheCadence(t *testing.T) {
	const interval = time.Minute // far below feedsched.DefaultBackoffMin
	bs, clk := newTestSyncer(t, &fakeMerger{})
	bs.SetFeed("https://feeds.example/fast.txt", interval)
	bs.mu.Lock()
	st := bs.feeds["https://feeds.example/fast.txt"]
	st.lastAttempt = clk.Now()
	for i := 0; i < 5; i++ {
		if d := bs.scheduleNextLocked(st, false); d > interval {
			bs.mu.Unlock()
			t.Fatalf("failure %d waited %v against a %v interval — a retry must never be slower than a healthy sync", i+1, d, interval)
		}
	}
	bs.mu.Unlock()
}

// TestChaos108_SteadyStateCadenceIsSpreadAcrossNodes covers the fleet-phase
// half. Pre-fix the cadence was unjittered and its phase was pinned at boot,
// so nodes restarted together synced together against a third-party origin
// forever. Uses the PRODUCTION jitter, since the spread is the subject.
func TestChaos108_SteadyStateCadenceIsSpreadAcrossNodes(t *testing.T) {
	const interval = 24 * time.Hour
	const nodes = 8
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	seen := map[time.Duration]int{}
	for i := 0; i < nodes; i++ {
		bs := New(&fakeMerger{}) // production jitter: bs.jitter stays nil
		bs.now = func() time.Time { return at }
		bs.SetFeed("https://feeds.example/a.txt", interval)
		bs.mu.Lock()
		st := bs.feeds["https://feeds.example/a.txt"]
		st.lastAttempt = at
		d := bs.scheduleNextLocked(st, true)
		bs.mu.Unlock()
		seen[d]++
		// The offset is a spread around the operator's interval, not a
		// licence to drift far from it.
		if d < interval/2 || d > interval*2 {
			t.Fatalf("node %d scheduled its next sync at %v, implausibly far from the configured %v", i, d, interval)
		}
	}
	if len(seen) < 2 {
		t.Errorf("all %d nodes scheduled the identical delay %v — the fleet is in phase against the feed origin", nodes, seen)
	}
}

// TestChaos108_ErrorResponseIsNotMergedAndNotReportedHealthy is the status
// gate. Pre-fix the body of a 4xx/5xx was scanned and merged —
// blocklist.NormalizeLine takes fields[0] of any line — while the feed
// recorded a clean sync.
func TestChaos108_ErrorResponseIsNotMergedAndNotReportedHealthy(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			// Shaped like a real error page: every line would normalize to a
			// host and be listed, permanently, on a deny control.
			_, _ = w.Write([]byte("<html>\n<head><title>503 Service Unavailable</title></head>\nupstream down\n</html>\n"))
		}))

		fm := &fakeMerger{added: 4}
		bs, _ := newTestSyncer(t, fm)
		bs.SetFeed(srv.URL, time.Hour)

		added, err := bs.SyncFeed(srv.URL)
		if err == nil {
			t.Errorf("HTTP %d accepted as a successful feed body", status)
		}
		if fm.calls != 0 || added != 0 {
			t.Errorf("HTTP %d error page reached the blocklist (%d merge call(s), %d added)", status, fm.calls, added)
		}
		f := bs.Feeds()[0]
		if f.LastError == "" {
			t.Errorf("HTTP %d left LastError empty — the admin API would report a healthy feed", status)
		}
		if !f.LastSync.IsZero() {
			t.Errorf("HTTP %d advanced LastSync — an origin down for a week would report 'synced just now'", status)
		}
		if f.ImportedCount != 0 {
			t.Errorf("HTTP %d counted %d imported entries", status, f.ImportedCount)
		}
		srv.Close()
	}
}

// TestChaos108_ShutdownInterruptsAnInFlightFetch covers the cancellation half:
// the fetch was parented to context.Background(), so shutdown waited out
// httpTimeout instead of ending the sync.
func TestChaos108_ShutdownInterruptsAnInFlightFetch(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	release := make(chan struct{})
	reached := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reached)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	bs, _ := newTestSyncer(t, &fakeMerger{})
	bs.SetFeed(srv.URL, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := bs.SyncFeedContext(ctx, srv.URL); done <- err }()

	<-reached
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a cancelled fetch returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("SyncFeedContext ignored cancellation; pre-fix it was parented to context.Background() and waited out the %v fetch timeout", httpTimeout)
	}
}

// TestChaos108_SyncDueStopsOnCancellation: a shutdown mid-round must not keep
// starting fetches for the remaining due feeds.
func TestChaos108_SyncDueStopsOnCancellation(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("a.invalid\n"))
	}))
	defer srv.Close()

	bs, _ := newTestSyncer(t, &fakeMerger{added: 1})
	// Several distinct due feeds on the same origin.
	for _, p := range []string{"/1.txt", "/2.txt", "/3.txt", "/4.txt"} {
		bs.SetFeed(srv.URL+p, time.Hour)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already shutting down when the round starts

	bs.syncDue(ctx)
	if n := hits.Load(); n != 0 {
		t.Errorf("syncDue started %d fetch(es) under an already-cancelled context", n)
	}
}

// TestChaos108_ShortenedIntervalTakesEffectImmediately guards the behaviour
// the absolute next-attempt stamp could have regressed: the old
// lastAttempt+interval gate was recomputed per tick, so shortening the
// cadence applied at once.
func TestChaos108_ShortenedIntervalTakesEffectImmediately(t *testing.T) {
	const url = "https://feeds.example/a.txt"
	bs, clk := newTestSyncer(t, &fakeMerger{})
	bs.SetFeed(url, 24*time.Hour)

	bs.mu.Lock()
	st := bs.feeds[url]
	st.lastAttempt = clk.Now()
	bs.scheduleNextLocked(st, true) // next attempt in 24h
	bs.mu.Unlock()

	if due := bs.dueURLs(clk.Now()); len(due) != 0 {
		t.Fatalf("feed due immediately after a successful sync: %v", due)
	}

	// The operator tightens the cadence to 5 minutes.
	bs.SetFeed(url, 5*time.Minute)
	clk.advance(5 * time.Minute)
	if due := bs.dueURLs(clk.Now()); len(due) != 1 {
		t.Errorf("a shortened interval did not take effect: due = %v, want the feed due 5m after its last attempt", due)
	}

	// Lengthening must not pull a pending retry out past its backoff.
	bs.mu.Lock()
	st.lastAttempt = clk.Now()
	d := bs.scheduleNextLocked(st, false) // backoff, <= 5m interval
	bs.mu.Unlock()
	bs.SetFeed(url, 24*time.Hour)
	bs.mu.Lock()
	got := st.nextAttempt
	bs.mu.Unlock()
	if want := clk.Now().Add(d); !got.Equal(want) {
		t.Errorf("lengthening the interval moved a pending retry from %v to %v", want, got)
	}
}

// TestChaos108_DisabledFeedIsNeverAutoSynced: interval 0 is manual-only and
// must stay so, including after the stamp a manual sync leaves behind.
func TestChaos108_DisabledFeedIsNeverAutoSynced(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("a.invalid\n"))
	}))
	defer srv.Close()

	bs, clk := newTestSyncer(t, &fakeMerger{added: 1})
	bs.SetFeed(srv.URL, 0)
	if due := bs.dueURLs(clk.Now()); len(due) != 0 {
		t.Fatalf("manual-only feed reported due: %v", due)
	}
	if _, err := bs.SyncFeed(srv.URL); err != nil {
		t.Fatalf("manual sync of a disabled feed: %v", err)
	}
	clk.advance(365 * 24 * time.Hour)
	if due := bs.dueURLs(clk.Now()); len(due) != 0 {
		t.Errorf("manual-only feed became due after a manual sync: %v", due)
	}
}
