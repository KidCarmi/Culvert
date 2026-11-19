package blocklistfeed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// steppingClock advances by step on every read, so a fetch — stamped by a
// read at its attempt and another at its success — takes about step of fake
// time, and a round of n feeds takes about 2n·step. It models slow origins
// without sleeping and without the HTTP handler touching the clock.
type steppingClock struct {
	t    time.Time
	step time.Duration
}

func (c *steppingClock) Now() time.Time {
	c.t = c.t.Add(c.step)
	return c.t
}

// TestChaos123_MaxHealthyGapBoundsTheScheduledCadence drives the real round
// (syncDue) the way Start does — a round, then TickInterval before the next —
// for feeds whose every fetch succeeds, and checks that no feed's two
// successive successes are further apart than MaxHealthyGap. Package main
// measures staleness against that bound, so a cadence the scheduler can
// deliver past it is a false page on a healthy node (CHAOS-123).
//
// Two shapes a bare max(interval, tick) bound missed: a 60 s feed at +10%
// jitter is due at 66 s, skips the tick at 60 s and is fetched at 120 s; and
// six 60 s feeds whose fetches each take ~28 s are fetched one after another,
// so each feed's successes are a whole slow round plus a tick apart.
func TestChaos123_MaxHealthyGapBoundsTheScheduledCadence(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "blocked.example.com")
	}))
	t.Cleanup(srv.Close)

	type shape struct {
		interval time.Duration
		feeds    int
		step     time.Duration // per clock read; a fetch is ~2 reads apart
	}
	shapes := []shape{
		{10 * time.Second, 1, 0},
		{55 * time.Second, 1, 0},
		{time.Minute, 1, 0},
		{61 * time.Second, 1, 0},
		{90 * time.Second, 1, 0},
		{5 * time.Minute, 1, 0},
		{time.Hour, 1, 0},
		{time.Minute, 1, time.Second},
		{time.Minute, 6, 14 * time.Second}, // ~28 s per fetch, inside httpTimeout
		{5 * time.Minute, 6, 14 * time.Second},
	}
	for _, sh := range shapes {
		for _, off := range []float64{-jitterFrac, 0, jitterFrac} {
			name := fmt.Sprintf("%v/x%d/step%v/%+.2f", sh.interval, sh.feeds, sh.step, off)
			t.Run(name, func(t *testing.T) {
				worst := worstHealthyGap(t, srv.URL, sh.interval, sh.feeds, sh.step, off)
				if bound := MaxHealthyGap(sh.interval, sh.feeds); worst > bound {
					t.Fatalf("healthy feed synced %v apart, past MaxHealthyGap %v", worst, bound)
				}
			})
		}
	}
}

// TestChaos123_SerialSlowRoundsExceedATickMargin is the negative control for
// the round-length term: the six-slow-feed shape really does put a feed's
// successes further apart than jitter plus two ticks, so a bound without the
// round term would page on it.
func TestChaos123_SerialSlowRoundsExceedATickMargin(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "blocked.example.com")
	}))
	t.Cleanup(srv.Close)

	const interval = time.Minute
	worst := worstHealthyGap(t, srv.URL, interval, 6, 14*time.Second, 0)
	noRoundTerm := interval + time.Duration(float64(interval)*jitterFrac) + 2*TickInterval
	if worst <= noRoundTerm {
		t.Fatalf("six ~28 s feeds synced only %v apart; the shape no longer exercises the round term (%v)", worst, noRoundTerm)
	}
}

// worstHealthyGap runs Start's loop on a fake clock for n feeds at interval,
// all served by origin, and returns the largest gap between two successive
// successes of any one feed.
func worstHealthyGap(t *testing.T, origin string, interval time.Duration, n int, step time.Duration, off float64) time.Duration {
	t.Helper()
	clk := &steppingClock{t: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), step: step}
	bs := New(&fakeMerger{})
	bs.now = clk.Now
	bs.jitter = func(d time.Duration) time.Duration { return d + time.Duration(float64(d)*off) }
	for i := range n {
		bs.SetFeed(fmt.Sprintf("%s/feed-%d.txt", origin, i), interval)
	}

	// Enough rounds for several successes of every feed at the longest gap.
	rounds := int(6*MaxHealthyGap(interval, n)/TickInterval) + 2
	last := map[string]time.Time{}
	var worst time.Duration
	for range rounds {
		bs.syncDue(context.Background())
		for _, f := range bs.Feeds() {
			if f.LastError != "" {
				t.Fatalf("feed %s failed: %s", f.URL, f.LastError)
			}
			if prev, ok := last[f.URL]; ok && f.LastSync.After(prev) {
				worst = max(worst, f.LastSync.Sub(prev))
			}
			last[f.URL] = f.LastSync
		}
		clk.t = clk.t.Add(TickInterval)
	}
	if worst == 0 {
		t.Fatalf("observed no second success in %d rounds", rounds)
	}
	return worst
}
