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

// TestChaos123_MaxHealthyGapBoundsTheScheduledCadence drives the real round
// (syncDue) the way Start does — a round, then TickInterval before the next —
// for a feed whose every fetch succeeds, at both jitter extremes, and checks
// that no two successes are further apart than MaxHealthyGap. Package main
// measures staleness against that bound, so a cadence the scheduler can
// deliver past it is a false page on a healthy node (CHAOS-123).
//
// The 60 s case at +10% is the one a bound of max(interval, tick) missed: due
// at 66 s, it skips the tick at 60 s and is fetched at 120 s.
func TestChaos123_MaxHealthyGapBoundsTheScheduledCadence(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "blocked.example.com")
	}))
	t.Cleanup(srv.Close)

	intervals := []time.Duration{
		10 * time.Second, 55 * time.Second, time.Minute, 61 * time.Second,
		90 * time.Second, 5 * time.Minute, time.Hour,
	}
	for _, interval := range intervals {
		for _, off := range []float64{-jitterFrac, jitterFrac} {
			t.Run(fmt.Sprintf("%v/%+.2f", interval, off), func(t *testing.T) {
				bs, clk := newTestSyncer(t, &fakeMerger{})
				bs.jitter = func(d time.Duration) time.Duration {
					return d + time.Duration(float64(d)*off)
				}
				bs.SetFeed(srv.URL, interval)
				start := clk.Now()

				// Enough ticks for several successes at the longest interval.
				ticks := int(6*MaxHealthyGap(interval)/TickInterval) + 2
				var prev, worst time.Duration
				prev = -1
				for i := range ticks {
					bs.syncDue(context.Background())
					last := bs.Feeds()[0].LastSync
					if last.IsZero() {
						t.Fatalf("tick %d: a healthy feed has not synced", i)
					}
					at := last.Sub(start)
					if prev >= 0 && at != prev {
						worst = max(worst, at-prev)
					}
					prev = at
					clk.advance(TickInterval)
				}
				if worst == 0 {
					t.Fatalf("observed no second success in %d ticks", ticks)
				}
				if bound := MaxHealthyGap(interval); worst > bound {
					t.Fatalf("healthy feed synced %v apart, past MaxHealthyGap %v", worst, bound)
				}
			})
		}
	}
}
