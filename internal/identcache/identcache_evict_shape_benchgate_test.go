//go:build benchgate

package identcache

import (
	"strconv"
	"testing"
	"time"
)

// Wall-clock cost-shape gate for the eviction index (PERF-IDENTCACHE-1), kept
// BEHIND THE benchgate TAG.
//
// It is tagged for the reason internal/catgroup's equivalent gate is: a
// wall-clock ratio is not a property an ordinary test run can decide, and a
// gate that red-lights a correct tree under load is worse than no gate.
// `benchgate`-tagged tests are outside the default `go test ./...` build and
// run in the dedicated serial job (`Gate · perf-regression (allocs/op)` in
// .github/workflows/pr-fast-gate.yml), which is the only place a timing
// comparison is meaningful. ./internal/identcache is named in that command;
// without it this file would compile nowhere and the gate would silently never
// run.
//
// What the ORDINARY suite keeps instead, deterministically:
//   - TestChaos76_WallNoBucketScanSurvivesInEviction — an AST wall over
//     evictOneLocked, so a reintroduced `range c.buckets` fails the build
//     regardless of load.
//   - TestChaos76_EvictionIndexSelectsTheSameVictimAsTheFullScan — the
//     differential oracle against the scan this replaced.

// measureBest runs fn iters times and returns the best of three samples: a
// scheduler hiccup inflates a sample, never deflates it, so best-of-three is
// the noise-robust statistic for a ratio gate.
func measureBest(iters int, fn func(i int)) time.Duration {
	one := func() time.Duration {
		for i := 0; i < iters/10; i++ { // warm up; neither arm pays first-touch alone
			fn(i)
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			fn(i)
		}
		return time.Since(start)
	}
	d := one()
	for i := 0; i < 2; i++ {
		if e := one(); e < d {
			d = e
		}
	}
	return d
}

// TestBenchGate_EvictionAtCapIsFlatInClientCount is a RATIO gate, so it is
// machine-independent: it compares insertion-at-cap against ITSELF at two
// client counts rather than against an absolute nanosecond budget (the standing
// rule — an absolute bound gets re-baselined per machine and then muted).
//
// The scan cost one hashed map lookup per distinct client, so 2,500 clients
// cost ~80x what 25 did (measured 3.4 µs → 276 µs on a 4-core Xeon @2.10GHz,
// at the real 5,000 cap). The eviction index makes the cost logarithmic in the
// client count; measured ratio after the change is ~2x, which is the heap depth
// difference plus the larger working set. The bound is 10x: a wide margin over
// the index's real shape, and still a hard failure if the linear scan returns.
//
// The cap assertion inside measure is an EMBEDDED CONTROL: the cheapest way to
// make eviction flat is to stop evicting, and an implementation that let the
// cache grow past its cap — or that stopped admitting entries at all — would
// fail here rather than post a fast green.
func TestBenchGate_EvictionAtCapIsFlatInClientCount(t *testing.T) {
	const (
		capacity = 5_000 // main's maxAuthCacheSize
		few      = 25
		many     = 2_500
		bound    = 10.0
	)
	measure := func(clients int) time.Duration {
		c := New[int](Options{MaxEntries: capacity})
		for i := 0; i < capacity; i++ {
			c.Set("seed-"+strconv.Itoa(i), "client-"+strconv.Itoa(i%clients), i, true, time.Hour)
		}
		if got := c.Len(); got != capacity {
			t.Fatalf("clients=%d: cache holds %d entries, want the cap %d", clients, got, capacity)
		}
		d := measureBest(20_000, func(i int) {
			c.Set("new-"+strconv.Itoa(i), "client-"+strconv.Itoa(i%clients), i, true, time.Hour)
		})
		// Every one of those insertions was at the cap, so every one had to
		// displace an entry: the cap must still hold, and the cache must not
		// have quietly stopped accepting entries.
		if got := c.Len(); got != capacity {
			t.Fatalf("clients=%d: cache holds %d entries after churn, want the cap %d",
				clients, got, capacity)
		}
		return d
	}
	dFew, dMany := measure(few), measure(many)
	ratio := float64(dMany) / float64(dFew)
	t.Logf("clients=%d: %v, clients=%d: %v, ratio=%.2fx (indexed ~2x, linear ~80x, bound %.1fx)",
		few, dFew, many, dMany, ratio, bound)
	if ratio > bound {
		t.Errorf("insertion at the cap scales with the client count (%.2fx for %dx the "+
			"clients, bound %.1fx): the linear scan over c.buckets has returned",
			ratio, many/few, bound)
	}
}
