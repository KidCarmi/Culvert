//go:build benchgate

package main

import (
	"strconv"
	"testing"
	"time"
)

// Wall-clock cost-shape gate for the local credential cache's eviction index
// (PERF-AUTHCACHE-1), kept BEHIND THE benchgate TAG.
//
// It is tagged for the reason internal/identcache's equivalent gate is: a
// wall-clock ratio is not a property an ordinary test run can decide, and a
// gate that red-lights a correct tree under load is worse than no gate.
// `benchgate`-tagged tests are outside the default `go test ./...` build and
// run in the dedicated serial job (`Gate · perf-regression (allocs/op)` in
// .github/workflows/pr-fast-gate.yml, and the same command in qa-gate.yml and
// proxy-weekly-stress.yml). The root package `.` is already named in all three.
//
// What the ORDINARY suite keeps instead, deterministically:
//   - TestPerfAuthCache1_WallNoBucketScanSurvivesInEviction — an AST wall over
//     evictOneLocked, so a reintroduced `range a.buckets` fails the build
//     regardless of load.
//   - TestPerfAuthCache1_EvictionIndexSelectsTheSameVictimAsTheFullScan — the
//     differential oracle against the scan this replaced.

// authMeasureBest runs fn iters times and returns the best of three samples: a
// scheduler hiccup inflates a sample, never deflates it, so best-of-three is
// the noise-robust statistic for a ratio gate.
func authMeasureBest(iters int, fn func(i int)) time.Duration {
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

// TestBenchGate_AuthCacheEvictionAtCapIsFlatInClientCount is a RATIO gate, so
// it is machine-independent: it compares insertion-at-cap against ITSELF at two
// client counts rather than against an absolute nanosecond budget (the standing
// rule — an absolute bound gets re-baselined per machine and then muted).
//
// The replaced scan cost one hashed map lookup per distinct client, so 2,500
// clients cost ~60x what 25 did (measured 5.5 µs → 328 µs on a 4-core Xeon
// @2.10GHz at the real 5,000 cap, where the whole sweep ran 1.4 µs at one
// client and 328 µs at five thousand). The eviction index makes the cost
// logarithmic in the client count. The bound is 10x: a wide margin over the
// index's real shape, and still a hard failure if the linear scan returns.
//
// The cap assertion inside measure is an EMBEDDED CONTROL: the cheapest way to
// make eviction flat is to stop evicting, and an implementation that let the
// cache grow past its cap — or that stopped admitting entries at all — would
// fail here rather than post a fast green.
func TestBenchGate_AuthCacheEvictionAtCapIsFlatInClientCount(t *testing.T) {
	const (
		few   = 25
		many  = 2_500
		bound = 10.0
	)
	size := func(a *authCacheStore) int {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.entries)
	}
	measure := func(clients int) time.Duration {
		a := &authCacheStore{}
		for i := 0; i < maxAuthCacheSize; i++ {
			a.set("client-"+strconv.Itoa(i%clients), "user", "seed-"+strconv.Itoa(i), true)
		}
		if got := size(a); got != maxAuthCacheSize {
			t.Fatalf("clients=%d: cache holds %d entries, want the cap %d",
				clients, got, maxAuthCacheSize)
		}
		d := authMeasureBest(20_000, func(i int) {
			a.set("client-"+strconv.Itoa(i%clients), "user", "new-"+strconv.Itoa(i), true)
		})
		// Every one of those insertions was at the cap, so every one had to
		// displace an entry: the cap must still hold, and the cache must not
		// have quietly stopped accepting entries.
		if got := size(a); got != maxAuthCacheSize {
			t.Fatalf("clients=%d: cache holds %d entries after churn, want the cap %d",
				clients, got, maxAuthCacheSize)
		}
		return d
	}
	dFew, dMany := measure(few), measure(many)
	ratio := float64(dMany) / float64(dFew)
	t.Logf("clients=%d: %v, clients=%d: %v, ratio=%.2fx (indexed ~1x, linear ~60x, bound %.1fx)",
		few, dFew, many, dMany, ratio, bound)
	if ratio > bound {
		t.Errorf("insertion at the cap scales with the client count (%.2fx for %dx the "+
			"clients, bound %.1fx): the linear scan over a.buckets has returned",
			ratio, many/few, bound)
	}
}
