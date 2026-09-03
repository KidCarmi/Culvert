//go:build benchgate

package main

// Scaling-regression gate for the per-IP rate-limiter's sliding window.
//
//	go test -tags benchgate -run 'TestBenchGate_RateLimit' -v .

import (
	"testing"
	"time"
)

// TestBenchGate_RateLimitWindowIsFlatInConfiguredLimit locks in the contract
// that made the ring worth building: the per-request cost of the rate-limit
// gate must NOT be a function of security.rate_limit.
//
// RateLimiter.Allow bounds a bucket's occupancy by the configured limit, so the
// old filter-and-copy eviction charged every request from an IP a walk over
// that IP's whole in-window history — measured at 168 ns for a 60/min policy
// and 131.6 µs for a 60000/min one, i.e. an operator's policy setting was the
// price of the gate, paid on the request path while holding the shard mutex.
//
// GATE DESIGN. This is a RATIO gate, not an absolute-nanosecond one: it
// compares the SAME operation at a small and a large limit within a single run,
// so it is machine-independent, immune to a shared CI runner's load, and does
// not need re-baselining when the hardware changes. Healthy, the ratio is ~1
// (measured 20.3 ns vs 17.7 ns — the large limit is, if anything, marginally
// cheaper). Regressed back to an occupancy-proportional scan the ratio is the
// ratio of the limits themselves, ~100x. The bound is 4x: far above any
// plausible cache-effect noise between the two bucket sizes, far below the
// smallest regression that could reintroduce the defect.
func TestBenchGate_RateLimitWindowIsFlatInConfiguredLimit(t *testing.T) {
	const (
		smallLimit = 60
		largeLimit = 6000
		maxRatio   = 4.0
	)

	measure := func(limit int) float64 {
		res := testing.Benchmark(func(b *testing.B) {
			base := time.Now()
			bk := steadyRing(limit, base)
			now := base.Add(time.Microsecond * time.Duration(limit))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ringAdmit(bk, now, time.Minute, limit)
				if bk.n > limit/2 {
					bk.expire(bk.stamps[bk.head])
				}
			}
		})
		return float64(res.NsPerOp())
	}

	small := measure(smallLimit)
	large := measure(largeLimit)
	if small <= 0 || large <= 0 {
		t.Fatalf("benchmark produced no signal: small=%.1fns large=%.1fns", small, large)
	}

	ratio := large / small
	t.Logf("limit=%d: %.1f ns/op; limit=%d: %.1f ns/op; ratio %.2fx (bound %.1fx)",
		smallLimit, small, largeLimit, large, ratio, maxRatio)
	if ratio > maxRatio {
		t.Fatalf("rate-limit window cost scales with the configured limit: %.2fx from limit %d to %d "+
			"(bound %.1fx) — the sliding window is walking the bucket again instead of dropping an "+
			"expired prefix (see clientBucket in security.go)", ratio, smallLimit, largeLimit, maxRatio)
	}
}

// TestBenchGate_RateLimitWindowIsAllocationFree pins that a steady-state
// request neither grows the ring nor allocates: growth is bounded by the limit
// and reached once, so past warm-up the gate must cost zero allocations on the
// request path.
func TestBenchGate_RateLimitWindowIsAllocationFree(t *testing.T) {
	const limit = 6000
	r := newRateLimiter()
	r.Configure(limit, time.Minute)
	const ip = "203.0.113.42"

	// Drive the IP to its cap so the ring has finished growing.
	for i := 0; i < limit; i++ {
		r.Allow(ip)
	}

	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r.Allow(ip)
		}
	})
	if got := res.AllocsPerOp(); got != 0 {
		t.Fatalf("Allow costs %d allocs/op at steady state; want 0", got)
	}
}
