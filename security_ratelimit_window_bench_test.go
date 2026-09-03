package main

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// security_ratelimit_window_bench_test.go — the cost measurement behind the
// ring-buffer sliding window (see clientBucket in security.go).
//
// RateLimiter.Allow runs on EVERY proxied request (handleRequest, socks5.go),
// and its window maintenance used to be a filter-and-copy over the whole
// bucket. The interesting axis is therefore NOT a single number but the
// CONFIGURED LIMIT: the accept test bounds a bucket's occupancy by
// security.rate_limit, so the old shape made an operator's policy setting the
// per-request price of the gate. Run:
//
//	go test -run XXX -bench 'BenchmarkRateLimitWindow' -benchtime=200ms .
//
// and read the SHAPE across limits, not the absolute constants.
//
// Measured on a 4-core Xeon @2.80GHz (Go 1.26, bucket held at half occupancy):
//
//	rate_limit (rpm) │ legacy (before) │ ring (after) │ speedup
//	─────────────────┼─────────────────┼──────────────┼─────────
//	        60       │        172 ns   │     24.6 ns  │      7x
//	       600       │       1376 ns   │     22.2 ns  │     62x
//	     6 000       │      13165 ns   │     22.8 ns  │    578x
//	    60 000       │     132551 ns   │     22.4 ns  │   5917x
//
// (medians of n=3, -benchtime=300ms.)
//
// The legacy figure is not a historical note that can drift: legacyWindow
// (security_ratelimit_window_test.go) is the verbatim pre-change algorithm and
// is benchmarked HERE, in the same run, on the same hardware — so the
// comparison stays reproducible in-tree and the gate below can assert on it.

// benchWindowLimits are the shapes an operator actually configures: 60/min is a
// tight per-user cap, 6000/min a busy NAT egress or downstream proxy.
var benchWindowLimits = []int{60, 600, 6000, 60000}

// steadyRing returns a bucket primed to half the limit — the steady state of an
// IP sending at half its allowance, which is what the old scan-and-copy walked
// on every request.
func steadyRing(limit int, base time.Time) *clientBucket {
	b := &clientBucket{}
	for i := 0; i < limit/2; i++ {
		b.add(base.Add(time.Duration(i)*time.Microsecond), limit)
	}
	return b
}

func steadyLegacy(limit int, base time.Time) *legacyWindow {
	w := &legacyWindow{}
	for i := 0; i < limit/2; i++ {
		w.timestamps = append(w.timestamps, base.Add(time.Duration(i)*time.Microsecond))
	}
	return w
}

// BenchmarkRateLimitWindow_Ring measures the shipped path at each limit. It must
// be FLAT: the cost of one request is the cost of one request, whatever the
// operator set the limit to.
func BenchmarkRateLimitWindow_Ring(b *testing.B) {
	for _, limit := range benchWindowLimits {
		b.Run(fmt.Sprintf("limit=%d", limit), func(b *testing.B) {
			base := time.Now()
			bk := steadyRing(limit, base)
			now := base.Add(time.Microsecond * time.Duration(limit))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ringAdmit(bk, now, time.Minute, limit)
				// Hold occupancy steady so every iteration measures the same
				// state rather than drifting toward saturation.
				if bk.n > limit/2 {
					bk.expire(bk.stamps[bk.head])
				}
			}
		})
	}
}

// BenchmarkRateLimitWindow_Legacy is the same measurement against the verbatim
// pre-change algorithm, kept so the improvement is a measurement rather than a
// claim.
func BenchmarkRateLimitWindow_Legacy(b *testing.B) {
	for _, limit := range benchWindowLimits {
		b.Run(fmt.Sprintf("limit=%d", limit), func(b *testing.B) {
			base := time.Now()
			w := steadyLegacy(limit, base)
			now := base.Add(time.Microsecond * time.Duration(limit))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w.admit(now, time.Minute, limit)
				if len(w.timestamps) > limit/2 {
					w.timestamps = w.timestamps[1:]
				}
			}
		})
	}
}

// BenchmarkRateLimitWindow_AllowAtCapParallel is the end-to-end gate cost —
// shard lock, exempt probe and window together — for IPs sitting AT their cap.
//
// That is the case that matters most and the one the old shape handled worst: a
// client already at its limit keeps sending, every one of those requests walks
// the window, and the walk happens while HOLDING the shard mutex, so it does
// not merely cost its own request but blocks every other IP hashing to the same
// shard (1/64 of the process's traffic). A flood was therefore self-amplifying:
// the more an abusive source sent, the more expensive its own gate became for
// everyone else. Priming to the cap also makes the measurement steady-state and
// allocation-free — no ring growth is folded into it.
//
// Run with -cpu=1,2,4; the cost must be flat in BOTH the limit and the core
// count.
func BenchmarkRateLimitWindow_AllowAtCapParallel(b *testing.B) {
	for _, limit := range []int{600, 6000} {
		b.Run(fmt.Sprintf("limit=%d", limit), func(b *testing.B) {
			r := newRateLimiter()
			r.Configure(limit, time.Minute)
			ips := make([]string, 256)
			for i := range ips {
				ips[i] = fmt.Sprintf("203.0.113.%d", i)
			}
			for i := 0; i < limit; i++ {
				for _, ip := range ips {
					r.Allow(ip)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			// RunParallel invokes the body once per worker GOROUTINE, so the
			// starting offset must be handed out atomically: a plain counter
			// races (which fails `go test -race -bench`) and, worse for the
			// measurement, lost updates start several workers on the SAME IP
			// and therefore the same shard, manufacturing exactly the
			// contention this benchmark exists to rule out. The atomic is paid
			// once per worker, not per iteration, so it is outside what is
			// being measured.
			var seed atomic.Int64
			b.RunParallel(func(pb *testing.PB) {
				i := int(seed.Add(1))
				for pb.Next() {
					i++
					if r.Allow(ips[i&255]) {
						b.Fatal("expected the primed IP to be at its cap")
					}
				}
			})
		})
	}
}
