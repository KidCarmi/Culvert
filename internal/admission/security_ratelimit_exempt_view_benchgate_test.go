//go:build benchgate

package admission

// Wall-clock cost-shape gate for the rate-limit exempt view's read path.
//
//	go test -tags benchgate -run 'TestBenchGate_' -v ./internal/admission
//
// It lives behind the benchgate tag because a nanosecond RATIO measured inside
// the shuffled, -count=2 default suite inherits the load of every package
// running beside it; a gate that can flake gets muted. The benchgate job runs
// it serially. The untagged suite keeps the deterministic halves of the same
// contract: TestRLExemptView_DifferentialAgainstLegacy_* for the verdict and
// TestBenchGate_IsExemptTakesNoLock / TestBenchGate_IsExemptAllocsFree for the
// lock-free, allocation-free read path.

import (
	"testing"
	"time"
)

// TestBenchGate_IsExemptIsFlatInCIDRCount is a RATIO gate, so it is
// machine-independent: it compares the limiter against itself at two exempt-
// list sizes rather than against an absolute nanosecond budget.
//
// The pre-change linear net.IPNet.Contains scan cost ~14 ns per exempt CIDR,
// so 256 exempt prefixes cost ~57x what 1 costs — measured at 3.6 µs per
// request on a 4-core Xeon, inside the request goroutine, which was ~74% of
// the entire rate-limit gate. Bucketing by prefix length makes the cost depend
// on the number of DISTINCT prefix lengths (here: one, /24) instead. Measured
// ratio after the change is ~1.0; the bound is 4x so the gate keeps a wide
// margin under -race on a shared CI runner while still failing hard if the
// linear scan returns.
func TestBenchGate_IsExemptIsFlatInCIDRCount(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	const (
		small = 1
		large = 256
		bound = 4.0
	)

	measure := func(n int) time.Duration {
		r := NewRateLimiter()
		_ = r.AddExemptions(benchExemptCIDRs(n))
		const iters = 20000
		// Warm up so neither size pays first-touch costs the other does not.
		for i := 0; i < 1000; i++ {
			_ = r.IsExempt(benchExemptProbeIP)
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			_ = r.IsExempt(benchExemptProbeIP)
		}
		return time.Since(start)
	}

	// Best-of-three: a scheduler hiccup inflates a sample, never deflates it.
	best := func(n int) time.Duration {
		d := measure(n)
		for i := 0; i < 2; i++ {
			if e := measure(n); e < d {
				d = e
			}
		}
		return d
	}

	dSmall, dLarge := best(small), best(large)
	ratio := float64(dLarge) / float64(dSmall)
	t.Logf("cidrs=%d: %v, cidrs=%d: %v, ratio=%.2fx (flat ~1x, linear ~57x, bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("IsExempt cost scales with the exempt CIDR count (%.2fx for %dx the "+
			"prefixes, bound %.1fx): the linear net.IPNet.Contains scan has returned",
			ratio, large/small, bound)
	}
}
