//go:build benchgate

package admission

// Wall-clock cost-shape gate for the IP filter's read path.
//
//	go test -tags benchgate -run 'TestBenchGate_' -v ./internal/admission
//
// It lives behind the benchgate tag because a nanosecond RATIO measured inside
// the shuffled, -count=2 default suite inherits the load of every package
// running beside it; a gate that can flake gets muted. The benchgate job runs
// it serially. The untagged suite keeps the deterministic halves of the same
// contract: TestIPFilterView_DifferentialAgainstLegacy for the verdict and
// TestBenchGate_IPFilterAllowedTakesNoLock / TestBenchGate_IPFilterAllowedAllocsFree
// for the lock-free, allocation-free read path.

import (
	"fmt"
	"testing"
	"time"
)

// TestBenchGate_IPFilterAllowedIsFlatInCIDRCount is a RATIO gate, so it is
// machine-independent: it compares the filter against itself at two sizes
// rather than against an absolute nanosecond budget.
//
// The pre-change linear scan cost ~14 ns per configured CIDR, so 256 prefixes
// cost ~35x what 1 costs — 3.8 µs of CPU per request, inside the request
// goroutine, before any policy work. Bucketing by prefix length makes the cost
// depend on the number of DISTINCT prefix lengths (here: one, /24) instead.
// Measured ratio after the change is ~1.0; the bound is set at 4x so the gate
// has a wide margin under -race on a shared CI runner while still failing hard
// if the linear scan returns.
func TestBenchGate_IPFilterAllowedIsFlatInCIDRCount(t *testing.T) {
	if testing.Short() {
		t.Skip("cost-shape gate skipped in -short")
	}
	const (
		small = 1
		large = 256
		bound = 4.0
	)

	measure := func(n int) time.Duration {
		f := &IPFilter{single: map[string]bool{}}
		for i := 0; i < n; i++ {
			if err := f.Add(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)); err != nil {
				t.Fatal(err)
			}
		}
		f.SetMode("allow")
		const iters = 20000
		// Warm up so neither size pays first-touch costs the other does not.
		for i := 0; i < 1000; i++ {
			_ = f.Allowed(benchProbeIP)
		}
		start := time.Now()
		for i := 0; i < iters; i++ {
			_ = f.Allowed(benchProbeIP)
		}
		return time.Since(start)
	}

	// Best-of-three on each size: a scheduler hiccup inflates a sample, never
	// deflates it, so taking the minimum removes the flake direction.
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
	t.Logf("cidrs=%d: %v, cidrs=%d: %v, ratio=%.2fx (bound %.1fx)",
		small, dSmall, large, dLarge, ratio, bound)
	if ratio > bound {
		t.Errorf("Allowed cost scales with CIDR count (%.2fx from %d to %d prefixes, bound %.1fx): "+
			"the per-request membership test has returned to a linear scan", ratio, small, large, bound)
	}
}
