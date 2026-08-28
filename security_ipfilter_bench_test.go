package main

import (
	"fmt"
	"testing"
)

// IPFilter.Allowed runs on EVERY proxied request — handleRequest (proxy.go)
// and the SOCKS5 handler both gate on it before any other work. These
// benchmarks pin its cost in the three postures that matter:
//
//	Disabled    — mode "" — the DEFAULT posture, so it is 100% of traffic on a
//	              stock appliance. The interesting axis is CORE COUNT: a shared
//	              read lock taken per request is an atomic read-modify-write on
//	              one cache line, which turns a constant cost into a throughput
//	              CEILING that gets worse as cores are added. Run the *Parallel
//	              benchmarks with -cpu=1,2,4 — the shape across that list is
//	              the measurement; a single absolute number is not.
//	Block mode  — the common enforcement posture (deny a handful of bad IPs).
//	              Every legitimate request pays the full miss path.
//	Allow mode  — allowlist posture, scaled over CIDR count, because the CIDR
//	              side of the lookup is a linear scan.
//
// newBenchIPFilter builds an isolated filter so these never touch the package
// global `ipf` that the rest of the suite mutates.
func newBenchIPFilter(mode string, entries []string) *IPFilter {
	f := &IPFilter{single: map[string]bool{}}
	for _, e := range entries {
		if err := f.Add(e); err != nil {
			panic("bench fixture: " + e + ": " + err.Error())
		}
	}
	f.SetMode(mode)
	return f
}

// benchCIDRs returns n distinct, non-overlapping /24s that never contain the
// probe IP, so the lookup always walks the whole list — the worst case, and
// the only one that is stable across runs.
func benchCIDRs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	return out
}

// benchBlockList is the shape a real deny-list takes: a few individual bad
// hosts plus a couple of ranges.
var benchBlockList = []string{"198.51.100.7", "198.51.100.8", "192.0.2.0/24", "10.0.0.0/8"}

const benchProbeIP = "203.0.113.47" // TEST-NET-3: never inside any fixture above

// ─── Disabled (the default posture: mode "", no entries) ────────────────────

func BenchmarkIPFilterAllowed_Disabled(b *testing.B) {
	f := newBenchIPFilter("", nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !f.Allowed(benchProbeIP) {
			b.Fatal("disabled filter must allow")
		}
	}
}

// BenchmarkIPFilterAllowed_DisabledParallel is the load-bearing one. A filter
// that is switched OFF should cost the same whether one core or all of them
// are serving traffic. Run with -cpu=1,2,4: if the per-op number RISES with
// core count, the gate is a scalability ceiling on the whole proxy rather than
// a constant, and every request in the process pays for a disabled feature.
func BenchmarkIPFilterAllowed_DisabledParallel(b *testing.B) {
	f := newBenchIPFilter("", nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !f.Allowed(benchProbeIP) {
				b.Fatal("disabled filter must allow")
			}
		}
	})
}

// ─── Block mode (deny-list enforcement; every good request is a miss) ───────

func BenchmarkIPFilterAllowed_BlockMiss(b *testing.B) {
	f := newBenchIPFilter("block", benchBlockList)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !f.Allowed(benchProbeIP) {
			b.Fatal("unlisted IP must pass a blocklist")
		}
	}
}

func BenchmarkIPFilterAllowed_BlockMissParallel(b *testing.B) {
	f := newBenchIPFilter("block", benchBlockList)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !f.Allowed(benchProbeIP) {
				b.Fatal("unlisted IP must pass a blocklist")
			}
		}
	})
}

// ─── Allow mode, scaled over CIDR count (the linear-scan axis) ──────────────

// BenchmarkIPFilterAllowed_AllowCIDRScan is the cost-shape gate: the per-op
// number should be FLAT in CIDR count, not proportional to it. An enterprise
// allowlist (branch offices, VPN pools, partner ranges) reaches hundreds of
// prefixes without being unusual.
func BenchmarkIPFilterAllowed_AllowCIDRScan(b *testing.B) {
	for _, n := range []int{1, 16, 64, 256} {
		b.Run(fmt.Sprintf("cidrs=%d", n), func(b *testing.B) {
			f := newBenchIPFilter("allow", benchCIDRs(n))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Probe sits outside every CIDR: the full-scan worst case.
				_ = f.Allowed(benchProbeIP)
			}
		})
	}
}

// BenchmarkIPFilterAllowed_AllowSingleHit measures the exact-IP hit path — the
// shape an allowlist of individual hosts takes.
func BenchmarkIPFilterAllowed_AllowSingleHit(b *testing.B) {
	f := newBenchIPFilter("allow", []string{benchProbeIP, "198.51.100.7", "198.51.100.8"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !f.Allowed(benchProbeIP) {
			b.Fatal("listed IP must pass an allowlist")
		}
	}
}
