package connlimit

import (
	"strconv"
	"testing"
)

// Benchmarks for the per-request Acquire/Release pair. handleRequest (proxy.go)
// and the SOCKS5 handler call Acquire + a deferred Release on EVERY proxied
// request, so this pair's cost — and, more importantly, how it SCALES with
// core count — is paid by every request the gateway serves.
//
// The parallel variants are the load-bearing ones: a single process-wide mutex
// is a constant cost when measured serially and a throughput CEILING when
// measured under concurrency, and only the second shape shows up in production.

// benchIPs builds a spread of distinct client IPs. A real gateway serves many
// clients concurrently, so distinct keys — not one hot key — are the realistic
// shape for a contention measurement.
func benchIPs(n int) []string {
	ips := make([]string, n)
	for i := range ips {
		ips[i] = "203.0.113." + strconv.Itoa(i&0xff) + ":" + strconv.Itoa(i)
	}
	return ips
}

func BenchmarkAcquireRelease_SingleIP(b *testing.B) {
	cl := New()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cl.Acquire("203.0.113.7")
		cl.Release("203.0.113.7")
	}
}

// BenchmarkAcquireRelease_DistinctIPsParallel is the primary scaling gate:
// distinct client IPs, one Acquire/Release pair per iteration, run across all
// available cores. With one process-wide mutex the per-op cost RISES with core
// count (the ceiling); with per-IP sharding it stays close to the serial cost.
func BenchmarkAcquireRelease_DistinctIPsParallel(b *testing.B) {
	cl := New()
	ips := benchIPs(1024)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i&1023]
			cl.Acquire(ip)
			cl.Release(ip)
			i++
		}
	})
}

// BenchmarkAcquireRelease_SingleIPParallel is the worst realistic case: every
// request comes from ONE client IP (a single NAT egress). All work lands on one
// shard, so this measures what sharding does NOT fix and pins that it does not
// regress either.
func BenchmarkAcquireRelease_SingleIPParallel(b *testing.B) {
	cl := New()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cl.Acquire("203.0.113.7")
			cl.Release("203.0.113.7")
		}
	})
}

// BenchmarkAcquireRelease_EnabledParallel exercises the enabled path (the
// admitted branch — Acquire also reads the cap), which is what a deployment
// with a configured per-IP limit actually runs.
func BenchmarkAcquireRelease_EnabledParallel(b *testing.B) {
	cl := New()
	cl.Enable(1024)
	ips := benchIPs(1024)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ips[i&1023]
			cl.Acquire(ip)
			cl.Release(ip)
			i++
		}
	})
}

// BenchmarkMaxPerIP measures the admin/snapshot accessor. It is not on the
// request path, but it used to take the same lock Acquire did, so it is kept
// as evidence that reading the cap no longer touches request-path state.
func BenchmarkMaxPerIP(b *testing.B) {
	cl := New()
	cl.Enable(64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if cl.MaxPerIP() != 64 {
			b.Fatal("unexpected cap")
		}
	}
}
