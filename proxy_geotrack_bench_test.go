package main

// Benchmarks for the per-request destination-country dispatch gate
// (maybeTrackDestinationCountry, proxy.go). handleRequest runs this once per
// allowed request, so the disabled path — the default deployment, no MaxMind
// DB configured — must stay allocation- and goroutine-free.
//
// The *_PreGate benchmarks reproduce the pre-gate behavior (unconditional
// `go trackDestinationCountry(host)`) as the before/after baseline. The host
// rotates through a package-level slice so the spawn captures a runtime
// variable exactly like handleRequest's `host` — since Go 1.17 that `go
// f(arg)` lowering heap-allocates a capturing closure (24 B), and the spawned
// tracker pays a schedule round plus two semaphore channel ops before
// discovering geoip.Enabled() == false inside geo.LookupFull. Measured on the
// CI dev-container class (linux/amd64, 4 vCPU):
//
//   BenchmarkGeoTrackDispatch_Disabled                  ~16 ns/op   0 B/op  0 allocs/op
//   BenchmarkGeoTrackDispatch_Disabled_PreGate     ~440–710 ns/op  24 B/op  1 alloc/op
//   BenchmarkGeoTrackDispatch_DisabledParallel          ~39 ns/op   0 B/op  0 allocs/op
//   BenchmarkGeoTrackDispatch_PreGateParallel      ~820–900 ns/op  24 B/op  1 alloc/op
//
// The regression gate for the disabled-path allocation contract is
// TestBenchGate_GeoTrackDispatchDisabledAllocs (bench_regression_test.go).

import "testing"

// benchGeoTrackHosts defeats constant-folding of the spawn argument so the
// PreGate baseline allocates the same capturing closure production did (a
// string literal argument lets the compiler build a static closure and
// under-reports the old cost by one allocation).
var benchGeoTrackHosts = []string{
	"a.bench.example.com", "b.bench.example.com",
	"c.bench.example.com", "d.bench.example.com",
}

// BenchmarkGeoTrackDispatch_Disabled measures the gated dispatch with no
// GeoIP DB loaded — the per-request cost every non-GeoIP deployment pays.
func BenchmarkGeoTrackDispatch_Disabled(b *testing.B) {
	if geoTrackEnabledFn() {
		b.Skip("GeoIP DB unexpectedly loaded; disabled-path benchmark requires no DB")
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		maybeTrackDestinationCountry(benchGeoTrackHosts[i&3])
	}
}

// BenchmarkGeoTrackDispatch_Disabled_PreGate reproduces the pre-gate
// per-request cost: an unconditional tracker spawn that no-ops inside the
// goroutine. Kept as the permanent before/after comparison for the gate.
func BenchmarkGeoTrackDispatch_Disabled_PreGate(b *testing.B) {
	if geoTrackEnabledFn() {
		b.Skip("GeoIP DB unexpectedly loaded; disabled-path benchmark requires no DB")
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		go trackDestinationCountry(benchGeoTrackHosts[i&3])
	}
}

// BenchmarkGeoTrackDispatch_DisabledParallel exercises the gate under
// concurrent request handling (the geoip.Enabled RLock probe is the only
// shared state on the gated path).
func BenchmarkGeoTrackDispatch_DisabledParallel(b *testing.B) {
	if geoTrackEnabledFn() {
		b.Skip("GeoIP DB unexpectedly loaded; disabled-path benchmark requires no DB")
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			maybeTrackDestinationCountry(benchGeoTrackHosts[i&3])
			i++
		}
	})
}

// BenchmarkGeoTrackDispatch_PreGateParallel is the concurrent before/after
// baseline: per-request goroutine spawns contending on the scheduler and the
// tracker semaphore.
func BenchmarkGeoTrackDispatch_PreGateParallel(b *testing.B) {
	if geoTrackEnabledFn() {
		b.Skip("GeoIP DB unexpectedly loaded; disabled-path benchmark requires no DB")
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			go trackDestinationCountry(benchGeoTrackHosts[i&3])
			i++
		}
	})
}
