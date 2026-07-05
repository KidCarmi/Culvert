package main

// Benchmark for the upstream-leg TLS config of SSL-inspected tunnels.
//
// Before the shared-pool optimization, handleTunnelInspect called
// x509.SystemCertPool() per tunnel, which CLONES the cached system pool on
// every call — measured at ~21.7 µs / ~26.7 KB / 162 allocs per inspected
// CONNECT on the CI runner class (Linux ca-certificates bundle, ~150 roots).
// With upstreamVerifyRoots (sync.OnceValue) the steady state is one small
// tls.Config allocation.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkUpstreamInspect' -benchmem .
//
// The hard regression gate on allocs/op lives in bench_regression_test.go
// (TestBenchGate_UpstreamInspectTLSConfigAllocs); the nightly/weekly bench
// workflows include this benchmark in their benchstat artifacts.

import "testing"

func BenchmarkUpstreamInspectTLSConfig(b *testing.B) {
	// Warm the once-loaded pool so the benchmark measures steady state.
	if cfg := upstreamInspectTLSConfig("warm.example.com", false); cfg.RootCAs == nil {
		b.Fatal("nil RootCAs on the verifying path")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfg := upstreamInspectTLSConfig("origin.example.com", false)
		if cfg.RootCAs == nil {
			b.Fatal("nil RootCAs on the verifying path")
		}
	}
}
