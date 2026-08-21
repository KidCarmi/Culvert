package main

// connlimit_bench_test.go — allocation/latency benchmarks for the per-request
// tracing-ID generators (generateRequestID / generateTraceparent). Both run on
// EVERY proxied request via setupRequestTracing (proxy.go): the request ID when
// the client sent none, the traceparent likewise — i.e. essentially all
// client-originated traffic. The alloc bound is pinned by
// TestBenchGate_TracingIDAllocs (bench_regression_test.go, -tags benchgate).

import "testing"

func BenchmarkGenerateRequestID(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if id := generateRequestID(); len(id) != 16 {
			b.Fatalf("bad request id %q", id)
		}
	}
}

func BenchmarkGenerateTraceparent(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if tp := generateTraceparent(); len(tp) != 55 {
			b.Fatalf("bad traceparent %q", tp)
		}
	}
}
