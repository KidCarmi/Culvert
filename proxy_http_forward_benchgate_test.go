//go:build benchgate

package main

// Allocation-regression gate for the plain-HTTP forward step (proxy_http.go).
//
// Correctness contracts for that step live in proxy_http_forward_test.go and
// run in the normal suite; this file holds the PERFORMANCE contract only, in
// the repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Keyed on allocations per op, which are deterministic and hardware
// independent, rather than ns/op, which is not.

import (
	"testing"
)

// TestBenchGate_HTTPForwardAllocs locks in the removal of the per-request
// http.Client from the forward path.
//
// Measured (Go 1.26, linux/amd64): 81 allocs/op direct, 90 allocs/op for the
// pre-change http.Client-per-request shape. The bound sits at 85 — comfortably
// above the measured value so stdlib churn across Go releases does not flip the
// gate, and comfortably below the legacy 90 so reintroducing the client wrapper
// (a full Header.Clone of the request headers, the redirect body-rewind
// wrapper, the response-body cancel wrapper, and the client itself) fails here.
//
// The gate deliberately asserts the RELATIONSHIP as well as the absolute bound:
// both shapes are measured in the same run on the same machine, so a runner
// that is slow or differently-tuned cannot make the comparison lie.
func TestBenchGate_HTTPForwardAllocs(t *testing.T) {
	const maxAllocs int64 = 85

	direct := testing.Benchmark(func(b *testing.B) { benchForward(b, forwardDirect) })
	legacy := testing.Benchmark(func(b *testing.B) { benchForward(b, forwardLegacyClient) })

	directAllocs, legacyAllocs := direct.AllocsPerOp(), legacy.AllocsPerOp()
	t.Logf("forward direct: %d allocs/op, %d B/op (bound %d)", directAllocs, direct.AllocedBytesPerOp(), maxAllocs)
	t.Logf("forward legacy: %d allocs/op, %d B/op", legacyAllocs, legacy.AllocedBytesPerOp())

	if directAllocs > maxAllocs {
		t.Errorf("plain-HTTP forward allocates %d/op, bound %d — the http.Client wrapper (or equivalent per-request machinery) is back on the hot path",
			directAllocs, maxAllocs)
	}
	if directAllocs >= legacyAllocs {
		t.Errorf("direct forward (%d allocs/op) is no cheaper than the pre-change http.Client shape (%d allocs/op); the optimization has been undone",
			directAllocs, legacyAllocs)
	}
}
