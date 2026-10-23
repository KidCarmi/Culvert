//go:build benchgate

package main

// Allocation-regression gate for the known-empty request body contract
// (proxy_http.go prepareHTTPForward, proxy_tunnel.go's inspected inner loop).
//
// Correctness contracts for both legs live in proxy_emptybody_test.go and run
// in the normal suite; this file holds the PERFORMANCE contract only, in the
// repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Keyed on allocations per op, which are deterministic and hardware
// independent, rather than ns/op, which on these two benchmarks is either
// loopback-bound (the forward leg) or fast enough to be scheduler-sensitive
// (the inner leg).
//
// Each gate asserts the RELATIONSHIP as well as an absolute bound: both shapes
// are measured in the same run on the same machine, so a slow or
// differently-tuned runner cannot make the comparison lie. The relationship is
// the part that actually catches a regression — a new wrapper added to either
// leg without a sentinel check closes the gap, whatever the absolute numbers
// have drifted to across Go releases.

import (
	"testing"
)

// TestBenchGate_EmptyBodyForwardAllocs locks in the forward leg's skip.
//
// Measured (Go 1.26, linux/amd64, 4 vCPU): 68 allocs/op with the sentinel
// preserved, 79 allocs/op for the frozen pre-change wrapping — the difference
// being net/http's probeRequestBody machinery (goroutine, channel, 200 ms
// timer) plus the two wrapper objects. The bound sits at 73: above the measured
// value so stdlib churn does not flip the gate, and below the legacy 79 so
// reintroducing an unconditional wrapper fails here.
func TestBenchGate_EmptyBodyForwardAllocs(t *testing.T) {
	const maxAllocs int64 = 73

	sentinel := testing.Benchmark(func(b *testing.B) { benchEmptyBodyForward(b, "GET", false) })
	wrapped := testing.Benchmark(func(b *testing.B) { benchEmptyBodyForward(b, "GET", true) })

	sa, wa := sentinel.AllocsPerOp(), wrapped.AllocsPerOp()
	t.Logf("empty-body forward sentinel: %d allocs/op, %d B/op (bound %d)", sa, sentinel.AllocedBytesPerOp(), maxAllocs)
	t.Logf("empty-body forward wrapped:  %d allocs/op, %d B/op", wa, wrapped.AllocedBytesPerOp())

	if sa > maxAllocs {
		t.Errorf("bodyless forward allocates %d/op, bound %d — a wrapper on the http.NoBody sentinel is back on the forward path, so net/http is probing the body again",
			sa, maxAllocs)
	}
	if sa >= wa {
		t.Errorf("bodyless forward (%d allocs/op) is no cheaper than the pre-change wrapping (%d allocs/op) — the sentinel skip has stopped firing",
			sa, wa)
	}
}

// TestBenchGate_EmptyBodyInnerWriteAllocs locks in the inspected inner leg's
// skip. This one carries no network at all, so it is the cleanest view of the
// cost: measured 6 allocs/op with the sentinel against 13 for the frozen
// wrapping, and 1.2 µs against 4.2 µs of pure CPU. Bound at 9.
func TestBenchGate_EmptyBodyInnerWriteAllocs(t *testing.T) {
	const maxAllocs int64 = 9

	sentinel := testing.Benchmark(func(b *testing.B) { benchEmptyBodyInnerWrite(b, false) })
	wrapped := testing.Benchmark(func(b *testing.B) { benchEmptyBodyInnerWrite(b, true) })

	sa, wa := sentinel.AllocsPerOp(), wrapped.AllocsPerOp()
	t.Logf("inner-leg write sentinel: %d allocs/op, %d B/op, %d ns/op (bound %d)", sa, sentinel.AllocedBytesPerOp(), sentinel.NsPerOp(), maxAllocs)
	t.Logf("inner-leg write wrapped:  %d allocs/op, %d B/op, %d ns/op", wa, wrapped.AllocedBytesPerOp(), wrapped.NsPerOp())

	if sa > maxAllocs {
		t.Errorf("bodyless inner-leg write allocates %d/op, bound %d — a wrapper on the http.NoBody sentinel is back on the inspected path",
			sa, maxAllocs)
	}
	if sa >= wa {
		t.Errorf("bodyless inner-leg write (%d allocs/op) is no cheaper than the pre-change wrapping (%d allocs/op) — the sentinel skip has stopped firing",
			sa, wa)
	}
}
