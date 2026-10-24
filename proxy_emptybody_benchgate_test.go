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
// differently-tuned runner cannot make the comparison lie, whatever the
// absolute numbers have drifted to across Go releases.
//
// WHAT THESE GATES DO NOT COVER. The workloads here build and wrap their own
// requests; they do NOT call prepareHTTPForward or the inspected inner loop,
// deliberately, so that the measurement is the framing and serialization cost
// and not proxy or inspection overhead. A wrapper reintroduced in PRODUCTION
// code would therefore leave both gates passing. What catches that is the
// normal suite: TestPrepareHTTPForward_EmptyBodyKeepsSentinel calls the real
// prepareHTTPForward and asserts the sentinel survives it, and
// TestInspectInnerLeg_EmptyBodyKeepsClientFraming drives a real CONNECT /
// forged-leaf tunnel (both in proxy_emptybody_test.go). These gates measure the
// cost that skip is worth; those tests prove the skip is still there. Neither
// substitutes for the other, and neither should be deleted on the strength of
// the other passing.

import (
	"testing"
)

// TestBenchGate_EmptyBodyForwardAllocs locks in the forward leg's skip.
//
// Measured (go1.27.3, linux/amd64, 4 vCPU): 69 allocs/op with the sentinel
// preserved, 80 allocs/op for the frozen pre-change wrapping — the difference
// being net/http's probeRequestBody machinery (goroutine, channel, 200 ms
// timer) plus the two wrapper objects. On go1.26.10 the same pair measured
// 68/79: both arms moved by one, the gap did not.
//
// The bound sits at 73, between the two and clear of both: above the measured
// sentinel value so stdlib churn does not flip the gate (that headroom is what
// absorbed the go1.26→go1.27 +1), and below the legacy 80 so reintroducing an
// unconditional wrapper fails here.
func TestBenchGate_EmptyBodyForwardAllocs(t *testing.T) {
	const maxAllocs int64 = 73

	sentinel := testing.Benchmark(func(b *testing.B) { benchEmptyBodyForward(b, "GET", false) })
	wrapped := testing.Benchmark(func(b *testing.B) { benchEmptyBodyForward(b, "GET", true) })

	sa, wa := sentinel.AllocsPerOp(), wrapped.AllocsPerOp()
	t.Logf("empty-body forward sentinel: %d allocs/op, %d B/op (bound %d)", sa, sentinel.AllocedBytesPerOp(), maxAllocs)
	t.Logf("empty-body forward wrapped:  %d allocs/op, %d B/op", wa, wrapped.AllocedBytesPerOp())

	if sa > maxAllocs {
		t.Errorf("bodyless forward allocates %d/op, bound %d — the isolated cost of a preserved http.NoBody has grown; net/http may be probing the body again (this gate does not call prepareHTTPForward, so check proxy_emptybody_test.go for the production-path contract)",
			sa, maxAllocs)
	}
	if sa >= wa {
		t.Errorf("preserving the sentinel (%d allocs/op) is no cheaper than the frozen pre-change wrapping (%d allocs/op) — the saving this PR measured has gone",
			sa, wa)
	}
}

// TestBenchGate_EmptyBodyInnerWriteAllocs locks in the inspected inner leg's
// skip. This one carries no network at all, so it is the cleanest view of the
// cost, and it did not move across the toolchain bump at all (6/13 on both
// go1.26.10 and go1.27.3): measured 6 allocs/op with the sentinel against 13 for the frozen
// wrapping, and 1.2 µs against 4.2 µs of pure CPU. Bound at 9.
func TestBenchGate_EmptyBodyInnerWriteAllocs(t *testing.T) {
	const maxAllocs int64 = 9

	sentinel := testing.Benchmark(func(b *testing.B) { benchEmptyBodyInnerWrite(b, false) })
	wrapped := testing.Benchmark(func(b *testing.B) { benchEmptyBodyInnerWrite(b, true) })

	sa, wa := sentinel.AllocsPerOp(), wrapped.AllocsPerOp()
	t.Logf("inner-leg write sentinel: %d allocs/op, %d B/op, %d ns/op (bound %d)", sa, sentinel.AllocedBytesPerOp(), sentinel.NsPerOp(), maxAllocs)
	t.Logf("inner-leg write wrapped:  %d allocs/op, %d B/op, %d ns/op", wa, wrapped.AllocedBytesPerOp(), wrapped.NsPerOp())

	if sa > maxAllocs {
		t.Errorf("bodyless inner-leg write allocates %d/op, bound %d — the isolated serialization cost of a preserved http.NoBody has grown (this gate does not run the inspected loop, so check proxy_emptybody_test.go for the production-path contract)",
			sa, maxAllocs)
	}
	if sa >= wa {
		t.Errorf("preserving the sentinel (%d allocs/op) is no cheaper than the frozen pre-change wrapping (%d allocs/op) — the saving this PR measured has gone",
			sa, wa)
	}
}
