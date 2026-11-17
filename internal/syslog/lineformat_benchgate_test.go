//go:build benchgate

package syslog

// lineformat_benchgate_test.go — the allocation gate for syslog line assembly.
//
// Behind the benchgate tag, like every other allocation gate in the tree, so
// it runs in the dedicated "Gate · perf-regression (allocs/op)" job
// (.github/workflows/pr-fast-gate.yml runs `go test -tags benchgate -run
// TestBenchGate_` over an explicit package list, which internal/syslog is on)
// and nowhere else. The tag is what makes the gate meaningful: it keeps ~12s of
// benchmarking off every ordinary lane, and it keeps the gate off the -race
// lanes, where the detector allocates per instrumented access — enough to both
// inflate the bounds and REVERSE the legacy comparison (the pooled writeLine
// measured 251 B/op against fmt.Fprint's 164 under -race), so the verdict would
// be about instrumentation rather than about the code.
//
// The benchmarks and the legacy arms it measures live in the untagged
// lineformat_bench_test.go, so they stay runnable by hand without the tag.
// Nothing is lost on the lanes this does not run on: the byte-identity, handoff
// and pool-residency tests in lineformat_test.go are neither timing nor
// allocation gates and run everywhere.

import "testing"

// TestBenchGate_SyslogLineAllocs bounds the per-record cost this sink charges
// the goroutine that logged the record, and asserts it stays cheaper than the
// shape it replaced.
//
// It is gated as a CEILING on allocs/op and B/op rather than on ns/op, for the
// usual reason: those two are deterministic and hardware-independent, and this
// cost is paid inside the request goroutine once per logged request on every
// protocol whenever a SIEM collector is configured.
//
// The legacy comparison is the load-bearing half. An absolute bound alone
// would still pass if someone reinstated the intermediate json.Marshal slice
// and the string copy while the bound happened to be generous; comparing
// against legacyWriteRequest/legacyFormatLine fails the moment the fused
// builder stops being used.
func TestBenchGate_SyslogLineAllocs(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark gate")
	}
	// Steady state at the time of measurement, with headroom:
	//
	//	WriteRequest  3 allocs / 1 120 B   (legacy 11 / 2 017)
	//	formatLine    1 alloc  /   480 B   (legacy  6 /   528)
	cases := []struct {
		name          string
		cur, legacy   func(*testing.B)
		allocs, bytes int64
	}{
		{"WriteRequest", BenchmarkWriteRequest_RealEntry, BenchmarkWriteRequest_RealEntryLegacy, 4, 1280},
		{"formatLine/rfc3164", BenchmarkFormatLine_RFC3164, BenchmarkFormatLine_RFC3164Legacy, 1, 640},
		{"formatLine/rfc5424", BenchmarkFormatLine_RFC5424, BenchmarkFormatLine_RFC5424Legacy, 1, 640},
		{"writeLine", BenchmarkWriteLine, BenchmarkWriteLineLegacy, 0, 0},
	}
	for _, c := range cases {
		cur := testing.Benchmark(c.cur)
		legacy := testing.Benchmark(c.legacy)
		if cur.N == 0 || legacy.N == 0 {
			t.Errorf("%s: a benchmark arm did not run (current N=%d, legacy N=%d), so the bounds below measured nothing", c.name, cur.N, legacy.N)
			continue
		}
		t.Logf("%s: %d allocs/op (bound %d), %d B/op (bound %d), %d ns/op — legacy %d allocs/op, %d B/op, %d ns/op",
			c.name, cur.AllocsPerOp(), c.allocs, cur.AllocedBytesPerOp(), c.bytes, cur.NsPerOp(),
			legacy.AllocsPerOp(), legacy.AllocedBytesPerOp(), legacy.NsPerOp())

		if got := cur.AllocsPerOp(); got > c.allocs {
			t.Errorf("REGRESSION: %s allocates %d/op, exceeding the bound %d — line assembly (internal/syslog/lineformat.go) "+
				"has regained a per-record allocation. This is paid inside the request goroutine on every logged request, "+
				"on every protocol, whenever a SIEM collector is configured. Most likely a body is being marshalled into an "+
				"intermediate slice or copied into an intermediate string again instead of being encoded into the line buffer.",
				c.name, got, c.allocs)
		}
		if got := cur.AllocedBytesPerOp(); got > c.bytes {
			t.Errorf("REGRESSION: %s allocates %d B/op, exceeding the bound %d — re-measure BenchmarkWriteRequest_RealEntry "+
				"and the BenchmarkFormatLine arms before moving this bound.", c.name, got, c.bytes)
		}
		if cur.AllocsPerOp() >= legacy.AllocsPerOp() {
			t.Errorf("%s is no cheaper than the shape it replaced (%d vs %d allocs/op): the fused line builder is no longer "+
				"on this path. See lineformat.go for what it removes and legacyWriteRequest/legacyFormatLine for what it replaced.",
				c.name, cur.AllocsPerOp(), legacy.AllocsPerOp())
		}
	}
}
