//go:build benchgate

package threatfeed

// Wall-clock half of the CheckRequestURL cost gate.
//
//	go test -tags benchgate -run 'TestBenchGate_' -v ./internal/threatfeed
//
// It lives behind the benchgate tag because an ns/op comparison measured
// inside the shuffled, -count=2 default suite inherits the load of every
// package running beside it; a gate that can flake gets muted. The benchgate
// job runs it serially. The untagged suite keeps the deterministic half,
// TestBenchGate_CheckRequestURLAllocs, on every lane.

import "testing"

// gateSink keeps the timing gate's two arms symmetric — see its comment.
var gateSink bool

// raceDetectorOn is set true by the //go:build race && benchgate companion file
// (race_on_test.go).
var raceDetectorOn = false

// TestBenchGate_CheckRequestURLBeatsLegacy is the timing half, expressed as a
// RATIO measured in ONE run so it is machine-independent and needs no
// re-baselining. The bound is deliberately loose (the measured saving is far
// larger) because its job is to catch the round trip coming back, not to police
// a few nanoseconds.
//
// It does not run under -race. The saving it measures is mostly the legacy
// arm's extra allocations, and the race detector's per-access instrumentation
// costs far more than those, so both arms converge (measured on the Fast gate's
// race lane: 12054 vs 11830 and 7316 vs 7271 ns/op, ~1% apart) and the verdict
// becomes a coin toss in either direction. Nothing is lost by stepping aside:
// TestBenchGate_CheckRequestURLAllocs pins the same regression on every lane
// (allocation counts are race-independent), and this gate runs uninstrumented
// in the serial benchgate job.
func TestBenchGate_CheckRequestURLBeatsLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	if raceDetectorOn {
		t.Skip("timing gate: -race instrumentation swamps the allocation saving being timed; the allocs gate covers this lane")
	}
	tf := benchFeed(1000)
	u := benchProxyURL(t)

	// Both arms assign into the same package-level sink so neither can be
	// optimised away differently from the other; the verdict itself is not
	// under test here (the differential covers it).
	fast := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gateSink, _ = tf.CheckRequestURL(u)
		}
	})
	legacy := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gateSink, _ = tf.CheckURL(u.String())
		}
	})
	if fast.NsPerOp() >= legacy.NsPerOp() {
		t.Errorf("CheckRequestURL %d ns/op is not faster than CheckURL(u.String()) %d ns/op",
			fast.NsPerOp(), legacy.NsPerOp())
	}
}
