package reqlog

import "testing"

// Benchmarks for the enqueue fast path (persistRunning, persist.go).
//
// enqueue runs once per logged request, which on this product is once per
// proxied request: reqlog.Add is called from the HTTP forward path, the
// CONNECT path and every terminal block, so what it costs is what every
// request pays. The interesting arm is DISABLED persistence — the default
// configuration, and the one where the old code's exclusive persistMu bought
// nothing at all.
//
// Each arm is measured against legacyEnqueueDisabledProbe, the frozen
// pre-change lock discipline in persist_fastpath_test.go, so the comparison
// is reproducible from the tree instead of quoted from a commit message and
// both arms are timed on the same machine in the same run. The parallel arms
// are the point of the change: run them across -cpu values to see that the
// old shape's cost per request RISES with core count and the new one's does
// not.
//
//	go test ./internal/reqlog/ -run '^$' -bench 'Enqueue_Disabled|AddParallel' \
//	    -benchmem -cpu=1,2,4 -count=5
//
// Measured on a 4-core Xeon @ 2.10GHz, count=5, benchtime=2s (legacy → current):
//
//	Enqueue_DisabledParallel      -cpu=1    22.7 → 5.9 ns/op
//	Enqueue_DisabledParallel      -cpu=4    65.8 → 1.5 ns/op
//	Add            (whole of Add) -cpu=1    55.5 → 39.7 ns/op
//	AddParallel    (whole of Add) -cpu=4   196.1 → 142.1 ns/op
//
// The remaining ~142 ns at four goroutines is ringMu, the in-memory ring's own
// exclusive mutex, which this change deliberately does not touch.

func benchEnqueueDisabled(b *testing.B, enq func(Entry), parallel bool) {
	restore := SwapPersistenceForTest()
	defer restore()
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	if !parallel {
		for i := 0; i < b.N; i++ {
			enq(e)
		}
		return
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			enq(e)
		}
	})
}

// BenchmarkEnqueue_Disabled is the per-request floor in the default
// configuration: what a logged request pays to establish that there is no
// JSONL file to write to.
func BenchmarkEnqueue_Disabled(b *testing.B) {
	benchEnqueueDisabled(b, enqueue, false)
}

// BenchmarkEnqueue_DisabledLegacy is the same measurement against the frozen
// pre-change lock discipline.
func BenchmarkEnqueue_DisabledLegacy(b *testing.B) {
	benchEnqueueDisabled(b, legacyEnqueueDisabledProbe, false)
}

// BenchmarkEnqueue_DisabledParallel is the arm that matters: concurrent
// request goroutines, which is how a proxy calls this. The old shape
// serialized them on one exclusive mutex.
func BenchmarkEnqueue_DisabledParallel(b *testing.B) {
	benchEnqueueDisabled(b, enqueue, true)
}

// BenchmarkEnqueue_DisabledParallelLegacy is the frozen pre-change shape
// under the same concurrency.
func BenchmarkEnqueue_DisabledParallelLegacy(b *testing.B) {
	benchEnqueueDisabled(b, legacyEnqueueDisabledProbe, true)
}

// BenchmarkEnqueue_EnabledParallel measures the arm the change does NOT claim
// to improve: with a live drain goroutine the channel send dominates and
// enqueue still takes persistMu exactly as before. It is here so a future
// reader can see that the enabled path was measured rather than assumed, and
// so a regression that pushes cost ONTO this path is visible.
func BenchmarkEnqueue_EnabledParallel(b *testing.B) {
	restoreRing := SwapRingForTest()
	defer restoreRing()
	restore := SetWriterForTest(discardSink{})
	defer restore()
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			enqueue(e)
		}
	})
}

// discardSink is a zero-cost JSONL sink, so the enabled benchmark measures
// the queue hand-off rather than a test sink's own mutex.
type discardSink struct{}

func (discardSink) Write(p []byte) (int, error) { return len(p), nil }
