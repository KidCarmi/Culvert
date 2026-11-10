//go:build benchgate

package main

// Heap-exposure measurement for the scan sidecar's admission gate — CHAOS-115.
//
//	go test -tags benchgate -run 'TestBenchGate_ScanSvcAdmission' -v .
//
// WHY THIS IS NOT IN THE DEFAULT SUITE. `runtime.MemStats.HeapAlloc` is a
// PROCESS-wide number. This measurement first lived in
// `scan_svc_admission_chaos_test.go` and passed in isolation at ~6-9 MiB
// against a 16 MiB ceiling; in the full package run, with ~140 live goroutines
// from unrelated tests churning, the same correctly-bounded sidecar measured
// 37 MiB. The contract held and the oracle did not. The behavioural contract
// therefore lives on the always-on gauge assertions, and the number lives here,
// where the process is quiet — the same division CHAOS-111's wall-clock budgets
// took when they moved to this tag.
//
// WHAT IT IS FOR. The defect CHAOS-115 fixed was a HEAP defect:
// `handleScan` buffered up to `window+1` bytes per request before doing
// anything else, with nothing bounding how many requests were inside that
// buffer at once. Measured on the pre-fix tree, callers that declare a
// Content-Length and stall one byte short so every handler parks inside
// readScanWindow:
//
//	window = 1 MiB
//	slow callers | handlers buffering concurrently | heap delta
//	          64 |                             64 |    75.8 MiB
//	         192 |                            192 |   244.5 MiB
//
// Linear at ~1.27x the window per request (io.ReadAll grows by doubling). This
// gate re-measures the fixed shape so a future change that reverts the
// ORDERING — admission after the read rather than before — is visible as a
// number rather than only as a gauge.

import (
	"runtime"
	"testing"
	"time"
)

func TestBenchGate_ScanSvcAdmissionBoundsTheHeap(t *testing.T) {
	const window = 1 << 20
	const slots = 4
	const callers = 8 * slots

	withScanWindow(t, window, nil)
	resetScanSvcAdmission(t, slots)
	addr := startScanSvc(t)

	prefix := stallPayload(window)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	// Built BEFORE the baseline sample and shared, so the only thing that grows
	// with the caller count is the sidecar's own buffering — see stallPayload.
	for i := 0; i < callers; i++ {
		stallingScanPost(t, addr, prefix)
	}
	peak := waitForInflight(slots, 10*time.Second)

	runtime.ReadMemStats(&after)
	// Kept in uint64: MemStats fields are unsigned and converting them is a
	// gosec G115 finding. A shrinking heap is a zero delta, not a negative one.
	var heapDelta uint64
	if after.HeapAlloc > before.HeapAlloc {
		heapDelta = after.HeapAlloc - before.HeapAlloc
	}

	t.Logf("CHAOS-115 heap: window=%d slots=%d stalled callers=%d peak inflight=%d heap delta=%.1f MiB goroutines=%d",
		window, slots, callers, peak, float64(heapDelta)/(1<<20), runtime.NumGoroutine())

	if peak != slots {
		t.Fatalf("peak inflight = %d, want %d: the measurement below is only meaningful with the gate holding", peak, slots)
	}

	// The ceiling sits between the bounded regime (~6 MiB measured) and the
	// pre-fix one (~40 MiB for this ratio), with roughly 3x of margin either
	// way. Under this tag the process is quiet enough for that to be a
	// measurement rather than a flake.
	const ceiling = uint64(slots) * window * 4
	if heapDelta > ceiling {
		t.Errorf("sidecar heap grew %.1f MiB holding %d stalled callers through %d slots (ceiling %.1f MiB): bodies are being buffered outside the bound — check that admission is acquired BEFORE readScanWindow",
			float64(heapDelta)/(1<<20), callers, slots, float64(ceiling)/(1<<20))
	}
}
