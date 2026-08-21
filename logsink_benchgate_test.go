//go:build benchgate

package main

// Perf-regression gate for the asynchronous process-log sink (internal/logsink).
//
// Lives with the other benchgate tests because it is a PERFORMANCE contract,
// not a correctness one — the correctness contracts (nothing lost, FIFO order,
// flushing Closer, JSON mode) are in logger_async_test.go and run in the normal
// suite. Run with:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .

import (
	"log"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/logsink"
)

// TestBenchGate_LogSinkDecouplesCaller is the regression gate for the whole
// optimization, in the deterministic form: with a destination that stalls for
// 20ms per write, a burst of log lines that fits in the queue must return in
// far less than burst x 20ms. Written synchronously — the pre-change behavior —
// the same burst cannot finish in under burst x 20ms.
//
// Timing is used only as an ORDER-OF-MAGNITUDE separator (a 40x gap), not as a
// ns/op measurement, so the gate holds across CI runners.
func TestBenchGate_LogSinkDecouplesCaller(t *testing.T) {
	const perWrite = 20 * time.Millisecond
	const burst = 64

	async := logsink.New(&stallingWriter{d: perWrite})
	t.Cleanup(func() { _ = async.Close() })
	l := log.New(async, "[Culvert] ", log.LstdFlags)

	start := time.Now()
	for i := 0; i < burst; i++ {
		l.Printf("POLICY_ALLOW seq=%d", i)
	}
	elapsed := time.Since(start)

	syncFloor := perWrite * burst // 1.28s
	if limit := perWrite * 4; elapsed > limit {
		t.Fatalf("REGRESSION: %d log lines against a %v-per-write sink took %v (limit %v, synchronous floor %v) — "+
			"the proxy request goroutine is blocking on the log sink again. Every allowed request emits a "+
			"POLICY_ALLOW line, so this re-couples request latency to stdout/disk latency across the whole "+
			"process. See internal/logsink.", burst, perWrite, elapsed, limit, syncFloor)
	}
	t.Logf("%d lines against a %v sink returned in %v (synchronous floor %v)", burst, perWrite, elapsed, syncFloor)
}

// stallingWriter stands in for a slow log volume or a container stdout whose
// reader is not keeping up.
type stallingWriter struct{ d time.Duration }

func (s *stallingWriter) Write(p []byte) (int, error) {
	time.Sleep(s.d)
	return len(p), nil
}
