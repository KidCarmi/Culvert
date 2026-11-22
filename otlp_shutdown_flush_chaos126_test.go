package main

// CHAOS-126 — the OTLP exporters' shutdown flush.
//
// internal/otlp's push loop has always carried a `case <-ctx.Done():` arm
// commented "Final flush on shutdown". It could not flush on a shutdown:
// nothing in the shutdown sequence cancelled that loop. main_shutdown.go
// flushed syslog, the community DB, the log store, the request log, the
// audit FD and the cluster store, and left the one sink whose entire state
// lives in a RAM ring buffer with no hook at all — so every graceful
// restart lost up to a full push interval of request spans, with no counter
// and no log line. The only two callers that DID cancel the loop were
// Stop(), which clears the endpoint first (so the flush drained the ring and
// returned having posted nothing), and Configure(new), whose flush posted the
// previous collector's spans to the new one.
//
// These gates pin the hook, its position, and the fact that it reaches the
// production singletons. Delivery itself is gated in the engine suite: the
// shipped transport dials through ssrf.SafeDialContext, which correctly
// refuses the loopback address an httptest collector listens on, so a
// main-side test cannot (and should not be able to) post to one.

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/otlp"
)

// swapOTLPGlobalsForTest installs fresh exporters and restores the originals,
// per the house rule that a global a test installs is a global the test takes
// back (not merely stops pointing at).
func swapOTLPGlobalsForTest(t *testing.T) {
	t.Helper()
	oldMetrics, oldTraces := globalOTLP, globalOTLPTraces
	globalOTLP = otlp.NewMetrics(nil)
	globalOTLPTraces = otlp.NewSpans()
	t.Cleanup(func() {
		globalOTLP.Stop()
		globalOTLPTraces.Stop()
		globalOTLP, globalOTLPTraces = oldMetrics, oldTraces
	})
}

// The hook must exist, sit above the flush boundary, run after every durable
// closer, and run before the log closer. Each of those four is a separate
// failure mode: no hook at all is the defect this round found; below the
// boundary a stuck drain can spend its budget; before a durable closer an
// off-box collector can starve local durability; after the log closer its own
// diagnostics go to a sink that is already closed.
func TestChaos126_OTLPFlushHookPosition(t *testing.T) {
	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())

	orders := map[string]int{}
	for _, h := range late.Hooks() {
		orders[h.Name] = h.Order
	}
	otlpOrder, ok := orders["otlp-flush"]
	if !ok {
		t.Fatal(`no "otlp-flush" hook: the span buffer is RAM-only, so without a hook every graceful restart loses the window silently`)
	}
	if otlpOrder <= shutdownFlushBoundary {
		t.Errorf("otlp-flush order %d is at or below shutdownFlushBoundary (%d): a stuck drain could spend its budget",
			otlpOrder, shutdownFlushBoundary)
	}
	for _, durable := range []string{"cluster-store-flush", "syslog-close", "community-db-close",
		"log-store-close", "request-log-close", "audit-log-close"} {
		o, found := orders[durable]
		if !found {
			t.Fatalf("durable closer %q is missing from the late registry", durable)
		}
		if otlpOrder <= o {
			t.Errorf("otlp-flush (%d) must run AFTER %q (%d): an off-box collector must not spend the reserve a local store needs",
				otlpOrder, durable, o)
		}
	}
	if otlpOrder >= orders["log-closer"] {
		t.Errorf("otlp-flush (%d) must run BEFORE log-closer (%d) so its own diagnostics reach the log file",
			otlpOrder, orders["log-closer"])
	}

	// The partition is what actually decides the phase; assert it directly
	// rather than trusting the boundary arithmetic above.
	_, flush := late.PartitionAt(shutdownFlushBoundary)
	inFlush := false
	for _, h := range flush.Hooks() {
		if h.Name == "otlp-flush" {
			inFlush = true
		}
	}
	if !inFlush {
		t.Error("otlp-flush is not in the flush partition")
	}
}

// The hook must reach the production singletons. Driven through an endpoint
// the exporter can hold but never post to (the engine's own validEndpoint
// barrier rejects it), so the gate needs no network at all and cannot be
// satisfied by a hook that quietly does nothing: a span exporter that was
// never asked to flush records no failure.
func TestChaos126_OTLPFlushHookReachesTheExporters(t *testing.T) {
	snapshotLateShutdownGlobals(t)
	swapOTLPGlobalsForTest(t)

	globalOTLPTraces.Configure("ftp://collector.invalid:4318", nil)
	globalOTLP.Configure("ftp://collector.invalid:4318", nil)
	globalOTLPTraces.RecordSpan(SpanRecord{
		TraceID: "0af7651916cd43dd8448eb211c80319c", SpanID: "b7ad6b7169203331",
		Name: "proxy_request", Method: "CONNECT", Host: "chaos126.example",
		Status: "BLOCKED", StartNano: 1, EndNano: 2,
	})

	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll: %v", err)
	}

	if got := globalOTLPTraces.Health().FailureCount; got == 0 {
		t.Error("the span exporter recorded no push attempt: the shutdown hook did not reach it")
	}
	if got := globalOTLP.Health().FailureCount; got == 0 {
		t.Error("the metrics exporter recorded no push attempt: the shutdown hook did not reach it")
	}
	// The attempt failed and the process is going away, so the span must be
	// ENDED and COUNTED rather than retained for an interval that will never
	// come. This assertion previously demanded the opposite — a retained
	// batch, DroppedSpans 0 — which pinned exactly the silent loss the round
	// set out to remove, moved to the last second of the process's life. The
	// count also reaches the log file, which is the only form in which the
	// number survives the exit.
	if got := globalOTLPTraces.Health().DroppedSpans; got != 1 {
		t.Errorf("DroppedSpans = %d after a failed shutdown flush; want 1 — a span that dies at shutdown is a lost span", got)
	}
}

// The hook must use the TERMINAL flush, not the ordinary one: a failed
// ordinary flush retains, and retention has no future once the process is
// exiting. Pinned structurally, because the difference is invisible in the
// success case that CI usually exercises.
func TestChaos126_OTLPFlushHookUsesTheTerminalFlush(t *testing.T) {
	snapshotLateShutdownGlobals(t)
	swapOTLPGlobalsForTest(t)

	globalOTLPTraces.Configure("ftp://collector.invalid:4318", nil)
	for i := 0; i < 3; i++ {
		globalOTLPTraces.RecordSpan(SpanRecord{Name: "proxy_request", StartNano: int64(i)})
	}

	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll: %v", err)
	}
	if got := globalOTLPTraces.Health().DroppedSpans; got != 3 {
		t.Errorf("DroppedSpans = %d; want 3 — the hook must END and COUNT what it could not deliver, not retain it into a dying process", got)
	}
}

// With export disabled — the shipped default — the hook must be a silent
// no-op that records nothing and costs nothing.
func TestChaos126_OTLPFlushHookIsANoOpWhenDisabled(t *testing.T) {
	snapshotLateShutdownGlobals(t)
	swapOTLPGlobalsForTest(t)

	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll with OTLP disabled: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("late phase took %s with OTLP disabled; the hook must be a no-op", elapsed)
	}
	if h := globalOTLPTraces.Health(); h.FailureCount != 0 || h.DroppedSpans != 0 {
		t.Errorf("disabled span exporter recorded activity: %+v", h)
	}
}

// The flush budget must stay well inside the reserve it shares with every
// durable closer. An OTLP flush that could spend the whole reserve would put
// the next boot's cleanliness behind an off-box collector's availability —
// the dependency the reserve exists to remove.
func TestChaos126_OTLPFlushBudgetFitsInsideTheReserve(t *testing.T) {
	if otlpShutdownFlushBudget <= 0 {
		t.Fatal("otlpShutdownFlushBudget must be positive: an unbounded terminal flush is the thing being prevented")
	}
	if otlpShutdownFlushBudget*2 > defaultShutdownBudget.Flush {
		t.Errorf("otlpShutdownFlushBudget (%s) is more than half the flush reserve (%s): the durable closers run inside the same reserve",
			otlpShutdownFlushBudget, defaultShutdownBudget.Flush)
	}
}
