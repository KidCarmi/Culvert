package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestContainedPanicRows(t *testing.T) {
	recent := 5 * time.Minute

	if got := containedPanicRows(0, recent, "feed_sync", "abc"); len(got) != 0 {
		t.Errorf("no contained panic: want no row, got %+v", got)
	}
	if got := containedPanicRows(3, containedPanicRecentWindow+time.Minute, "feed_sync", "abc"); len(got) != 0 {
		t.Errorf("older than the window: want no row, got %+v", got)
	}

	got := containedPanicRows(3, recent, "feed_sync", "abc123")
	if len(got) != 1 {
		t.Fatalf("recent contained panic: want 1 row, got %d", len(got))
	}
	c := got[0]
	if c.Code != containedPanicCode || c.Status != diagWarn {
		t.Fatalf("unexpected row %+v", c)
	}
	for _, want := range []string{"3 internal fault(s)", "5m0s ago", `"feed_sync"`, "crash_id=abc123"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message must contain %q, got %q", want, c.Message)
		}
	}
	for _, want := range []string{"panic_recovered", "Support", "Contained panic", "24h"} {
		if !strings.Contains(c.OperatorAction, want) {
			t.Errorf("action must contain %q, got %q", want, c.OperatorAction)
		}
	}

	// Every record throttled (no last-crash record): the row still reports the
	// count and recency, and names no component.
	got = containedPanicRows(2, recent, "", "")
	if len(got) != 1 || strings.Contains(got[0].Message, "component \"") || strings.Contains(got[0].Message, "crash_id") {
		t.Errorf("no recorded crash: want one row naming no component, got %+v", got)
	}
}

// The sink stamps every contained panic and the operator contract reports it;
// the row never carries the panic value. The window is measured on the
// monotonic clock, so driving monoNanos past it clears the row. Not parallel:
// it swaps the package-level monoNanos and resets the crash-plane globals.
func TestContainedPanic_SinkFeedsOperatorContractAndWindowIsMonotonic(t *testing.T) {
	resetCrashGuardStateForTest()
	prevMono := monoNanos
	prevFire := firePanicContainedAlert
	t.Cleanup(func() {
		monoNanos = prevMono
		firePanicContainedAlert = prevFire
		resetCrashGuardStateForTest()
	})
	firePanicContainedAlert = func(string, string) {} // no webhook dispatch from this test
	var clock int64 = 1_000
	monoNanos = func() int64 { return clock }

	if got := checkContainedPanic(); len(got) != 0 {
		t.Fatalf("row present before any contained panic: %+v", got)
	}

	const secret = "s3cr3t-panic-value-7f1c"
	const component = "diag-contained-panic-test"
	recordCrash(component, "", secret)
	recordCrash(component, "", secret) // throttled by the sink, still counted and stamped

	if atomic.LoadInt64(&crashLastMono) == 0 {
		t.Fatal("contained panic did not record its timestamp")
	}
	row := findDiagnosticCheck(buildOperatorContract(), containedPanicCode)
	if row == nil || row.Status != diagWarn {
		t.Fatalf("operator contract missing the warn row after a contained panic: %+v", row)
	}
	if !strings.Contains(row.Message, "2 internal fault(s)") || !strings.Contains(row.Message, component) {
		t.Errorf("row must give the count and the component, got %q", row.Message)
	}
	rec, ok := lastCrashSnapshot()
	if !ok || !strings.Contains(row.Message, "crash_id="+rec.ID) {
		t.Errorf("row must quote the recorded crash id %q, got %q", rec.ID, row.Message)
	}
	if strings.Contains(row.Message+row.OperatorAction, secret) {
		t.Fatalf("row leaked the panic value: %+v", row)
	}

	clock += int64(containedPanicRecentWindow - time.Minute)
	if got := checkContainedPanic(); len(got) != 1 {
		t.Fatalf("inside the window: want 1 row, got %d", len(got))
	}
	clock += int64(2 * time.Minute)
	if got := checkContainedPanic(); len(got) != 0 {
		t.Fatalf("past the window: want no row, got %+v", got)
	}
}
