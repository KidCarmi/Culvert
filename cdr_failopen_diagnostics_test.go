package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCDRFailOpenPassthroughRows(t *testing.T) {
	recent := 5 * time.Minute
	open := CDRConfig{Enabled: true, FailMode: "open", DefaultProfile: "default"}

	none := []struct {
		name  string
		cfg   CDRConfig
		total int64
		ago   time.Duration
	}{
		{"disabled", CDRConfig{Enabled: false}, 3, recent},
		{"fail closed", CDRConfig{Enabled: true, FailMode: "closed"}, 3, recent},
		{"never fell open", open, 0, recent},
		{"older than window", open, 3, cdrFailOpenRecentWindow + time.Minute},
	}
	for _, tc := range none {
		if got := cdrFailOpenPassthroughRows(tc.cfg, tc.total, tc.ago); len(got) != 0 {
			t.Errorf("%s: want no row, got %+v", tc.name, got)
		}
	}

	got := cdrFailOpenPassthroughRows(open, 3, recent)
	if len(got) != 1 {
		t.Fatalf("recent fail-open: want 1 row, got %d", len(got))
	}
	c := got[0]
	if c.Code != cdrFailOpenRecentCode || c.Status != diagWarn {
		t.Fatalf("unexpected row %+v", c)
	}
	if !strings.Contains(c.Message, "3 document(s)") || !strings.Contains(c.Message, "5m0s ago") {
		t.Errorf("message must state the count and recency, got %q", c.Message)
	}
	// The counter records the fail-open DECISION; DPI and AV still run after
	// it and can block the document, so the row must not claim a delivery.
	if strings.Contains(c.Message, "delivered") || !strings.Contains(c.Message, "may still have blocked") {
		t.Errorf("message must not claim delivery and must say downstream scanning still applied, got %q", c.Message)
	}
	if !strings.Contains(c.OperatorAction, "CDR_ERROR") || !strings.Contains(c.OperatorAction, "fail_mode") {
		t.Errorf("action must name the log filter and the fail_mode setting, got %q", c.OperatorAction)
	}

	// Unset fail_mode defaults to open and must warn too.
	if got := cdrFailOpenPassthroughRows(CDRConfig{Enabled: true}, 1, recent); len(got) != 1 {
		t.Errorf("default fail_mode: want 1 row, got %d", len(got))
	}
}

// The window is measured on the monotonic clock (CHAOS-83): driving monoNanos
// past the window clears the row, and no wall-clock reading is involved. Not
// parallel: it swaps the package-level monoNanos.
func TestCDRFailOpenPassthrough_WindowIsMonotonic(t *testing.T) {
	prevTotal := atomic.LoadInt64(&statCDRFailOpen)
	prevLast := atomic.LoadInt64(&cdrFailOpenLastMono)
	prevMono := monoNanos
	t.Cleanup(func() {
		atomic.StoreInt64(&statCDRFailOpen, prevTotal)
		atomic.StoreInt64(&cdrFailOpenLastMono, prevLast)
		monoNanos = prevMono
	})
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "open", DefaultProfile: "default"})

	var clock int64 = 1_000
	monoNanos = func() int64 { return clock }
	atomic.StoreInt64(&statCDRFailOpen, 1)
	noteCDRFailOpenPassthrough()

	clock += int64(cdrFailOpenRecentWindow - time.Minute)
	if got := checkCDRFailOpenPassthrough(); len(got) != 1 {
		t.Fatalf("inside the window: want 1 row, got %d", len(got))
	}
	clock += int64(2 * time.Minute)
	if got := checkCDRFailOpenPassthrough(); len(got) != 0 {
		t.Fatalf("past the window: want no row, got %+v", got)
	}
}

// The fail-open branch of cdrErrorOutcome records the timestamp the row reads;
// the outcome itself is unchanged (pass, status ERROR).
func TestCDRErrorOutcome_FailOpenRecordsPassthroughForDiagnostics(t *testing.T) {
	prevTotal := atomic.LoadInt64(&statCDRFailOpen)
	prevErr := atomic.LoadInt64(&statCDRErrors)
	prevLast := atomic.LoadInt64(&cdrFailOpenLastMono)
	t.Cleanup(func() {
		atomic.StoreInt64(&statCDRFailOpen, prevTotal)
		atomic.StoreInt64(&statCDRErrors, prevErr)
		atomic.StoreInt64(&cdrFailOpenLastMono, prevLast)
	})
	atomic.StoreInt64(&cdrFailOpenLastMono, 0)
	cfg := CDRConfig{Enabled: true, FailMode: "open", DefaultProfile: "default"}
	withActiveCDRConfig(t, cfg)

	if got := checkCDRFailOpenPassthrough(); len(got) != 0 {
		t.Fatalf("row present before any passthrough: %+v", got)
	}

	res := cdrErrorOutcome("engine error", "default", "full", 1, cfg)
	if res.Outcome != cdrPass || res.Status != "ERROR" {
		t.Fatalf("fail-open outcome changed: %+v", res)
	}
	if atomic.LoadInt64(&cdrFailOpenLastMono) == 0 {
		t.Fatal("fail-open passthrough did not record its timestamp")
	}
	if c := findDiagnosticCheck(buildOperatorContract(), cdrFailOpenRecentCode); c == nil || c.Status != diagWarn {
		t.Fatalf("operator contract missing the warn row after a passthrough: %+v", c)
	}

	// Fail-closed errors are refusals, not passthroughs: no timestamp.
	atomic.StoreInt64(&cdrFailOpenLastMono, 0)
	closed := CDRConfig{Enabled: true, FailMode: "closed", DefaultProfile: "default"}
	if res := cdrErrorOutcome("engine error", "default", "full", 1, closed); res.Outcome == cdrPass {
		t.Fatalf("fail-closed outcome changed: %+v", res)
	}
	if atomic.LoadInt64(&cdrFailOpenLastMono) != 0 {
		t.Fatal("fail-closed refusal recorded a passthrough timestamp")
	}
}
