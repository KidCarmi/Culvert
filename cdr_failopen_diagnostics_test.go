package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCDRFailOpenPassthroughRows(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	recent := now.Add(-5 * time.Minute).UnixNano()
	open := CDRConfig{Enabled: true, FailMode: "open", DefaultProfile: "default"}

	none := []struct {
		name  string
		cfg   CDRConfig
		total int64
		last  int64
	}{
		{"disabled", CDRConfig{Enabled: false}, 3, recent},
		{"fail closed", CDRConfig{Enabled: true, FailMode: "closed"}, 3, recent},
		{"never fell open", open, 0, 0},
		{"older than window", open, 3, now.Add(-cdrFailOpenRecentWindow - time.Minute).UnixNano()},
	}
	for _, tc := range none {
		if got := cdrFailOpenPassthroughRows(tc.cfg, tc.total, tc.last, now); len(got) != 0 {
			t.Errorf("%s: want no row, got %+v", tc.name, got)
		}
	}

	got := cdrFailOpenPassthroughRows(open, 3, recent, now)
	if len(got) != 1 {
		t.Fatalf("recent fail-open: want 1 row, got %d", len(got))
	}
	c := got[0]
	if c.Code != cdrUnsanitizedDeliveryCode || c.Status != diagWarn {
		t.Fatalf("unexpected row %+v", c)
	}
	if !strings.Contains(c.Message, "3 document(s)") || !strings.Contains(c.Message, "5m0s ago") {
		t.Errorf("message must state the count and recency, got %q", c.Message)
	}
	if !strings.Contains(c.OperatorAction, "CDR_ERROR") || !strings.Contains(c.OperatorAction, "fail_mode") {
		t.Errorf("action must name the log filter and the fail_mode setting, got %q", c.OperatorAction)
	}

	// Unset fail_mode defaults to open and must warn too.
	if got := cdrFailOpenPassthroughRows(CDRConfig{Enabled: true}, 1, recent, now); len(got) != 1 {
		t.Errorf("default fail_mode: want 1 row, got %d", len(got))
	}
	// A backward clock step must not hide a recent passthrough.
	if got := cdrFailOpenPassthroughRows(open, 1, now.Add(time.Hour).UnixNano(), now); len(got) != 1 {
		t.Errorf("future timestamp: want 1 row, got %d", len(got))
	}
}

// The fail-open branch of cdrErrorOutcome records the timestamp the row reads;
// the outcome itself is unchanged (pass, status ERROR).
func TestCDRErrorOutcome_FailOpenRecordsPassthroughForDiagnostics(t *testing.T) {
	prevTotal := atomic.LoadInt64(&statCDRFailOpen)
	prevErr := atomic.LoadInt64(&statCDRErrors)
	prevLast := atomic.LoadInt64(&cdrFailOpenLastUnixNano)
	t.Cleanup(func() {
		atomic.StoreInt64(&statCDRFailOpen, prevTotal)
		atomic.StoreInt64(&statCDRErrors, prevErr)
		atomic.StoreInt64(&cdrFailOpenLastUnixNano, prevLast)
	})
	atomic.StoreInt64(&cdrFailOpenLastUnixNano, 0)
	cfg := CDRConfig{Enabled: true, FailMode: "open", DefaultProfile: "default"}
	withActiveCDRConfig(t, cfg)

	if got := checkCDRFailOpenPassthrough(); len(got) != 0 {
		t.Fatalf("row present before any passthrough: %+v", got)
	}

	res := cdrErrorOutcome("engine error", "default", "full", 1, cfg)
	if res.Outcome != cdrPass || res.Status != "ERROR" {
		t.Fatalf("fail-open outcome changed: %+v", res)
	}
	if atomic.LoadInt64(&cdrFailOpenLastUnixNano) == 0 {
		t.Fatal("fail-open passthrough did not record its timestamp")
	}
	if c := findDiagnosticCheck(buildOperatorContract(), cdrUnsanitizedDeliveryCode); c == nil || c.Status != diagWarn {
		t.Fatalf("operator contract missing the warn row after a passthrough: %+v", c)
	}

	// Fail-closed errors are refusals, not passthroughs: no timestamp.
	atomic.StoreInt64(&cdrFailOpenLastUnixNano, 0)
	closed := CDRConfig{Enabled: true, FailMode: "closed", DefaultProfile: "default"}
	if res := cdrErrorOutcome("engine error", "default", "full", 1, closed); res.Outcome == cdrPass {
		t.Fatalf("fail-closed outcome changed: %+v", res)
	}
	if atomic.LoadInt64(&cdrFailOpenLastUnixNano) != 0 {
		t.Fatal("fail-closed refusal recorded a passthrough timestamp")
	}
}
