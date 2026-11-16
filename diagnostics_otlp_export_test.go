package main

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/otlp"
)

func TestOTLPLatestPushFailed(t *testing.T) {
	const earlier, later = "2026-11-14T10:00:00Z", "2026-11-14T10:00:15Z"
	cases := []struct {
		name string
		h    otlp.PushHealth
		want bool
	}{
		{"no attempt yet", otlp.PushHealth{}, false},
		{"only deliveries", otlp.PushHealth{LastSuccessAt: later}, false},
		{"never delivered", otlp.PushHealth{FailureCount: 3, LastErrorAt: earlier}, true},
		{"failed after a delivery", otlp.PushHealth{FailureCount: 1, LastErrorAt: later, LastSuccessAt: earlier}, true},
		{"recovered after a failure", otlp.PushHealth{FailureCount: 9, LastErrorAt: earlier, LastSuccessAt: later}, false},
		{"same second reads as delivered", otlp.PushHealth{FailureCount: 1, LastErrorAt: later, LastSuccessAt: later}, false},
	}
	for _, c := range cases {
		if got := otlpLatestPushFailed(c.h); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOTLPExportRows(t *testing.T) {
	if rows := otlpExportRows(nil); len(rows) != 0 {
		t.Fatalf("nothing failing: want no rows, got %+v", rows)
	}
	rows := otlpExportRows([]string{"metrics", "traces"})
	if len(rows) != 1 || rows[0].Code != "otlp_export" || rows[0].Status != diagWarn || rows[0].OperatorAction == "" {
		t.Fatalf("want one otlp_export WARN row, got %+v", rows)
	}
	if !strings.Contains(rows[0].Message, "metrics and traces") {
		t.Errorf("message should name the failing signals, got %q", rows[0].Message)
	}
}

// With OTLP export off, the row must be absent no matter what an earlier
// configuration recorded, and the assembled report must not carry it.
func TestCheckOTLPExport_DisabledAddsNoRow(t *testing.T) {
	if globalOTLP.Enabled() || globalOTLPTraces.Enabled() {
		t.Skip("OTLP export is enabled by another test")
	}
	if rows := checkOTLPExport(); len(rows) != 0 {
		t.Fatalf("OTLP off: want no rows, got %+v", rows)
	}
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "otlp_export" {
			t.Fatalf("OTLP off: row must be absent from the report, got %+v", c)
		}
	}
}
