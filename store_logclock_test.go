package main

// store_logclock_test.go — the root half of the request-log clock contract.
// The memo itself and its equivalence proof against time.Format live with
// their owner in internal/reqlog (clock.go, clock_test.go); what stays here is
// the composition persistLogEntry performs.

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// TestPersistLogEntry_TSAndTimeShareOneClockRead pins the consistency half of
// the change. The pre-change code called time.Now() twice, so TS and Time could
// straddle a second boundary and disagree in the persisted record. One read
// makes them agree by construction; this asserts the two fields describe the
// same instant.
func TestPersistLogEntry_TSAndTimeShareOneClockRead(t *testing.T) {
	before := time.Now()
	persistLogEntry("203.0.113.7", "GET", "logclock.example.test", "OK", "r", "Allow",
		"", 0, 0, 0, "", "", AuthLogFields{})
	after := time.Now()

	var entry *LogEntry
	for _, e := range logGet() {
		if e.Host == "logclock.example.test" {
			entry = &e
			break
		}
	}
	if entry == nil {
		t.Fatal("entry not found in the request-log ring")
	}
	if entry.TS < before.UnixMilli() || entry.TS > after.UnixMilli() {
		t.Fatalf("TS %d outside the call window [%d,%d]", entry.TS, before.UnixMilli(), after.UnixMilli())
	}
	want := time.UnixMilli(entry.TS).Format(reqlog.TimeLayout)
	if entry.Time != want {
		t.Errorf("Time %q does not render the record's own TS (%q) — TS and Time came from different clock reads",
			entry.Time, want)
	}
}
