package yara

// CHAOS-84 / CK-9 — the YARA degraded-log gate across a backward clock step.
// Sibling of internal/secscan's degradedLogAllowed, with the same defect, the
// same cause (the two-step `now - prev` form the first sweep's search missed)
// and the same fix: compare the ABSOLUTE interval, so a backward step costs at
// most one suppressed line instead of silencing the gate for the whole step.

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestChaos84_YARADegradedLogSurvivesABackwardClockStep(t *testing.T) {
	var gate atomic.Int64
	gate.Store(time.Now().Add(time.Hour).UnixNano())

	if !yaraDegradedLogAllowed(&gate) {
		t.Fatal("yaraDegradedLogAllowed suppressed the degraded line after a backward clock step — " +
			"regex saturation goes unreported until the clock catches up")
	}
}

// TestChaos84_YARADegradedLogStillRateLimits is the CONTROL.
func TestChaos84_YARADegradedLogStillRateLimits(t *testing.T) {
	var gate atomic.Int64
	if !yaraDegradedLogAllowed(&gate) {
		t.Fatal("first degraded line was suppressed")
	}
	if yaraDegradedLogAllowed(&gate) {
		t.Fatal("a second line inside yaraDegradedLogInterval was allowed — the gate stopped limiting")
	}
}

// TestChaos84_YARADegradedLogIgnoresAConcurrentClaimantsStamp is the CONTROL for
// the other side of the symmetric window.
func TestChaos84_YARADegradedLogIgnoresAConcurrentClaimantsStamp(t *testing.T) {
	var gate atomic.Int64
	gate.Store(time.Now().Add(50 * time.Microsecond).UnixNano())
	if yaraDegradedLogAllowed(&gate) {
		t.Fatal("a stamp microseconds ahead was read as a clock rollback; it is a concurrent claimant")
	}
}
