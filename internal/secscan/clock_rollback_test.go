package secscan

// CHAOS-84 / CK-9 — the scanner's degraded-log gate across a backward clock step.
//
// degradedLogAllowed compares two wall-clock nanos, so a backward step makes the
// difference negative and a sign-based test suppresses for the whole step. The
// line it gates is the operator's only notice that scans are saturating or being
// abandoned, which is how a fail-closed scan budget becomes visible — so the
// step turns a reported degradation into a silent one.
//
// This site was missed by the first sweep's search (it uses the two-step
// `now := time.Now().UnixNano(); now - prev` form) and named by Codex on #1650.

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestChaos84_DegradedLogSurvivesABackwardClockStep(t *testing.T) {
	var gate atomic.Int64
	// Stamped before a one-hour backward step, so it reads an hour ahead.
	gate.Store(time.Now().Add(time.Hour).UnixNano())

	if !degradedLogAllowed(&gate) {
		t.Fatal("degradedLogAllowed suppressed the scanner's degraded line after a backward clock " +
			"step — saturation and abandonment go unreported until the clock catches up")
	}
}

// TestChaos84_DegradedLogStillRateLimits is the CONTROL: one line per interval
// on a sane clock.
func TestChaos84_DegradedLogStillRateLimits(t *testing.T) {
	var gate atomic.Int64
	if !degradedLogAllowed(&gate) {
		t.Fatal("first degraded line was suppressed")
	}
	if degradedLogAllowed(&gate) {
		t.Fatal("a second line inside degradedLogInterval was allowed — the gate stopped limiting")
	}
}

// TestChaos84_DegradedLogIgnoresAConcurrentClaimantsStamp is the CONTROL for the
// other side of the symmetric window.
func TestChaos84_DegradedLogIgnoresAConcurrentClaimantsStamp(t *testing.T) {
	var gate atomic.Int64
	gate.Store(time.Now().Add(50 * time.Microsecond).UnixNano())
	if degradedLogAllowed(&gate) {
		t.Fatal("a stamp microseconds ahead was read as a clock rollback; it is a concurrent claimant")
	}
}
