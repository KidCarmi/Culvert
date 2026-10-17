package ocsp

// CHAOS-71 — the responder-cap log gate across a backward wall-clock step.
//
// lastTruncationLog is a unix-nanos int64, so the interval test is a wall-clock
// subtraction. A backward step makes it negative, which reads as "logged in the
// future" and suppresses the notice for the duration of the step. The notice is
// how an operator learns that responder output is being capped, so the step
// converts a visible degradation into a silent one.

import (
	"testing"
	"time"
)

func TestChaos71_TruncationLogIsNotSuppressedByABackwardClockStep(t *testing.T) {
	oc := &Checker{}
	now := time.Now()
	// Stamped before a one-hour backward step, so it reads an hour ahead.
	oc.lastTruncationLog.Store(now.Add(time.Hour).UnixNano())

	if !oc.allowTruncationLog(now) {
		t.Fatal("allowTruncationLog suppressed the responder-cap notice after a backward clock step — " +
			"a capped responder goes unreported until the wall clock catches up")
	}
	if last := oc.lastTruncationLog.Load(); last != now.UnixNano() {
		t.Fatalf("lastTruncationLog = %d, want the current stamp %d — the future stamp was not re-anchored", last, now.UnixNano())
	}
}

// TestChaos71_TruncationLogStillRateLimits is the CONTROL: with a sane clock the
// gate still emits once per interval, not once per handshake.
func TestChaos71_TruncationLogStillRateLimits(t *testing.T) {
	oc := &Checker{}
	now := time.Now()
	if !oc.allowTruncationLog(now) {
		t.Fatal("first call was suppressed")
	}
	if oc.allowTruncationLog(now.Add(truncationLogEvery / 2)) {
		t.Fatal("a second call inside the interval was allowed — the rate gate stopped limiting")
	}
	if !oc.allowTruncationLog(now.Add(truncationLogEvery + time.Second)) {
		t.Fatal("a call after the interval was suppressed")
	}
}
