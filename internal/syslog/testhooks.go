package syslog

import "time"

// testhooks.go — test seams for the delivery-freshness plane (CHAOS-72).
//
// The engine stamps its own timestamps (noteDelivered / noteDrop) while the
// plane in package main measures age against its own clock seam. A test that
// drives one clock and not the other measures the DIFFERENCE between two
// clocks rather than the age of a delivery, which is how a recovery gate ends
// up asserting the opposite of what it means. SetNowForTest lets a caller move
// both together.
//
// Mirrors internal/audit's ResetForTest/ClearPersistForTest convention: an
// exported, restore-returning seam rather than an unexported hook a sibling
// package cannot reach.

// SetNowForTest replaces the package clock and returns a restore function.
// Test-only; production never calls it.
func SetNowForTest(fn func() time.Time) (restore func()) {
	prev := nowFn.Load()
	if fn == nil {
		nowFn.Store(nil)
	} else {
		nowFn.Store(&fn)
	}
	return func() { nowFn.Store(prev) }
}

// ResetLateDropsForTest clears the process-lifetime late-drop counter.
//
// That counter is process-lifetime BY DESIGN — its whole purpose is to
// outlive the Writer the loss was charged against — which makes it exactly
// the kind of global a test must hand back rather than merely stop looking
// at. A gate that produces one late drop otherwise shifts the exported drop
// total for every gate that runs after it, and those assert exact counts.
// Observed, not hypothetical: adding the late-drop gate turned seven
// unrelated CHAOS-72 gates red. Same rule as swapAutoExclude and
// armSyslogFeed closing the writer it installs.
func ResetLateDropsForTest() { lateDrops.Store(0) }
