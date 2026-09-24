package syslog

import "time"

// testhooks.go — test seams for the delivery-freshness plane (CHAOS-66).
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
