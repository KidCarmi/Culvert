package main

import "testing"

func resetConfigSnapshotApplyHealth(t *testing.T) {
	t.Helper()
	prev := configSnapshotApplyFailing.Load()
	t.Cleanup(func() { configSnapshotApplyFailing.Store(prev) })
	configSnapshotApplyFailing.Store(false)
}

func TestConfigSnapshotApplyHealth_DefaultsHealthy(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	if !lastConfigSnapshotApplyOK() {
		t.Error("with no recorded attempt, lastConfigSnapshotApplyOK() should default true")
	}
}

func TestConfigSnapshotApplyHealth_RejectedThenRecovered(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)

	markConfigSnapshotApplyRejected()
	if lastConfigSnapshotApplyOK() {
		t.Error("after markConfigSnapshotApplyRejected(), lastConfigSnapshotApplyOK() should be false")
	}

	markConfigSnapshotApplyOK()
	if !lastConfigSnapshotApplyOK() {
		t.Error("after markConfigSnapshotApplyOK(), lastConfigSnapshotApplyOK() should be true")
	}
}

// TestSupportHealthConfigSnapshotValid_ReflectsRealApplyOutcome is the
// regression test for the review finding that support_health_config_snapshot_valid
// only self-tested the validator against an empty baseline and never reflected
// a real rejected snapshot/delta apply.
func TestSupportHealthConfigSnapshotValid_ReflectsRealApplyOutcome(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)

	if got := readSupportHealthConfigSnapshotValid(); got != 1 {
		t.Fatalf("baseline (validator OK, no real apply recorded) = %v, want 1", got)
	}

	markConfigSnapshotApplyRejected()
	if got := readSupportHealthConfigSnapshotValid(); got != 0 {
		t.Fatalf("after a real rejected apply, readSupportHealthConfigSnapshotValid() = %v, want 0", got)
	}

	markConfigSnapshotApplyOK()
	if got := readSupportHealthConfigSnapshotValid(); got != 1 {
		t.Fatalf("after recovery, readSupportHealthConfigSnapshotValid() = %v, want 1", got)
	}
}
