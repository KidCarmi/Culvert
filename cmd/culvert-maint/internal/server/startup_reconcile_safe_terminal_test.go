package server

import (
	"testing"

	"culvert-maint/internal/journal"
)

// TestStartupReconcile_SafeTerminalRecordIsNotReconciled (Codex review on
// #2102): a record kept only because the terminal audit entry or the removal
// of a safely-ended operation was cut is deferred to startup's own cleanup;
// the reconcile neither decides it nor touches Docker.
func TestStartupReconcile_SafeTerminalRecordIsNotReconciled(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew // what would otherwise be realigned
	r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) {
		rec.TerminalOutcome, rec.TerminalSafe = "succeeded", true
	})
	got := r.run(t)
	if got.Outcome != OutcomeDeferred || got.Reason != "terminal_cleanup_pending" {
		t.Fatalf("result = %+v, want deferred/terminal_cleanup_pending", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("reconciled a safely-ended operation: %v", c)
	}
}
