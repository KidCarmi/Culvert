package server

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// reconciledEntries counts this record's ":reconciled" audit entries by outcome.
func reconciledEntries(t *testing.T, r *reconRig) map[audit.Outcome]int {
	t.Helper()
	f, err := os.Open(r.al.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	kind := reportKind(ops.KindUpgradeApply) + ":reconciled"
	n := map[audit.Outcome]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev audit.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.OpID == testOpULID && ev.Kind == kind {
			n[ev.Outcome]++
		}
	}
	return n
}

func writeReconciled(t *testing.T, r *reconRig, outcome audit.Outcome) {
	t.Helper()
	now := time.Now().UTC()
	if err := r.al.Write(audit.Event{Actor: AuditActorReconcile, OpID: testOpULID,
		Kind: reportKind(ops.KindUpgradeApply) + ":reconciled", Outcome: outcome, OutcomeAt: &now}); err != nil {
		t.Fatal(err)
	}
}

// TestStartupReconcile_RetirementIsAuditedExactlyOnce: retire fsyncs the
// ":reconciled" entry before removing the record, so a kill between the two
// leaves an audited record that the next start retires again (real-Docker
// e2e case rc_after_audit_before_retire). That second retirement must not
// write a second entry; a retirement with no earlier entry writes exactly one;
// and an earlier FAILED entry (a recovery_required run) does not count.
func TestStartupReconcile_RetirementIsAuditedExactlyOnce(t *testing.T) {
	for _, tc := range []struct {
		name          string
		prior         []audit.Outcome // ":reconciled" entries already in the log
		wantSucceeded int
	}{
		{"killed after the audit, before the removal", []audit.Outcome{audit.OutcomeSucceeded}, 1},
		{"first retirement", nil, 1},
		{"an earlier recovery_required run does not count", []audit.Outcome{audit.OutcomeFailed}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReconRig(t, true)
			r.seed(t, journal.PhaseRestarting, nil) // Docker already on prior: noop, then retire
			for _, o := range tc.prior {
				writeReconciled(t, r, o)
			}
			got := r.run(t)
			if got.Outcome != OutcomeConverged {
				t.Fatalf("outcome = %q (%+v)", got.Outcome, got)
			}
			if r.recordOnDisk(t) != nil {
				t.Fatal("record not retired")
			}
			if n := reconciledEntries(t, r)[audit.OutcomeSucceeded]; n != tc.wantSucceeded {
				t.Errorf("succeeded :reconciled entries = %d, want %d", n, tc.wantSucceeded)
			}
			if c := r.world.calls(); len(c) != 0 {
				t.Errorf("mutating calls = %v, want none", c)
			}
		})
	}
}
