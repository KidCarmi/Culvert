package status

// status_terminal_test.go — a record KEPT by a failed operation (ADR-0062
// slice 1) is listed like an interrupted one: at once in the process that ran
// the operation, and after a restart with the operation's real reason.

import (
	"context"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/server"
)

func keptRecord(opID string) journal.Record {
	now := time.Now().UTC()
	return journal.Record{OpID: opID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarted, StartedAt: now, UpdatedAt: now,
		TerminalOutcome: "failed:health_failed", TerminalAt: &now, TerminalAudited: true}
}

// TestSnapshot_KeptRecordOfThisProcessIsListed: the operation ran and failed in
// this process; its record is listed as soon as it is terminal, with its
// outcome, and not while it runs.
func TestSnapshot_KeptRecordOfThisProcessIsListed(t *testing.T) {
	p, jnl := providerWithJournal(t)
	op, err := p.mgr.Begin(ops.KindUpgradeApply, "uid=0", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := jnl.Write(keptRecord(op.ID)); err != nil {
		t.Fatal(err)
	}
	st, _ := p.Snapshot(context.Background()) //nolint:errcheck // Snapshot never fails
	if len(st.InterruptedOperations) != 0 {
		t.Fatalf("a running op's record was listed: %+v", st.InterruptedOperations)
	}
	_ = p.mgr.Finish(op.ID, ops.StateFailed, ops.ReasonHealthFailed, nil)
	st, _ = p.Snapshot(context.Background()) //nolint:errcheck // Snapshot never fails
	if len(st.InterruptedOperations) != 1 || st.InterruptedOperations[0].OpID != op.ID ||
		st.InterruptedOperations[0].TerminalOutcome != "failed:health_failed" || st.InterruptedOperations[0].TerminalAt == nil {
		t.Fatalf("interrupted_operations = %+v, want the kept record with its outcome", st.InterruptedOperations)
	}
	if st.RecoveryRequired != nil {
		t.Error("recovery_required set in the default (off) mode, whose payload must not gain it")
	}
}

// TestSnapshot_KeptRecordAfterRestartIsListedWithItsReason: startup marks the
// op with its real reason (not agent_restart_interrupted); it is still listed.
func TestSnapshot_KeptRecordAfterRestartIsListedWithItsReason(t *testing.T) {
	p, jnl := providerWithJournal(t)
	const kept = "01HZZZZZZZZZZZZZZZZZZZZZK1"
	if err := jnl.Write(keptRecord(kept)); err != nil {
		t.Fatal(err)
	}
	p.mgr.MarkAllInterrupted([]ops.InterruptedOp{{OpID: kept, Kind: ops.KindUpgradeApply, FailureReason: ops.ReasonHealthFailed}})
	st, _ := p.Snapshot(context.Background()) //nolint:errcheck // Snapshot never fails
	if len(st.InterruptedOperations) != 1 || st.InterruptedOperations[0].OpID != kept {
		t.Fatalf("interrupted_operations = %+v, want the kept record", st.InterruptedOperations)
	}
	if got := st.InterruptedOperations[0].OperatorAction; !strings.HasPrefix(got, "This operation did not die: it ended failed:health_failed") {
		t.Errorf("operator_action does not say the op ended: %q", got)
	}
}

// TestSnapshot_ConvergeReportsRecoveryRequiredForAKeptRecord: with the startup
// reconcile wired, a kept failed record it has not decided is recovery_required.
func TestSnapshot_ConvergeReportsRecoveryRequiredForAKeptRecord(t *testing.T) {
	p, jnl := providerWithJournal(t)
	p.WithReconcile(server.NewReconcileTracker())
	st, _ := p.Snapshot(context.Background()) //nolint:errcheck // Snapshot never fails
	if st.RecoveryRequired == nil || *st.RecoveryRequired {
		t.Fatalf("recovery_required = %v with nothing kept, want false", st.RecoveryRequired)
	}
	const kept = "01HZZZZZZZZZZZZZZZZZZZZZK2"
	if err := jnl.Write(keptRecord(kept)); err != nil {
		t.Fatal(err)
	}
	st, _ = p.Snapshot(context.Background()) //nolint:errcheck // Snapshot never fails
	if st.RecoveryRequired == nil || !*st.RecoveryRequired {
		t.Errorf("recovery_required = %v with a kept failed record, want true", st.RecoveryRequired)
	}
}
