package ops

// terminal_test.go — the crash-safe terminal sequence (ADR-0062 slice 1):
// record the outcome, write the terminal audit entry, then settle the record,
// all before the op becomes terminal and releases the maintenance lock.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"culvert-maint/internal/audit"
)

// fakeTerminalJournal records the calls and, at each, what the audit log and
// the manager said at that moment.
type fakeTerminalJournal struct {
	mu        sync.Mutex
	auditPath string
	mgr       *Manager
	calls     []string
	// terminalAuditAt[i] is whether the audit log held the op's terminal entry
	// when calls[i] ran; opTerminalAt[i] whether the op was already terminal.
	terminalAuditAt []bool
	opTerminalAt    []bool
	got             []Terminal
	recordErr       error
	panicOn         string
}

func (f *fakeTerminalJournal) note(call, opID, kind string, t Terminal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ev, _ := audit.FindTerminal(f.auditPath, opID, kind) //nolint:errcheck // nil on error is "absent", asserted by the caller
	op := f.mgr.Get(opID)
	f.calls = append(f.calls, call)
	f.terminalAuditAt = append(f.terminalAuditAt, ev != nil)
	f.opTerminalAt = append(f.opTerminalAt, op != nil && op.State.IsTerminal())
	f.got = append(f.got, t)
	if f.panicOn == call {
		panic("injected: " + call)
	}
}

func (f *fakeTerminalJournal) RecordTerminal(opID string, t Terminal) error {
	f.note("record", opID, KindBackupCreate, t)
	return f.recordErr
}

func (f *fakeTerminalJournal) SettleTerminal(opID string, t Terminal) (bool, error) {
	f.note("settle", opID, KindBackupCreate, t)
	return !t.Safe, nil
}

func withTerminalJournal(r *orchTestRig) *fakeTerminalJournal {
	f := &fakeTerminalJournal{auditPath: r.auditPath, mgr: r.mgr}
	r.deps.Journal = f
	return f
}

func healthFailStage(name string) FlowStage {
	return FlowStage{Name: name, FailureReason: ReasonHealthFailed,
		Run: func(context.Context) ([]byte, []byte, error) { return nil, nil, errors.New("boom") }}
}

// TestTerminal_RecordThenAuditThenSettleThenFinish pins the order every crash
// argument of slice 1 rests on: the outcome is on the record before the audit
// entry exists, the entry exists before the record is settled, and the op is
// not terminal (still holds the lock) until all three are done.
func TestTerminal_RecordThenAuditThenSettleThenFinish(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stages []FlowStage
	}{
		{"succeeded", []FlowStage{okStage("a", "")}},
		{"failed", []FlowStage{healthFailStage("a")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newOrchTestRig(t)
			f := withTerminalJournal(r)
			Run(context.Background(), r.deps, r.opID, KindBackupCreate, "uid=1,user=test", nil, "", tc.stages, nil)

			if strings.Join(f.calls, ",") != "record,settle" {
				t.Fatalf("calls = %v, want record then settle", f.calls)
			}
			if f.terminalAuditAt[0] {
				t.Error("the terminal audit entry existed before the outcome was recorded on the journal record")
			}
			if !f.terminalAuditAt[1] {
				t.Error("the record was settled (possibly removed) before its terminal audit entry was durable")
			}
			if f.opTerminalAt[0] || f.opTerminalAt[1] {
				t.Error("the op was terminal (lock released) before its record was settled")
			}
			if op := r.mgr.Get(r.opID); op == nil || !op.State.IsTerminal() {
				t.Fatalf("op not terminal after Run: %+v", op)
			}
		})
	}
}

// TestTerminal_AuditFailureNeverSettles: an entry that is not durable must not
// let the record go. The record keeps its outcome for the next start.
func TestTerminal_AuditFailureNeverSettles(t *testing.T) {
	r := newOrchTestRig(t)
	f := withTerminalJournal(r)
	_ = r.deps.Audit.Close() // every write fails
	Run(context.Background(), r.deps, r.opID, KindBackupCreate, "uid=1,user=test", nil, "", []FlowStage{okStage("a", "")}, nil)
	if strings.Join(f.calls, ",") != "record" {
		t.Fatalf("calls = %v, want only record (no settle without a durable audit entry)", f.calls)
	}
	if op := r.mgr.Get(r.opID); op == nil || op.State != StateSucceeded {
		t.Errorf("a failing audit log must not change the op's outcome: %+v", op)
	}
}

// TestTerminal_RecordFailureStillAuditsAndSettles: the audit entry is never
// skipped because the journal could not be stamped.
func TestTerminal_RecordFailureStillAuditsAndSettles(t *testing.T) {
	r := newOrchTestRig(t)
	f := withTerminalJournal(r)
	f.recordErr = errors.New("disk full")
	Run(context.Background(), r.deps, r.opID, KindBackupCreate, "uid=1,user=test", nil, "", []FlowStage{healthFailStage("a")}, nil)
	if strings.Join(f.calls, ",") != "record,settle" || !f.terminalAuditAt[1] {
		t.Fatalf("calls = %v audit-at-settle=%v", f.calls, f.terminalAuditAt)
	}
	if !strings.Contains(r.opLogContent(t), "journal terminal record failed") {
		t.Error("the failed record write is not in the op log")
	}
}

// TestTerminal_SafeVerdict: success is always safe; a failure is safe only when
// the flow's judge proves it, and the judge sees the first failed stage.
func TestTerminal_SafeVerdict(t *testing.T) {
	cases := []struct {
		name     string
		stages   []FlowStage
		judge    EndStateJudge
		wantSafe bool
	}{
		{"success without a judge", []FlowStage{okStage("a", "")}, nil, true},
		{"failure without a judge", []FlowStage{healthFailStage("a")}, nil, false},
		{"failure the judge rejects", []FlowStage{healthFailStage("a")}, func(string) bool { return false }, false},
		{"failure the judge accepts", []FlowStage{healthFailStage("a")}, func(st string) bool { return st == "a" }, true},
		{"judge sees the FIRST failed stage", []FlowStage{healthFailStage("first"), {Name: "rec", ContinueOnError: true,
			Run: func(context.Context) ([]byte, []byte, error) { return nil, nil, errors.New("x") }}},
			func(st string) bool { return st == "first" }, true},
		{"a panicking judge is not proof", []FlowStage{healthFailStage("a")}, func(string) bool { panic("judge") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newOrchTestRig(t)
			f := withTerminalJournal(r)
			r.deps.EndStateSafe = tc.judge
			Run(context.Background(), r.deps, r.opID, KindBackupCreate, "uid=1,user=test", nil, "", tc.stages, nil)
			if len(f.got) != 2 || f.got[0].Safe != tc.wantSafe || f.got[1].Safe != tc.wantSafe {
				t.Fatalf("terminal = %+v, want safe=%v at record and settle", f.got, tc.wantSafe)
			}
			if f.got[0].State == StateFailed && f.got[0].Reason != ReasonHealthFailed {
				t.Errorf("reason = %q", f.got[0].Reason)
			}
			if r.mgr.Holder() != nil {
				t.Error("maintenance lock still held after Run")
			}
		})
	}
}

// TestTerminal_PanickingJournalStillReleasesTheLock: nothing in the terminal
// journal step may leave the lock held or skip Finish.
func TestTerminal_PanickingJournalStillReleasesTheLock(t *testing.T) {
	for _, at := range []string{"record", "settle"} {
		t.Run(at, func(t *testing.T) {
			r := newOrchTestRig(t)
			f := withTerminalJournal(r)
			f.panicOn = at
			Run(context.Background(), r.deps, r.opID, KindBackupCreate, "uid=1,user=test", nil, "", []FlowStage{okStage("a", "")}, nil)
			if op := r.mgr.Get(r.opID); op == nil || op.State != StateSucceeded {
				t.Fatalf("op = %+v, want succeeded", op)
			}
			if r.mgr.Holder() != nil {
				t.Error("maintenance lock still held")
			}
			if ev, _ := audit.FindTerminal(r.auditPath, r.opID, KindBackupCreate); ev == nil { //nolint:errcheck // nil is the failure
				t.Error("a panicking journal step suppressed the terminal audit entry")
			}
			if strings.Join(f.calls, ",") != "record,settle" {
				t.Errorf("calls = %v, want both steps attempted", f.calls)
			}
		})
	}
}

func TestParseTerminalOutcome(t *testing.T) {
	for in, want := range map[string]struct {
		state  State
		reason FailureReason
		ok     bool
	}{
		"succeeded":                         {StateSucceeded, "", true},
		"failed:health_failed":              {StateFailed, ReasonHealthFailed, true},
		"failed:agent_restart_interrupted":  {StateFailed, ReasonAgentRestartInterrupted, true},
		"":                                  {"", "", false},
		"failed:":                           {"", "", false},
		"failed:Health":                     {"", "", false},
		"failed:x\ny":                       {"", "", false},
		"failed:" + strings.Repeat("a", 65): {"", "", false},
		"cancelled":                         {"", "", false},
		"succeeded:health_failed":           {"", "", false},
		"failed:health_failed\t":            {"", "", false},
		"failed:" + strings.Repeat("a", 64): {StateFailed, FailureReason(strings.Repeat("a", 64)), true},
		Terminal{State: StateFailed, Reason: ReasonRollbackFailed}.Outcome(): {StateFailed, ReasonRollbackFailed, true},
	} {
		s, r, ok := ParseTerminalOutcome(in)
		if s != want.state || r != want.reason || ok != want.ok {
			t.Errorf("ParseTerminalOutcome(%q) = %q,%q,%v want %+v", in, s, r, ok, want)
		}
	}
}

// TestMarkAllInterrupted_KeptRecordCarriesItsOwnReason: a kept record of an op
// that ENDED is marked with its real reason, never agent_restart_interrupted.
func TestMarkAllInterrupted_KeptRecordCarriesItsOwnReason(t *testing.T) {
	m := NewManager(nil)
	m.MarkAllInterrupted([]InterruptedOp{
		{OpID: "01HZZZZZZZZZZZZZZZZZZZZZZA", Kind: KindUpgradeApply},
		{OpID: "01HZZZZZZZZZZZZZZZZZZZZZZB", Kind: KindUpgradeApply, FailureReason: ReasonHealthFailed},
	})
	if op := m.Get("01HZZZZZZZZZZZZZZZZZZZZZZA"); op == nil || op.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Errorf("interrupted op = %+v", op)
	}
	if op := m.Get("01HZZZZZZZZZZZZZZZZZZZZZZB"); op == nil || op.State != StateFailed || op.FailureReason != string(ReasonHealthFailed) {
		t.Errorf("kept op = %+v, want failed(health_failed)", op)
	}
}
