package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// intentRig: a server with one journal record (an upgrade at phase restarting)
// and a context that names its operation, as ops.Run gives every stage.
func intentRig(t *testing.T) (*reconRig, context.Context) {
	t.Helper()
	r := newReconRig(t, true)
	r.seed(t, journal.PhaseRestarting, nil)
	return r, ops.WithOpID(context.Background(), testOpULID)
}

func (r *reconRig) intentOnDisk(t *testing.T) *journal.CommandIntent {
	t.Helper()
	rec := r.recordOnDisk(t)
	if rec == nil {
		t.Fatal("no record on disk")
	}
	return rec.Intent
}

// TestCommandIntent_WrittenBeforeAndClosedWhenTheCommandReturns: the record
// says "compose up in flight" while the command runs and stops saying so as
// soon as it returns to this process, however it returns. A command that
// returned is not a crash (second review of #2093).
func TestCommandIntent_WrittenBeforeAndClosedWhenTheCommandReturns(t *testing.T) {
	for name, outcome := range map[string]func() (*runner.Result, error){
		"success": func() (*runner.Result, error) { return &runner.Result{}, nil },
		"error":   func() (*runner.Result, error) { return nil, errors.New("exit status 1") },
		"panic":   func() (*runner.Result, error) { panic("the command wrapper blew up") },
	} {
		t.Run(name, func(t *testing.T) {
			r, ctx := intentRig(t)
			var during *journal.CommandIntent
			fencedDuring := false
			func() {
				defer func() { _ = recover() }()
				_, _ = r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
					during = r.intentOnDisk(t)
					fencedDuring, _ = r.jnl.FenceActive()
					return outcome()
				})
			}()
			if during == nil || during.Command != journal.MutationComposeUp {
				t.Fatalf("intent on disk while the command ran = %+v, want compose up", during)
			}
			rec := r.recordOnDisk(t)
			if rec.Intent != nil {
				t.Errorf("intent still on disk after the command returned (%s): %+v", name, rec.Intent)
			}
			if !fencedDuring {
				t.Error("no downgrade fence while the intent was open")
			}
			if on, _ := r.jnl.FenceActive(); on || rec.EffectiveSchema() != 1 {
				t.Errorf("after the command returned: fence=%v schema=%d, want no fence and schema 1", on, rec.EffectiveSchema())
			}
			// What the next agent start would conclude:
			rec.SeenByStartup(time.Now().UTC(), 1_000_000)
			if rec.CutByThisStart(journal.MutationComposeUp) {
				t.Error("the next start would be told the agent died in a command that returned")
			}
		})
	}
}

// TestCommandIntent_AMissingIntentCostsARecoveryNotACommand: the intent cannot
// be written (state directory full). The command is still run: an inline
// rollback must not be stopped here. Nothing is on disk to attribute, so if
// the agent died in the command the next start would only report.
func TestCommandIntent_AMissingIntentCostsARecoveryNotACommand(t *testing.T) {
	r, ctx := intentRig(t)
	r.jnl.SetWriteErrorForTest(errors.New("no space left on device"))
	ran := false
	if _, err := r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
		ran = true
		return &runner.Result{}, nil
	}); err != nil || !ran {
		t.Fatalf("ran=%v err=%v, want the command run without an intent", ran, err)
	}
	rec := r.recordOnDisk(t)
	if rec.Intent != nil {
		t.Fatalf("an intent is on disk although the write was refused: %+v", rec.Intent)
	}
	rec.SeenByStartup(time.Now().UTC(), 1_000_000)
	if rec.CutByThisStart(journal.MutationComposeUp) {
		t.Error("the next start would attribute an outage with no intent on disk")
	}
}

// TestCommandIntent_OnlyWhereThereIsARecordOfTheOperation: a command run for
// no operation, or for one that has no journal record, writes nothing and is
// run as before. Another operation's record is never touched.
func TestCommandIntent_OnlyWhereThereIsARecordOfTheOperation(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no operation":             context.Background(),
		"operation without record": ops.WithOpID(context.Background(), "01BX5ZZKBKACTAV9WEVGEMMVRZ"),
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := intentRig(t)
			ran := false
			if _, err := r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
				ran = true
				if in := r.intentOnDisk(t); in != nil {
					t.Errorf("an intent was written to another operation's record: %+v", in)
				}
				return &runner.Result{}, nil
			}); err != nil || !ran {
				t.Fatalf("ran=%v err=%v, want the command run", ran, err)
			}
			if rec := r.recordOnDisk(t); rec.Intent != nil || rec.EffectiveSchema() >= journal.SchemaFenced {
				t.Errorf("the record was changed: intent=%+v schema=%d", rec.Intent, rec.EffectiveSchema())
			}
		})
	}
}

// TestCommandIntent_ACloseThatCannotBeWrittenIsRetried: the command returned
// but the record could not be rewritten. The intent must not stay on disk for
// the rest of the process: it is closed before the next command, or at Close.
func TestCommandIntent_ACloseThatCannotBeWrittenIsRetried(t *testing.T) {
	for _, via := range []string{"next command", "close"} {
		t.Run(via, func(t *testing.T) {
			r, ctx := intentRig(t)
			if _, err := r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
				r.jnl.SetWriteErrorForTest(errors.New("read-only file system")) // from here on
				return &runner.Result{}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if r.intentOnDisk(t) == nil {
				t.Fatal("test setup: the close was expected to fail and leave the intent")
			}
			r.jnl.SetWriteErrorForTest(nil)
			if via == "close" {
				_ = r.srv.Close()
			} else {
				_, _ = r.srv.markedMutation(context.Background(), journal.MutationComposeUp, func() (*runner.Result, error) {
					if in := r.intentOnDisk(t); in != nil {
						t.Errorf("the earlier intent is still open while the next command runs: %+v", in)
					}
					return &runner.Result{}, nil
				})
			}
			if in := r.intentOnDisk(t); in != nil {
				t.Errorf("intent still on disk after %s: %+v", via, in)
			}
		})
	}
}
