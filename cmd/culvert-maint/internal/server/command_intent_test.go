package server

import (
	"context"
	"errors"
	"testing"

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

// nextStartConcludes is what an agent start would conclude from the record as
// it is on disk now (main.go takeCommandIntents).
func (r *reconRig) nextStartConcludes(t *testing.T) (command string, attributed bool) {
	t.Helper()
	rec := r.recordOnDisk(t)
	command, attributed, _ = rec.TakeIntent()
	return command, attributed
}

// TestCommandIntent_WrittenBeforeAndClosedWhenTheCommandReturns: the record
// says "compose up in flight" while the command runs and stops saying so as
// soon as it returns to this process, however it returns. A command that
// returned is not a crash.
func TestCommandIntent_WrittenBeforeAndClosedWhenTheCommandReturns(t *testing.T) {
	for name, outcome := range map[string]func() (*runner.Result, error){
		"success": func() (*runner.Result, error) { return &runner.Result{}, nil },
		"error":   func() (*runner.Result, error) { return nil, errors.New("exit status 1") },
		"panic":   func() (*runner.Result, error) { panic("the command wrapper blew up") },
	} {
		t.Run(name, func(t *testing.T) {
			r, ctx := intentRig(t)
			var during *journal.CommandIntent
			diedDuring := false
			func() {
				defer func() { _ = recover() }()
				_, _ = r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
					during = r.intentOnDisk(t)
					_, diedDuring = r.nextStartConcludes(t) // had the agent been killed here
					return outcome()
				})
			}()
			if during == nil || during.Command != journal.MutationComposeUp {
				t.Fatalf("intent on disk while the command ran = %+v, want compose up", during)
			}
			if !diedDuring {
				t.Error("an agent killed while the command ran would not be attributed")
			}
			if in := r.intentOnDisk(t); in != nil {
				t.Errorf("intent still on disk after the command returned (%s): %+v", name, in)
			}
			if _, attributed := r.nextStartConcludes(t); attributed {
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
		if in := r.intentOnDisk(t); in != nil {
			t.Errorf("an intent is on disk although the write was refused: %+v", in)
		}
		return &runner.Result{}, nil
	}); err != nil || !ran {
		t.Fatalf("ran=%v err=%v, want the command run without an intent", ran, err)
	}
	if _, attributed := r.nextStartConcludes(t); attributed {
		t.Error("the next start would attribute an outage with no intent on disk")
	}
}

// TestCommandIntent_OnlyWhereThereIsARecordOfTheOperation: a command run for
// no operation, or for one that has no journal record, writes nothing and is
// run as before. Another operation's record is never touched.
func TestCommandIntent_OnlyWhereThereIsARecordOfTheOperation(t *testing.T) {
	const other = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
	for name, ctx := range map[string]context.Context{
		"no operation":             context.Background(),
		"operation without record": ops.WithOpID(context.Background(), other),
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := intentRig(t)
			before := r.recordOnDisk(t)
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
			if after := r.recordOnDisk(t); after.Intent != nil || after.Cut != nil || !after.UpdatedAt.Equal(before.UpdatedAt) {
				t.Errorf("the record was changed: %+v", after)
			}
			if _, found, _ := r.jnl.Read(other); found {
				t.Error("a record was created for an operation that had none")
			}
		})
	}
}

// TestCommandIntent_ACloseThatCannotBeWrittenDoesNotStay: the command returned
// but the record could not be rewritten at that moment. The intent must not
// stay on disk: it goes at the record's next write by the operation (a phase
// advance), or, failing that, before the next compose command.
func TestCommandIntent_ACloseThatCannotBeWrittenDoesNotStay(t *testing.T) {
	failedClose := func(t *testing.T) (*reconRig, context.Context) {
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
		return r, ctx
	}
	t.Run("the operation's next record write", func(t *testing.T) {
		r, _ := failedClose(t)
		rec := r.recordOnDisk(t) // what advanceJournalPhase does: read, change, write
		rec.Phase = journal.PhaseRestarted
		if err := r.jnl.Write(*rec); err != nil {
			t.Fatal(err)
		}
		if in := r.intentOnDisk(t); in != nil {
			t.Errorf("the phase advance wrote the stale intent back: %+v", in)
		}
	})
	t.Run("before the next command", func(t *testing.T) {
		r, _ := failedClose(t)
		_, _ = r.srv.markedMutation(ops.WithOpID(context.Background(), "01BX5ZZKBKACTAV9WEVGEMMVRZ"), journal.MutationComposeUp, func() (*runner.Result, error) {
			if in := r.intentOnDisk(t); in != nil {
				t.Errorf("the earlier intent is still open while the next command runs: %+v", in)
			}
			return &runner.Result{}, nil
		})
	})
}
