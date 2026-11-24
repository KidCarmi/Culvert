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

// TestCommandIntent_ACloseThatCannotBeWrittenIsRetriedUntilItIs: the command
// returned to a live agent, but for a moment the record could not be
// rewritten (the disk was full while the operation ended). The agent then
// runs on, perhaps for days, and is restarted cleanly. That restart must not
// read "died in compose up". So the close is retried: by the record's next
// write, before the next compose command of ANY operation or none, by a
// background loop while the agent is otherwise idle, and at Close.
func TestCommandIntent_ACloseThatCannotBeWrittenIsRetriedUntilItIs(t *testing.T) {
	failedClose := func(t *testing.T) (*reconRig, context.Context) {
		r, ctx := intentRig(t)
		r.srv.intentRetryEvery = time.Hour // each subtest says which retry it means
		if _, err := r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
			r.jnl.SetWriteErrorForTest(errors.New("no space left on device")) // from here on
			return &runner.Result{}, nil
		}); err != nil {
			t.Fatal(err)
		}
		if r.intentOnDisk(t) == nil {
			t.Fatal("test setup: the close was expected to fail and leave the intent")
		}
		return r, ctx
	}
	t.Run("the operation's next record write", func(t *testing.T) {
		r, _ := failedClose(t)
		r.jnl.SetWriteErrorForTest(nil)
		rec := r.recordOnDisk(t) // what advanceJournalPhase does: read, change, write
		rec.Phase = journal.PhaseRestarted
		if err := r.jnl.Write(*rec); err != nil {
			t.Fatal(err)
		}
		intentGone(t, r, "the record's next write")
	})
	for name, ctx := range map[string]context.Context{
		"before the next command of another operation": ops.WithOpID(context.Background(), "01BX5ZZKBKACTAV9WEVGEMMVRZ"),
		"before the next command of no operation":      context.Background(),
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := failedClose(t)
			r.jnl.SetWriteErrorForTest(nil)
			_, _ = r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
				if in := r.intentOnDisk(t); in != nil {
					t.Errorf("the earlier intent is still open while the next command runs: %+v", in)
				}
				return &runner.Result{}, nil
			})
			intentGone(t, r, name)
		})
	}
	t.Run("the idle agent's retry loop", retryLoopClosesIt)
	t.Run("close stops the loop even while nothing can be written", closeStopsTheRetryLoop)
	t.Run("close", func(t *testing.T) {
		r, _ := failedClose(t)
		r.jnl.SetWriteErrorForTest(nil)
		_ = r.srv.Close()
		intentGone(t, r, "Close")
	})
}

// intentGone asserts that nothing of a closed command is left: no intent on
// disk, nothing a clean restart would attribute, no fence.
func intentGone(t *testing.T, r *reconRig, how string) {
	t.Helper()
	if in := r.intentOnDisk(t); in != nil {
		t.Errorf("intent still on disk after %s: %+v", how, in)
	}
	if _, attributed := r.nextStartConcludes(t); attributed {
		t.Errorf("after %s a clean restart would still read a death inside the command", how)
	}
	if on, _ := r.jnl.IntentFenceActive(); on {
		t.Errorf("the intent fence is still up after %s", how)
	}
}

// retryLoopClosesIt: no command, no write, no restart; the idle agent closes
// the intent by itself once the journal can be written, and the loop ends.
func retryLoopClosesIt(t *testing.T) {
	r, ctx := intentRig(t)
	r.srv.intentRetryEvery = 10 * time.Millisecond
	if _, err := r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
		r.jnl.SetWriteErrorForTest(errors.New("no space left on device"))
		return &runner.Result{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // still unwritable: the loop keeps trying
	if r.intentOnDisk(t) == nil {
		t.Fatal("test setup: the intent was expected to be still there")
	}
	r.jnl.SetWriteErrorForTest(nil) // space was freed; no command, no write, no restart
	deadline := time.Now().Add(5 * time.Second)
	fenced := func() bool { on, _ := r.jnl.IntentFenceActive(); return on }
	for (r.intentOnDisk(t) != nil || fenced()) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	intentGone(t, r, "the retry loop")
	// And the loop ends once there is nothing left to retry.
	for (r.srv.intentRetryRunning.Load() || r.srv.staleIntents.Load()) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.srv.intentRetryRunning.Load() || r.srv.staleIntents.Load() {
		t.Errorf("after the close was written: loop running=%v stale=%v, want both false",
			r.srv.intentRetryRunning.Load(), r.srv.staleIntents.Load())
	}
}

// closeStopsTheRetryLoop: Close returns only once the loop has ended, and no
// loop starts after it.
func closeStopsTheRetryLoop(t *testing.T) {
	r, ctx := intentRig(t)
	r.srv.intentRetryStop = make(chan struct{})
	r.srv.intentRetryEvery = 5 * time.Millisecond
	if _, err := r.srv.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) {
		r.jnl.SetWriteErrorForTest(errors.New("no space left on device"))
		return &runner.Result{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if !r.srv.intentRetryRunning.Load() {
		t.Fatal("test setup: the retry loop was expected to be running")
	}
	_ = r.srv.Close() // returns only once the loop has ended
	if r.srv.intentRetryRunning.Load() {
		t.Error("the retry loop is still running after Close")
	}
	r.srv.staleIntents.Store(true)
	r.srv.startIntentRetry()
	if r.srv.intentRetryRunning.Load() {
		t.Error("a retry loop was started after Close")
	}
}

// TestCommandIntent_ComposeDownIsAttributedToo: `compose down` goes through
// the same wrapper with the operation's context (a restore or a data rollback
// stops the stack with it).
func TestCommandIntent_ComposeDownIsAttributedToo(t *testing.T) {
	r, ctx := intentRig(t)
	var during *journal.CommandIntent
	r.world.onDown = func() { during = r.intentOnDisk(t) }
	if _, err := r.srv.composeDown(ctx); err != nil {
		t.Fatal(err)
	}
	if during == nil || during.Command != journal.MutationComposeDown {
		t.Fatalf("intent on disk while `compose down` ran = %+v, want compose down", during)
	}
	if in := r.intentOnDisk(t); in != nil {
		t.Errorf("intent still on disk after `compose down` returned: %+v", in)
	}
}
