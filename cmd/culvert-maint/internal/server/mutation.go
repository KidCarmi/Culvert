package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// composeUp and composeDown are the only places the server runs the two docker
// commands that can stop a container of the stack (pinned by
// TestMutation_OnlyTheWrappersRunComposeUpDown).
//
// Record before effect: the durable marker is written before the command
// starts. If it cannot be written the command is not run.
//
// The marker is removed only when the command returned success AND, when it
// started, nothing earlier could still be pending (markerMayBeCleared). After
// an error it stays (the command may have been killed after it sent its
// request), the in-process window is restarted (noteMutationCut), and this
// process never removes a marker again. And a success while something earlier
// may be pending proves nothing about it: a restore whose `compose down` was
// cut goes straight on to `compose up`, which finds the proxy still `running`,
// changes nothing and exits 0 while dockerd is still stopping it. Removing the
// marker there would tell the next agent start that nothing was left
// unfinished. A marker that stays costs a wait at the next start, never a
// missed one.
func (s *Server) composeUp(ctx context.Context) (*runner.Result, error) {
	return s.markedMutation(ctx, journal.MutationComposeUp, func() (*runner.Result, error) { return s.opts.Runner.ComposeUp(ctx) })
}

func (s *Server) composeDown(ctx context.Context) (*runner.Result, error) {
	return s.markedMutation(ctx, journal.MutationComposeDown, func() (*runner.Result, error) { return s.opts.Runner.ComposeDown(ctx) })
}

func (s *Server) markedMutation(ctx context.Context, command string, run func() (*runner.Result, error)) (*runner.Result, error) {
	mayClear := s.markerMayBeCleared() // asked before the command runs
	if err := s.mutations.Begin(command); err != nil {
		return nil, fmt.Errorf("%s not started: the in-flight marker could not be written: %w", command, err)
	}
	// The marker above answers "may dockerd still be finishing something";
	// the intent answers "did the agent die inside THIS operation's command"
	// (ADR-0062 slice 3). They are kept apart on purpose.
	//
	// Best effort, unlike the marker: an intent that is missing can only cost
	// a recovery (a later start has nothing to attribute the outage to and
	// reports it), never cause one. Refusing the command instead would stop
	// the inline rollback's own `compose up` on a state directory that cannot
	// be written, and leave an image that failed its gate serving
	// (TestInlineRollback_ArmWriteFailureStillRollsBack).
	opID := ops.OpIDFrom(ctx)
	if err := s.beginCommandIntent(opID, command); err != nil {
		log.Printf("culvert-maint: WARN: could not write the command intent of op %s before %s; if the agent dies in it, the next start will only report: %v", opID, command, err)
	}
	// Deferred: a command that returns to a live process is not a crash,
	// whether it succeeded, failed or panicked.
	defer s.endCommandIntent(opID)
	res, err := run()
	if err != nil {
		s.noteMutationCut()
		return res, err
	}
	if mayClear {
		// Best effort: a marker left behind only costs a wait at the next start.
		if s.mutations.End() == nil {
			s.startMarkerLive.Store(false)
		}
	}
	return res, nil
}

// beginCommandIntent writes the intent into the record of opID
// (journal.BeginCommand). No operation, no journal, or no record for it:
// nothing is written, and nothing will ever be attributed to the command.
// Before any compose command, whatever it is run for, intents left by a close
// that could not be written are closed.
func (s *Server) beginCommandIntent(opID, command string) error {
	if s.opts.Journal == nil {
		return nil
	}
	s.sweepStaleIntents()
	if opID == "" {
		return nil
	}
	_, err := s.opts.Journal.BeginCommand(opID, command, time.Now().UTC())
	return err
}

// endCommandIntent removes the intent from the record of opID. If that cannot
// be written the record would keep saying "in flight" although this process
// is alive, and an agent start after a perfectly clean restart would read
// "died in the command". So it is retried until it is written: by every later
// write of that record (journal.Write drops it), before the next compose
// command, every intentRetryEvery from a background loop, and at Close. What
// is left is a state directory that stays unwritable from here until the
// process is gone.
func (s *Server) endCommandIntent(opID string) {
	if s.opts.Journal == nil || opID == "" {
		return
	}
	if err := s.opts.Journal.EndCommand(opID); err != nil {
		log.Printf("culvert-maint: WARN: could not close the command intent of op %s (retrying): %v", opID, err)
		s.closeFailures.Add(1)
		s.staleIntents.Store(true)
		s.startIntentRetry()
	}
}

// sweepStaleIntents closes what endCommandIntent could not. Safe beside a
// running operation: the journal makes each close one atomic step.
func (s *Server) sweepStaleIntents() {
	if s.opts.Journal == nil || !s.staleIntents.Load() {
		return
	}
	// One sweep at a time: a second caller waits and then sweeps for itself,
	// so it never goes on while an intent it could have closed is still open.
	s.sweepMu.Lock()
	defer s.sweepMu.Unlock()
	if !s.staleIntents.Load() {
		return
	}
	// The flag is cleared only if no close has failed since the sweep began:
	// one that fails while the sweep runs may have left an intent the sweep
	// did not see.
	failures := s.closeFailures.Load()
	if left, err := s.opts.Journal.CloseStaleIntents(); err == nil && left == 0 && s.closeFailures.Load() == failures {
		s.staleIntents.Store(false)
	}
}

// defaultIntentRetryEvery is how often a close that could not be written is
// retried while the agent is otherwise idle.
const defaultIntentRetryEvery = 5 * time.Second

// startIntentRetry runs the retry loop until nothing is stale or the server
// closes. At most one runs at a time.
func (s *Server) startIntentRetry() {
	s.intentRetryMu.Lock()
	defer s.intentRetryMu.Unlock()
	select {
	case <-s.intentRetryStop: // closing (a nil channel never fires)
		return
	default:
	}
	if !s.intentRetryRunning.CompareAndSwap(false, true) {
		return
	}
	done := make(chan struct{})
	s.intentRetryDone = done
	every := s.intentRetryEvery
	if every <= 0 {
		every = defaultIntentRetryEvery
	}
	go func() {
		defer close(done)
		t := time.NewTicker(every)
		defer t.Stop()
		s.sweepStaleIntents() // once at once: the failure may have been momentary
		for s.staleIntents.Load() {
			select {
			case <-s.intentRetryStop:
				s.intentRetryRunning.Store(false)
				return
			case <-t.C:
				s.sweepStaleIntents()
			}
		}
		if s.intentRetryExitHook != nil {
			s.intentRetryExitHook() // tests only: the gap between the check and the Store
		}
		s.intentRetryRunning.Store(false)
		// A close that failed between the loop's last check and the Store above
		// found the loop still running and started none. Start one for it:
		// otherwise an idle agent would never retry it. startIntentRetry
		// refuses after Close, and Close waits for any loop it does start.
		if s.staleIntents.Load() {
			s.startIntentRetry()
		}
	}()
}
