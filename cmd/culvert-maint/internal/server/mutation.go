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

// beginCommandIntent writes the intent into the record of opID. No operation (opID ""), no journal, or no record for it: nothing to write,
// and nothing will ever be attributed to the command.
func (s *Server) beginCommandIntent(opID, command string) error {
	s.closePendingIntents()
	if s.opts.Journal == nil || opID == "" {
		return nil
	}
	rec, found, err := s.opts.Journal.Read(opID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	rec.BeginCommand(command, time.Now().UTC())
	return s.opts.Journal.Write(*rec)
}

// endCommandIntent removes the intent from the record of opID. If that cannot
// be written the record still says "in flight" while this process is alive:
// it is remembered and retried before every later command and at shutdown.
// Left on disk until the agent next starts, it would read as "died in the
// command" (a double fault: the state directory unwritable from here to the
// end of the process).
func (s *Server) endCommandIntent(opID string) {
	if s.opts.Journal == nil || opID == "" {
		return
	}
	if err := s.closeIntent(opID); err != nil {
		s.intentMu.Lock()
		if s.pendingIntents == nil {
			s.pendingIntents = map[string]struct{}{}
		}
		s.pendingIntents[opID] = struct{}{}
		s.intentMu.Unlock()
		log.Printf("culvert-maint: WARN: could not close the command intent of op %s (will retry): %v", opID, err)
	}
}

func (s *Server) closeIntent(opID string) error {
	rec, found, err := s.opts.Journal.Read(opID)
	if err != nil || !found {
		return err
	}
	if !rec.EndCommand() {
		return nil
	}
	return s.opts.Journal.Write(*rec)
}

// closePendingIntents retries every intent whose close could not be written.
func (s *Server) closePendingIntents() {
	s.intentMu.Lock()
	defer s.intentMu.Unlock()
	for opID := range s.pendingIntents {
		if s.closeIntent(opID) == nil {
			delete(s.pendingIntents, opID)
		}
	}
}
