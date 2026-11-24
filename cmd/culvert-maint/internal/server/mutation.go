package server

import (
	"context"
	"fmt"

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

// The marker names the operation the command is run for (ops.OpIDFrom): a
// later start may attribute an outage to an interrupted `compose up` only for
// that operation's own record (startup_reconcile.go, upInterruptedFor).
func (s *Server) markedMutation(ctx context.Context, command string, run func() (*runner.Result, error)) (*runner.Result, error) {
	mayClear := s.markerMayBeCleared() // asked before the command runs
	if err := s.mutations.BeginFor(command, ops.OpIDFrom(ctx)); err != nil {
		return nil, fmt.Errorf("%s not started: the in-flight marker could not be written: %w", command, err)
	}
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
