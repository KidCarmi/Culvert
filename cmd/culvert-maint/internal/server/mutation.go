package server

import (
	"context"
	"fmt"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/runner"
)

// composeUp and composeDown are the only places the server runs the two docker
// commands that can stop a container of the stack (pinned by
// TestMutation_OnlyTheWrappersRunComposeUpDown).
//
// Record before effect: the durable marker is written before the command
// starts. If it cannot be written the command is not run.
//
// The marker is removed only when the command returned success AND no settle
// window was open when it started. After an error it stays (the command may
// have been killed after it sent its request) and the in-process window is
// restarted as well (noteMutationCut). And a success inside an open window
// proves nothing about what opened the window: a restore whose `compose down`
// was cut goes straight on to `compose up`, which finds the proxy still
// `running`, changes nothing and exits 0 while dockerd is still stopping it.
// Removing the marker there would tell the next agent start that nothing was
// left unfinished. A marker that stays costs a wait at the next start, never a
// missed one.
func (s *Server) composeUp(ctx context.Context) (*runner.Result, error) {
	return s.markedMutation(journal.MutationComposeUp, func() (*runner.Result, error) { return s.opts.Runner.ComposeUp(ctx) })
}

func (s *Server) composeDown(ctx context.Context) (*runner.Result, error) {
	return s.markedMutation(journal.MutationComposeDown, func() (*runner.Result, error) { return s.opts.Runner.ComposeDown(ctx) })
}

func (s *Server) markedMutation(command string, run func() (*runner.Result, error)) (*runner.Result, error) {
	windowOpen := s.settleRemaining() > 0
	if err := s.mutations.Begin(command); err != nil {
		return nil, fmt.Errorf("%s not started: the in-flight marker could not be written: %w", command, err)
	}
	res, err := run()
	if err != nil {
		s.noteMutationCut()
		return res, err
	}
	if !windowOpen {
		// Best effort: a marker left behind only costs a wait at the next start.
		_ = s.mutations.End()
	}
	return res, nil
}
