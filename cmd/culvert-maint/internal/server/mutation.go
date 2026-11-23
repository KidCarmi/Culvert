package server

import (
	"context"
	"fmt"

	"culvert-maint/internal/runner"
)

// composeUp and composeDown are the only places the server runs the two docker
// commands that can stop the proxy container (pinned by
// TestMutation_OnlyTheWrappersRunComposeUpDown).
//
// Record before effect: the durable marker is written before the command
// starts. If it cannot be written the command is not run. It is removed only
// when the command returned success; after an error it stays (the command may
// have been killed after it sent its request) and the in-process window is
// restarted as well (noteMutationCut). A marker that cannot be removed also
// stays: the cost is a wait at the next agent start, never a missed one.
func (s *Server) composeUp(ctx context.Context) (*runner.Result, error) {
	return s.markedMutation("compose up", func() (*runner.Result, error) { return s.opts.Runner.ComposeUp(ctx) })
}

func (s *Server) composeDown(ctx context.Context) (*runner.Result, error) {
	return s.markedMutation("compose down", func() (*runner.Result, error) { return s.opts.Runner.ComposeDown(ctx) })
}

func (s *Server) markedMutation(command string, run func() (*runner.Result, error)) (*runner.Result, error) {
	if err := s.mutations.Begin(command); err != nil {
		return nil, fmt.Errorf("%s not started: the in-flight marker could not be written: %w", command, err)
	}
	res, err := run()
	if err != nil {
		s.noteMutationCut()
		return res, err
	}
	// Best effort: a marker left behind only costs a wait at the next start.
	_ = s.mutations.End()
	return res, nil
}
