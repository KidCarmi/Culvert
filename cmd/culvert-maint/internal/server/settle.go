// Waiting out what a dead agent left running in dockerd.
//
// When the agent dies, the shipped unit's control-group kill guarantees that
// no docker command it started is still alive when the next agent starts
// (packaging/systemd/culvert-maint.service). It guarantees nothing about
// dockerd, which finishes the last request it was sent. A tag is done in
// milliseconds. A container stop is not: it lasts as long as the proxy takes
// to exit, up to its stop_grace_period, and during that time the container is
// `running`, serves, and — for every image that answers /ready while it
// drains — passes a health gate.
//
// Measured on real Docker: an upgrade killed while Compose was stopping the
// old proxy; a rollback started six seconds later found that container
// running on the right image, changed nothing, passed its health gate,
// reported success and retired the record; the container then exited.
//
// So the rule: nothing tags and recreates, and nothing is called converged,
// while a stop the previous agent process requested can still be pending.
//
// The bound is counted from THIS process's start, not from a journal record.
// Every request of the previous process was sent before this one started, and
// Docker bounds a stop by the container's stop timeout, so start +
// interrupted_settle is a time after which no such request is left. Tying the
// bound to records would miss the stops that leave none behind or leave one
// of another class: `compose down` in a restore (not journaled) or a data
// rollback, and the `up` of a startup reconcile killed in mid-flight. It would
// also depend on a best-effort journal write having succeeded.
//
// The cost is that the first tag+recreate within the window after ANY agent
// start waits for the rest of it, crash or not. Agent starts are rare, and the
// agent cannot tell a clean predecessor from a killed one.
//
// Waiting BEFORE `tag` + `up` means `up` sees the container as the stale stop
// left it and starts or recreates it, and the health gate that follows judges
// a container no outstanding request can touch.
package server

import (
	"context"
	"fmt"
	"time"
)

// settleRemaining returns how long is left until no request of the previous
// agent process can still be pending in dockerd. Zero or negative: nothing to
// wait for. time.Since uses the monotonic clock, so a wall-clock step in
// either direction changes nothing.
func (s *Server) settleRemaining() time.Duration {
	window := s.opts.Cfg.InterruptedSettle
	if window <= 0 {
		return 0
	}
	return window - time.Since(s.startedAt)
}

// settleInterrupted blocks until settleRemaining has run out and returns a
// note for the operation log (nil when it did not have to wait). It fails only
// if ctx ends first: the caller then fails without having tagged or recreated
// anything.
func (s *Server) settleInterrupted(ctx context.Context) ([]byte, error) {
	wait := s.settleRemaining()
	if wait <= 0 {
		return nil, nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return []byte(fmt.Sprintf("settle: waited %s before tag+up (a container stop the previous agent process left in dockerd may still have been pending; interrupted_settle=%s from agent start)\n",
			wait.Round(time.Millisecond), s.opts.Cfg.InterruptedSettle)), nil
	case <-ctx.Done():
		return nil, fmt.Errorf("settle: gave up waiting for the settle window (interrupted_settle=%s): %w", s.opts.Cfg.InterruptedSettle, ctx.Err())
	}
}
